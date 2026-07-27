"use server";

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { APIError } from "better-auth/api";

import { auth } from "@/lib/auth";
import { mergeGuestCart } from "@/lib/cart";

export interface FormState {
  error?: string;
}

/**
 * Sign-in and sign-up both go through `auth.api.*` rather than the client, so
 * the guest cart can be merged in the same request that establishes the
 * session. Doing it client-side would need a second round trip and would leave
 * a window where the user is signed in with an empty cart.
 *
 * The user id comes from the endpoint's return value, **not** from
 * `getCurrentUser()`. The session cookie is written to the *response*; the
 * request headers this action was called with still describe an anonymous
 * visitor, so asking for the current session here reports nobody and the merge
 * silently does nothing.
 */
export async function signInAction(_state: FormState, formData: FormData): Promise<FormState> {
  const next = String(formData.get("next") ?? "/products");
  let userId: string;

  try {
    const result = await auth.api.signInBastion({
      body: {
        email: String(formData.get("email") ?? ""),
        password: String(formData.get("password") ?? ""),
      },
      headers: await headers(),
      asResponse: false,
    });
    userId = result.user.id;
  } catch (error) {
    return { error: messageFor(error) };
  }

  await mergeGuestCart(userId);
  redirect(next);
}

export async function signUpAction(_state: FormState, formData: FormData): Promise<FormState> {
  const password = String(formData.get("password") ?? "");

  // Bastion enforces 12–128 itself; checking here turns a 422 round trip into
  // an immediate message.
  if (password.length < 12) {
    return { error: "Password must be at least 12 characters." };
  }

  let userId: string;

  try {
    const result = await auth.api.signUpBastion({
      body: { email: String(formData.get("email") ?? ""), password },
      headers: await headers(),
      asResponse: false,
    });
    userId = result.user.id;
  } catch (error) {
    return { error: messageFor(error) };
  }

  await mergeGuestCart(userId);
  redirect("/products");
}

function messageFor(error: unknown): string {
  if (error instanceof APIError) {
    return error.message ?? "Something went wrong.";
  }
  // Anything else is a bug or an outage; do not leak its text to the browser.
  console.error("auth action failed", error);
  return "Something went wrong. Please try again.";
}
