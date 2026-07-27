"use server";

import { headers } from "next/headers";
import { APIError } from "better-auth/api";

import { auth } from "@/lib/auth";
import { requireUser } from "@/lib/session";

export interface PasswordFormState {
  error?: string;
  ok?: boolean;
}

/**
 * One of only two places in the app that needs a live Bastion access token.
 *
 * Bastion revokes every session on the account when the password changes, so
 * the plugin immediately signs back in with the new password and swaps the
 * stored credential in place — the BetterAuth session survives, the Bastion
 * token family is new, and other devices are signed out. That last part is the
 * point of `revoke_all` and is left intact deliberately.
 */
export async function changePasswordAction(
  _state: PasswordFormState,
  formData: FormData,
): Promise<PasswordFormState> {
  await requireUser("/account/password");

  const newPassword = String(formData.get("newPassword") ?? "");
  if (newPassword.length < 12) {
    return { error: "New password must be at least 12 characters." };
  }
  if (newPassword !== String(formData.get("confirmPassword") ?? "")) {
    return { error: "The two new passwords do not match." };
  }

  try {
    await auth.api.changePasswordBastion({
      body: { currentPassword: String(formData.get("currentPassword") ?? ""), newPassword },
      headers: await headers(),
      asResponse: false,
    });
  } catch (error) {
    if (error instanceof APIError) {
      return { error: error.message ?? "Could not change the password." };
    }
    console.error("password change failed", error);
    return { error: "Could not change the password. Please try again." };
  }

  return { ok: true };
}
