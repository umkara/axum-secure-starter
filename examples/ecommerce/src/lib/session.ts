/**
 * Session access for server components and actions.
 *
 * **This module deliberately imports nothing from `lib/bastion/api`.** That is
 * a structural guard, not a style preference: if reading the session could
 * reach Bastion, every page render would become an outbound HTTP call against
 * a shared rate-limit bucket. Everything a page needs — the Bastion user id,
 * the email, the role — is mirrored onto the local session at sign-in, so
 * rendering costs one SQLite read and nothing else.
 *
 * The only code allowed to talk to Bastion is the handful of actions that
 * genuinely need a live token: password change and admin revocation.
 */

import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";

import { auth } from "./auth";

export interface CurrentUser {
  id: string;
  email: string;
  name: string;
  bastionUserId: string;
  role: "user" | "admin";
  /** BetterAuth session id — the key `getAccessToken` needs. */
  sessionId: string;
}

/** Returns the current user, or null. Never throws, never redirects. */
export async function getCurrentUser(): Promise<CurrentUser | null> {
  const result = await auth.api.getSession({ headers: await headers() });
  if (!result) return null;

  const { user, session } = result;
  const bastionUserId = (user as { bastionUserId?: string }).bastionUserId;
  if (!bastionUserId) return null;

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    bastionUserId,
    role: (user as { role?: string }).role === "admin" ? "admin" : "user",
    sessionId: session.id,
  };
}

/** Redirects to sign-in, preserving where the user was headed. */
export async function requireUser(returnTo = "/"): Promise<CurrentUser> {
  const user = await getCurrentUser();
  if (!user) {
    redirect(`/sign-in?next=${encodeURIComponent(returnTo)}`);
  }
  return user;
}

/**
 * 404 rather than 403 for non-admins — a 403 confirms the route exists, which
 * is a free hint for anyone probing.
 */
export async function requireAdmin(): Promise<CurrentUser> {
  const user = await getCurrentUser();
  if (!user || user.role !== "admin") {
    notFound();
  }
  return user;
}
