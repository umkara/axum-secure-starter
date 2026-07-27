"use server";

import { revalidatePath } from "next/cache";

import { CredentialRevoked, revokeUserSessions, withAccessToken } from "@/lib/bastion";
import { requireAdmin } from "@/lib/session";

export interface AdminState {
  error?: string;
  message?: string;
}

/**
 * The second and last place needing a live Bastion token: break-glass session
 * revocation for another account.
 *
 * `requireAdmin` gates on the mirrored `role` column, but that is only a UI
 * gate — Bastion re-checks the role on the access token and would answer 403
 * regardless. Two independent checks is the intent, not redundancy.
 */
export async function revokeSessionsAction(
  _state: AdminState,
  formData: FormData,
): Promise<AdminState> {
  const admin = await requireAdmin();
  const targetBastionId = String(formData.get("bastionUserId") ?? "");

  if (!targetBastionId) {
    return { error: "No user selected." };
  }

  try {
    await withAccessToken(admin.sessionId, (token) => revokeUserSessions(token, targetBastionId));
  } catch (error) {
    if (error instanceof CredentialRevoked) {
      return { error: "Your own session expired — sign in again." };
    }
    console.error("session revocation failed", error);
    return { error: "Bastion refused the revocation." };
  }

  revalidatePath("/admin");
  return { message: `Revoked every Bastion session for ${targetBastionId.slice(0, 8)}…` };
}
