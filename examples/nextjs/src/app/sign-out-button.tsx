"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { authClient } from "@/lib/auth-client";

/**
 * Signing out goes through the client so BetterAuth clears its cookie the way
 * it expects. The plugin's `before` hook on `/sign-out` revokes the Bastion
 * refresh family server-side on the way through.
 */
export function SignOutButton() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  return (
    <button
      type="button"
      disabled={pending}
      className="text-bark-600 hover:underline disabled:opacity-50"
      onClick={() => {
        startTransition(async () => {
          await authClient.signOut();
          router.push("/");
          router.refresh();
        });
      }}
    >
      {pending ? "Signing out…" : "Sign out"}
    </button>
  );
}
