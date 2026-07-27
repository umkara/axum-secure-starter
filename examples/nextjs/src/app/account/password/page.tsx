import { requireUser } from "@/lib/session";

import { PasswordForm } from "./password-form";

export default async function PasswordPage() {
  const user = await requireUser("/account/password");

  return (
    <div className="mx-auto max-w-md">
      <h1 className="text-2xl font-semibold">Password</h1>
      <p className="mt-2 text-sm text-bark-600">
        Signed in as <strong>{user.email}</strong>. Changing this changes it in Bastion, which is
        the only place your password exists.
      </p>

      <PasswordForm />

      <p className="mt-8 text-xs text-bark-600">
        Bastion signs out every session on the account when a password changes. This one is
        re-established automatically; anything else you were signed in on is not.
      </p>
    </div>
  );
}
