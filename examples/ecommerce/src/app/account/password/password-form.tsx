"use client";

import { useActionState } from "react";

import { changePasswordAction, type PasswordFormState } from "./actions";

const initial: PasswordFormState = {};

export function PasswordForm() {
  const [state, formAction, pending] = useActionState(changePasswordAction, initial);

  return (
    <form action={formAction} className="mt-6 space-y-4">
      {(
        [
          ["currentPassword", "Current password", "current-password"],
          ["newPassword", "New password", "new-password"],
          ["confirmPassword", "Confirm new password", "new-password"],
        ] as const
      ).map(([name, label, autoComplete]) => (
        <label key={name} className="block">
          <span className="text-sm font-medium">{label}</span>
          <input
            name={name}
            type="password"
            required
            autoComplete={autoComplete}
            className="mt-1 w-full rounded border border-bark-200 bg-white px-3 py-2"
          />
        </label>
      ))}

      {state.error && (
        <p role="alert" className="rounded bg-red-50 px-3 py-2 text-sm text-red-800">
          {state.error}
        </p>
      )}
      {state.ok && (
        <p role="status" className="rounded bg-bark-100 px-3 py-2 text-sm">
          Password changed. Every other device has been signed out.
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="rounded bg-bark-600 px-4 py-2 text-white hover:bg-bark-700 disabled:opacity-50"
      >
        {pending ? "Changing…" : "Change password"}
      </button>
    </form>
  );
}
