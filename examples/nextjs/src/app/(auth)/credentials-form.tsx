"use client";

import { useActionState } from "react";

import type { FormState } from "./actions";

interface Props {
  action: (state: FormState, formData: FormData) => Promise<FormState>;
  submitLabel: string;
  next?: string;
  passwordHint?: string;
}

export function CredentialsForm({ action, submitLabel, next, passwordHint }: Props) {
  const [state, formAction, pending] = useActionState(action, {});

  return (
    <form action={formAction} className="space-y-4">
      {next && <input type="hidden" name="next" value={next} />}

      <label className="block">
        <span className="text-sm font-medium">Email</span>
        <input
          name="email"
          type="email"
          required
          autoComplete="email"
          className="mt-1 w-full rounded border border-bark-200 bg-white px-3 py-2"
        />
      </label>

      <label className="block">
        <span className="text-sm font-medium">Password</span>
        <input
          name="password"
          type="password"
          required
          minLength={1}
          autoComplete="current-password"
          className="mt-1 w-full rounded border border-bark-200 bg-white px-3 py-2"
        />
        {passwordHint && <span className="mt-1 block text-xs text-bark-600">{passwordHint}</span>}
      </label>

      {state.error && (
        <p role="alert" className="rounded bg-red-50 px-3 py-2 text-sm text-red-800">
          {state.error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="w-full rounded bg-bark-600 px-4 py-2 text-white hover:bg-bark-700 disabled:opacity-50"
      >
        {pending ? "Working…" : submitLabel}
      </button>
    </form>
  );
}
