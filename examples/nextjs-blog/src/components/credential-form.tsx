"use client";

import { useActionState } from "react";

import { Button, Field, Problem } from "@/components/field";
import type { FormState } from "@/lib/actions";

/**
 * The one client component in the app, and only because `useActionState`
 * renders the error the action returned. Everything else is a server component
 * posting to an action.
 */
export function CredentialForm({
  action,
  submit,
}: {
  action: (state: FormState, form: FormData) => Promise<FormState>;
  submit: string;
}) {
  const [state, dispatch] = useActionState(action, {});

  return (
    <form action={dispatch} className="space-y-4">
      <Problem>{state.error}</Problem>
      <Field label="Email" name="email" type="email" autoComplete="username" />
      <Field
        label="Password"
        name="password"
        type="password"
        autoComplete="current-password"
        placeholder="at least 12 characters"
      />
      <Button>{submit}</Button>
    </form>
  );
}
