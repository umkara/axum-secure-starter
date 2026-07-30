"use client";

import { useActionState } from "react";

import { Button, Field, Problem, TextArea } from "@/components/field";
import type { FormState } from "@/lib/actions";

export function ProfileForm({
  action,
  profile,
}: {
  action: (state: FormState, form: FormData) => Promise<FormState>;
  profile: { displayName: string; bio: string };
}) {
  const [state, dispatch] = useActionState(action, {});

  return (
    <form action={dispatch} className="space-y-4">
      <Problem>{state.error}</Problem>
      <Field label="Display name" name="displayName" defaultValue={profile.displayName} />
      <TextArea label="Bio" name="bio" defaultValue={profile.bio} rows={4} />
      <Button>Save profile</Button>
    </form>
  );
}

export function PasswordForm({
  action,
}: {
  action: (state: FormState, form: FormData) => Promise<FormState>;
}) {
  const [state, dispatch] = useActionState(action, {});

  return (
    <form action={dispatch} className="space-y-4">
      <Problem>{state.error}</Problem>
      <Field
        label="Current password"
        name="current_password"
        type="password"
        autoComplete="current-password"
      />
      <Field
        label="New password"
        name="new_password"
        type="password"
        autoComplete="new-password"
        placeholder="at least 12 characters"
      />
      <Button>Change password</Button>
    </form>
  );
}
