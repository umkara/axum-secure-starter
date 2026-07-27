"use client";

import { useActionState } from "react";

import { revokeSessionsAction, type AdminState } from "./actions";

const initial: AdminState = {};

export function RevokeForm({ bastionUserId }: { bastionUserId: string }) {
  const [state, formAction, pending] = useActionState(revokeSessionsAction, initial);

  return (
    <form action={formAction} className="flex items-center gap-3">
      <input type="hidden" name="bastionUserId" value={bastionUserId} />
      <button
        type="submit"
        disabled={pending}
        className="rounded border border-bark-200 px-3 py-1 text-sm hover:bg-bark-100 disabled:opacity-50"
      >
        {pending ? "Revoking…" : "Revoke sessions"}
      </button>
      {state.error && <span className="text-xs text-red-700">{state.error}</span>}
      {state.message && <span className="text-xs text-bark-600">{state.message}</span>}
    </form>
  );
}
