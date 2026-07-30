import { redirect } from "next/navigation";

import { CredentialForm } from "@/components/credential-form";
import { signUp } from "@/lib/actions";
import { currentUser } from "@/lib/session";

export default async function SignUpPage() {
  if (await currentUser()) redirect("/drafts");

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="mb-6 text-2xl font-semibold">Sign up</h1>
      <CredentialForm action={signUp} submit="Create account" />
      <p className="mt-4 text-sm text-stone-600">
        Bastion issues no tokens on registration, so this signs you in straight afterwards.
      </p>
    </div>
  );
}
