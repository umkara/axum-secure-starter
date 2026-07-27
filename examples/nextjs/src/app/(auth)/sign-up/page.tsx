import Link from "next/link";
import { redirect } from "next/navigation";

import { getCurrentUser } from "@/lib/session";

import { signUpAction } from "../actions";
import { CredentialsForm } from "../credentials-form";

export default async function SignUpPage() {
  if (await getCurrentUser()) {
    redirect("/products");
  }

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="text-2xl font-semibold">Create an account</h1>
      <p className="mt-2 mb-6 text-sm text-bark-600">
        Registering makes two calls to Bastion: one to create the account, one to sign in — Bastion
        returns no tokens from registration.
      </p>

      <CredentialsForm
        action={signUpAction}
        submitLabel="Create account"
        passwordHint="At least 12 characters — Bastion's minimum."
      />

      <p className="mt-6 text-sm">
        Already have one?{" "}
        <Link href="/sign-in" className="underline">
          Sign in
        </Link>
      </p>
    </div>
  );
}
