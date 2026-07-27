import Link from "next/link";
import { redirect } from "next/navigation";

import { getCurrentUser } from "@/lib/session";

import { signInAction } from "../actions";
import { CredentialsForm } from "../credentials-form";

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  if (await getCurrentUser()) {
    redirect("/products");
  }

  const { next } = await searchParams;

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="text-2xl font-semibold">Sign in</h1>
      <p className="mt-2 mb-6 text-sm text-bark-600">
        Your password is checked by Bastion. This app never sees it after the request leaves the
        form.
      </p>

      <CredentialsForm action={signInAction} submitLabel="Sign in" next={next} />

      <p className="mt-6 text-sm">
        No account?{" "}
        <Link href="/sign-up" className="underline">
          Create one
        </Link>
      </p>
    </div>
  );
}
