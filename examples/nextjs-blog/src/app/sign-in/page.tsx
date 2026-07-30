import { redirect } from "next/navigation";

import { CredentialForm } from "@/components/credential-form";
import { signIn } from "@/lib/actions";
import { currentUser } from "@/lib/session";

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ changed?: string }>;
}) {
  if (await currentUser()) redirect("/drafts");
  const { changed } = await searchParams;

  return (
    <div className="mx-auto max-w-sm">
      <h1 className="mb-6 text-2xl font-semibold">Sign in</h1>
      {changed ? (
        <p className="mb-4 rounded border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">
          Password changed. Every session was ended — sign in with the new one.
        </p>
      ) : null}
      <CredentialForm action={signIn} submit="Sign in" />
      <p className="mt-4 text-sm text-stone-600">
        No account? <a href="/sign-up" className="underline">Sign up</a>.
      </p>
    </div>
  );
}
