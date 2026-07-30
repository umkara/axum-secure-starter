import { redirect } from "next/navigation";

import { PasswordForm, ProfileForm } from "@/components/account-forms";
import { changePassword, saveProfile } from "@/lib/actions";
import { ensureAuthor } from "@/lib/posts";
import { currentUser } from "@/lib/session";

/**
 * The profile is this app's data; the password is Bastion's. Changing the
 * password is the *only* screen in the blog that needs a live access token —
 * everything else renders from the local session row.
 */
export default async function AccountPage() {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const profile = ensureAuthor(user.bastionUserId, user.email);

  return (
    <div className="space-y-12">
      <section>
        <h1 className="mb-1 text-2xl font-semibold">Account</h1>
        <p className="mb-6 text-sm text-stone-500">
          Signed in as {user.email} · public page{" "}
          <a href={`/authors/${profile.handle}`} className="underline">
            /authors/{profile.handle}
          </a>
        </p>
        <ProfileForm action={saveProfile} profile={profile} />
      </section>

      <section>
        <h2 className="mb-1 text-lg font-semibold">Password</h2>
        <p className="mb-4 text-sm text-stone-500">
          Handled by Bastion. Changing it ends every session, including this one, so you will be
          asked to sign in again.
        </p>
        <PasswordForm action={changePassword} />
      </section>
    </div>
  );
}
