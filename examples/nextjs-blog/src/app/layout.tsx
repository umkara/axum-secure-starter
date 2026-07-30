import type { Metadata } from "next";

import { signOut } from "@/lib/actions";
import { currentUser } from "@/lib/session";

import "./globals.css";

export const metadata: Metadata = {
  title: "A blog on Bastion",
  description: "A Next.js 16 blog that delegates accounts and sessions to Bastion.",
};

/**
 * The header reads the session, which is one local SELECT and no Bastion call.
 * That is what lets every public page stay free of network round trips.
 */
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await currentUser();

  return (
    <html lang="en">
      <body className="min-h-screen bg-stone-50 text-stone-900 antialiased">
        <header className="border-b border-stone-200 bg-white">
          <nav className="mx-auto flex max-w-3xl items-center gap-4 px-6 py-4 text-sm">
            <a href="/" className="font-semibold">
              A blog on Bastion
            </a>
            <span className="flex-1" />
            {user ? (
              <>
                <a href="/drafts" className="hover:underline">
                  Your posts
                </a>
                <a href="/write" className="hover:underline">
                  Write
                </a>
                <a href="/account" className="hover:underline">
                  Account
                </a>
                <form action={signOut}>
                  <button className="text-stone-500 hover:underline">Sign out</button>
                </form>
              </>
            ) : (
              <>
                <a href="/sign-in" className="hover:underline">
                  Sign in
                </a>
                <a href="/sign-up" className="rounded bg-stone-900 px-3 py-1.5 text-white">
                  Sign up
                </a>
              </>
            )}
          </nav>
        </header>
        <main className="mx-auto max-w-3xl px-6 py-10">{children}</main>
        <footer className="mx-auto max-w-3xl px-6 pb-12 text-xs text-stone-500">
          Accounts, passwords and session rotation are handled by{" "}
          <a href="https://bastionrs.dev" className="underline">
            Bastion
          </a>
          . Posts live in this app&rsquo;s own SQLite database.
        </footer>
      </body>
    </html>
  );
}
