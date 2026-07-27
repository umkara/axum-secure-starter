import Link from "next/link";

import { Logo } from "./logo";

export default function HomePage() {
  return (
    <div className="mx-auto max-w-2xl">
      <Logo size={44} />
      <h1 className="mt-5 text-4xl font-semibold tracking-tight">Next.js on Bastion</h1>
      <p className="mt-4 text-lg text-bark-700">
        A Next.js 16 app that keeps its own data in SQLite and hands every question about{" "}
        <em>who you are</em> to Bastion. The shop below is only here to give that something to
        protect.
      </p>

      <dl className="mt-10 space-y-5 text-sm">
        <div>
          <dt className="font-medium">Bastion tokens never reach the browser.</dt>
          <dd className="text-bark-600">
            The access and refresh tokens live in a server-side table, sealed with AES-256-GCM. The
            browser holds one BetterAuth cookie and nothing else.
          </dd>
        </div>
        <div>
          <dt className="font-medium">Rendering a page costs zero Bastion calls.</dt>
          <dd className="text-bark-600">
            The session carries the user id, email and role, so only a password change or an admin
            revocation ever needs a live token.
          </dd>
        </div>
        <div>
          <dt className="font-medium">Refreshes are serialised through the database.</dt>
          <dd className="text-bark-600">
            Bastion's refresh tokens are single-use and losing the rotation race revokes the whole
            family — so a lease with a compare-and-swap makes sure only one refresh ever runs.
          </dd>
        </div>
      </dl>

      <div className="mt-10 flex gap-4">
        <Link
          href="/products"
          className="rounded bg-bark-600 px-5 py-2.5 text-white hover:bg-bark-700"
        >
          Browse the shop
        </Link>
        <Link
          href="/sign-up"
          className="rounded border border-bark-200 bg-white px-5 py-2.5 hover:bg-bark-100"
        >
          Create an account
        </Link>
      </div>
    </div>
  );
}
