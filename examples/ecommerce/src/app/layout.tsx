import type { Metadata } from "next";
import Link from "next/link";

import { readCart } from "@/lib/cart";
import { getCurrentUser } from "@/lib/session";

import { SignOutButton } from "./sign-out-button";
import "./globals.css";

export const metadata: Metadata = {
  title: "Bastion Provisions",
  description: "A Next.js storefront that delegates identity to Bastion.",
};

/**
 * Every page reads the session and the cart, and neither touches Bastion —
 * that is the point being demonstrated. Rendering the whole shell costs two
 * SQLite reads.
 */
export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();
  const cart = await readCart(user?.id);

  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-bark-200 bg-white">
          <nav className="mx-auto flex max-w-5xl items-center gap-6 px-6 py-4">
            <Link href="/" className="text-lg font-semibold tracking-tight">
              Bastion Provisions
            </Link>
            <Link href="/products" className="text-sm hover:underline">
              Shop
            </Link>
            {user && (
              <Link href="/orders" className="text-sm hover:underline">
                Orders
              </Link>
            )}
            {user?.role === "admin" && (
              <Link href="/admin" className="text-sm hover:underline">
                Admin
              </Link>
            )}

            <div className="ml-auto flex items-center gap-4 text-sm">
              <Link href="/cart" className="hover:underline">
                Cart{cart.itemCount > 0 ? ` (${cart.itemCount})` : ""}
              </Link>
              {user ? (
                <>
                  <Link href="/account/password" className="hover:underline">
                    {user.email}
                  </Link>
                  <SignOutButton />
                </>
              ) : (
                <>
                  <Link href="/sign-in" className="hover:underline">
                    Sign in
                  </Link>
                  <Link
                    href="/sign-up"
                    className="rounded bg-bark-600 px-3 py-1.5 text-white hover:bg-bark-700"
                  >
                    Create account
                  </Link>
                </>
              )}
            </div>
          </nav>
        </header>

        <main className="mx-auto max-w-5xl px-6 py-10">{children}</main>

        <footer className="mx-auto max-w-5xl px-6 py-10 text-xs text-bark-600">
          Identity by Bastion · sessions by BetterAuth · catalogue in SQLite
        </footer>
      </body>
    </html>
  );
}
