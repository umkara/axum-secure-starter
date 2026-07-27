import Link from "next/link";
import { redirect } from "next/navigation";

import { readCart } from "@/lib/cart";
import { formatCents } from "@/lib/money";
import { requireUser } from "@/lib/session";

import { checkoutAction } from "../actions";

export default async function CheckoutPage() {
  // The redirect carries `?next=/checkout`, so signing in here lands back on
  // this page with the guest cart already merged.
  const user = await requireUser("/checkout");
  const summary = await readCart(user.id);

  if (summary.lines.length === 0) {
    redirect("/cart");
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold">Checkout</h1>
      <p className="mt-2 text-sm text-bark-600">
        Placing an order as <strong>{user.email}</strong>.
      </p>

      <ul className="mt-6 divide-y divide-bark-200 rounded-lg border border-bark-200 bg-white">
        {summary.lines.map((line) => (
          <li key={line.productId} className="flex items-center justify-between p-4">
            <span>
              {line.name} <span className="text-bark-600">× {line.quantity}</span>
            </span>
            <span className="font-medium">{formatCents(line.lineTotalCents)}</span>
          </li>
        ))}
        <li className="flex items-center justify-between p-4 text-lg">
          <span>Total</span>
          <strong>{formatCents(summary.totalCents)}</strong>
        </li>
      </ul>

      <form action={checkoutAction} className="mt-6">
        <button
          type="submit"
          className="w-full rounded bg-bark-600 px-5 py-3 text-white hover:bg-bark-700"
        >
          Place order
        </button>
      </form>

      <p className="mt-4 text-center text-xs text-bark-600">
        No payment is taken — this example stops at writing the order.{" "}
        <Link href="/cart" className="underline">
          Back to cart
        </Link>
      </p>
    </div>
  );
}
