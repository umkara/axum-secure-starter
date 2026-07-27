import Link from "next/link";

import { readCart } from "@/lib/cart";
import { formatCents } from "@/lib/money";
import { getCurrentUser } from "@/lib/session";

import { removeFromCartAction, setQuantityAction } from "../actions";

export default async function CartPage() {
  const user = await getCurrentUser();
  const summary = await readCart(user?.id);

  if (summary.lines.length === 0) {
    return (
      <>
        <h1 className="text-2xl font-semibold">Cart</h1>
        <p className="mt-4 text-sm text-bark-600">
          Nothing here yet.{" "}
          <Link href="/products" className="underline">
            Have a look around
          </Link>
          .
        </p>
      </>
    );
  }

  return (
    <>
      <h1 className="text-2xl font-semibold">Cart</h1>

      <ul className="mt-6 divide-y divide-bark-200 rounded-lg border border-bark-200 bg-white">
        {summary.lines.map((line) => (
          <li key={line.productId} className="flex items-center gap-4 p-4">
            <span className="text-3xl" aria-hidden>
              {line.image}
            </span>

            <div className="min-w-0 flex-1">
              <Link href={`/products/${line.slug}`} className="font-medium hover:underline">
                {line.name}
              </Link>
              <p className="text-sm text-bark-600">{formatCents(line.unitPriceCents)} each</p>
            </div>

            <form action={setQuantityAction} className="flex items-center gap-2">
              <input type="hidden" name="productId" value={line.productId} />
              <input
                name="quantity"
                type="number"
                min={0}
                max={99}
                defaultValue={line.quantity}
                className="w-16 rounded border border-bark-200 px-2 py-1"
              />
              <button type="submit" className="text-sm underline">
                Update
              </button>
            </form>

            <span className="w-20 text-right font-medium">{formatCents(line.lineTotalCents)}</span>

            <form action={removeFromCartAction}>
              <input type="hidden" name="productId" value={line.productId} />
              <button type="submit" className="text-sm text-bark-600 hover:underline">
                Remove
              </button>
            </form>
          </li>
        ))}
      </ul>

      <div className="mt-6 flex items-center justify-end gap-6">
        <span className="text-lg">
          Total <strong>{formatCents(summary.totalCents)}</strong>
        </span>
        <Link
          href="/checkout"
          className="rounded bg-bark-600 px-5 py-2.5 text-white hover:bg-bark-700"
        >
          Checkout
        </Link>
      </div>

      {!user && (
        <p className="mt-4 text-right text-xs text-bark-600">
          You will be asked to sign in at checkout. This cart follows you in.
        </p>
      )}
    </>
  );
}
