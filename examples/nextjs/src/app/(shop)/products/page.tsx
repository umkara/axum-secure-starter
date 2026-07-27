import Link from "next/link";

import { db } from "@/db";
import { product } from "@/db/schema/commerce";
import { formatCents } from "@/lib/money";

import { addToCartAction } from "../actions";

export default async function ProductsPage() {
  const products = db.select().from(product).all();

  if (products.length === 0) {
    return (
      <p className="text-sm text-bark-600">
        No products yet — run <code className="rounded bg-bark-100 px-1">npm run db:seed</code>.
      </p>
    );
  }

  return (
    <>
      <h1 className="mb-6 text-2xl font-semibold">Everything</h1>

      <ul className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {products.map((item) => (
          <li key={item.id} className="rounded-lg border border-bark-200 bg-white p-5">
            <Link href={`/products/${item.slug}`} className="block">
              <span className="text-4xl" aria-hidden>
                {item.image}
              </span>
              <h2 className="mt-3 font-medium hover:underline">{item.name}</h2>
            </Link>
            <p className="mt-1 line-clamp-2 text-sm text-bark-600">{item.description}</p>

            <div className="mt-4 flex items-center justify-between">
              <span className="font-semibold">{formatCents(item.priceCents)}</span>
              <form action={addToCartAction}>
                <input type="hidden" name="productId" value={item.id} />
                <button
                  type="submit"
                  className="rounded bg-bark-600 px-3 py-1.5 text-sm text-white hover:bg-bark-700"
                >
                  Add
                </button>
              </form>
            </div>
          </li>
        ))}
      </ul>
    </>
  );
}
