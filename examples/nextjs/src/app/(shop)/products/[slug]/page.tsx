import { notFound } from "next/navigation";
import { eq } from "drizzle-orm";

import { db } from "@/db";
import { product } from "@/db/schema/commerce";
import { formatCents } from "@/lib/money";

import { addToCartAction } from "../../actions";

export default async function ProductPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const item = db.select().from(product).where(eq(product.slug, slug)).get();

  if (!item) {
    notFound();
  }

  return (
    <article className="grid gap-10 sm:grid-cols-2">
      <div className="flex items-center justify-center rounded-lg border border-bark-200 bg-white py-20 text-8xl">
        <span aria-hidden>{item.image}</span>
      </div>

      <div>
        <p className="text-xs uppercase tracking-wide text-bark-600">{item.category}</p>
        <h1 className="mt-1 text-3xl font-semibold">{item.name}</h1>
        <p className="mt-4 text-bark-700">{item.description}</p>
        <p className="mt-6 text-2xl font-semibold">{formatCents(item.priceCents)}</p>

        <form action={addToCartAction} className="mt-6 flex items-end gap-3">
          <input type="hidden" name="productId" value={item.id} />
          <label className="block">
            <span className="text-sm font-medium">Quantity</span>
            <input
              name="quantity"
              type="number"
              min={1}
              max={99}
              defaultValue={1}
              className="mt-1 w-20 rounded border border-bark-200 bg-white px-3 py-2"
            />
          </label>
          <button
            type="submit"
            className="rounded bg-bark-600 px-4 py-2 text-white hover:bg-bark-700"
          >
            Add to cart
          </button>
        </form>
      </div>
    </article>
  );
}
