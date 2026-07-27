import Link from "next/link";
import { desc, eq, inArray } from "drizzle-orm";

import { db } from "@/db";
import { order, orderItem } from "@/db/schema/commerce";
import { formatCents } from "@/lib/money";
import { requireUser } from "@/lib/session";

export default async function OrdersPage({
  searchParams,
}: {
  searchParams: Promise<{ placed?: string }>;
}) {
  const user = await requireUser("/orders");
  const { placed } = await searchParams;

  const orders = db
    .select()
    .from(order)
    .where(eq(order.userId, user.id))
    .orderBy(desc(order.placedAt))
    .all();

  const lines =
    orders.length === 0
      ? []
      : db
          .select()
          .from(orderItem)
          .where(
            inArray(
              orderItem.orderId,
              orders.map((row) => row.id),
            ),
          )
          .all();

  const byOrder = new Map<string, typeof lines>();
  for (const line of lines) {
    const bucket = byOrder.get(line.orderId) ?? [];
    bucket.push(line);
    byOrder.set(line.orderId, bucket);
  }

  return (
    <>
      <h1 className="text-2xl font-semibold">Orders</h1>

      {placed && (
        <p className="mt-4 rounded bg-bark-100 px-4 py-3 text-sm">
          Order placed. Reference <code>{placed.slice(0, 8)}</code>.
        </p>
      )}

      {orders.length === 0 ? (
        <p className="mt-4 text-sm text-bark-600">
          Nothing ordered yet.{" "}
          <Link href="/products" className="underline">
            Start here
          </Link>
          .
        </p>
      ) : (
        <ul className="mt-6 space-y-4">
          {orders.map((row) => (
            <li key={row.id} className="rounded-lg border border-bark-200 bg-white p-5">
              <div className="flex items-baseline justify-between">
                <span className="font-medium">
                  {new Date(row.placedAt).toLocaleDateString("en-US", {
                    year: "numeric",
                    month: "long",
                    day: "numeric",
                  })}
                </span>
                <span className="font-semibold">{formatCents(row.totalCents)}</span>
              </div>

              <ul className="mt-3 space-y-1 text-sm text-bark-600">
                {(byOrder.get(row.id) ?? []).map((line) => (
                  <li key={line.id}>
                    {line.name} × {line.quantity} — {formatCents(line.unitPriceCents * line.quantity)}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
