"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { eq } from "drizzle-orm";

import { db } from "@/db";
import { cart, order, orderItem } from "@/db/schema/commerce";
import { clearCart, productsByIds, readCart, removeItem, resolveOwner, setQuantity, addItem } from "@/lib/cart";
import { getCurrentUser, requireUser } from "@/lib/session";

/** Cart mutations are entirely local — no Bastion call, no access token. */
export async function addToCartAction(formData: FormData): Promise<void> {
  const user = await getCurrentUser();
  const owner = await resolveOwner(user?.id);

  addItem(owner, String(formData.get("productId")), Number(formData.get("quantity") ?? 1));
  revalidatePath("/cart");
}

export async function setQuantityAction(formData: FormData): Promise<void> {
  const user = await getCurrentUser();
  const owner = await resolveOwner(user?.id);

  setQuantity(owner, String(formData.get("productId")), Number(formData.get("quantity") ?? 0));
  revalidatePath("/cart");
}

export async function removeFromCartAction(formData: FormData): Promise<void> {
  const user = await getCurrentUser();
  const owner = await resolveOwner(user?.id);

  removeItem(owner, String(formData.get("productId")));
  revalidatePath("/cart");
}

/**
 * Checkout writes an order and stops — there are no payments in this example.
 *
 * Prices are re-read from the catalogue inside the transaction rather than
 * trusted from the rendered page, and copied onto the order lines so later
 * catalogue edits do not rewrite history.
 */
export async function checkoutAction(): Promise<void> {
  const user = await requireUser("/checkout");
  const summary = await readCart(user.id);

  if (summary.lines.length === 0) {
    redirect("/cart");
  }

  const catalogue = new Map(
    productsByIds(summary.lines.map((line) => line.productId)).map((row) => [row.id, row]),
  );

  const orderId = crypto.randomUUID();

  db.transaction((tx) => {
    let totalCents = 0;

    for (const line of summary.lines) {
      const current = catalogue.get(line.productId);
      if (!current) continue;
      totalCents += current.priceCents * line.quantity;
    }

    tx.insert(order).values({ id: orderId, userId: user.id, totalCents, status: "placed" }).run();

    for (const line of summary.lines) {
      const current = catalogue.get(line.productId);
      if (!current) continue;

      tx.insert(orderItem)
        .values({
          id: crypto.randomUUID(),
          orderId,
          productId: current.id,
          name: current.name,
          unitPriceCents: current.priceCents,
          quantity: line.quantity,
        })
        .run();
    }
  });

  clearCart({ userId: user.id });
  db.delete(cart).where(eq(cart.userId, user.id)).run();

  revalidatePath("/orders");
  redirect(`/orders?placed=${orderId}`);
}
