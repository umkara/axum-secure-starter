/**
 * Cart storage. Entirely local — Bastion has no idea this exists.
 *
 * A cart is keyed by user id once signed in, and by an opaque cookie before
 * that. The cookie is only ever *written* from a server action or route
 * handler, because Next forbids setting cookies during a render; server
 * components read it and accept that an absent cookie means an empty cart.
 */

import { cookies } from "next/headers";
import { and, eq, inArray, sql } from "drizzle-orm";

import { db } from "@/db";
import { cart, cartItem, product } from "@/db/schema/commerce";

export const GUEST_COOKIE = "shop_cart";

const GUEST_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: "lax" as const,
  path: "/",
  maxAge: 60 * 60 * 24 * 30,
  secure: process.env.NODE_ENV === "production",
};

export interface CartLine {
  productId: string;
  slug: string;
  name: string;
  image: string;
  unitPriceCents: number;
  quantity: number;
  lineTotalCents: number;
}

export interface CartSummary {
  lines: CartLine[];
  totalCents: number;
  itemCount: number;
}

const EMPTY: CartSummary = { lines: [], totalCents: 0, itemCount: 0 };

/** Read-only lookup, safe to call during a render. */
function findCartId(owner: { userId?: string; guestToken?: string }): string | null {
  if (owner.userId) {
    const row = db.select({ id: cart.id }).from(cart).where(eq(cart.userId, owner.userId)).get();
    return row?.id ?? null;
  }
  if (owner.guestToken) {
    const row = db
      .select({ id: cart.id })
      .from(cart)
      .where(eq(cart.guestToken, owner.guestToken))
      .get();
    return row?.id ?? null;
  }
  return null;
}

/** Creates the cart if it does not exist. Only call from an action or handler. */
function ensureCartId(owner: { userId?: string; guestToken?: string }): string {
  const existing = findCartId(owner);
  if (existing) return existing;

  const id = crypto.randomUUID();
  db.insert(cart)
    .values({ id, userId: owner.userId ?? null, guestToken: owner.guestToken ?? null })
    .run();
  return id;
}

/**
 * Resolves the caller's cart owner, minting a guest cookie if there is neither
 * a user nor an existing cookie. Must be called from a server action.
 */
export async function resolveOwner(userId?: string): Promise<{ userId?: string; guestToken?: string }> {
  if (userId) return { userId };

  const jar = await cookies();
  let token = jar.get(GUEST_COOKIE)?.value;

  if (!token) {
    token = crypto.randomUUID();
    jar.set(GUEST_COOKIE, token, GUEST_COOKIE_OPTIONS);
  }

  return { guestToken: token };
}

export async function readCart(userId?: string): Promise<CartSummary> {
  const owner = userId
    ? { userId }
    : { guestToken: (await cookies()).get(GUEST_COOKIE)?.value };

  const cartId = findCartId(owner);
  if (!cartId) return EMPTY;

  const rows = db
    .select({
      productId: product.id,
      slug: product.slug,
      name: product.name,
      image: product.image,
      unitPriceCents: product.priceCents,
      quantity: cartItem.quantity,
    })
    .from(cartItem)
    .innerJoin(product, eq(cartItem.productId, product.id))
    .where(eq(cartItem.cartId, cartId))
    .all();

  const lines = rows.map((row) => ({
    ...row,
    lineTotalCents: row.unitPriceCents * row.quantity,
  }));

  return {
    lines,
    totalCents: lines.reduce((sum, line) => sum + line.lineTotalCents, 0),
    itemCount: lines.reduce((sum, line) => sum + line.quantity, 0),
  };
}

export function addItem(
  owner: { userId?: string; guestToken?: string },
  productId: string,
  quantity = 1,
): void {
  const cartId = ensureCartId(owner);

  db.insert(cartItem)
    .values({ id: crypto.randomUUID(), cartId, productId, quantity })
    .onConflictDoUpdate({
      target: [cartItem.cartId, cartItem.productId],
      // Raw SQL so the increment is atomic rather than read-then-write.
      set: { quantity: sqlIncrement(quantity) },
    })
    .run();
}

/**
 * `quantity + n`, evaluated by SQLite rather than read-modify-written in JS.
 * Two tabs adding the same product would otherwise lose one of the additions.
 */
function sqlIncrement(by: number) {
  return sql`${cartItem.quantity} + ${by}`;
}

export function setQuantity(
  owner: { userId?: string; guestToken?: string },
  productId: string,
  quantity: number,
): void {
  const cartId = findCartId(owner);
  if (!cartId) return;

  if (quantity <= 0) {
    removeItem(owner, productId);
    return;
  }

  db.update(cartItem)
    .set({ quantity })
    .where(and(eq(cartItem.cartId, cartId), eq(cartItem.productId, productId)))
    .run();
}

export function removeItem(
  owner: { userId?: string; guestToken?: string },
  productId: string,
): void {
  const cartId = findCartId(owner);
  if (!cartId) return;

  db.delete(cartItem)
    .where(and(eq(cartItem.cartId, cartId), eq(cartItem.productId, productId)))
    .run();
}

export function clearCart(owner: { userId?: string; guestToken?: string }): void {
  const cartId = findCartId(owner);
  if (!cartId) return;
  db.delete(cartItem).where(eq(cartItem.cartId, cartId)).run();
}

/**
 * Folds a guest cart into the user's cart on sign-in, summing quantities where
 * both contain the same product, then drops the guest cart and its cookie.
 *
 * Call this from the sign-in action — it writes a cookie, so it cannot run
 * during a render.
 */
export async function mergeGuestCart(userId: string): Promise<void> {
  const jar = await cookies();
  const guestToken = jar.get(GUEST_COOKIE)?.value;
  if (!guestToken) return;

  const guestCartId = findCartId({ guestToken });
  if (!guestCartId) {
    jar.delete(GUEST_COOKIE);
    return;
  }

  const guestLines = db
    .select()
    .from(cartItem)
    .where(eq(cartItem.cartId, guestCartId))
    .all();

  if (guestLines.length > 0) {
    const userCartId = ensureCartId({ userId });

    db.transaction((tx) => {
      for (const line of guestLines) {
        tx.insert(cartItem)
          .values({
            id: crypto.randomUUID(),
            cartId: userCartId,
            productId: line.productId,
            quantity: line.quantity,
          })
          .onConflictDoUpdate({
            target: [cartItem.cartId, cartItem.productId],
            set: { quantity: sqlIncrement(line.quantity) },
          })
          .run();
      }
      tx.delete(cart).where(eq(cart.id, guestCartId)).run();
    });
  } else {
    db.delete(cart).where(eq(cart.id, guestCartId)).run();
  }

  jar.delete(GUEST_COOKIE);
}

/** Products by id, for checkout's price snapshot. */
export function productsByIds(ids: string[]) {
  if (ids.length === 0) return [];
  return db.select().from(product).where(inArray(product.id, ids)).all();
}
