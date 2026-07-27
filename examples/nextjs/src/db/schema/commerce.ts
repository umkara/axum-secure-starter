/**
 * The shop's own data. None of it goes near Bastion.
 *
 * Money is stored as integer cents throughout. Floating-point currency is a
 * rounding bug waiting for a total large enough to expose it.
 */

import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

import { user } from "./auth";

export const product = sqliteTable("product", {
  id: text("id").primaryKey(),
  slug: text("slug").notNull().unique(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  /** Cents. */
  priceCents: integer("priceCents").notNull(),
  /** Emoji placeholder — the example ships no image assets. */
  image: text("image").notNull().default("📦"),
  category: text("category").notNull(),
  createdAt: integer("createdAt", { mode: "timestamp_ms" })
    .notNull()
    .default(sql`(unixepoch() * 1000)`),
});

/**
 * A cart belongs either to a signed-in user or to an anonymous browser
 * (`guestToken`, a cookie). Exactly one of the two is set — which is why
 * neither column can be `notNull`, and why merging on sign-in is a real step
 * rather than a nice-to-have.
 */
export const cart = sqliteTable(
  "cart",
  {
    id: text("id").primaryKey(),
    userId: text("userId").references(() => user.id, { onDelete: "cascade" }),
    guestToken: text("guestToken"),
    createdAt: integer("createdAt", { mode: "timestamp_ms" })
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (table) => [
    uniqueIndex("cart_userId_idx").on(table.userId),
    uniqueIndex("cart_guestToken_idx").on(table.guestToken),
  ],
);

export const cartItem = sqliteTable(
  "cartItem",
  {
    id: text("id").primaryKey(),
    cartId: text("cartId")
      .notNull()
      .references(() => cart.id, { onDelete: "cascade" }),
    productId: text("productId")
      .notNull()
      .references(() => product.id, { onDelete: "cascade" }),
    quantity: integer("quantity").notNull().default(1),
  },
  (table) => [uniqueIndex("cartItem_cart_product_idx").on(table.cartId, table.productId)],
);

export const order = sqliteTable(
  "order",
  {
    id: text("id").primaryKey(),
    userId: text("userId")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    /** Cents, summed at checkout. */
    totalCents: integer("totalCents").notNull(),
    status: text("status").notNull().default("placed"),
    placedAt: integer("placedAt", { mode: "timestamp_ms" })
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (table) => [index("order_userId_idx").on(table.userId)],
);

/**
 * Name and price are copied, not joined. An order is a record of what was
 * agreed at the time; re-pricing history because the catalogue changed would
 * be a bug, not a feature.
 */
export const orderItem = sqliteTable(
  "orderItem",
  {
    id: text("id").primaryKey(),
    orderId: text("orderId")
      .notNull()
      .references(() => order.id, { onDelete: "cascade" }),
    productId: text("productId").notNull(),
    name: text("name").notNull(),
    unitPriceCents: integer("unitPriceCents").notNull(),
    quantity: integer("quantity").notNull(),
  },
  (table) => [index("orderItem_orderId_idx").on(table.orderId)],
);
