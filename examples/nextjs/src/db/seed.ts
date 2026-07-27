/**
 * Seeds the catalogue. Idempotent — re-running it updates prices rather than
 * duplicating rows, so `npm run db:seed` is safe to repeat.
 *
 * Run with: npm run db:seed
 */

import { db } from "./index";
import { product } from "./schema/commerce";

const CATALOGUE = [
  {
    slug: "cast-iron-skillet",
    name: "Cast Iron Skillet",
    description: "Pre-seasoned, 26cm. Outlives its owner if kept dry.",
    priceCents: 4_900,
    image: "🍳",
    category: "kitchen",
  },
  {
    slug: "burr-grinder",
    name: "Hand Burr Grinder",
    description: "Stainless burrs, 40 clicks of adjustment. Quiet at 6am.",
    priceCents: 8_500,
    image: "☕",
    category: "kitchen",
  },
  {
    slug: "chef-knife",
    name: "Chef's Knife, 20cm",
    description: "High-carbon steel. Takes an edge, holds it, rusts if ignored.",
    priceCents: 11_000,
    image: "🔪",
    category: "kitchen",
  },
  {
    slug: "linen-apron",
    name: "Linen Apron",
    description: "Heavyweight linen, cross-back straps. Softens with washing.",
    priceCents: 5_400,
    image: "🧵",
    category: "textiles",
  },
  {
    slug: "wool-blanket",
    name: "Wool Blanket",
    description: "Undyed, 100% wool, 140x200cm.",
    priceCents: 12_900,
    image: "🧶",
    category: "textiles",
  },
  {
    slug: "brass-desk-lamp",
    name: "Brass Desk Lamp",
    description: "Articulated arm, warm bulb included. Develops a patina.",
    priceCents: 15_500,
    image: "💡",
    category: "home",
  },
  {
    slug: "notebook-a5",
    name: "A5 Notebook",
    description: "Dot grid, 160gsm, lies flat. 192 pages.",
    priceCents: 2_200,
    image: "📓",
    category: "desk",
  },
  {
    slug: "fountain-pen",
    name: "Fountain Pen, Medium",
    description: "Steel nib, converter fill. Ships with one ink cartridge.",
    priceCents: 6_800,
    image: "🖋️",
    category: "desk",
  },
  {
    slug: "ceramic-mug",
    name: "Ceramic Mug, 350ml",
    description: "Stoneware, speckled glaze. Dishwasher safe, reluctantly.",
    priceCents: 2_600,
    image: "🍵",
    category: "kitchen",
  },
  {
    slug: "canvas-tote",
    name: "Canvas Tote",
    description: "18oz cotton canvas, reinforced base. Carries far too much.",
    priceCents: 3_400,
    image: "👜",
    category: "textiles",
  },
];

for (const item of CATALOGUE) {
  db.insert(product)
    .values({ id: crypto.randomUUID(), ...item })
    .onConflictDoUpdate({
      target: product.slug,
      set: {
        name: item.name,
        description: item.description,
        priceCents: item.priceCents,
        image: item.image,
        category: item.category,
      },
    })
    .run();
}

console.log(`Seeded ${CATALOGUE.length} products.`);
