/**
 * Demo content for the public pages.
 *
 * Seeds an author and two posts *without* creating an account — there is no
 * password here, because this app cannot create one. Accounts come from Bastion,
 * via sign-up. The seeded author is therefore unclaimed: sign up with the
 * matching address and the profile is yours.
 */

import { db } from "./index";
import { author, post } from "./schema";

const SEED_ID = "seed-author";

const posts = [
  {
    id: "seed-post-1",
    slug: "why-the-blog-holds-no-passwords",
    title: "Why this blog holds no passwords",
    body: `Every account in this app lives in Bastion. This database has posts, authors and sessions — no password hashes, no credentials, nothing that would matter if the file leaked.\n\nThat is not a small distinction. Argon2 parameters, lockout thresholds, refresh-token rotation and replay detection are all things you get wrong quietly. Delegating them to a server built for the job means this app never has to be the place they were got wrong.`,
  },
  {
    id: "seed-post-2",
    slug: "one-cookie-and-nothing-else",
    title: "One cookie, and nothing else",
    body: `The browser holds thirty-two random bytes. That is the entire client-side footprint of being signed in.\n\nBastion's tokens never leave the server: they sit in a row in this database, encrypted at rest, and are read only when something genuinely needs one. Rendering a page needs none — the session row already knows who you are.`,
  },
];

const now = Date.now();

db.insert(author)
  .values({
    bastionUserId: SEED_ID,
    handle: "demo",
    displayName: "The demo author",
    bio: "Seeded content. Sign up to write your own.",
    createdAt: now,
  })
  .onConflictDoNothing()
  .run();

for (const [index, item] of posts.entries()) {
  db.insert(post)
    .values({
      ...item,
      authorId: SEED_ID,
      published: true,
      publishedAt: now - index * 86_400_000,
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoNothing()
    .run();
}

console.log(`seeded ${posts.length} posts`);
