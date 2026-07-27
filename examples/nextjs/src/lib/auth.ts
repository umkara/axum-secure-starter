import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { nextCookies } from "better-auth/next-js";

import { db, schema } from "@/db";

import { bastion } from "./bastion";

if (!process.env.BETTER_AUTH_SECRET) {
  throw new Error("BETTER_AUTH_SECRET is required. Generate one: openssl rand -base64 32");
}

export const auth = betterAuth({
  database: drizzleAdapter(db, { provider: "sqlite", schema }),
  secret: process.env.BETTER_AUTH_SECRET,
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",

  /**
   * Off, and it must stay off.
   *
   * Enabling it would mount `/sign-up/email`, `/forget-password` and
   * `/reset-password`, which write password hashes into the local `account`
   * table. Bastion would know nothing about them, and a user who reset their
   * password here would find it unchanged everywhere else. Passwords have one
   * owner in this design.
   */
  emailAndPassword: { enabled: false },

  session: {
    expiresIn: 60 * 60 * 24 * 7,
    updateAge: 60 * 60 * 24,
  },

  user: {
    additionalFields: {
      /** Both are declared by the plugin's schema; repeated here so the session type carries them. */
      bastionUserId: { type: "string", required: false, input: false },
      role: { type: "string", required: false, input: false, defaultValue: "user" },
    },
  },

  // nextCookies() must be last — it wraps the response to flush Set-Cookie
  // through Next's server-action boundary.
  plugins: [bastion(), nextCookies()],
});

export type Session = typeof auth.$Infer.Session;
