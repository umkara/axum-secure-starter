/**
 * AES-256-GCM for tokens at rest.
 *
 * BetterAuth's `encryptOAuthTokens` only covers its own `account` table, and
 * we store credentials in a table of our own — so the sealing is ours to do. A
 * refresh token in plaintext is a standing account takeover for anyone who
 * gets a copy of the SQLite file.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { bastionConfig } from "./config";

const IV_BYTES = 12;
const TAG_BYTES = 16;

const key = (() => {
  const raw = Buffer.from(bastionConfig.tokenSecret, "base64");
  if (raw.length !== 32) {
    throw new Error(
      `BASTION_TOKEN_SECRET must decode to 32 bytes, got ${raw.length}. ` +
        "Generate one with: openssl rand -base64 32",
    );
  }
  return raw;
})();

/** Returns `iv.ciphertext.tag`, each segment base64url. */
export function seal(plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return [iv.toString("base64url"), ciphertext.toString("base64url"), tag.toString("base64url")].join(
    ".",
  );
}

/** @throws if the value was tampered with, truncated, or sealed under another key. */
export function open(sealed: string): string {
  const segments = sealed.split(".");
  if (segments.length !== 3) {
    throw new Error("malformed sealed token");
  }

  const iv = Buffer.from(segments[0], "base64url");
  const ciphertext = Buffer.from(segments[1], "base64url");
  const tag = Buffer.from(segments[2], "base64url");

  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error("malformed sealed token");
  }

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
