/**
 * AES-256-GCM at rest for the Bastion token pair.
 *
 * The threat is narrow and worth stating: someone who reads `blog.db` off disk
 * — a stray backup, a shared volume — should not walk away with live refresh
 * tokens. It is not protection against a compromised server process, which can
 * read the key anyway.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const IV_BYTES = 12;
const TAG_BYTES = 16;

function key(): Buffer {
  const raw = process.env.BASTION_TOKEN_SECRET;
  if (!raw) {
    throw new Error("BASTION_TOKEN_SECRET is not set; generate one with `openssl rand -base64 32`");
  }

  const decoded = Buffer.from(raw, "base64");
  if (decoded.length !== 32) {
    throw new Error(
      `BASTION_TOKEN_SECRET must decode to 32 bytes, got ${decoded.length}`,
    );
  }
  return decoded;
}

export function seal(plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");
}

export function open(sealed: string): string {
  const raw = Buffer.from(sealed, "base64");
  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const body = raw.subarray(IV_BYTES + TAG_BYTES);

  const decipher = createDecipheriv("aes-256-gcm", key(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}
