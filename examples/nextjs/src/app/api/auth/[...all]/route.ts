/**
 * BetterAuth's own routes, including the three the Bastion plugin adds.
 *
 * This is the app's *only* public auth surface. Bastion is never reachable
 * from the browser — every call to it originates from Node, behind this handler.
 */

import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@/lib/auth";

export const { GET, POST } = toNextJsHandler(auth);
