/**
 * Client-side counterpart. Its only job is type inference: it teaches
 * `createAuthClient` about the endpoints `plugin.ts` added, so
 * `authClient.signIn.bastion(...)` type-checks and autocompletes.
 *
 * There is no runtime logic here on purpose — Bastion tokens never reach the
 * browser, so there is nothing for a client plugin to do with them.
 */

import type { BetterAuthClientPlugin } from "better-auth";

import type { bastion } from "./plugin";

export const bastionClient = () =>
  ({
    id: "bastion",
    $InferServerPlugin: {} as ReturnType<typeof bastion>,
  }) satisfies BetterAuthClientPlugin;
