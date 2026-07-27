"use client";

import { createAuthClient } from "better-auth/react";

import { bastionClient } from "./bastion/client";

export const authClient = createAuthClient({
  plugins: [bastionClient()],
});

export const { useSession, signOut } = authClient;
