"use server";

/**
 * Every mutation in the app.
 *
 * Server Actions rather than route handlers because they are the only place
 * cookies can be written, and because the forms then need no client JavaScript
 * at all — the blog works with scripting disabled.
 *
 * Each action re-reads the session itself. None of them takes an author id from
 * the form: a hidden field saying who you are is not authentication.
 */

import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { z } from "zod";

import * as bastion from "./bastion";
import * as posts from "./posts";
import {
  SessionExpired,
  currentUser,
  endSession,
  forgetSession,
  startSession,
  withAccessToken,
} from "./session";

export interface FormState {
  error?: string;
}

/** Bastion's own minimum. Rejecting here saves a round trip and says so sooner. */
const PASSWORD_MIN = 12;

const credentials = z.object({
  email: z.string().trim().toLowerCase().pipe(z.email("that does not look like an email address")),
  password: z.string().min(PASSWORD_MIN, `password must be at least ${PASSWORD_MIN} characters`),
});

function fieldsOf(form: FormData): Record<string, string> {
  return Object.fromEntries(
    [...form.entries()].map(([key, value]) => [key, typeof value === "string" ? value : ""]),
  );
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export async function signUp(_state: FormState, form: FormData): Promise<FormState> {
  const parsed = credentials.safeParse(fieldsOf(form));
  if (!parsed.success) return { error: parsed.error.issues[0].message };

  const { email, password } = parsed.data;

  try {
    // Register issues no tokens, so signing up is register-then-login. Doing
    // both here means the user is signed in when the redirect lands, rather
    // than staring at a login form having just proved who they are.
    await bastion.register(email, password);
    const tokens = await bastion.login(email, password);
    const user = await startSession({ email, tokens });
    posts.ensureAuthor(user.bastionUserId, email);
  } catch (error) {
    if (error instanceof bastion.Conflict) {
      return { error: "that email address is already registered — try signing in" };
    }
    if (error instanceof bastion.RateLimited) {
      return { error: "too many attempts just now; wait a moment and try again" };
    }
    return { error: "could not create the account" };
  }

  redirect("/drafts");
}

export async function signIn(_state: FormState, form: FormData): Promise<FormState> {
  const parsed = credentials.safeParse(fieldsOf(form));
  if (!parsed.success) return { error: parsed.error.issues[0].message };

  const { email, password } = parsed.data;

  try {
    const tokens = await bastion.login(email, password);
    const user = await startSession({ email, tokens });
    posts.ensureAuthor(user.bastionUserId, email);
  } catch (error) {
    if (error instanceof bastion.RateLimited) {
      return { error: "too many attempts just now; wait a moment and try again" };
    }
    // Bastion does not distinguish an unknown address from a wrong password,
    // and neither does this message — saying which would be an account oracle.
    return { error: "those credentials were not accepted" };
  }

  redirect("/drafts");
}

export async function signOut(): Promise<void> {
  await endSession();
  redirect("/");
}

const passwordChange = z.object({
  current_password: z.string().min(1, "enter your current password"),
  new_password: z.string().min(PASSWORD_MIN, `new password must be at least ${PASSWORD_MIN} characters`),
});

/**
 * Changing the password ends every session for the account, this one included —
 * so it is followed by a local sign-out rather than pretending the session
 * survived.
 */
export async function changePassword(_state: FormState, form: FormData): Promise<FormState> {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const parsed = passwordChange.safeParse(fieldsOf(form));
  if (!parsed.success) return { error: parsed.error.issues[0].message };

  try {
    await withAccessToken(
      user.sessionId,
      (token) =>
        bastion.changePassword(token, parsed.data.current_password, parsed.data.new_password),
      // A wrong current password is a 401, identical to a stale token. Retrying
      // would spend a refresh rotation to rediscover the same 401.
      { retryOnUnauthorized: false },
    );
  } catch (error) {
    if (error instanceof bastion.Unauthorized) {
      return { error: "that is not your current password" };
    }
    if (error instanceof SessionExpired) {
      await forgetSession(user.sessionId);
      redirect("/sign-in");
    }
    return { error: "could not change the password" };
  }

  await forgetSession(user.sessionId);
  redirect("/sign-in?changed=1");
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

const draft = z.object({
  title: z.string().trim().min(1, "a post needs a title").max(200, "title is too long"),
  body: z.string().trim().min(1, "a post needs a body").max(20_000, "body is too long"),
});

export async function createPost(_state: FormState, form: FormData): Promise<FormState> {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const parsed = draft.safeParse(fieldsOf(form));
  if (!parsed.success) return { error: parsed.error.issues[0].message };

  const created = posts.createPost({
    authorId: user.bastionUserId,
    title: parsed.data.title,
    body: parsed.data.body,
    publish: form.get("intent") === "publish",
  });

  revalidatePath("/");
  redirect(`/write/${created.id}`);
}

export async function savePost(_state: FormState, form: FormData): Promise<FormState> {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const id = String(form.get("id") ?? "");
  const parsed = draft.safeParse(fieldsOf(form));
  if (!parsed.success) return { error: parsed.error.issues[0].message };

  // The author id comes from the session, never from the form, and it is part
  // of the `where` — so a forged `id` matches nothing rather than editing
  // somebody else's post.
  const saved = posts.updatePost({
    id,
    authorId: user.bastionUserId,
    title: parsed.data.title,
    body: parsed.data.body,
  });

  if (!saved) return { error: "that post is not yours" };

  revalidatePath("/");
  revalidatePath(`/posts/${saved.slug}`);
  return {};
}

export async function togglePublished(form: FormData): Promise<void> {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const updated = posts.setPublished({
    id: String(form.get("id") ?? ""),
    authorId: user.bastionUserId,
    published: form.get("published") === "1",
  });

  if (updated) {
    revalidatePath("/");
    revalidatePath(`/posts/${updated.slug}`);
  }
  redirect("/drafts");
}

export async function removePost(form: FormData): Promise<void> {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  posts.deletePost(String(form.get("id") ?? ""), user.bastionUserId);
  revalidatePath("/");
  redirect("/drafts");
}

const profile = z.object({
  displayName: z.string().trim().min(1, "a display name is required").max(60),
  bio: z.string().trim().max(400, "bio is too long"),
});

export async function saveProfile(_state: FormState, form: FormData): Promise<FormState> {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const parsed = profile.safeParse(fieldsOf(form));
  if (!parsed.success) return { error: parsed.error.issues[0].message };

  posts.updateProfile(user.bastionUserId, parsed.data);
  revalidatePath("/");
  return {};
}
