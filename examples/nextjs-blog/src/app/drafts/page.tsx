import { redirect } from "next/navigation";

import { Button } from "@/components/field";
import { removePost, togglePublished } from "@/lib/actions";
import { postsByAuthor } from "@/lib/posts";
import { currentUser } from "@/lib/session";

/** Everything this author has written, drafts included. Scoped by their id. */
export default async function DraftsPage() {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const items = postsByAuthor(user.bastionUserId);

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Your posts</h1>
        <a href="/write" className="rounded bg-stone-900 px-4 py-2 text-sm font-medium text-white">
          New post
        </a>
      </div>

      {items.length === 0 ? (
        <p className="text-stone-600">Nothing yet.</p>
      ) : (
        <ul className="divide-y divide-stone-200 rounded border border-stone-200 bg-white">
          {items.map((item) => (
            <li key={item.id} className="flex items-center gap-3 px-4 py-3">
              <div className="flex-1">
                <a href={`/write/${item.id}`} className="font-medium hover:underline">
                  {item.title}
                </a>
                <p className="text-xs text-stone-500">
                  {item.published ? "published" : "draft"} · updated{" "}
                  {new Date(item.updatedAt).toLocaleDateString()}
                </p>
              </div>

              {item.published ? (
                <a href={`/posts/${item.slug}`} className="text-sm text-stone-500 hover:underline">
                  View
                </a>
              ) : null}

              <form action={togglePublished}>
                <input type="hidden" name="id" value={item.id} />
                <input type="hidden" name="published" value={item.published ? "0" : "1"} />
                <Button variant="ghost">{item.published ? "Unpublish" : "Publish"}</Button>
              </form>

              <form action={removePost}>
                <input type="hidden" name="id" value={item.id} />
                <Button variant="ghost">Delete</Button>
              </form>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
