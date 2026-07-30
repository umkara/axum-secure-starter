import { notFound, redirect } from "next/navigation";

import { PostEditor } from "@/components/post-editor";
import { Button } from "@/components/field";
import { savePost, togglePublished } from "@/lib/actions";
import { ownedPost } from "@/lib/posts";
import { currentUser } from "@/lib/session";

/**
 * The only way to read a draft, and it is scoped by author id in the `where`
 * clause — so another signed-in user with the id in hand gets a 404, not a
 * preview.
 */
export default async function EditPostPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await currentUser();
  if (!user) redirect("/sign-in");

  const { id } = await params;
  const post = ownedPost(id, user.bastionUserId);
  if (!post) notFound();

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Edit</h1>
        <form action={togglePublished} className="flex items-center gap-3">
          <span className="text-sm text-stone-500">{post.published ? "Published" : "Draft"}</span>
          <input type="hidden" name="id" value={post.id} />
          <input type="hidden" name="published" value={post.published ? "0" : "1"} />
          <Button variant="ghost">{post.published ? "Unpublish" : "Publish"}</Button>
        </form>
      </div>

      <PostEditor action={savePost} post={post} submit="Save" />
    </div>
  );
}
