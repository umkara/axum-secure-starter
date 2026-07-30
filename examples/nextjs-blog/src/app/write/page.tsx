import { redirect } from "next/navigation";

import { PostEditor } from "@/components/post-editor";
import { createPost } from "@/lib/actions";
import { currentUser } from "@/lib/session";

export default async function NewPostPage() {
  if (!(await currentUser())) redirect("/sign-in");

  return (
    <div>
      <h1 className="mb-6 text-2xl font-semibold">New post</h1>
      <PostEditor action={createPost} submit="Save draft" showPublish />
    </div>
  );
}
