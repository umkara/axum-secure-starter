"use client";

import { useActionState } from "react";

import { Button, Field, Problem, TextArea } from "@/components/field";
import type { FormState } from "@/lib/actions";

export function PostEditor({
  action,
  post,
  submit,
  showPublish = false,
}: {
  action: (state: FormState, form: FormData) => Promise<FormState>;
  post?: { id: string; title: string; body: string };
  submit: string;
  showPublish?: boolean;
}) {
  const [state, dispatch] = useActionState(action, {});

  return (
    <form action={dispatch} className="space-y-4">
      <Problem>{state.error}</Problem>
      {post ? <input type="hidden" name="id" value={post.id} /> : null}
      <Field label="Title" name="title" defaultValue={post?.title} />
      <TextArea label="Body" name="body" defaultValue={post?.body} />
      <div className="flex gap-2">
        <Button name="intent" value="draft">
          {submit}
        </Button>
        {showPublish ? (
          <Button name="intent" value="publish" variant="ghost">
            Save and publish
          </Button>
        ) : null}
      </div>
    </form>
  );
}
