import { notFound } from "next/navigation";

import { publishedPostBySlug } from "@/lib/posts";

/**
 * Public. `publishedPostBySlug` puts `published` in the `where`, so a draft's
 * slug 404s here for everyone — including its author, who reads drafts through
 * `/write/[id]` instead.
 */
export default async function PostPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const item = publishedPostBySlug(slug);
  if (!item) notFound();

  return (
    <article>
      <h1 className="text-3xl font-semibold">{item.title}</h1>
      <p className="mt-2 text-sm text-stone-500">
        <a href={`/authors/${item.author.handle}`} className="hover:underline">
          {item.author.displayName}
        </a>
        {item.publishedAt ? ` · ${new Date(item.publishedAt).toLocaleDateString()}` : null}
      </p>
      <div className="prose mt-8 font-serif text-lg">
        {item.body.split(/\n{2,}/).map((paragraph, index) => (
          <p key={index}>{paragraph}</p>
        ))}
      </div>
    </article>
  );
}
