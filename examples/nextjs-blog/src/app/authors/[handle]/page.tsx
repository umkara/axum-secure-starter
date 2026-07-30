import { notFound } from "next/navigation";

import { authorByHandle, publishedPostsByAuthor } from "@/lib/posts";

/** Public, and shows only published posts — an author's drafts are their own. */
export default async function AuthorPage({ params }: { params: Promise<{ handle: string }> }) {
  const { handle } = await params;
  const writer = authorByHandle(handle);
  if (!writer) notFound();

  const items = publishedPostsByAuthor(writer.bastionUserId);

  return (
    <div>
      <h1 className="text-2xl font-semibold">{writer.displayName}</h1>
      {writer.bio ? <p className="mt-2 text-stone-600">{writer.bio}</p> : null}

      <ul className="mt-8 space-y-4">
        {items.map((item) => (
          <li key={item.id}>
            <a href={`/posts/${item.slug}`} className="font-medium hover:underline">
              {item.title}
            </a>
            {item.publishedAt ? (
              <span className="ml-2 text-sm text-stone-500">
                {new Date(item.publishedAt).toLocaleDateString()}
              </span>
            ) : null}
          </li>
        ))}
        {items.length === 0 ? <li className="text-stone-600">Nothing published yet.</li> : null}
      </ul>
    </div>
  );
}
