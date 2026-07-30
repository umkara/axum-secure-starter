import { publishedPosts } from "@/lib/posts";

/** Public. Makes no Bastion call and needs no session. */
export default function Home() {
  const items = publishedPosts();

  if (items.length === 0) {
    return (
      <p className="text-stone-600">
        Nothing published yet. <a href="/sign-up" className="underline">Sign up</a> and write the
        first post.
      </p>
    );
  }

  return (
    <div className="space-y-8">
      {items.map((item) => (
        <article key={item.id}>
          <h2 className="text-xl font-semibold">
            <a href={`/posts/${item.slug}`} className="hover:underline">
              {item.title}
            </a>
          </h2>
          <p className="mt-1 text-sm text-stone-500">
            <a href={`/authors/${item.author.handle}`} className="hover:underline">
              {item.author.displayName}
            </a>
            {item.publishedAt ? ` · ${new Date(item.publishedAt).toLocaleDateString()}` : null}
          </p>
          <p className="mt-2 line-clamp-3 text-stone-700">{item.body}</p>
        </article>
      ))}
    </div>
  );
}
