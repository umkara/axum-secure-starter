/**
 * The header mark. Same shield as `icon.svg` and the docs site — inlined rather
 * than loaded as an image so it inherits the page's colour scheme and costs no
 * request.
 *
 * The gradient id is namespaced because this renders inside the document, where
 * a bare `id="g"` would collide with any other inline SVG on the page.
 */
export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role="img"
      aria-label="Next.js on Bastion"
      className="shrink-0"
    >
      <defs>
        <linearGradient id="bastion-mark" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#34d399" />
          <stop offset="1" stopColor="#059669" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="7" fill="url(#bastion-mark)" />
      <path
        d="M16 4.8l9 2.9v6.9c0 5.8-3.9 9.8-9 11.8-5.1-2-9-6-9-11.8V7.7z"
        fill="#fff"
      />
      <path
        d="M11.6 15.6l3.3 3.3 5.7-6.4"
        fill="none"
        stroke="#047857"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
