/**
 * The form primitives, in one file so the pages stay about their own subject.
 * No client components: every form here posts to a Server Action, so the app
 * works with JavaScript disabled.
 */

export function Field({
  label,
  name,
  type = "text",
  defaultValue,
  required = true,
  autoComplete,
  placeholder,
}: {
  label: string;
  name: string;
  type?: string;
  defaultValue?: string;
  required?: boolean;
  autoComplete?: string;
  placeholder?: string;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-stone-700">{label}</span>
      <input
        className="w-full rounded border border-stone-300 px-3 py-2 outline-none focus:border-stone-900"
        name={name}
        type={type}
        defaultValue={defaultValue}
        required={required}
        autoComplete={autoComplete}
        placeholder={placeholder}
      />
    </label>
  );
}

export function TextArea({
  label,
  name,
  defaultValue,
  rows = 16,
}: {
  label: string;
  name: string;
  defaultValue?: string;
  rows?: number;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-stone-700">{label}</span>
      <textarea
        className="w-full rounded border border-stone-300 px-3 py-2 font-serif outline-none focus:border-stone-900"
        name={name}
        rows={rows}
        defaultValue={defaultValue}
        required
      />
    </label>
  );
}

export function Problem({ children }: { children?: string }) {
  if (!children) return null;
  return (
    <p role="alert" className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">
      {children}
    </p>
  );
}

export function Button({
  children,
  name,
  value,
  variant = "primary",
}: {
  children: React.ReactNode;
  name?: string;
  value?: string;
  variant?: "primary" | "ghost";
}) {
  const styles =
    variant === "primary"
      ? "bg-stone-900 text-white hover:bg-stone-700"
      : "border border-stone-300 text-stone-700 hover:border-stone-900";
  return (
    <button className={`rounded px-4 py-2 text-sm font-medium ${styles}`} name={name} value={value}>
      {children}
    </button>
  );
}
