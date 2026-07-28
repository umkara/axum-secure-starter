// Bastion — tab switching, copy buttons, and sidebar highlighting.
//
// Loaded as a module from a file rather than inlined: the server serves this
// page under a CSP without 'unsafe-inline', so inline handlers and inline
// <script> blocks would simply not run. That is the point of the policy, and
// this page lives within it like any frontend should.

/** Only ever shown in the fallback, where the user has to press it themselves. */
const COPY_KEY = /Mac|iP(hone|ad|od)/.test(navigator.platform || "") ? "⌘C" : "Ctrl+C";

// ---------------------------------------------------------------------------
// Package manager switching
//
// Every command on this page is written as pnpm, because the repository uses
// it. Readers do not have to. The commands are rewritten in place from the
// pnpm source of truth rather than being written out four times in the HTML —
// four copies would drift, and only one of them would ever be read.
//
// Blocks marked data-pm="keep" are exempt: examples/nextjs is pnpm-native, so
// telling somebody to npm install it would be wrong rather than merely
// different.
// ---------------------------------------------------------------------------

const PM_KEY = "bastion:pm";
const MANAGERS = ["pnpm", "npm", "yarn", "bun"];

const join = (...parts) => parts.filter(Boolean).join(" ");

/** npm passes flags to itself unless a bare `--` hands them to the scaffolder. */
function withDoubleDash(args) {
  const first = args.findIndex((arg) => arg.startsWith("-"));
  return first === -1 ? args : [...args.slice(0, first), "--", ...args.slice(first)];
}

/** Rewrites one `pnpm …` command for another manager. */
function translate(command, manager) {
  const match = command.match(/^pnpm\s+([\s\S]+)$/);
  if (manager === "pnpm" || !match) return command;

  const [subcommand, ...args] = match[1].split(/\s+/);

  if (subcommand === "install" && args.length === 0) return `${manager} install`;

  if (subcommand === "add") {
    const dev = args[0] === "-D" || args[0] === "--save-dev";
    const packages = dev ? args.slice(1) : args;
    if (manager === "npm") return join("npm install", dev && "-D", ...packages);
    if (manager === "yarn") return join("yarn add", dev && "-D", ...packages);
    return join("bun add", dev && "--dev", ...packages);
  }

  if (subcommand === "dlx") {
    if (manager === "npm") return join("npx", ...args);
    if (manager === "yarn") return join("yarn dlx", ...args);
    return join("bunx", ...args);
  }

  if (subcommand === "create") {
    const target = args[0].replace(/@latest$/, "");
    const rest = args.slice(1);
    if (manager === "npm") {
      // `npm create vite@latest` exists; the others are reached as create-<name>.
      return target === "vite"
        ? join("npm create vite@latest", ...withDoubleDash(rest))
        : join("npx", `create-${target}@latest`, ...rest);
    }
    if (manager === "yarn") return join("yarn create", target, ...rest);
    return join("bun create", target, ...rest);
  }

  // Anything left is a package script.
  if (manager === "npm") return join("npm run", subcommand, ...args);
  if (manager === "yarn") return join("yarn", subcommand, ...args);
  return join("bun run", subcommand, ...args);
}

/** Rewrites a whole line, which may chain commands with &&. */
function translateLine(line, manager) {
  return line
    .split("&&")
    .map((segment) => {
      const [, indent, body, trailing] = segment.match(/^(\s*)(.*?)(\s*)$/);
      return indent + translate(body, manager) + trailing;
    })
    .join("&&");
}

/** The pnpm original of every block we rewrite, so switching is lossless. */
const originals = new WeakMap();

function applyManager(manager) {
  for (const code of document.querySelectorAll("pre code")) {
    if (code.closest('[data-pm="keep"]')) continue;

    if (!originals.has(code)) {
      if (!/(^|\s)pnpm\s/.test(code.textContent)) continue;
      originals.set(code, code.textContent);
    }

    code.textContent = originals
      .get(code)
      .split("\n")
      .map((line) => translateLine(line, manager))
      .join("\n");
  }

  for (const button of document.querySelectorAll(".pm")) {
    button.setAttribute("aria-pressed", String(button.dataset.pmChoice === manager));
  }
}

function initManagerSwitch() {
  const anchor = document.querySelector(".brand-sub");
  if (!anchor) return;

  const group = document.createElement("div");
  group.className = "pm-switch";
  group.setAttribute("role", "group");
  group.setAttribute("aria-label", "Package manager");

  for (const manager of MANAGERS) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "pm";
    button.dataset.pmChoice = manager;
    button.textContent = manager;
    button.setAttribute("aria-pressed", "false");
    button.dataset.tip = `Show commands as ${manager}`;
    button.dataset.tipPos = "top";
    button.addEventListener("click", () => {
      applyManager(manager);
      try {
        localStorage.setItem(PM_KEY, manager);
      } catch {
        // Private mode, or storage denied. The choice just will not persist.
      }
    });
    group.append(button);
  }

  anchor.after(group);

  let stored;
  try {
    stored = localStorage.getItem(PM_KEY);
  } catch {
    stored = null;
  }
  applyManager(MANAGERS.includes(stored) ? stored : "pnpm");
}

initManagerSwitch();

const CLIPBOARD_ICON =
  '<svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true" focusable="false">' +
  '<path fill="currentColor" d="M10 1H4a2 2 0 0 0-2 2v8h1.5V3a.5.5 0 0 1 .5-.5h6V1Z"/>' +
  '<path fill="currentColor" d="M12 4H6.5A1.5 1.5 0 0 0 5 5.5v8A1.5 1.5 0 0 0 6.5 15H12a1.5 1.5 0 0 0 1.5-1.5v-8A1.5 1.5 0 0 0 12 4Zm0 9.5H6.5v-8H12Z"/>' +
  "</svg>";

const CHECK_ICON =
  '<svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true" focusable="false">' +
  '<path fill="currentColor" d="M6.2 12.3 2.4 8.5l1.3-1.3 2.5 2.5 6.1-6.1 1.3 1.3z"/>' +
  "</svg>";

/**
 * Gives every code block a copy button.
 *
 * Built here rather than written into the markup: there are more than a
 * hundred of them, and a button that cannot work without JavaScript has no
 * business being in the HTML.
 */
function initCopyButtons() {
  for (const pre of document.querySelectorAll("pre")) {
    const wrapper = document.createElement("div");
    wrapper.className = "code-block";
    pre.parentNode.insertBefore(wrapper, pre);
    wrapper.append(pre);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.innerHTML = CLIPBOARD_ICON;
    button.setAttribute("aria-label", "Copy code");
    // The visible tooltip. A `title` would do the same job three seconds
    // later and cannot be styled; the CSS draws this one from the attribute.
    button.dataset.tip = "Copy";
    // Announces the outcome to a screen reader without moving focus.
    button.setAttribute("aria-live", "polite");
    wrapper.append(button);

    let revert;
    button.addEventListener("click", async () => {
      const code = pre.textContent.replace(/\s+$/, "");
      let ok = true;

      try {
        await navigator.clipboard.writeText(code);
      } catch {
        // No clipboard permission, or an insecure context. Select the block
        // instead so the keyboard shortcut is one keystroke away.
        ok = false;
        const range = document.createRange();
        range.selectNodeContents(pre);
        const selection = getSelection();
        selection.removeAllRanges();
        selection.addRange(range);
      }

      button.innerHTML = ok ? CHECK_ICON : CLIPBOARD_ICON;
      button.setAttribute("aria-label", ok ? "Copied" : "Select and copy");
      button.dataset.tip = ok ? "Copied" : `Press ${COPY_KEY}`;
      button.classList.toggle("copied", ok);

      clearTimeout(revert);
      revert = setTimeout(() => {
        button.innerHTML = CLIPBOARD_ICON;
        button.setAttribute("aria-label", "Copy code");
        button.dataset.tip = "Copy";
        button.classList.remove("copied");
      }, 1800);
    });
  }
}

initCopyButtons();

/** Wires one group of tabs to its panels. */
function initTabs(container) {
  const tabs = [...container.querySelectorAll(".tab")];

  const select = (target) => {
    for (const tab of tabs) {
      const active = tab === target;
      tab.setAttribute("aria-selected", String(active));
      document.getElementById(tab.dataset.panel).hidden = !active;
    }
  };

  for (const tab of tabs) {
    tab.addEventListener("click", () => select(tab));
    tab.addEventListener("keydown", (event) => {
      const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
      if (!step) return;
      event.preventDefault();
      const next = tabs[(tabs.indexOf(tab) + step + tabs.length) % tabs.length];
      next.focus();
      select(next);
    });
  }
}

document.querySelectorAll(".tabs").forEach(initTabs);

// Highlight the section currently in view. `rootMargin` biases the observer
// towards the top of the viewport so the heading you are reading is the one
// marked, rather than whichever section happens to be largest on screen.
const links = new Map(
  [...document.querySelectorAll("#nav a")].map((a) => [a.getAttribute("href").slice(1), a]),
);

const observer = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      for (const link of links.values()) link.classList.remove("active");
      links.get(entry.target.id)?.classList.add("active");
    }
  },
  { rootMargin: "-10% 0px -75% 0px", threshold: 0 },
);

for (const id of links.keys()) {
  const section = document.getElementById(id);
  if (section) observer.observe(section);
}
