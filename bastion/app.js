// Bastion — tab switching, copy buttons, and sidebar highlighting.
//
// Loaded as a module from a file rather than inlined: the server serves this
// page under a CSP without 'unsafe-inline', so inline handlers and inline
// <script> blocks would simply not run. That is the point of the policy, and
// this page lives within it like any frontend should.

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
      button.classList.toggle("copied", ok);

      clearTimeout(revert);
      revert = setTimeout(() => {
        button.innerHTML = CLIPBOARD_ICON;
        button.setAttribute("aria-label", "Copy code");
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
