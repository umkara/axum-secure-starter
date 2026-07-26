// Bastion — tab switching and sidebar highlighting.
//
// Loaded as a module from a file rather than inlined: the server serves this
// page under a CSP without 'unsafe-inline', so inline handlers and inline
// <script> blocks would simply not run. That is the point of the policy, and
// this page lives within it like any frontend should.

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
