"use strict";

for (const time of document.querySelectorAll("time[data-local-time]")) {
  const parsed = new Date(time.dateTime);
  if (!Number.isNaN(parsed.getTime())) {
    time.textContent = parsed.toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
    time.title = `${time.dateTime} (UTC source value)`;
  }
}

const form = document.querySelector("[data-filter-form]");
const list = document.querySelector("[data-filter-list]");
const result = document.querySelector("[data-filter-result]");

if (form instanceof HTMLFormElement && list && result) {
  const controls = [...form.querySelectorAll("[data-filter]")];
  const items = [...list.children];

  const apply = () => {
    const active = new Map(
      controls.map((control) => [control.dataset.filter, control.value]),
    );
    let visible = 0;
    for (const item of items) {
      const matches = [...active].every(
        ([key, value]) => !value || item.dataset[key] === value,
      );
      item.hidden = !matches;
      if (matches) visible += 1;
    }
    result.textContent =
      `${visible} of ${items.length} change${items.length === 1 ? "" : "s"} ` +
      "shown on this page";
  };

  form.addEventListener("change", apply);
  form.addEventListener("reset", () => window.setTimeout(apply, 0));
  apply();
}
