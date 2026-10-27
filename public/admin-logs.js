const errorPanel = document.querySelector("#logs-error");
const statusPanel = document.querySelector("#logs-status");
const tabs = [...document.querySelectorAll(".logs-tab")];

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function formatTimestamp(timestamp) {
  const date = new Date(`${timestamp.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime())
    ? timestamp
    : date.toLocaleString(undefined, { timeZone: "UTC" });
}

const searchForm = document.querySelector("#logs-search");
const searchInput = document.querySelector("#logs-search-input");
const statusFilter = document.querySelector("#logs-status-filter");
const fromInput = document.querySelector("#logs-from");
const toInput = document.querySelector("#logs-to");
const moreButton = document.querySelector("#logs-more");
let activeCategory = "login";
let nextBefore = null;
let loadedCount = 0;
let requestId = 0;
let searchTimer = 0;

function currentFilters() {
  return {
    q: searchInput.value.trim(),
    status: statusFilter.value,
    from: fromInput.value,
    to: toInput.value,
  };
}

function highlight(text, terms) {
  const value = String(text);
  if (!terms.length) return escapeHtml(value);
  // Split the raw text on the search terms, then escape each piece so markup never mixes with entities.
  const pattern = new RegExp(`(${terms.map((term) => term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})`, "gi");
  return value.split(pattern).map((part, index) => index % 2 ? `<mark>${escapeHtml(part)}</mark>` : escapeHtml(part)).join("");
}

function syncUrl() {
  const params = new URLSearchParams({ tab: activeCategory });
  for (const [key, value] of Object.entries(currentFilters())) if (value) params.set(key, value);
  history.replaceState(null, "", `${window.location.pathname}?${params}`);
}

async function loadLogs(category, { append = false } = {}) {
  activeCategory = category;
  const tableBody = document.querySelector(`#${category}-table-body`);
  const filters = currentFilters();
  const terms = filters.q.split(/\s+/).filter(Boolean);
  const thisRequest = ++requestId;
  errorPanel.hidden = true;
  statusPanel.textContent = append ? "Loading older entries…" : "Loading logs…";
  moreButton.disabled = true;
  if (!append) {
    tableBody.replaceChildren();
    nextBefore = null;
    loadedCount = 0;
  }
  syncUrl();
  try {
    const params = new URLSearchParams({ category });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
    if (append && nextBefore) params.set("before", String(nextBefore));
    const response = await fetch(`/api/admin/logs?${params}`, {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    const data = await response.json();
    if (response.status === 401) {
      window.location.assign(`/login.html?next=${encodeURIComponent("/admin-logs.html")}`);
      return;
    }
    if (thisRequest !== requestId) return;
    if (!response.ok) throw new Error(data.error || "Unable to load logs.");
    tableBody.insertAdjacentHTML("beforeend", data.logs.map((entry) => `
      <tr>
        <td class="logs-time">${escapeHtml(formatTimestamp(entry.timestamp))}</td>
        <td>${highlight(entry.username || "—", terms)}</td>
        <td class="logs-ip">${highlight(entry.clientIp || "—", terms)}</td>
        <td>${highlight(entry.action, terms)}</td>
        <td class="logs-details">${highlight(entry.details || "—", terms)}</td>
        <td><span class="logs-status-code ${entry.statusCode < 400 ? "success" : "failure"}">${escapeHtml(entry.statusCode)}</span></td>
      </tr>
    `).join(""));
    loadedCount += data.logs.length;
    nextBefore = data.nextBefore;
    moreButton.hidden = !nextBefore;
    moreButton.disabled = false;
    statusPanel.textContent = !data.total
      ? (data.filtered ? "No entries match your search." : "No log entries yet.")
      : data.filtered
        ? `${data.total.toLocaleString()} matching entr${data.total === 1 ? "y" : "ies"}; showing ${loadedCount.toLocaleString()}.`
        : `Showing ${loadedCount.toLocaleString()} of ${data.total.toLocaleString()} entries, newest first.`;
  } catch (error) {
    if (thisRequest !== requestId) return;
    statusPanel.textContent = "";
    errorPanel.textContent = error.message;
    errorPanel.hidden = false;
  }
}

searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  clearTimeout(searchTimer);
  loadLogs(activeCategory);
});
searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadLogs(activeCategory), 300);
});
[statusFilter, fromInput, toInput].forEach((control) => control.addEventListener("change", () => loadLogs(activeCategory)));
document.querySelector("#logs-clear").addEventListener("click", () => {
  searchInput.value = "";
  statusFilter.value = "";
  fromInput.value = "";
  toInput.value = "";
  loadLogs(activeCategory);
});
moreButton.addEventListener("click", () => loadLogs(activeCategory, { append: true }));

function selectTab(tab) {
  for (const candidate of tabs) {
    const selected = candidate === tab;
    candidate.classList.toggle("active", selected);
    candidate.setAttribute("aria-selected", String(selected));
    candidate.tabIndex = selected ? 0 : -1;
    document.querySelector(`#${candidate.getAttribute("aria-controls")}`).hidden = !selected;
  }
  loadLogs(tab.dataset.category);
}

tabs.forEach((tab, index) => {
  tab.addEventListener("click", () => selectTab(tab));
  tab.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const nextIndex = event.key === "Home"
      ? 0
      : event.key === "End"
        ? tabs.length - 1
        : (index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
    tabs[nextIndex].focus();
    selectTab(tabs[nextIndex]);
  });
});

document.querySelector("#admin-logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.assign("/");
});

const initial = new URLSearchParams(window.location.search);
searchInput.value = (initial.get("q") || "").slice(0, 200);
statusFilter.value = ["success", "failure"].includes(initial.get("status")) ? initial.get("status") : "";
fromInput.value = /^\d{4}-\d{2}-\d{2}$/.test(initial.get("from") || "") ? initial.get("from") : "";
toInput.value = /^\d{4}-\d{2}-\d{2}$/.test(initial.get("to") || "") ? initial.get("to") : "";
const initialTab = tabs.find((tab) => tab.dataset.category === initial.get("tab")) || tabs[0];
selectTab(initialTab);
