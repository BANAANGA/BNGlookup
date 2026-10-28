const list = document.querySelector("#history-list");
const statusPanel = document.querySelector("#history-status");
const errorPanel = document.querySelector("#history-error");
const filterInput = document.querySelector("#history-filter");
const compareButton = document.querySelector("#history-compare");
const compareResult = document.querySelector("#history-compare-result");
let entries = [];

// Fields that change on every run and would only add noise to a comparison.
const volatileKeys = new Set(["durationMs", "elapsedMs", "responseMs", "createdAt", "checkedAt", "time", "testTime", "scanTime", "id", "url", "expiresAt"]);

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const data = await response.json();
  if (response.status === 401) {
    window.location.assign(`/login.html?next=${encodeURIComponent("/history.html")}`);
    throw new Error("Log in to continue.");
  }
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function showError(message) {
  errorPanel.textContent = message;
  errorPanel.hidden = false;
}

function render() {
  const term = filterInput.value.trim().toLowerCase();
  const visible = entries.filter((entry) => !term || `${entry.title} ${entry.query}`.toLowerCase().includes(term));
  statusPanel.textContent = entries.length
    ? `${visible.length} of ${entries.length} lookups`
    : "No lookups yet. Results you look up while logged in appear here.";
  list.innerHTML = visible.map((entry) => `
    <div class="history-row">
      <label class="history-select" title="Select to compare"><input type="checkbox" data-select="${entry.id}" ${entry.hasResult ? "" : "disabled"}></label>
      <div class="history-main">
        <strong>${escapeHtml(entry.title)}</strong>
        <span>${escapeHtml(new Date(entry.createdAt).toLocaleString())}${entry.hasResult ? "" : " · result too large to store"}</span>
      </div>
      <div class="history-actions">
        ${entry.hasResult ? `<a href="/?history=${entry.id}">View</a>` : ""}
        <a href="/?rerun=${entry.id}">Re-run</a>
        <button type="button" data-delete="${entry.id}">Delete</button>
      </div>
    </div>`).join("");
  updateCompareButton();
}

function selectedEntries() {
  return [...list.querySelectorAll("[data-select]:checked")]
    .map((box) => entries.find((entry) => String(entry.id) === box.dataset.select))
    .filter(Boolean);
}

function updateCompareButton() {
  const selected = selectedEntries();
  compareButton.disabled = selected.length !== 2 || selected[0].mode !== selected[1].mode;
  compareButton.title = selected.length === 2 && selected[0].mode !== selected[1].mode
    ? "Choose two runs of the same tool."
    : "";
}

// Turns a result into "path: value" pairs. Arrays are sorted by content so that a
// different answer order is not reported as a change.
function flatten(value, path = "", output = new Map()) {
  if (Array.isArray(value)) {
    const items = value.map((item) => [JSON.stringify(item), item]).sort((left, right) => left[0].localeCompare(right[0]));
    if (items.every(([, item]) => item === null || typeof item !== "object")) {
      output.set(path || "(value)", items.map(([, item]) => String(item)).join(", "));
    } else {
      items.forEach(([, item], index) => flatten(item, `${path}[${index}]`, output));
    }
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (volatileKeys.has(key)) continue;
      flatten(item, path ? `${path}.${key}` : key, output);
    }
  } else {
    output.set(path || "(value)", value === null || value === undefined ? "" : String(value));
  }
  return output;
}

async function compare() {
  const [first, second] = selectedEntries().sort((left, right) => new Date(left.createdAt) - new Date(right.createdAt));
  compareResult.hidden = false;
  compareResult.innerHTML = '<p class="logs-status">Comparing…</p>';
  try {
    const [older, newer] = await Promise.all([api(`/api/history/${first.id}`), api(`/api/history/${second.id}`)]);
    const before = flatten(older.data);
    const after = flatten(newer.data);
    const keys = [...new Set([...before.keys(), ...after.keys()])].sort();
    const changes = keys.filter((key) => before.get(key) !== after.get(key));
    const rows = changes.slice(0, 500).map((key) => {
      const kind = !before.has(key) ? "added" : !after.has(key) ? "removed" : "changed";
      return `
        <tr class="diff-${kind}">
          <td>${escapeHtml(key.replace(/^result\./, ""))}</td>
          <td>${escapeHtml(before.get(key) ?? "")}</td>
          <td>${escapeHtml(after.get(key) ?? "")}</td>
        </tr>`;
    }).join("");
    compareResult.innerHTML = `
      <h2>Comparison</h2>
      <p class="form-hint">${escapeHtml(`${older.title} · ${new Date(older.createdAt).toLocaleString()} → ${new Date(newer.createdAt).toLocaleString()}`)}</p>
      <p class="logs-status">${escapeHtml(changes.length
        ? `${changes.length} difference(s); ${keys.length - changes.length} field(s) unchanged. Timing fields are ignored.`
        : `No differences in ${keys.length} field(s). Timing fields are ignored.`)}</p>
      ${rows ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table history-diff">
        <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}
      ${changes.length > 500 ? '<p class="detail-notice">Only the first 500 differences are shown.</p>' : ""}`;
    compareResult.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    compareResult.innerHTML = `<p class="error-message">${escapeHtml(error.message)}</p>`;
  }
}

async function load() {
  try {
    entries = (await api("/api/history")).entries;
    render();
  } catch (error) {
    statusPanel.textContent = "";
    showError(error.message);
  }
}

filterInput.addEventListener("input", render);
list.addEventListener("change", updateCompareButton);
compareButton.addEventListener("click", compare);
list.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-delete]");
  if (!button) return;
  button.disabled = true;
  try {
    await api(`/api/history/${encodeURIComponent(button.dataset.delete)}`, { method: "DELETE" });
    entries = entries.filter((entry) => String(entry.id) !== button.dataset.delete);
    render();
  } catch (error) {
    showError(error.message);
    button.disabled = false;
  }
});
document.querySelector("#history-clear").addEventListener("click", async () => {
  if (!window.confirm("Delete your whole lookup history?")) return;
  try {
    await api("/api/history", { method: "DELETE" });
    entries = [];
    compareResult.hidden = true;
    render();
  } catch (error) {
    showError(error.message);
  }
});

load();
