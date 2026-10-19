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

async function loadLogs(category) {
  const tableBody = document.querySelector(`#${category}-table-body`);
  errorPanel.hidden = true;
  statusPanel.textContent = "Loading logs…";
  tableBody.replaceChildren();
  try {
    const response = await fetch(`/api/admin/logs?category=${encodeURIComponent(category)}`, {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    const data = await response.json();
    if (response.status === 401) {
      window.location.assign(`/login.html?next=${encodeURIComponent("/admin-logs.html")}`);
      return;
    }
    if (!response.ok) throw new Error(data.error || "Unable to load logs.");
    if (!data.logs.length) {
      statusPanel.textContent = "No log entries yet.";
      return;
    }
    tableBody.innerHTML = data.logs.map((entry) => `
      <tr>
        <td class="logs-time">${escapeHtml(formatTimestamp(entry.timestamp))}</td>
        <td>${escapeHtml(entry.username || "—")}</td>
        <td class="logs-ip">${escapeHtml(entry.clientIp || "—")}</td>
        <td>${escapeHtml(entry.action)}</td>
        <td class="logs-details">${escapeHtml(entry.details || "—")}</td>
        <td><span class="logs-status-code ${entry.statusCode < 400 ? "success" : "failure"}">${escapeHtml(entry.statusCode)}</span></td>
      </tr>
    `).join("");
    statusPanel.textContent = `Showing ${data.logs.length} most recent entries.`;
  } catch (error) {
    statusPanel.textContent = "";
    errorPanel.textContent = error.message;
    errorPanel.hidden = false;
  }
}

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

loadLogs("login");
