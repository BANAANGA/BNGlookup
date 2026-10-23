const errorPanel = document.querySelector("#dash-error");
const statusPanel = document.querySelector("#dash-status");
const refreshMs = 3000;
let timer = 0;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${seconds % 60}s`;
}

function formatTimestamp(timestamp) {
  const date = new Date(`${timestamp.replace(" ", "T")}Z`);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString(undefined, { timeZone: "UTC" });
}

function setGauge(id, percent, text, detail) {
  const clamped = Math.max(0, Math.min(100, percent));
  document.querySelector(`#g-${id}`).textContent = text;
  const bar = document.querySelector(`#b-${id}`);
  bar.style.width = `${clamped}%`;
  bar.className = clamped >= 90 ? "crit" : clamped >= 75 ? "warn" : "";
  document.querySelector(`#s-${id}`).textContent = detail;
}

function setText(id, value) {
  document.querySelector(id).textContent = value;
}

function queryText(entry) {
  try {
    const details = JSON.parse(entry.details);
    const parts = [details.name, details.target, details.domain, details.ip, details.mac, details.query]
      .filter((part) => typeof part === "string" && part);
    if (Array.isArray(details.targets)) parts.push(details.targets.slice(0, 3).join(", "));
    return parts[0] || "";
  } catch {
    return entry.details || "";
  }
}

function render(data) {
  const cpu = data.cpu;
  setGauge("cpu", cpu.system, `${cpu.system.toFixed(1)}%`, `App ${cpu.process.toFixed(1)}% · ${cpu.cores} core${cpu.cores === 1 ? "" : "s"}`);
  const mem = data.memory;
  setText("#l-mem", mem.scope === "container" ? "Memory usage (container)" : "Memory usage (host)");
  setGauge("mem", (mem.used / mem.total) * 100, `${((mem.used / mem.total) * 100).toFixed(1)}%`,
    `${formatBytes(mem.used)} of ${formatBytes(mem.total)} · app ${formatBytes(mem.process.rss)}`);
  if (data.disk) {
    setGauge("disk", (data.disk.used / data.disk.total) * 100, `${((data.disk.used / data.disk.total) * 100).toFixed(1)}%`,
      `${formatBytes(data.disk.used)} of ${formatBytes(data.disk.total)} · database ${formatBytes(data.database.size)}`);
  } else {
    setGauge("disk", 0, "—", `Database ${formatBytes(data.database.size)}`);
  }
  const [one, five, fifteen] = data.load;
  setGauge("load", (one / cpu.cores) * 100, one.toFixed(2), `5 min ${five.toFixed(2)} · 15 min ${fifteen.toFixed(2)} (${cpu.cores} cores)`);

  const stats = data.stats;
  setText("#a-queries", stats.queries24h.toLocaleString());
  setText("#a-hour", `${stats.queriesLastHour.toLocaleString()} in the last hour`);
  setText("#a-visitors", stats.visitors24h.toLocaleString());
  setText("#a-failures", stats.failures24h.toLocaleString());
  setText("#a-logins", `${stats.loginFailures24h.toLocaleString()} failed logins`);
  setText("#a-users", `${stats.users.toLocaleString()} / ${stats.sessions.toLocaleString()}`);
  setText("#a-logs", `${stats.logs.toLocaleString()} log entries`);

  const rows = [
    ["App uptime", formatDuration(data.uptimeSeconds)],
    ["Host uptime", formatDuration(data.systemUptimeSeconds)],
    ["Node.js", data.node],
    ["Platform", data.platform],
    ["Heap used", `${formatBytes(mem.process.heapUsed)} / ${formatBytes(mem.process.heapTotal)}`],
    ["Running traceroutes", String(stats.heavyJobs.traceroute)],
    ["Running ping scans", String(stats.heavyJobs.pingScan)],
  ];
  document.querySelector("#dash-system").innerHTML = rows.map(([label, value]) => `
    <div class="detail-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");

  const max = Math.max(1, ...data.topActions.map((entry) => entry.count));
  document.querySelector("#dash-top").innerHTML = data.topActions.length
    ? data.topActions.map((entry) => `
      <div class="stats-top-row">
        <div class="stats-top-label"><span>${escapeHtml(entry.action)}</span><strong>${entry.count.toLocaleString()}</strong></div>
        <svg class="stats-top-track" viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true"><rect width="100" height="5" rx="2.5" fill="#202020"/><rect class="stats-top-fill" width="${(entry.count / max) * 100}" height="5" rx="2.5" fill="#65d993"/></svg>
      </div>`).join("")
    : '<p class="stats-empty">No queries in the last 24 hours.</p>';

  document.querySelector("#dash-latest").innerHTML = data.latest.length
    ? data.latest.map((entry) => `
      <tr>
        <td class="logs-time">${escapeHtml(formatTimestamp(entry.timestamp))}</td>
        <td>${escapeHtml(entry.username || "guest")}</td>
        <td class="logs-ip">${escapeHtml(entry.clientIp || "")}</td>
        <td>${escapeHtml(entry.action)}</td>
        <td class="logs-details">${escapeHtml(queryText(entry))}</td>
        <td>${entry.statusCode}</td>
      </tr>`).join("")
    : '<tr><td colspan="6">No queries yet.</td></tr>';
  statusPanel.textContent = `Updated ${new Date(data.time).toLocaleTimeString()}`;
}

async function refresh() {
  try {
    const response = await fetch("/api/admin/system", {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    if (response.status === 401) {
      window.location.assign(`/login.html?next=${encodeURIComponent("/admin-dashboard.html")}`);
      return;
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load the dashboard.");
    errorPanel.hidden = true;
    render(data);
  } catch (error) {
    errorPanel.textContent = error.message;
    errorPanel.hidden = false;
  }
}

function schedule() {
  clearInterval(timer);
  if (!document.hidden) timer = setInterval(refresh, refreshMs);
}

document.addEventListener("visibilitychange", () => {
  schedule();
  if (!document.hidden) refresh();
});
document.querySelector("#admin-logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.assign("/");
});

refresh();
schedule();
