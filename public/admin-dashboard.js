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

function formatIsoTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : `${date.toLocaleString(undefined, { timeZone: "UTC" })} UTC`;
}

function formatVersion(version) {
  return /^\d/.test(version) ? `v${version}` : version;
}

function renderVersion(data) {
  const update = data.updateCheck;
  const commit = data.commit
    ? `<a href="${escapeHtml(`${data.repositoryUrl}/commit/${data.commit}`)}" target="_blank" rel="noopener noreferrer">${escapeHtml(data.commit.slice(0, 7))}</a>`
    : "—";
  let status;
  if (!update.enabled) status = "Update check disabled (UPDATE_CHECK=false)";
  else if (update.error && !update.latestVersion) status = `Could not check: ${update.error}`;
  else if (update.updateAvailable === true) status = `Update available: ${update.latestVersion}`;
  else if (update.updateAvailable === false) status = "Up to date";
  else status = "Development build; compare with the latest release";
  const statusClass = update.updateAvailable === true ? "warning" : update.updateAvailable === false ? "success" : "";
  const rows = [
    ["Running version", escapeHtml(data.version === "dev" ? "dev (local build)" : formatVersion(data.version))],
    ["Commit", commit],
    ["Built", escapeHtml(data.buildDate ? formatIsoTime(data.buildDate) : "—")],
    ["Latest release", update.latestVersion
      ? `<a href="${escapeHtml(update.latestUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(update.latestVersion)}</a>${update.publishedAt ? escapeHtml(` · ${formatIsoTime(update.publishedAt)}`) : ""}`
      : "—"],
    ["Status", `<span class="logs-status-code ${statusClass}">${escapeHtml(status)}</span>`],
    ["Last checked", escapeHtml(update.checkedAt ? formatIsoTime(update.checkedAt) : "—")],
    ["Source code", `<a href="${escapeHtml(data.repositoryUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(data.repositoryUrl.replace("https://", ""))}</a>`],
  ];
  document.querySelector("#dash-version").innerHTML = rows.map(([label, value]) => `
    <div class="detail-row"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`).join("");
  const banner = document.querySelector("#dash-update-banner");
  banner.hidden = update.updateAvailable !== true;
  if (update.updateAvailable === true) {
    banner.innerHTML = `A new version is available: <a href="${escapeHtml(update.latestUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(update.latestVersion)}</a> (running ${escapeHtml(formatVersion(data.version))}).`;
  }
}

async function loadVersion(refreshCheck = false) {
  const button = document.querySelector("#dash-version-check");
  button.disabled = true;
  try {
    const response = await fetch(`/api/admin/version${refreshCheck ? "?refresh=1" : ""}`, {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load version information.");
    renderVersion(data);
  } catch (error) {
    document.querySelector("#dash-version").innerHTML = `<div class="detail-row"><span>${escapeHtml(error.message)}</span></div>`;
  } finally {
    button.disabled = false;
  }
}

document.querySelector("#dash-version-check").addEventListener("click", () => loadVersion(true));

refresh();
schedule();
loadVersion();

// Insights: ratings recorded by Web check, TLS grade and Email check, monitors and new-tool usage.
const insightsRange = document.querySelector("#insights-range");
const insightsStatus = document.querySelector("#insights-status");
const insightsRefreshMs = 60000;
const gradeOrder = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"];

function gradeClass(grade) {
  if (/^A/.test(grade)) return "good";
  if (/^[BC]$/.test(grade)) return "fair";
  return "poor";
}

function relativeDate(iso) {
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  return days <= 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago`;
}

function ratingRows(entries, empty) {
  if (!entries.length) return `<p class="stats-empty">${escapeHtml(empty)}</p>`;
  return `<ol class="rating-list">${entries.map((entry) => `
    <li>
      <span class="rating-grade ${gradeClass(entry.grade)}">${escapeHtml(entry.grade)}</span>
      <span class="rating-domain"><a href="/?q=${encodeURIComponent(entry.domain.replace(/:\d+$/, ""))}">${escapeHtml(entry.domain)}</a><small>${escapeHtml(entry.detail)}</small></span>
      <span class="rating-meta">${escapeHtml(entry.score)}<small>${escapeHtml(relativeDate(entry.checkedAt))}</small></span>
    </li>`).join("")}</ol>`;
}

function gradeBar(grades) {
  const entries = Object.entries(grades).sort(([left], [right]) => gradeOrder.indexOf(left) - gradeOrder.indexOf(right));
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  if (!total) return "";
  return `<div class="grade-bar" role="img" aria-label="${escapeHtml(entries.map(([grade, count]) => `${grade}: ${count}`).join(", "))}">${entries.map(([grade, count]) => `
    <span class="${gradeClass(grade)}" data-share="${(count / total) * 100}" title="${escapeHtml(`${grade}: ${count}`)}">${count / total >= 0.08 ? escapeHtml(grade) : ""}</span>`).join("")}</div>`;
}

function renderInsights(data) {
  const ratings = data.ratings;
  const rated = ratings.web.count + ratings.tls.count + ratings.email.count + (ratings.dns?.count || 0);
  setText("#i-rated", rated.toLocaleString());
  setText("#i-rated-detail", `${ratings.web.count} web · ${ratings.tls.count} TLS · ${ratings.email.count} email · ${ratings.dns?.count || 0} DNS`);
  setText("#i-web", ratings.web.average === null ? "—" : `${ratings.web.average}/100`);
  setText("#i-web-detail", ratings.web.count ? `${ratings.web.grades["A+"] || 0} domains graded A+` : "No web checks yet");
  setText("#i-email", ratings.email.average === null ? "—" : `${ratings.email.average}/100`);
  setText("#i-email-detail", ratings.email.count ? `${(ratings.email.grades.D || 0) + (ratings.email.grades.F || 0)} domains graded D or F` : "No email checks yet");
  const statuses = data.monitors.byStatus;
  setText("#i-monitors", `${data.monitors.enabled.toLocaleString()} active`);
  setText("#i-monitors-detail", `${statuses.fail || 0} failing · ${statuses.warn || 0} warning · ${data.monitors.alerts} alert(s) sent`);

  document.querySelector("#dash-ratings").innerHTML = ["web", "tls", "email", "dns"].filter((kind) => ratings[kind]).map((kind) => {
    const rating = ratings[kind];
    return `
      <article class="account-card admin-card stats-panel rating-panel">
        <div class="rating-heading"><h2>${escapeHtml(rating.label)}</h2><span>${escapeHtml(rating.count ? `${rating.count} domain(s) · avg ${rating.average}` : "No checks yet")}</span></div>
        ${gradeBar(rating.grades)}
        <h3>Best rated</h3>
        ${ratingRows(rating.best, "Run a check to see ratings here.")}
        <h3>Worst rated</h3>
        ${ratingRows(rating.worst.filter((entry) => !rating.best.some((best) => best.domain === entry.domain)), rating.count ? "Rate more than five domains to see a separate worst list." : "—")}
      </article>`;
  }).join("");
  document.querySelectorAll(".grade-bar [data-share]").forEach((segment) => { segment.style.flexBasis = `${segment.dataset.share}%`; });

  document.querySelector("#dash-monitors").innerHTML = `
    <p class="form-hint">${escapeHtml(`${data.monitors.total} monitor(s), ${data.monitors.enabled} active · ${data.monitors.changes} change(s) and ${data.monitors.alerts} alert(s) in this period · ${Object.entries(data.monitors.byKind).map(([kind, count]) => `${kind} ${count}`).join(", ") || "none yet"}`)}</p>
    ${data.monitors.failing.length ? `<ol class="rating-list">${data.monitors.failing.map((monitor) => `
      <li>
        <span class="rating-grade ${monitor.status === "fail" ? "poor" : "fair"}">${monitor.status === "fail" ? "✕" : "!"}</span>
        <span class="rating-domain"><strong>${escapeHtml(monitor.target)}</strong><small>${escapeHtml(`${monitor.kindLabel} · ${monitor.summary || ""}`)}</small></span>
        <span class="rating-meta">${escapeHtml(monitor.username)}<small>${escapeHtml(monitor.changedAt ? relativeDate(monitor.changedAt) : "")}</small></span>
      </li>`).join("")}</ol>` : '<p class="stats-empty">All active monitors are OK.</p>'}`;

  const max = Math.max(1, ...data.usage.map((entry) => entry.count));
  document.querySelector("#dash-usage").innerHTML = data.usage.map((entry) => `
    <div class="stats-top-row">
      <div class="stats-top-label"><span>${escapeHtml(entry.action)}</span><strong>${entry.count.toLocaleString()}</strong></div>
      <svg class="stats-top-track" viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true"><rect width="100" height="5" rx="2.5" fill="#202020"/><rect width="${(entry.count / max) * 100}" height="5" rx="2.5" fill="#65d993"/></svg>
    </div>`).join("");

  document.querySelector("#dash-takeover").innerHTML = data.takeoverRisks.length
    ? `<ol class="rating-list">${data.takeoverRisks.map((risk) => `
      <li>
        <span class="rating-grade ${risk.grade === "risk" ? "poor" : "fair"}">${risk.grade === "risk" ? "✕" : "!"}</span>
        <span class="rating-domain"><strong>${escapeHtml(risk.domain)}</strong><small>${escapeHtml(`CNAME ${risk.detail}`)}</small></span>
        <span class="rating-meta">${escapeHtml(risk.grade === "risk" ? "Takeover possible" : "Dangling")}<small>${escapeHtml(relativeDate(risk.checkedAt))}</small></span>
      </li>`).join("")}</ol>`
    : '<p class="stats-empty">No takeover risks found by Magic scans in this period.</p>';
  insightsStatus.textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

async function loadInsights() {
  try {
    const response = await fetch(`/api/admin/insights?days=${insightsRange.value}`, { credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Insights could not be loaded.");
    renderInsights(data);
  } catch (error) {
    insightsStatus.textContent = error.message;
  }
}

insightsRange.addEventListener("change", loadInsights);
loadInsights();
setInterval(() => {
  if (!document.hidden) void loadInsights();
}, insightsRefreshMs);
