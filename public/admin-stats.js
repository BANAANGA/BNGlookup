const errorPanel = document.querySelector("#stats-error");
const statusPanel = document.querySelector("#stats-status");
const rangeSelect = document.querySelector("#stats-range");
const chartColors = ["#65d993", "#6f9cff", "#f5bd62", "#c58af9", "#fa8390", "#53d6d0", "#d8df74"];

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function renderTimeline(days) {
  const width = 800;
  const height = 250;
  const margin = { top: 20, right: 46, bottom: 37, left: 42 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const maxVisitors = Math.max(1, ...days.map((day) => day.visitors));
  const maxQueries = Math.max(1, ...days.map((day) => day.queries));
  const x = (index) => margin.left + (days.length <= 1
    ? plotWidth / 2
    : (index / (days.length - 1)) * plotWidth);
  const visitorY = (value) => margin.top + plotHeight - (value / maxVisitors) * plotHeight;
  const bars = days.map((day, index) => {
    const barWidth = Math.max(2, Math.min(12, plotWidth / days.length * 0.6));
    const barHeight = (day.queries / maxQueries) * plotHeight;
    return `<rect x="${x(index) - barWidth / 2}" y="${margin.top + plotHeight - barHeight}" width="${barWidth}" height="${barHeight}" rx="2" fill="#6f9cff" opacity="0.66"><title>${escapeHtml(day.date)}: ${day.queries} queries</title></rect>`;
  }).join("");
  const visitorPoints = days.map((day, index) => `${x(index)},${visitorY(day.visitors)}`).join(" ");
  const dots = days.map((day, index) => `
    <circle cx="${x(index)}" cy="${visitorY(day.visitors)}" r="3.5" fill="#65d993">
      <title>${escapeHtml(day.date)}: ${day.visitors} unique visitors</title>
    </circle>
  `).join("");
  const ticks = [0, 0.5, 1].map((fraction) => {
    const y = margin.top + plotHeight * fraction;
    const visitorTick = Math.round(maxVisitors * (1 - fraction));
    const queryTick = Math.round(maxQueries * (1 - fraction));
    return `<line x1="${margin.left}" y1="${y}" x2="${width - margin.right}" y2="${y}" class="chart-gridline"/>
      <text x="${margin.left - 8}" y="${y + 4}" text-anchor="end" class="chart-axis-label">${visitorTick}</text>
      <text x="${width - margin.right + 8}" y="${y + 4}" text-anchor="start" class="chart-axis-label">${queryTick}</text>`;
  }).join("");
  const labelIndexes = [...new Set([0, Math.floor((days.length - 1) / 4), Math.floor((days.length - 1) / 2), Math.floor(3 * (days.length - 1) / 4), days.length - 1])];
  const labels = labelIndexes.map((index) => {
    const label = days[index].date.slice(5);
    return `<text x="${x(index)}" y="${height - 10}" text-anchor="middle" class="chart-axis-label">${escapeHtml(label)}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Visitors and query volume by day">
    ${ticks}${bars}
    <polyline points="${visitorPoints}" fill="none" stroke="#65d993" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
    ${dots}${labels}
  </svg>`;
}

function renderQueryMix(queryTypes) {
  const container = document.querySelector("#stats-query-mix");
  const total = queryTypes.reduce((sum, entry) => sum + entry.count, 0);
  if (!total) {
    container.innerHTML = '<p class="stats-empty">No query activity in this period.</p>';
    return;
  }
  const circumference = 2 * Math.PI * 42;
  let consumed = 0;
  const segments = queryTypes.map((entry, index) => {
    const length = (entry.count / total) * circumference;
    const offset = -consumed;
    consumed += length;
    return `<circle cx="60" cy="60" r="42" fill="none" stroke="${chartColors[index % chartColors.length]}" stroke-width="18" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${offset}" transform="rotate(-90 60 60)"><title>${escapeHtml(entry.label)}: ${entry.count}</title></circle>`;
  }).join("");
  container.innerHTML = `
    <svg class="stats-pie" viewBox="0 0 120 120" aria-hidden="true">
      <circle cx="60" cy="60" r="42" fill="none" stroke="#252525" stroke-width="18"/>
      ${segments}
      <text x="60" y="57" text-anchor="middle" class="stats-pie-total">${total}</text>
      <text x="60" y="72" text-anchor="middle" class="stats-pie-caption">queries</text>
    </svg>
    <ul class="stats-pie-legend">
      ${queryTypes.map((entry, index) => `
        <li><i class="stats-color-${index % chartColors.length}"></i>
          <span>${escapeHtml(entry.label)}</span><strong>${entry.count}</strong>
        </li>
      `).join("")}
    </ul>
  `;
}

function renderTopQueries(queries) {
  const container = document.querySelector("#stats-top-queries");
  if (!queries.length) {
    container.innerHTML = '<p class="stats-empty">No named queries in this period.</p>';
    return;
  }
  const maxCount = queries[0].count;
  container.innerHTML = queries.map((entry) => `
    <div class="stats-top-row">
      <div class="stats-top-label"><span title="${escapeHtml(entry.name)}">${escapeHtml(entry.name)}</span><strong>${entry.count}</strong></div>
      <svg class="stats-top-track" viewBox="0 0 100 5" preserveAspectRatio="none" aria-hidden="true"><rect width="100" height="5" rx="2.5" fill="#202020"/><rect class="stats-top-fill" width="${(entry.count / maxCount) * 100}" height="5" rx="2.5" fill="#65d993"/></svg>
    </div>
  `).join("");
}

async function loadStats() {
  errorPanel.hidden = true;
  statusPanel.textContent = "Loading statistics…";
  try {
    const response = await fetch(`/api/admin/stats?days=${rangeSelect.value}`, {
      credentials: "same-origin",
      headers: { accept: "application/json" },
    });
    const data = await response.json();
    if (response.status === 401) {
      window.location.assign(`/login.html?next=${encodeURIComponent("/admin-stats.html")}`);
      return;
    }
    if (!response.ok) throw new Error(data.error || "Unable to load statistics.");

    document.querySelector("#stat-visitors").textContent = data.totals.visitors.toLocaleString();
    document.querySelector("#stat-queries").textContent = data.totals.queries.toLocaleString();
    document.querySelector("#stat-users").textContent = data.totals.signedInUsers.toLocaleString();
    document.querySelector("#stat-failures").textContent = data.totals.failedQueries.toLocaleString();
    document.querySelector("#stats-period").textContent = `${data.startDate} – ${data.endDate} UTC`;
    document.querySelector("#stats-timeline").innerHTML = renderTimeline(data.timeline);
    renderQueryMix(data.queryTypes);
    renderTopQueries(data.topQueries);
    statusPanel.textContent = data.totals.queries
      ? `Based on ${data.totals.queries.toLocaleString()} retained query log entries.`
      : "No query activity recorded in this period.";
  } catch (error) {
    statusPanel.textContent = "";
    errorPanel.textContent = error.message;
    errorPanel.hidden = false;
  }
}

document.querySelector("#admin-logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.assign("/login.html");
});

rangeSelect.addEventListener("change", loadStats);
loadStats();
