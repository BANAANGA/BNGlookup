const form = document.querySelector("#monitor-form");
const kindSelect = document.querySelector("#monitor-kind");
const targetInput = document.querySelector("#monitor-target");
const intervalSelect = document.querySelector("#monitor-interval");
const notifyInput = document.querySelector("#monitor-notify");
const kindHint = document.querySelector("#monitor-kind-hint");
const list = document.querySelector("#monitor-list");
const statusPanel = document.querySelector("#monitor-status");
const errorPanel = document.querySelector("#monitor-error");
const mailNotice = document.querySelector("#monitor-mail-notice");
let monitors = [];
let limit = 25;

const kindHints = {
  website: ["https://example.com", "Alerts when the site stops answering, returns an error or starts redirecting elsewhere."],
  certificate: ["example.com or mail.example.com:465", "Alerts 14 days before the certificate expires, when it becomes untrusted, and when it is replaced."],
  dns: ["example.com", "Alerts when A, AAAA, CNAME, MX, NS, TXT or CAA records change."],
  email: ["example.com", "Alerts when MX, SPF, DMARC or the MTA-STS mode change, or when SPF or DMARC break."],
  blocklist: ["example.com or 203.0.113.10", "Alerts when the domain or its address appears on (or leaves) a spam blocklist."],
};
const statusLabels = { ok: ["found", "OK"], warn: ["warning", "Warning"], fail: ["danger", "Problem"], pending: ["missing", "Pending"] };

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: options.body ? { "content-type": "application/json" } : {},
  });
  const data = await response.json();
  if (response.status === 401) {
    window.location.assign(`/login.html?next=${encodeURIComponent("/monitors.html")}`);
    throw new Error("Log in to continue.");
  }
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function showError(message) {
  errorPanel.textContent = message;
  errorPanel.hidden = !message;
}

function relative(iso) {
  if (!iso) return "never";
  const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  const format = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const absolute = Math.abs(seconds);
  if (absolute < 60) return format.format(seconds, "second");
  if (absolute < 3600) return format.format(Math.round(seconds / 60), "minute");
  if (absolute < 86400) return format.format(Math.round(seconds / 3600), "hour");
  return format.format(Math.round(seconds / 86400), "day");
}

function render() {
  statusPanel.textContent = monitors.length
    ? `${monitors.length} of ${limit} monitors · ${monitors.filter((monitor) => monitor.status === "fail").length} with problems`
    : "No monitors yet. Add one above, or use “Monitor this” under a lookup result.";
  list.innerHTML = monitors.map((monitor) => {
    const [statusClass, statusLabel] = statusLabels[monitor.status] || statusLabels.pending;
    return `
      <article class="monitor-card ${monitor.enabled ? "" : "paused"}" data-id="${monitor.id}">
        <div class="monitor-head">
          <span class="email-auth-status ${statusClass}">${escapeHtml(monitor.enabled ? statusLabel : "Paused")}</span>
          <strong>${escapeHtml(monitor.kindLabel)}</strong>
          <span class="monitor-target">${escapeHtml(monitor.target)}</span>
        </div>
        <p class="monitor-summary">${escapeHtml(monitor.summary || "Not checked yet.")}</p>
        <p class="monitor-meta">${escapeHtml(`Every ${monitor.intervalHours} h · checked ${relative(monitor.lastRunAt)}${monitor.enabled ? ` · next ${relative(monitor.nextRunAt)}` : ""}${monitor.lastChangeAt ? ` · last change ${relative(monitor.lastChangeAt)}` : ""} · ${monitor.notify ? "email alerts on" : "no email alerts"}`)}</p>
        <div class="monitor-actions">
          <button type="button" data-action="run">Check now</button>
          <button type="button" data-action="toggle">${monitor.enabled ? "Pause" : "Resume"}</button>
          <button type="button" data-action="notify">${monitor.notify ? "Mute alerts" : "Alert me"}</button>
          <select data-action="interval" aria-label="Check interval">${[1, 6, 12, 24].map((hours) => `<option value="${hours}" ${hours === monitor.intervalHours ? "selected" : ""}>every ${hours} h</option>`).join("")}</select>
          <button type="button" data-action="delete" class="history-clear">Delete</button>
        </div>
        ${monitor.events.length ? `<details class="monitor-events"><summary>History (${monitor.events.length})</summary><ul>${monitor.events.map((event) => `
          <li class="monitor-event ${escapeHtml(event.level)}"><time>${escapeHtml(new Date(event.at).toLocaleString())}</time><span>${escapeHtml(event.message)}</span></li>`).join("")}</ul></details>` : ""}
      </article>`;
  }).join("");
}

function replaceMonitor(updated) {
  monitors = monitors.map((monitor) => (monitor.id === updated.id ? updated : monitor));
  render();
}

async function load() {
  try {
    const data = await api("/api/monitors");
    monitors = data.monitors;
    limit = data.limit;
    kindSelect.innerHTML = Object.entries(data.kinds).map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("");
    intervalSelect.innerHTML = data.intervals.map((hours) => `<option value="${hours}" ${hours === 24 ? "selected" : ""}>${hours === 1 ? "hour" : `${hours} hours`}</option>`).join("");
    if (!data.mailEnabled || !data.email) {
      mailNotice.hidden = false;
      mailNotice.innerHTML = !data.mailEnabled
        ? "Email is not set up on this server, so changes are only recorded here. An administrator can configure SMTP in Settings → Email."
        : 'Add an email address on <a href="/my-account.html">My account</a> to receive alerts; until then changes are only recorded here.';
    }
    const params = new URLSearchParams(window.location.search);
    if (params.get("kind") && data.kinds[params.get("kind")]) kindSelect.value = params.get("kind");
    if (params.get("target")) targetInput.value = params.get("target").slice(0, 2048);
    updateHint();
    render();
  } catch (error) {
    statusPanel.textContent = "";
    showError(error.message);
  }
}

function updateHint() {
  const [placeholder, hint] = kindHints[kindSelect.value] || ["", ""];
  targetInput.placeholder = placeholder;
  kindHint.textContent = hint;
}

kindSelect.addEventListener("change", updateHint);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("");
  const button = document.querySelector("#monitor-add");
  button.disabled = true;
  statusPanel.textContent = "Adding and running the first check…";
  try {
    const created = await api("/api/monitors", {
      method: "POST",
      body: JSON.stringify({ kind: kindSelect.value, target: targetInput.value, intervalHours: Number(intervalSelect.value), notify: notifyInput.checked }),
    });
    monitors.push(created);
    targetInput.value = "";
    history.replaceState(null, "", "/monitors.html");
    render();
  } catch (error) {
    showError(error.message);
    render();
  } finally {
    button.disabled = false;
  }
});

list.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const card = button.closest("[data-id]");
  const monitor = monitors.find((entry) => String(entry.id) === card.dataset.id);
  showError("");
  button.disabled = true;
  try {
    if (button.dataset.action === "run") {
      button.textContent = "Checking…";
      replaceMonitor(await api(`/api/monitors/${monitor.id}/run`, { method: "POST", body: "{}" }));
    } else if (button.dataset.action === "toggle") {
      replaceMonitor(await api(`/api/monitors/${monitor.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !monitor.enabled }) }));
    } else if (button.dataset.action === "notify") {
      replaceMonitor(await api(`/api/monitors/${monitor.id}`, { method: "PATCH", body: JSON.stringify({ notify: !monitor.notify }) }));
    } else if (button.dataset.action === "delete") {
      if (!window.confirm(`Delete the ${monitor.kindLabel} monitor for ${monitor.target}?`)) {
        button.disabled = false;
        return;
      }
      await api(`/api/monitors/${monitor.id}`, { method: "DELETE" });
      monitors = monitors.filter((entry) => entry.id !== monitor.id);
      render();
    }
  } catch (error) {
    showError(error.message);
    render();
  }
});

list.addEventListener("change", async (event) => {
  const select = event.target.closest("select[data-action='interval']");
  if (!select) return;
  const id = select.closest("[data-id]").dataset.id;
  try {
    replaceMonitor(await api(`/api/monitors/${id}`, { method: "PATCH", body: JSON.stringify({ intervalHours: Number(select.value) }) }));
  } catch (error) {
    showError(error.message);
  }
});

load();
