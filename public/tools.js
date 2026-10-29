// Web check, email header analyzer, DMARC report viewer, record builder and bulk domain check.
// Shares helpers (escapeHtml, copyableResult, renderFacts, ...) with app.js, which loads first.

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await readApiResponse(response);
  if (response.status === 401) throw Object.assign(new Error(data.error || "Log in to continue."), { loginRequired: true });
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

async function getJson(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  const data = await readApiResponse(response);
  if (response.status === 401) throw Object.assign(new Error(data.error || "Log in to continue."), { loginRequired: true });
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

// Bar widths are set through the CSSOM because the CSP forbids inline style attributes.
function applyBars(root) {
  root.querySelectorAll("[data-pct]").forEach((bar) => {
    bar.style.width = `${Math.max(0, Math.min(100, Number(bar.dataset.pct) || 0))}%`;
  });
}

function percentBar(value, state = "") {
  return `<span class="pct-bar ${state}"><span data-pct="${escapeHtml(value)}"></span></span>`;
}

function pill(state, label) {
  const classes = { ok: "found", pass: "found", warn: "warning", fail: "danger", bad: "danger", info: "missing", none: "missing" };
  return `<span class="email-auth-status ${classes[state] || "missing"}">${escapeHtml(label)}</span>`;
}

function scoreTiles(tiles) {
  const icons = { ok: "✓", warn: "!", bad: "✕", none: "–" };
  return `<div class="mail-scorecard">${tiles.map(([label, state, value]) => `
    <div class="mail-score ${state}">
      <span class="mail-score-icon" aria-hidden="true">${icons[state] || "–"}</span>
      <span class="mail-score-text"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></span>
    </div>`).join("")}</div>`;
}

function dataTable(head, rows, className = "") {
  if (!rows.length) return "";
  return `<div class="dns-results-table-wrap"><table class="dns-results-table net-table ${className}">
    <thead><tr>${head.map((cell) => `<th>${escapeHtml(cell)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
}

function formatSeconds(seconds) {
  if (seconds === null || seconds === undefined) return "";
  const sign = seconds < 0 ? "−" : "";
  const value = Math.abs(seconds);
  if (value < 60) return `${sign}${value} s`;
  if (value < 3600) return `${sign}${Math.floor(value / 60)} min ${value % 60} s`;
  return `${sign}${Math.floor(value / 3600)} h ${Math.floor((value % 3600) / 60)} min`;
}

async function runToolMode(toolMode, lookupName) {
  if (toolMode === "web") {
    const data = await getJson(`/api/web-check?${new URLSearchParams({ name: lookupName })}`);
    renderWebCheckResult(data);
    return { data, subject: data.finalUrl || lookupName };
  }
  if (toolMode === "bulk-domains") {
    const data = await postJson("/api/bulk-domain-check", { domains: bulkDomainsInput.value });
    renderBulkDomainsResult(data);
    return { data, subject: `${data.rows.length} domains` };
  }
  if (toolMode === "email-headers") {
    const data = await postJson("/api/email-headers", { headers: headersInput.value });
    renderHeadersResult(data);
    return { data, subject: data.summary.subject || data.summary.from || "message" };
  }
  if (toolMode === "dmarc-reports") {
    const data = await readDmarcReports([...dmarcFilesInput.files]);
    renderDmarcReportResult(data);
    return { data, subject: `${data.domains.join(", ") || "reports"} (${data.reports.length} reports)` };
  }
  const getTools = {
    "dns-health": ["/api/dns-health", renderDnsHealthResult, (data) => data.zone || data.domain],
    reputation: ["/api/reputation", renderReputationResult, (data) => data.target],
    lookalike: ["/api/lookalike", renderLookalikeResult, (data) => data.domain],
    "spf-flatten": ["/api/spf-flatten", renderSpfFlattenResult, (data) => data.domain],
  };
  if (getTools[toolMode]) {
    const [path, render, subject] = getTools[toolMode];
    const data = await getJson(`${path}?${new URLSearchParams({ name: lookupName })}`);
    render(data);
    return { data, subject: subject(data) };
  }
  if (toolMode === "ip-calc") {
    const data = calculateIp(lookupName);
    renderIpCalcResult(data);
    return { data, subject: data.input };
  }
  throw new Error("Unknown tool.");
}

// ---------------------------------------------------------------- Web check

function webCheckHtml(data) {
  const heading = `
    <div class="result-heading">
      <div><p class="eyebrow">WEB CHECK</p><h2>${copyableResult(data.finalUrl || data.startUrl || data.input)}</h2>${data.title ? `<p class="web-title">${escapeHtml(data.title)}</p>` : ""}</div>
      ${data.grade ? `<span class="ssllabs-grade tls-grade-large ${tlsGradeClass(data.grade)}" title="Security header grade">${escapeHtml(data.grade)}</span>` : ""}
    </div>`;
  const hopRows = (data.hops || []).map((hop, index) => `
    <tr>
      <td>${index + 1}</td>
      <td>${copyableResult(hop.url)}</td>
      <td>${hop.error ? `<span class="dnssec-bad">${escapeHtml(hop.error)}</span>` : pill(hop.status >= 400 ? "fail" : hop.status >= 300 ? "info" : "ok", String(hop.status))}</td>
      <td>${escapeHtml(hop.address || "")}</td>
      <td>${hop.timeMs !== undefined ? `${escapeHtml(hop.timeMs)} ms` : ""}</td>
    </tr>`);
  if (data.error) {
    return `${heading}<p class="detail-notice">${escapeHtml(data.error)}</p>${dataTable(["#", "URL", "Status", "Address", "Time"], hopRows)}`;
  }
  const tls = data.tls;
  const certState = !data.https ? "bad" : !tls ? "none" : !tls.authorized || tls.daysRemaining < 0 ? "bad" : tls.daysRemaining < 14 ? "warn" : "ok";
  const tiles = [
    ["HTTPS", data.https ? (data.redirectsToHttps === false ? "warn" : "ok") : "bad", data.https ? (data.redirectsToHttps ? "HTTP redirects to HTTPS" : data.httpUnavailable ? "HTTPS only" : "HTTPS") : "Not used"],
    ["Certificate", certState, !tls ? "None" : !tls.authorized ? "Not trusted" : tls.daysRemaining === null ? "Trusted" : `${tls.daysRemaining} days left`],
    ["HTTP/2", data.http2 ? "ok" : data.https ? "warn" : "none", data.http2 ? "Supported" : data.http2 === false ? "Not supported" : "Not tested"],
    ["HTTP/3", data.http3 ? "ok" : "none", data.http3 ? "Advertised (Alt-Svc)" : "Not advertised"],
    ["Compression", data.compression ? "ok" : "warn", data.compression || "None"],
    ["Response", data.finalStatus >= 400 ? "bad" : "ok", `HTTP ${data.finalStatus} · ${data.firstByteMs} ms to first byte`],
    ["Redirects", (data.hops || []).length > 3 ? "warn" : "ok", `${Math.max(0, (data.hops || []).length - 1)}`],
    ["Headers", data.score >= 85 ? "ok" : data.score >= 55 ? "warn" : "bad", `${data.grade} · ${data.score}/100`],
  ];
  const stateLabels = { pass: "Pass", warn: "Warning", fail: "Missing", info: "Optional" };
  const checkRows = (data.checks || []).map((check) => `
    <tr>
      <td>${escapeHtml(check.label)}</td>
      <td>${pill(check.state, stateLabels[check.state] || check.state)}</td>
      <td>${escapeHtml(check.message)}${check.value ? `<br><code class="web-header-value">${escapeHtml(check.value)}</code>` : ""}</td>
    </tr>`);
  const cookieRows = (data.cookies || []).map((cookie) => `
    <tr>
      <td>${escapeHtml(cookie.name)}</td>
      <td>${cookie.secure ? "Yes" : '<span class="dnssec-bad">No</span>'}</td>
      <td>${cookie.httpOnly ? "Yes" : "No"}</td>
      <td>${escapeHtml(cookie.sameSite || "not set")}</td>
    </tr>`);
  return `
    ${heading}
    ${scoreTiles(tiles)}
    ${renderMailFixList([["", data.issues]])}
    <section class="email-auth">
      <h3>Redirect chain</h3>
      ${data.httpUnavailable ? `<p class="detail-notice">${escapeHtml(`Plain HTTP was not reachable (${data.httpUnavailable}), so the check started over HTTPS.`)}</p>` : ""}
      ${dataTable(["#", "URL", "Status", "Address", "Time"], hopRows)}
    </section>
    <section class="email-auth">
      <h3>Security headers ${pill(data.score >= 85 ? "ok" : data.score >= 55 ? "warn" : "fail", `${data.grade} · ${data.score}/100`)}</h3>
      ${dataTable(["Check", "Result", "Details"], checkRows, "web-checks-table")}
      <p class="scan-disclaimer">The grade starts at 100 and deducts points for missing or weak headers on the final page. It covers HTTP response headers only, not the site's code.</p>
    </section>
    ${cookieRows.length ? `<section class="email-auth"><h3>Cookies set by the page</h3>${dataTable(["Cookie", "Secure", "HttpOnly", "SameSite"], cookieRows)}</section>` : ""}
    ${webExtrasHtml(data)}
    <section class="email-auth">
      <h3>Connection</h3>
      ${renderFacts([
        ["Final URL", data.finalUrl],
        ["Status", data.finalStatus ? `HTTP ${data.finalStatus}` : ""],
        ["Server", data.server],
        ["Content type", data.contentType],
        ["Page size", data.pageBytes ? `${(data.pageBytes / 1024).toFixed(1)} KB${data.compression ? ` (${data.compression})` : ""}` : ""],
        ["TLS", tls?.protocol],
        ["Certificate expires", tls?.validTo ? `${new Date(tls.validTo).toLocaleDateString()} (${tls.daysRemaining} days)` : ""],
        ["Alt-Svc", data.altSvc],
      ])}
      <details class="web-raw-headers"><summary>All response headers (${escapeHtml((data.headers || []).length)})</summary>
        <dl>${(data.headers || []).map(([name, value]) => `<dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>
      </details>
    </section>
    <p class="scan-disclaimer">${escapeHtml(`Completed in ${data.durationMs} ms. Redirects are followed up to 10 times; every new host is checked before connecting.`)}</p>`;
}

function renderWebCheckResult(data) {
  resultPanel.innerHTML = webCheckHtml(data);
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- Subdomain takeover (Magic scan)

function renderTakeoverSection(takeover) {
  if (!takeover) return "";
  const labels = { vulnerable: ["danger", "Takeover possible"], dangling: ["warning", "Dangling CNAME"], ok: ["found", "Claimed"] };
  const rows = (takeover.findings || []).map((finding) => {
    const [state, label] = labels[finding.status] || labels.ok;
    return `
      <tr>
        <td>${copyableResult(finding.host)}</td>
        <td>${copyableResult(finding.cname)}</td>
        <td>${escapeHtml(finding.service || "")}</td>
        <td><span class="email-auth-status ${state}">${escapeHtml(label)}</span></td>
        <td>${escapeHtml(finding.evidence || "")}</td>
      </tr>`;
  });
  const status = takeover.vulnerable
    ? `<span class="email-auth-status danger">${escapeHtml(`${takeover.vulnerable} at risk`)}</span>`
    : takeover.dangling ? `<span class="email-auth-status warning">${escapeHtml(`${takeover.dangling} dangling`)}</span>`
      : '<span class="email-auth-status found">None found</span>';
  return `
    <section class="email-auth">
      <h3>Subdomain takeover ${status}</h3>
      ${rows.length ? dataTable(["Host", "CNAME target", "Service", "Status", "Evidence"], rows) : `<p class="empty-result">${escapeHtml(takeover.checked ? `None of the ${takeover.checked} CNAME record(s) point to an unclaimed service.` : "No CNAME records were found to check.")}</p>`}
      <p class="scan-disclaimer">Checks found CNAMEs for targets that no longer exist (NXDOMAIN) and for services such as GitHub Pages, Heroku, Azure, S3, Shopify and Netlify that show an "unclaimed" page. Someone could register the missing resource and serve content on your subdomain. Remove or fix such records.</p>
    </section>`;
}

// ---------------------------------------------------------------- Email header analyzer

function renderHeadersResult(data) {
  const auth = data.authentication || {};
  const summary = data.summary || {};
  const resultState = (result) => (!result ? "none" : result === "pass" ? "ok" : ["none", "neutral", "softfail", "temperror"].includes(result) ? "warn" : "bad");
  const dkimResult = auth.dkim?.length ? (auth.dkim.some((entry) => entry.result === "pass") ? "pass" : auth.dkim[0].result) : null;
  const spam = data.spam || [];
  const spamVerdict = spam.find((signal) => /^spam/i.test(signal.verdict || ""));
  const tiles = [
    ["SPF", resultState(auth.spf?.result), auth.spf ? `${auth.spf.result}${auth.spf.domain ? ` · ${auth.spf.domain}` : ""}` : "No result"],
    ["DKIM", resultState(dkimResult), dkimResult ? `${dkimResult}${auth.dkim.find((entry) => entry.domain)?.domain ? ` · ${auth.dkim.find((entry) => entry.domain).domain}` : ""}` : data.dkimSignatures?.length ? "Signed, not verified" : "Not signed"],
    ["DMARC", resultState(auth.dmarc?.result), auth.dmarc ? `${auth.dmarc.result}${auth.dmarc.policy ? ` · p=${auth.dmarc.policy.toLowerCase()}` : ""}` : "No result"],
    ["Alignment", auth.alignment?.dkim || auth.alignment?.spf ? "ok" : auth.alignment?.dkim === false && auth.alignment?.spf === false ? "bad" : "none",
      [auth.alignment?.spf === null || auth.alignment?.spf === undefined ? null : `SPF ${auth.alignment.spf ? "✓" : "✕"}`, auth.alignment?.dkim === null || auth.alignment?.dkim === undefined ? null : `DKIM ${auth.alignment.dkim ? "✓" : "✕"}`].filter(Boolean).join(" · ") || "Unknown"],
    ["Spam filter", spamVerdict ? "bad" : spam.length ? "ok" : "none", spamVerdict ? `${spamVerdict.source}: spam` : spam.length ? `${spam[0].source}: ${spam[0].verdict}` : "No verdict headers"],
    ["Delivery time", summary.totalDelaySeconds === null ? "none" : summary.totalDelaySeconds > 600 ? "warn" : "ok", summary.totalDelaySeconds === null ? "Unknown" : formatSeconds(summary.totalDelaySeconds)],
  ];
  const maxDelay = Math.max(1, ...(data.hops || []).map((hop) => Math.max(0, hop.delaySeconds || 0)));
  const hopRows = (data.hops || []).map((hop) => {
    const ptr = data.ptrLookups?.[hop.ip]?.answers?.join(", ");
    const geo = data.geolocations?.[hop.ip];
    const place = geo && !geo.error ? [geo.city, geo.country].filter(Boolean).join(", ") : "";
    return `
      <tr>
        <td>${escapeHtml(hop.index)}</td>
        <td>${escapeHtml(hop.from || "—")}${hop.ip ? `<br>${copyableResult(hop.ip)}` : ""}${ptr ? `<br><span class="trace-silent">${escapeHtml(ptr)}</span>` : ""}${place ? `<br><span class="trace-silent">${escapeHtml(place)}</span>` : ""}</td>
        <td>${escapeHtml(hop.by || "")}</td>
        <td>${escapeHtml(hop.protocol || "")} ${hop.tls ? pill("ok", hop.tlsVersion || "TLS") : hop.protocol ? pill("info", "no TLS") : ""}</td>
        <td>${hop.date ? escapeHtml(new Date(hop.date).toLocaleString()) : ""}</td>
        <td class="hop-delay">${hop.delaySeconds === null ? "" : `${escapeHtml(formatSeconds(hop.delaySeconds))}${percentBar(Math.round(Math.max(0, hop.delaySeconds) / maxDelay * 100), hop.delaySeconds > 300 ? "warn" : "")}`}</td>
      </tr>`;
  });
  const authRows = (auth.all || []).flatMap((header) => header.results.map((entry) => `
    <tr>
      <td>${escapeHtml(header.authservId || "")}</td>
      <td>${escapeHtml(entry.method.toUpperCase())}</td>
      <td>${pill(entry.result === "pass" ? "ok" : ["none", "neutral"].includes(entry.result) ? "info" : "fail", entry.result)}</td>
      <td>${escapeHtml(Object.entries(entry.properties).map(([key, value]) => `${key}=${value}`).join(" "))}${entry.comment ? `<br><span class="trace-silent">${escapeHtml(entry.comment)}</span>` : ""}</td>
    </tr>`));
  const spamRows = spam.map((signal) => `
    <tr><td>${escapeHtml(signal.source)}</td><td>${pill(/^spam/i.test(signal.verdict || "") ? "fail" : "ok", signal.verdict || "?")}</td><td>${escapeHtml([signal.score, signal.threshold ? `threshold ${signal.threshold}` : null].filter(Boolean).join(" · "))}</td><td>${escapeHtml(signal.detail || "")}</td></tr>`);
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">EMAIL HEADERS</p><h2>${escapeHtml(summary.subject || "(no subject)")}</h2><p class="web-title">${escapeHtml(summary.from || "")}</p></div>
      <span class="status-badge ${auth.dmarc?.result === "pass" ? "success" : "warning"}">${escapeHtml(auth.dmarc ? `DMARC ${auth.dmarc.result}` : "No DMARC result")}</span>
    </div>
    ${scoreTiles(tiles)}
    ${renderMailFixList([["", data.issues]])}
    <section class="email-auth">
      <h3>Message</h3>
      ${renderFacts([
        ["From", summary.from], ["To", summary.to], ["Date", summary.date ? new Date(summary.date).toLocaleString() : ""],
        ["Return-Path", summary.returnPath], ["Reply-To", summary.replyTo], ["Message-ID", summary.messageId],
        ["Sent with", summary.mailer], ["Unsubscribe", summary.listUnsubscribe ? (summary.oneClickUnsubscribe ? "List-Unsubscribe (one-click)" : "List-Unsubscribe") : ""],
      ])}
    </section>
    <section class="email-auth">
      <h3>Delivery path ${pill("info", `${(data.hops || []).length} hop(s)`)}</h3>
      ${dataTable(["#", "From", "By", "Protocol", "Received", "Delay"], hopRows, "hops-table") || '<p class="empty-result">No Received headers were found.</p>'}
      <p class="scan-disclaimer">Oldest hop first. The delay is the time since the previous hop (the first hop is compared with the Date header). Clocks on different servers are not always in sync.</p>
    </section>
    <section class="email-auth">
      <h3>Authentication results</h3>
      ${dataTable(["Checked by", "Method", "Result", "Details"], authRows) || '<p class="empty-result">No Authentication-Results header was found; the receiving server may not add one.</p>'}
      ${data.dkimSignatures?.length ? `<h4 class="tool-subheading">DKIM signatures</h4>${dataTable(["Domain (d=)", "Selector (s=)", "Algorithm", "Signed headers"], data.dkimSignatures.map((signature) => `<tr><td>${escapeHtml(signature.domain || "")}</td><td>${escapeHtml(signature.selector || "")}</td><td>${escapeHtml(signature.algorithm || "")}</td><td>${escapeHtml(signature.headers ?? "")}</td></tr>`))}` : ""}
    </section>
    ${spamRows.length ? `<section class="email-auth"><h3>Spam filter verdicts</h3>${dataTable(["Filter", "Verdict", "Score", "Details"], spamRows)}</section>` : ""}
    <section class="email-auth">
      <details class="web-raw-headers"><summary>All headers (${escapeHtml(data.headerCount)})</summary>
        <dl>${(data.headers || []).map(([name, value]) => `<dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>
      </details>
    </section>`;
  applyBars(resultPanel);
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- Bulk domain check

let bulkDomainRows = [];

function bulkCells(row) {
  const cert = row.certificate || {};
  const certState = cert.error ? "info" : !cert.authorized || cert.daysRemaining < 0 ? "fail" : cert.daysRemaining < 14 ? "warn" : "ok";
  const certLabel = cert.error ? cert.error : !cert.authorized ? "Not trusted" : cert.daysRemaining < 0 ? "Expired" : `${cert.daysRemaining} days`;
  const dmarcState = !row.dmarc?.found ? "fail" : ["reject", "quarantine"].includes(row.dmarc.policy) ? "ok" : "warn";
  const spfState = !row.spf?.found ? "fail" : row.spf.lookups === null || row.spf.lookups > 10 ? "fail" : row.spf.issues ? "warn" : "ok";
  const listed = row.blocklist?.listed || 0;
  return {
    mx: row.mx ? [row.mx.count ? "ok" : "warn", row.mx.count ? `${row.mx.count} · ${row.mx.providers.join(", ") || row.mx.hosts[0]}` : "None"] : ["info", "?"],
    spf: row.spf ? [spfState, row.spf.found ? `${row.spf.all || "no all"} · ${row.spf.lookups ?? "?"}/10` : "Missing"] : ["info", "?"],
    dmarc: row.dmarc ? [dmarcState, row.dmarc.found ? `p=${row.dmarc.policy || "?"}` : "Missing"] : ["info", "?"],
    cert: [certState, certLabel],
    blocklist: row.blocklist ? [listed ? "fail" : "ok", listed ? `Listed (${listed})` : "Clean"] : ["info", "?"],
  };
}

function renderBulkDomainsResult(data) {
  bulkDomainRows = data.rows || [];
  const counts = { dmarcMissing: 0, spfMissing: 0, certIssues: 0, listed: 0 };
  const rows = bulkDomainRows.map((row) => {
    if (row.error) return `<tr><td>${copyableResult(row.domain)}</td><td colspan="5"><span class="dnssec-bad">${escapeHtml(row.error)}</span></td></tr>`;
    const cells = bulkCells(row);
    if (!row.dmarc?.found) counts.dmarcMissing += 1;
    if (!row.spf?.found) counts.spfMissing += 1;
    if (["fail", "warn"].includes(cells.cert[0])) counts.certIssues += 1;
    if (row.blocklist?.listed) counts.listed += 1;
    const cell = ([state, label], title = "") => `<td>${pill(state, label)}${title ? `<br><span class="trace-silent">${escapeHtml(title)}</span>` : ""}</td>`;
    return `
      <tr>
        <td>${copyableResult(row.domain)}${row.address ? `<br><span class="trace-silent">${escapeHtml(row.address)}</span>` : ""}</td>
        ${cell(cells.mx)}
        ${cell(cells.spf)}
        ${cell(cells.dmarc)}
        ${cell(cells.cert, row.certificate?.issuer?.match(/O=([^,]+)/)?.[1] || "")}
        ${cell(cells.blocklist, (row.blocklist?.lists || []).join(", "))}
      </tr>`;
  });
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">BULK DOMAIN CHECK</p><h2>${escapeHtml(`${bulkDomainRows.length} domain(s)`)}</h2></div>
      <button type="button" class="dash-version-check" id="bulk-export-csv">⬇ Export CSV</button>
    </div>
    ${scoreTiles([
      ["Domains", "ok", `${bulkDomainRows.length} checked`],
      ["No DMARC", counts.dmarcMissing ? "bad" : "ok", String(counts.dmarcMissing)],
      ["No SPF", counts.spfMissing ? "bad" : "ok", String(counts.spfMissing)],
      ["Certificate issues", counts.certIssues ? "warn" : "ok", String(counts.certIssues)],
    ])}
    ${data.invalid?.length ? `<p class="detail-notice">${escapeHtml(`Skipped invalid entries: ${data.invalid.join(", ")}`)}</p>` : ""}
    ${dataTable(["Domain", "MX", "SPF", "DMARC", "HTTPS certificate", "Blocklists"], rows, "bulk-domains-table")}
    <p class="scan-disclaimer">${escapeHtml(`Completed in ${(data.durationMs / 1000).toFixed(1)} s. Certificates are checked on port 443 of the domain's first address; blocklists cover the domain and that address.`)}</p>`;
  resultPanel.hidden = false;
}

function csvEscape(value) {
  const text = String(value ?? "");
  return /[",\n\r]/.test(text) || /^[=+\-@]/.test(text) ? `"${text.replace(/^([=+\-@])/, "'$1").replace(/"/g, '""')}"` : text;
}

resultPanel.addEventListener("click", (event) => {
  if (!event.target.closest("#bulk-export-csv")) return;
  const header = ["domain", "address", "mx_count", "mx_providers", "mx_hosts", "spf_found", "spf_all", "spf_lookups", "dmarc_found", "dmarc_policy", "cert_trusted", "cert_days_remaining", "cert_valid_to", "cert_error", "blocklists_listed", "blocklists", "error"];
  const lines = bulkDomainRows.map((row) => [
    row.domain, row.address, row.mx?.count, row.mx?.providers?.join("; "), row.mx?.hosts?.join("; "),
    row.spf?.found, row.spf?.all, row.spf?.lookups, row.dmarc?.found, row.dmarc?.policy,
    row.certificate?.authorized, row.certificate?.daysRemaining, row.certificate?.validTo, row.certificate?.error,
    row.blocklist?.listed, row.blocklist?.lists?.join("; "), row.error,
  ].map(csvEscape).join(","));
  const blob = new Blob([`${header.join(",")}\r\n${lines.join("\r\n")}\r\n`], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `bulk-domain-check-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
});

// ---------------------------------------------------------------- DMARC aggregate reports

const dmarcLimits = { files: 50, fileBytes: 20 * 1024 * 1024, xmlBytes: 50 * 1024 * 1024 };

async function inflate(bytes, format) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > dmarcLimits.xmlBytes) {
      await reader.cancel();
      throw new Error("A report is too large after decompression.");
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(await new Blob(chunks).arrayBuffer());
}

// Reads the XML files inside a .zip using its central directory (stored or deflated entries).
async function unzipXml(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = -1;
  for (let index = bytes.length - 22; index >= Math.max(0, bytes.length - 65557); index -= 1) {
    if (view.getUint32(index, true) === 0x06054b50) {
      end = index;
      break;
    }
  }
  if (end < 0) throw new Error("The zip file is damaged.");
  const entries = view.getUint16(end + 10, true);
  let offset = view.getUint32(end + 16, true);
  const texts = [];
  for (let entry = 0; entry < entries && entry < 200; entry += 1) {
    if (view.getUint32(offset, true) !== 0x02014b50) break;
    const method = view.getUint16(offset + 10, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const localOffset = view.getUint32(offset + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(offset + 46, offset + 46 + nameLength));
    offset += 46 + nameLength + extraLength + commentLength;
    if (!/\.xml$/i.test(name)) continue;
    const dataStart = localOffset + 30 + view.getUint16(localOffset + 26, true) + view.getUint16(localOffset + 28, true);
    const data = bytes.subarray(dataStart, dataStart + compressedSize);
    if (method === 0) texts.push(new TextDecoder().decode(data));
    else if (method === 8) texts.push(await inflate(data, "deflate-raw"));
  }
  return texts;
}

async function readReportFile(file) {
  if (file.size > dmarcLimits.fileBytes) throw new Error(`${file.name} is larger than 20 MB.`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return [await inflate(bytes, "gzip")];
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) return unzipXml(bytes);
  return [new TextDecoder().decode(bytes)];
}

function parseDmarcXml(text) {
  if (!/<feedback[\s>]/.test(text)) return null;
  const documentNode = new DOMParser().parseFromString(text, "application/xml");
  if (documentNode.querySelector("parsererror") || !documentNode.querySelector("feedback")) return null;
  const value = (parent, selector) => parent?.querySelector(selector)?.textContent?.trim() || null;
  const metadata = documentNode.querySelector("report_metadata");
  const policy = documentNode.querySelector("policy_published");
  const records = [...documentNode.querySelectorAll("feedback > record")].map((record) => ({
    ip: value(record, "row > source_ip"),
    count: Number(value(record, "row > count")) || 0,
    disposition: value(record, "row > policy_evaluated > disposition") || "none",
    dkim: value(record, "row > policy_evaluated > dkim") || "fail",
    spf: value(record, "row > policy_evaluated > spf") || "fail",
    headerFrom: value(record, "identifiers > header_from"),
    envelopeFrom: value(record, "identifiers > envelope_from"),
    dkimDomains: [...record.querySelectorAll("auth_results > dkim")].map((dkim) => `${value(dkim, "domain") || "?"}:${value(dkim, "result") || "?"}`),
    spfDomains: [...record.querySelectorAll("auth_results > spf")].map((spf) => `${value(spf, "domain") || "?"}:${value(spf, "result") || "?"}`),
  }));
  return {
    org: value(metadata, "org_name") || "Unknown reporter",
    reportId: value(metadata, "report_id"),
    begin: Number(value(metadata, "date_range > begin")) * 1000 || null,
    end: Number(value(metadata, "date_range > end")) * 1000 || null,
    policy: {
      domain: value(policy, "domain"), p: value(policy, "p"), sp: value(policy, "sp"), pct: value(policy, "pct"),
      adkim: value(policy, "adkim"), aspf: value(policy, "aspf"),
    },
    records,
  };
}

async function readDmarcReports(files) {
  if (!files.length) throw new Error("Choose one or more report files.");
  if (files.length > dmarcLimits.files) throw new Error(`Choose at most ${dmarcLimits.files} files.`);
  const reports = [];
  const skipped = [];
  for (const file of files) {
    try {
      const texts = await readReportFile(file);
      const parsed = texts.map(parseDmarcXml).filter(Boolean);
      if (!parsed.length) skipped.push(`${file.name} (not a DMARC aggregate report)`);
      reports.push(...parsed);
    } catch (error) {
      skipped.push(`${file.name} (${error.message})`);
    }
  }
  if (!reports.length) throw new Error(`No DMARC reports could be read. ${skipped.join("; ")}`);
  const sources = new Map();
  const reporters = new Map();
  const totals = { messages: 0, pass: 0, dkimAligned: 0, spfAligned: 0, quarantined: 0, rejected: 0 };
  for (const report of reports) {
    const reporter = reporters.get(report.org) || { org: report.org, reports: 0, messages: 0 };
    reporter.reports += 1;
    for (const record of report.records) {
      const passed = record.dkim === "pass" || record.spf === "pass";
      totals.messages += record.count;
      if (passed) totals.pass += record.count;
      if (record.dkim === "pass") totals.dkimAligned += record.count;
      if (record.spf === "pass") totals.spfAligned += record.count;
      if (record.disposition === "quarantine") totals.quarantined += record.count;
      if (record.disposition === "reject") totals.rejected += record.count;
      reporter.messages += record.count;
      const source = sources.get(record.ip) || { ip: record.ip, messages: 0, pass: 0, dkim: 0, spf: 0, dispositions: {}, headerFrom: new Set(), envelopeFrom: new Set(), dkimDomains: new Set(), reporters: new Set() };
      source.messages += record.count;
      if (passed) source.pass += record.count;
      if (record.dkim === "pass") source.dkim += record.count;
      if (record.spf === "pass") source.spf += record.count;
      source.dispositions[record.disposition] = (source.dispositions[record.disposition] || 0) + record.count;
      if (record.headerFrom) source.headerFrom.add(record.headerFrom);
      if (record.envelopeFrom) source.envelopeFrom.add(record.envelopeFrom);
      record.dkimDomains.forEach((domain) => source.dkimDomains.add(domain));
      source.reporters.add(report.org);
      sources.set(record.ip, source);
    }
    reporters.set(report.org, reporter);
  }
  const sourceList = [...sources.values()].sort((left, right) => right.messages - left.messages).slice(0, 300).map((source) => ({
    ...source,
    headerFrom: [...source.headerFrom].slice(0, 5),
    envelopeFrom: [...source.envelopeFrom].slice(0, 5),
    dkimDomains: [...source.dkimDomains].slice(0, 5),
    reporters: [...source.reporters].slice(0, 8),
  }));
  try {
    const lookup = await postJson("/api/dmarc-sources", { ips: sourceList.map((source) => source.ip).filter(Boolean) });
    sourceList.forEach((source) => Object.assign(source, lookup.sources?.[source.ip] || {}));
  } catch {
    // Host names are a convenience; the report is still useful without them.
  }
  const times = reports.flatMap((report) => [report.begin, report.end]).filter(Boolean);
  return {
    domains: [...new Set(reports.map((report) => report.policy.domain).filter(Boolean))],
    policies: [...new Map(reports.map((report) => [JSON.stringify(report.policy), report.policy])).values()].slice(0, 5),
    reports: reports.map((report) => ({ org: report.org, reportId: report.reportId, begin: report.begin, end: report.end, domain: report.policy.domain, messages: report.records.reduce((sum, record) => sum + record.count, 0) })).slice(0, 500),
    reporters: [...reporters.values()].sort((left, right) => right.messages - left.messages),
    sources: sourceList,
    sourceCount: sources.size,
    totals,
    begin: times.length ? Math.min(...times) : null,
    end: times.length ? Math.max(...times) : null,
    skipped,
  };
}

function renderDmarcReportResult(data) {
  const percent = (part) => (data.totals.messages ? Math.round(part / data.totals.messages * 1000) / 10 : 0);
  const passRate = percent(data.totals.pass);
  const failing = data.sources.filter((source) => source.pass < source.messages);
  const unknownFailing = failing.filter((source) => !source.provider);
  const policy = data.policies[0] || {};
  const verdict = passRate >= 98
    ? ["ok", `${passRate}% of mail passes DMARC. ${policy.p === "reject" ? "You already reject failing mail." : "You can move towards p=reject; first check that the failing sources below are not your own services."}`]
    : passRate >= 90
      ? ["warn", `${passRate}% of mail passes. Fix the legitimate sources that fail (add them to SPF or set up DKIM for them) before tightening the policy.`]
      : ["bad", `Only ${passRate}% of mail passes. Tightening the policy now would block real mail; find out which senders below are yours and authenticate them first.`];
  const rows = data.sources.map((source) => {
    const rate = source.messages ? Math.round(source.pass / source.messages * 100) : 0;
    return `
      <tr>
        <td>${copyableResult(source.ip)}${source.ptr?.length ? `<br><span class="trace-silent">${escapeHtml(source.ptr[0])}</span>` : ""}${source.provider ? `<br>${pill("info", source.provider)}` : ""}</td>
        <td>${escapeHtml(source.messages.toLocaleString())}</td>
        <td class="hop-delay">${escapeHtml(`${rate}%`)}${percentBar(rate, rate >= 98 ? "ok" : rate >= 50 ? "warn" : "bad")}</td>
        <td>${pill(source.dkim === source.messages ? "ok" : source.dkim ? "warn" : "fail", `${Math.round(source.dkim / source.messages * 100)}%`)}</td>
        <td>${pill(source.spf === source.messages ? "ok" : source.spf ? "warn" : "fail", `${Math.round(source.spf / source.messages * 100)}%`)}</td>
        <td>${escapeHtml(Object.entries(source.dispositions).map(([key, count]) => `${key} ${count}`).join(", "))}</td>
        <td>${escapeHtml([...source.headerFrom, ...source.envelopeFrom.filter((value) => !source.headerFrom.includes(value)).map((value) => `envelope ${value}`)].join(", "))}${source.dkimDomains.length ? `<br><span class="trace-silent">${escapeHtml(`DKIM ${source.dkimDomains.join(", ")}`)}</span>` : ""}</td>
      </tr>`;
  });
  const reportRows = data.reporters.map((reporter) => `<tr><td>${escapeHtml(reporter.org)}</td><td>${escapeHtml(reporter.reports)}</td><td>${escapeHtml(reporter.messages.toLocaleString())}</td></tr>`);
  const range = data.begin ? `${new Date(data.begin).toLocaleDateString()} – ${new Date(data.end).toLocaleDateString()}` : "";
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">DMARC REPORTS</p><h2>${escapeHtml(data.domains.join(", ") || "Unknown domain")}</h2><p class="web-title">${escapeHtml(`${data.reports.length} report(s) · ${range}`)}</p></div>
      <span class="status-badge ${passRate >= 98 ? "success" : "warning"}">${escapeHtml(`${passRate}% pass`)}</span>
    </div>
    ${scoreTiles([
      ["Messages", "ok", data.totals.messages.toLocaleString()],
      ["DMARC pass", passRate >= 98 ? "ok" : passRate >= 90 ? "warn" : "bad", `${passRate}%`],
      ["DKIM aligned", percent(data.totals.dkimAligned) >= 95 ? "ok" : "warn", `${percent(data.totals.dkimAligned)}%`],
      ["SPF aligned", percent(data.totals.spfAligned) >= 95 ? "ok" : "warn", `${percent(data.totals.spfAligned)}%`],
      ["Sending sources", "ok", `${data.sourceCount}${failing.length ? ` · ${failing.length} failing` : ""}`],
      ["Unknown failing", unknownFailing.length ? "warn" : "ok", String(unknownFailing.length)],
      ["Policy", policy.p === "reject" ? "ok" : policy.p === "quarantine" ? "warn" : "bad", `p=${policy.p || "?"}${policy.pct && policy.pct !== "100" ? ` pct=${policy.pct}` : ""}`],
      ["Quarantined / rejected", data.totals.quarantined + data.totals.rejected ? "warn" : "ok", `${data.totals.quarantined} / ${data.totals.rejected}`],
    ])}
    <p class="dmarc-verdict ${verdict[0]}">${escapeHtml(verdict[1])}</p>
    ${data.skipped.length ? `<p class="detail-notice">${escapeHtml(`Skipped: ${data.skipped.join("; ")}`)}</p>` : ""}
    <section class="email-auth">
      <h3>Sending sources ${pill("info", `${data.sources.length}${data.sourceCount > data.sources.length ? ` of ${data.sourceCount}` : ""}`)}</h3>
      ${dataTable(["Source IP", "Messages", "DMARC pass", "DKIM", "SPF", "Disposition", "From domains"], rows, "dmarc-sources-table")}
      <p class="scan-disclaimer">A source passes DMARC when DKIM or SPF passes and aligns with the From domain. Sources marked with a provider are recognised from their host name; look up unknown IP addresses before trusting them.</p>
    </section>
    <section class="email-auth">
      <h3>Reporters</h3>
      ${dataTable(["Organization", "Reports", "Messages"], reportRows)}
    </section>`;
  applyBars(resultPanel);
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- Record builder

const spfProviders = [
  ["google", "Google Workspace", "include:_spf.google.com", 4],
  ["microsoft", "Microsoft 365", "include:spf.protection.outlook.com", 2],
  ["sendgrid", "SendGrid", "include:sendgrid.net", 1],
  ["mailgun", "Mailgun", "include:mailgun.org", 3],
  ["ses", "Amazon SES", "include:amazonses.com", 1],
  ["mailchimp", "Mailchimp / Mandrill", "include:servers.mcsv.net", 1],
  ["postmark", "Postmark", "include:spf.mtasv.net", 1],
  ["brevo", "Brevo", "include:spf.brevo.com", 1],
  ["zoho", "Zoho Mail", "include:zohomail.eu", 1],
  ["proton", "Proton Mail", "include:_spf.protonmail.ch", 1],
  ["fastmail", "Fastmail", "include:spf.messagingengine.com", 1],
];
let recordBuilderReady = false;

function builderOutput(name, value, notes = []) {
  return `
    <div class="builder-output">
      <div class="builder-output-row"><span>Name</span>${copyableResult(name)}</div>
      <div class="builder-output-row"><span>Type</span><strong>TXT</strong></div>
      <div class="builder-output-row"><span>Value</span>${copyableResult(value, "builder-value")}</div>
      ${notes.length ? `<ul class="dnssec-issues">${notes.map(([severity, message]) => `<li class="dnssec-issue ${escapeHtml(severity)}">${escapeHtml(message)}</li>`).join("")}</ul>` : ""}
    </div>`;
}

function initRecordBuilder(panel) {
  if (recordBuilderReady) return;
  recordBuilderReady = true;
  const isAdmin = authState?.user?.role === "admin";
  panel.innerHTML = `
    <div class="builder-domain">
      <label for="builder-domain">Domain</label>
      <input id="builder-domain" type="text" placeholder="example.com" autocomplete="off" spellcheck="false">
      <button type="button" class="dash-version-check" id="builder-import">Load current records</button>
      <span id="builder-import-status" class="trace-silent" role="status"></span>
    </div>
    <div class="email-subtabs builder-tabs" role="tablist" aria-label="Record type">
      ${["SPF", "DMARC", "MTA-STS", "TLS-RPT", "BIMI"].map((label, index) => `<button type="button" class="email-subtab${index ? "" : " active"}" data-builder-tab="${label.toLowerCase()}">${label}</button>`).join("")}
    </div>
    <form class="builder-form" data-builder="spf">
      <fieldset><legend>Services that send mail as this domain</legend>
        <div class="builder-checks">${spfProviders.map(([id, label]) => `<label><input type="checkbox" name="provider" value="${id}"> ${escapeHtml(label)}</label>`).join("")}
          <label><input type="checkbox" name="mx"> This domain's MX servers (mx)</label>
          <label><input type="checkbox" name="a"> This domain's own address (a)</label>
        </div>
      </fieldset>
      <label>Other includes <input name="includes" type="text" placeholder="e.g. spf.example.net, _spf.crm.example" spellcheck="false"></label>
      <label>IP addresses and ranges <input name="ips" type="text" placeholder="e.g. 203.0.113.10, 198.51.100.0/24, 2001:db8::/48" spellcheck="false"></label>
      <label>Everything else <select name="all"><option value="-all">Reject (-all, recommended)</option><option value="~all">Soft fail (~all)</option><option value="?all">Neutral (?all)</option></select></label>
      <div class="builder-result"></div>
    </form>
    <form class="builder-form" data-builder="dmarc" hidden>
      <label>Policy <select name="p"><option value="none">none — monitor only</option><option value="quarantine">quarantine — spam folder</option><option value="reject" selected>reject — block</option></select></label>
      <label>Subdomain policy <select name="sp"><option value="">Same as policy</option><option value="none">none</option><option value="quarantine">quarantine</option><option value="reject">reject</option></select></label>
      <label>Apply to % of failing mail <input name="pct" type="number" min="1" max="100" value="100"></label>
      <label>Aggregate reports to (rua) <input name="rua" type="text" placeholder="dmarc@example.com" spellcheck="false"></label>
      <label>Failure reports to (ruf, optional) <input name="ruf" type="text" placeholder="optional; few providers send them" spellcheck="false"></label>
      <label>DKIM alignment <select name="adkim"><option value="r">relaxed (subdomains may sign)</option><option value="s">strict</option></select></label>
      <label>SPF alignment <select name="aspf"><option value="r">relaxed</option><option value="s">strict</option></select></label>
      <div class="builder-result"></div>
    </form>
    <form class="builder-form" data-builder="mta-sts" hidden>
      <label>Mode <select name="mode"><option value="testing">testing — report only</option><option value="enforce">enforce</option><option value="none">none — turn off</option></select></label>
      <label>Mail servers (one per line, * for a subdomain wildcard) <textarea name="mx" rows="3" placeholder="mx1.example.com&#10;*.mail.protection.outlook.com" spellcheck="false"></textarea></label>
      <label>Cache time (max_age) <select name="maxAge"><option value="86400">1 day (while testing)</option><option value="604800" selected>1 week</option><option value="2592000">30 days</option><option value="31557600">1 year</option></select></label>
      <div class="builder-result"></div>
      ${isAdmin ? '<div class="builder-host"><button type="button" class="dash-version-check" id="builder-host-mta-sts">Host this policy on this server</button><button type="button" class="dash-version-check" id="builder-unhost-mta-sts" hidden>Stop hosting</button><span id="builder-host-status" class="trace-silent" role="status"></span></div>' : ""}
    </form>
    <form class="builder-form" data-builder="tls-rpt" hidden>
      <label>Send TLS reports to <input name="rua" type="text" placeholder="tls-reports@example.com" spellcheck="false"></label>
      <div class="builder-result"></div>
    </form>
    <form class="builder-form" data-builder="bimi" hidden>
      <label>Logo URL (SVG Tiny PS, HTTPS) <input name="logo" type="url" placeholder="https://example.com/logo.svg" spellcheck="false"></label>
      ${isAdmin ? `<button type="button" class="dash-version-check" id="builder-own-logo">Use this server's logo (${escapeHtml(window.location.host)}/logo.svg)</button>` : ""}
      <label>Mark certificate URL (optional) <input name="vmc" type="url" placeholder="https://example.com/vmc.pem" spellcheck="false"></label>
      <div class="builder-result"></div>
    </form>`;
  const domainInput = panel.querySelector("#builder-domain");
  const forms = [...panel.querySelectorAll(".builder-form")];
  const domain = () => (domainInput.value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "example.com");
  const emails = (value) => value.split(/[\s,;]+/).map((entry) => entry.trim().replace(/^mailto:/i, "")).filter(Boolean);
  let mtaStsId = new Date().toISOString().replace(/\D/g, "").slice(0, 14);

  const builders = {
    spf(form) {
      const values = new FormData(form);
      const selected = spfProviders.filter(([id]) => values.getAll("provider").includes(id));
      const includes = (values.get("includes") || "").split(/[\s,;]+/).filter(Boolean).map((value) => `include:${value.replace(/^include:/i, "")}`);
      const ips = (values.get("ips") || "").split(/[\s,;]+/).filter(Boolean).map((value) => `${value.includes(":") ? "ip6" : "ip4"}:${value.replace(/^ip[46]:/i, "")}`);
      const parts = ["v=spf1", values.get("mx") ? "mx" : null, values.get("a") ? "a" : null, ...ips, ...selected.map(([, , mechanism]) => mechanism), ...includes, values.get("all")].filter(Boolean);
      const lookups = (values.get("mx") ? 1 : 0) + (values.get("a") ? 1 : 0) + selected.reduce((sum, [, , , count]) => sum + count, 0) + includes.length;
      const record = parts.join(" ");
      const notes = [[lookups > 10 ? "high" : lookups >= 8 ? "medium" : "low", `About ${lookups} DNS lookups (limit 10${includes.length ? "; your own includes are counted as 1 each" : ""}).`]];
      if (record.length > 255) notes.push(["medium", "Longer than 255 characters: publish it as several quoted strings in one TXT record."]);
      if (parts.length === 2) notes.push(["medium", "No senders selected: this record says the domain sends no mail at all."]);
      if (values.get("all") !== "-all") notes.push(["low", "-all is safest once you are sure every sender is listed."]);
      notes.push(["low", "Publish only one SPF record per domain; replace the existing one."]);
      return builderOutput(domain(), record, notes);
    },
    dmarc(form) {
      const values = Object.fromEntries(new FormData(form));
      const rua = emails(values.rua || "");
      const ruf = emails(values.ruf || "");
      const record = [
        "v=DMARC1", `p=${values.p}`, values.sp ? `sp=${values.sp}` : null, Number(values.pct) && Number(values.pct) !== 100 ? `pct=${Number(values.pct)}` : null,
        rua.length ? `rua=${rua.map((entry) => `mailto:${entry}`).join(",")}` : null, ruf.length ? `ruf=${ruf.map((entry) => `mailto:${entry}`).join(",")}` : null,
        values.adkim === "s" ? "adkim=s" : null, values.aspf === "s" ? "aspf=s" : null, ruf.length ? "fo=1" : null,
      ].filter(Boolean).join("; ");
      const notes = [];
      if (!rua.length) notes.push(["medium", "Add a rua address so you receive aggregate reports; read them in the DMARC reports tab."]);
      if (values.p === "none") notes.push(["low", "Start with p=none to collect reports, then move to quarantine and reject once all your senders pass."]);
      if (rua.some((entry) => !entry.toLowerCase().endsWith(`@${domain()}`) && !entry.toLowerCase().endsWith(`.${domain()}`))) notes.push(["low", "Reports to another domain need that domain to publish an authorization record (<your-domain>._report._dmarc.<their-domain>)."]);
      return builderOutput(`_dmarc.${domain()}`, record, notes);
    },
    "mta-sts"(form) {
      const values = Object.fromEntries(new FormData(form));
      const mx = (values.mx || "").split(/[\s,]+/).map((entry) => entry.trim().toLowerCase()).filter(Boolean);
      const policy = ["version: STSv1", `mode: ${values.mode}`, ...mx.map((entry) => `mx: ${entry}`), `max_age: ${values.maxAge}`].join("\n");
      form.dataset.policy = policy;
      const notes = [];
      if (!mx.length && values.mode !== "none") notes.push(["high", "List every MX host (or a wildcard such as *.example.com)."]);
      if (values.mode === "enforce") notes.push(["medium", "Use testing mode with TLS-RPT first; enforce makes senders refuse delivery when TLS fails."]);
      return `
        ${builderOutput(`_mta-sts.${domain()}`, `v=STSv1; id=${mtaStsId}`, [["low", "Change the id whenever you change the policy file, so senders fetch it again."]])}
        <div class="builder-output">
          <div class="builder-output-row"><span>Policy file</span>${copyableResult(`https://mta-sts.${domain()}/.well-known/mta-sts.txt`)}</div>
          <pre class="builder-policy">${escapeHtml(policy)}</pre>
          ${notes.length ? `<ul class="dnssec-issues">${notes.map(([severity, message]) => `<li class="dnssec-issue ${escapeHtml(severity)}">${escapeHtml(message)}</li>`).join("")}</ul>` : ""}
          <p class="scan-disclaimer">Serve this file over HTTPS with a valid certificate for mta-sts.${escapeHtml(domain())}, as text/plain.${isAdmin ? " If you point that name at this server, it can serve the file for you." : ""}</p>
        </div>`;
    },
    "tls-rpt"(form) {
      const rua = emails(new FormData(form).get("rua") || "");
      return builderOutput(`_smtp._tls.${domain()}`, `v=TLSRPTv1; rua=${rua.length ? rua.map((entry) => `mailto:${entry}`).join(",") : "mailto:tls-reports@" + domain()}`,
        rua.length ? [] : [["low", "Enter where reports should go; a placeholder address is shown."]]);
    },
    bimi(form) {
      const values = Object.fromEntries(new FormData(form));
      const notes = [["medium", "BIMI only works when DMARC is p=quarantine or p=reject (pct=100)."]];
      if (values.logo && !/^https:\/\//i.test(values.logo)) notes.push(["high", "The logo must be served over HTTPS."]);
      if (!values.vmc) notes.push(["low", "Gmail and Apple Mail also require a Verified Mark Certificate (a=)."]);
      return builderOutput(`default._bimi.${domain()}`, `v=BIMI1; l=${values.logo || "https://" + domain() + "/logo.svg"};${values.vmc ? ` a=${values.vmc};` : ""}`, notes);
    },
  };
  const refresh = () => forms.forEach((form) => {
    form.querySelector(".builder-result").innerHTML = builders[form.dataset.builder](form);
  });
  panel.addEventListener("input", refresh);
  panel.addEventListener("change", refresh);
  forms.forEach((form) => form.addEventListener("submit", (event) => event.preventDefault()));
  panel.querySelectorAll("[data-builder-tab]").forEach((button) => button.addEventListener("click", () => {
    panel.querySelectorAll("[data-builder-tab]").forEach((other) => other.classList.toggle("active", other === button));
    forms.forEach((form) => { form.hidden = form.dataset.builder !== button.dataset.builderTab; });
  }));

  panel.querySelector("#builder-import").addEventListener("click", async () => {
    const status = panel.querySelector("#builder-import-status");
    status.textContent = "Loading…";
    try {
      const data = await getJson(`/api/record-import?${new URLSearchParams({ name: domain() })}`);
      domainInput.value = data.domain;
      const spf = data.spf[0] || "";
      const spfForm = panel.querySelector('[data-builder="spf"]');
      spfForm.querySelectorAll('[name="provider"]').forEach((box) => {
        box.checked = spf.includes(spfProviders.find(([id]) => id === box.value)[2].slice(8));
      });
      spfForm.elements.mx.checked = /\smx(\s|$)/.test(spf);
      spfForm.elements.a.checked = /\sa(\s|$)/.test(spf);
      const known = spfProviders.map(([, , mechanism]) => mechanism);
      spfForm.elements.includes.value = (spf.match(/include:\S+/g) || []).filter((entry) => !known.includes(entry)).map((entry) => entry.slice(8)).join(", ");
      spfForm.elements.ips.value = (spf.match(/ip[46]:\S+/g) || []).map((entry) => entry.slice(4)).join(", ");
      if (/[-~?]all/.test(spf)) spfForm.elements.all.value = spf.match(/[-~?]all/)[0];
      const tags = (record) => Object.fromEntries((record || "").split(";").map((part) => part.trim().split("=")).filter(([key, value]) => key && value).map(([key, value]) => [key.toLowerCase(), value]));
      const dmarc = tags(data.dmarc);
      const dmarcForm = panel.querySelector('[data-builder="dmarc"]');
      if (dmarc.p) dmarcForm.elements.p.value = dmarc.p;
      if (dmarc.sp) dmarcForm.elements.sp.value = dmarc.sp;
      if (dmarc.pct) dmarcForm.elements.pct.value = dmarc.pct;
      dmarcForm.elements.rua.value = (dmarc.rua || "").replace(/mailto:/gi, "");
      dmarcForm.elements.ruf.value = (dmarc.ruf || "").replace(/mailto:/gi, "");
      if (dmarc.adkim) dmarcForm.elements.adkim.value = dmarc.adkim;
      if (dmarc.aspf) dmarcForm.elements.aspf.value = dmarc.aspf;
      const stsForm = panel.querySelector('[data-builder="mta-sts"]');
      stsForm.elements.mx.value = data.mx.join("\n");
      if (tags(data.mtaSts).id) mtaStsId = tags(data.mtaSts).id;
      panel.querySelector('[data-builder="tls-rpt"]').elements.rua.value = (tags(data.tlsRpt).rua || "").replace(/mailto:/gi, "");
      const bimiForm = panel.querySelector('[data-builder="bimi"]');
      bimiForm.elements.logo.value = tags(data.bimi).l || "";
      bimiForm.elements.vmc.value = tags(data.bimi).a || "";
      status.textContent = `Loaded: ${[spf && "SPF", data.dmarc && "DMARC", data.mtaSts && "MTA-STS", data.tlsRpt && "TLS-RPT", data.bimi && "BIMI"].filter(Boolean).join(", ") || "no records found"}.`;
      refresh();
    } catch (error) {
      status.textContent = error.message;
    }
  });

  if (isAdmin) {
    const hostButton = panel.querySelector("#builder-host-mta-sts");
    const unhostButton = panel.querySelector("#builder-unhost-mta-sts");
    const hostStatus = panel.querySelector("#builder-host-status");
    const showHosted = (policy) => {
      unhostButton.hidden = !policy;
      hostStatus.textContent = policy ? `Hosted at ${window.location.origin}/.well-known/mta-sts.txt (mode: ${policy.match(/mode:\s*(\w+)/)?.[1] || "?"}).` : "Not hosted on this server.";
    };
    getJson("/api/admin/mta-sts").then((data) => showHosted(data.policy), () => {});
    hostButton.addEventListener("click", async () => {
      try {
        const response = await fetch("/api/admin/mta-sts", {
          method: "PUT", credentials: "same-origin", headers: { "content-type": "application/json" },
          body: JSON.stringify({ policy: panel.querySelector('[data-builder="mta-sts"]').dataset.policy }),
        });
        const data = await readApiResponse(response);
        if (!response.ok) throw new Error(data.error);
        showHosted(data.policy);
      } catch (error) {
        hostStatus.textContent = error.message || "Could not save the policy.";
      }
    });
    unhostButton.addEventListener("click", async () => {
      const response = await fetch("/api/admin/mta-sts", { method: "DELETE", credentials: "same-origin" });
      if (response.ok) showHosted(null);
    });
    panel.querySelector("#builder-own-logo").addEventListener("click", () => {
      panel.querySelector('[data-builder="bimi"]').elements.logo.value = `${window.location.origin.replace(/^http:/, "https:")}/logo.svg`;
      refresh();
    });
  }
  refresh();
}

// ---------------------------------------------------------------- Web check: security.txt, robots.txt, sitemap, mixed content

function webExtrasHtml(data) {
  if (!data.securityTxt && !data.robots) return "";
  const security = data.securityTxt || {};
  const robots = data.robots || {};
  const sitemap = data.sitemap || {};
  const mixed = data.mixedContent || [];
  const row = (label, state, value, detail = "", okLabel = "Found") => `
    <tr><td>${escapeHtml(label)}</td><td>${pill(state, { ok: okLabel, warn: "Check", fail: "Problem", info: "Not found" }[state] || state)}</td><td>${escapeHtml(value)}${detail ? `<br><span class="trace-silent">${escapeHtml(detail)}</span>` : ""}</td></tr>`;
  const rows = [
    row("security.txt", security.found ? (security.issues?.length ? "warn" : "ok") : "info",
      security.found ? `Contact: ${(security.contact || []).join(", ") || "none"}` : "No /.well-known/security.txt",
      security.found ? [security.expires ? `Expires ${security.expires.slice(0, 10)}` : "No Expires field", security.policy ? `Policy ${security.policy}` : null, security.signed ? "PGP signed" : null].filter(Boolean).join(" · ") : "Lets security researchers know how to report problems (RFC 9116)."),
    row("robots.txt", robots.found ? (robots.blocksAll ? "warn" : "ok") : "info",
      robots.found ? `${robots.lines} rule line(s)${robots.blocksAll ? " · blocks all crawlers" : ""}` : "No robots.txt",
      robots.sitemaps?.length ? `Sitemaps: ${robots.sitemaps.join(", ")}` : ""),
    row("Sitemap", sitemap.found ? "ok" : "info", sitemap.found ? sitemap.url : "No sitemap found", sitemap.entries ? `${sitemap.entries} entries` : ""),
  ];
  if (data.https) rows.push(row("Mixed content", mixed.length ? "fail" : "ok", mixed.length ? `${mixed.length} resource(s) over plain HTTP` : "None found on the page", mixed.slice(0, 5).join(", "), "None"));
  return `<section class="email-auth"><h3>Site files and content</h3>${dataTable(["Check", "Result", "Details"], rows)}</section>`;
}

// ---------------------------------------------------------------- DNS health

function dnsHealthHtml(data) {
  const stateLabel = { pass: "Pass", warn: "Warning", fail: "Problem", info: "Info" };
  if (data.error) {
    return `<div class="result-heading"><div><p class="eyebrow">DNS HEALTH</p><h2>${copyableResult(data.domain)}</h2></div></div><p class="detail-notice">${escapeHtml(data.error)}</p>`;
  }
  const failed = data.checks.filter((check) => check.state === "fail").length;
  const warned = data.checks.filter((check) => check.state === "warn").length;
  const checkRows = data.checks.map((check) => `
    <tr><td>${escapeHtml(check.label)}</td><td>${pill(check.state, stateLabel[check.state])}</td><td>${escapeHtml(check.message)}${check.detail ? `<br><span class="trace-silent">${escapeHtml(check.detail)}</span>` : ""}</td></tr>`);
  const serverRows = data.nameservers.flatMap((entry) => (entry.results.length ? entry.results : [{ address: entry.addresses[0] || "", error: entry.error }]).map((result, index) => `
    <tr>
      <td>${index ? "" : `${copyableResult(entry.host)}${entry.inParent === false ? '<br><span class="trace-silent">not in parent</span>' : ""}${!entry.inZone ? '<br><span class="trace-silent">not in zone</span>' : ""}`}</td>
      <td>${escapeHtml(result.address || "")}</td>
      <td>${result.error ? `<span class="dnssec-bad">${escapeHtml(result.error)}</span>` : pill(result.authoritative ? "ok" : "fail", result.authoritative ? "Authoritative" : `Not authoritative (${result.rcode})`)}</td>
      <td>${escapeHtml(result.serial ?? "")}</td>
      <td>${result.error ? "" : `${result.tcp ? "✓" : "✕"}`}</td>
      <td>${result.error ? "" : result.openRecursion ? pill("fail", "Open") : "No"}</td>
      <td>${result.error ? "" : result.zoneTransfer ? pill("fail", "Allowed") : "Refused"}</td>
      <td>${result.timeMs !== undefined ? `${escapeHtml(result.timeMs)} ms` : ""}</td>
    </tr>`));
  return `
    <div class="result-heading">
      <div><p class="eyebrow">DNS HEALTH</p><h2>${copyableResult(data.zone)}</h2>${data.zone !== data.domain ? `<p class="web-title">${escapeHtml(`Zone that contains ${data.domain}`)}</p>` : ""}</div>
      <span class="status-badge ${failed ? "warning" : "success"}">${escapeHtml(failed ? `${failed} problem(s)` : warned ? `${warned} warning(s)` : "Healthy")}</span>
    </div>
    ${scoreTiles([
      ["Name servers", data.nameservers.length >= 2 ? "ok" : "bad", String(data.nameservers.length)],
      ["Delegation", ({ pass: "ok", warn: "warn", fail: "bad" })[data.checks.find((check) => check.id === "delegation")?.state] || "none", data.parent ? `Parent ${data.parent.server}` : "Not read"],
      ["Zone transfer", data.checks.find((check) => check.id === "axfr")?.state === "fail" ? "bad" : "ok", data.checks.find((check) => check.id === "axfr")?.state === "fail" ? "Open" : "Refused"],
      ["Open recursion", data.checks.find((check) => check.id === "recursion")?.state === "fail" ? "bad" : "ok", data.checks.find((check) => check.id === "recursion")?.state === "fail" ? "Yes" : "No"],
    ])}
    ${renderMailFixList([["", data.issues]])}
    <section class="email-auth"><h3>Checks</h3>${dataTable(["Check", "Result", "Details"], checkRows, "web-checks-table")}</section>
    <section class="email-auth"><h3>Name servers</h3>${dataTable(["Name server", "Address", "Answer", "SOA serial", "TCP", "Recursion", "AXFR", "Time"], serverRows)}
      <p class="scan-disclaimer">Each name server is asked directly, without recursion, for the zone's SOA and NS records over UDP and TCP. Open recursion is tested with a query for another domain; a zone transfer (AXFR) is attempted over TCP.</p>
    </section>
    ${data.soa ? `<section class="email-auth"><h3>SOA record</h3>${renderFacts([["Primary", data.soa.mname], ["Contact", data.soa.rname], ["Serial", data.soa.serial], ["Refresh", `${data.soa.refresh} s`], ["Retry", `${data.soa.retry} s`], ["Expire", `${data.soa.expire} s`], ["Negative TTL", `${data.soa.minimum} s`]])}</section>` : ""}
    <p class="scan-disclaimer">${escapeHtml(`Completed in ${(data.durationMs / 1000).toFixed(1)} s.`)}</p>`;
}

function renderDnsHealthResult(data) {
  resultPanel.innerHTML = dnsHealthHtml(data);
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- Reputation

function renderReputationResult(data) {
  const labels = { flagged: ["fail", "Flagged"], suspicious: ["warn", "Suspicious"], clean: ["ok", "Clean"], error: ["info", "Error"], off: ["info", "Not configured"] };
  const rows = data.sources.map((source) => {
    const [state, label] = labels[source.state] || labels.error;
    return `<tr><td>${escapeHtml(source.source)}</td><td>${pill(state, label)}</td><td>${escapeHtml(source.detail)}${source.link && /^https:\/\//.test(source.link) ? ` · <a href="${escapeHtml(source.link)}" target="_blank" rel="noopener noreferrer">details</a>` : ""}</td></tr>`;
  });
  const verdict = { malicious: ["bad", "Malicious", "warning"], suspicious: ["warn", "Suspicious", "warning"], clean: ["ok", "No threats found", "success"] }[data.verdict];
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">REPUTATION</p><h2>${copyableResult(data.target)}</h2>${data.addresses.length && !data.isAddress ? `<p class="web-title">${escapeHtml(`Resolves to ${data.addresses.join(", ")}`)}</p>` : ""}</div>
      <span class="status-badge ${verdict[2]}">${escapeHtml(verdict[1])}</span>
    </div>
    ${scoreTiles([
      ["Verdict", verdict[0], verdict[1]],
      ["Flagged by", data.flagged ? "bad" : "ok", `${data.flagged} of ${data.checked} sources`],
      ["Domain exists", data.exists ? "ok" : "warn", data.exists ? "Yes" : "No answer"],
    ])}
    ${!data.exists ? '<p class="detail-notice">The domain does not resolve, so filtering resolvers cannot show whether they block it.</p>' : ""}
    <section class="email-auth"><h3>Sources</h3>${dataTable(["Source", "Result", "Details"], rows, "web-checks-table")}
      <p class="scan-disclaimer">Filtering resolvers (Quad9, Cloudflare for Families, DNS4EU, CleanBrowsing) are compared with an unfiltered answer; a block means the service considers the domain malicious. Spam blocklists cover mail abuse. The threat lists (Spamhaus DROP for hijacked networks, abuse.ch Feodo Tracker for botnet command-and-control servers, abuse.ch URLhaus for malware hosts and OpenPhish for phishing sites) are downloaded by the server every few hours and checked locally. VirusTotal, Google Safe Browsing and the URLhaus API are used when the administrator has configured their keys. A clean result is not a guarantee.</p>
    </section>`;
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- Lookalike domains

function renderLookalikeResult(data) {
  const riskLabels = { high: ["fail", "Mail server"], medium: ["warn", "Website"], low: ["info", "Registered"] };
  const rows = data.registered.map((entry) => {
    const [state, label] = riskLabels[entry.risk];
    return `
      <tr>
        <td>${copyableResult(entry.name)}</td>
        <td>${escapeHtml(entry.kind)}</td>
        <td>${pill(state, label)}</td>
        <td>${escapeHtml(entry.addresses.join(", "))}</td>
        <td>${escapeHtml(entry.mx.join(", "))}</td>
        <td>${escapeHtml(entry.nameservers.join(", "))}</td>
      </tr>`;
  });
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">LOOKALIKE DOMAINS</p><h2>${copyableResult(data.domain)}</h2><p class="web-title">${escapeHtml(`${data.checked} variants checked of ${data.base}`)}</p></div>
      <span class="status-badge ${data.counts.high ? "warning" : "success"}">${escapeHtml(`${data.registered.length} registered`)}</span>
    </div>
    ${scoreTiles([
      ["With mail servers", data.counts.high ? "bad" : "ok", String(data.counts.high)],
      ["With websites", data.counts.medium ? "warn" : "ok", String(data.counts.medium)],
      ["Registered only", "none", String(data.counts.low)],
      ["Not registered", "ok", String(data.checked - data.registered.length - data.failed)],
    ])}
    ${data.failed ? `<p class="detail-notice">${escapeHtml(`${data.failed} variant(s) could not be checked because the DNS provider did not answer.`)}</p>` : ""}
    <section class="email-auth"><h3>Registered lookalikes</h3>
      ${dataTable(["Domain", "Variant", "Active", "Addresses", "Mail (MX)", "Name servers"], rows) || '<p class="empty-result">None of the variants are registered.</p>'}
      <p class="scan-disclaimer">Variants: ${escapeHtml(data.kinds.join(", "))}. Domains with mail servers can send phishing mail that looks like yours. Some lookalikes are registered defensively by the brand owner, or are unrelated sites; check before acting. Use "Monitor this" to be told about new certificates for your own domain.</p>
    </section>`;
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- SPF flattener

function renderSpfFlattenResult(data) {
  const records = data.records.map((record) => `
    <div class="builder-output">
      <div class="builder-output-row"><span>Name</span>${copyableResult(record.name)}</div>
      <div class="builder-output-row"><span>Type</span><strong>TXT</strong></div>
      <div class="builder-output-row"><span>Value</span>${copyableResult(record.value, "builder-value")}</div>
    </div>`).join("");
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">SPF FLATTENER</p><h2>${copyableResult(data.domain)}</h2></div>
      <span class="status-badge ${data.originalLookups > 10 ? "warning" : "success"}">${escapeHtml(`${data.originalLookups} → ${data.flattenedLookups} lookups`)}</span>
    </div>
    ${scoreTiles([
      ["Current lookups", data.originalLookups > 10 ? "bad" : data.originalLookups >= 8 ? "warn" : "ok", `${data.originalLookups}/10`],
      ["After flattening", "ok", `${data.flattenedLookups}/10`],
      ["IPv4 ranges", "ok", String(data.ip4)],
      ["IPv6 ranges", "ok", String(data.ip6)],
    ])}
    ${data.original ? `<section class="email-auth"><h3>Current record</h3><div class="email-auth-record"><span>${escapeHtml(data.original)}</span></div></section>` : '<p class="detail-notice">The domain has no SPF record to flatten.</p>'}
    ${data.notes.length ? renderMailIssues(data.notes.map((message) => ({ severity: "low", message }))) : ""}
    <section class="email-auth"><h3>Flattened record${data.records.length > 1 ? "s" : ""}</h3>${records}
      <p class="scan-disclaimer">Flattening copies your providers' current IP ranges into your own records. When a provider changes its addresses, mail from the new ones fails SPF until you flatten again, so re-run this regularly (an Email security monitor alerts you when the published record changes) and prefer removing unused includes where possible. ${data.originalLookups <= 10 ? "Your record is within the limit, so flattening is not needed." : ""}</p>
    </section>`;
  resultPanel.hidden = false;
}

// ---------------------------------------------------------------- IP calculator (in the browser)

function ipv4ToInt(text) {
  const parts = text.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((value, part) => (value * 256) + Number(part), 0);
}

function intToIpv4(value) {
  return [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join(".");
}

function parseIpv6(text) {
  let value = text.toLowerCase().replace(/^\[|\]$/g, "");
  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    const v4 = ipv4ToInt(value.slice(lastColon + 1));
    if (v4 === null) return null;
    value = `${value.slice(0, lastColon + 1)}${Math.floor(v4 / 65536).toString(16)}:${(v4 % 65536).toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 2 && missing < 1) || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.reduce((total, group) => (total << 16n) + BigInt(parseInt(group, 16)), 0n);
}

function formatIpv6(value) {
  const groups = Array.from({ length: 8 }, (_unused, index) => Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < 8; start += 1) {
    let length = 0;
    while (start + length < 8 && groups[start + length] === "0") length += 1;
    if (length > bestLength && length > 1) {
      bestStart = start;
      bestLength = length;
    }
  }
  if (bestStart < 0) return groups.join(":");
  return `${groups.slice(0, bestStart).join(":")}::${groups.slice(bestStart + bestLength).join(":")}`;
}

function ipv4Type(value) {
  const inRange = (base, prefix) => Math.floor(value / 2 ** (32 - prefix)) === Math.floor(ipv4ToInt(base) / 2 ** (32 - prefix));
  return inRange("10.0.0.0", 8) || inRange("172.16.0.0", 12) || inRange("192.168.0.0", 16) ? "Private (RFC 1918)"
    : inRange("100.64.0.0", 10) ? "Carrier-grade NAT (RFC 6598)"
    : inRange("127.0.0.0", 8) ? "Loopback"
    : inRange("169.254.0.0", 16) ? "Link-local"
    : inRange("224.0.0.0", 4) ? "Multicast"
    : inRange("192.0.2.0", 24) || inRange("198.51.100.0", 24) || inRange("203.0.113.0", 24) ? "Documentation"
    : inRange("0.0.0.0", 8) ? "This network"
    : inRange("240.0.0.0", 4) ? "Reserved"
    : "Public";
}

function ipv6Type(value) {
  const top = (bits) => value >> BigInt(128 - bits);
  return value === 1n ? "Loopback" : value === 0n ? "Unspecified"
    : top(7) === 0x7en ? "Unique local (ULA)"
    : top(10) === 0x3fan ? "Link-local"
    : top(8) === 0xffn ? "Multicast"
    : top(32) === 0x20010db8n ? "Documentation"
    : top(96) === 0xffffn ? "IPv4-mapped"
    : top(3) === 1n ? "Global unicast" : "Reserved";
}

function calculateIp(rawInput, splitPrefix = null) {
  const input = String(rawInput || "").trim().replace(/\s+/g, " ");
  const [addressPart, maskPart] = input.includes("/") ? input.split("/") : input.split(" ");
  if (addressPart.includes(":")) {
    const value = parseIpv6(addressPart);
    const prefix = maskPart === undefined ? 128 : Number(maskPart);
    if (value === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) throw new Error("Enter an IPv6 address with an optional /prefix (0–128).");
    const hostBits = BigInt(128 - prefix);
    const network = (value >> hostBits) << hostBits;
    const last = network + (1n << hostBits) - 1n;
    const nibbles = Math.floor(prefix / 4);
    const hex = network.toString(16).padStart(32, "0");
    const split = splitPrefix === null ? Math.min(128, prefix <= 48 ? 64 : prefix + 8) : splitPrefix;
    const subnets = [];
    if (split > prefix && split <= 128) {
      const count = 1n << BigInt(split - prefix);
      for (let index = 0n; index < count && index < 256n; index += 1n) subnets.push(`${formatIpv6(network + (index << BigInt(128 - split)))}/${split}`);
    }
    return {
      input, family: 6, prefix, address: formatIpv6(value),
      network: `${formatIpv6(network)}/${prefix}`, first: formatIpv6(network), last: formatIpv6(last),
      expanded: hex.match(/.{4}/g).join(":"), total: (1n << hostBits).toString(), type: ipv6Type(value),
      reverseZone: `${hex.slice(0, nibbles).split("").reverse().join(".")}${nibbles ? "." : ""}ip6.arpa`,
      split, splitCount: split > prefix ? (1n << BigInt(split - prefix)).toString() : "0", subnets,
    };
  }
  const value = ipv4ToInt(addressPart);
  if (value === null) throw new Error("Enter an IPv4 address such as 192.168.1.10/24 or 10.0.0.0 255.255.0.0, or an IPv6 prefix.");
  let prefix = 32;
  if (maskPart !== undefined && maskPart !== "") {
    if (/^\d{1,2}$/.test(maskPart)) prefix = Number(maskPart);
    else {
      let mask = ipv4ToInt(maskPart);
      if (mask === null) throw new Error("The netmask is not valid.");
      if (mask !== 0 && (mask % 2 === 1) && mask < 2 ** 31) mask = 2 ** 32 - 1 - mask;
      const binary = mask.toString(2).padStart(32, "0");
      if (!/^1*0*$/.test(binary)) throw new Error("The netmask is not contiguous.");
      prefix = binary.indexOf("0") === -1 ? 32 : binary.indexOf("0");
    }
  }
  if (prefix < 0 || prefix > 32) throw new Error("The prefix must be between 0 and 32.");
  const size = 2 ** (32 - prefix);
  const network = Math.floor(value / size) * size;
  const broadcast = network + size - 1;
  const mask = 2 ** 32 - size;
  const usable = prefix === 32 ? 1 : prefix === 31 ? 2 : size - 2;
  const split = splitPrefix === null ? Math.min(32, prefix + 2) : splitPrefix;
  const subnets = [];
  if (split > prefix && split <= 32) {
    const step = 2 ** (32 - split);
    for (let start = network; start <= broadcast && subnets.length < 256; start += step) subnets.push(`${intToIpv4(start)}/${split}`);
  }
  const octets = Math.floor(prefix / 8);
  return {
    input, family: 4, prefix, address: intToIpv4(value),
    network: `${intToIpv4(network)}/${prefix}`, netmask: intToIpv4(mask), wildcard: intToIpv4(size - 1),
    broadcast: prefix >= 31 ? null : intToIpv4(broadcast),
    first: intToIpv4(prefix >= 31 ? network : network + 1), last: intToIpv4(prefix >= 31 ? broadcast : broadcast - 1),
    total: String(size), usable: String(usable), type: ipv4Type(value),
    binaryMask: mask.toString(2).padStart(32, "0").match(/.{8}/g).join("."),
    hex: value.toString(16).padStart(8, "0"),
    reverseZone: `${intToIpv4(network).split(".").slice(0, octets).reverse().join(".")}${octets ? "." : ""}in-addr.arpa`,
    split, splitCount: split > prefix ? String(2 ** (split - prefix)) : "0", subnets,
  };
}

function renderIpCalcResult(data) {
  const maxSplit = data.family === 4 ? 32 : 128;
  const splitOptions = [];
  for (let value = data.prefix + 1; value <= Math.min(maxSplit, data.prefix + (data.family === 4 ? 16 : 32)); value += 1) splitOptions.push(value);
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">IP CALCULATOR</p><h2>${copyableResult(data.network)}</h2><p class="web-title">${escapeHtml(`${data.type} · IPv${data.family}`)}</p></div>
    </div>
    <section class="email-auth">
      ${renderFacts(data.family === 4 ? [
        ["Address", data.address], ["Network", data.network], ["Netmask", data.netmask], ["Wildcard", data.wildcard],
        ["Broadcast", data.broadcast], ["First host", data.first], ["Last host", data.last],
        ["Addresses", Number(data.total).toLocaleString()], ["Usable hosts", Number(data.usable).toLocaleString()],
        ["Binary netmask", data.binaryMask], ["Hex", data.hex], ["Reverse DNS zone", data.reverseZone],
      ] : [
        ["Address", data.address], ["Network", data.network], ["First address", data.first], ["Last address", data.last],
        ["Addresses", BigInt(data.total) > 10n ** 15n ? `2^${128 - data.prefix}` : BigInt(data.total).toLocaleString()],
        ["Expanded", data.expanded], ["Reverse DNS zone", data.reverseZone],
      ])}
    </section>
    ${splitOptions.length ? `
      <section class="email-auth">
        <h3>Split into subnets</h3>
        <label class="ip-split">Subnet size <select id="ip-split">${splitOptions.map((value) => `<option value="${value}" ${value === data.split ? "selected" : ""}>/${value}</option>`).join("")}</select>
          <span>${escapeHtml(`${BigInt(data.splitCount).toLocaleString()} subnet(s)${BigInt(data.splitCount) > 256n ? ", first 256 shown" : ""}`)}</span></label>
        <div class="ip-subnets">${data.subnets.map((subnet) => copyableResult(subnet)).join("")}</div>
      </section>` : ""}`;
  resultPanel.hidden = false;
  resultPanel.querySelector("#ip-split")?.addEventListener("change", (event) => {
    const next = calculateIp(data.input, Number(event.target.value));
    renderIpCalcResult(next);
    if (lastResult?.mode === "ip-calc") lastResult.data.result = next;
  });
}
