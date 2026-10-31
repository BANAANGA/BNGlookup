"use strict";

// Simple landing page: one search box that runs every tool visitors may use and shows
// the combined results in animated tabs per category. The full interface is behind the
// small "Log in" button.

const categories = [
  { id: "overview", label: "tabOverview" },
  { id: "dns", label: "tabDns" },
  { id: "email", label: "tabEmail" },
  { id: "web", label: "tabWeb" },
  { id: "security", label: "tabSecurity" },
  { id: "network", label: "tabNetwork" },
];
const themeVariables = {
  background: "--bg", background2: "--bg2", surface: "--surface", text: "--text", muted: "--muted",
  accent: "--accent", accent2: "--accent2", success: "--ok", warning: "--warn", danger: "--bad",
};
const statusWords = { good: "Good", warn: "Attention", bad: "Problem", info: "Info" };
const severityRank = { high: 3, medium: 2, low: 1 };

const page = {
  config: null,
  auth: null,
  content: {},
  run: 0,
  token: "",
  jobs: [],
  active: "overview",
  preview: window.location.pathname === "/landing" && new URLSearchParams(window.location.search).has("preview"),
};

const byId = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function plural(count, word, many = `${word}s`) {
  return `${count.toLocaleString()} ${count === 1 ? word : many}`;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value || "") : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function daysUntil(value) {
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? null : Math.floor((time - Date.now()) / 86400000);
}

function motionAllowed() {
  return !document.body.classList.contains("no-anim") && !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// ------------------------------------------------------------------ Theme and content

function relativeLuminance(hex) {
  const [r, g, b] = [1, 3, 5].map((index) => {
    const channel = parseInt(hex.slice(index, index + 2), 16) / 255;
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function applyTheme(theme, background) {
  const root = document.documentElement.style;
  for (const [key, variable] of Object.entries(themeVariables)) {
    if (/^#[0-9a-f]{6}$/i.test(theme[key] || "")) root.setProperty(variable, theme[key]);
  }
  if (theme.fontStack) root.setProperty("--font", theme.fontStack);
  root.setProperty("--radius", `${Number(theme.radius) || 0}px`);
  root.setProperty("--overlay", String((Number(theme.overlay) || 0) / 100));
  root.setProperty("--blur", `${Number(theme.blur) || 0}px`);
  const light = /^#[0-9a-f]{6}$/i.test(theme.background || "") && relativeLuminance(theme.background) > 0.45;
  root.setProperty("color-scheme", light ? "light" : "dark");
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme.background || "#06080f");

  const image = byId("backdrop-image");
  const mode = theme.backgroundMode === "image" && !background?.url ? "aurora" : theme.backgroundMode;
  image.style.backgroundImage = mode === "image" ? `url("${background.url.replace(/["\\]/g, "")}")` : "";
  const body = document.body.classList;
  for (const name of ["aurora", "gradient", "solid", "image"]) body.toggle(`bg-${name}`, mode === name);
  body.toggle("no-anim", theme.animations === false);
  body.toggle("glass", theme.glass !== false);
}

function applyContent(content) {
  page.content = content;
  byId("headline").textContent = content.headline || "";
  byId("subheadline").textContent = content.subheadline || "";
  byId("query").placeholder = content.placeholder || "";
  byId("scan-label").textContent = content.button || "Scan";
  byId("footer").textContent = content.footer || "";
  const examples = byId("examples");
  examples.replaceChildren(...String(content.examples || "").split(",").map((item) => item.trim()).filter(Boolean).slice(0, 6).map((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "example";
    button.textContent = item;
    button.addEventListener("click", () => {
      byId("query").value = item;
      startScan();
    });
    return button;
  }));
  if (!page.auth?.user) byId("login-label").textContent = content.login || "Log in";
  document.querySelectorAll(".tab").forEach((tab) => {
    const category = categories.find((item) => item.id === tab.dataset.category);
    if (category) tab.querySelector(".tab-name").textContent = content[category.label] || category.id;
  });
  positionIndicator();
}

function applyConfig(config) {
  applyTheme(config.theme || {}, config.background);
  applyContent(config.content || {});
  if (config.siteTitle) document.title = config.siteTitle;
  if (config.iconUrl) {
    byId("hero-logo").src = config.iconUrl;
    document.querySelector('link[rel="icon"]').href = config.iconUrl;
  }
}

// ------------------------------------------------------------------ What can be scanned

function allowedFeatures() {
  const access = page.auth?.featureAccess || {};
  const user = page.auth?.user;
  const allowed = new Set(page.config.publicFeatures || []);
  if (user) {
    for (const [feature, level] of Object.entries(access)) {
      if (level === "user" || (level === "admin" && user.role === "admin")) allowed.add(feature);
    }
  }
  return allowed;
}

function classify(raw) {
  let value = String(raw || "").trim();
  if (!value) return null;
  const compact = value.replace(/\s+/g, "");
  if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(compact) || /^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/i.test(compact)) {
    return { kind: "mac", value: compact };
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) && value.split(".").every((part) => Number(part) <= 255)) return { kind: "ip", value };
  const bracketless = value.replace(/^\[|\]$/g, "");
  if (bracketless.includes(":") && /^[0-9a-f:.]+$/i.test(bracketless) && bracketless.split(":").length > 2) return { kind: "ip", value: bracketless };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      value = new URL(value).hostname;
    } catch {
      return null;
    }
  } else {
    value = value.replace(/^[^@\s]*@/, "").split(/[/?#]/)[0].replace(/:\d+$/, "");
  }
  try {
    value = new URL(`http://${value}`).hostname.replace(/\.$/, "");
  } catch {
    return null;
  }
  if (!/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i.test(value)) return null;
  return { kind: "domain", value };
}

async function api(url, token = page.token) {
  const response = await fetch(url, { credentials: "same-origin", headers: { "x-landing-scan": token } });
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) throw new Error(data?.error || `The check failed (HTTP ${response.status}).`);
  return data;
}

const query = (path, params) => `${path}?${new URLSearchParams(params)}`;

async function pingTarget(name, call = api) {
  const icmp = await call(query("/api/ping", { name }));
  if (icmp.up || !/not available/i.test(icmp.error || "")) return icmp;
  return call(query("/api/ping", { name, method: "https" }));
}

// token is the landing scan token the tool calls use (each compared scan has its own).
function planJobs(target, allowed, token) {
  const name = target.value;
  const call = (url) => api(url, token ?? page.token);
  const jobs = [];
  const add = (feature, job) => {
    if (allowed.has(feature)) jobs.push({ feature, ...job });
  };
  if (target.kind === "domain") {
    add("forward", {
      id: "records", category: "dns", title: "DNS records", render: renderRecords,
      load: async () => Object.fromEntries(await Promise.all(["A", "AAAA", "MX", "NS", "TXT", "CAA"]
        .map(async (type) => [type, await call(query("/api/lookup", { name, type }))]))),
    });
    add("forward", { id: "dnssec", category: "dns", title: "DNSSEC", render: renderDnssec, load: () => call(query("/api/lookup", { name, type: "DNSSEC" })) });
    add("whois", { id: "whois", category: "dns", title: "Registration", render: renderWhois, load: () => call(query("/api/domain-info", { name })) });
    add("propagation", { id: "propagation", category: "dns", title: "Propagation", render: renderPropagation, load: () => call(query("/api/propagation", { name, type: "A" })) });
    add("dns-health", { id: "dns-health", category: "dns", title: "Name server health", render: renderDnsHealth, load: () => call(query("/api/dns-health", { name })) });
    add("email", { id: "email", category: "email", title: "Email security", render: renderEmail, load: () => call(query("/api/email-check", { name })) });
    add("mail-server", { id: "mail-server", category: "email", title: "Mail servers", render: renderMailServers, load: () => call(query("/api/mail-server", { name })) });
    add("web", { id: "web", category: "web", title: "Website", render: renderWeb, load: () => call(query("/api/web-check", { name })) });
    add("privacy", { id: "privacy", category: "web", title: "Privacy", render: renderPrivacy, load: () => call(query("/api/privacy", { name })) });
    add("sslscan", { id: "tls", category: "web", title: "TLS certificate", render: renderTls, load: () => call(query("/api/sslscan", { name, port: "443" })) });
    add("reputation", { id: "reputation", category: "security", title: "Reputation", render: renderReputation, load: () => call(query("/api/reputation", { name })) });
    add("subdomains", { id: "subdomains", category: "security", title: "Subdomains", render: renderSubdomains, load: () => call(query("/api/subdomains", { name })) });
    add("lookalike", { id: "lookalike", category: "security", title: "Look-alike domains", render: renderLookalike, load: () => call(query("/api/lookalike", { name })) });
    add("ping", { id: "ping", category: "network", title: "Reachability", render: renderPing, load: () => pingTarget(name, call) });
    add("asn", { id: "asn", category: "network", title: "Network (ASN)", render: renderAsn, load: () => call(query("/api/asn", { name })) });
    add("ipv6", { id: "ipv6", category: "network", title: "IPv6 readiness", render: renderIpv6, load: () => call(query("/api/ipv6", { name })) });
  } else if (target.kind === "ip") {
    add("reverse", { id: "reverse", category: "dns", title: "Reverse DNS", render: renderReverse, load: () => call(query("/api/lookup", { name, reverse: "true" })) });
    add("whois", { id: "whois", category: "dns", title: "IP registration", render: renderIpWhois, load: () => call(query("/api/domain-info", { name })) });
    add("reputation", { id: "reputation", category: "security", title: "Reputation", render: renderReputation, load: () => call(query("/api/reputation", { name })) });
    add("ping", { id: "ping", category: "network", title: "Reachability", render: renderPing, load: () => pingTarget(name, call) });
    add("asn", { id: "asn", category: "network", title: "Network (ASN)", render: renderAsn, load: () => call(query("/api/asn", { name })) });
  } else {
    add("mac", { id: "mac", category: "network", title: "MAC address vendor", render: renderMac, load: () => call(query("/api/mac-lookup", { name })) });
  }
  return jobs;
}

// ------------------------------------------------------------------ Result renderers
// Each renderer returns { status, summary, grade?, facts: [[label, value]], checks: [...], issues: [...] }.

const stateFromCheck = (state) => ({ pass: "good", ok: "good", good: "good", clean: "good", valid: "good", warn: "warn", warning: "warn", fail: "bad", bad: "bad", error: "info", flagged: "bad", invalid: "bad" })[state] || "info";

function normalizeIssues(list) {
  return (Array.isArray(list) ? list : []).map((issue) => (typeof issue === "string"
    ? { severity: "medium", message: issue }
    : { severity: issue?.severity || "medium", message: issue?.message || "" })).filter((issue) => issue.message);
}

function statusFromIssues(issues, fallback = "good") {
  if (issues.some((issue) => issue.severity === "high")) return "bad";
  if (issues.some((issue) => issue.severity === "medium")) return "warn";
  return fallback;
}

function renderRecords(data) {
  const facts = [];
  for (const [type, result] of Object.entries(data)) {
    const answers = (result.answers || []).filter((answer) => answer.typeName === type || !answer.typeName);
    if (answers.length) facts.push([type, answers.map((answer) => answer.data).join("\n")]);
  }
  const nx = data.A?.statusText === "NXDOMAIN";
  const hasAddress = facts.some(([type]) => type === "A" || type === "AAAA");
  const issues = [];
  if (nx) issues.push({ severity: "high", message: "The domain does not exist (NXDOMAIN)." });
  else if (!hasAddress) issues.push({ severity: "low", message: "The domain has no A or AAAA record, so it has no website at this name." });
  if (!nx && !data.CAA?.answers?.length) issues.push({ severity: "low", message: "No CAA record limits which certificate authorities may issue certificates." });
  return {
    status: nx ? "bad" : hasAddress ? "good" : "warn",
    summary: nx ? "This domain does not exist." : `${plural(facts.reduce((sum, [, value]) => sum + value.split("\n").length, 0), "record")} found.`,
    facts: facts.map(([type, value]) => [type, value, true]),
    issues,
  };
}

function renderDnssec(data) {
  const check = data.dnssecCheck || {};
  const status = { secure: "good", unsigned: "warn", insecure: "warn", bogus: "bad" }[check.status] || "info";
  return {
    status,
    summary: check.summary,
    facts: [["Status", check.status], ["DS records", String(check.ds?.length || 0)], ["DNSKEY records", String(check.dnskeys?.length || 0)]],
    issues: normalizeIssues(check.issues).concat(check.status === "unsigned" ? [{ severity: "low", message: "DNSSEC is not enabled, so DNS answers cannot be verified." }] : []),
  };
}

function renderWhois(data) {
  const registration = data.registration;
  if (!registration) return { status: "info", summary: data.registrationError || "No registration details were returned.", facts: [], issues: [] };
  const dates = registration.dates || {};
  const expiresIn = dates.expiration ? daysUntil(dates.expiration) : null;
  const issues = [];
  if (expiresIn !== null && expiresIn < 0) issues.push({ severity: "high", message: "The domain registration has expired." });
  else if (expiresIn !== null && expiresIn < 30) issues.push({ severity: "medium", message: `The domain registration expires in ${plural(expiresIn, "day")}.` });
  const nameservers = (registration.nameservers || []).map((server) => String(server.name || "").toLowerCase()).filter(Boolean);
  return {
    status: statusFromIssues(issues, "info"),
    summary: registration.registrar?.name ? `Registered through ${registration.registrar.name}.` : "Registration details found.",
    facts: [
      ["Registrar", registration.registrar?.name],
      ["Registered", dates.registration && formatDate(dates.registration)],
      ["Expires", dates.expiration && `${formatDate(dates.expiration)}${expiresIn !== null && expiresIn >= 0 ? ` (in ${plural(expiresIn, "day")})` : ""}`],
      ["Status", (registration.statuses || []).join(", ")],
      ["Name servers", nameservers.join("\n"), true],
    ].filter(([, value]) => value),
    issues,
  };
}

function renderIpWhois(data) {
  const registration = data.ipRegistration;
  if (!registration) return { status: "info", summary: data.registrationError ? `No registration details (${data.registrationError}).` : "No registration details were returned.", facts: [], issues: [] };
  return {
    status: "info",
    summary: registration.name ? `Registered as ${registration.name}.` : "Registration details found.",
    facts: [
      ["Network", registration.name],
      ["Handle", registration.handle],
      ["Range", (registration.cidrs || []).join(", ")],
      ["Country", registration.country],
      ["AS numbers", (registration.asNumbers || []).map((asn) => `AS${String(asn).replace(/^AS/i, "")}`).join(", ")],
    ].filter(([, value]) => value),
    issues: [],
  };
}

function renderPropagation(data) {
  const results = data.results || [];
  return {
    status: data.consistent ? "good" : "warn",
    summary: data.consistent
      ? `All ${plural(results.length, "resolver")} return the same answer.`
      : `Resolvers return ${plural(data.distinctAnswers || 0, "different answer")}; a change may still be spreading.`,
    facts: [["Answered", `${data.answered ?? 0} of ${results.length}`]],
    checks: results.map((result) => ({
      state: result.status !== "NOERROR" ? "bad" : result.group === 0 ? "good" : "warn",
      label: result.source,
      text: result.answers?.length ? result.answers.join(", ") : result.status,
    })),
    issues: data.consistent ? [] : [{ severity: "low", message: "Not all resolvers return the same A records yet." }],
  };
}

function renderDnsHealth(data) {
  const issues = normalizeIssues(data.issues);
  return {
    status: statusFromIssues(issues),
    summary: `${plural((data.nameservers || []).length, "name server")} checked for ${data.zone || data.domain}.`,
    checks: (data.checks || []).map((check) => ({ state: stateFromCheck(check.state), label: check.label, text: check.message })),
    issues,
  };
}

function renderEmail(data) {
  const mx = data.mx || {};
  const records = mx.records || [];
  const smtp = data.smtp || [];
  const connected = smtp.filter((server) => server.connected);
  const dmarcPolicy = data.dmarc?.policy;
  const checks = [
    { state: data.spf?.found ? (/^[-~]all$/.test(data.spf.all || "") ? "good" : "warn") : "bad", label: "SPF", text: data.spf?.found ? `Found, ends with ${data.spf.all || "no all"} (${plural(data.spf.lookups || 0, "lookup")}).` : "No SPF record." },
    { state: !data.dmarc?.found ? "bad" : dmarcPolicy === "none" ? "warn" : "good", label: "DMARC", text: data.dmarc?.found ? `Policy: ${dmarcPolicy || "none"}.` : "No DMARC record." },
    { state: data.dkim?.records?.length ? "good" : "warn", label: "DKIM", text: data.dkim?.records?.length ? `${plural(data.dkim.records.length, "key")} found (${data.dkim.records.map((record) => record.selector).join(", ")}).` : `None of ${data.dkim?.checked || 0} common selectors found.` },
    { state: data.mtaSts?.found ? "good" : "info", label: "MTA-STS", text: data.mtaSts?.found ? `Published${data.mtaSts.policy?.mode ? `, mode ${data.mtaSts.policy.mode}` : ""}.` : "Not published." },
    { state: data.tlsRpt?.found ? "good" : "info", label: "TLS-RPT", text: data.tlsRpt?.found ? "Published." : "Not published." },
    { state: data.bimi?.found ? "good" : "info", label: "BIMI", text: data.bimi?.found ? "Brand logo published." : "Not published." },
  ];
  if (smtp.length) {
    checks.push({
      state: !connected.length ? "info" : connected.every((server) => server.starttls) ? "good" : "bad",
      label: "STARTTLS",
      text: !connected.length ? "The mail servers could not be reached from this server." : `${connected.filter((server) => server.starttls).length} of ${connected.length} reachable mail servers offer encryption.`,
    });
  }
  const issues = [
    // A missing record is reported once below, not also by the tool's own findings.
    ...(data.spf?.found ? normalizeIssues(data.spf.issues) : []), ...(data.dmarc?.found ? normalizeIssues(data.dmarc.issues) : []), ...normalizeIssues(data.mtaSts?.issues),
    ...normalizeIssues(data.tlsRpt?.issues), ...normalizeIssues(data.bimi?.issues), ...smtp.flatMap((server) => normalizeIssues(server.issues)),
  ];
  if (!data.spf?.found) issues.push({ severity: "high", message: "No SPF record, so anyone can send mail that claims to come from this domain." });
  if (!data.dmarc?.found) issues.push({ severity: "high", message: "No DMARC record, so receivers have no policy for forged mail." });
  else if (dmarcPolicy === "none") issues.push({ severity: "medium", message: "The DMARC policy is p=none, so forged mail is still delivered." });
  return {
    status: statusFromIssues(issues),
    summary: mx.nullMx
      ? "This domain says it does not receive mail (null MX)."
      : records.length ? `Mail goes to ${data.providers?.inbound?.[0] || records[0].host}.` : "No MX records: this domain does not receive mail.",
    facts: [["Mail servers", records.map((record) => `${record.priority}  ${record.host}`).join("\n"), true]].filter(([, value]) => value),
    checks,
    issues,
  };
}

function renderMailServers(data) {
  const reachable = data.servers.filter((server) => server.connected && !server.error);
  const issues = normalizeIssues(data.issues);
  return {
    status: !data.servers.length || !reachable.length ? statusFromIssues(issues, "info") : statusFromIssues(issues),
    summary: data.nullMx ? "This domain does not accept mail."
      : !data.servers.length ? "No mail servers to test."
      : !reachable.length ? "The mail servers could not be reached on port 25 from this server."
      : `${plural(reachable.length, "mail server")} tested on port 25.`,
    checks: reachable.flatMap((server) => [
      { state: server.relay?.open ? "bad" : server.relay?.tested ? "good" : "info", label: `${server.host}: open relay`, text: server.relay?.open ? "Accepts mail for other domains." : server.relay?.tested ? "No." : "Not tested." },
      { state: server.ptr?.confirmed ? "good" : "warn", label: `${server.host}: reverse DNS`, text: server.ptr?.confirmed ? server.ptr.confirmedName : server.ptr?.names?.length ? `${server.ptr.names[0]} (not confirmed)` : "None." },
      { state: server.authBeforeTls ? "warn" : "good", label: `${server.host}: login before TLS`, text: server.authBeforeTls ? "Offered." : "No." },
    ]),
    issues,
  };
}

function renderWeb(data) {
  const score = Number(data.score);
  const issues = normalizeIssues(data.issues);
  const days = data.tls?.daysRemaining;
  return {
    status: !Number.isFinite(score) ? statusFromIssues(issues) : score >= 80 ? "good" : score >= 50 ? "warn" : "bad",
    grade: data.grade,
    summary: [data.finalStatus && `HTTP ${data.finalStatus}`, data.title].filter(Boolean).join(" · ") || data.httpUnavailable || "",
    facts: [
      ["Final address", data.finalUrl],
      ["HTTPS", data.https ? (data.redirectsToHttps ? "Yes, HTTP redirects to HTTPS" : "Yes") : "No"],
      ["Protocols", [data.http2 && "HTTP/2", data.http3 && "HTTP/3"].filter(Boolean).join(", ") || "HTTP/1.1"],
      ["Certificate", Number.isFinite(days) ? `Valid for ${plural(days, "more day")}` : ""],
      ["Server", data.server],
      ["First byte", Number.isFinite(data.firstByteMs) ? `${data.firstByteMs} ms` : ""],
    ].filter(([, value]) => value),
    checks: (data.checks || []).map((check) => ({ state: stateFromCheck(check.state), label: check.label, text: check.message })),
    issues,
  };
}

function certificateName(value, key) {
  const match = String(value || "").match(new RegExp(`(?:^|, )${key}=([^,]+)`));
  return match ? match[1] : "";
}

function renderTls(data) {
  if (!data.handshake) {
    return { status: "bad", summary: data.error || "The TLS handshake failed.", facts: [], issues: [{ severity: "high", message: `No TLS connection on port ${data.port || 443}: ${data.error || "handshake failed"}` }] };
  }
  const leaf = data.certificateChain?.[0] || {};
  const days = daysUntil(leaf.validTo);
  const issues = [];
  if (!data.authorized) issues.push({ severity: "high", message: `The certificate is not trusted: ${data.authorizationError || "unknown reason"}.` });
  if (days !== null && days < 0) issues.push({ severity: "high", message: "The certificate has expired." });
  else if (days !== null && days < 21) issues.push({ severity: "medium", message: `The certificate expires in ${plural(days, "day")}.` });
  if (/^TLSv1(\.1)?$/.test(data.protocol || "")) issues.push({ severity: "high", message: `The server negotiated the outdated ${data.protocol}.` });
  return {
    status: statusFromIssues(issues),
    summary: data.authorized ? "The certificate is trusted." : "The certificate is not trusted.",
    facts: [
      ["Issued to", certificateName(leaf.subject, "CN")],
      ["Issuer", certificateName(leaf.issuer, "O") || certificateName(leaf.issuer, "CN")],
      ["Valid until", leaf.validTo && `${formatDate(leaf.validTo)}${days !== null && days >= 0 ? ` (${plural(days, "day")})` : ""}`],
      ["Protocol", data.protocol],
      ["Cipher", data.cipher?.name, true],
    ].filter(([, value]) => value),
    issues,
  };
}

function renderReputation(data) {
  const flagged = data.flagged || 0;
  const status = data.verdict === "malicious" ? "bad" : data.verdict === "suspicious" ? "warn" : "good";
  return {
    status,
    summary: flagged ? `${flagged} of ${plural(data.checked || 0, "source")} flag this ${data.isAddress ? "address" : "domain"}.` : `None of ${plural(data.checked || 0, "source")} flag this ${data.isAddress ? "address" : "domain"}.`,
    checks: (data.sources || []).map((source) => ({ state: source.state === "suspicious" ? "warn" : stateFromCheck(source.state), label: source.source, text: source.detail })),
    issues: flagged ? [{ severity: status === "bad" ? "high" : "medium", message: `Listed as ${data.verdict} by ${plural(flagged, "security source")}.` }] : [],
  };
}

function renderSubdomains(data) {
  const issues = normalizeIssues(data.issues);
  const risky = data.subdomains.filter((entry) => entry.takeover || entry.private);
  return {
    status: statusFromIssues(issues),
    summary: `${plural(data.subdomains.length, "subdomain")} found${data.sources.certificates.error ? " (certificate logs unavailable)" : ""}.`,
    facts: [["Where they point", data.groups.slice(0, 5).map((group) => `${group.label}: ${group.names.length}`).join("\n")]].filter(([, value]) => value),
    checks: (risky.length ? risky : data.subdomains.slice(0, 12)).map((entry) => ({
      state: entry.takeover?.status === "vulnerable" ? "bad" : entry.takeover || entry.private ? "warn" : "info",
      label: entry.name,
      text: entry.takeover ? (entry.takeover.status === "vulnerable" ? `takeover risk${entry.takeover.service ? ` (${entry.takeover.service})` : ""}` : `dangling CNAME to ${entry.cname}`)
        : entry.private ? `private address ${entry.addresses[0]}` : entry.provider || entry.addresses[0] || "no address",
      mono: true,
    })),
    issues,
  };
}

function renderLookalike(data) {
  const registered = data.registered || [];
  const high = data.counts?.high || 0;
  return {
    status: high ? "warn" : registered.length ? "info" : "good",
    summary: `${plural(registered.length, "look-alike domain")} registered out of ${(data.checked || 0).toLocaleString()} checked.`,
    checks: registered.map((item) => ({
      state: item.risk === "high" ? "bad" : item.risk === "medium" ? "warn" : "info",
      label: item.name,
      text: [item.kind, item.mx?.length ? "receives mail" : "", item.addresses?.length ? "has a website address" : ""].filter(Boolean).join(" · "),
      mono: true,
    })),
    issues: high ? [{ severity: "medium", message: `${plural(high, "high-risk look-alike domain")} could be used for phishing.` }] : [],
  };
}

function renderPing(data) {
  return {
    status: data.up ? "good" : "bad",
    summary: data.up ? `Reachable${Number.isFinite(data.responseMs ?? data.timeMs) ? ` in ${data.responseMs ?? data.timeMs} ms` : ""}.` : data.error || "Not reachable.",
    facts: [
      ["Address", data.address, true],
      ["Method", String(data.method || "").toUpperCase()],
      ["Response", data.status ? `${data.status} ${data.statusText || ""}` : ""],
    ].filter(([, value]) => value),
    issues: data.up ? [] : [{ severity: "medium", message: `The host did not answer (${data.error || "no reply"}).` }],
  };
}

function renderAsn(data) {
  const rpki = data.network?.rpki?.status;
  const issues = rpki === "invalid" ? [{ severity: "high", message: "The route is RPKI-invalid: the announcing network is not authorized." }] : [];
  return {
    status: statusFromIssues(issues, "info"),
    summary: data.as ? `AS${data.as.asn} · ${data.as.holder || "unknown holder"}` : "No network information.",
    facts: [
      ["Address", data.network?.address, true],
      ["Prefix", data.network?.prefix, true],
      ["RPKI", rpki],
      ["Registry", data.as?.registry],
      ["Announced", data.prefixes ? `${plural(data.prefixes.ipv4Count || 0, "IPv4 prefix", "IPv4 prefixes")}, ${plural(data.prefixes.ipv6Count || 0, "IPv6 prefix", "IPv6 prefixes")}` : ""],
    ].filter(([, value]) => value),
    issues,
  };
}

function renderPrivacy(data) {
  if (data.error) return { status: "info", summary: data.error, facts: [], issues: [] };
  const issues = normalizeIssues(data.issues);
  const ungated = data.thirdParties.filter((party) => party.tracking && !party.gated);
  return {
    status: statusFromIssues(issues),
    grade: data.grade,
    summary: ungated.length ? `${plural(ungated.length, "tracker")} load before a visitor can consent.` : `No trackers load before consent; ${plural(data.thirdParties.length, "third party", "third parties")} in total.`,
    checks: data.thirdParties.slice(0, 12).map((party) => ({
      state: party.tracking && !party.gated ? (party.category === "advertising" || party.category === "session-replay" ? "bad" : "warn") : party.gated || party.category === "consent" ? "good" : "info",
      label: party.name,
      text: `${party.categoryLabel}${party.gated ? " · after consent" : ""}`,
    })),
    facts: [["Consent banner", data.consent.join(", ") || "not found"], ["Cookies set at once", String(data.cookies.length)]],
    issues,
  };
}

function renderIpv6(data) {
  const issues = normalizeIssues(data.issues);
  const part = (label, percent) => ({ state: percent === null ? "info" : percent >= 100 ? "good" : percent > 0 ? "warn" : "bad", label, text: percent === null ? "not used" : percent >= 100 ? "ready for IPv6" : percent > 0 ? "partly ready" : "IPv4 only" });
  return {
    status: data.score >= 100 ? "good" : statusFromIssues(issues, "warn"),
    grade: data.grade,
    summary: `${data.score}/100 for IPv6.${data.serverHasIpv6 ? "" : " Only the records could be checked; this server has no IPv6."}`,
    checks: [part("Website", data.parts.web), part("Mail", data.parts.mail), part("Name servers", data.parts.dns)],
    issues,
  };
}

function renderReverse(data) {
  const names = (data.answers || []).map((answer) => answer.data);
  return {
    status: names.length ? "good" : "warn",
    summary: names.length ? `Points back to ${names[0]}.` : "This address has no reverse DNS name.",
    facts: names.length ? [["PTR", names.join("\n"), true]] : [],
    issues: names.length ? [] : [{ severity: "low", message: "No PTR record: mail from this address is often rejected." }],
  };
}

function renderMac(data) {
  return {
    status: data.found ? "info" : "warn",
    summary: data.found ? `Made by ${data.company}.` : data.locallyAdministered ? "A private (randomized) address; it has no registered vendor." : "No vendor is registered for this prefix.",
    facts: [
      ["Address", data.mac, true],
      ["Vendor", data.company],
      ["Country", data.country],
      ["Likely device", data.deviceGuess?.category && data.deviceGuess.category !== "Unknown" ? data.deviceGuess.category : ""],
    ].filter(([, value]) => value),
    issues: [],
  };
}

// ------------------------------------------------------------------ How to fix
// Plain-language advice for common findings, matched on the finding's text. A snippet is
// a ready-to-use record, header or setting for the scanned domain.

const fixCatalog = [
  { match: /more than one spf record/i, text: "Merge all SPF records into one TXT record that starts with v=spf1; receivers treat two records as an error." },
  { match: /\+all allows every server/i, text: "Replace +all with -all (or ~all while testing) so only the listed servers may send mail.", snippet: (d) => `${d}. TXT "v=spf1 mx -all"` },
  { match: /no spf record|spf.*no spf record/i, text: "Publish one SPF record listing the servers and services that send mail for the domain. Add include: entries for services such as your mail provider or newsletter tool.", snippet: (d) => `${d}. TXT "v=spf1 mx -all"` },
  { match: /\?all is neutral|no all mechanism/i, text: "End the SPF record with -all (or ~all) so unlisted senders fail.", snippet: (d) => `${d}. TXT "v=spf1 mx -all"` },
  { match: /spf needs \d+ dns lookups/i, text: "Remove unused include: entries, or flatten them into ip4:/ip6: ranges with the SPF flattener in the full interface." },
  { match: /more than one dmarc record/i, text: "Keep exactly one TXT record at _dmarc; delete the others." },
  { match: /no dmarc record|dmarc.*no dmarc record/i, text: "Publish a DMARC record. Start by collecting reports, then move to quarantine and reject once all your own mail passes.", snippet: (d) => `_dmarc.${d}. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${d}"` },
  { match: /p=none only monitors|policy: none|dmarc policy is p=none/i, text: "Check the DMARC reports; once your own mail passes SPF or DKIM, raise the policy to quarantine and later reject.", snippet: (d) => `_dmarc.${d}. TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@${d}"` },
  { match: /no valid p= policy/i, text: "Add a p= tag with none, quarantine or reject to the DMARC record.", snippet: (d) => `_dmarc.${d}. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${d}"` },
  { match: /dkim|common selectors/i, text: "Turn on DKIM signing at your mail provider and publish the public key it gives you as a TXT record at <selector>._domainkey. If you already sign, the selector may simply have an uncommon name." },
  { match: /starttls is not offered|starttls/i, text: "Enable STARTTLS on the mail server with a valid certificate, so mail to the domain is encrypted in transit." },
  { match: /mta-sts.*testing mode/i, text: "After a few weeks of clean TLS reports, change mode: testing to mode: enforce in the policy file and update the id in the _mta-sts record." },
  { match: /mta-sts/i, text: "Publish an MTA-STS policy so senders require TLS. You need a TXT record plus a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt (BNGlookup can host it).", snippet: (d) => `_mta-sts.${d}. TXT "v=STSv1; id=${new Date().toISOString().slice(0, 10).replace(/-/g, "")}"` },
  { match: /tls-rpt/i, text: "Publish a TLS-RPT record to receive reports about failed encrypted deliveries.", snippet: (d) => `_smtp._tls.${d}. TXT "v=TLSRPTv1; rua=mailto:tls-reports@${d}"` },
  { match: /open relay|accepts mail for other domains/i, text: "Only relay mail for your own domains and for users who log in. In Postfix, check smtpd_relay_restrictions (permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination)." },
  { match: /login before tls|auth\) before encryption|password login/i, text: "Only offer AUTH after STARTTLS. For Postfix: smtpd_tls_auth_only = yes." },
  { match: /reverse dns.*(not confirmed|does not point back)|not forward-confirmed/i, text: "Make the reverse DNS (PTR) name of the mail server's address resolve back to the same address, ideally the name it uses in HELO. Your hosting provider sets the PTR record." },
  { match: /before a visitor can give consent|no consent banner/i, text: "Load analytics, advertising and session-recording scripts only after the visitor agrees: use a consent banner (CMP) and mark those scripts to run after consent, or switch to cookieless, privacy-friendly analytics." },
  { match: /google fonts are loaded/i, text: "Download the fonts and serve them from your own website (for example with the google-webfonts-helper), then remove the links to fonts.googleapis.com." },
  { match: /embedded from youtube\.com/i, text: "Change the embed address from www.youtube.com/embed/… to www.youtube-nocookie.com/embed/…." },
  { match: /no link to a privacy/i, text: "Add a link to your privacy and cookie policy in the footer of every page." },
  { match: /tag manager is used/i, text: "Review the tags in your tag manager and make every tracking tag wait for consent." },
  { match: /no aaaa record|ipv4 only|no ipv6 address|ipv6 address .* without reverse dns|does not answer over ipv6/i, text: "Ask your hosting, mail or DNS provider to enable IPv6, then publish AAAA records for the website, mail servers and name servers (and reverse DNS for IPv6 mail servers). Test before publishing: an AAAA record that does not answer is worse than none." },
  { match: /can probably be taken over|takeover risk/i, text: "Delete the DNS record of the unused subdomain, or claim the resource it points to again (the app, bucket or site at the provider)." },
  { match: /dangling cname/i, text: "Remove the CNAME record: it points to a name that no longer exists, and someone who registers that name controls your subdomain." },
  { match: /private address/i, text: "Remove public DNS records that point to internal addresses, or move them to an internal DNS zone." },
  { match: /bimi requires dmarc/i, text: "BIMI logos are only shown when DMARC is enforced: raise the DMARC policy to quarantine or reject.", snippet: (d) => `_dmarc.${d}. TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${d}"` },
  { match: /logo could not be fetched|logo.*served as/i, text: "Serve the BIMI logo directly (no redirects) over HTTPS as image/svg+xml in the SVG Tiny Portable/Secure format. BNGlookup can host it at /logo.svg." },
  { match: /mark certificate.*(expire|not valid)/i, text: "Renew the Verified Mark Certificate with your certificate authority and replace the file at the a= address." },
  { match: /dnssec is not enabled|dnssec/i, text: "Turn on DNSSEC signing at your DNS host, then add the DS record it shows at your domain registrar." },
  { match: /chain of trust is broken|no ds record matches/i, text: "The DS record at the registrar does not match the zone's keys. Replace it with the DS record your DNS host currently shows." },
  { match: /rrsig.*(expired|expires soon)/i, text: "The zone's signatures are expiring: check that automatic re-signing at your DNS host is working." },
  { match: /no caa record/i, text: "Add a CAA record naming the certificate authorities you use, so others cannot issue certificates for the domain.", snippet: (d) => `${d}. CAA 0 issue "letsencrypt.org"` },
  { match: /does not exist \(nxdomain\)/i, text: "Check the spelling. If the name is yours, check that it is registered and that the name servers serve the zone." },
  { match: /registration (has expired|expires)/i, text: "Renew the domain at your registrar and turn on automatic renewal, or it may be lost." },
  { match: /not all resolvers return the same|resolvers return \d+ different/i, text: "A recent change is still spreading (wait for the TTL to pass), or your name servers give different answers. Make sure every name server has the same zone." },
  { match: /glue/i, text: "Add glue records (the name servers' IP addresses) at the registrar for name servers inside your own domain." },
  { match: /lame delegation|answer authoritatively/i, text: "Remove name servers that do not serve the zone from the delegation at the registrar, or add the zone to them." },
  { match: /parent and zone agree|not listed in the zone/i, text: "Make the NS records in the zone and the name servers set at the registrar identical." },
  { match: /open recursion|answers recursive queries/i, text: "Turn off recursion for outside clients on the authoritative name servers (for BIND: recursion no; or allow-recursion { localhost; };)." },
  { match: /zone transfer|axfr/i, text: "Only allow zone transfers to your own secondary name servers (for BIND: allow-transfer { <secondary IP>; };)." },
  { match: /soa serials|different serials/i, text: "A secondary name server is not picking up changes: check zone transfers (NOTIFY / AXFR) from the primary." },
  { match: /network diversity|same \/24|one \/24/i, text: "Add a name server in a different network or with another DNS provider, so one outage does not take the domain down." },
  { match: /ipv6 name servers|no name server has an ipv6/i, text: "Give at least one name server an IPv6 address (AAAA record), so IPv6-only resolvers can reach it." },
  { match: /does not redirect http to https|not redirect/i, text: "Redirect all plain HTTP requests to HTTPS with a permanent (301) redirect.", snippet: () => "# nginx\nserver { listen 80; server_name _; return 301 https://$host$request_uri; }" },
  { match: /hsts|strict-transport-security/i, text: "Send an HSTS header from the HTTPS site so browsers always use HTTPS.", snippet: () => "Strict-Transport-Security: max-age=31536000; includeSubDomains" },
  { match: /content-security-policy|injected scripts/i, text: "Add a Content-Security-Policy header. Start strict and allow only the sources your site really uses.", snippet: () => "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'" },
  { match: /clickjacking|frame this page/i, text: "Stop other sites from embedding your pages in a frame.", snippet: () => "X-Frame-Options: DENY\n# or, in the Content-Security-Policy: frame-ancestors 'self'" },
  { match: /x-content-type-options|guess content types/i, text: "Tell browsers not to guess content types.", snippet: () => "X-Content-Type-Options: nosniff" },
  { match: /referrer-policy/i, text: "Limit what other sites learn from links on your pages.", snippet: () => "Referrer-Policy: strict-origin-when-cross-origin" },
  { match: /permissions-policy/i, text: "Turn off browser features the site does not use.", snippet: () => "Permissions-Policy: camera=(), microphone=(), geolocation=()" },
  { match: /software version/i, text: "Hide version numbers in the Server and X-Powered-By headers (for nginx: server_tokens off; for PHP: expose_php = Off)." },
  { match: /cookies?/i, text: "Set the Secure, HttpOnly and SameSite attributes on cookies.", snippet: () => "Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax" },
  { match: /mixed content/i, text: "Load every image, script and stylesheet over https:// (or use relative addresses)." },
  { match: /security\.txt/i, text: "Publish /.well-known/security.txt with a contact for security reports (RFC 9116).", snippet: (d) => `Contact: mailto:security@${d}\nExpires: ${new Date(Date.now() + 364 * 86400000).toISOString().slice(0, 10)}T00:00:00Z\nCanonical: https://${d}/.well-known/security.txt` },
  { match: /not compressed/i, text: "Enable gzip or Brotli compression on the web server (for nginx: gzip on;)." },
  { match: /final page returned http/i, text: "The site's start page returns an error: check the web server and application logs." },
  { match: /certificate (has expired|expires in)/i, text: "Renew the TLS certificate and switch to automatic renewal (ACME, for example Let's Encrypt)." },
  { match: /certificate is not trusted|does not cover|does not match/i, text: "Install a certificate from a public certificate authority that covers this exact host name, including the intermediate certificates." },
  { match: /tlsv1(\.1)?\b|outdated tls|tls 1\.2 or newer/i, text: "Turn off TLS 1.0 and 1.1 and allow only TLS 1.2 and 1.3.", snippet: () => "# nginx\nssl_protocols TLSv1.2 TLSv1.3;" },
  { match: /no tls connection|handshake failed/i, text: "Make sure HTTPS is served on port 443 with a valid certificate." },
  { match: /listed as (malicious|suspicious)|flag this/i, text: "Check the site and server for malware or phishing pages, clean them up, then ask each listing service to review the domain." },
  { match: /look-alike/i, text: "Watch the high-risk look-alikes. Consider registering the most dangerous ones yourself, and report abuse to their registrar." },
  { match: /did not answer|not reachable/i, text: "Check that the host is up and that a firewall allows the check (ICMP or HTTPS)." },
  { match: /rpki-invalid/i, text: "The announcing network is not authorized by the address holder's ROA. Ask the network operator to fix the route or the ROA." },
  { match: /no ptr record|no reverse dns|reverse dns: none/i, text: "Ask the owner of the IP address (usually your hosting provider) to set a reverse DNS (PTR) name." },
];

function fixFor(text) {
  return fixCatalog.find((fix) => fix.match.test(text)) || null;
}

function fixHtml(text) {
  const fix = fixFor(text);
  if (!fix) return "";
  const domain = page.target?.kind === "domain" ? page.target.value : "example.com";
  const snippet = fix.snippet ? fix.snippet(domain) : "";
  return `<details class="fix"><summary>How to fix</summary><div class="fix-body"><p>${escapeHtml(fix.text)}</p>${snippet
    ? `<div class="fix-snippet"><pre>${escapeHtml(snippet)}</pre><button class="fix-copy" type="button" data-copy="${escapeHtml(snippet)}">Copy</button></div>`
    : ""}</div></details>`;
}

// One listener handles the Copy buttons in every fix.
document.addEventListener("click", async (event) => {
  const button = event.target.closest?.(".fix-copy");
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "Copied ✓";
  } catch {
    button.textContent = "Copy failed";
  }
  window.setTimeout(() => { button.textContent = "Copy"; }, 1500);
});

// ------------------------------------------------------------------ Full details
// Every card can expand to show everything the tool returned, laid out as readable
// tables, plus the raw JSON and a link to the same tool in the full interface.

const fullModes = {
  "mail-server": "mail-server",
  subdomains: "subdomains",
  ipv6: "ipv6",
  privacy: "privacy",
  records: "forward", dnssec: "forward", whois: "details", propagation: "propagation", "dns-health": "dns-health", email: "email",
  web: "web", tls: "sslscan", reputation: "reputation", lookalike: "lookalike", ping: "ping", asn: "asn", reverse: "reverse", mac: "mac",
};
const acronyms = new Set(["dns", "mx", "spf", "dmarc", "dkim", "tls", "rpt", "sts", "bimi", "url", "ttl", "asn", "as", "http", "https", "ip", "ns",
  "soa", "ds", "rpki", "roa", "roas", "smtp", "ehlo", "mta", "ptr", "caa", "id", "oui", "rdap", "csp", "hsts", "cidr", "sha", "vmc", "axfr", "rua", "ruf", "nx"]);

const keyLabels = { mtaSts: "MTA-STS", tlsRpt: "TLS-RPT", subjectAltName: "Subject alternative names", fingerprint256: "SHA-256 fingerprint", altSvc: "Alt-Svc" };

function humanizeKey(key) {
  if (keyLabels[key]) return keyLabels[key];
  if (/^[A-Z0-9]+$/.test(key)) return key;
  const words = String(key).replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").trim().split(/\s+/);
  return words.map((word, index) => {
    const lower = word.toLowerCase();
    if (lower === "ms") return "(ms)";
    if (/^ipv[46]$/.test(lower)) return `IPv${lower.slice(3)}`;
    if (/^http[23]$/.test(lower)) return `HTTP/${lower.slice(4)}`;
    if (acronyms.has(lower)) return lower.toUpperCase();
    return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
  }).join(" ");
}

const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isPrimitive = (value) => value === null || ["string", "number", "boolean"].includes(typeof value);

function isEmptyValue(value) {
  return value === null || value === undefined || value === "" ||
    (Array.isArray(value) && !value.length) || (isPlainObject(value) && !Object.keys(value).length);
}

function primitiveHtml(value) {
  if (typeof value === "boolean") return `<span class="pill ${value ? "good" : "info"}">${value ? "Yes" : "No"}</span>`;
  if (typeof value === "number") return escapeHtml(Number.isInteger(value) ? value.toLocaleString() : String(Math.round(value * 100) / 100));
  const text = String(value ?? "");
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(text) && !Number.isNaN(Date.parse(text))) {
    return escapeHtml(new Date(text).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }));
  }
  if (text.length > 90 || text.includes("\n")) return `<pre class="detail-pre">${escapeHtml(text)}</pre>`;
  return `<span class="detail-text">${escapeHtml(text)}</span>`;
}

function arrayHtml(list, depth) {
  const items = list.filter((item) => !isEmptyValue(item));
  if (!items.length) return "";
  if (items.every(isPrimitive)) {
    return items.every((item) => String(item).length <= 60)
      ? `<div class="chips">${items.slice(0, 300).map((item) => `<span class="chip">${escapeHtml(item)}</span>`).join("")}${items.length > 300 ? `<span class="chip">+${items.length - 300}</span>` : ""}</div>`
      : `<ol class="detail-list">${items.slice(0, 300).map((item) => `<li>${primitiveHtml(item)}</li>`).join("")}</ol>`;
  }
  // Name/value pairs, such as response headers.
  if (items.every((item) => Array.isArray(item) && item.length === 2 && item.every(isPrimitive))) {
    return `<div class="detail-table-wrap"><table class="detail-table pairs"><tbody>${items.slice(0, 500).map(([name, value]) => `<tr><th scope="row">${escapeHtml(name)}</th><td data-label="${escapeHtml(name)}">${primitiveHtml(value)}</td></tr>`).join("")}</tbody></table></div>`;
  }
  if (items.every(isPlainObject)) {
    const columns = [...new Set(items.flatMap((item) => Object.keys(item)))]
      .filter((key) => items.some((item) => !isEmptyValue(item[key])));
    const flat = columns.every((key) => items.every((item) => isPrimitive(item[key]) || item[key] === undefined ||
      (Array.isArray(item[key]) && item[key].every(isPrimitive))));
    if (flat && columns.length <= 9) {
      const rows = items.slice(0, 500);
      return `<div class="detail-table-wrap"><table class="detail-table"><thead><tr>${columns.map((key) => `<th>${escapeHtml(humanizeKey(key))}</th>`).join("")}</tr></thead>
        <tbody>${rows.map((item) => `<tr>${columns.map((key) => `<td data-label="${escapeHtml(humanizeKey(key))}">${isEmptyValue(item[key]) ? "" : Array.isArray(item[key])
          ? escapeHtml(item[key].join(", "))
          : primitiveHtml(item[key])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>${items.length > rows.length ? `<p class="card-summary">${items.length - rows.length} more rows in the raw JSON.</p>` : ""}`;
    }
    return items.slice(0, 100).map((item, index) => `<div class="detail-item"><span class="detail-index">${index + 1}</span>${treeHtml(item, depth + 1)}</div>`).join("");
  }
  return items.slice(0, 100).map((item) => `<div class="detail-item">${valueHtml(item, depth + 1)}</div>`).join("");
}

function valueHtml(value, depth) {
  if (isPrimitive(value)) return primitiveHtml(value);
  if (depth > 6) return `<pre class="detail-pre">${escapeHtml(JSON.stringify(value, null, 2))}</pre>`;
  if (Array.isArray(value)) return arrayHtml(value, depth);
  return treeHtml(value, depth + 1);
}

function treeHtml(object, depth = 0) {
  const entries = Object.entries(object).filter(([, value]) => !isEmptyValue(value));
  const simple = entries.filter(([, value]) => isPrimitive(value) || (Array.isArray(value) && value.every(isPrimitive)));
  const complex = entries.filter((entry) => !simple.includes(entry));
  const rows = simple.length ? `<dl class="detail-rows">${simple.map(([key, value]) => `<dt>${escapeHtml(humanizeKey(key))}</dt><dd>${valueHtml(value, depth)}</dd>`).join("")}</dl>` : "";
  const sections = complex.map(([key, value]) => `<section class="detail-section depth-${Math.min(depth, 3)}">
      <h4>${escapeHtml(humanizeKey(key))}${Array.isArray(value) ? ` <span class="detail-count">${value.length}</span>` : ""}</h4>
      ${valueHtml(value, depth)}</section>`).join("");
  return rows + sections;
}

function fullDetailsHtml(job) {
  const mode = fullModes[job.id];
  const link = mode && page.target ? `/?${new URLSearchParams({ mode, q: page.target.value })}` : "";
  return `<div class="detail-toolbar">
      <button class="detail-action" type="button" data-action="copy">Copy JSON</button>
      ${link ? `<a class="detail-action" href="${escapeHtml(link)}" target="_blank" rel="noopener">Open in full interface ↗</a>` : ""}
    </div>
    <div class="detail-body">${treeHtml(job.data) || '<p class="card-summary">The tool returned no further details.</p>'}</div>
    <details class="detail-raw"><summary>Raw JSON</summary><pre class="detail-pre">${escapeHtml(JSON.stringify(job.data, null, 2))}</pre></details>`;
}

function toggleDetails(job, card, button) {
  const expand = !card.classList.contains("expanded");
  const body = card.querySelector(".card-details-inner");
  if (expand && !body.dataset.ready) {
    body.innerHTML = fullDetailsHtml(job);
    body.dataset.ready = "true";
    body.querySelector('[data-action="copy"]').addEventListener("click", async (event) => {
      const copyButton = event.currentTarget;
      try {
        await navigator.clipboard.writeText(JSON.stringify(job.data, null, 2));
        copyButton.textContent = "Copied ✓";
      } catch {
        copyButton.textContent = "Copy failed";
      }
      window.setTimeout(() => { copyButton.textContent = "Copy JSON"; }, 1600);
    });
  }
  const apply = () => {
    card.classList.toggle("expanded", expand);
    button.setAttribute("aria-expanded", String(expand));
    button.querySelector(".card-expand-label").textContent = expand ? "Hide details" : "Full details";
  };
  // Let the card grow to full width smoothly where the browser supports view transitions.
  if (motionAllowed() && document.startViewTransition) {
    card.style.viewTransitionName = "expanding-card";
    const transition = document.startViewTransition(apply);
    transition.finished.finally(() => { card.style.viewTransitionName = ""; });
  } else {
    apply();
  }
  if (expand) window.setTimeout(() => card.scrollIntoView({ block: "nearest", behavior: motionAllowed() ? "smooth" : "auto" }), 350);
}

// ------------------------------------------------------------------ Drawing

function cardSkeleton(job, index) {
  const card = document.createElement("article");
  card.className = "card loading";
  card.id = `card-${job.id}`;
  card.style.animationDelay = `${index * 70}ms`;
  card.innerHTML = `
    <div class="card-head"><h3 class="card-title">${escapeHtml(job.title)}</h3><span class="pill">Checking…</span></div>
    <div class="skeleton mid"></div><div class="skeleton"></div><div class="skeleton short"></div>`;
  return card;
}

function listHtml(items, className, render) {
  if (!items.length) return "";
  // Hiding a single item behind a "Show 1 more" button saves nothing, so show it instead.
  const limit = items.length <= 7 ? items.length : 6;
  return `<ul class="${className}">${items.map((item, index) => `<li${index >= limit ? " hidden" : ""}>${render(item)}</li>`).join("")}</ul>${items.length > limit
    ? `<button class="card-more" type="button">Show ${items.length - limit} more</button>`
    : ""}`;
}

const markSymbol = { good: "✓", warn: "!", bad: "✕", info: "i" };

function drawCard(job) {
  const card = byId(`card-${job.id}`);
  if (!card) return;
  card.className = `card ${job.error ? "info" : job.view.status}`;
  if (job.error) {
    card.innerHTML = `<div class="card-head"><h3 class="card-title">${escapeHtml(job.title)}</h3><span class="pill info">Not available</span></div>
      <p class="card-error">${escapeHtml(job.error)}</p>`;
    return;
  }
  const view = job.view;
  const badge = view.grade
    ? `<span class="big-grade ${view.status}">${escapeHtml(view.grade)}</span>`
    : `<span class="pill ${view.status}">${statusWords[view.status]}</span>`;
  card.innerHTML = `
    <div class="card-head"><h3 class="card-title">${escapeHtml(job.title)}</h3>${badge}</div>
    ${view.summary ? `<p class="card-summary">${escapeHtml(view.summary)}</p>` : ""}
    ${view.facts?.length ? `<dl class="facts">${view.facts.map(([label, value, mono]) => `<dt>${escapeHtml(label)}</dt><dd${mono ? ' class="mono"' : ""}>${escapeHtml(value)}</dd>`).join("")}</dl>` : ""}
    ${listHtml(view.checks || [], "checks", (check) => `<span class="mark ${check.state}">${markSymbol[check.state]}</span><span><span class="check-label${check.mono ? " mono" : ""}">${escapeHtml(check.label)}</span>${check.text ? ` <span class="check-text">${escapeHtml(check.text)}</span>` : ""}${check.state === "warn" || check.state === "bad" ? fixHtml(`${check.label}: ${check.text || ""}`) : ""}</span>`)}
    ${view.checks?.length ? "" : listHtml(view.issues.filter((issue) => severityRank[issue.severity] >= 2), "issues", (issue) => `<span class="mark ${issue.severity === "high" ? "bad" : "warn"}">!</span><span>${escapeHtml(issue.message)}${fixHtml(issue.message)}</span>`)}`;
  card.querySelectorAll("li").forEach((item, index) => {
    item.style.animationDelay = `${Math.min(index, 8) * 40}ms`;
  });
  card.querySelectorAll(".card-more").forEach((button) => button.addEventListener("click", () => {
    button.previousElementSibling.querySelectorAll("li[hidden]").forEach((item) => { item.hidden = false; });
    button.remove();
  }));
  card.insertAdjacentHTML("beforeend", `
    <button class="card-expand" type="button" aria-expanded="false" aria-controls="details-${job.id}">
      <span class="card-expand-label">Full details</span><span class="card-expand-icon" aria-hidden="true"></span>
    </button>
    <div class="card-details" id="details-${job.id}"><div class="card-details-inner"></div></div>`);
  const expandButton = card.querySelector(".card-expand");
  expandButton.addEventListener("click", () => toggleDetails(job, card, expandButton));
}

function buildLayout(target) {
  const used = new Set(page.jobs.map((job) => job.category));
  const visible = categories.filter((category) => category.id === "overview" || used.has(category.id));
  const tabs = byId("tabs");
  tabs.querySelectorAll(".tab").forEach((tab) => tab.remove());
  const panels = byId("panels");
  panels.replaceChildren();
  for (const category of visible) {
    const tab = document.createElement("button");
    tab.type = "button";
    tab.className = "tab";
    tab.id = `tab-${category.id}`;
    tab.dataset.category = category.id;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-controls", `panel-${category.id}`);
    tab.innerHTML = '<span class="tab-name"></span><span class="tab-badge busy" aria-hidden="true"></span>';
    tab.querySelector(".tab-name").textContent = page.content[category.label] || category.id;
    tab.addEventListener("click", () => selectTab(category.id));
    tabs.append(tab);

    const panel = document.createElement("section");
    panel.className = "panel";
    panel.id = `panel-${category.id}`;
    panel.setAttribute("role", "tabpanel");
    panel.setAttribute("aria-labelledby", tab.id);
    panel.hidden = true;
    if (category.id !== "overview") {
      const cards = document.createElement("div");
      cards.className = "cards";
      page.jobs.filter((job) => job.category === category.id).forEach((job, index) => cards.append(cardSkeleton(job, index)));
      panel.append(cards);
    }
    panels.append(panel);
  }
  tabs.addEventListener("keydown", tabKeys);
  byId("summary").innerHTML = `
    <div class="ring" id="ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="42"/><circle class="ring-value" id="ring-value" cx="50" cy="50" r="42"/></svg>
      <div class="ring-label"><span><span id="ring-number">0</span><small>Score</small></span></div></div>
    <div><p class="summary-target" id="summary-target"></p><p class="summary-text" id="summary-text"></p>
      <div class="summary-counts" id="summary-counts"></div><div class="progress" id="progress"><div class="progress-bar" id="progress-bar"></div></div>
      <div class="summary-actions" id="summary-actions" hidden>
        <button class="detail-action" type="button" id="share-button">Share link</button>
        <button class="detail-action" type="button" id="pdf-button">Save as PDF</button>
      </div>
      <div class="share-box" id="share-box" hidden></div></div>`;
  byId("share-button").addEventListener("click", shareScan);
  byId("pdf-button").addEventListener("click", () => window.print());
  byId("summary-target").textContent = target.value;
  const circle = byId("ring-value");
  const length = 2 * Math.PI * 42;
  circle.style.strokeDasharray = String(length);
  circle.style.strokeDashoffset = String(length);
  page.active = "";
  selectTab("overview");
}

function selectTab(id) {
  const order = [...document.querySelectorAll(".tab")].map((tab) => tab.dataset.category);
  const previous = order.indexOf(page.active);
  page.active = id;
  document.querySelectorAll(".tab").forEach((tab) => {
    const selected = tab.dataset.category === id;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    const show = panel.id === `panel-${id}`;
    if (show && panel.hidden) {
      panel.classList.toggle("from-left", previous > order.indexOf(id));
      panel.hidden = false;
    } else if (!show) {
      panel.hidden = true;
    }
  });
  positionIndicator();
  byId(`tab-${id}`)?.scrollIntoView({ block: "nearest", inline: "nearest", behavior: motionAllowed() ? "smooth" : "auto" });
}

function tabKeys(event) {
  const tabs = [...document.querySelectorAll(".tab")];
  const index = tabs.findIndex((tab) => tab.dataset.category === page.active);
  let next = null;
  if (event.key === "ArrowRight") next = tabs[(index + 1) % tabs.length];
  if (event.key === "ArrowLeft") next = tabs[(index - 1 + tabs.length) % tabs.length];
  if (event.key === "Home") next = tabs[0];
  if (event.key === "End") next = tabs[tabs.length - 1];
  if (!next) return;
  event.preventDefault();
  selectTab(next.dataset.category);
  next.focus();
}

function positionIndicator() {
  const tab = byId(`tab-${page.active}`);
  const indicator = byId("tab-indicator");
  if (!tab || !indicator) return;
  indicator.style.width = `${tab.offsetWidth}px`;
  indicator.style.transform = `translateX(${tab.offsetLeft}px)`;
}

function animateNumber(element, to) {
  const from = Number(element.textContent) || 0;
  if (!motionAllowed() || from === to) {
    element.textContent = String(to);
    return;
  }
  const started = performance.now();
  const step = (now) => {
    const progress = Math.min(1, (now - started) / 900);
    element.textContent = String(Math.round(from + (to - from) * (1 - (1 - progress) ** 3)));
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// A card's status always follows from its findings: "Problem" means at least one serious
// finding and "Attention" at least one warning. The tab badges, the summary and the cards
// then all count the same findings.
function alignStatus(job) {
  const view = job.view;
  view.issues = view.issues || [];
  const has = (severity) => view.issues.some((issue) => issue.severity === severity);
  const promote = (from, to) => {
    const issue = view.issues.find((item) => from.includes(item.severity));
    if (issue) issue.severity = to;
    else view.issues.unshift({ severity: to, message: view.summary || `${job.title} needs attention.` });
  };
  if (view.status === "bad" && !has("high")) promote(["medium", "low"], "high");
  if (view.status === "warn" && !has("high") && !has("medium")) promote(["low"], "medium");
  view.status = has("high") ? "bad" : has("medium") ? "warn" : view.status === "info" ? "info" : "good";
}

function categoryState(id) {
  const jobs = page.jobs.filter((job) => id === "overview" || job.category === id);
  const busy = jobs.some((job) => !job.done);
  const issues = jobs.flatMap((job) => (job.view?.issues || []).filter((issue) => severityRank[issue.severity] >= 2));
  const status = jobs.some((job) => job.view?.status === "bad") ? "bad" : jobs.some((job) => job.view?.status === "warn") ? "warn" : "good";
  return { jobs, busy, issues, status };
}

function updateSummary() {
  const finished = page.jobs.filter((job) => job.done);
  const scored = finished.filter((job) => job.view && job.view.status !== "info");
  const points = { good: 100, warn: 60, bad: 15 };
  const score = scored.length ? Math.round(scored.reduce((sum, job) => sum + points[job.view.status], 0) / scored.length) : 0;
  const ring = byId("ring");
  ring.className = `ring ${!scored.length ? "" : score >= 80 ? "good" : score >= 50 ? "warn" : "bad"}`;
  const length = 2 * Math.PI * 42;
  byId("ring-value").style.strokeDashoffset = String(length - (length * score) / 100);
  animateNumber(byId("ring-number"), score);

  const all = categoryState("overview");
  const done = finished.length === page.jobs.length;
  byId("summary-text").textContent = done
    ? `${plural(page.jobs.length, "check")} finished${all.issues.length ? ` · ${plural(all.issues.length, "point")} to look at` : " · no problems found"}.`
    : `Running ${plural(page.jobs.length, "check")}… ${finished.length} done.`;
  const passed = scored.filter((job) => job.view.status === "good").length;
  const counts = { warn: all.issues.filter((issue) => issue.severity === "medium").length, bad: all.issues.filter((issue) => issue.severity === "high").length };
  byId("summary-counts").innerHTML = [
    passed && `<span class="pill good">${plural(passed, "check")} passed</span>`,
    counts.warn && `<span class="pill warn">${counts.warn} attention</span>`,
    counts.bad && `<span class="pill bad">${counts.bad} ${counts.bad === 1 ? "problem" : "problems"}</span>`,
  ].filter(Boolean).join("");
  byId("progress-bar").style.width = `${page.jobs.length ? (finished.length / page.jobs.length) * 100 : 100}%`;
  byId("progress").classList.toggle("done", done);
  byId("summary-actions").hidden = !done || page.preview;

  document.querySelectorAll(".tab").forEach((tab) => {
    const state = categoryState(tab.dataset.category);
    const badge = tab.querySelector(".tab-badge");
    const warnings = state.issues.length;
    const tone = warnings ? (state.issues.some((issue) => issue.severity === "high") ? "bad" : "warn") : "good";
    // Each issue is counted once, on its own category's tab; the overview only shows a status dot.
    const overview = tab.dataset.category === "overview";
    badge.className = `tab-badge ${state.busy ? "busy" : overview ? `dot ${tone}` : tone}`;
    badge.textContent = state.busy || overview ? "" : warnings ? String(warnings) : "✓";
  });
  positionIndicator();
  drawOverview();
}

function drawOverview() {
  const panel = byId("panel-overview");
  if (!panel) return;
  const tiles = categories.filter((category) => category.id !== "overview" && byId(`tab-${category.id}`)).map((category, index) => {
    const state = categoryState(category.id);
    const value = state.busy ? "Checking…" : state.issues.length ? plural(state.issues.length, "point") + " to check" : "All good";
    return `<button class="tile" type="button" data-category="${category.id}" data-index="${index}">
      <span class="tile-name">${escapeHtml(page.content[category.label] || category.id)}</span>
      <span class="tile-value">${state.busy ? '<span class="pill">…</span>' : `<span class="pill ${state.issues.length ? state.status : "good"}">${escapeHtml(value)}</span>`}</span>
      <span class="card-summary">${escapeHtml(state.jobs.map((job) => job.title).join(", "))}</span>
    </button>`;
  }).join("");
  const issues = page.jobs.flatMap((job) => (job.view?.issues || []).filter((issue) => severityRank[issue.severity] >= 2).map((issue) => ({ ...issue, job })))
    .sort((left, right) => severityRank[right.severity] - severityRank[left.severity]);
  const firstDraw = !panel.firstElementChild;
  panel.innerHTML = `<div class="overview-grid">${tiles}</div>
    ${issues.length ? `<div class="card overview-issues ${issues.some((issue) => issue.severity === "high") ? "bad" : "warn"}"><h2>Most important findings</h2>
      ${listHtml(issues, "issues", (issue) => `<span class="mark ${issue.severity === "high" ? "bad" : "warn"}">!</span><span><span class="check-label">${escapeHtml(issue.job.title)}:</span> <span class="check-text">${escapeHtml(issue.message)}</span>${fixHtml(issue.message)}</span>`)}</div>`
    : page.jobs.every((job) => job.done) ? '<div class="card good overview-issues"><h2>No problems found</h2><p class="card-summary">Every check passed without important findings.</p></div>' : ""}`;
  // Only the first drawing animates; later updates replace the content in place.
  panel.classList.toggle("settled", !firstDraw);
  panel.querySelectorAll(".tile").forEach((tile) => {
    tile.style.animationDelay = `${Number(tile.dataset.index) * 70}ms`;
    tile.addEventListener("click", () => selectTab(tile.dataset.category));
  });
  panel.querySelectorAll(".card-more").forEach((button) => button.addEventListener("click", () => {
    button.previousElementSibling.querySelectorAll("li[hidden]").forEach((item) => { item.hidden = false; });
    button.remove();
  }));
}

// ------------------------------------------------------------------ Scanning

function showNotice(message) {
  const notice = byId("notice");
  notice.textContent = message || "";
  notice.hidden = !message;
}

async function startScan() {
  const target = classify(byId("query").value);
  if (!target) {
    showNotice("Enter a domain name, an IP address or a MAC address.");
    byId("query").focus();
    return;
  }
  const allowed = allowedFeatures();
  const jobs = planJobs(target, allowed);
  if (!jobs.length) {
    showNotice(target.kind === "domain" || !allowed.size ? page.content.empty : "This type of lookup needs an account. Log in to use it.");
    return;
  }
  showNotice("");
  const run = ++page.run;
  document.body.classList.add("is-scanning");
  byId("scan-button").disabled = true;
  try {
    const response = await fetch("/api/landing/start", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: "{}" });
    const started = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(started.error || "The scan could not be started.");
    if (run !== page.run) return;
    page.token = started.token;
  } catch (error) {
    if (run === page.run) {
      showNotice(error.message);
      document.body.classList.remove("is-scanning");
      byId("scan-button").disabled = false;
    }
    return;
  }

  page.jobs = jobs;
  page.target = target;
  page.shared = null;
  page.compare = null;
  byId("compare").hidden = true;
  page.scannedAt = new Date();
  document.body.classList.add("has-results");
  byId("results").hidden = false;
  buildLayout(target);
  updateSummary();
  if (!page.preview) {
    try {
      window.history.replaceState(null, "", `${window.location.pathname.startsWith("/s/") ? "/" : ""}#${encodeURIComponent(target.value)}`);
    } catch {
      // Not important if the address cannot be updated.
    }
  }
  if (window.matchMedia("(max-width: 640px)").matches) byId("results").scrollIntoView({ behavior: motionAllowed() ? "smooth" : "auto" });

  await Promise.all(jobs.map(async (job) => {
    try {
      const data = await job.load();
      if (run !== page.run) return;
      job.data = data;
      job.view = job.render(data);
      alignStatus(job);
    } catch (error) {
      if (run !== page.run) return;
      job.error = error.message;
    }
    job.done = true;
    drawCard(job);
    updateSummary();
  }));
  if (run !== page.run) return;
  document.body.classList.remove("is-scanning");
  byId("scan-button").disabled = false;
}

// ------------------------------------------------------------------ Compare two domains

const statusRank = { good: 3, info: 2, warn: 1, bad: 0 };

function scoreOf(jobs) {
  const scored = jobs.filter((job) => job.done && job.view && job.view.status !== "info");
  const points = { good: 100, warn: 60, bad: 15 };
  const score = scored.length ? Math.round(scored.reduce((sum, job) => sum + points[job.view.status], 0) / scored.length) : 0;
  return { score, tone: !scored.length ? "" : score >= 80 ? "good" : score >= 50 ? "warn" : "bad" };
}

function findingCount(jobs) {
  return jobs.flatMap((job) => (job.view?.issues || []).filter((issue) => severityRank[issue.severity] >= 2)).length;
}

function compareCell(job) {
  if (!job) return '<span class="card-summary">—</span>';
  if (!job.done) return '<span class="skeleton short"></span>';
  if (job.error) return '<span class="pill info">Not available</span>';
  const count = (job.view.issues || []).filter((issue) => severityRank[issue.severity] >= 2).length;
  return `<span class="pill ${job.view.status}">${statusWords[job.view.status]}</span>${job.view.grade ? ` <span class="compare-grade ${job.view.status}">${escapeHtml(job.view.grade)}</span>` : ""}${count ? ` <span class="compare-count">${plural(count, "finding")}</span>` : ""}`;
}

function buildCompare() {
  const [left, right] = page.compare;
  const section = byId("compare");
  const ring = (side) => `<div class="ring" id="compare-ring-${side}"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="42"/><circle class="ring-value" cx="50" cy="50" r="42"/></svg>
    <div class="ring-label"><span><span class="compare-number">0</span><small>Score</small></span></div></div>`;
  const used = new Set(left.jobs.concat(right.jobs).map((job) => job.category));
  const rows = categories.filter((category) => category.id !== "overview" && used.has(category.id)).map((category) => {
    const ids = [...new Set(left.jobs.concat(right.jobs).filter((job) => job.category === category.id).map((job) => job.id))];
    return `<tr class="compare-category"><th scope="rowgroup" colspan="3">${escapeHtml(page.content[category.label] || category.id)}</th></tr>
      ${ids.map((id) => `<tr data-job="${id}"><th scope="row">${escapeHtml((left.jobs.concat(right.jobs)).find((job) => job.id === id).title)}</th><td data-side="0"></td><td data-side="1"></td></tr>`).join("")}`;
  }).join("");
  section.innerHTML = `
    <div class="compare-head">
      ${[left, right].map((side, index) => `<div class="compare-side" id="compare-side-${index}">${ring(index)}
        <p class="summary-target">${escapeHtml(side.target.value)}</p><p class="summary-text" id="compare-text-${index}"></p>
        <button class="detail-action" type="button" data-open="${index}">Open full result</button></div>`).join('<div class="compare-vs-big" aria-hidden="true">vs</div>')}
    </div>
    <div class="compare-table-wrap"><table class="compare-table">
      <thead><tr><th scope="col">Check</th><th scope="col">${escapeHtml(left.target.value)}</th><th scope="col">${escapeHtml(right.target.value)}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  section.querySelectorAll("[data-open]").forEach((button) => button.addEventListener("click", () => openCompareSide(Number(button.dataset.open))));
  section.querySelectorAll(".ring-value").forEach((circle) => {
    const length = 2 * Math.PI * 42;
    circle.style.strokeDasharray = String(length);
    circle.style.strokeDashoffset = String(length);
  });
}

function updateCompare() {
  if (!page.compare) return;
  const sides = page.compare;
  const length = 2 * Math.PI * 42;
  const scores = sides.map((side) => scoreOf(side.jobs));
  const done = sides.every((side) => side.jobs.every((job) => job.done));
  sides.forEach((side, index) => {
    const ring = byId(`compare-ring-${index}`);
    ring.className = `ring ${scores[index].tone}`;
    ring.querySelector(".ring-value").style.strokeDashoffset = String(length - (length * scores[index].score) / 100);
    animateNumber(ring.querySelector(".compare-number"), scores[index].score);
    const finished = side.jobs.filter((job) => job.done).length;
    byId(`compare-text-${index}`).textContent = finished < side.jobs.length
      ? `Running… ${finished} of ${side.jobs.length} done.`
      : `${plural(findingCount(side.jobs), "point")} to look at.`;
    byId(`compare-side-${index}`).classList.toggle("winner", done && scores[index].score > scores[1 - index].score);
  });
  byId("compare").querySelectorAll("tr[data-job]").forEach((row) => {
    const jobs = sides.map((side) => side.jobs.find((job) => job.id === row.dataset.job));
    row.querySelectorAll("td").forEach((cell, index) => {
      cell.innerHTML = compareCell(jobs[index]);
      cell.classList.remove("better");
    });
    if (jobs.every((job) => job?.done && job.view)) {
      const rank = jobs.map((job) => statusRank[job.view.status] * 100 - findingCount([job]));
      if (rank[0] !== rank[1]) row.querySelectorAll("td")[rank[0] > rank[1] ? 0 : 1].classList.add("better");
    }
  });
}

function openCompareSide(index) {
  const side = page.compare[index];
  page.jobs = side.jobs;
  page.target = side.target;
  page.shared = null;
  page.scannedAt = side.scannedAt;
  byId("compare").hidden = true;
  byId("results").hidden = false;
  buildLayout(side.target);
  page.jobs.forEach(drawCard);
  updateSummary();
  const notice = byId("notice");
  notice.hidden = false;
  notice.classList.add("shared-notice");
  notice.innerHTML = `Full result for ${escapeHtml(side.target.value)}. <button class="example" type="button" id="back-to-compare">Back to the comparison</button>`;
  byId("back-to-compare").addEventListener("click", () => {
    notice.hidden = true;
    notice.classList.remove("shared-notice");
    byId("results").hidden = true;
    byId("compare").hidden = false;
  });
  byId("results").scrollIntoView({ behavior: motionAllowed() ? "smooth" : "auto", block: "start" });
}

async function startCompare() {
  const targets = [classify(byId("query").value), classify(byId("query2").value)];
  if (!targets[0] || !targets[1]) {
    showNotice("Enter two domain names (or two IP addresses) to compare.");
    return;
  }
  if (targets[0].kind !== targets[1].kind || targets[0].kind === "mac") {
    showNotice("Compare two domain names or two IP addresses.");
    return;
  }
  if (targets[0].value === targets[1].value) {
    showNotice("Enter two different names to compare.");
    return;
  }
  const allowed = allowedFeatures();
  if (!planJobs(targets[0], allowed).length) {
    showNotice(page.content.empty);
    return;
  }
  showNotice("");
  const run = ++page.run;
  document.body.classList.add("is-scanning");
  byId("scan-button").disabled = true;
  let tokens;
  try {
    tokens = await Promise.all(targets.map(async () => {
      const response = await fetch("/api/landing/start", { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: "{}" });
      const started = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(started.error || "The comparison could not be started.");
      return started.token;
    }));
  } catch (error) {
    if (run === page.run) {
      showNotice(error.message);
      document.body.classList.remove("is-scanning");
      byId("scan-button").disabled = false;
    }
    return;
  }
  if (run !== page.run) return;
  page.compare = targets.map((target, index) => ({ target, jobs: planJobs(target, allowed, tokens[index]), scannedAt: new Date() }));
  page.jobs = [];
  document.body.classList.add("has-results");
  byId("results").hidden = true;
  byId("compare").hidden = false;
  buildCompare();
  updateCompare();
  if (!page.preview) {
    try {
      window.history.replaceState(null, "", `/#compare:${encodeURIComponent(targets[0].value)},${encodeURIComponent(targets[1].value)}`);
    } catch {
      // Not important if the address cannot be updated.
    }
  }
  let pending = false;
  const redraw = () => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      if (run === page.run) updateCompare();
    });
  };
  await Promise.all(page.compare.flatMap((side) => side.jobs).map(async (job) => {
    try {
      const data = await job.load();
      if (run !== page.run) return;
      job.data = data;
      job.view = job.render(data);
      alignStatus(job);
    } catch (error) {
      if (run !== page.run) return;
      job.error = error.message;
    }
    job.done = true;
    redraw();
  }));
  if (run !== page.run) return;
  updateCompare();
  document.body.classList.remove("is-scanning");
  byId("scan-button").disabled = false;
}

function setCompareMode(on) {
  const field = byId("compare-field");
  field.hidden = !on;
  byId("compare-toggle").setAttribute("aria-expanded", String(on));
  byId("compare-toggle").textContent = on ? "Scan one domain" : "Compare with another domain";
  if (on) byId("query2").focus();
}

// ------------------------------------------------------------------ Share and PDF

const allLandingFeatures = new Set(["forward", "whois", "propagation", "dns-health", "email", "mail-server", "subdomains", "ipv6", "privacy", "web", "sslscan", "reputation", "lookalike", "ping", "asn", "reverse", "mac"]);

async function shareScan() {
  const box = byId("share-box");
  let link = page.shared ? window.location.href.split("#")[0] : "";
  let expires = page.shared?.expiresAt;
  if (!link) {
    byId("share-button").disabled = true;
    try {
      const response = await fetch("/api/landing/share", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          target: page.target,
          jobs: page.jobs.map((job) => (job.error ? { id: job.id, error: job.error } : { id: job.id, data: job.data })),
        }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || "The result could not be shared.");
      link = `${window.location.origin}${result.url}`;
      expires = result.expiresAt;
      page.shared = { url: result.url, expiresAt: result.expiresAt, own: true };
    } catch (error) {
      box.hidden = false;
      box.innerHTML = `<p class="card-error">${escapeHtml(error.message)}</p>`;
      return;
    } finally {
      byId("share-button").disabled = false;
    }
  }
  box.hidden = false;
  box.innerHTML = `<div class="share-row"><input class="share-link" type="text" readonly value="${escapeHtml(link)}" aria-label="Share link"><button class="fix-copy share-copy" type="button" data-copy="${escapeHtml(link)}">Copy</button></div>
    <p class="card-summary">Anyone with this link can see this result${expires ? ` until ${escapeHtml(formatDate(expires))}` : ""}.</p>`;
  box.querySelector(".share-link").select();
}

async function openSharedScan(id) {
  let shared;
  try {
    const response = await fetch(`/api/landing/shares/${encodeURIComponent(id)}`, { credentials: "same-origin" });
    shared = await response.json();
    if (!response.ok) throw new Error(shared.error || "This shared result could not be loaded.");
  } catch (error) {
    showNotice(error.message);
    return;
  }
  const stored = new Map(shared.jobs.map((job) => [job.id, job]));
  page.target = shared.target;
  page.jobs = planJobs(shared.target, allLandingFeatures).filter((job) => stored.has(job.id));
  page.shared = { url: `/s/${shared.id}`, expiresAt: shared.expiresAt };
  page.scannedAt = new Date(shared.createdAt);
  for (const job of page.jobs) {
    const entry = stored.get(job.id);
    job.done = true;
    if (entry.error !== undefined) {
      job.error = entry.error;
      continue;
    }
    job.data = entry.data;
    try {
      job.view = job.render(entry.data);
      alignStatus(job);
    } catch {
      job.error = "This part of the shared result could not be shown.";
    }
  }
  byId("query").value = shared.target.value;
  document.body.classList.add("has-results");
  byId("results").hidden = false;
  buildLayout(shared.target);
  page.jobs.forEach(drawCard);
  updateSummary();
  const notice = byId("notice");
  notice.hidden = false;
  notice.classList.add("shared-notice");
  notice.innerHTML = `Shared result, scanned ${escapeHtml(page.scannedAt.toLocaleString())}. <button class="example" type="button" id="rescan">Run a new scan</button>`;
  byId("rescan").addEventListener("click", () => {
    notice.classList.remove("shared-notice");
    startScan();
  });
}

// Printing (Save as PDF) shows every category, open lists and the "How to fix" advice.
let printState = null;
window.addEventListener("beforeprint", () => {
  if (!page.jobs.length || printState) return;
  printState = {
    // The theme's colors are set inline; printing uses its own light colors.
    themeStyle: document.documentElement.getAttribute("style") || "",
    panels: [...document.querySelectorAll(".panel")].map((panel) => [panel, panel.hidden]),
    items: [...document.querySelectorAll("li[hidden]")],
    fixes: [...document.querySelectorAll(".fix:not([open])")],
  };
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.hidden = false;
    panel.dataset.title = byId(panel.getAttribute("aria-labelledby"))?.querySelector(".tab-name")?.textContent || "";
  });
  printState.items.forEach((item) => { item.hidden = false; });
  printState.fixes.forEach((fix) => { fix.open = true; });
  document.documentElement.removeAttribute("style");
  let meta = byId("print-meta");
  if (!meta) {
    meta = document.createElement("p");
    meta.id = "print-meta";
    meta.className = "print-meta";
    byId("results").prepend(meta);
  }
  meta.textContent = `${page.config?.siteTitle || "BNGlookup"} scan report · ${(page.scannedAt || new Date()).toLocaleString()}${page.shared ? ` · ${window.location.origin}${page.shared.url}` : ""}`;
});
window.addEventListener("afterprint", () => {
  if (!printState) return;
  printState.panels.forEach(([panel, hidden]) => { panel.hidden = hidden; });
  printState.items.forEach((item) => { item.hidden = true; });
  printState.fixes.forEach((fix) => { fix.open = false; });
  document.documentElement.setAttribute("style", printState.themeStyle);
  printState = null;
});

// ------------------------------------------------------------------ Start

// Logged-in users switch between the simple and the full interface; the choice is kept
// in a cookie for this browser and "/" serves the chosen one.
function setupInterfaceSwitch(button, target) {
  button.hidden = false;
  button.addEventListener("click", () => {
    button.setAttribute("aria-checked", String(target === "full"));
    const secure = window.location.protocol === "https:" ? "; secure" : "";
    document.cookie = `bng_ui=${target}; path=/; max-age=31536000; samesite=lax${secure}`;
    window.setTimeout(() => window.location.assign("/"), 280);
  });
}

async function init() {
  byId("scan-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (!byId("compare-field").hidden && byId("query2").value.trim()) startCompare();
    else startScan();
  });
  byId("query2").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      startCompare();
    }
  });
  byId("compare-toggle").addEventListener("click", () => setCompareMode(byId("compare-field").hidden));
  window.addEventListener("resize", positionIndicator);
  try {
    const [configResponse, authResponse] = await Promise.all([
      fetch("/api/landing/config", { credentials: "same-origin" }),
      fetch("/api/auth/status", { credentials: "same-origin" }),
    ]);
    page.config = await configResponse.json();
    page.auth = authResponse.ok ? await authResponse.json() : null;
  } catch {
    page.config = { theme: {}, content: { headline: "DNS lookup", button: "Scan" }, publicFeatures: [] };
  }
  if (page.auth?.user) {
    byId("login-chip").hidden = true;
    if (!page.preview) setupInterfaceSwitch(byId("ui-switch"), "full");
  }
  applyConfig(page.config);
  document.body.classList.remove("is-loading");
  if (!allowedFeatures().size) {
    showNotice(page.config.content?.empty || "");
    byId("query").disabled = true;
    byId("scan-button").disabled = true;
    byId("examples").hidden = true;
  }
  const sharedId = window.location.pathname.match(/^\/s\/([A-Za-z0-9_-]{22})$/)?.[1];
  if (sharedId) {
    await openSharedScan(sharedId);
  } else if (allowedFeatures().size) {
    byId("compare-toggle").hidden = page.preview;
    const fromHash = decodeURIComponent(window.location.hash.slice(1));
    const compareHash = fromHash.match(/^compare:([^,]+),(.+)$/);
    if (compareHash && !page.preview) {
      byId("query").value = compareHash[1];
      byId("query2").value = compareHash[2];
      setCompareMode(true);
      startCompare();
    } else if (fromHash && !page.preview) {
      byId("query").value = fromHash;
      startScan();
    } else if (!page.preview && window.matchMedia("(min-width: 641px)").matches) {
      byId("query").focus({ preventScroll: true });
    }
  }

  // The admin settings page sends unsaved settings to the preview frame.
  if (page.preview) {
    window.addEventListener("message", (event) => {
      if (event.origin !== window.location.origin || event.source !== window.parent || event.data?.type !== "landing-preview") return;
      const draft = event.data.config || {};
      page.config = { ...page.config, theme: draft.theme || page.config.theme, content: draft.content || page.config.content, background: draft.background === undefined ? page.config.background : draft.background };
      applyConfig(page.config);
    });
    window.parent.postMessage({ type: "landing-preview-ready" }, window.location.origin);
  }
}

init();
