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

async function api(url) {
  const response = await fetch(url, { credentials: "same-origin", headers: { "x-landing-scan": page.token } });
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

async function pingTarget(name) {
  const icmp = await api(query("/api/ping", { name }));
  if (icmp.up || !/not available/i.test(icmp.error || "")) return icmp;
  return api(query("/api/ping", { name, method: "https" }));
}

function planJobs(target, allowed) {
  const name = target.value;
  const jobs = [];
  const add = (feature, job) => {
    if (allowed.has(feature)) jobs.push({ feature, ...job });
  };
  if (target.kind === "domain") {
    add("forward", {
      id: "records", category: "dns", title: "DNS records", render: renderRecords,
      load: async () => Object.fromEntries(await Promise.all(["A", "AAAA", "MX", "NS", "TXT", "CAA"]
        .map(async (type) => [type, await api(query("/api/lookup", { name, type }))]))),
    });
    add("forward", { id: "dnssec", category: "dns", title: "DNSSEC", render: renderDnssec, load: () => api(query("/api/lookup", { name, type: "DNSSEC" })) });
    add("whois", { id: "whois", category: "dns", title: "Registration", render: renderWhois, load: () => api(query("/api/domain-info", { name })) });
    add("propagation", { id: "propagation", category: "dns", title: "Propagation", render: renderPropagation, load: () => api(query("/api/propagation", { name, type: "A" })) });
    add("dns-health", { id: "dns-health", category: "dns", title: "Name server health", render: renderDnsHealth, load: () => api(query("/api/dns-health", { name })) });
    add("email", { id: "email", category: "email", title: "Email security", render: renderEmail, load: () => api(query("/api/email-check", { name })) });
    add("web", { id: "web", category: "web", title: "Website", render: renderWeb, load: () => api(query("/api/web-check", { name })) });
    add("sslscan", { id: "tls", category: "web", title: "TLS certificate", render: renderTls, load: () => api(query("/api/sslscan", { name, port: "443" })) });
    add("reputation", { id: "reputation", category: "security", title: "Reputation", render: renderReputation, load: () => api(query("/api/reputation", { name })) });
    add("lookalike", { id: "lookalike", category: "security", title: "Look-alike domains", render: renderLookalike, load: () => api(query("/api/lookalike", { name })) });
    add("ping", { id: "ping", category: "network", title: "Reachability", render: renderPing, load: () => pingTarget(name) });
    add("asn", { id: "asn", category: "network", title: "Network (ASN)", render: renderAsn, load: () => api(query("/api/asn", { name })) });
  } else if (target.kind === "ip") {
    add("reverse", { id: "reverse", category: "dns", title: "Reverse DNS", render: renderReverse, load: () => api(query("/api/lookup", { name, reverse: "true" })) });
    add("whois", { id: "whois", category: "dns", title: "IP registration", render: renderIpWhois, load: () => api(query("/api/domain-info", { name })) });
    add("reputation", { id: "reputation", category: "security", title: "Reputation", render: renderReputation, load: () => api(query("/api/reputation", { name })) });
    add("ping", { id: "ping", category: "network", title: "Reachability", render: renderPing, load: () => pingTarget(name) });
    add("asn", { id: "asn", category: "network", title: "Network (ASN)", render: renderAsn, load: () => api(query("/api/asn", { name })) });
  } else {
    add("mac", { id: "mac", category: "network", title: "MAC address vendor", render: renderMac, load: () => api(query("/api/mac-lookup", { name })) });
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
    ...normalizeIssues(data.spf?.issues), ...normalizeIssues(data.dmarc?.issues), ...normalizeIssues(data.mtaSts?.issues),
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

// ------------------------------------------------------------------ Full details
// Every card can expand to show everything the tool returned, laid out as readable
// tables, plus the raw JSON and a link to the same tool in the full interface.

const fullModes = {
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
  const limit = 6;
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
    ${listHtml(view.checks || [], "checks", (check) => `<span class="mark ${check.state}">${markSymbol[check.state]}</span><span><span class="check-label${check.mono ? " mono" : ""}">${escapeHtml(check.label)}</span>${check.text ? ` <span class="check-text">${escapeHtml(check.text)}</span>` : ""}</span>`)}
    ${view.checks?.length ? "" : listHtml(view.issues.filter((issue) => severityRank[issue.severity] >= 2), "issues", (issue) => `<span class="mark ${issue.severity === "high" ? "bad" : "warn"}">!</span><span>${escapeHtml(issue.message)}</span>`)}`;
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
      <div class="summary-counts" id="summary-counts"></div><div class="progress" id="progress"><div class="progress-bar" id="progress-bar"></div></div></div>`;
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
  const high = all.issues.filter((issue) => issue.severity === "high").length;
  const done = finished.length === page.jobs.length;
  byId("summary-text").textContent = done
    ? `${plural(page.jobs.length, "check")} finished${all.issues.length ? ` · ${plural(all.issues.length, "point")} to look at` : " · no problems found"}.`
    : `Running ${plural(page.jobs.length, "check")}… ${finished.length} done.`;
  const counts = { good: 0, warn: 0, bad: 0 };
  for (const job of scored) counts[job.view.status] += 1;
  byId("summary-counts").innerHTML = [
    counts.good && `<span class="pill good">${counts.good} good</span>`,
    counts.warn && `<span class="pill warn">${counts.warn} attention</span>`,
    counts.bad && `<span class="pill bad">${counts.bad} ${counts.bad === 1 ? "problem" : "problems"}</span>`,
    high && `<span class="pill bad">${plural(high, "serious issue")}</span>`,
  ].filter(Boolean).join("");
  byId("progress-bar").style.width = `${page.jobs.length ? (finished.length / page.jobs.length) * 100 : 100}%`;
  byId("progress").classList.toggle("done", done);

  document.querySelectorAll(".tab").forEach((tab) => {
    const state = categoryState(tab.dataset.category);
    const badge = tab.querySelector(".tab-badge");
    const warnings = state.issues.length;
    badge.className = `tab-badge ${state.busy ? "busy" : warnings ? (state.issues.some((issue) => issue.severity === "high") ? "bad" : "warn") : "good"}`;
    badge.textContent = state.busy ? "" : warnings ? String(warnings) : "✓";
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
      ${listHtml(issues, "issues", (issue) => `<span class="mark ${issue.severity === "high" ? "bad" : "warn"}">!</span><span><span class="check-label">${escapeHtml(issue.job.title)}:</span> <span class="check-text">${escapeHtml(issue.message)}</span></span>`)}</div>`
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
  document.body.classList.add("has-results");
  byId("results").hidden = false;
  buildLayout(target);
  updateSummary();
  if (!page.preview) {
    try {
      window.history.replaceState(null, "", `#${encodeURIComponent(target.value)}`);
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
      job.view.issues = job.view.issues || [];
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
    startScan();
  });
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
  } else {
    const fromHash = decodeURIComponent(window.location.hash.slice(1));
    if (fromHash && !page.preview) {
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
