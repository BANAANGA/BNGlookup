const http = require("node:http");
const https = require("node:https");
const tls = require("node:tls");
const { execFile, spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { isIP } = require("node:net");
const dgram = require("node:dgram");
const net = require("node:net");
const http2 = require("node:http2");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const { Readable } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const { promisify } = require("node:util");
const { DatabaseSync } = require("node:sqlite");
const { lookup: resolveHost, Resolver: DnsResolver } = require("node:dns/promises");
const { domainToASCII } = require("node:url");
const { createAcmeManager } = require("./acme");
const { sendMail, validAddress } = require("./mail");
const { analyzeEmailHeaders, organizationalDomain } = require("./email-headers");
const webauthn = require("./webauthn");
const oidc = require("./oidc");

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
const httpsPort = Number(process.env.HTTPS_PORT || 8443);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}
function parseTrustedProxyEntries(value, maxEntries = 50, maxLength = 2048) {
  if (typeof value !== "string" || value.length > maxLength) {
    throw new Error(`Trusted proxies must be a list no longer than ${maxLength.toLocaleString()} characters.`);
  }
  const entries = [...new Set(value.split(/[,\r\n]+/).map((entry) => entry.trim()).filter(Boolean))];
  if (entries.length > maxEntries) {
    throw new Error(`Trusted proxies may contain no more than ${maxEntries} IP addresses or CIDRs.`);
  }
  const ranges = new net.BlockList();
  for (const entry of entries) {
    const [address, prefixText, ...extra] = entry.split("/");
    const family = isIP(address);
    if (!family || extra.length > 0 ||
      (prefixText !== undefined &&
        (!/^\d+$/.test(prefixText) || Number(prefixText) > (family === 4 ? 32 : 128)))) {
      throw new Error(`Invalid trusted proxy address or CIDR: ${entry}`);
    }
    if (prefixText === undefined) {
      ranges.addAddress(address, family === 4 ? "ipv4" : "ipv6");
    } else {
      ranges.addSubnet(address, Number(prefixText), family === 4 ? "ipv4" : "ipv6");
    }
  }
  return { entries, ranges };
}
let { entries: trustedProxyEntries, ranges: trustedProxyRanges } =
  parseTrustedProxyEntries(process.env.TRUSTED_PROXIES || "");
let cloudflareProxyEntries = [];
let cloudflareProxyTrustEnabled = false;
let cloudflareProxyUpdatedAt = null;
let cloudflareProxyRefreshPromise = null;
const customDohEndpoint = process.env.DOH_ENDPOINT || "";
const dnsResolvers = {
  google: { label: "Google Public DNS", endpoint: "https://dns.google/dns-query" },
  cloudflare: { label: "Cloudflare", endpoint: "https://cloudflare-dns.com/dns-query" },
  quad9: { label: "Quad9", endpoint: "https://dns.quad9.net/dns-query" },
  dns4eu: { label: "DNS4EU (EU)", endpoint: "https://protective.joindns4.eu/dns-query" },
};
const customResolverOption = customDohEndpoint &&
  !Object.values(dnsResolvers).some(({ endpoint }) => endpoint === customDohEndpoint)
  ? [{ id: "custom", label: "Custom (DOH_ENDPOINT)" }]
  : [];
const publicDir = path.join(__dirname, "public");
const staticFiles = new Set([
  "/index.html",
  "/setup.html",
  "/login.html",
  "/my-account.html",
  "/my-account.js",
  "/change-password.html",
  "/admin.html",
  "/admin-logs.html",
  "/admin-stats.html",
  "/admin-dashboard.html",
  "/about.html",
  "/about.js",
  "/history.html",
  "/history.js",
  "/monitors.html",
  "/monitors.js",
  "/tools.js",
  "/qr.js",
  "/landing.html",
  "/passkeys.js",
  "/landing.js",
  "/landing.css",
  "/styles.css",
  "/app.js",
  "/account.js",
  "/admin.js",
  "/admin-logs.js",
  "/admin-stats.js",
  "/admin-dashboard.js",
  "/branding.js",
  "/favicon.svg",
  "/logo.svg",
  "/brand-logo.svg",
]);
const dataDir = path.resolve(process.env.DATA_DIR || "/data");
fs.mkdirSync(dataDir, { recursive: true });
process.umask(0o077);
// A restore uploaded in Admin -> Backup is staged in restore-pending/ and swapped in here,
// before the database is opened. The replaced files are kept in pre-restore-<time>/.
const restorePendingDir = path.join(dataDir, "restore-pending");
const restorableNames = ["bnglookup.sqlite", "bnglookup.sqlite-wal", "bnglookup.sqlite-shm", "landing-background", "acme"];
const restoreApplied = (function applyPendingRestore() {
  if (!fs.existsSync(path.join(restorePendingDir, "ready"))) {
    fs.rmSync(restorePendingDir, { recursive: true, force: true });
    return false;
  }
  const keep = path.join(dataDir, `pre-restore-${new Date().toISOString().replace(/[:.]/g, "-")}`);
  fs.mkdirSync(keep, { mode: 0o700 });
  for (const name of restorableNames) {
    if (fs.existsSync(path.join(dataDir, name))) fs.renameSync(path.join(dataDir, name), path.join(keep, name));
  }
  for (const name of fs.readdirSync(restorePendingDir)) {
    if (name !== "ready" && restorableNames.includes(name)) fs.renameSync(path.join(restorePendingDir, name), path.join(dataDir, name));
  }
  fs.rmSync(restorePendingDir, { recursive: true, force: true });
  const previous = fs.readdirSync(dataDir).filter((name) => name.startsWith("pre-restore-")).sort();
  for (const old of previous.slice(0, -3)) fs.rmSync(path.join(dataDir, old), { recursive: true, force: true });
  console.log(`Restored a backup; the previous data is kept in ${keep}.`);
  return true;
}());
const database = new DatabaseSync(path.join(dataDir, "bnglookup.sqlite"));
fs.chmodSync(path.join(dataDir, "bnglookup.sqlite"), 0o600);
const scrypt = promisify(crypto.scrypt);
const sessionCookieName = "bnglookup_session";
const sessionDurationMs = 12 * 60 * 60 * 1000;
const featureAccessDefaults = {
  forward: "user",
  reverse: "user",
  whois: "user",
  mac: "user",
  ping: "user",
  "ping-scan": "admin",
  traceroute: "user",
  "multi-traceroute": "admin",
  scan: "admin",
  "custom-port": "admin",
  "bulk-port": "admin",
  nmap: "admin",
  sslscan: "user",
  dig: "user",
  blocklist: "user",
  propagation: "user",
  email: "user",
  asn: "user",
  web: "user",
  "email-headers": "user",
  "dmarc-reports": "user",
  "tlsrpt-reports": "user",
  "record-builder": "user",
  "bulk-domains": "admin",
  monitors: "user",
  "dns-health": "user",
  "mail-server": "user",
  reputation: "user",
  lookalike: "user",
  "ip-calc": "user",
  "api-tokens": "user",
  preview: "user",
  history: "user",
};
const featureNames = {
  forward: "DNS lookup",
  reverse: "Reverse lookup",
  whois: "Whois",
  mac: "MAC lookup",
  ping: "Ping / host check",
  "ping-scan": "Ping scan",
  traceroute: "Traceroute",
  "multi-traceroute": "Multi traceroute",
  scan: "Magic scan",
  "custom-port": "Port scan",
  "bulk-port": "Bulk port scan",
  nmap: "Nmap scan (authorized targets only)",
  sslscan: "SSL/TLS handshake and certificate check",
  dig: "Custom dig command",
  blocklist: "Blocklist (DNSBL) check in auto lookup",
  propagation: "DNS propagation check",
  email: "Email check (MX, SMTP STARTTLS, SPF, DMARC, DKIM)",
  asn: "ASN and announced prefixes",
  web: "Web check (redirects, security headers, HTTP/2 and HTTP/3)",
  "email-headers": "Email header analyzer",
  "dmarc-reports": "DMARC aggregate report viewer",
  "tlsrpt-reports": "TLS-RPT report viewer (SMTP TLS reports)",
  "record-builder": "SPF, DMARC, MTA-STS, TLS-RPT and BIMI record builder",
  "bulk-domains": "Bulk domain check (up to 50 domains)",
  monitors: "Monitoring and email alerts (requires login)",
  "dns-health": "DNS health check (delegation, SOA, zone transfer, open recursion)",
  "mail-server": "Mail server check (open relay, reverse DNS, TLS on port 25)",
  reputation: "Reputation check (protective DNS, blocklists, optional threat feeds)",
  lookalike: "Lookalike domain finder",
  "ip-calc": "IP / CIDR calculator",
  "api-tokens": "API tokens for scripts (requires login)",
  preview: "Website previews (proxied live view, requires login)",
  history: "Lookup history (saved per user)",
};

function parseNmapAllowedCidrs(value) {
  if (typeof value !== "string" || value.length > 12288) {
    throw new Error("Authorized Nmap networks must be a list no longer than 12,288 characters.");
  }
  const entries = [...new Set(value.split(/[,\r\n]+/).map((entry) => entry.trim()).filter(Boolean))];
  if (entries.length > 254) {
    throw new Error("Authorized Nmap networks may contain no more than 254 CIDRs.");
  }
  const ranges = new net.BlockList();
  for (const entry of entries) {
    const [address, prefixText, ...extra] = entry.split("/");
    const family = isIP(address);
    const maxPrefix = family === 4 ? 32 : 128;
    const minPrefix = family === 4 ? 8 : 32;
    const prefix = prefixText === undefined ? maxPrefix : Number(prefixText);
    if (!family || extra.length || !Number.isInteger(prefix) ||
      prefix < minPrefix || prefix > maxPrefix) {
      throw new Error(`Invalid authorized network CIDR: ${entry}. Use IPv4 /8–/32 or IPv6 /32–/128.`);
    }
    ranges.addSubnet(address, prefix, family === 4 ? "ipv4" : "ipv6");
  }
  return { entries, ranges };
}
const portScanPolicyDefaults = {
  maxPortsByRole: { admin: 100, user: 25 },
  localScanByRole: { admin: true, user: false },
  largestBulkCidrPrefix: { ipv4: 24, ipv6: 120 },
  zmapRate: 10000,
};
const zmapEnabled = process.env.ZMAP_ENABLED === "true";
const zmapRateLimits = { min: 1000, max: 100000 };
const bulkScanLimits = { tcpConnect: 256, zmapIpv4: 65536 };
database.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS user_sessions_expiry ON user_sessions(expires_at);
  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS shared_results (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS shared_results_user ON shared_results(user_id, created_at);
  CREATE TABLE IF NOT EXISTS lookup_history (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    title TEXT NOT NULL,
    query TEXT NOT NULL,
    params TEXT NOT NULL,
    payload TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS lookup_history_user ON lookup_history(user_id, id DESC);
  CREATE TABLE IF NOT EXISTS monitors (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    interval_hours INTEGER NOT NULL,
    notify INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    next_run_at INTEGER NOT NULL,
    last_run_at INTEGER,
    last_status TEXT,
    last_summary TEXT,
    last_snapshot TEXT,
    last_change_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS monitors_user ON monitors(user_id, id);
  CREATE INDEX IF NOT EXISTS monitors_due ON monitors(enabled, next_run_at);
  CREATE TABLE IF NOT EXISTS monitor_events (
    id INTEGER PRIMARY KEY,
    monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS monitor_events_monitor ON monitor_events(monitor_id, id DESC);
  CREATE TABLE IF NOT EXISTS domain_ratings (
    domain TEXT NOT NULL,
    kind TEXT NOT NULL,
    grade TEXT NOT NULL,
    score INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (domain, kind)
  );
  CREATE INDEX IF NOT EXISTS domain_ratings_kind ON domain_ratings(kind, checked_at);
  CREATE INDEX IF NOT EXISTS shared_results_expiry ON shared_results(expires_at);
  CREATE TABLE IF NOT EXISTS public_lookup_usage (
    client_hash TEXT NOT NULL,
    utc_date TEXT NOT NULL,
    lookup_count INTEGER NOT NULL,
    PRIMARY KEY (client_hash, utc_date)
  );
  CREATE TABLE IF NOT EXISTS nmap_login_ips (
    address TEXT PRIMARY KEY,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS nmap_login_ips_expiry ON nmap_login_ips(expires_at);
  CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY,
    category TEXT NOT NULL CHECK (category IN ('login', 'audit', 'query')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username TEXT,
    client_ip TEXT,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    status_code INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS admin_logs_category_id ON admin_logs(category, id DESC);
  CREATE TRIGGER IF NOT EXISTS admin_logs_retention
  AFTER INSERT ON admin_logs
  BEGIN
    DELETE FROM admin_logs
    WHERE id NOT IN (SELECT id FROM admin_logs ORDER BY id DESC LIMIT 20000);
  END;
`);
if (!database.prepare("PRAGMA table_info(users)").all()
  .some((column) => column.name === "must_change_password")) {
  database.exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
}
if (!database.prepare("PRAGMA table_info(users)").all()
  .some((column) => column.name === "email")) {
  database.exec("ALTER TABLE users ADD COLUMN email TEXT");
}
for (const [column, definition] of [["totp_secret", "TEXT"], ["totp_enabled", "INTEGER NOT NULL DEFAULT 0"], ["totp_last_step", "INTEGER NOT NULL DEFAULT 0"], ["totp_recovery", "TEXT"]]) {
  if (!database.prepare("PRAGMA table_info(users)").all().some((entry) => entry.name === column)) {
    database.exec(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
  }
}
database.exec(`
  CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(user_id);
`);
database.prepare("UPDATE admin_logs SET action = 'Port scan' WHERE action = 'Port scan'").run();
database.prepare(`
  INSERT OR IGNORE INTO app_settings (key, value) VALUES ('trusted_proxies', ?)
`).run(JSON.stringify(trustedProxyEntries));
const savedTrustedProxies = database.prepare(
  "SELECT value FROM app_settings WHERE key = 'trusted_proxies'",
).get();
if (savedTrustedProxies) {
  let entries;
  try {
    entries = JSON.parse(savedTrustedProxies.value);
  } catch {
    throw new Error("Stored trusted proxy settings are invalid JSON.");
  }
  if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) {
    throw new Error("Stored trusted proxy settings must be an array of strings.");
  }
  ({ entries: trustedProxyEntries, ranges: trustedProxyRanges } =
    parseTrustedProxyEntries(entries.join("\n")));
}
const savedCloudflareProxyTrust = database.prepare(
  "SELECT value FROM app_settings WHERE key = 'cloudflare_proxy_trust'",
).get();
if (savedCloudflareProxyTrust) {
  try {
    cloudflareProxyTrustEnabled = JSON.parse(savedCloudflareProxyTrust.value) === true;
  } catch {
    throw new Error("Stored Cloudflare proxy trust setting is invalid JSON.");
  }
}
const savedCloudflareProxyRanges = database.prepare(
  "SELECT value FROM app_settings WHERE key = 'cloudflare_proxy_ranges'",
).get();
if (savedCloudflareProxyRanges) {
  try {
    const entries = JSON.parse(savedCloudflareProxyRanges.value);
    if (!Array.isArray(entries) || entries.some((entry) => typeof entry !== "string")) {
      throw new Error("Expected an array of CIDR strings.");
    }
    cloudflareProxyEntries = parseCloudflareProxyRanges(entries.join("\n"));
  } catch {
    throw new Error("Stored Cloudflare proxy ranges are invalid.");
  }
}
cloudflareProxyUpdatedAt = database.prepare(
  "SELECT value FROM app_settings WHERE key = 'cloudflare_proxy_updated_at'",
).get()?.value || null;
({ ranges: trustedProxyRanges } = combineTrustedProxyRanges(
  trustedProxyEntries,
  cloudflareProxyTrustEnabled ? cloudflareProxyEntries : [],
));
database.prepare(`
  INSERT OR IGNORE INTO app_settings (key, value)
  VALUES ('public_lookup_hash_key', ?)
`).run(crypto.randomBytes(32).toString("hex"));
// Sessions saved in a restored backup are not carried over: everyone logs in again.
if (restoreApplied) database.exec("DELETE FROM user_sessions");
const publicLookupHashKey = database.prepare(
  "SELECT value FROM app_settings WHERE key = 'public_lookup_hash_key'",
).get().value;

function parseCloudflareProxyRanges(value) {
  if (typeof value !== "string" || value.length > 8192) {
    throw new Error("The Cloudflare proxy range list is too large.");
  }
  const entries = [...new Set(value.split(/\s+/).map((entry) => entry.trim()).filter(Boolean))];
  if (entries.length < 2 || entries.length > 100) {
    throw new Error("The Cloudflare proxy range list has an unexpected number of networks.");
  }
  const ranges = new net.BlockList();
  const families = new Set();
  for (const entry of entries) {
    const [address, prefixText, ...extra] = entry.split("/");
    const family = isIP(address);
    const prefix = Number(prefixText);
    if (!family || extra.length || prefixText === undefined || !/^\d+$/.test(prefixText) ||
      !Number.isInteger(prefix) || prefix < (family === 4 ? 8 : 16) ||
      prefix > (family === 4 ? 32 : 128)) {
      throw new Error("Cloudflare published an invalid proxy IP range.");
    }
    ranges.addSubnet(address, prefix, family === 4 ? "ipv4" : "ipv6");
    families.add(family);
  }
  if (!families.has(4) || !families.has(6)) {
    throw new Error("Cloudflare must publish both IPv4 and IPv6 proxy ranges.");
  }
  return entries;
}

function combineTrustedProxyRanges(manualEntries, cloudflareEntries) {
  return parseTrustedProxyEntries(
    [...manualEntries, ...cloudflareEntries].join("\n"),
    150,
    16384,
  );
}

async function fetchCloudflareProxyRanges(url) {
  const response = await fetch(url, {
    headers: { accept: "text/plain", "user-agent": "BNGlookup trusted proxy range updater" },
    signal: AbortSignal.timeout(10000),
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Cloudflare range service returned HTTP ${response.status}.`);
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Cloudflare range service returned an empty response.");
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > 8192) {
      await reader.cancel();
      throw new Error("Cloudflare range response exceeded the size limit.");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

function refreshCloudflareProxyRanges() {
  if (cloudflareProxyRefreshPromise) return cloudflareProxyRefreshPromise;
  cloudflareProxyRefreshPromise = (async () => {
    const [ipv4, ipv6] = await Promise.all([
      fetchCloudflareProxyRanges("https://www.cloudflare.com/ips-v4"),
      fetchCloudflareProxyRanges("https://www.cloudflare.com/ips-v6"),
    ]);
    const updatedEntries = parseCloudflareProxyRanges(`${ipv4}\n${ipv6}`);
    combineTrustedProxyRanges(trustedProxyEntries, updatedEntries);
    const updatedAt = new Date().toISOString();
    const saveSetting = database.prepare(`
      INSERT INTO app_settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);
    database.exec("BEGIN IMMEDIATE");
    try {
      saveSetting.run("cloudflare_proxy_ranges", JSON.stringify(updatedEntries));
      saveSetting.run("cloudflare_proxy_updated_at", updatedAt);
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    cloudflareProxyEntries = updatedEntries;
    cloudflareProxyUpdatedAt = updatedAt;
    trustedProxyRanges = combineTrustedProxyRanges(
      trustedProxyEntries,
      cloudflareProxyTrustEnabled ? updatedEntries : [],
    ).ranges;
    return updatedAt;
  })().finally(() => {
    cloudflareProxyRefreshPromise = null;
  });
  return cloudflareProxyRefreshPromise;
}

if (cloudflareProxyTrustEnabled) {
  void refreshCloudflareProxyRanges().catch((error) => {
    console.error("Unable to refresh Cloudflare proxy ranges; retaining the last known-good list:", error);
  });
}
setInterval(() => {
  if (cloudflareProxyTrustEnabled) {
    void refreshCloudflareProxyRanges().catch((error) => {
      console.error("Unable to refresh Cloudflare proxy ranges; retaining the last known-good list:", error);
    });
  }
}, 12 * 60 * 60 * 1000).unref();

function recordAdminLog(category, request, action, details, statusCode, username) {
  try {
    const actor = username === undefined
      ? request.logUsername || currentUser(request)?.username || null
      : username;
    database.prepare(`
      INSERT INTO admin_logs (category, username, client_ip, action, details, status_code)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      category,
      actor,
      request.logClientAddress ?? getClientAddress(request),
      action,
      String(details || "").slice(0, 2000),
      statusCode,
    );
  } catch (error) {
    console.error("Unable to write admin log entry:", error);
  }
}

const dnsStatusNames = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
  6: "YXDOMAIN",
  7: "YXRRSET",
  8: "NXRRSET",
  9: "NOTAUTH",
  10: "NOTZONE",
  16: "BADVERS",
  23: "BADCOOKIE",
};
const dnsTypeCodes = {
  A: 1,
  NS: 2,
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  WKS: 11,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19,
  ISDN: 20,
  RT: 21,
  NSAP: 22,
  "NSAP-PTR": 23,
  SIG: 24,
  KEY: 25,
  PX: 26,
  GPOS: 27,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  EID: 31,
  NIMLOC: 32,
  SRV: 33,
  ATMA: 34,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  A6: 38,
  DNAME: 39,
  SINK: 40,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  NINFO: 56,
  RKEY: 57,
  TALINK: 58,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  UINFO: 100,
  UID: 101,
  GID: 102,
  UNSPEC: 103,
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  TKEY: 249,
  TSIG: 250,
  IXFR: 251,
  AXFR: 252,
  MAILB: 253,
  MAILA: 254,
  ANY: 255,
  URI: 256,
  CAA: 257,
  AVC: 258,
  DOA: 259,
  AMTRELAY: 260,
  TA: 32768,
  DLV: 32769,
};
const dnsTypeNames = Object.fromEntries(
  Object.entries(dnsTypeCodes).map(([name, code]) => [code, name]),
);
const scanRecordTypes = ["A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "SOA", "SRV", "TXT"];
const certificateTransparencyRecordTypes = ["A", "AAAA", "CNAME", "TXT"];
const certificateTransparencyCandidateLimit = 25;
const commonSubdomains = [
  "www", "mail", "webmail", "ftp", "api", "app", "admin", "portal",
  "blog", "shop", "dev", "staging", "test", "status", "cdn", "static",
  "vpn", "smtp", "imap", "pop", "files", "docs", "support", "git",
];
const providerCandidates = [
  { name: "_amazonses", provider: "AWS / SES", types: ["TXT"] },
  { name: "selector1._domainkey", provider: "AWS / SES", types: ["CNAME", "TXT"] },
  { name: "selector2._domainkey", provider: "AWS / SES", types: ["CNAME", "TXT"] },
  { name: "amazonses._domainkey", provider: "AWS / SES", types: ["CNAME", "TXT"] },
  { name: "awverify", provider: "Azure", types: ["CNAME", "TXT"] },
  { name: "awverify.www", provider: "Azure", types: ["CNAME", "TXT"] },
  { name: "asuid", provider: "Azure", types: ["TXT"] },
  { name: "asuid.www", provider: "Azure", types: ["TXT"] },
  { name: "afdverify", provider: "Azure Front Door", types: ["CNAME", "TXT"] },
  { name: "afdverify.www", provider: "Azure Front Door", types: ["CNAME", "TXT"] },
  { name: "azurefd", provider: "Azure Front Door", types: ["A", "AAAA", "CNAME"] },
  { name: "azurewebsites", provider: "Azure App Service", types: ["A", "AAAA", "CNAME"] },
  { name: "trafficmanager", provider: "Azure Traffic Manager", types: ["A", "AAAA", "CNAME"] },
  { name: "appspot", provider: "Google Cloud", types: ["A", "AAAA", "CNAME"] },
  { name: "ghs", provider: "Google Cloud", types: ["A", "AAAA", "CNAME"] },
  { name: "googleapis", provider: "Google Cloud", types: ["A", "AAAA", "CNAME"] },
  { name: "cloudrun", provider: "Google Cloud Run", types: ["A", "AAAA", "CNAME"] },
  { name: "cloudfunctions", provider: "Google Cloud Functions", types: ["A", "AAAA", "CNAME"] },
  { name: "storage", provider: "Google Cloud Storage", types: ["A", "AAAA", "CNAME"] },
  { name: "_cloudflare", provider: "Cloudflare", types: ["TXT", "CNAME"] },
  { name: "workers", provider: "Cloudflare Workers", types: ["A", "AAAA", "CNAME"] },
  { name: "pages", provider: "Cloudflare Pages / GitHub Pages", types: ["A", "AAAA", "CNAME", "TXT"] },
  { name: "_vercel", provider: "Vercel", types: ["TXT", "CNAME"] },
  { name: "vercel", provider: "Vercel", types: ["A", "AAAA", "CNAME"] },
  { name: "netlify", provider: "Netlify", types: ["A", "AAAA", "CNAME"] },
  { name: "_netlify", provider: "Netlify", types: ["TXT", "CNAME"] },
  { name: "heroku", provider: "Heroku", types: ["A", "AAAA", "CNAME"] },
  { name: "herokuapp", provider: "Heroku", types: ["A", "AAAA", "CNAME"] },
  { name: "digitalocean", provider: "DigitalOcean", types: ["A", "AAAA", "CNAME"] },
  { name: "render", provider: "Render", types: ["A", "AAAA", "CNAME"] },
  { name: "fly", provider: "Fly.io", types: ["A", "AAAA", "CNAME"] },
  { name: "railway", provider: "Railway", types: ["A", "AAAA", "CNAME"] },
  { name: "shopify", provider: "Shopify", types: ["A", "AAAA", "CNAME", "TXT"] },
  { name: "_acme-challenge", provider: "ACME certificate validation", types: ["TXT", "CNAME"] },
  { name: "_dmarc", provider: "Email security", types: ["TXT"] },
  { name: "_mta-sts", provider: "Email security", types: ["TXT"] },
  { name: "_smtp._tls", provider: "Email security", types: ["TXT"] },
];
const dkimSelectors = [
  ["default", "Common DKIM"],
  ["google", "Google Workspace"],
  ["selector1", "Microsoft 365"],
  ["selector2", "Microsoft 365"],
  ["k1", "Mailchimp"],
  ["s1", "Common DKIM"],
  ["s2", "Common DKIM"],
  ["mail", "Common DKIM"],
  ["smtp", "Common DKIM"],
  ["dkim", "Common DKIM"],
  ["amazonses", "AWS / SES"],
  ["mandrill", "Mailchimp / Mandrill"],
  ["zoho", "Zoho Mail"],
  ["protonmail", "Proton Mail"],
  ["mxvault", "Common DKIM"],
];
const scanConcurrency = 12;
const commonTcpPorts = [
  20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
  1433, 1521, 2222, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
];
const nonPublicAddressRanges = new net.BlockList();
[
  ["0.0.0.0", 8, "ipv4"], ["10.0.0.0", 8, "ipv4"],
  ["100.64.0.0", 10, "ipv4"], ["127.0.0.0", 8, "ipv4"],
  ["169.254.0.0", 16, "ipv4"], ["172.16.0.0", 12, "ipv4"],
  ["192.0.0.0", 24, "ipv4"], ["192.0.2.0", 24, "ipv4"],
  ["192.88.99.0", 24, "ipv4"], ["192.168.0.0", 16, "ipv4"],
  ["198.18.0.0", 15, "ipv4"], ["198.51.100.0", 24, "ipv4"],
  ["203.0.113.0", 24, "ipv4"], ["224.0.0.0", 4, "ipv4"],
  ["240.0.0.0", 4, "ipv4"], ["::", 128, "ipv6"],
  ["::1", 128, "ipv6"], ["64:ff9b:1::", 48, "ipv6"],
  // IPv6 forms that embed an IPv4 address and can be routed to it (IPv4-compatible,
  // SIIT, NAT64 and 6to4). net.BlockList only maps ::ffff:0:0/96 onto IPv4 rules itself.
  ["::", 96, "ipv6"], ["::ffff:0:0:0", 96, "ipv6"],
  ["64:ff9b::", 96, "ipv6"], ["2002::", 16, "ipv6"],
  ["100::", 64, "ipv6"],
  ["2001::", 23, "ipv6"], ["2001:db8::", 32, "ipv6"],
  ["fc00::", 7, "ipv6"], ["fe80::", 10, "ipv6"],
  ["ff00::", 8, "ipv6"],
].forEach(([address, prefix, family]) => {
  nonPublicAddressRanges.addSubnet(address, prefix, family);
});
const localAddressRanges = new net.BlockList();
[
  ["10.0.0.0", 8, "ipv4"], ["127.0.0.0", 8, "ipv4"],
  ["169.254.0.0", 16, "ipv4"], ["172.16.0.0", 12, "ipv4"],
  ["192.168.0.0", 16, "ipv4"], ["::1", 128, "ipv6"],
  ["fc00::", 7, "ipv6"], ["fe80::", 10, "ipv6"],
].forEach(([address, prefix, family]) => {
  localAddressRanges.addSubnet(address, prefix, family);
});
const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

function reverseName(address) {
  if (isIP(address) === 4) {
    return `${address.split(".").reverse().join(".")}.in-addr.arpa`;
  }

  if (isIP(address) !== 6) {
    throw new Error("Enter a valid IPv4 or IPv6 address for reverse lookup.");
  }

  const halves = address.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  let right = halves[1] ? halves[1].split(":") : [];

  if (right.some((part) => part.includes("."))) {
    const ipv4 = right.pop().split(".").map(Number);
    right.push(
      ((ipv4[0] << 8) | ipv4[1]).toString(16),
      ((ipv4[2] << 8) | ipv4[3]).toString(16),
    );
  } else if (left.some((part) => part.includes("."))) {
    const ipv4 = left.pop().split(".").map(Number);
    left.push(
      ((ipv4[0] << 8) | ipv4[1]).toString(16),
      ((ipv4[2] << 8) | ipv4[3]).toString(16),
    );
  }

  const missing = 8 - left.length - right.length;
  const groups = halves.length === 2
    ? [...left, ...Array(missing).fill("0"), ...right]
    : left;

  if (groups.length !== 8) {
    throw new Error("Enter a valid IPv4 or IPv6 address for reverse lookup.");
  }

  return `${groups
    .map((group) => group.padStart(4, "0"))
    .join("")
    .split("")
    .reverse()
    .join(".")}.ip6.arpa`;
}

function validDnsName(name) {
  if (!name || name.length > 253) return false;
  const normalized = name.endsWith(".") ? name.slice(0, -1) : name;
  if (!normalized) return false;
  return normalized.split(".").every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      /^[a-zA-Z0-9_-]+$/.test(label),
  );
}

// Reduces a pasted URL (scheme, credentials, port, path, query, fragment) to its host name or IP.
function hostFromInput(raw) {
  const value = String(raw || "").trim();
  if (!value) return "";
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
  if (!hasScheme && isIP(value.replace(/^\[(.*)\]$/, "$1"))) return value.replace(/^\[(.*)\]$/, "$1");
  try {
    const parsed = new URL(hasScheme ? value : `http://${value}`);
    if (parsed.hostname) return parsed.hostname.replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "").toLowerCase();
  } catch {
    // Not URL-shaped; validate the raw value as typed.
  }
  return value;
}

function normalizeDomain(name) {
  const normalized = domainToASCII(name.trim().replace(/\.$/, "").toLowerCase());
  if (
    !normalized ||
    normalized.length > 253 ||
    !normalized.includes(".") ||
    !normalized.split(".").every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    return null;
  }
  return normalized;
}

function entityContact(entity) {
  const vcard = entity.vcardArray;
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return null;

  const fields = Object.fromEntries(
    vcard[1]
      .filter((field) => Array.isArray(field) && typeof field[0] === "string")
      .map((field) => [
        field[0].toLowerCase(),
        Array.isArray(field[3])
          ? field[3].flat().filter((part) => typeof part === "string" && part.trim()).join(", ")
          : field[3],
      ]),
  );
  const contact = {
    name: fields.fn || fields["org"] || null,
    organization: fields.org || null,
    email: fields.email || null,
    phone: fields.tel || null,
    address: fields.adr || null,
  };
  return Object.values(contact).some(Boolean) ? contact : null;
}

const whoisServerCache = new Map();
const whoisNotFoundPattern = /^(?:no match|not found|no entries found|no data found|domain not found|status:\s*(?:free|available)|.*\bis (?:free|available for registration)\b|.*\bno (?:object|matching record)s? found\b|.*\bnot (?:been )?registered\b)/im;

function queryWhoisServer(server, query, { timeoutMs = 10000, maxBytes = 131072 } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const socket = net.connect({ host: server, port: 43 });
    const finish = (error) => {
      socket.destroy();
      if (error) reject(error);
      else resolve(Buffer.concat(chunks).toString("utf8"));
    };
    socket.setTimeout(timeoutMs, () => finish(Object.assign(new Error(`The WHOIS server ${server} did not respond in time.`), { name: "TimeoutError" })));
    socket.once("connect", () => socket.write(`${query}\r\n`));
    socket.on("data", (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        finish(null);
        return;
      }
      chunks.push(chunk);
    });
    socket.once("end", () => finish(null));
    socket.once("error", (error) => finish(new Error(`The WHOIS server ${server} could not be reached (${error.code || error.message}).`)));
  });
}

// Optional overrides, e.g. WHOIS_SERVERS="ga=whois.example.ga,xyz=whois.nic.xyz".
const whoisServerOverrides = new Map((process.env.WHOIS_SERVERS || "")
  .split(/[\s,]+/)
  .map((entry) => entry.split("=").map((part) => part.trim().toLowerCase()))
  .filter(([tld, server]) => /^[a-z0-9-]{2,63}$/.test(tld || "") && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(server || "")));

async function whoisServerForTld(tld) {
  if (whoisServerOverrides.has(tld)) return { server: whoisServerOverrides.get(tld), registryUrl: null };
  const cached = whoisServerCache.get(tld);
  if (cached && Date.now() - cached.at < 24 * 3600_000) return cached;
  const text = await queryWhoisServer("whois.iana.org", tld);
  const server = (text.match(/^whois:\s*([a-z0-9.-]+)\s*$/im) || text.match(/^refer:\s*([a-z0-9.-]+)\s*$/im) || [])[1]?.toLowerCase() || null;
  const registryUrl = text.match(/^remarks:\s*registration information:\s*(https?:\/\/\S+)\s*$/im)?.[1] || null;
  const entry = { server, registryUrl, at: Date.now() };
  whoisServerCache.set(tld, entry);
  return entry;
}

// Parses "Key: value" WHOIS text, including indented multi-line blocks such as the .nl format.
function parseWhoisText(text) {
  const fields = [];
  let current = null;
  for (const rawLine of text.split(/\r?\n/)) {
    if (/^\s*[%#>]/.test(rawLine) || /^\s*-{3,}/.test(rawLine)) continue;
    if (!rawLine.trim()) {
      current = null;
      continue;
    }
    const match = rawLine.match(/^\s*([A-Za-z][A-Za-z0-9 ./()'_-]{0,60}?)\s*:\s*(.*)$/);
    if (match && !/^https?$/i.test(match[1])) {
      current = { key: match[1].trim().toLowerCase(), values: match[2].trim() ? [match[2].trim()] : [] };
      fields.push(current);
    } else if (current && /^\s+/.test(rawLine)) {
      current.values.push(rawLine.trim());
    }
  }
  return fields;
}

function registrationFromWhois(domain, server, text) {
  const fields = parseWhoisText(text);
  const valuesFor = (pattern) => fields.filter((field) => pattern.test(field.key)).flatMap((field) => field.values).filter(Boolean);
  const firstDate = (pattern) => {
    for (const value of valuesFor(pattern)) {
      const cleaned = value.replace(/\s*\(.*\)$/, "").trim();
      const parsed = Date.parse(/^\d{4}\.\d{2}\.\d{2}/.test(cleaned) ? cleaned.replace(/\./g, "-") : cleaned.replace(/^(\d{2})[-./](\d{2})[-./](\d{4})/, "$3-$2-$1"));
      if (!Number.isNaN(parsed)) return new Date(parsed).toISOString();
    }
    return null;
  };
  const dates = {};
  const created = firstDate(/^(creation date|created|created on|registered|registered on|registration date|registration time|domain registration date|record created|activated)$/);
  const expires = firstDate(/^(registry expiry date|registrar registration expiration date|expiry date|expiration date|expires|expires on|expire|paid-till|renewal date|validity)$/);
  const updated = firstDate(/^(updated date|last updated|last update|changed|last modified|modified|last-update)$/);
  if (created) dates.registration = created;
  if (expires) dates.expiration = expires;
  if (updated) dates["last changed"] = updated;
  const registrarName = valuesFor(/^(registrar|sponsoring registrar|registrar name|registrar organization)$/)[0] || null;
  const nameservers = [...new Set(valuesFor(/^(name ?servers?|nserver|domain nameservers|nameservers? information|dns|host ?name)$/)
    .flatMap((value) => value.split(/[\s,]+/))
    .map((value) => value.toLowerCase().replace(/\.$/, ""))
    .filter((value) => /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(value) && !isIP(value)))];
  const statuses = [...new Set(valuesFor(/^(domain status|status|state)$/)
    .map((value) => value.split(/\s+/)[0])
    .filter(Boolean))];
  const registrant = valuesFor(/^(registrant organization|registrant organisation|registrant|org)$/)[0] || null;
  return {
    name: (valuesFor(/^(domain name|domain)$/)[0] || domain).toLowerCase(),
    handle: null,
    registrar: registrarName ? { name: registrarName, organization: null, email: null, phone: null, address: null } : null,
    dates,
    statuses,
    contacts: registrant && !/redacted|privacy|withheld|not disclosed/i.test(registrant)
      ? [{ roles: ["registrant"], name: registrant, organization: null, email: null, phone: null, address: null }]
      : [],
    nameservers: nameservers.map((name) => ({ name, ipv4: [], ipv6: [] })),
    source: "whois",
    whoisServer: server,
    rawWhois: text.trim().slice(0, 20000),
  };
}

async function fetchWhois(domain) {
  const tld = domain.split(".").pop();
  const { server, registryUrl } = await whoisServerForTld(tld);
  if (!server) {
    throw Object.assign(new Error(`The .${tld} registry publishes no RDAP or WHOIS service, so registration details cannot be retrieved automatically.${registryUrl ? " Check the registry's website instead." : ""} DNS details are still shown.`), { noService: true, registryUrl });
  }
  const query = server === "whois.denic.de" ? `-T dn,ace ${domain}` : domain;
  let text = await queryWhoisServer(server, query);
  let usedServer = server;
  if (whoisNotFoundPattern.test(text) && !/^domain name:/im.test(text)) {
    throw Object.assign(new Error("No registration record was found for this domain."), { notFound: true });
  }
  // Thin registries (such as .com) refer to the registrar's WHOIS server for full details.
  const referral = text.match(/^\s*registrar whois server:\s*([a-z0-9.-]+)\s*$/im)?.[1]?.toLowerCase();
  if (referral && referral !== server && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(referral)) {
    try {
      const detailed = await queryWhoisServer(referral, domain);
      if (detailed.trim() && !whoisNotFoundPattern.test(detailed)) {
        text = `${text.trim()}\n\n# ${referral}\n${detailed}`;
        usedServer = `${server} → ${referral}`;
      }
    } catch {
      // Keep the registry answer if the registrar server is unreachable.
    }
  }
  return registrationFromWhois(domain, usedServer, text);
}

// RDAP first; many ccTLDs (for example .nl and .ga) only offer port-43 WHOIS.
async function fetchRegistration(domain) {
  let rdapError;
  try {
    return { source: "rdap", ...await fetchRdap(domain) };
  } catch (error) {
    rdapError = error;
  }
  // A subdomain is not registered on its own, so retry with parent names down to two labels.
  const labels = domain.split(".");
  const candidates = labels.slice(0, -1).map((_, index) => labels.slice(index).join(".")).slice(0, 4);
  let whoisError;
  for (const candidate of candidates) {
    try {
      return await fetchWhois(candidate);
    } catch (error) {
      whoisError ||= error;
      if (!error.notFound) break;
    }
  }
  if (whoisError?.notFound || whoisError?.noService) throw whoisError;
  throw Object.assign(new Error(`Registration details are unavailable: ${rdapError.message} WHOIS fallback: ${whoisError?.message || "unavailable"}`), { registryUrl: whoisError?.registryUrl || null });
}

async function fetchRdap(domain) {
  const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: {
      accept: "application/rdap+json, application/json",
      "user-agent": "BNGlookup/0.1 (+https://github.com/BANAANGA/BNGlookup)",
    },
    signal: AbortSignal.timeout(10000),
  });
  if (response.status === 404) {
    throw Object.assign(new Error("RDAP has no record for this domain (or no RDAP service for its TLD)."), { notFound: true });
  }
  if (!response.ok) {
    throw new Error(`RDAP provider returned HTTP ${response.status}.`);
  }

  const data = await response.json();
  if (data.objectClassName !== "domain") {
    throw new Error("RDAP provider returned an invalid domain record.");
  }

  const entities = Array.isArray(data.entities) ? data.entities : [];
  const registrar = entities.find((entity) =>
    Array.isArray(entity.roles) && entity.roles.includes("registrar"),
  );
  const contacts = entities.flatMap((entity) => {
    const contact = entityContact(entity);
    return contact
      ? [{ roles: Array.isArray(entity.roles) ? entity.roles : [], ...contact }]
      : [];
  });
  const dates = {};
  for (const event of Array.isArray(data.events) ? data.events : []) {
    if (event.eventAction && event.eventDate) {
      dates[event.eventAction] = event.eventDate;
    }
  }

  return {
    name: data.ldhName || domain,
    handle: data.handle || null,
    registrar: registrar ? entityContact(registrar) : null,
    dates,
    statuses: Array.isArray(data.status) ? data.status : [],
    contacts,
    nameservers: Array.isArray(data.nameservers)
      ? data.nameservers.map((nameserver) => ({
        name: nameserver.ldhName || nameserver.unicodeName || "",
        ipv4: Array.isArray(nameserver.ipAddresses?.v4) ? nameserver.ipAddresses.v4 : [],
        ipv6: Array.isArray(nameserver.ipAddresses?.v6) ? nameserver.ipAddresses.v6 : [],
      }))
      : [],
  };
}

async function fetchIpRdap(address) {
  const response = await fetch(`https://rdap.org/ip/${address}`, {
    headers: {
      accept: "application/rdap+json, application/json",
      "user-agent": "BNGlookup/0.1 (+https://github.com/BANAANGA/BNGlookup)",
    },
    signal: AbortSignal.timeout(10000),
  });
  if (response.status === 404) {
    throw new Error("No registration record was found for this IP address.");
  }
  if (!response.ok) {
    throw new Error(`RDAP provider returned HTTP ${response.status}.`);
  }

  const data = await response.json();
  if (data.objectClassName !== "ip network") {
    throw new Error("RDAP provider returned an invalid IP address record.");
  }

  const contacts = [];
  function collectContacts(entities) {
    for (const entity of entities) {
      if (!entity || typeof entity !== "object") continue;
      const contact = entityContact(entity);
      if (contact) {
        contacts.push({
          roles: Array.isArray(entity.roles) ? entity.roles : [],
          ...contact,
        });
      }
      if (Array.isArray(entity.entities)) collectContacts(entity.entities);
    }
  }
  collectContacts(Array.isArray(data.entities) ? data.entities : []);
  const asNumbers = [
    ...(Array.isArray(data.originAutnums) ? data.originAutnums : []),
    ...(Array.isArray(data.arin_originas0_originautnums)
      ? data.arin_originas0_originautnums
      : []),
  ]
    .map((value) => typeof value === "number" ? String(value) : String(value).replace(/^AS/i, ""))
    .filter((value) => /^\d+$/.test(value))
    .map((value) => `AS${value}`);
  const cidrs = (Array.isArray(data.cidr0_cidrs) ? data.cidr0_cidrs : [])
    .flatMap((entry) => {
      if (!entry || typeof entry !== "object") return [];
      const prefix = typeof entry.v4prefix === "string"
        ? entry.v4prefix
        : typeof entry.v6prefix === "string"
          ? entry.v6prefix
          : null;
      const maxPrefix = entry.v4prefix ? 32 : entry.v6prefix ? 128 : 0;
      return prefix && Number.isInteger(entry.length) &&
        entry.length >= 0 && entry.length <= maxPrefix
        ? [`${prefix}/${entry.length}`]
        : [];
    });
  let asnError = null;
  if (asNumbers.length === 0 && isPublicAddress(address)) {
    const errors = [];
    try {
      const response = await fetch(
        `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(address)}`,
        {
          headers: {
            accept: "application/json",
            "user-agent": "BNGlookup/0.1 (+https://github.com/BANAANGA/BNGlookup)",
          },
          signal: AbortSignal.timeout(5000),
        },
      );
      if (!response.ok) {
        throw new Error(`RIPE Stat returned HTTP ${response.status}.`);
      }
      const result = await response.json();
      const candidates = result.status === "ok" && result.data_call_status === "supported"
        ? result.data?.asns
        : null;
      const ripeAsns = (Array.isArray(candidates) ? candidates : [])
        .map((value) => String(value).replace(/^AS/i, ""))
        .filter((value) => /^\d+$/.test(value) && Number(value) <= 4294967295)
        .map((value) => `AS${value}`);
      asNumbers.push(...ripeAsns);
      if (!ripeAsns.length) throw new Error("RIPE Stat returned no autonomous system number.");
    } catch (error) {
      errors.push(error.message || "RIPE Stat lookup failed.");
    }
    if (!asNumbers.length) {
      try {
        const response = await fetch(`https://ipwho.is/${address}`, {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) {
          throw new Error(`ASN provider returned HTTP ${response.status}.`);
        }
        const result = await response.json();
        const asn = result.success === true ? result.connection?.asn : null;
        const normalizedAsn = String(asn ?? "").replace(/^AS/i, "");
        if (/^\d+$/.test(normalizedAsn) && Number(normalizedAsn) <= 4294967295) {
          asNumbers.push(`AS${normalizedAsn}`);
        } else {
          throw new Error("ASN provider returned no autonomous system number.");
        }
      } catch (error) {
        errors.push(error.message || "ASN provider lookup failed.");
      }
    }
    if (!asNumbers.length) asnError = errors.join(" ");
  }
  const dates = {};
  for (const event of Array.isArray(data.events) ? data.events : []) {
    if (event.eventAction && event.eventDate) {
      dates[event.eventAction] = event.eventDate;
    }
  }

  return {
    name: typeof data.name === "string" ? data.name : null,
    handle: typeof data.handle === "string" ? data.handle : null,
    startAddress: typeof data.startAddress === "string" ? data.startAddress : null,
    endAddress: typeof data.endAddress === "string" ? data.endAddress : null,
    ipVersion: typeof data.ipVersion === "string" ? data.ipVersion : null,
    country: typeof data.country === "string" ? data.country : null,
    type: typeof data.type === "string" ? data.type : null,
    parentHandle: typeof data.parentHandle === "string" ? data.parentHandle : null,
    port43: typeof data.port43 === "string" ? data.port43 : null,
    asNumbers: [...new Set(asNumbers)],
    asnError,
    cidrs: [...new Set(cidrs)],
    dates,
    statuses: Array.isArray(data.status) ? data.status : [],
    contacts,
  };
}

function parseNameserver(input) {
  if (!input) return null;
  if (input.length > 300) {
    throw new Error("Nameserver input must not exceed 300 characters.");
  }
  let address = input.trim();
  let port = 53;

  const ipv6WithPort = address.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (ipv6WithPort) {
    address = ipv6WithPort[1];
    if (ipv6WithPort[2]) port = Number(ipv6WithPort[2]);
  } else {
    const ipv4WithPort = address.match(/^([^:]+):(\d+)$/);
    if (ipv4WithPort) {
      address = ipv4WithPort[1];
      port = Number(ipv4WithPort[2]);
    }
  }

  const family = isIP(address);
  const hostname = family ? null : normalizeDomain(address);
  if ((!family && !hostname) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Enter a valid nameserver IP address or hostname, optionally followed by a port.");
  }
  return { address: family ? address : hostname, family, port };
}

async function resolveNameserver(nameserver) {
  if (!nameserver || nameserver.family) return nameserver;
  const addresses = await resolveHost(nameserver.address, { all: true, verbatim: true });
  const address = addresses.find((entry) => entry.family === 4 || entry.family === 6);
  if (!address) throw new Error("The nameserver hostname did not resolve to an IP address.");
  return { ...nameserver, address: address.address, family: address.family };
}

function dnsQuestionType(type) {
  if (/^\d+$/.test(type)) {
    const code = Number(type);
    if (code > 0 && code <= 65535) return code;
    throw new Error("Enter a valid DNS record type.");
  }
  const code = dnsTypeCodes[type];
  if (code) return code;
  throw new Error("This record type is not supported for direct nameserver queries.");
}

function encodeDnsQuery(name, typeCode, { dnssec = false, checkingDisabled = false, recursion = true } = {}) {
  const labels = name.replace(/\.$/, "").split(".");
  const encodedName = Buffer.concat([
    ...labels.map((label) => {
      const bytes = Buffer.from(label, "ascii");
      if (bytes.length === 0 || bytes.length > 63) {
        throw new Error("The DNS name contains an invalid label.");
      }
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    }),
    Buffer.from([0]),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(Math.floor(Math.random() * 65536), 0);
  // RD, plus AD to request the validation result and CD to skip validation when asked.
  header.writeUInt16BE((recursion ? 0x0100 : 0) | (dnssec ? 0x0020 : 0) | (checkingDisabled ? 0x0010 : 0), 2);
  header.writeUInt16BE(1, 4);
  const questionTail = Buffer.alloc(4);
  questionTail.writeUInt16BE(typeCode, 0);
  questionTail.writeUInt16BE(1, 2);
  if (!dnssec) return Buffer.concat([header, encodedName, questionTail]);
  header.writeUInt16BE(1, 10);
  // EDNS(0) OPT record: root name, type 41, 4096-byte UDP size, DO bit set.
  const opt = Buffer.from([0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0]);
  return Buffer.concat([header, encodedName, questionTail, opt]);
}

function decodeDnsName(packet, start) {
  const labels = [];
  let offset = start;
  let nextOffset = null;
  let jumps = 0;
  while (offset < packet.length) {
    const length = packet[offset];
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= packet.length || jumps++ > 20) {
        throw new Error("DNS response contains an invalid name pointer.");
      }
      const pointer = ((length & 0x3f) << 8) | packet[offset + 1];
      if (nextOffset === null) nextOffset = offset + 2;
      offset = pointer;
      continue;
    }
    if (length & 0xc0) throw new Error("DNS response contains an invalid label.");
    offset += 1;
    if (length === 0) {
      return { name: labels.join(".") || ".", nextOffset: nextOffset ?? offset };
    }
    if (length > 63 || offset + length > packet.length) {
      throw new Error("DNS response contains an invalid label.");
    }
    labels.push(packet.toString("utf8", offset, offset + length));
    offset += length;
  }
  throw new Error("DNS response contains a truncated name.");
}

function decodeDnsRecordData(packet, typeCode, start, length) {
  const end = start + length;
  if (end > packet.length) throw new Error("DNS response contains truncated record data.");
  if (typeCode === 1 && length === 4) return [...packet.subarray(start, end)].join(".");
  if (typeCode === 28 && length === 16) {
    const groups = [];
    for (let i = start; i < end; i += 2) groups.push(packet.readUInt16BE(i).toString(16));
    return groups.join(":");
  }
  if ([2, 5, 12, 39].includes(typeCode)) return decodeDnsName(packet, start).name;
  if (typeCode === 15 && length >= 3) {
    return `${packet.readUInt16BE(start)} ${decodeDnsName(packet, start + 2).name}`;
  }
  if (typeCode === 33 && length >= 7) {
    return `${packet.readUInt16BE(start)} ${packet.readUInt16BE(start + 2)} ${packet.readUInt16BE(start + 4)} ${decodeDnsName(packet, start + 6).name}`;
  }
  if (typeCode === 35 && length >= 7) {
    const order = packet.readUInt16BE(start);
    const preference = packet.readUInt16BE(start + 2);
    let offset = start + 4;
    const strings = [];
    for (let index = 0; index < 3; index += 1) {
      if (offset >= end) throw new Error("DNS response contains truncated NAPTR data.");
      const stringLength = packet[offset++];
      if (offset + stringLength > end) throw new Error("DNS response contains truncated NAPTR data.");
      strings.push(JSON.stringify(packet.toString("utf8", offset, offset + stringLength)));
      offset += stringLength;
    }
    const replacement = decodeDnsName(packet, offset);
    if (replacement.nextOffset > end) throw new Error("DNS response contains truncated NAPTR data.");
    return `${order} ${preference} ${strings.join(" ")} ${replacement.name}`;
  }
  if (typeCode === 6) {
    const mname = decodeDnsName(packet, start);
    const rname = decodeDnsName(packet, mname.nextOffset);
    const numbersOffset = rname.nextOffset;
    if (numbersOffset + 20 > end) throw new Error("DNS response contains truncated SOA data.");
    return `${mname.name} ${rname.name} ${[
      packet.readUInt32BE(numbersOffset),
      packet.readUInt32BE(numbersOffset + 4),
      packet.readUInt32BE(numbersOffset + 8),
      packet.readUInt32BE(numbersOffset + 12),
      packet.readUInt32BE(numbersOffset + 16),
    ].join(" ")}`;
  }
  if (typeCode === 16) {
    const chunks = [];
    for (let offset = start; offset < end;) {
      const chunkLength = packet[offset++];
      if (offset + chunkLength > end) throw new Error("DNS response contains truncated TXT data.");
      chunks.push(JSON.stringify(packet.toString("utf8", offset, offset + chunkLength)));
      offset += chunkLength;
    }
    return chunks.join(" ");
  }
  if ((typeCode === 43 || typeCode === 59) && length >= 4) {
    return `${packet.readUInt16BE(start)} ${packet[start + 2]} ${packet[start + 3]} ${packet.subarray(start + 4, end).toString("hex").toUpperCase()}`;
  }
  if ((typeCode === 48 || typeCode === 60) && length >= 4) {
    return `${packet.readUInt16BE(start)} ${packet[start + 2]} ${packet[start + 3]} ${packet.subarray(start + 4, end).toString("base64")}`;
  }
  if (typeCode === 46 && length >= 19) {
    const covered = packet.readUInt16BE(start);
    const signer = decodeDnsName(packet, start + 18);
    const stamp = (seconds) => new Date(seconds * 1000).toISOString().replace(/[-:T]/g, "").slice(0, 14);
    return [
      dnsTypeNames[covered] || `TYPE${covered}`,
      packet[start + 2],
      packet[start + 3],
      packet.readUInt32BE(start + 4),
      stamp(packet.readUInt32BE(start + 8)),
      stamp(packet.readUInt32BE(start + 12)),
      packet.readUInt16BE(start + 16),
      signer.name,
      packet.subarray(signer.nextOffset, end).toString("base64"),
    ].join(" ");
  }
  if (typeCode === 257 && length >= 2) {
    const flags = packet[start];
    const tagLength = packet[start + 1];
    if (start + 2 + tagLength > end) throw new Error("DNS response contains truncated CAA data.");
    const tag = packet.toString("ascii", start + 2, start + 2 + tagLength);
    const value = packet.toString("utf8", start + 2 + tagLength, end);
    return `${flags} ${tag} ${JSON.stringify(value)}`;
  }
  return `\\# ${length} ${packet.subarray(start, end).toString("hex").toUpperCase()}`;
}

function parseDnsPacket(packet) {
  if (packet.length < 12) throw new Error("DNS server returned a truncated response.");
  const flags = packet.readUInt16BE(2);
  const questionCount = packet.readUInt16BE(4);
  const counts = [
    packet.readUInt16BE(6),
    packet.readUInt16BE(8),
    packet.readUInt16BE(10),
  ];
  let offset = 12;
  for (let i = 0; i < questionCount; i += 1) {
    offset = decodeDnsName(packet, offset).nextOffset + 4;
  }
  const sections = [];
  for (const count of counts) {
    const records = [];
    for (let i = 0; i < count; i += 1) {
      const decodedName = decodeDnsName(packet, offset);
      offset = decodedName.nextOffset;
      if (offset + 10 > packet.length) throw new Error("DNS server returned a truncated record.");
      const typeCode = packet.readUInt16BE(offset);
      const recordClass = packet.readUInt16BE(offset + 2);
      const ttl = packet.readUInt32BE(offset + 4);
      const dataLength = packet.readUInt16BE(offset + 8);
      const dataStart = offset + 10;
      offset = dataStart + dataLength;
      if (offset > packet.length) throw new Error("DNS server returned truncated record data.");
      if (recordClass !== 1) continue;
      records.push({
        name: decodedName.name,
        type: typeCode,
        typeName: dnsTypeNames[typeCode] || `TYPE${typeCode}`,
        TTL: ttl,
        data: decodeDnsRecordData(packet, typeCode, dataStart, dataLength),
      });
    }
    sections.push(records);
  }
  return {
    status: flags & 0x000f,
    authoritative: Boolean(flags & 0x0400),
    recursionAvailable: Boolean(flags & 0x0080),
    truncated: Boolean(flags & 0x0200),
    authenticated: Boolean(flags & 0x0020),
    answers: sections[0],
    authority: sections[1],
    additional: sections[2],
  };
}

function sendDnsUdp(nameserver, query) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(nameserver.family === 6 ? "udp6" : "udp4");
    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("The selected nameserver did not respond before timeout."));
    }, 5000);
    socket.once("error", (error) => {
      clearTimeout(timeout);
      socket.close();
      reject(error);
    });
    socket.on("message", (message) => {
      clearTimeout(timeout);
      socket.close();
      resolve(message);
    });
    socket.send(query, nameserver.port, nameserver.address, (error) => {
      if (error) {
        clearTimeout(timeout);
        socket.close();
        reject(error);
      }
    });
  });
}

function sendDnsTcp(nameserver, query) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: nameserver.address,
      port: nameserver.port,
      family: nameserver.family,
    });
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("The selected nameserver TCP query timed out."));
    }, 5000);
    let response = Buffer.alloc(0);
    let expectedLength = null;
    socket.once("connect", () => {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(query.length);
      socket.write(Buffer.concat([length, query]));
    });
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (expectedLength === null && response.length >= 2) {
        expectedLength = response.readUInt16BE(0);
      }
      if (expectedLength !== null && response.length >= expectedLength + 2) {
        clearTimeout(timeout);
        socket.end();
        resolve(response.subarray(2, expectedLength + 2));
      }
    });
    socket.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    socket.once("end", () => {
      clearTimeout(timeout);
      if (expectedLength === null || response.length < expectedLength + 2) {
        reject(new Error("Nameserver closed the TCP connection before completing its response."));
      }
    });
  });
}

async function directDnsLookup(name, type, nameserver) {
  const typeCode = dnsQuestionType(type);
  const query = encodeDnsQuery(name, typeCode);
  let packet = await sendDnsUdp(nameserver, query);
  if (packet.length < 12 || packet.readUInt16BE(0) !== query.readUInt16BE(0)) {
    throw new Error("The selected nameserver returned an invalid response.");
  }
  if (packet.readUInt16BE(2) & 0x0200) packet = await sendDnsTcp(nameserver, query);
  const result = parseDnsPacket(packet);
  return {
    name,
    type: dnsTypeNames[typeCode] || `TYPE${typeCode}`,
    status: result.status,
    statusText: dnsStatusNames[result.status] || `DNS status ${result.status}`,
    answers: result.answers,
    authority: result.authority,
    additional: result.additional,
  };
}


// ---------------------------------------------------------------- DNS health check

// One query sent straight to a nameserver address (not through the DoH resolver).
async function queryNameserverAt(address, name, type, { recursion = false, tcp = false } = {}) {
  const typeCode = typeof type === "number" ? type : dnsTypeCodes[type];
  const query = encodeDnsQuery(name, typeCode, { recursion });
  const nameserver = { address, family: isIP(address), port: 53 };
  const started = performance.now();
  let packet = tcp ? await sendDnsTcp(nameserver, query) : await sendDnsUdp(nameserver, query);
  if (packet.length < 12 || packet.readUInt16BE(0) !== query.readUInt16BE(0)) throw new Error("Invalid response.");
  if (!tcp && packet.readUInt16BE(2) & 0x0200) packet = await sendDnsTcp(nameserver, query);
  return { ...parseDnsPacket(packet), timeMs: Math.round(performance.now() - started) };
}

async function dohAnswers(name, type) {
  const code = dnsTypeCodes[type];
  return queryDohDns(name, type).then(
    (data) => ({ status: data.status, values: data.answers.filter((answer) => answer.type === code || answer.typeName === type).map((answer) => String(answer.data).replace(/\.$/, "").toLowerCase()) }),
    () => ({ status: null, values: [] }),
  );
}

function parseSoa(data) {
  const [mname, rname, serial, refresh, retry, expire, minimum] = String(data || "").split(/\s+/);
  return mname ? { mname: mname.replace(/\.$/, ""), rname: rname?.replace(/\.$/, ""), serial: Number(serial), refresh: Number(refresh), retry: Number(retry), expire: Number(expire), minimum: Number(minimum) } : null;
}

async function findZoneApex(name) {
  let candidate = name;
  for (let step = 0; step < 5 && candidate.includes("."); step += 1) {
    const soa = await dohAnswers(candidate, "SOA");
    if (soa.values.length) return { zone: candidate, soa: parseSoa(soa.values[0]) };
    if (soa.status === 3 && step === 0) return { zone: null, soa: null, nxdomain: true };
    candidate = candidate.slice(candidate.indexOf(".") + 1);
  }
  return { zone: null, soa: null };
}

// Asks a server of the parent zone which nameservers (and glue) it delegates the zone to.
async function parentDelegation(zone) {
  const parent = zone.slice(zone.indexOf(".") + 1);
  const parentNs = (await dohAnswers(parent || ".", "NS")).values.slice(0, 3);
  for (const host of parentNs) {
    const address = (await dohAnswers(host, "A")).values.find((value) => isPublicAddress(value));
    if (!address) continue;
    try {
      const reply = await queryNameserverAt(address, zone, "NS");
      const records = [...reply.answers, ...reply.authority].filter((record) => record.typeName === "NS" && record.name.replace(/\.$/, "").toLowerCase() === zone);
      if (!records.length) continue;
      const glue = {};
      for (const record of reply.additional.filter((entry) => ["A", "AAAA"].includes(entry.typeName))) {
        const host = record.name.replace(/\.$/, "").toLowerCase();
        (glue[host] ||= []).push(String(record.data));
      }
      return { server: host, nameservers: [...new Set(records.map((record) => String(record.data).replace(/\.$/, "").toLowerCase()))].sort(), glue };
    } catch {
      // Try the next parent server.
    }
  }
  return null;
}

const dnsHealthLimits = { nameservers: 8 };

async function runDnsHealth(input) {
  const domain = normalizeDomain(hostFromInput(input));
  if (!domain) throw Object.assign(new Error("Enter a valid domain name."), { statusCode: 400 });
  const started = Date.now();
  const apex = await findZoneApex(domain);
  if (!apex.zone) {
    return { domain, error: apex.nxdomain ? "The domain does not exist (NXDOMAIN)." : "No DNS zone (SOA record) was found for this name.", checks: [], nameservers: [] };
  }
  const zone = apex.zone;
  const [childNs, delegation] = await Promise.all([dohAnswers(zone, "NS"), parentDelegation(zone).catch(() => null)]);
  const hosts = [...new Set([...(delegation?.nameservers || []), ...childNs.values])].slice(0, dnsHealthLimits.nameservers);
  const recursionProbe = "www.wikipedia.org";
  const nameservers = await Promise.all(hosts.map(async (host) => {
    const [v4, v6] = await Promise.all([dohAnswers(host, "A"), dohAnswers(host, "AAAA")]);
    const addresses = [...v4.values, ...v6.values];
    const entry = { host, addresses, ipv6: v6.values.length > 0, inParent: delegation ? delegation.nameservers.includes(host) : null, inZone: childNs.values.includes(host), results: [] };
    const targets = addresses.filter((address) => isPublicAddress(address)).sort((left, right) => isIP(left) - isIP(right)).slice(0, 2);
    if (!addresses.length) entry.error = "The name server's host name does not resolve.";
    else if (!targets.length) entry.error = "The name server only has private or reserved addresses.";
    for (const address of targets) {
      const result = { address };
      try {
        const soa = await queryNameserverAt(address, zone, "SOA");
        result.timeMs = soa.timeMs;
        result.rcode = dnsStatusNames[soa.status] || String(soa.status);
        result.authoritative = soa.authoritative && soa.status === 0;
        result.serial = parseSoa(soa.answers.find((record) => record.typeName === "SOA")?.data)?.serial ?? null;
        const ns = await queryNameserverAt(address, zone, "NS").catch(() => null);
        result.nameservers = ns ? [...new Set(ns.answers.filter((record) => record.typeName === "NS").map((record) => String(record.data).replace(/\.$/, "").toLowerCase()))].sort() : null;
        result.tcp = await queryNameserverAt(address, zone, "SOA", { tcp: true }).then((reply) => reply.status === 0, () => false);
        const probe = await queryNameserverAt(address, recursionProbe, "A", { recursion: true }).catch(() => null);
        result.openRecursion = Boolean(probe && probe.recursionAvailable && probe.status === 0 && probe.answers.length);
        const axfr = await queryNameserverAt(address, zone, 252, { tcp: true }).catch(() => null);
        result.zoneTransfer = Boolean(axfr && axfr.status === 0 && axfr.answers.some((record) => record.typeName === "SOA") && axfr.answers.length > 1);
      } catch (error) {
        result.error = error.message?.includes("timeout") || error.message?.includes("respond") ? "No answer (timed out)." : `No answer (${String(error.code || error.message).slice(0, 60)}).`;
      }
      entry.results.push(result);
    }
    return entry;
  }));

  const checks = [];
  const add = (id, label, state, message, detail = null) => checks.push({ id, label, state, message, detail });
  const responding = nameservers.flatMap((entry) => entry.results).filter((result) => !result.error);
  const serials = [...new Set(responding.filter((result) => result.authoritative).map((result) => result.serial).filter((serial) => serial !== null))];
  add("ns-count", "Number of name servers", hosts.length >= 2 ? "pass" : "fail",
    hosts.length >= 2 ? `${hosts.length} name servers.` : "Fewer than two name servers; one outage takes the domain offline.", hosts.join(", "));
  if (delegation) {
    const missingInZone = delegation.nameservers.filter((host) => !childNs.values.includes(host));
    const missingInParent = childNs.values.filter((host) => !delegation.nameservers.includes(host));
    add("delegation", "Parent and zone agree", missingInZone.length || missingInParent.length ? "warn" : "pass",
      missingInZone.length || missingInParent.length
        ? [missingInZone.length ? `Delegated by the parent but not listed in the zone: ${missingInZone.join(", ")}.` : null, missingInParent.length ? `Listed in the zone but not delegated by the parent: ${missingInParent.join(", ")}.` : null].filter(Boolean).join(" ")
        : "The parent zone and the zone itself list the same name servers.", `Parent server: ${delegation.server}`);
    const inBailiwick = delegation.nameservers.filter((host) => host === zone || host.endsWith(`.${zone}`));
    const missingGlue = inBailiwick.filter((host) => !delegation.glue[host]?.length);
    if (inBailiwick.length) add("glue", "Glue records", missingGlue.length ? "fail" : "pass", missingGlue.length ? `No glue for ${missingGlue.join(", ")}; resolvers cannot reach these servers.` : "Glue is present for name servers inside the zone.");
  } else {
    add("delegation", "Parent and zone agree", "info", "The parent zone's delegation could not be read.");
  }
  const lame = nameservers.filter((entry) => entry.error || (entry.results.length && entry.results.every((result) => result.error || !result.authoritative)));
  add("lame", "All name servers answer authoritatively", lame.length ? "fail" : "pass",
    lame.length ? `Not answering authoritatively: ${lame.map((entry) => entry.host).join(", ")} (lame delegation).` : "Every name server answers for the zone.");
  add("serial", "SOA serials match", serials.length > 1 ? "warn" : serials.length ? "pass" : "info",
    serials.length > 1 ? `Name servers report different serials (${serials.join(", ")}); a secondary may not be updating.` : serials.length ? `All servers report serial ${serials[0]}.` : "No serial could be read.");
  const openRecursion = responding.filter((result) => result.openRecursion).map((result) => result.address);
  add("recursion", "No open recursion", openRecursion.length ? "fail" : "pass",
    openRecursion.length ? `Answers recursive queries for anyone: ${openRecursion.join(", ")}. Open resolvers are abused for DDoS amplification.` : "Name servers do not resolve other domains for strangers.");
  const transfers = responding.filter((result) => result.zoneTransfer).map((result) => result.address);
  add("axfr", "Zone transfer (AXFR) refused", transfers.length ? "fail" : "pass",
    transfers.length ? `Anyone can download the whole zone from ${transfers.join(", ")}.` : "Zone transfers are refused to the public.");
  const noTcp = responding.filter((result) => result.tcp === false).map((result) => result.address);
  add("tcp", "DNS over TCP", noTcp.length ? "warn" : "pass", noTcp.length ? `No answer over TCP from ${noTcp.join(", ")}; large answers (DNSSEC, many records) will fail.` : "All servers answer over TCP.");
  const prefixes = new Set(nameservers.flatMap((entry) => entry.addresses.filter((address) => isIP(address) === 4).map((address) => address.split(".").slice(0, 3).join("."))));
  if (hosts.length >= 2) add("diversity", "Network diversity", prefixes.size >= 2 ? "pass" : "warn", prefixes.size >= 2 ? `Name servers are in ${prefixes.size} different /24 networks.` : "All IPv4 name server addresses are in one /24 network; one network problem can take them all down.");
  add("ipv6", "IPv6 name servers", nameservers.some((entry) => entry.ipv6) ? "pass" : "info", nameservers.some((entry) => entry.ipv6) ? "At least one name server has an IPv6 address." : "No name server has an IPv6 address.");
  const soa = apex.soa;
  if (soa) {
    const soaNotes = [];
    if (soa.refresh < 1200 || soa.refresh > 86400) soaNotes.push(`refresh ${soa.refresh}s (1200–86400 recommended)`);
    if (soa.retry >= soa.refresh) soaNotes.push(`retry ${soa.retry}s should be lower than refresh`);
    if (soa.expire < 604800 || soa.expire > 2419200) soaNotes.push(`expire ${soa.expire}s (1–4 weeks recommended)`);
    if (soa.minimum > 86400) soaNotes.push(`negative-cache TTL ${soa.minimum}s is long (≤ 1 day recommended)`);
    add("soa", "SOA timers", soaNotes.length ? "warn" : "pass", soaNotes.length ? `Unusual values: ${soaNotes.join("; ")}.` : "SOA timers are within the usual ranges.",
      `primary ${soa.mname} · contact ${soa.rname} · serial ${soa.serial}`);
  }
  const severity = { fail: "high", warn: "medium" };
  return {
    domain,
    zone,
    soa,
    parent: delegation,
    nameservers,
    checks,
    issues: checks.filter((check) => severity[check.state]).map((check) => ({ severity: severity[check.state], message: `${check.label}: ${check.message}` })),
    durationMs: Date.now() - started,
  };
}

async function dnsHealthCheck(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  if (!acquireHeavyJob("dnsHealth")) {
    sendJson(response, 503, { error: "The server is busy with other DNS health checks. Try again shortly." });
    return;
  }
  try {
    const result = await runDnsHealth(rawName);
    if (result.zone) {
      const failed = result.checks.filter((check) => check.state === "fail").length;
      const warned = result.checks.filter((check) => check.state === "warn").length;
      const score = Math.max(0, 100 - failed * 20 - warned * 7);
      recordDomainRating("dns", result.zone, gradeForScore(score), score, failed + warned ? result.checks.filter((check) => ["fail", "warn"].includes(check.state)).map((check) => check.label).join(", ") : "No problems found");
    }
    sendJson(response, 200, result);
  } catch (error) {
    if (error.statusCode) sendJson(response, error.statusCode, { error: error.message });
    else {
      console.error("DNS health check failed:", error);
      sendJson(response, 500, { error: "Unable to complete the DNS health check." });
    }
  } finally {
    releaseHeavyJob("dnsHealth");
  }
}

function queryDohOverHttp2(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const client = http2.connect(url.origin);
    let settled = false;
    let status;
    const chunks = [];
    const timeout = setTimeout(() => finish(new Error("DNS lookup timed out. Please try again.")), timeoutMs);

    function finish(error, packet) {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) {
        client.destroy();
        reject(error);
      } else {
        client.close();
        resolve({ status, packet: Buffer.concat(chunks) });
      }
    }

    client.once("error", (error) => finish(error));
    const request = client.request({
      ":method": "GET",
      ":path": `${url.pathname}${url.search}`,
      accept: "application/dns-message",
    });
    request.once("response", (headers) => { status = headers[":status"]; });
    request.on("data", (chunk) => chunks.push(chunk));
    request.once("end", () => {
      if (status < 200 || status >= 300) {
        finish(new Error(`DNS provider returned HTTP ${status}.`));
        return;
      }
      finish(null);
    });
    request.once("error", (error) => finish(error));
    request.end();
  });
}

async function queryDohDns(name, type, { dnssec = false, checkingDisabled = false, resolver = getDnsResolver() } = {}) {
  if (resolver.format === "json") {
    const queryUrl = new URL(resolver.endpoint);
    queryUrl.searchParams.set("name", name);
    queryUrl.searchParams.set("type", type);
    if (dnssec) queryUrl.searchParams.set("do", "1");
    if (checkingDisabled) queryUrl.searchParams.set("cd", "1");
    const response = await fetch(queryUrl, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`DNS provider returned HTTP ${response.status}.`);
    const data = await response.json();
    if (typeof data.Status !== "number" || !Array.isArray(data.Answer || []) ||
      !Array.isArray(data.Authority || []) || !Array.isArray(data.Additional || [])) {
      throw new Error("DNS provider returned an invalid response.");
    }
    return {
      name,
      type,
      status: data.Status,
      statusText: dnsStatusNames[data.Status] || `DNS status ${data.Status}`,
      authenticated: data.AD === true,
      answers: data.Answer || [],
      authority: data.Authority || [],
      additional: data.Additional || [],
    };
  }

  const query = encodeDnsQuery(name, dnsQuestionType(type), { dnssec, checkingDisabled });
  const queryUrl = new URL(resolver.endpoint);
  queryUrl.searchParams.set("dns", query.toString("base64url"));
  let packet;
  if (["quad9", "dns4eu"].includes(resolver.id)) {
    packet = (await queryDohOverHttp2(queryUrl, 8000)).packet;
  } else {
    const response = await fetch(queryUrl, {
      headers: { accept: "application/dns-message" },
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) throw new Error(`DNS provider returned HTTP ${response.status}.`);
    packet = Buffer.from(await response.arrayBuffer());
  }
  if (packet.length < 12 || packet.readUInt16BE(0) !== query.readUInt16BE(0) ||
    !(packet.readUInt16BE(2) & 0x8000)) {
    throw new Error("DNS provider returned an invalid response.");
  }
  const result = parseDnsPacket(packet);
  if (result.truncated) throw new Error("DNS provider returned a truncated response.");
  return {
    name,
    type,
    status: result.status,
    statusText: dnsStatusNames[result.status] || `DNS status ${result.status}`,
    authenticated: result.authenticated,
    answers: result.answers,
    authority: result.authority,
    additional: result.additional,
  };
}

const dnssecAlgorithms = {
  1: { name: "RSA/MD5", status: "prohibited" },
  3: { name: "DSA/SHA-1", status: "prohibited" },
  5: { name: "RSA/SHA-1", status: "deprecated" },
  6: { name: "DSA-NSEC3-SHA1", status: "prohibited" },
  7: { name: "RSASHA1-NSEC3-SHA1", status: "deprecated" },
  8: { name: "RSA/SHA-256", status: "ok" },
  10: { name: "RSA/SHA-512", status: "ok" },
  12: { name: "GOST R 34.10-2001", status: "prohibited" },
  13: { name: "ECDSA P-256/SHA-256", status: "ok" },
  14: { name: "ECDSA P-384/SHA-384", status: "ok" },
  15: { name: "Ed25519", status: "ok" },
  16: { name: "Ed448", status: "ok" },
};
const dnssecDigestTypes = { 1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384" };

function dnskeyTag(flags, protocol, algorithm, publicKey) {
  const rdata = Buffer.concat([Buffer.from([flags >> 8, flags & 255, protocol, algorithm]), publicKey]);
  let accumulator = 0;
  for (let index = 0; index < rdata.length; index += 1) {
    accumulator += index & 1 ? rdata[index] : rdata[index] << 8;
  }
  accumulator += (accumulator >> 16) & 0xffff;
  return accumulator & 0xffff;
}

function dnssecRecordsOfType(data, typeName, owner) {
  const normalize = (value) => String(value || "").toLowerCase().replace(/\.$/, "");
  return (data?.answers || []).filter((answer) =>
    (answer.typeName === typeName || dnsTypeNames[answer.type] === typeName) &&
    normalize(answer.name) === normalize(owner));
}

async function checkDnssec(domain) {
  const resolver = getDnsResolver();
  const settle = (promise) => promise.then((data) => ({ data }), (error) => ({ error }));
  const [dsResult, dnskeyResult, soaResult] = await Promise.all([
    settle(queryDohDns(domain, "DS", { dnssec: true })),
    settle(queryDohDns(domain, "DNSKEY", { dnssec: true })),
    settle(queryDohDns(domain, "SOA", { dnssec: true })),
  ]);
  if (soaResult.error) {
    return {
      domain,
      resolver: resolver.label,
      status: "error",
      summary: soaResult.error.name === "TimeoutError" ? "The DNS provider timed out." : "The DNS provider could not be queried.",
      ds: [],
      dnskeys: [],
      signatures: [],
      issues: [],
    };
  }
  let bogus = false;
  let dsData = dsResult.data;
  let dnskeyData = dnskeyResult.data;
  let soaData = soaResult.data;
  if (soaResult.data.status === 2) {
    const unchecked = await settle(queryDohDns(domain, "SOA", { dnssec: true, checkingDisabled: true }));
    bogus = unchecked.data?.status === 0;
    if (bogus) {
      // Fetch the records without validation so the report can show why validation fails.
      const [uncheckedDs, uncheckedKeys] = await Promise.all([
        settle(queryDohDns(domain, "DS", { dnssec: true, checkingDisabled: true })),
        settle(queryDohDns(domain, "DNSKEY", { dnssec: true, checkingDisabled: true })),
      ]);
      dsData = uncheckedDs.data || dsData;
      dnskeyData = uncheckedKeys.data || dnskeyData;
      soaData = unchecked.data;
    }
  }
  const dnskeys = dnssecRecordsOfType(dnskeyData, "DNSKEY", domain).map((record) => {
    const [flags, protocol, algorithm, ...keyParts] = String(record.data).split(" ");
    const key = Buffer.from(keyParts.join(""), "base64");
    const flagValue = Number(flags);
    return {
      flags: flagValue,
      role: flagValue & 1 ? "KSK" : "ZSK",
      algorithm: Number(algorithm),
      algorithmName: dnssecAlgorithms[algorithm]?.name || `Algorithm ${algorithm}`,
      keyTag: dnskeyTag(flagValue, Number(protocol), Number(algorithm), key),
      keyBytes: key.length,
    };
  });
  const ds = dnssecRecordsOfType(dsData, "DS", domain).map((record) => {
    const [keyTag, algorithm, digestType, ...digest] = String(record.data).split(" ");
    return {
      keyTag: Number(keyTag),
      algorithm: Number(algorithm),
      algorithmName: dnssecAlgorithms[algorithm]?.name || `Algorithm ${algorithm}`,
      digestType: Number(digestType),
      digestTypeName: dnssecDigestTypes[digestType] || `Digest ${digestType}`,
      digest: digest.join("").toUpperCase(),
      matchesKey: dnskeys.some((key) => key.keyTag === Number(keyTag) && key.algorithm === Number(algorithm)),
    };
  });
  const signatures = [...dnssecRecordsOfType(dnskeyData, "RRSIG", domain), ...dnssecRecordsOfType(soaData, "RRSIG", domain)]
    .map((record) => {
      const [typeCovered, algorithm, , , expiration, inception, keyTag, signer] = String(record.data).split(" ");
      const parseStamp = (value) => /^\d{14}$/.test(value || "")
        ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}T${value.slice(8, 10)}:${value.slice(10, 12)}:${value.slice(12, 14)}Z`
        : null;
      return {
        typeCovered,
        algorithm: Number(algorithm),
        algorithmName: dnssecAlgorithms[algorithm]?.name || `Algorithm ${algorithm}`,
        keyTag: Number(keyTag),
        signer: String(signer || "").replace(/\.$/, ""),
        inception: parseStamp(inception),
        expiration: parseStamp(expiration),
      };
    });
  const issues = [];
  const algorithmsInUse = new Set([...ds, ...dnskeys].map((entry) => entry.algorithm));
  for (const algorithm of algorithmsInUse) {
    const info = dnssecAlgorithms[algorithm];
    if (info?.status === "prohibited") issues.push({ severity: "high", message: `Algorithm ${algorithm} (${info.name}) must not be used for DNSSEC signing (RFC 8624).` });
    else if (info?.status === "deprecated") issues.push({ severity: "medium", message: `Algorithm ${algorithm} (${info.name}) is deprecated; move to ECDSA P-256 (13) or Ed25519 (15).` });
  }
  if (ds.some((entry) => entry.digestType === 1)) {
    issues.push({ severity: "low", message: "A DS record uses a SHA-1 digest; publish a SHA-256 (type 2) DS record instead." });
  }
  if (ds.length && dnskeys.length && !ds.some((entry) => entry.matchesKey)) {
    issues.push({ severity: "high", message: "No DS record matches a DNSKEY in the zone; the chain of trust is broken." });
  }
  const now = Date.now();
  for (const signature of signatures) {
    const expires = Date.parse(signature.expiration || "");
    if (Number.isFinite(expires) && expires < now) {
      issues.push({ severity: "high", message: `The RRSIG over ${signature.typeCovered} (key ${signature.keyTag}) expired on ${signature.expiration}.` });
    } else if (Number.isFinite(expires) && expires - now < 7 * 86400_000) {
      issues.push({ severity: "medium", message: `The RRSIG over ${signature.typeCovered} (key ${signature.keyTag}) expires soon (${signature.expiration}).` });
    }
  }
  let status;
  let summary;
  if (bogus) {
    status = "bogus";
    summary = "DNSSEC validation fails: the resolver returns SERVFAIL unless checking is disabled. Resolvers that validate cannot resolve this domain.";
  } else if (soaResult.data.authenticated && ds.length) {
    status = "secure";
    summary = "DNSSEC is enabled and the chain of trust validates.";
  } else if (soaResult.data.authenticated) {
    status = "secure";
    summary = "Answers for this name are DNSSEC-validated (signed via a parent zone).";
  } else if (!ds.length && dnskeys.length) {
    status = "insecure";
    summary = "The zone is signed, but the parent zone has no DS record, so the chain of trust is not established.";
  } else if (!ds.length) {
    status = "unsigned";
    summary = "DNSSEC is not enabled for this domain.";
  } else {
    status = "indeterminate";
    summary = "A DS record exists, but the resolver did not mark the answer as validated.";
  }
  return {
    domain,
    resolver: resolver.label,
    status,
    summary,
    authenticated: soaResult.data.authenticated,
    ds,
    dnskeys,
    signatures,
    issues,
  };
}

function txtRecordText(data) {
  const chunks = [...String(data || "").matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((match) => {
    try {
      return JSON.parse(`"${match[1]}"`);
    } catch {
      return match[1];
    }
  });
  return chunks.length ? chunks.join("") : String(data || "");
}

async function queryTxtRecords(name) {
  const data = await queryDohDns(name, "TXT");
  return {
    status: data.status,
    records: data.answers
      .filter((answer) => answer.type === 16 || answer.typeName === "TXT")
      .map((answer) => txtRecordText(answer.data)),
  };
}

function parseTagList(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const key = part.slice(0, index).trim().toLowerCase();
    if (key && !(key in tags)) tags[key] = part.slice(index + 1).trim();
  }
  return tags;
}

async function analyzeDmarc(domain) {
  const { records } = await queryTxtRecords(`_dmarc.${domain}`);
  const dmarc = records.filter((record) => /^v\s*=\s*DMARC1\b/i.test(record.trim()));
  const issues = [];
  if (!dmarc.length) {
    issues.push({ severity: "high", message: "No DMARC record at _dmarc. Receivers get no policy for mail that fails SPF and DKIM, and you get no reports." });
    return { found: false, record: null, tags: {}, issues };
  }
  if (dmarc.length > 1) issues.push({ severity: "high", message: "More than one DMARC record is published; receivers will ignore DMARC entirely." });
  const tags = parseTagList(dmarc[0]);
  const policy = (tags.p || "").toLowerCase();
  if (!["none", "quarantine", "reject"].includes(policy)) {
    issues.push({ severity: "high", message: "The DMARC record has no valid p= policy (none, quarantine or reject)." });
  } else if (policy === "none") {
    issues.push({ severity: "medium", message: "Policy p=none only monitors; spoofed mail is still delivered. Move to quarantine or reject once reports look clean." });
  }
  const subdomainPolicy = (tags.sp || "").toLowerCase();
  if (subdomainPolicy === "none" && policy && policy !== "none") {
    issues.push({ severity: "low", message: "Subdomains use sp=none, so they can be spoofed even though the domain itself is protected." });
  }
  if (tags.pct && Number(tags.pct) < 100) {
    issues.push({ severity: "low", message: `The policy only applies to ${tags.pct}% of failing mail (pct=${tags.pct}).` });
  }
  if (!tags.rua) issues.push({ severity: "low", message: "No rua= address, so you receive no aggregate reports about who sends mail as your domain." });
  return { found: true, record: dmarc[0], tags, policy: policy || null, issues };
}

function fetchPinnedHttps(hostname, address, requestPath, { timeoutMs = 6000, maxBytes = 65536, port = 443 } = {}) {
  return new Promise((resolve, reject) => {
    const request = https.get({
      host: hostname,
      port,
      servername: hostname,
      path: requestPath,
      headers: { "user-agent": "BNGlookup-mail-check" },
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address, family: isIP(address) }]);
        else callback(null, address, isIP(address));
      },
      timeout: timeoutMs,
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
        if (body.length > maxBytes) request.destroy(new Error("The response is too large."));
      });
      response.on("end", () => resolve({ status: response.statusCode, contentType: String(response.headers["content-type"] || ""), body }));
    });
    request.on("timeout", () => request.destroy(Object.assign(new Error("The request timed out."), { name: "TimeoutError" })));
    request.on("error", reject);
  });
}

// Latest result per domain and check type, for the admin dashboard's best/worst lists.
const ratingKinds = { web: "Web security headers", tls: "TLS grade", email: "Email security", dns: "DNS health", takeover: "Subdomain takeover risk" };
const ratingRetentionMs = 180 * 86400000;
const tlsGradeScores = { "A+": 100, A: 95, "A-": 90, B: 80, C: 70, D: 60, E: 50, F: 35, T: 25, M: 25 };

function gradeForScore(score) {
  return score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";
}

function recordDomainRating(kind, domain, grade, score, detail = "") {
  if (!domain || !grade || !Number.isFinite(score)) return;
  try {
    database.prepare(`
      INSERT INTO domain_ratings (domain, kind, grade, score, detail, checked_at) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(domain, kind) DO UPDATE SET grade = excluded.grade, score = excluded.score, detail = excluded.detail, checked_at = excluded.checked_at
    `).run(String(domain).toLowerCase().slice(0, 253), kind, String(grade).slice(0, 8), Math.round(score), String(detail).slice(0, 300), Date.now());
  } catch (error) {
    console.error("Could not record rating:", error.message);
  }
}

const webCheckLimits = { redirects: 10, bodyBytes: 262144, timeoutMs: 10000 };
const webUserAgent = "Mozilla/5.0 (compatible; BNGlookup web check)";

// Resolves a host to an address this user may connect to, so redirects cannot reach private networks.
async function resolveWebAddress(hostname, allowLocal) {
  const host = hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) return isScannableAddress(host, allowLocal) ? host : null;
  for (const type of ["A", "AAAA"]) {
    const answers = await queryDohDns(host, type).then((data) => data.answers, () => []);
    const address = answers
      .filter((answer) => answer.type === (type === "A" ? 1 : 28) || answer.typeName === type)
      .map((answer) => answer.data)
      .find((value) => isScannableAddress(value, allowLocal));
    if (address) return address;
  }
  return null;
}

function decodeBody(body, encoding) {
  const options = { maxOutputLength: 1048576, finishFlush: zlib.constants.Z_SYNC_FLUSH };
  try {
    if (/\bbr\b/i.test(encoding)) return zlib.brotliDecompressSync(body, { maxOutputLength: 1048576, finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH }).toString("utf8");
    if (/gzip/i.test(encoding)) return zlib.gunzipSync(body, options).toString("utf8");
    if (/deflate/i.test(encoding)) return zlib.inflateSync(body, options).toString("utf8");
  } catch {
    return "";
  }
  return body.toString("utf8");
}

// One HTTP(S) request pinned to an already checked address. Redirects are not followed here.
function requestPinnedUrl(target, address, { timeoutMs = webCheckLimits.timeoutMs, maxBytes = webCheckLimits.bodyBytes } = {}) {
  return new Promise((resolve, reject) => {
    const secure = target.protocol === "https:";
    const hostname = target.hostname.replace(/^\[|\]$/g, "");
    const started = performance.now();
    const request = (secure ? https : http).request({
      method: "GET",
      host: hostname,
      port: Number(target.port) || (secure ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      headers: { "user-agent": webUserAgent, accept: "text/html,application/xhtml+xml,*/*;q=0.8", "accept-encoding": "gzip, deflate, br" },
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address, family: isIP(address) }]);
        else callback(null, address, isIP(address));
      },
      timeout: timeoutMs,
      agent: false,
      ...(secure ? { servername: isIP(hostname) ? undefined : hostname, rejectUnauthorized: false } : {}),
    }, (response) => {
      const firstByteMs = Math.round(performance.now() - started);
      let tlsInfo = null;
      if (secure && response.socket?.getPeerCertificate) {
        const certificate = response.socket.getPeerCertificate();
        const validTo = certificate?.valid_to ? new Date(certificate.valid_to) : null;
        tlsInfo = {
          protocol: response.socket.getProtocol?.() || null,
          authorized: response.socket.authorized,
          authorizationError: response.socket.authorized ? null : String(response.socket.authorizationError || "Certificate is not trusted."),
          validTo: validTo && !Number.isNaN(validTo.getTime()) ? validTo.toISOString() : null,
          daysRemaining: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null,
        };
      }
      const chunks = [];
      let size = 0;
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        const raw = Buffer.concat(chunks);
        resolve({
          status: response.statusCode,
          headers: response.headers,
          body: raw,
          bytes: size,
          truncated: size > maxBytes,
          firstByteMs,
          totalMs: Math.round(performance.now() - started),
          tls: tlsInfo,
        });
      };
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size <= maxBytes) chunks.push(chunk);
        else response.destroy();
      });
      response.once("end", finish);
      response.once("close", finish);
      response.once("error", finish);
    });
    request.on("timeout", () => request.destroy(Object.assign(new Error("The request timed out."), { name: "TimeoutError" })));
    request.on("error", reject);
    // The socket timeout only covers idle time; this caps slow, trickling responses too.
    const deadline = setTimeout(() => request.destroy(Object.assign(new Error("The request timed out."), { name: "TimeoutError" })), timeoutMs * 2);
    request.on("close", () => clearTimeout(deadline));
    request.end();
  });
}

function describeWebError(error) {
  if (error.name === "TimeoutError") return "The request timed out.";
  const messages = {
    ECONNREFUSED: "The connection was refused.",
    ECONNRESET: "The connection was reset.",
    EHOSTUNREACH: "The host is unreachable.",
    ENETUNREACH: "The network is unreachable.",
    EPROTO: "The TLS handshake failed.",
    ERR_SSL_WRONG_VERSION_NUMBER: "The server does not speak TLS on this port.",
  };
  return messages[error.code] || `The request failed (${String(error.code || error.message).slice(0, 80)}).`;
}

// Follows redirects one hop at a time, re-checking every new host before connecting to it.
async function followWebRedirects(startUrl, allowLocal, options = {}) {
  const hops = [];
  let current = startUrl;
  let final = null;
  for (let count = 0; count <= webCheckLimits.redirects; count += 1) {
    const address = await resolveWebAddress(current.hostname, allowLocal);
    if (!address) {
      hops.push({ url: current.href, error: `${current.hostname} does not resolve to an address that can be checked.` });
      break;
    }
    let response;
    try {
      response = await requestPinnedUrl(current, address, options);
    } catch (error) {
      hops.push({ url: current.href, address, error: describeWebError(error) });
      break;
    }
    const location = response.headers.location;
    const hop = { url: current.href, address, status: response.status, timeMs: response.totalMs, location: location || null };
    hops.push(hop);
    final = { url: current, response };
    if (response.status >= 300 && response.status < 400 && location) {
      let next;
      try {
        next = new URL(location, current);
      } catch {
        hop.error = "The redirect location is not a valid URL.";
        break;
      }
      if (!["http:", "https:"].includes(next.protocol) || next.username || next.password) {
        hop.error = "The redirect points to an unsupported URL.";
        break;
      }
      if (count === webCheckLimits.redirects) {
        hop.error = `Stopped after ${webCheckLimits.redirects} redirects.`;
        break;
      }
      current = next;
      continue;
    }
    break;
  }
  return { hops, final };
}

function checkHttp2(hostname, address, port) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: isIP(hostname) ? undefined : hostname,
      ALPNProtocols: ["h2", "http/1.1"],
      rejectUnauthorized: false,
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address, family: isIP(address) }]);
        else callback(null, address, isIP(address));
      },
    });
    const finish = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(6000, () => finish(null));
    socket.once("secureConnect", () => finish(socket.alpnProtocol === "h2"));
    socket.once("error", () => finish(null));
  });
}

function parseSetCookies(values = []) {
  return (Array.isArray(values) ? values : [values]).slice(0, 30).map((cookie) => {
    const [pair, ...attributes] = String(cookie).split(";").map((part) => part.trim());
    const flags = attributes.map((attribute) => attribute.toLowerCase());
    const sameSite = flags.find((flag) => flag.startsWith("samesite="))?.slice(9) || null;
    return {
      name: pair.split("=")[0].slice(0, 100),
      secure: flags.includes("secure"),
      httpOnly: flags.includes("httponly"),
      sameSite,
    };
  });
}

function webCheckChecks(headers, secure, cookies) {
  const checks = [];
  const add = (id, label, state, value, message, weight = 0) => checks.push({ id, label, state, value: value ? String(value).slice(0, 600) : null, message, weight });
  const hsts = headers["strict-transport-security"];
  if (!secure) add("hsts", "HSTS", "fail", null, "The final page is not served over HTTPS.", 25);
  else if (!hsts) add("hsts", "HSTS", "fail", null, "No Strict-Transport-Security header, so browsers may still try plain HTTP first.", 15);
  else {
    const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] || 0);
    const parts = [`max-age ${maxAge}`, /includesubdomains/i.test(hsts) ? "includeSubDomains" : null, /preload/i.test(hsts) ? "preload" : null].filter(Boolean).join(" · ");
    if (maxAge < 15552000) add("hsts", "HSTS", "warn", hsts, `max-age is ${Math.round(maxAge / 86400)} days; at least 180 days is recommended.`, 6);
    else add("hsts", "HSTS", "pass", hsts, parts);
  }
  const csp = headers["content-security-policy"];
  if (!csp) {
    add("csp", "Content-Security-Policy", "fail", headers["content-security-policy-report-only"] || null,
      headers["content-security-policy-report-only"] ? "Only a report-only policy is set; it does not block anything." : "No Content-Security-Policy, so injected scripts are not restricted.", 12);
  } else {
    const scriptPolicy = csp.match(/script-src[^;]*/i)?.[0] || csp.match(/default-src[^;]*/i)?.[0] || "";
    const weak = [/'unsafe-inline'/i.test(scriptPolicy) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/i.test(scriptPolicy) ? "'unsafe-inline'" : null, /'unsafe-eval'/i.test(scriptPolicy) ? "'unsafe-eval'" : null].filter(Boolean);
    if (!scriptPolicy) add("csp", "Content-Security-Policy", "warn", csp, "The policy has no script-src or default-src, so scripts are not restricted.", 6);
    else if (weak.length) add("csp", "Content-Security-Policy", "warn", csp, `Scripts allow ${weak.join(" and ")}, which weakens protection against injected scripts.`, 5);
    else add("csp", "Content-Security-Policy", "pass", csp, "Scripts are restricted.");
  }
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  const xfo = headers["x-frame-options"];
  if (frameAncestors || /^(deny|sameorigin)$/i.test(String(xfo || "").trim())) add("framing", "Clickjacking protection", "pass", frameAncestors ? csp.match(/frame-ancestors[^;]*/i)[0] : xfo, "Other sites cannot frame this page.");
  else add("framing", "Clickjacking protection", "fail", xfo || null, "No X-Frame-Options or CSP frame-ancestors, so other sites can embed this page in a frame.", 8);
  const nosniff = headers["x-content-type-options"];
  if (/nosniff/i.test(nosniff || "")) add("nosniff", "X-Content-Type-Options", "pass", nosniff, "Browsers will not guess content types.");
  else add("nosniff", "X-Content-Type-Options", "fail", nosniff || null, "Missing nosniff; browsers may interpret files as a different type.", 5);
  const referrer = headers["referrer-policy"];
  if (!referrer) add("referrer", "Referrer-Policy", "warn", null, "No Referrer-Policy; browsers default to strict-origin-when-cross-origin.", 2);
  else if (/unsafe-url|no-referrer-when-downgrade/i.test(referrer)) add("referrer", "Referrer-Policy", "warn", referrer, "This policy sends full URLs to other sites.", 3);
  else add("referrer", "Referrer-Policy", "pass", referrer, "Limits what other sites learn from links.");
  const permissions = headers["permissions-policy"];
  add("permissions", "Permissions-Policy", permissions ? "pass" : "info", permissions || null, permissions ? "Restricts browser features such as camera and location." : "No Permissions-Policy; optional, but it can switch off browser features the site does not use.");
  const leaks = [["server", headers.server], ["x-powered-by", headers["x-powered-by"]], ["x-aspnet-version", headers["x-aspnet-version"]]]
    .filter(([, value]) => value && /\d/.test(value));
  if (leaks.length) add("disclosure", "Software versions", "warn", leaks.map(([name, value]) => `${name}: ${value}`).join(" · "), "Headers reveal software versions, which helps attackers pick exploits.", 2);
  else add("disclosure", "Software versions", "pass", headers.server || null, "No software version numbers in the headers.");
  if (cookies.length) {
    const insecure = cookies.filter((cookie) => secure && !cookie.secure).map((cookie) => cookie.name);
    const scriptReadable = cookies.filter((cookie) => !cookie.httpOnly).map((cookie) => cookie.name);
    const noSameSite = cookies.filter((cookie) => !cookie.sameSite).map((cookie) => cookie.name);
    if (insecure.length) add("cookies", "Cookies", "fail", insecure.join(", "), `${insecure.length} cookie(s) lack the Secure flag and can leak over plain HTTP.`, 8);
    else if (noSameSite.length || scriptReadable.length) add("cookies", "Cookies", "warn", [...new Set([...noSameSite, ...scriptReadable])].join(", "), [noSameSite.length ? `${noSameSite.length} without SameSite` : null, scriptReadable.length ? `${scriptReadable.length} readable by scripts (no HttpOnly; fine for non-session cookies)` : null].filter(Boolean).join("; ") + ".", 2);
    else add("cookies", "Cookies", "pass", cookies.map((cookie) => cookie.name).join(", "), "All cookies are Secure, HttpOnly and SameSite.");
  }
  const score = Math.max(0, 100 - checks.reduce((total, check) => total + check.weight, 0));
  const grade = score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";
  return { checks: checks.map(({ weight, ...check }) => check), score, grade };
}

// security.txt, robots.txt, the sitemap and mixed content on the final page.
async function webCheckExtras(finalUrl, address, html, secure) {
  const origin = `${finalUrl.protocol}//${finalUrl.host}`;
  const fetchText = async (path) => {
    try {
      const page = await requestPinnedUrl(new URL(path, origin), address, { timeoutMs: 6000, maxBytes: 65536 });
      return { status: page.status, type: String(page.headers["content-type"] || ""), text: decodeBody(page.body, String(page.headers["content-encoding"] || "")) };
    } catch {
      return null;
    }
  };
  const [securityPage, robotsPage] = address ? await Promise.all([fetchText("/.well-known/security.txt"), fetchText("/robots.txt")]) : [null, null];
  const securityTxt = { found: false, issues: [] };
  if (securityPage?.status === 200 && /^text\/plain/i.test(securityPage.type) && /^\s*(contact|expires)\s*:/im.test(securityPage.text)) {
    const field = (name) => [...securityPage.text.matchAll(new RegExp(`^\\s*${name}\\s*:\\s*(.+)$`, "gim"))].map((match) => match[1].trim());
    const expires = field("expires")[0] || null;
    Object.assign(securityTxt, { found: true, contact: field("contact").slice(0, 5), expires, policy: field("policy")[0] || null, signed: /BEGIN PGP SIGNED MESSAGE/.test(securityPage.text) });
    if (!securityTxt.contact.length) securityTxt.issues.push({ severity: "low", message: "security.txt has no Contact field." });
    if (!expires) securityTxt.issues.push({ severity: "low", message: "security.txt has no Expires field (required by RFC 9116)." });
    else if (Date.parse(expires) < Date.now()) securityTxt.issues.push({ severity: "low", message: `security.txt expired on ${expires.slice(0, 10)}.` });
  } else if (secure) {
    securityTxt.issues.push({ severity: "low", message: "No /.well-known/security.txt, so security researchers have no published contact." });
  }
  const robots = { found: false };
  if (robotsPage?.status === 200 && !/<html/i.test(robotsPage.text.slice(0, 500))) {
    const sitemaps = [...robotsPage.text.matchAll(/^\s*sitemap\s*:\s*(\S+)/gim)].map((match) => match[1]).slice(0, 5);
    const blocksAll = /user-agent\s*:\s*\*\s*[\r\n]+(?:\s*(?:allow|disallow)\s*:.*[\r\n]+)*?\s*disallow\s*:\s*\/\s*$/im.test(robotsPage.text);
    Object.assign(robots, { found: true, sitemaps, blocksAll, lines: robotsPage.text.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#")).length });
  }
  let sitemap = { found: false, url: null };
  const sitemapUrl = robots.sitemaps?.[0] || `${origin}/sitemap.xml`;
  try {
    const target = new URL(sitemapUrl);
    if (target.host === finalUrl.host && address) {
      const page = await fetchText(target.pathname + target.search);
      if (page?.status === 200 && /<(urlset|sitemapindex)\b/i.test(page.text)) sitemap = { found: true, url: target.href, entries: (page.text.match(/<loc>/gi) || []).length };
    } else {
      sitemap = { found: true, url: target.href, entries: null };
    }
  } catch {
    sitemap = { found: false, url: null };
  }
  const mixedContent = secure
    ? [...new Set([...html.matchAll(/<(?:script|img|iframe|audio|video|source|embed)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)|<link\b[^>]*\brel\s*=\s*["']?stylesheet[^>]*\bhref\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi)].map((match) => match[1] || match[2]))].slice(0, 15)
    : [];
  return { securityTxt, robots, sitemap, mixedContent };
}

async function runWebCheck(input, allowLocal) {
  const raw = String(input || "").trim();
  const explicit = /^https?:\/\//i.test(raw);
  let start;
  try {
    start = new URL(explicit ? raw : `http://${raw}/`);
  } catch {
    throw Object.assign(new Error("Enter a domain name or an http(s) URL."), { statusCode: 400 });
  }
  if (start.username || start.password || !start.hostname) throw Object.assign(new Error("Enter a domain name or an http(s) URL."), { statusCode: 400 });
  const host = start.hostname.replace(/^\[|\]$/g, "");
  if (!isIP(host) && !normalizeDomain(host)) throw Object.assign(new Error("Enter a valid domain name or URL."), { statusCode: 400 });
  const started = Date.now();
  let { hops, final } = await followWebRedirects(start, allowLocal);
  let httpUnavailable = null;
  if (!final && !explicit) {
    httpUnavailable = hops[0]?.error || "Plain HTTP is not reachable.";
    const httpsStart = new URL(`https://${raw}/`);
    ({ hops, final } = await followWebRedirects(httpsStart, allowLocal));
  }
  const result = { input: raw, startUrl: hops[0]?.url || start.href, hops, httpUnavailable, durationMs: 0 };
  if (!final) {
    result.error = hops.at(-1)?.error || "The site could not be reached.";
    result.durationMs = Date.now() - started;
    return result;
  }
  const { url: finalUrl, response } = final;
  const secure = finalUrl.protocol === "https:";
  const headers = response.headers;
  const cookies = parseSetCookies(headers["set-cookie"] || []);
  const html = decodeBody(response.body, String(headers["content-encoding"] || ""));
  const finalAddress = hops.at(-1)?.address;
  const http2 = secure && finalAddress ? await checkHttp2(finalUrl.hostname.replace(/^\[|\]$/g, ""), finalAddress, Number(finalUrl.port) || 443) : null;
  const startedPlain = result.startUrl.startsWith("http:");
  Object.assign(result, {
    finalUrl: finalUrl.href,
    finalStatus: response.status,
    https: secure,
    redirectsToHttps: startedPlain ? secure : null,
    tls: response.tls,
    http2,
    http3: /\bh3(?:-\d+)?=/i.test(String(headers["alt-svc"] || "")),
    altSvc: headers["alt-svc"] || null,
    compression: headers["content-encoding"] || null,
    contentType: headers["content-type"] || null,
    server: headers.server || null,
    title: html.match(/<title[^>]*>([^<]{0,300})/i)?.[1]?.replace(/\s+/g, " ").trim() || null,
    firstByteMs: response.firstByteMs,
    pageBytes: response.bytes,
    headers: Object.entries(headers).filter(([name]) => name !== "set-cookie").slice(0, 60)
      .map(([name, value]) => [name, String(Array.isArray(value) ? value.join(", ") : value).slice(0, 1000)]),
    cookies,
    ...webCheckChecks(headers, secure, cookies),
  });
  Object.assign(result, await webCheckExtras(finalUrl, finalAddress, html, secure));
  const issues = [];
  if (startedPlain && !secure) issues.push({ severity: "high", message: "The site does not redirect HTTP to HTTPS." });
  if (result.mixedContent?.length) issues.push({ severity: "medium", message: `${result.mixedContent.length} resource(s) load over plain HTTP on this HTTPS page (mixed content).` });
  for (const issue of result.securityTxt?.issues || []) issues.push(issue);
  if (secure && response.tls && !response.tls.authorized) issues.push({ severity: "high", message: `The certificate is not trusted (${response.tls.authorizationError}).` });
  if (response.tls?.daysRemaining !== null && response.tls?.daysRemaining !== undefined && response.tls.daysRemaining < 14) {
    issues.push({ severity: response.tls.daysRemaining < 0 ? "high" : "medium", message: response.tls.daysRemaining < 0 ? "The certificate has expired." : `The certificate expires in ${response.tls.daysRemaining} days.` });
  }
  if (response.status >= 400) issues.push({ severity: "medium", message: `The final page returned HTTP ${response.status}.` });
  if (hops.length > 3) issues.push({ severity: "low", message: `${hops.length - 1} redirects before the final page; each adds a round trip.` });
  if (secure && http2 === false) issues.push({ severity: "low", message: "HTTP/2 is not supported." });
  if (!result.compression && /text\/html|javascript|css|json/i.test(result.contentType || "") && response.bytes > 1024) issues.push({ severity: "low", message: "The response is not compressed." });
  for (const check of result.checks) {
    if (check.state === "fail") issues.push({ severity: ["hsts", "csp", "framing", "cookies"].includes(check.id) ? "medium" : "low", message: `${check.label}: ${check.message}` });
  }
  result.issues = issues;
  result.durationMs = Date.now() - started;
  return result;
}

async function webCheck(request, url, response) {
  const rawName = queryInput(url, "name", 2048, response);
  if (rawName === null) return;
  const user = currentUser(request);
  const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
  if (!acquireHeavyJob("webCheck")) {
    sendJson(response, 503, { error: "The server is busy with other web checks. Try again shortly." });
    return;
  }
  try {
    const result = await runWebCheck(rawName, allowLocal);
    if (result.grade && result.finalUrl) {
      const failed = result.checks.filter((check) => check.state === "fail").map((check) => check.label);
      recordDomainRating("web", new URL(result.finalUrl).hostname.replace(/^\[|\]$/g, ""), result.grade, result.score,
        failed.length ? `Missing: ${failed.join(", ")}` : "All key headers present");
    }
    sendJson(response, 200, result);
  } catch (error) {
    if (error.statusCode) sendJson(response, error.statusCode, { error: error.message });
    else {
      console.error("Web check failed:", error);
      sendJson(response, 500, { error: "Unable to complete the web check." });
    }
  } finally {
    releaseHeavyJob("webCheck");
  }
}

// Services whose custom-domain CNAMEs can be claimed by anyone once the original resource is deleted.
const takeoverServices = [
  { service: "GitHub Pages", cname: /\.github\.io$/, body: /There isn't a GitHub Pages site here/i },
  { service: "Heroku", cname: /\.(herokuapp\.com|herokudns\.com)$/, body: /no-such-app\.html|No such app/i },
  { service: "Amazon S3", cname: /(^|\.)s3[.-]([a-z0-9-]+\.)?amazonaws\.com$|\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/, body: /NoSuchBucket|The specified bucket does not exist/i },
  { service: "Microsoft Azure", cname: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azure-api\.net|azurefd\.net|azurecontainer\.io|azurestaticapps\.net)$/, nxdomain: true },
  { service: "AWS Elastic Beanstalk", cname: /\.elasticbeanstalk\.com$/, nxdomain: true },
  { service: "Shopify", cname: /\.myshopify\.com$/, body: /Sorry, this shop is currently unavailable|Only one step left/i },
  { service: "Fastly", cname: /\.fastly\.net$/, body: /Fastly error: unknown domain/i },
  { service: "Ghost", cname: /\.ghost\.io$/, body: /The thing you were looking for is no longer here|Domain error/i },
  { service: "Surge.sh", cname: /\.surge\.sh$/, body: /project not found/i },
  { service: "Bitbucket", cname: /\.bitbucket\.io$/, body: /Repository not found/i },
  { service: "Pantheon", cname: /\.pantheonsite\.io$/, body: /The gods are wise|404 error unknown site/i },
  { service: "Tumblr", cname: /\.tumblr\.com$/, body: /Whatever you were looking for doesn't currently exist|There's nothing here/i },
  { service: "WordPress.com", cname: /\.wordpress\.com$/, body: /Do you want to register .*\.wordpress\.com/i },
  { service: "Zendesk", cname: /\.zendesk\.com$/, body: /Help Center Closed|this help center no longer exists/i },
  { service: "Unbounce", cname: /\.unbouncepages\.com$/, body: /The requested URL was not found on this server/i },
  { service: "Netlify", cname: /\.netlify\.(app|com)$/, body: /Not Found - Request ID/i },
  { service: "Fly.io", cname: /\.fly\.dev$/, nxdomain: true },
  { service: "ReadMe", cname: /\.readme\.io$/, body: /Project doesnt exist/i },
  { service: "Help Scout", cname: /\.helpscoutdocs\.com$/, body: /No settings were found for this company/i },
  { service: "Strikingly", cname: /\.strikinglydns\.com$/, body: /PAGE NOT FOUND/i },
  { service: "Webflow", cname: /proxy(-ssl)?\.webflow\.com$/, body: /The page you are looking for doesn't exist or has been moved/i },
  { service: "Vercel", cname: /\.vercel-dns\.com$|cname\.vercel-dns\.com$/, body: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/i },
];

async function checkSubdomainTakeover(hosts, allowLocal) {
  const candidates = hosts
    .map((host) => {
      const cname = host.records.find((record) => record.type === "CNAME")?.answers.at(-1)?.data;
      return cname ? { host: host.name, cname: String(cname).replace(/\.$/, "").toLowerCase() } : null;
    })
    .filter(Boolean)
    .slice(0, 25);
  const findings = [];
  for (let index = 0; index < candidates.length; index += 5) {
    findings.push(...await Promise.all(candidates.slice(index, index + 5).map(async ({ host, cname }) => {
      const service = takeoverServices.find((entry) => entry.cname.test(cname)) || null;
      const finding = { host, cname, service: service?.service || null, status: "ok", evidence: null };
      let targetStatus = null;
      try {
        targetStatus = (await queryDohDns(cname, "A")).status;
      } catch {
        targetStatus = null;
      }
      if (targetStatus === 3) {
        finding.status = service ? "vulnerable" : "dangling";
        finding.evidence = `${cname} does not exist (NXDOMAIN).`;
        return finding;
      }
      if (!service?.body) return finding;
      for (const scheme of ["https", "http"]) {
        try {
          const target = new URL(`${scheme}://${host}/`);
          const address = await resolveWebAddress(host, allowLocal);
          if (!address) break;
          const page = await requestPinnedUrl(target, address, { timeoutMs: 6000, maxBytes: 65536 });
          const body = decodeBody(page.body, String(page.headers["content-encoding"] || ""));
          if (service.body.test(body)) {
            finding.status = "vulnerable";
            finding.evidence = `The page shows the ${service.service} "not found / unclaimed" message (HTTP ${page.status}).`;
          }
          break;
        } catch {
          // Try plain HTTP when HTTPS is not available.
        }
      }
      return finding;
    })));
  }
  return {
    checked: candidates.length,
    findings: findings.filter((finding) => finding.status !== "ok" || finding.service),
    vulnerable: findings.filter((finding) => finding.status === "vulnerable").length,
    dangling: findings.filter((finding) => finding.status === "dangling").length,
  };
}

async function analyzeMtaSts(domain, mxHosts) {
  const { records } = await queryTxtRecords(`_mta-sts.${domain}`);
  const txt = records.filter((record) => /^v\s*=\s*STSv1\b/i.test(record.trim()));
  const issues = [];
  if (!txt.length) return { found: false, record: null, policy: null, issues };
  const result = { found: true, record: txt[0], id: parseTagList(txt[0]).id || null, policy: null, issues };
  if (txt.length > 1) issues.push({ severity: "high", message: "More than one MTA-STS TXT record is published; senders will ignore MTA-STS." });
  const policyHost = `mta-sts.${domain}`;
  let address;
  try {
    const answers = (await queryDohDns(policyHost, "A")).answers.filter((answer) => answer.type === 1 || answer.typeName === "A");
    address = answers.map((answer) => answer.data).find((value) => isPublicAddress(value));
  } catch {
    address = null;
  }
  if (!address) {
    issues.push({ severity: "high", message: `${policyHost} does not resolve to a public IPv4 address, so senders cannot fetch the policy.` });
    return result;
  }
  try {
    const response = await fetchPinnedHttps(policyHost, address, "/.well-known/mta-sts.txt");
    if (response.status !== 200) {
      issues.push({ severity: "high", message: `The policy file returned HTTP ${response.status}.` });
      return result;
    }
    if (!/^text\/plain\b/i.test(response.contentType)) {
      issues.push({ severity: "medium", message: `The policy file is served as "${response.contentType || "no content type"}" instead of text/plain.` });
    }
    const fields = { mx: [] };
    for (const line of response.body.split(/\r?\n/)) {
      const index = line.indexOf(":");
      if (index < 0) continue;
      const key = line.slice(0, index).trim().toLowerCase();
      const value = line.slice(index + 1).trim();
      if (key === "mx") fields.mx.push(value.toLowerCase());
      else if (key) fields[key] = value;
    }
    result.policy = { version: fields.version || null, mode: fields.mode || null, maxAge: Number(fields.max_age) || null, mx: fields.mx };
    if (fields.version !== "STSv1") issues.push({ severity: "high", message: "The policy file does not start with version: STSv1." });
    if (fields.mode === "testing") issues.push({ severity: "medium", message: "MTA-STS is in testing mode; senders report failures but still deliver over insecure connections." });
    else if (fields.mode === "none") issues.push({ severity: "medium", message: "MTA-STS mode is none, which disables the policy." });
    else if (fields.mode !== "enforce") issues.push({ severity: "high", message: "The policy has no valid mode (enforce, testing or none)." });
    if (!result.policy.maxAge) issues.push({ severity: "high", message: "The policy has no valid max_age." });
    else if (result.policy.maxAge < 86400) issues.push({ severity: "low", message: `max_age is only ${result.policy.maxAge} seconds; at least a week (604800) is recommended.` });
    const matches = (host, pattern) => pattern.startsWith("*.")
      ? host.endsWith(pattern.slice(1)) && host.split(".").length === pattern.split(".").length
      : host === pattern;
    const uncovered = mxHosts.filter((host) => !fields.mx.some((pattern) => matches(host, pattern)));
    if (uncovered.length) issues.push({ severity: "high", message: `These MX hosts are not covered by the policy's mx: lines, so mail to them would fail under enforce: ${uncovered.join(", ")}.` });
  } catch (error) {
    issues.push({
      severity: "high",
      message: error.code && /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS/.test(error.code)
        ? `The policy host's HTTPS certificate is not valid (${error.code}); senders will not trust the policy.`
        : `The policy file could not be fetched (${error.name === "TimeoutError" ? "timed out" : error.code || error.message}).`,
    });
  }
  return result;
}

async function analyzeTlsRpt(domain) {
  const { records } = await queryTxtRecords(`_smtp._tls.${domain}`);
  const txt = records.filter((record) => /^v\s*=\s*TLSRPTv1\b/i.test(record.trim()));
  if (!txt.length) return { found: false, record: null, issues: [] };
  const tags = parseTagList(txt[0]);
  const issues = [];
  if (!tags.rua) issues.push({ severity: "medium", message: "The TLS-RPT record has no rua= destination for reports." });
  if (txt.length > 1) issues.push({ severity: "medium", message: "More than one TLS-RPT record is published." });
  return { found: true, record: txt[0], rua: tags.rua || null, issues };
}

async function analyzeSpf(domain) {
  let queries = 0;
  const maxQueries = 30;
  const tree = [];
  const issues = [];
  async function spfRecordFor(name) {
    queries += 1;
    const { records } = await queryTxtRecords(name);
    return records.filter((record) => /^v=spf1(\s|$)/i.test(record.trim()));
  }
  async function evaluate(name, depth) {
    const records = await spfRecordFor(name);
    if (records.length !== 1) return { name, record: records[0] || null, lookups: 0, error: records.length ? "multiple SPF records" : "no SPF record" };
    const terms = records[0].trim().split(/\s+/).slice(1);
    let lookups = 0;
    const children = [];
    for (const term of terms) {
      const mechanism = term.replace(/^[+\-~?]/, "").toLowerCase();
      const [kind, argument] = mechanism.split(/[:=]/);
      if (["include", "a", "mx", "ptr", "exists", "redirect"].includes(kind)) lookups += 1;
      if ((kind === "include" || kind === "redirect") && argument && !argument.includes("%") && depth < 10 && queries < maxQueries) {
        const child = await evaluate(argument, depth + 1);
        lookups += child.lookups;
        children.push({ ...child, via: kind });
      }
      if (kind === "ptr") issues.push({ severity: "low", message: `${name} uses the ptr mechanism, which RFC 7208 says not to use.` });
    }
    return { name, record: records[0], lookups, children };
  }
  const rootRecords = await spfRecordFor(domain);
  if (!rootRecords.length) {
    return { found: false, record: null, lookups: 0, tree, issues: [{ severity: "medium", message: "No SPF record on the domain; receivers cannot tell which servers may send its mail." }] };
  }
  if (rootRecords.length > 1) {
    return { found: true, record: rootRecords[0], lookups: null, tree, issues: [{ severity: "high", message: "More than one SPF record is published, which is a permanent error (SPF fails for all mail)." }] };
  }
  queries = 0;
  const root = await evaluate(domain, 0);
  const all = root.record.trim().split(/\s+/).find((term) => /^[+\-~?]?all$/i.test(term));
  if (!all && !/\sredirect=/i.test(root.record)) issues.push({ severity: "medium", message: "The SPF record has no all mechanism, so unlisted senders get a neutral result." });
  else if (all && /^\+?all$/i.test(all)) issues.push({ severity: "high", message: "+all allows every server on the internet to send as this domain." });
  else if (all && /^\?all$/i.test(all)) issues.push({ severity: "medium", message: "?all is neutral and gives no protection." });
  if (root.lookups > 10) issues.push({ severity: "high", message: `SPF needs ${root.lookups} DNS lookups; the limit is 10, so evaluation fails with a permanent error.` });
  else if (root.lookups >= 8) issues.push({ severity: "low", message: `SPF uses ${root.lookups} of 10 allowed DNS lookups; little room is left for new includes.` });
  const flatten = (node, depth = 0) => [{ name: node.name, via: node.via || null, lookups: node.lookups, error: node.error || null, depth }, ...(node.children || []).flatMap((child) => flatten(child, depth + 1))];
  return { found: true, record: root.record, all: all || null, lookups: root.lookups, tree: flatten(root), issues, truncated: queries >= maxQueries };
}

async function analyzeMailSecurity(domain) {
  const settle = (promise) => promise.catch((error) => ({ error: error.name === "TimeoutError" ? "The DNS provider timed out." : "The check could not be completed." }));
  let mxHosts = [];
  try {
    mxHosts = (await queryDohDns(domain, "MX")).answers
      .filter((answer) => answer.type === 15 || answer.typeName === "MX")
      .map((answer) => String(answer.data).split(" ").pop().replace(/\.$/, "").toLowerCase())
      .filter(Boolean);
  } catch {
    mxHosts = [];
  }
  const [dmarc, mtaSts, tlsRpt, spf] = await Promise.all([
    settle(analyzeDmarc(domain)),
    settle(analyzeMtaSts(domain, mxHosts)),
    settle(analyzeTlsRpt(domain)),
    settle(analyzeSpf(domain)),
  ]);
  return { mxHosts, dmarc, mtaSts, tlsRpt, spf };
}

// Mail providers recognised from MX hosts (inbound) and SPF includes (outbound senders).
const mailProviders = [
  { name: "Google Workspace / Gmail", mx: [/(^|\.)google\.com$/, /(^|\.)googlemail\.com$/], spf: [/(^|\.)google\.com$/] },
  { name: "Microsoft 365 / Exchange Online", mx: [/\.mail\.protection\.outlook\.com$/, /(^|\.)outlook\.com$/], spf: [/(^|\.)protection\.outlook\.com$/, /(^|\.)outlook\.com$/] },
  { name: "Proton Mail", mx: [/(^|\.)protonmail\.ch$/, /(^|\.)proton\.me$/], spf: [/(^|\.)protonmail\.ch$/] },
  { name: "Zoho Mail", mx: [/(^|\.)zoho\.(com|eu|in|com\.au|jp|com\.cn)$/, /(^|\.)zohomail\./], spf: [/(^|\.)zoho\.(com|eu|in|com\.au|jp)$/, /(^|\.)zcsend\.net$/] },
  { name: "Fastmail", mx: [/(^|\.)messagingengine\.com$/, /(^|\.)fastmail\.com$/], spf: [/(^|\.)messagingengine\.com$/] },
  { name: "iCloud Mail", mx: [/(^|\.)mail\.icloud\.com$/], spf: [/(^|\.)icloud\.com$/] },
  { name: "Yahoo Mail", mx: [/(^|\.)yahoodns\.net$/, /(^|\.)yahoo\.com$/], spf: [/(^|\.)yahoo\.com$/] },
  { name: "Amazon SES", mx: [/inbound-smtp\..*\.amazonaws\.com$/], spf: [/(^|\.)amazonses\.com$/] },
  { name: "Amazon WorkMail", mx: [/(^|\.)awsapps\.com$/], spf: [] },
  { name: "Mailgun", mx: [/(^|\.)mailgun\.org$/], spf: [/(^|\.)mailgun\.org$/] },
  { name: "SendGrid (Twilio)", mx: [/(^|\.)sendgrid\.net$/], spf: [/(^|\.)sendgrid\.net$/] },
  { name: "Mailchimp / Mandrill", mx: [], spf: [/(^|\.)mcsv\.net$/, /(^|\.)mandrillapp\.com$/, /(^|\.)mailchimpapp\.net$/] },
  { name: "Postmark", mx: [/(^|\.)mtasv\.net$/], spf: [/(^|\.)mtasv\.net$/] },
  { name: "SparkPost", mx: [], spf: [/(^|\.)sparkpostmail\.com$/] },
  { name: "Brevo (Sendinblue)", mx: [/(^|\.)brevo\.com$/, /(^|\.)sendinblue\.com$/], spf: [/(^|\.)sendinblue\.com$/, /(^|\.)brevo\.com$/] },
  { name: "Mailjet", mx: [], spf: [/(^|\.)mailjet\.com$/] },
  { name: "Mimecast", mx: [/(^|\.)mimecast\.(com|co\.za)$/], spf: [/(^|\.)mimecast\.(com|co\.za)$/] },
  { name: "Proofpoint", mx: [/(^|\.)pphosted\.com$/, /(^|\.)ppe-hosted\.com$/], spf: [/(^|\.)pphosted\.com$/, /(^|\.)ppe-hosted\.com$/] },
  { name: "Cisco Secure Email (IronPort)", mx: [/(^|\.)iphmx\.com$/], spf: [/(^|\.)iphmx\.com$/] },
  { name: "Barracuda", mx: [/(^|\.)barracudanetworks\.com$/], spf: [/(^|\.)barracudanetworks\.com$/] },
  { name: "Sophos Email", mx: [/(^|\.)hydra\.sophos\.com$/], spf: [/(^|\.)sophos\.com$/] },
  { name: "Hornetsecurity", mx: [/(^|\.)hornetsecurity\.com$/], spf: [/(^|\.)hornetsecurity\.com$/] },
  { name: "N-able Mail Assure / SpamExperts", mx: [/(^|\.)antispamcloud\.com$/, /(^|\.)spamexperts\./], spf: [/(^|\.)antispamcloud\.com$/, /(^|\.)spamexperts\./] },
  { name: "Cloudflare Email Routing", mx: [/(^|\.)mx\.cloudflare\.net$/], spf: [/(^|\.)mx\.cloudflare\.net$/] },
  { name: "ImprovMX", mx: [/(^|\.)improvmx\.com$/], spf: [/(^|\.)improvmx\.com$/] },
  { name: "Forward Email", mx: [/(^|\.)forwardemail\.net$/], spf: [/(^|\.)forwardemail\.net$/] },
  { name: "Tuta (Tutanota)", mx: [/(^|\.)tutanota\.de$/], spf: [/(^|\.)tutanota\.de$/] },
  { name: "mailbox.org", mx: [/(^|\.)mailbox\.org$/], spf: [/(^|\.)mailbox\.org$/] },
  { name: "Migadu", mx: [/(^|\.)migadu\.com$/], spf: [/(^|\.)migadu\.com$/] },
  { name: "Yandex Mail", mx: [/(^|\.)yandex\.(net|ru)$/], spf: [/(^|\.)yandex\.(net|ru)$/] },
  { name: "GoDaddy / Microsoft 365 via GoDaddy", mx: [/(^|\.)secureserver\.net$/], spf: [/(^|\.)secureserver\.net$/] },
  { name: "Namecheap Private Email", mx: [/(^|\.)privateemail\.com$/], spf: [/(^|\.)privateemail\.com$/, /(^|\.)spf\.efwd\.registrar-servers\.com$/] },
  { name: "IONOS (1&1)", mx: [/(^|\.)ionos\.[a-z.]+$/, /(^|\.)kundenserver\.de$/], spf: [/(^|\.)ionos\.[a-z.]+$/, /(^|\.)kundenserver\.de$/] },
  { name: "OVHcloud", mx: [/(^|\.)ovh\.net$/], spf: [/(^|\.)ovh\.com$/, /(^|\.)ovh\.net$/] },
  { name: "Strato", mx: [/(^|\.)strato\.de$/], spf: [/(^|\.)strato\.de$/] },
  { name: "Hostinger", mx: [/(^|\.)hostinger\.com$/], spf: [/(^|\.)hostinger\.com$/] },
  { name: "Infomaniak", mx: [/(^|\.)infomaniak\.ch$/], spf: [/(^|\.)infomaniak\.ch$/] },
  { name: "TransIP", mx: [/(^|\.)transip\.email$/, /(^|\.)transip\.nl$/], spf: [/(^|\.)transip\.(email|nl)$/] },
  { name: "Salesforce", mx: [], spf: [/(^|\.)salesforce\.com$/, /(^|\.)exacttarget\.com$/] },
  { name: "HubSpot", mx: [], spf: [/(^|\.)hubspotemail\.net$/] },
  { name: "Zendesk", mx: [], spf: [/(^|\.)zendesk\.com$/] },
  { name: "Freshworks", mx: [], spf: [/(^|\.)freshdesk\.com$/, /(^|\.)freshemail\.io$/] },
  { name: "Atlassian", mx: [], spf: [/(^|\.)atlassian\.net$/] },
  { name: "Mailerlite", mx: [], spf: [/(^|\.)mlsend\.com$/] },
  { name: "Klaviyo", mx: [], spf: [/(^|\.)klaviyomail\.com$/] },
];

function identifyMailProvider(host, kind) {
  const value = String(host || "").toLowerCase().replace(/\.$/, "");
  return mailProviders.find((provider) => provider[kind].some((pattern) => pattern.test(value)))?.name || null;
}

function parseSmtpReplies(buffer) {
  // Returns complete replies ({ code, lines }) and the text of any reply that is still incomplete.
  const replies = [];
  let current = [];
  let consumed = 0;
  let replyStart = 0;
  let index;
  while ((index = buffer.indexOf("\n", consumed)) !== -1) {
    const line = buffer.slice(consumed, index).replace(/\r$/, "");
    consumed = index + 1;
    const match = line.match(/^(\d{3})([ -])(.*)$/);
    if (!match) continue;
    current.push(match[3]);
    if (match[2] === " ") {
      replies.push({ code: Number(match[1]), lines: current });
      current = [];
      replyStart = consumed;
    }
  }
  return { replies, rest: buffer.slice(replyStart) };
}

const smtpHeloName = /^[a-z0-9.-]{1,253}$/i.test(process.env.SMTP_TEST_HELO || "") ? process.env.SMTP_TEST_HELO : "bnglookup.localdomain";

// With deep: true the probe also records the greeting and timings and tests whether the
// server relays: it offers a foreign sender and recipient and stops before DATA.
function testSmtpStartTls(host, address, { timeoutMs = 15000, deep = false } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const result = { host, address, connected: false, banner: null, ehlo: false, starttls: false, tls: null, capabilities: [], capabilitiesAfterTls: [], error: null };
    let socket = net.connect({ host: address, port: 25, family: isIP(address) });
    let buffer = "";
    let stage = "banner";
    let finished = false;
    const finish = (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error && !result.error) result.error = error;
      result.durationMs = Date.now() - started;
      try {
        socket.end("QUIT\r\n");
      } catch {
        // The socket may already be closed.
      }
      setTimeout(() => socket.destroy(), 500).unref();
      resolve(result);
    };
    const timer = setTimeout(() => finish(stage === "banner" && !result.connected
      ? "Could not connect to port 25 in time. Outbound port 25 may be blocked by this server's network or hosting provider."
      : `The server stopped responding (${stage}).`), timeoutMs);
    const send = (line) => socket.write(`${line}\r\n`);
    const startRelayTest = () => {
      stage = "mail";
      send("MAIL FROM:<bnglookup-relay-test@example.org>");
    };
    const onReply = (reply) => {
      const text = reply.lines.join(" ").slice(0, 300);
      if (stage === "banner") {
        if (reply.code !== 220) return finish(`The server refused the connection: ${reply.code} ${text}`);
        result.banner = text;
        if (deep) result.bannerMs = Date.now() - started;
        stage = "ehlo";
        send(`EHLO ${smtpHeloName}`);
      } else if (stage === "ehlo") {
        if (reply.code !== 250) return finish(`EHLO was rejected: ${reply.code} ${text}`);
        result.ehlo = true;
        result.greeting = reply.lines[0]?.slice(0, 200) || null;
        result.capabilities = reply.lines.slice(1).map((line) => line.trim().toUpperCase()).filter(Boolean).slice(0, 30);
        result.starttls = result.capabilities.some((capability) => capability.split(" ")[0] === "STARTTLS");
        if (!result.starttls) return deep ? startRelayTest() : finish(null);
        stage = "starttls";
        send("STARTTLS");
      } else if (stage === "starttls") {
        if (reply.code !== 220) return finish(`STARTTLS was refused: ${reply.code} ${text}`);
        stage = "tls";
        socket.removeAllListeners("data");
        const secure = tls.connect({ socket, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, minVersion: "TLSv1" });
        secure.once("secureConnect", () => {
          const certificate = secure.getPeerCertificate();
          const nameError = certificate && Object.keys(certificate).length ? tls.checkServerIdentity(host, certificate) : new Error("No certificate");
          const validTo = certificate?.valid_to ? new Date(certificate.valid_to) : null;
          result.tls = {
            protocol: secure.getProtocol(),
            cipher: secure.getCipher()?.name || null,
            authorized: secure.authorized,
            authorizationError: secure.authorized ? null : String(secure.authorizationError || "Certificate is not trusted."),
            nameMatches: !nameError,
            subject: certificate?.subject?.CN || null,
            subjectAltName: certificate?.subjectaltname ? certificate.subjectaltname.slice(0, 500) : null,
            issuer: certificate?.issuer ? [certificate.issuer.O, certificate.issuer.CN].filter(Boolean).join(" · ") : null,
            validTo: validTo && !Number.isNaN(validTo.getTime()) ? validTo.toISOString() : null,
            daysRemaining: validTo && !Number.isNaN(validTo.getTime()) ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null,
          };
          socket = secure;
          buffer = "";
          stage = "ehlo-tls";
          secure.on("data", onData);
          send(`EHLO ${smtpHeloName}`);
        });
        secure.once("error", (error) => finish(`The TLS handshake failed (${error.code || error.message}).`));
      } else if (stage === "ehlo-tls") {
        if (reply.code === 250) result.capabilitiesAfterTls = reply.lines.slice(1).map((line) => line.trim().toUpperCase()).filter(Boolean).slice(0, 30);
        if (deep) return startRelayTest();
        finish(null);
      } else if (stage === "mail") {
        if (reply.code !== 250) {
          result.relay = { tested: false, open: false, reply: `${reply.code} ${text}` };
          return finish(null);
        }
        stage = "rcpt";
        send("RCPT TO:<bnglookup-relay-test@example.com>");
      } else if (stage === "rcpt") {
        result.relay = { tested: true, open: reply.code === 250 || reply.code === 251, reply: `${reply.code} ${text}` };
        stage = "rset";
        send("RSET");
        finish(null);
      }
    };
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > 65536) return finish("The server sent too much data.");
      const parsed = parseSmtpReplies(buffer);
      buffer = parsed.rest;
      for (const reply of parsed.replies) {
        if (finished) return;
        onReply(reply);
      }
    };
    socket.once("connect", () => {
      result.connected = true;
      if (deep) result.connectMs = Date.now() - started;
    });
    socket.on("data", onData);
    socket.once("error", (error) => finish(error.code === "ECONNREFUSED"
      ? "Port 25 refused the connection."
      : ["ETIMEDOUT", "ENETUNREACH", "EHOSTUNREACH"].includes(error.code)
        ? `Could not reach port 25 (${error.code}). Outbound port 25 may be blocked by this server's network or hosting provider.`
        : `The connection failed (${error.code || error.message}).`));
  });
}

// ---------------------------------------------------------------- Mail server deep check

async function resolveMailHosts(domain) {
  let records = [];
  let nullMx = false;
  let implicit = false;
  try {
    const mxData = await queryDohDns(domain, "MX");
    records = mxData.answers
      .filter((answer) => answer.type === 15 || answer.typeName === "MX")
      .map((answer) => {
        const [priority, host] = String(answer.data).split(/\s+/);
        return { priority: Number(priority), host: String(host || "").replace(/\.$/, "").toLowerCase() };
      })
      .sort((left, right) => left.priority - right.priority || left.host.localeCompare(right.host));
    nullMx = records.length === 1 && (!records[0].host || records[0].host === ".");
    if (!records.length) {
      implicit = true;
      records = [{ priority: 0, host: domain }];
    }
  } catch {
    records = [];
  }
  if (nullMx) records = [];
  const resolved = await Promise.all(records.slice(0, 10).map(async (record) => {
    const [v4, v6] = await Promise.all(["A", "AAAA"].map((type) => queryDohDns(record.host, type).then(
      (data) => data.answers.filter((answer) => answer.type === (type === "A" ? 1 : 28) || answer.typeName === type).map((answer) => answer.data),
      () => [],
    )));
    return { ...record, addresses: [...v4, ...v6] };
  }));
  return { records: resolved, nullMx, implicit };
}

// Forward-confirmed reverse DNS: the PTR name must resolve back to the same address.
async function forwardConfirmedPtr(address) {
  let ptr;
  try {
    ptr = await fetchPtr(address);
  } catch {
    return { names: [], confirmed: false, error: "The PTR lookup failed." };
  }
  const names = (ptr.answers || []).map((name) => String(name).replace(/\.$/, "").toLowerCase()).slice(0, 4);
  for (const name of names) {
    const type = isIP(address) === 6 ? "AAAA" : "A";
    const forward = await queryDohDns(name, type).then((data) => data.answers.map((answer) => answer.data), () => []);
    if (forward.includes(address)) return { names, confirmed: true, confirmedName: name };
  }
  return { names, confirmed: false };
}

const hostnameToken = (text) => {
  const token = String(text || "").trim().split(/\s+/)[0]?.replace(/[[\]]/g, "").toLowerCase() || "";
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(token) ? token : null;
};

function mailServerIssues(server) {
  const issues = [];
  if (!server.connected || server.error) {
    if (server.error) issues.push({ severity: "low", message: `${server.host}: ${server.error}` });
    return issues;
  }
  if (server.relay?.open) issues.push({ severity: "high", message: `${server.host} accepts mail for other domains without logging in (open relay); spammers can abuse it.` });
  if (!server.starttls) issues.push({ severity: "high", message: `${server.host} does not offer STARTTLS, so mail to it travels unencrypted.` });
  if (server.tls) {
    if (/^TLSv1(\.1)?$/.test(server.tls.protocol || "")) issues.push({ severity: "medium", message: `${server.host} negotiated the outdated ${server.tls.protocol}.` });
    if (server.tls.daysRemaining !== null && server.tls.daysRemaining < 0) issues.push({ severity: "high", message: `The certificate of ${server.host} has expired.` });
    else if (server.tls.daysRemaining !== null && server.tls.daysRemaining < 14) issues.push({ severity: "medium", message: `The certificate of ${server.host} expires in ${server.tls.daysRemaining} days.` });
    if (!server.tls.authorized) issues.push({ severity: "medium", message: `The certificate of ${server.host} is not trusted (${server.tls.authorizationError}); MTA-STS and DANE senders will refuse it.` });
    else if (!server.tls.nameMatches) issues.push({ severity: "medium", message: `The certificate of ${server.host} does not cover that name.` });
  }
  if (server.authBeforeTls) issues.push({ severity: "medium", message: `${server.host} offers password login (AUTH) before encryption, so passwords can be sent in clear text.` });
  if (!server.ptr.names.length) issues.push({ severity: "medium", message: `${server.address} has no reverse DNS (PTR) name; many receivers reject mail from such addresses.` });
  else if (!server.ptr.confirmed) issues.push({ severity: "medium", message: `The reverse DNS name of ${server.address} (${server.ptr.names[0]}) does not point back to it (not forward-confirmed).` });
  if (server.bannerHost && server.ptr.names.length && !server.ptr.names.includes(server.bannerHost) && server.bannerHost !== server.host) {
    issues.push({ severity: "low", message: `${server.host} introduces itself as ${server.bannerHost}, which matches neither its MX name nor its reverse DNS.` });
  }
  if (server.bannerMs > 5000) issues.push({ severity: "low", message: `${server.host} took ${(server.bannerMs / 1000).toFixed(1)} s to greet; senders may time out.` });
  return issues;
}

async function mailServerCheck(request, url, response) {
  const rawName = queryInput(url, "name", 320, response);
  if (rawName === null) return;
  const input = rawName.trim();
  const domain = normalizeDomain(hostFromInput(input.includes("@") ? input.slice(input.lastIndexOf("@") + 1) : input));
  if (!domain) return sendJson(response, 400, { error: "Enter a domain name or a mail server name." });
  const user = currentUser(request);
  const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
  if (!acquireHeavyJob("mailServer")) return sendJson(response, 503, { error: "The server is busy with other mail server checks. Try again shortly." });
  try {
    const started = Date.now();
    const { records, nullMx, implicit } = await resolveMailHosts(domain);
    const targets = records.filter((record) => record.addresses.length).slice(0, 3);
    const servers = await Promise.all(targets.map(async (record) => {
      const address = record.addresses.find((candidate) => isIP(candidate) === 4 && isScannableAddress(candidate, allowLocal));
      if (!address) return { host: record.host, priority: record.priority, address: null, error: "No public IPv4 address to test (private or reserved addresses are not tested).", ptr: { names: [], confirmed: false }, issues: [] };
      const [probe, ptr] = await Promise.all([testSmtpStartTls(record.host, address, { deep: true }), forwardConfirmedPtr(address)]);
      const authBefore = probe.capabilities.some((capability) => /^AUTH\b/.test(capability));
      const caps = probe.capabilitiesAfterTls.length ? probe.capabilitiesAfterTls : probe.capabilities;
      const size = caps.find((capability) => /^SIZE\b/.test(capability))?.split(/\s+/)[1];
      const server = {
        ...probe,
        priority: record.priority,
        ptr,
        bannerHost: hostnameToken(probe.banner),
        greetingHost: hostnameToken(probe.greeting),
        authBeforeTls: authBefore && probe.starttls,
        authMechanisms: (caps.find((capability) => /^AUTH\b/.test(capability)) || "").split(/\s+/).slice(1),
        sizeLimit: size && /^\d+$/.test(size) && Number(size) > 0 ? Number(size) : null,
        features: ["PIPELINING", "8BITMIME", "SMTPUTF8", "REQUIRETLS", "CHUNKING", "DSN", "ENHANCEDSTATUSCODES"].filter((name) => caps.some((capability) => capability.split(/\s+/)[0] === name)),
      };
      server.issues = mailServerIssues(server);
      return server;
    }));
    const issues = servers.flatMap((server) => server.issues);
    if (nullMx) issues.push({ severity: "low", message: "The domain publishes a null MX: it does not accept mail." });
    else if (!records.length) issues.push({ severity: "medium", message: "No mail servers were found for this domain." });
    sendJson(response, 200, { domain, nullMx, implicitMx: implicit, mx: records, servers, issues, durationMs: Date.now() - started });
  } catch (error) {
    console.error("Mail server check failed:", error);
    sendJson(response, 500, { error: "Unable to complete the mail server check." });
  } finally {
    releaseHeavyJob("mailServer");
  }
}

async function analyzeDkimSelector(domain, selector, provider) {
  const { records } = await queryTxtRecords(`${selector}._domainkey.${domain}`);
  const record = records.find((value) => /(^|;)\s*(v\s*=\s*DKIM1|p\s*=)/i.test(value));
  if (!record) return null;
  const tags = parseTagList(record);
  const issues = [];
  const keyType = (tags.k || "rsa").toLowerCase();
  const publicKey = (tags.p || "").replace(/\s+/g, "");
  let keyBits = null;
  if (tags.v && tags.v.toUpperCase() !== "DKIM1") issues.push({ severity: "high", message: `Unsupported version v=${tags.v}.` });
  if (!publicKey) {
    issues.push({ severity: "medium", message: "The public key is empty (p=), which means this key has been revoked." });
  } else if (keyType === "rsa") {
    try {
      keyBits = crypto.createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" }).asymmetricKeyDetails?.modulusLength || null;
    } catch {
      issues.push({ severity: "high", message: "The public key is not a valid RSA key, so signatures cannot be verified." });
    }
    if (keyBits && keyBits < 1024) issues.push({ severity: "high", message: `The RSA key is only ${keyBits} bits; receivers ignore keys shorter than 1024 bits.` });
    else if (keyBits && keyBits < 2048) issues.push({ severity: "low", message: `The RSA key is ${keyBits} bits; 2048 bits is recommended.` });
  } else if (keyType === "ed25519") {
    keyBits = Buffer.from(publicKey, "base64").length === 32 ? 256 : null;
    if (!keyBits) issues.push({ severity: "high", message: "The Ed25519 public key has the wrong length." });
  } else {
    issues.push({ severity: "high", message: `Unknown key type k=${keyType}.` });
  }
  if (/(^|:)y(:|$)/i.test(tags.t || "")) issues.push({ severity: "low", message: "Test mode (t=y): receivers treat failures as if the message were unsigned." });
  if (tags.h && !/sha256/i.test(tags.h)) issues.push({ severity: "medium", message: `Only ${tags.h} is allowed as hash algorithm; SHA-1 is no longer accepted.` });
  return { selector, provider, record: record.slice(0, 2000), keyType, keyBits, revoked: !publicKey, testing: /(^|:)y(:|$)/i.test(tags.t || ""), issues };
}

// Fetches a BIMI logo or certificate URL over HTTPS, pinned to a public address of its host.
async function fetchBimiFile(location, maxBytes) {
  let target;
  try {
    target = new URL(location);
  } catch {
    return { error: "The URL is not valid." };
  }
  if (target.protocol !== "https:") return { error: "The URL must use HTTPS." };
  if (target.username || target.password) return { error: "The URL must not contain credentials." };
  const hostname = target.hostname.replace(/^\[|\]$/g, "");
  let address = isIP(hostname) ? hostname : null;
  if (!address) {
    for (const type of ["A", "AAAA"]) {
      const answers = await queryDohDns(hostname, type).then((data) => data.answers, () => []);
      address = answers.filter((answer) => answer.type === (type === "A" ? 1 : 28) || answer.typeName === type)
        .map((answer) => answer.data).find((value) => isPublicAddress(value));
      if (address) break;
    }
  }
  if (!address || !isPublicAddress(address)) return { error: `${hostname} does not resolve to a public address.` };
  try {
    const response = await fetchPinnedHttps(hostname, address, `${target.pathname}${target.search}`, {
      maxBytes, timeoutMs: 8000, port: Number(target.port) || 443,
    });
    if (response.status !== 200) {
      return { error: response.status >= 300 && response.status < 400 ? `HTTP ${response.status} redirect; BIMI files must be served directly.` : `HTTP ${response.status}.` };
    }
    return { contentType: response.contentType, body: response.body };
  } catch (error) {
    return { error: error.message === "The response is too large." ? `The file is larger than ${Math.round(maxBytes / 1024)} KB.` : error.name === "TimeoutError" ? "The request timed out." : `Could not fetch the file (${String(error.code || error.message).slice(0, 80)}).` };
  }
}

const bimiMarkTypeOid = "1.3.6.1.4.1.53087.1.13";
const bimiExtendedKeyUsage = "1.3.6.1.5.5.7.3.31";

function analyzeBimiCertificate(pem, domain, logoSvg) {
  const blocks = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  if (!blocks.length) return { error: "The file contains no PEM certificate." };
  let chain;
  try {
    chain = blocks.slice(0, 5).map((block) => new crypto.X509Certificate(block));
  } catch {
    return { error: "The certificate could not be parsed." };
  }
  const leaf = chain[0];
  const issues = [];
  const subjectFields = Object.fromEntries(leaf.subject.split("\n").map((line) => {
    const index = line.indexOf("=");
    return [line.slice(0, index), line.slice(index + 1)];
  }));
  const markType = subjectFields[bimiMarkTypeOid] || null;
  const names = (leaf.subjectAltName || "").split(/,\s*/).filter((name) => name.startsWith("DNS:")).map((name) => name.slice(4).toLowerCase());
  const validTo = new Date(leaf.validTo);
  const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / 86400000);
  const kind = /prior use|modified registered/i.test(markType || "") ? "CMC" : markType ? "VMC" : null;
  if (!(leaf.keyUsage || []).includes(bimiExtendedKeyUsage)) {
    issues.push({ severity: "high", message: "The certificate is not a mark certificate (it lacks the BIMI extended key usage)." });
  }
  if (daysRemaining < 0) issues.push({ severity: "high", message: "The mark certificate has expired." });
  else if (daysRemaining < 30) issues.push({ severity: "medium", message: `The mark certificate expires in ${daysRemaining} days.` });
  if (new Date(leaf.validFrom) > new Date()) issues.push({ severity: "high", message: "The mark certificate is not valid yet." });
  if (!names.some((name) => name === domain || domain.endsWith(`.${name}`))) {
    issues.push({ severity: "high", message: `The certificate does not cover ${domain} (it lists ${names.join(", ") || "no domain names"}).` });
  }
  if (chain.length < 2) {
    issues.push({ severity: "medium", message: "The file only contains the end certificate; it should include the intermediate certificate(s) too." });
  } else if (!chain.slice(1).some((issuer) => leaf.checkIssued(issuer) && leaf.verify(issuer.publicKey))) {
    issues.push({ severity: "high", message: "The included intermediate certificate did not issue the mark certificate." });
  }
  // The certificate embeds the logo as a gzip-compressed SVG data URL; BIMI requires it to match l=.
  let embeddedLogoMatches = null;
  const raw = leaf.raw.toString("latin1");
  const marker = raw.indexOf("data:image/svg+xml;base64,");
  if (marker >= 0) {
    const encoded = raw.slice(marker + 26).match(/^[A-Za-z0-9+/=]+/)?.[0] || "";
    try {
      const data = Buffer.from(encoded, "base64");
      const embedded = (data[0] === 0x1f && data[1] === 0x8b ? zlib.gunzipSync(data, { maxOutputLength: 1048576 }) : data).toString("utf8");
      if (logoSvg) {
        const normalize = (svg) => svg.replace(/^\uFEFF/, "").replace(/\s+/g, " ").trim();
        embeddedLogoMatches = normalize(embedded) === normalize(logoSvg);
        if (!embeddedLogoMatches) issues.push({ severity: "high", message: "The logo embedded in the certificate differs from the logo at l=; receivers will not show it." });
      }
    } catch {
      issues.push({ severity: "medium", message: "The logo embedded in the certificate could not be decoded." });
    }
  } else {
    issues.push({ severity: "medium", message: "The certificate does not embed a logo." });
  }
  return {
    kind,
    markType,
    subject: subjectFields.O || subjectFields.CN || null,
    trademark: subjectFields["1.3.6.1.4.1.53087.1.4"] || null,
    issuer: leaf.issuer.split("\n").find((line) => line.startsWith("O="))?.slice(2) || leaf.issuer.split("\n").find((line) => line.startsWith("CN="))?.slice(3) || null,
    names,
    validTo: validTo.toISOString(),
    daysRemaining,
    chainLength: chain.length,
    embeddedLogoMatches,
    issues,
  };
}

async function analyzeBimi(domain) {
  const { records } = await queryTxtRecords(`default._bimi.${domain}`);
  const bimiRecords = records.filter((value) => /^v\s*=\s*BIMI1\b/i.test(value.trim()));
  const record = bimiRecords[0];
  if (!record) return { found: false, record: null, issues: [] };
  const tags = parseTagList(record);
  const issues = [];
  const result = { found: true, record, logo: tags.l || null, certificate: tags.a || null, logoCheck: null, certificateCheck: null, issues };
  if (bimiRecords.length > 1) issues.push({ severity: "high", message: "More than one BIMI record is published at default._bimi; receivers will ignore BIMI." });
  if (!tags.l && !tags.a) issues.push({ severity: "low", message: "The record has no logo (empty l=), which declines BIMI for this domain." });
  else if (!tags.l) issues.push({ severity: "medium", message: "No logo location (l=)." });
  if (!tags.a) issues.push({ severity: "low", message: "No mark certificate (a=); Gmail and Apple Mail only show BIMI logos with a VMC or CMC." });
  const [logoFile, certificateFile] = await Promise.all([
    tags.l ? fetchBimiFile(tags.l, 65536) : null,
    tags.a ? fetchBimiFile(tags.a, 131072) : null,
  ]);
  let logoSvg = null;
  if (logoFile) {
    const logoIssues = [];
    const check = { fetched: !logoFile.error, error: logoFile.error || null, contentType: logoFile.contentType || null, bytes: null, preview: null, issues: logoIssues };
    if (!logoFile.error) {
      logoSvg = logoFile.body;
      check.bytes = Buffer.byteLength(logoSvg);
      if (!/^image\/svg\+xml\b/i.test(check.contentType)) {
        logoIssues.push({ severity: "medium", message: `The logo is served as "${check.contentType || "no content type"}" instead of image/svg+xml.` });
      }
      const { errors, warnings } = validateBimiSvg(logoSvg);
      for (const message of errors) logoIssues.push({ severity: "high", message: `SVG Tiny PS: ${message}` });
      for (const message of warnings) logoIssues.push({ severity: "medium", message });
      // An SVG shown through <img> cannot run script, and a data URL keeps the logo host from seeing the visitor.
      if (!errors.length || errors.every((message) => !/root element/.test(message))) {
        check.preview = `data:image/svg+xml;base64,${Buffer.from(logoSvg).toString("base64")}`;
      }
    } else {
      logoIssues.push({ severity: "high", message: `The logo could not be fetched: ${logoFile.error}` });
    }
    result.logoCheck = check;
    issues.push(...logoIssues);
  }
  if (certificateFile) {
    if (certificateFile.error) {
      result.certificateCheck = { error: certificateFile.error, issues: [] };
      issues.push({ severity: "high", message: `The mark certificate could not be fetched: ${certificateFile.error}` });
    } else {
      result.certificateCheck = analyzeBimiCertificate(certificateFile.body, domain, logoSvg);
      if (result.certificateCheck.error) issues.push({ severity: "high", message: result.certificateCheck.error });
      else issues.push(...result.certificateCheck.issues);
    }
  }
  return result;
}

// BIMI is only honored when DMARC is enforced for all mail.
function addBimiDmarcIssues(bimi, dmarc) {
  if (!bimi?.found || dmarc?.error) return;
  const policy = dmarc?.policy;
  const pct = dmarc?.tags?.pct === undefined ? 100 : Number(dmarc.tags.pct);
  const subdomainPolicy = String(dmarc?.tags?.sp || "").toLowerCase();
  let message = null;
  if (!dmarc?.found) message = "BIMI requires a DMARC record; this domain has none.";
  else if (policy !== "quarantine" && policy !== "reject") message = `BIMI requires DMARC p=quarantine or p=reject; this domain uses p=${policy || "none"}.`;
  else if (pct < 100) message = `BIMI requires DMARC to apply to all mail; pct=${pct} is set.`;
  else if (subdomainPolicy === "none") message = "BIMI requires subdomains to be protected too; sp=none is set.";
  bimi.dmarcReady = !message;
  if (message) bimi.issues.unshift({ severity: "high", message });
}

async function emailCheck(request, url, response) {
  const rawName = queryInput(url, "name", 320, response);
  const rawSelectors = queryInput(url, "selectors", 200, response);
  if (rawName === null || rawSelectors === null) return;
  const input = rawName.trim();
  const inputWasEmail = input.includes("@");
  const domain = normalizeDomain(hostFromInput(inputWasEmail ? input.slice(input.lastIndexOf("@") + 1) : input));
  if (!domain) {
    sendJson(response, 400, { error: "Enter a domain name or an email address." });
    return;
  }
  const extraSelectors = [...new Set(rawSelectors.split(/[\s,]+/).map((value) => value.trim().toLowerCase()).filter(Boolean))];
  if (extraSelectors.length > 5 || extraSelectors.some((value) => !/^[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63}){0,3}$/.test(value))) {
    sendJson(response, 400, { error: "Enter up to five DKIM selectors (letters, numbers, hyphens and underscores)." });
    return;
  }
  const user = currentUser(request);
  const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
  if (!acquireHeavyJob("emailCheck")) {
    sendJson(response, 503, { error: "The server is busy with other email checks. Try again shortly." });
    return;
  }
  try {
    const started = Date.now();
    const settle = (promise) => promise.catch((error) => ({ error: error.name === "TimeoutError" ? "The DNS provider timed out." : "The check could not be completed." }));
    let mxRecords = [];
    let nullMx = false;
    let implicitMx = false;
    try {
      const mxData = await queryDohDns(domain, "MX");
      mxRecords = mxData.answers
        .filter((answer) => answer.type === 15 || answer.typeName === "MX")
        .map((answer) => {
          const [priority, host] = String(answer.data).split(/\s+/);
          return { priority: Number(priority), host: String(host || "").replace(/\.$/, "").toLowerCase() };
        })
        .sort((left, right) => left.priority - right.priority || left.host.localeCompare(right.host));
      nullMx = mxRecords.length === 1 && (!mxRecords[0].host || mxRecords[0].host === ".");
      if (!mxRecords.length) {
        implicitMx = true;
        mxRecords = [{ priority: 0, host: domain }];
      }
    } catch (error) {
      mxRecords = [];
    }
    if (nullMx) mxRecords = [];
    const resolved = await Promise.all(mxRecords.slice(0, 10).map(async (record) => {
      let addresses = [];
      try {
        const [v4, v6] = await Promise.all(["A", "AAAA"].map((type) => queryDohDns(record.host, type).then(
          (data) => data.answers.filter((answer) => answer.type === (type === "A" ? 1 : 28) || answer.typeName === type).map((answer) => answer.data),
          () => [],
        )));
        addresses = [...v4, ...v6];
      } catch {
        addresses = [];
      }
      return { ...record, addresses, provider: identifyMailProvider(record.host, "mx") };
    }));
    const smtpTargets = resolved
      .filter((record) => record.addresses.length)
      .slice(0, 3)
      .map((record) => ({ host: record.host, address: record.addresses.find((address) => isIP(address) === 4 && isScannableAddress(address, allowLocal)) }));
    const selectors = [...extraSelectors.map((selector) => [selector, "Your selector"]), ...dkimSelectors.filter(([selector]) => !extraSelectors.includes(selector))];
    const [smtp, spf, dmarc, mtaSts, tlsRpt, bimi, dkimResults, ptrLookups] = await Promise.all([
      Promise.all(smtpTargets.map((target) => target.address
        ? testSmtpStartTls(target.host, target.address)
        : Promise.resolve({ host: target.host, address: null, error: "No public IPv4 address to test (private or reserved addresses are not tested)." }))),
      settle(analyzeSpf(domain)),
      settle(analyzeDmarc(domain)),
      settle(analyzeMtaSts(domain, resolved.map((record) => record.host))),
      settle(analyzeTlsRpt(domain)),
      settle(analyzeBimi(domain)),
      Promise.all(selectors.map(([selector, provider]) => analyzeDkimSelector(domain, selector, provider).catch(() => null))),
      fetchPtrLookups(resolved.flatMap((record) => record.addresses)),
    ]);
    addBimiDmarcIssues(bimi, dmarc);
    const spfIncludes = (spf.tree || []).filter((node) => node.via).map((node) => node.name);
    const providers = {
      inbound: [...new Set(resolved.map((record) => record.provider).filter(Boolean))],
      outbound: [...new Set(spfIncludes.map((name) => identifyMailProvider(name, "spf")).filter(Boolean))],
      spfIncludes,
    };
    for (const result of smtp) {
      result.issues = [];
      if (result.error) continue;
      if (!result.starttls) result.issues.push({ severity: "high", message: "STARTTLS is not offered, so mail to this server travels unencrypted." });
      if (result.tls && !result.tls.authorized) result.issues.push({ severity: "medium", message: `The certificate is not trusted (${result.tls.authorizationError}). MTA-STS and DANE senders will refuse it.` });
      if (result.tls && !result.tls.nameMatches) result.issues.push({ severity: "medium", message: `The certificate does not match ${result.host}.` });
      if (result.tls?.daysRemaining !== null && result.tls?.daysRemaining !== undefined && result.tls.daysRemaining < 14) {
        result.issues.push({ severity: result.tls.daysRemaining < 0 ? "high" : "medium", message: result.tls.daysRemaining < 0 ? "The certificate has expired." : `The certificate expires in ${result.tls.daysRemaining} days.` });
      }
      if (result.tls && /^TLSv1(\.1)?$/.test(result.tls.protocol || "")) result.issues.push({ severity: "medium", message: `Only ${result.tls.protocol} was negotiated; TLS 1.2 or newer is expected.` });
    }
    const ratedIssues = [
      ...smtp.flatMap((result) => result.issues || []), ...(spf.issues || []), ...(dmarc.issues || []), ...(mtaSts.issues || []),
      ...(tlsRpt.issues || []), ...dkimResults.filter(Boolean).flatMap((record) => record.issues || []), ...(bimi.issues || []),
    ];
    const severityCount = (level) => ratedIssues.filter((issue) => issue.severity === level).length;
    const emailScore = Math.max(0, 100 - severityCount("high") * 15 - severityCount("medium") * 6 - severityCount("low") * 2);
    recordDomainRating("email", domain, gradeForScore(emailScore), emailScore,
      `${severityCount("high")} serious, ${severityCount("medium") + severityCount("low")} other${dmarc.policy ? ` · DMARC p=${dmarc.policy}` : dmarc.found ? "" : " · no DMARC"}`);
    sendJson(response, 200, {
      domain,
      inputWasEmail,
      mx: { records: resolved, nullMx, implicit: implicitMx },
      providers,
      smtp,
      spf,
      dmarc,
      dkim: { checked: selectors.length, records: dkimResults.filter(Boolean) },
      mtaSts,
      tlsRpt,
      bimi,
      ptrLookups,
      durationMs: Date.now() - started,
    });
  } catch (error) {
    console.error("Email check failed:", error);
    sendJson(response, 500, { error: "Unable to complete the email check." });
  } finally {
    releaseHeavyJob("emailCheck");
  }
}

async function emailHeadersCheck(request, response) {
  const body = await readAuthBody(request, response, 262144 + 1024);
  if (!body) return;
  const raw = typeof body.headers === "string" ? body.headers : "";
  if (!raw.trim()) {
    sendJson(response, 400, { error: "Paste the message headers." });
    return;
  }
  try {
    const result = analyzeEmailHeaders(raw.slice(0, 262144));
    const addresses = [...new Set(result.hops.map((hop) => hop.ip).filter((address) => address && isPublicAddress(address)))].slice(0, 20);
    const [ptrLookups, geolocations] = await Promise.all([fetchPtrLookups(addresses), fetchIpGeolocations(addresses)]);
    sendJson(response, 200, { ...result, ptrLookups, geolocations });
  } catch (error) {
    if (error.statusCode) sendJson(response, error.statusCode, { error: error.message });
    else {
      console.error("Header analysis failed:", error);
      sendJson(response, 500, { error: "Unable to analyze the headers." });
    }
  }
}

async function dmarcSourceLookup(request, response) {
  const body = await readAuthBody(request, response, 32768);
  if (!body) return;
  const ips = Array.isArray(body.ips) ? [...new Set(body.ips.filter((value) => typeof value === "string" && isPublicAddress(value.trim())).map((value) => value.trim()))].slice(0, 300) : [];
  const ptrLookups = await fetchPtrLookups(ips);
  const sources = Object.fromEntries(ips.map((address) => {
    const names = ptrLookups[address]?.answers?.map((name) => String(name).replace(/\.$/, "")) || [];
    const provider = names.map((name) => identifyMailProvider(name, "mx") || identifyMailProvider(name, "spf")).find(Boolean) || null;
    return [address, { ptr: names.slice(0, 3), provider }];
  }));
  sendJson(response, 200, { sources });
}

async function recordImport(url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  const domain = normalizeDomain(hostFromInput(rawName));
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name." });
    return;
  }
  const txt = (name, pattern) => queryTxtRecords(name).then((data) => data.records.filter((record) => pattern.test(record.trim())), () => []);
  const [spf, dmarc, mtaSts, tlsRpt, bimi, mx] = await Promise.all([
    txt(domain, /^v=spf1\b/i),
    txt(`_dmarc.${domain}`, /^v=DMARC1\b/i),
    txt(`_mta-sts.${domain}`, /^v=STSv1\b/i),
    txt(`_smtp._tls.${domain}`, /^v=TLSRPTv1\b/i),
    txt(`default._bimi.${domain}`, /^v=BIMI1\b/i),
    queryDohDns(domain, "MX").then((data) => data.answers
      .filter((answer) => answer.type === 15 || answer.typeName === "MX")
      .map((answer) => String(answer.data).split(/\s+/)[1]?.replace(/\.$/, "").toLowerCase())
      .filter(Boolean), () => []),
  ]);
  sendJson(response, 200, { domain, spf, dmarc: dmarc[0] || null, mtaSts: mtaSts[0] || null, tlsRpt: tlsRpt[0] || null, bimi: bimi[0] || null, mx });
}

const bulkDomainLimits = { domains: 50, concurrency: 5, perDomainMs: 30000 };

function withTimeout(promise, timeoutMs, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(message), { name: "TimeoutError" })), timeoutMs);
    }),
  ]).finally(() => clearTimeout(timer));
}

async function checkDomainSummary(domain, allowLocal) {
  const answers = (type, code) => queryDohDns(domain, type).then((data) => data.answers.filter((answer) => answer.type === code || answer.typeName === type).map((answer) => answer.data), () => []);
  const [mxAnswers, addresses, spf, dmarc] = await Promise.all([
    answers("MX", 15),
    answers("A", 1),
    analyzeSpf(domain).catch(() => null),
    analyzeDmarc(domain).catch(() => null),
  ]);
  const mxHosts = mxAnswers.map((value) => String(value).split(/\s+/)[1]?.replace(/\.$/, "").toLowerCase()).filter((host) => host && host !== ".");
  const address = addresses.find((value) => isScannableAddress(value, allowLocal));
  const [handshake, blocklists] = await Promise.all([
    address ? runTlsHandshake(domain, address, 443) : Promise.resolve(null),
    checkBlocklists({ addresses: addresses.filter((value) => isPublicAddress(value)).slice(0, 1), domain }).catch(() => null),
  ]);
  const leaf = handshake?.certificateChain?.[0];
  const validTo = leaf?.validTo ? new Date(leaf.validTo) : null;
  const listedOn = blocklists ? [
    ...(blocklists.domain?.lists || []).filter((list) => list.status === "listed").map((list) => list.name),
    ...(blocklists.ips || []).flatMap((entry) => entry.lists.filter((list) => list.status === "listed").map((list) => `${list.name} (${entry.address})`)),
  ] : null;
  return {
    domain,
    address: address || addresses[0] || null,
    mx: { count: mxHosts.length, hosts: mxHosts.slice(0, 3), providers: [...new Set(mxHosts.map((host) => identifyMailProvider(host, "mx")).filter(Boolean))] },
    spf: spf ? { found: spf.found, all: spf.all || null, lookups: spf.lookups ?? null, issues: spf.issues?.length || 0 } : null,
    dmarc: dmarc ? { found: dmarc.found, policy: dmarc.policy || null } : null,
    certificate: !address ? { error: "No address" } : handshake?.handshake ? {
      authorized: handshake.authorized,
      validTo: validTo && !Number.isNaN(validTo.getTime()) ? validTo.toISOString() : null,
      daysRemaining: validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null,
      issuer: leaf?.issuer || null,
    } : { error: handshake?.error || "No TLS on port 443" },
    blocklist: listedOn ? { listed: listedOn.length, lists: listedOn } : null,
  };
}

async function bulkDomainCheck(request, response) {
  const body = await readAuthBody(request, response, 16384);
  if (!body) return;
  const entries = String(typeof body.domains === "string" ? body.domains : "").split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean);
  const domains = [...new Set(entries.map((value) => normalizeDomain(hostFromInput(value))).filter(Boolean))];
  const invalid = entries.filter((value) => !normalizeDomain(hostFromInput(value)));
  if (!domains.length) {
    sendJson(response, 400, { error: "Enter at least one domain name." });
    return;
  }
  if (domains.length > bulkDomainLimits.domains) {
    sendJson(response, 400, { error: `Enter at most ${bulkDomainLimits.domains} domains.` });
    return;
  }
  if (!acquireHeavyJob("bulkDomains")) {
    sendJson(response, 503, { error: "A bulk domain check is already running. Try again shortly." });
    return;
  }
  const user = currentUser(request);
  const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
  const started = Date.now();
  try {
    const rows = new Array(domains.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(bulkDomainLimits.concurrency, domains.length) }, async () => {
      while (next < domains.length) {
        const index = next;
        next += 1;
        try {
          rows[index] = await withTimeout(checkDomainSummary(domains[index], allowLocal), bulkDomainLimits.perDomainMs, "The checks took too long.");
        } catch (error) {
          rows[index] = { domain: domains[index], error: error.name === "TimeoutError" ? error.message : "The checks could not be completed." };
        }
      }
    }));
    sendJson(response, 200, { rows, invalid: invalid.slice(0, 20), durationMs: Date.now() - started });
  } finally {
    releaseHeavyJob("bulkDomains");
  }
}

// Optional MTA-STS policy served at /.well-known/mta-sts.txt when mta-sts.<domain> points to this server.
function validateMtaStsPolicy(text) {
  const lines = String(text || "").replace(/\r\n?/g, "\n").split("\n").map((line) => line.trim()).filter(Boolean);
  const fields = { mx: [] };
  for (const line of lines) {
    const match = line.match(/^([a-z_]+)\s*:\s*(.+)$/i);
    if (!match) return { error: `Invalid line: ${line.slice(0, 80)}` };
    const key = match[1].toLowerCase();
    if (key === "mx") fields.mx.push(match[2].toLowerCase());
    else fields[key] = match[2];
  }
  if (fields.version !== "STSv1") return { error: "The policy must contain version: STSv1." };
  if (!["enforce", "testing", "none"].includes(fields.mode)) return { error: "mode must be enforce, testing or none." };
  const maxAge = Number(fields.max_age);
  if (!Number.isInteger(maxAge) || maxAge < 86400 || maxAge > 31557600) return { error: "max_age must be between 86400 (1 day) and 31557600 (1 year) seconds." };
  if (fields.mode !== "none" && !fields.mx.length) return { error: "Add at least one mx: line." };
  if (fields.mx.some((mx) => !/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(mx))) return { error: "Each mx: must be a host name, optionally starting with *." };
  return { policy: ["version: STSv1", `mode: ${fields.mode}`, ...fields.mx.map((mx) => `mx: ${mx}`), `max_age: ${maxAge}`].join("\r\n") + "\r\n" };
}

function readMtaStsPolicy() {
  return database.prepare("SELECT value FROM app_settings WHERE key = 'mta_sts_policy'").get()?.value || null;
}

function serveMtaStsPolicy(request, response) {
  const policy = readMtaStsPolicy();
  if (!policy) return false;
  response.writeHead(200, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "public, max-age=300",
    "x-content-type-options": "nosniff",
  });
  response.end(request.method === "HEAD" ? undefined : policy);
  return true;
}

function handleAdminMtaSts(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    sendJson(response, 200, { policy: readMtaStsPolicy() });
    return;
  }
  if (!["PUT", "DELETE"].includes(request.method)) {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  if (request.method === "DELETE") {
    database.prepare("DELETE FROM app_settings WHERE key = 'mta_sts_policy'").run();
    recordAdminLog("audit", request, "MTA-STS policy removed", null, 200, admin.username);
    sendJson(response, 200, { policy: null });
    return;
  }
  void readAuthBody(request, response, 8192).then((body) => {
    if (!body) return;
    const result = validateMtaStsPolicy(body.policy);
    if (result.error) {
      sendJson(response, 400, { error: result.error });
      return;
    }
    database.prepare(`
      INSERT INTO app_settings (key, value) VALUES ('mta_sts_policy', ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(result.policy);
    recordAdminLog("audit", request, "MTA-STS policy saved", result.policy.split("\r\n")[1], 200, admin.username);
    sendJson(response, 200, { policy: result.policy });
  });
}

const monitorKinds = {
  website: "Website up",
  certificate: "Certificate",
  dns: "DNS records",
  email: "Email security",
  blocklist: "Blocklists",
  ct: "New certificates (CT logs)",
};
const monitorIntervals = [1, 6, 12, 24];
const monitorLimits = { perUser: { user: 25, admin: 100 }, events: 50, concurrency: 3, checkMs: 90000, manualRunGapMs: 60000 };
const monitorDnsTypes = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"];
const monitorRuns = new Set();
const monitorManualRuns = new Map();

function normalizeMonitorTarget(kind, raw) {
  const value = String(raw || "").trim().slice(0, 2048);
  if (!value) return null;
  if (kind === "website") {
    try {
      const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
      if (url.username || url.password || !["http:", "https:"].includes(url.protocol)) return null;
      const host = url.hostname.replace(/^\[|\]$/g, "");
      return isIP(host) || normalizeDomain(host) ? url.href : null;
    } catch {
      return null;
    }
  }
  if (kind === "certificate") {
    const match = value.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").match(/^(\[[0-9a-f:.]+\]|[^:]+)(?::(\d{1,5}))?$/i);
    if (!match) return null;
    const host = match[1].replace(/^\[|\]$/g, "");
    const port = Number(match[2] || 443);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    const name = isIP(host) ? host : normalizeDomain(host);
    if (!name) return null;
    return `${isIP(name) === 6 ? `[${name}]` : name}:${port}`;
  }
  const host = hostFromInput(value).replace(/^\[|\]$/g, "");
  if (kind === "blocklist" && isIP(host)) return isIP(host) === 4 && isPublicAddress(host) ? host : null;
  return normalizeDomain(host);
}

async function runMonitorCheck(kind, target, allowLocal) {
  if (kind === "website") {
    const { hops, final } = await followWebRedirects(new URL(target), allowLocal, { maxBytes: 65536 });
    const last = hops.at(-1);
    if (!final || last?.error) {
      return { status: "fail", summary: `Down: ${last?.error || "no response"}`, snapshot: { up: false } };
    }
    const status = final.response.status;
    const totalMs = hops.reduce((sum, hop) => sum + (hop.timeMs || 0), 0);
    return {
      status: status >= 500 ? "fail" : status >= 400 ? "warn" : "ok",
      summary: `HTTP ${status} in ${totalMs} ms${hops.length > 1 ? ` via ${hops.length - 1} redirect(s) to ${final.url.href}` : ""}`,
      snapshot: { up: status < 500, status, finalUrl: final.url.href },
    };
  }
  if (kind === "certificate") {
    const separator = target.lastIndexOf(":");
    const host = target.slice(0, separator).replace(/^\[|\]$/g, "");
    const port = Number(target.slice(separator + 1));
    const address = await resolveWebAddress(host, allowLocal);
    if (!address) return { status: "fail", summary: `${host} does not resolve to an address that can be checked.`, snapshot: { reachable: false } };
    const result = await runTlsHandshake(host, address, port);
    if (!result.handshake) return { status: "fail", summary: result.error || "The TLS handshake failed.", snapshot: { reachable: false } };
    const leaf = result.certificateChain[0] || {};
    const validTo = leaf.validTo ? new Date(leaf.validTo) : null;
    const days = validTo ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null;
    const issuer = leaf.issuer?.match(/O=([^,]+)/)?.[1] || leaf.issuer?.match(/CN=([^,]+)/)?.[1] || "unknown issuer";
    const status = !result.authorized || (days !== null && days < 0) ? "fail" : days !== null && days < 14 ? "warn" : "ok";
    const trust = result.authorized ? "" : ` · not trusted (${result.authorizationError})`;
    return {
      status,
      summary: `${days === null ? "Unknown expiry" : days < 0 ? "Expired" : `Expires in ${days} days`} (${validTo ? validTo.toISOString().slice(0, 10) : "?"}) · ${issuer}${trust}`,
      snapshot: { reachable: true, fingerprint: leaf.fingerprint256 || null, trusted: result.authorized, expiresSoon: days !== null && days < 14 },
    };
  }
  if (kind === "dns") {
    const results = await Promise.all(monitorDnsTypes.map((type) => queryDohDns(target, type).then(
      (data) => [type, data.status, [...new Set(data.answers.filter((answer) => answer.typeName === type || answer.type === dnsTypeCodes[type]).map((answer) => String(answer.data)))].sort()],
      () => [type, null, null],
    )));
    if (results.every(([, status]) => status === null)) throw new Error("The DNS provider did not answer.");
    if (results.some(([, status]) => status === 3)) return { status: "fail", summary: "The domain does not exist (NXDOMAIN).", snapshot: { exists: false } };
    const snapshot = Object.fromEntries(results.filter(([, , answers]) => answers).map(([type, , answers]) => [type, answers]));
    return {
      status: "ok",
      summary: results.filter(([, , answers]) => answers?.length).map(([type, , answers]) => `${type} ${answers.length}`).join(" · ") || "No records",
      snapshot,
    };
  }
  if (kind === "email") {
    const [mxAnswers, spf, dmarc, mtaSts] = await Promise.all([
      queryDohDns(target, "MX").then((data) => data.answers.filter((answer) => answer.type === 15 || answer.typeName === "MX").map((answer) => String(answer.data).toLowerCase()).sort(), () => null),
      analyzeSpf(target).catch(() => null),
      analyzeDmarc(target).catch(() => null),
      analyzeMtaSts(target, []).catch(() => null),
    ]);
    const problems = [];
    if (!dmarc?.found) problems.push("no DMARC");
    else if (dmarc.policy === "none") problems.push("DMARC p=none");
    if (!spf?.found) problems.push("no SPF");
    else if (spf.lookups === null || spf.lookups > 10) problems.push("SPF permerror");
    return {
      status: problems.some((problem) => /^no |permerror/.test(problem)) ? "fail" : problems.length ? "warn" : "ok",
      summary: [`MX ${mxAnswers?.length ?? "?"}`, spf?.found ? `SPF ${spf.all || "?"} ${spf.lookups ?? "?"}/10` : "no SPF", dmarc?.found ? `DMARC p=${dmarc.policy || "?"}` : "no DMARC", mtaSts?.found ? `MTA-STS ${mtaSts.policy?.mode || "?"}` : null].filter(Boolean).join(" · "),
      snapshot: { mx: mxAnswers, spf: spf?.record || null, dmarc: dmarc?.record || null, mtaSts: mtaSts?.policy?.mode || null },
    };
  }
  if (kind === "ct") {
    const { source, certificates } = await fetchCertificateIssuances(target);
    const recent = certificates.sort().reverse().slice(0, 400);
    return {
      status: "ok",
      summary: `${certificates.length} unexpired certificate(s) in CT logs (${source})${recent[0] ? `; newest ${recent[0].split("|")[0]} by ${recent[0].split("|")[2] || "unknown issuer"}` : ""}`,
      snapshot: { certificates: recent },
    };
  }
  if (kind === "blocklist") {
    let addresses = [target];
    let domain = null;
    if (!isIP(target)) {
      domain = target;
      addresses = await queryDohDns(target, "A").then((data) => data.answers.filter((answer) => answer.type === 1 || answer.typeName === "A").map((answer) => answer.data), () => []);
    }
    const result = await checkBlocklists({ addresses: addresses.slice(0, 2), domain });
    const listed = [
      ...(result.domain?.lists || []).filter((list) => list.status === "listed").map((list) => `${list.name} (${domain})`),
      ...result.ips.flatMap((entry) => entry.lists.filter((list) => list.status === "listed").map((list) => `${list.name} (${entry.address})`)),
    ].sort();
    const checked = (result.domain?.checked || 0) + result.ips.reduce((sum, entry) => sum + entry.checked, 0);
    return {
      status: listed.length ? "fail" : "ok",
      summary: listed.length ? `Listed on ${listed.join(", ")}` : `Not listed (${checked} lists checked)`,
      snapshot: { listed },
    };
  }
  throw new Error("Unknown monitor type.");
}

function describeSnapshotChanges(kind, before, after) {
  if (!before || !after) return [];
  if (kind === "ct") {
    // Only newly logged certificates matter; expired ones simply drop out of the list.
    const known = new Set(before.certificates || []);
    return (after.certificates || []).filter((entry) => !known.has(entry)).slice(0, 20).map((entry) => {
      const [date, names, issuer] = entry.split("|");
      return `New certificate ${date} by ${issuer || "unknown issuer"} for ${names.split(",").slice(0, 6).join(", ")}${names.split(",").length > 6 ? " …" : ""}`;
    });
  }
  const changes = [];
  for (const key of [...new Set([...Object.keys(before), ...Object.keys(after)])]) {
    const left = before[key];
    const right = after[key];
    if (JSON.stringify(left) === JSON.stringify(right)) continue;
    if (Array.isArray(left) || Array.isArray(right)) {
      const added = (right || []).filter((value) => !(left || []).includes(value));
      const removed = (left || []).filter((value) => !(right || []).includes(value));
      if (added.length) changes.push(`${key} added: ${added.join(", ")}`);
      if (removed.length) changes.push(`${key} removed: ${removed.join(", ")}`);
    } else if (kind === "certificate" && key === "fingerprint" && left && right) {
      changes.push("A new certificate is being served (renewed or replaced).");
    } else if (kind !== "certificate" || !["expiresSoon", "trusted", "reachable"].includes(key)) {
      changes.push(`${key}: ${left ?? "none"} → ${right ?? "none"}`);
    }
  }
  return changes.map((change) => change.slice(0, 500)).slice(0, 20);
}

function addMonitorEvent(monitorId, level, message) {
  database.prepare("INSERT INTO monitor_events (monitor_id, created_at, level, message) VALUES (?, ?, ?, ?)").run(monitorId, Date.now(), level, message.slice(0, 2000));
  database.prepare(`
    DELETE FROM monitor_events WHERE monitor_id = ? AND id NOT IN (
      SELECT id FROM monitor_events WHERE monitor_id = ? ORDER BY id DESC LIMIT ?
    )
  `).run(monitorId, monitorId, monitorLimits.events);
}

async function sendMonitorAlert(row, user, result, previousStatus, changes) {
  const config = getMailConfig(true);
  if (!config || !user.email) return "No alert email was sent (no email address on the account, or email is not configured).";
  const statusWords = { ok: "OK", warn: "Warning", fail: "Problem" };
  const subject = previousStatus && previousStatus !== result.status
    ? `${statusWords[result.status]}: ${monitorKinds[row.kind]} for ${row.target}`
    : `Changed: ${monitorKinds[row.kind]} for ${row.target}`;
  const text = [
    `Monitor: ${monitorKinds[row.kind]} — ${row.target}`,
    previousStatus && previousStatus !== result.status ? `Status: ${statusWords[previousStatus] || previousStatus} → ${statusWords[result.status]}` : `Status: ${statusWords[result.status]}`,
    `Result: ${result.summary}`,
    ...(changes.length ? ["", "Changes:", ...changes.map((change) => `- ${change}`)] : []),
    "",
    `Checked ${new Date().toUTCString()}. Manage or pause this monitor on the Monitors page.`,
  ].join("\n");
  try {
    await sendMail(config, { from: config.from, fromName: config.fromName, to: user.email, subject, text });
    return `Alert sent to ${user.email}.`;
  } catch (error) {
    return `The alert email could not be sent: ${String(error.message).slice(0, 200)}`;
  }
}

async function runMonitor(row) {
  if (monitorRuns.has(row.id)) return null;
  monitorRuns.add(row.id);
  try {
    const user = database.prepare("SELECT id, username, role, active, email FROM users WHERE id = ?").get(row.user_id);
    const now = Date.now();
    database.prepare("UPDATE monitors SET next_run_at = ? WHERE id = ?").run(now + row.interval_hours * 3600000, row.id);
    if (!user?.active) return null;
    const allowLocal = Boolean(getPortScanPolicy().localScanByRole[user.role]);
    let result;
    try {
      result = await withTimeout(runMonitorCheck(row.kind, row.target, allowLocal), monitorLimits.checkMs, "The check took too long.");
    } catch (error) {
      result = { status: "fail", summary: `The check failed: ${String(error.message).slice(0, 200)}`, snapshot: null };
    }
    let previousSnapshot = null;
    try {
      previousSnapshot = row.last_snapshot ? JSON.parse(row.last_snapshot) : null;
    } catch {
      previousSnapshot = null;
    }
    const firstRun = !row.last_run_at;
    const changes = firstRun ? [] : describeSnapshotChanges(row.kind, previousSnapshot, result.snapshot);
    const statusChanged = !firstRun && row.last_status !== result.status;
    if (firstRun) addMonitorEvent(row.id, result.status, `First check: ${result.summary}`);
    else if (statusChanged) addMonitorEvent(row.id, result.status, `Status changed to ${result.status}: ${result.summary}`);
    if (changes.length) addMonitorEvent(row.id, "change", changes.join("\n"));
    database.prepare(`
      UPDATE monitors SET last_run_at = ?, last_status = ?, last_summary = ?, last_snapshot = COALESCE(?, last_snapshot),
        last_change_at = CASE WHEN ? THEN ? ELSE last_change_at END
      WHERE id = ?
    `).run(Date.now(), result.status, result.summary.slice(0, 1000), result.snapshot ? JSON.stringify(result.snapshot) : null,
      statusChanged || changes.length ? 1 : 0, Date.now(), row.id);
    if ((statusChanged || changes.length) && row.notify) {
      addMonitorEvent(row.id, "alert", await sendMonitorAlert(row, user, result, row.last_status, changes));
    }
    return result;
  } finally {
    monitorRuns.delete(row.id);
  }
}

let monitorTickRunning = false;
async function runDueMonitors() {
  if (monitorTickRunning) return;
  monitorTickRunning = true;
  try {
    const due = database.prepare("SELECT * FROM monitors WHERE enabled = 1 AND next_run_at <= ? ORDER BY next_run_at LIMIT 12").all(Date.now());
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(monitorLimits.concurrency, due.length) }, async () => {
      while (next < due.length) {
        const row = due[next];
        next += 1;
        await runMonitor(row).catch((error) => console.error("Monitor failed:", error.message));
      }
    }));
  } finally {
    monitorTickRunning = false;
  }
}

function describeMonitor(row, events = []) {
  return {
    id: row.id,
    kind: row.kind,
    kindLabel: monitorKinds[row.kind] || row.kind,
    target: row.target,
    intervalHours: row.interval_hours,
    notify: Boolean(row.notify),
    enabled: Boolean(row.enabled),
    createdAt: new Date(row.created_at).toISOString(),
    nextRunAt: row.enabled ? new Date(row.next_run_at).toISOString() : null,
    lastRunAt: row.last_run_at ? new Date(row.last_run_at).toISOString() : null,
    lastChangeAt: row.last_change_at ? new Date(row.last_change_at).toISOString() : null,
    status: row.last_status || "pending",
    summary: row.last_summary || null,
    events: events.map((event) => ({ at: new Date(event.created_at).toISOString(), level: event.level, message: event.message })),
  };
}

async function handleMonitors(request, response, url) {
  if (!checkFeatureAccess(request, response, "monitors", true)) return;
  const user = currentUser(request);
  const match = url.pathname.match(/^\/api\/monitors(?:\/(\d+))?(\/run)?$/);
  if (!match) {
    sendJson(response, 404, { error: "Not found." });
    return;
  }
  const id = match[1] ? Number(match[1]) : null;
  const own = id ? database.prepare("SELECT * FROM monitors WHERE id = ? AND user_id = ?").get(id, user.id) : null;
  if (id && !own) {
    sendJson(response, 404, { error: "Monitor not found." });
    return;
  }
  const account = database.prepare("SELECT email FROM users WHERE id = ?").get(user.id);
  const context = { mailEnabled: Boolean(getMailConfig()), email: account?.email || null, kinds: monitorKinds, intervals: monitorIntervals, limit: monitorLimits.perUser[user.role] || 25 };
  if (!id && request.method === "GET") {
    const rows = database.prepare("SELECT * FROM monitors WHERE user_id = ? ORDER BY id").all(user.id);
    const eventsFor = database.prepare("SELECT * FROM monitor_events WHERE monitor_id = ? ORDER BY id DESC LIMIT 10");
    sendJson(response, 200, { ...context, monitors: rows.map((row) => describeMonitor(row, eventsFor.all(row.id))) });
    return;
  }
  if (!id && request.method === "POST") {
    const body = await readAuthBody(request, response, 8192);
    if (!body) return;
    const kind = Object.hasOwn(monitorKinds, body.kind) ? body.kind : null;
    const target = kind ? normalizeMonitorTarget(kind, body.target) : null;
    const intervalHours = monitorIntervals.includes(Number(body.intervalHours)) ? Number(body.intervalHours) : null;
    if (!kind) return sendJson(response, 400, { error: "Choose what to monitor." });
    if (!target) return sendJson(response, 400, { error: kind === "website" ? "Enter a valid URL or domain." : kind === "certificate" ? "Enter a host name, optionally with :port." : kind === "blocklist" ? "Enter a domain or a public IPv4 address." : "Enter a valid domain name." });
    if (!intervalHours) return sendJson(response, 400, { error: "Choose how often to check." });
    const count = database.prepare("SELECT COUNT(*) AS count FROM monitors WHERE user_id = ?").get(user.id).count;
    if (count >= context.limit) return sendJson(response, 400, { error: `You can have up to ${context.limit} monitors.` });
    if (database.prepare("SELECT 1 FROM monitors WHERE user_id = ? AND kind = ? AND target = ?").get(user.id, kind, target)) {
      return sendJson(response, 400, { error: "You already monitor this." });
    }
    const now = Date.now();
    const created = database.prepare(`
      INSERT INTO monitors (user_id, kind, target, interval_hours, notify, enabled, created_at, next_run_at)
      VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    `).run(user.id, kind, target, intervalHours, body.notify === false ? 0 : 1, now, now + intervalHours * 3600000);
    const row = database.prepare("SELECT * FROM monitors WHERE id = ?").get(Number(created.lastInsertRowid));
    await runMonitor(row).catch(() => null);
    const fresh = database.prepare("SELECT * FROM monitors WHERE id = ?").get(row.id);
    sendJson(response, 201, describeMonitor(fresh, database.prepare("SELECT * FROM monitor_events WHERE monitor_id = ? ORDER BY id DESC LIMIT 10").all(row.id)));
    return;
  }
  if (id && match[2] && request.method === "POST") {
    const last = monitorManualRuns.get(id) || 0;
    if (Date.now() - last < monitorLimits.manualRunGapMs) return sendJson(response, 429, { error: "Wait a minute before running this monitor again." });
    monitorManualRuns.set(id, Date.now());
    await runMonitor(own);
    const fresh = database.prepare("SELECT * FROM monitors WHERE id = ?").get(id);
    sendJson(response, 200, describeMonitor(fresh, database.prepare("SELECT * FROM monitor_events WHERE monitor_id = ? ORDER BY id DESC LIMIT 10").all(id)));
    return;
  }
  if (id && !match[2] && request.method === "PATCH") {
    const body = await readAuthBody(request, response, 4096);
    if (!body) return;
    const enabled = typeof body.enabled === "boolean" ? (body.enabled ? 1 : 0) : own.enabled;
    const notify = typeof body.notify === "boolean" ? (body.notify ? 1 : 0) : own.notify;
    const intervalHours = body.intervalHours === undefined ? own.interval_hours : Number(body.intervalHours);
    if (!monitorIntervals.includes(intervalHours)) return sendJson(response, 400, { error: "Choose how often to check." });
    const nextRunAt = enabled && (!own.enabled || intervalHours !== own.interval_hours) ? Date.now() + 60000 : own.next_run_at;
    database.prepare("UPDATE monitors SET enabled = ?, notify = ?, interval_hours = ?, next_run_at = ? WHERE id = ?").run(enabled, notify, intervalHours, nextRunAt, id);
    const fresh = database.prepare("SELECT * FROM monitors WHERE id = ?").get(id);
    sendJson(response, 200, describeMonitor(fresh, database.prepare("SELECT * FROM monitor_events WHERE monitor_id = ? ORDER BY id DESC LIMIT 10").all(id)));
    return;
  }
  if (id && !match[2] && request.method === "DELETE") {
    database.prepare("DELETE FROM monitors WHERE id = ?").run(id);
    sendJson(response, 200, { deleted: true });
    return;
  }
  sendJson(response, 405, { error: "Method not allowed." });
}

setTimeout(() => {
  void runDueMonitors();
  setInterval(() => void runDueMonitors(), 60000).unref();
}, 20000).unref();

// ---------------------------------------------------------------- Reputation check

const protectiveResolvers = [
  { id: "quad9", label: "Quad9 (threat blocking)", endpoint: "https://dns.quad9.net/dns-query", format: "wire" },
  { id: "cloudflare-security", label: "Cloudflare for Families (malware)", endpoint: "https://security.cloudflare-dns.com/dns-query", format: "wire" },
  { id: "dns4eu", label: "DNS4EU protective", endpoint: "https://protective.joindns4.eu/dns-query", format: "wire" },
  { id: "cleanbrowsing", label: "CleanBrowsing Security", endpoint: "https://doh.cleanbrowsing.org/doh/security-filter/", format: "wire" },
];

// Free, keyless threat lists, downloaded on first use and cached for six hours.
const threatFeeds = [
  {
    id: "spamhaus-drop", label: "Spamhaus DROP (hijacked networks)", kind: "cidr",
    urls: ["https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json"],
    parse: (text) => text.split(/\r?\n/).flatMap((line) => {
      try {
        const entry = JSON.parse(line);
        return entry.cidr ? [[entry.cidr, entry.sblid ? `Spamhaus ${entry.sblid}` : "listed network"]] : [];
      } catch {
        return [];
      }
    }),
  },
  {
    id: "feodo", label: "abuse.ch Feodo Tracker (botnet C2)", kind: "ip",
    urls: ["https://feodotracker.abuse.ch/downloads/ipblocklist.json"],
    parse: (text) => {
      const entries = JSON.parse(text);
      return Array.isArray(entries) ? entries.filter((entry) => entry.ip_address).map((entry) => [entry.ip_address, `${entry.malware || "botnet"} C2${entry.port ? ` on port ${entry.port}` : ""}${entry.status ? ` (${entry.status})` : ""}`]) : [];
    },
  },
  {
    id: "urlhaus-hosts", label: "abuse.ch URLhaus (malware hosts)", kind: "host",
    // abuse.ch retired its keyless downloads on 21 October 2026 (they answer 410 Gone).
    // With URLHAUS_AUTH_KEY the official export is used; otherwise, or when that fails,
    // the free malware-filter mirror of URLhaus's online malware hosts.
    sources: () => [
      ...(process.env.URLHAUS_AUTH_KEY
        ? [[`https://urlhaus-api.abuse.ch/v2/files/exports/${encodeURIComponent(process.env.URLHAUS_AUTH_KEY)}/hostfile.txt`]]
        : []),
      ["https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"],
    ],
    parse: (text) => text.split(/\r?\n/).filter((line) => line && !line.startsWith("#"))
      .map((line) => line.trim().split(/\s+/).pop().toLowerCase()).filter(Boolean).map((host) => [host, "hosts malware downloads"]),
  },
  {
    id: "openphish", label: "OpenPhish (phishing)", kind: "host",
    urls: ["https://openphish.com/feed.txt"],
    parse: (text) => text.split(/\r?\n/).flatMap((line) => {
      try {
        return [[new URL(line.trim()).hostname.toLowerCase(), "active phishing page"]];
      } catch {
        return [];
      }
    }),
  },
];
const threatFeedLimits = { maxAgeMs: 6 * 3600000, retryMs: 15 * 60000, bytes: 32 * 1024 * 1024, timeoutMs: 20000 };
const threatFeedCache = new Map();

// A feed either combines all of its urls, or offers alternative sources tried in order.
async function downloadThreatFeed(feed) {
  let lastError = null;
  for (const urls of feed.sources ? feed.sources() : [feed.urls]) {
    try {
      return await downloadThreatFeedFrom(feed, urls);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

async function downloadThreatFeedFrom(feed, urls) {
  const entries = [];
  for (const url of urls) {
    const response = await fetch(url, { headers: { "user-agent": `BNGlookup/${appBuild.version} (+https://github.com/${appRepository})` }, signal: AbortSignal.timeout(threatFeedLimits.timeoutMs) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const length = Number(response.headers.get("content-length") || 0);
    if (length > threatFeedLimits.bytes) throw new Error("The list is too large.");
    const text = await response.text();
    if (text.length > threatFeedLimits.bytes) throw new Error("The list is too large.");
    entries.push(...feed.parse(text));
  }
  if (!entries.length) throw new Error("The list was empty.");
  const data = { count: entries.length, details: new Map(), networks: [] };
  if (feed.kind === "cidr") {
    data.list = new net.BlockList();
    for (const [cidr, detail] of entries) {
      const [address, prefix] = cidr.split("/");
      const family = isIP(address);
      if (!family || !/^\d+$/.test(prefix || "")) continue;
      data.list.addSubnet(address, Number(prefix), family === 4 ? "ipv4" : "ipv6");
      data.networks.push([address, Number(prefix), family, `${cidr} · ${detail}`]);
    }
  } else {
    for (const [key, detail] of entries) if (!data.details.has(key)) data.details.set(key, detail);
  }
  return data;
}

async function loadThreatFeed(feed) {
  const cached = threatFeedCache.get(feed.id);
  const now = Date.now();
  if (cached?.loading) return cached.loading;
  if (cached?.data && now - cached.loadedAt < threatFeedLimits.maxAgeMs) return cached;
  if (cached?.failedAt && now - cached.failedAt < threatFeedLimits.retryMs) return cached;
  const loading = downloadThreatFeed(feed).then(
    (data) => {
      const entry = { data, loadedAt: Date.now() };
      threatFeedCache.set(feed.id, entry);
      return entry;
    },
    (error) => {
      // Keep using an older copy when a refresh fails.
      const entry = { ...(cached || {}), loading: null, failedAt: Date.now(), error: String(error.message).slice(0, 80) };
      threatFeedCache.set(feed.id, entry);
      return entry;
    },
  );
  threatFeedCache.set(feed.id, { ...(cached || {}), loading });
  return loading;
}

async function threatFeedVerdicts(domain, addresses) {
  const hosts = [];
  if (domain) {
    const labels = domain.split(".");
    for (let index = 0; index < labels.length - 1; index += 1) hosts.push(labels.slice(index).join("."));
  }
  return Promise.all(threatFeeds.map(async (feed) => {
    const entry = await loadThreatFeed(feed);
    if (!entry?.data) return { source: feed.label, state: "error", detail: `The list could not be downloaded${entry?.error ? ` (${entry.error})` : ""}.` };
    const matches = [];
    if (feed.kind === "host") {
      for (const host of [...hosts, ...addresses]) if (entry.data.details.has(host)) matches.push(`${host} ${entry.data.details.get(host)}`);
    } else if (feed.kind === "ip") {
      for (const address of addresses) if (entry.data.details.has(address)) matches.push(`${address}: ${entry.data.details.get(address)}`);
    } else {
      for (const address of addresses) {
        const family = isIP(address);
        if (!family || !entry.data.list.check(address, family === 4 ? "ipv4" : "ipv6")) continue;
        const network = entry.data.networks.find(([base, prefix, networkFamily]) => {
          if (networkFamily !== family) return false;
          const single = new net.BlockList();
          single.addSubnet(base, prefix, family === 4 ? "ipv4" : "ipv6");
          return single.check(address, family === 4 ? "ipv4" : "ipv6");
        });
        matches.push(`${address} in ${network ? network[3] : "a listed network"}`);
      }
    }
    const age = Math.round((Date.now() - entry.loadedAt) / 60000);
    return matches.length
      ? { source: feed.label, state: "flagged", detail: matches.slice(0, 3).join("; ") }
      : { source: feed.label, state: "clean", detail: `Not listed (${entry.data.count.toLocaleString()} ${entry.data.count === 1 ? "entry" : "entries"}, updated ${age < 1 ? "just now" : age < 120 ? `${age} min ago` : `${Math.round(age / 60)} h ago`})` };
  }));
}
const sinkholeAddresses = new Set(["0.0.0.0", "127.0.0.1", "::", "::1"]);
const reputationKeys = {
  urlhaus: process.env.URLHAUS_AUTH_KEY || "",
  virustotal: process.env.VIRUSTOTAL_API_KEY || "",
  safeBrowsing: process.env.GOOGLE_SAFE_BROWSING_KEY || "",
};

async function fetchJsonWithLimit(url, options = {}, timeoutMs = 10000) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(timeoutMs) });
  const text = (await response.text()).slice(0, 2 * 1024 * 1024);
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  return { status: response.status, data };
}

async function protectiveDnsVerdicts(domain) {
  const baseline = await queryDohDns(domain, "A", { resolver: { ...dnsResolvers.google, format: "wire" } }).then(
    (data) => ({ status: data.status, addresses: data.answers.filter((answer) => answer.type === 1).map((answer) => answer.data) }),
    () => null,
  );
  const verdicts = await Promise.all(protectiveResolvers.map(async (resolver) => {
    if (baseline && !baseline.addresses.length) return { source: resolver.label, state: "off", detail: "Not applicable: the domain has no address" };
    try {
      const data = await queryDohDns(domain, "A", { resolver });
      const addresses = data.answers.filter((answer) => answer.type === 1).map((answer) => answer.data);
      const blocked = Boolean(baseline?.addresses.length) && (data.status === 3 || data.status === 5 || (addresses.length > 0 && addresses.every((address) => sinkholeAddresses.has(address))));
      return { source: resolver.label, state: blocked ? "flagged" : "clean", detail: blocked ? (data.status === 3 ? "Blocked (answers NXDOMAIN)" : data.status === 5 ? "Blocked (REFUSED)" : `Blocked (answers ${addresses.join(", ")})`) : "Resolves normally" };
    } catch {
      return { source: resolver.label, state: "error", detail: "No answer" };
    }
  }));
  return { baseline, verdicts };
}

async function optionalReputationSources(host, isAddress) {
  const results = [];
  if (reputationKeys.urlhaus) {
    try {
      const { status, data } = await fetchJsonWithLimit("https://urlhaus-api.abuse.ch/v1/host/", {
        method: "POST",
        headers: { "auth-key": reputationKeys.urlhaus, "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ host }).toString(),
      });
      if (status !== 200 || !data) throw new Error(`HTTP ${status}`);
      const count = Number(data.url_count || 0);
      results.push({ source: "URLhaus (abuse.ch)", state: data.query_status === "ok" && count ? "flagged" : "clean",
        detail: data.query_status === "ok" && count ? `${count} malware URL(s) recorded${data.urls?.[0]?.threat ? `, e.g. ${data.urls[0].threat}` : ""}` : "No malware URLs recorded",
        link: `https://urlhaus.abuse.ch/host/${encodeURIComponent(host)}/` });
    } catch (error) {
      results.push({ source: "URLhaus (abuse.ch)", state: "error", detail: `Lookup failed (${String(error.message).slice(0, 60)})` });
    }
  }
  if (reputationKeys.virustotal) {
    try {
      const path = isAddress ? `ip_addresses/${encodeURIComponent(host)}` : `domains/${encodeURIComponent(host)}`;
      const { status, data } = await fetchJsonWithLimit(`https://www.virustotal.com/api/v3/${path}`, { headers: { "x-apikey": reputationKeys.virustotal } });
      if (status === 404) results.push({ source: "VirusTotal", state: "clean", detail: "Not known to VirusTotal" });
      else if (status !== 200 || !data?.data) throw new Error(`HTTP ${status}`);
      else {
        const stats = data.data.attributes?.last_analysis_stats || {};
        const bad = Number(stats.malicious || 0) + Number(stats.suspicious || 0);
        results.push({ source: "VirusTotal", state: stats.malicious ? "flagged" : stats.suspicious ? "suspicious" : "clean",
          detail: `${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious of ${bad + Number(stats.harmless || 0) + Number(stats.undetected || 0)} engines`,
          link: `https://www.virustotal.com/gui/${isAddress ? "ip-address" : "domain"}/${encodeURIComponent(host)}` });
      }
    } catch (error) {
      results.push({ source: "VirusTotal", state: "error", detail: `Lookup failed (${String(error.message).slice(0, 60)})` });
    }
  } else {
    results.push({ source: "VirusTotal", state: "off", detail: "Not configured (VIRUSTOTAL_API_KEY)" });
  }
  if (reputationKeys.safeBrowsing && !isAddress) {
    try {
      const { status, data } = await fetchJsonWithLimit(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(reputationKeys.safeBrowsing)}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "bnglookup", clientVersion: appBuild.version },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: `http://${host}/` }, { url: `https://${host}/` }],
          },
        }),
      });
      if (status !== 200) throw new Error(`HTTP ${status}`);
      const matches = data?.matches || [];
      results.push({ source: "Google Safe Browsing", state: matches.length ? "flagged" : "clean",
        detail: matches.length ? `Listed as ${[...new Set(matches.map((match) => match.threatType.toLowerCase().replace(/_/g, " ")))].join(", ")}` : "Not listed" });
    } catch (error) {
      results.push({ source: "Google Safe Browsing", state: "error", detail: `Lookup failed (${String(error.message).slice(0, 60)})` });
    }
  } else if (!isAddress) {
    results.push({ source: "Google Safe Browsing", state: "off", detail: "Not configured (GOOGLE_SAFE_BROWSING_KEY)" });
  }
  return results;
}

async function runReputation(input) {
  const host = hostFromInput(String(input || "").trim()).replace(/^\[|\]$/g, "");
  const isAddress = Boolean(isIP(host));
  const domain = isAddress ? null : normalizeDomain(host);
  if (isAddress ? !isPublicAddress(host) : !domain) throw Object.assign(new Error("Enter a domain, URL or public IP address."), { statusCode: 400 });
  const target = domain || host;
  const started = Date.now();
  const addresses = isAddress ? [host] : (await dohAnswers(target, "A")).values.filter((address) => isIP(address) === 4).slice(0, 2);
  const [protective, blocklists, optional, feeds] = await Promise.all([
    domain ? protectiveDnsVerdicts(domain) : Promise.resolve(null),
    checkBlocklists({ addresses: addresses.filter((address) => isPublicAddress(address)), domain }).catch(() => null),
    optionalReputationSources(target, isAddress),
    threatFeedVerdicts(domain, addresses.filter((address) => isPublicAddress(address))),
  ]);
  const blocklistSources = [];
  if (blocklists?.domain) {
    blocklistSources.push({ source: `Domain blocklists (${blocklists.domain.checked})`, state: blocklists.domain.listed ? "flagged" : "clean",
      detail: blocklists.domain.listed ? `Listed on ${blocklists.domain.lists.filter((list) => list.status === "listed").map((list) => list.name).join(", ")}` : "Not listed" });
  }
  for (const entry of blocklists?.ips || []) {
    blocklistSources.push({ source: `IP blocklists for ${entry.address} (${entry.checked})`, state: entry.listed ? "flagged" : "clean",
      detail: entry.listed ? `Listed on ${entry.lists.filter((list) => list.status === "listed").map((list) => list.name).join(", ")}` : "Not listed" });
  }
  const sources = [...(protective?.verdicts || []), ...blocklistSources, ...feeds, ...optional];
  const flagged = sources.filter((source) => source.state === "flagged");
  const suspicious = sources.filter((source) => source.state === "suspicious");
  return {
    target,
    isAddress,
    addresses,
    exists: isAddress || Boolean(protective?.baseline?.addresses?.length) || protective?.baseline?.status === 0,
    verdict: flagged.length >= 2 ? "malicious" : flagged.length || suspicious.length ? "suspicious" : "clean",
    flagged: flagged.length,
    checked: sources.filter((source) => !["off", "error"].includes(source.state)).length,
    sources,
    durationMs: Date.now() - started,
  };
}

async function reputationCheck(request, url, response) {
  const rawName = queryInput(url, "name", 2048, response);
  if (rawName === null) return;
  if (!acquireHeavyJob("reputation")) {
    sendJson(response, 503, { error: "The server is busy with other reputation checks. Try again shortly." });
    return;
  }
  try {
    sendJson(response, 200, await runReputation(rawName));
  } catch (error) {
    if (error.statusCode) sendJson(response, error.statusCode, { error: error.message });
    else {
      console.error("Reputation check failed:", error);
      sendJson(response, 500, { error: "Unable to complete the reputation check." });
    }
  } finally {
    releaseHeavyJob("reputation");
  }
}

// ---------------------------------------------------------------- Lookalike domains

const keyboardNeighbours = {
  q: "wa", w: "qeas", e: "wrds", r: "etdf", t: "ryfg", y: "tugh", u: "yihj", i: "uojk", o: "ipkl", p: "ol",
  a: "qwsz", s: "awedxz", d: "serfcx", f: "drtgvc", g: "ftyhbv", h: "gyujnb", j: "huikmn", k: "jiolm", l: "kop",
  z: "asx", x: "zsdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
  1: "2q", 2: "13w", 3: "24e", 4: "35r", 5: "46t", 6: "57y", 7: "68u", 8: "79i", 9: "80o", 0: "9p",
};
const homoglyphs = { o: ["0"], 0: ["o"], l: ["1", "i"], i: ["1", "l"], 1: ["l", "i"], e: ["3"], a: ["4"], s: ["5"], g: ["9", "q"], q: ["g"], b: ["6"], z: ["2"], m: ["rn", "nn"], w: ["vv"], d: ["cl"], u: ["v"], v: ["u"], c: ["e"], n: ["m"] };
const lookalikeTlds = ["com", "net", "org", "co", "io", "info", "biz", "app", "xyz", "online", "site", "shop", "eu", "nl", "de", "uk", "us", "me", "cc", "top"];
const lookalikeWords = ["login", "secure", "account", "support", "mail", "my", "app", "online", "verify", "help"];
const lookalikeLimits = { variants: 260, concurrency: 10 };

function splitRegistrable(domain) {
  const org = organizationalDomain(domain);
  const index = org.indexOf(".");
  return { label: org.slice(0, index), suffix: org.slice(index + 1) };
}

function generateLookalikes(domain) {
  const { label, suffix } = splitRegistrable(domain);
  const variants = new Map();
  const add = (candidateLabel, kind, candidateSuffix = suffix) => {
    const name = `${candidateLabel}.${candidateSuffix}`;
    if (candidateLabel === label && candidateSuffix === suffix) return;
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(candidateLabel) || candidateLabel.includes("--")) return;
    if (!variants.has(name)) variants.set(name, kind);
  };
  const chars = [...label];
  chars.forEach((character, index) => {
    for (const glyph of homoglyphs[character] || []) add(label.slice(0, index) + glyph + label.slice(index + 1), "Homoglyph");
  });
  for (const [from, to] of [["rn", "m"], ["vv", "w"], ["cl", "d"], ["nn", "m"]]) if (label.includes(from)) add(label.replace(from, to), "Homoglyph");
  chars.forEach((_character, index) => add(label.slice(0, index) + label.slice(index + 1), "Missing letter"));
  for (let index = 0; index < chars.length - 1; index += 1) {
    if (chars[index] !== chars[index + 1]) add(label.slice(0, index) + chars[index + 1] + chars[index] + label.slice(index + 2), "Swapped letters");
  }
  chars.forEach((character, index) => {
    for (const neighbour of keyboardNeighbours[character] || "") add(label.slice(0, index) + neighbour + label.slice(index + 1), "Typo (nearby key)");
  });
  for (const tld of lookalikeTlds) add(label, "Other TLD", tld);
  if (suffix.includes(".")) add(label, "Other TLD", suffix.split(".").pop());
  for (let index = 1; index < chars.length; index += 1) add(`${label.slice(0, index)}-${label.slice(index)}`, "Hyphen");
  for (const word of lookalikeWords) {
    add(`${label}-${word}`, "Added word");
    add(`${word}-${label}`, "Added word");
    add(`${label}${word}`, "Added word");
  }
  chars.forEach((character, index) => add(label.slice(0, index) + character + label.slice(index), "Doubled letter"));
  chars.forEach((character, index) => {
    for (let bit = 0; bit < 7; bit += 1) {
      const flipped = String.fromCharCode(character.charCodeAt(0) ^ (1 << bit));
      if (/[a-z0-9]/.test(flipped)) add(label.slice(0, index) + flipped + label.slice(index + 1), "Bit flip");
    }
  });
  return { label, suffix, variants: [...variants.entries()].slice(0, lookalikeLimits.variants).map(([name, kind]) => ({ name, kind })) };
}

async function runLookalike(input) {
  const domain = normalizeDomain(hostFromInput(String(input || "").trim()));
  if (!domain) throw Object.assign(new Error("Enter a valid domain name."), { statusCode: 400 });
  const started = Date.now();
  const { label, suffix, variants } = generateLookalikes(domain);
  const results = [];
  let next = 0;
  let failed = 0;
  await Promise.all(Array.from({ length: lookalikeLimits.concurrency }, async () => {
    while (next < variants.length) {
      const variant = variants[next];
      next += 1;
      const ns = await dohAnswers(variant.name, "NS");
      if (ns.status === null) {
        failed += 1;
        continue;
      }
      if (ns.status === 3) continue;
      const [a, mx] = await Promise.all([dohAnswers(variant.name, "A"), dohAnswers(variant.name, "MX")]);
      if (!ns.values.length && !a.values.length && !mx.values.length) continue;
      const mail = mx.values.some((value) => !/\s\.?$/.test(value) && value.split(/\s+/)[1] !== ".");
      results.push({
        ...variant,
        nameservers: ns.values.slice(0, 2),
        addresses: a.values.slice(0, 3),
        mx: mx.values.map((value) => value.split(/\s+/)[1] || value).slice(0, 2),
        risk: mail ? "high" : a.values.length ? "medium" : "low",
      });
    }
  }));
  const order = { high: 0, medium: 1, low: 2 };
  results.sort((left, right) => order[left.risk] - order[right.risk] || left.name.localeCompare(right.name));
  return {
    domain,
    base: `${label}.${suffix}`,
    checked: variants.length,
    failed,
    registered: results,
    counts: { high: results.filter((entry) => entry.risk === "high").length, medium: results.filter((entry) => entry.risk === "medium").length, low: results.filter((entry) => entry.risk === "low").length },
    kinds: [...new Set(variants.map((variant) => variant.kind))],
    durationMs: Date.now() - started,
  };
}

async function lookalikeCheck(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  if (!acquireHeavyJob("lookalike")) {
    sendJson(response, 503, { error: "The server is busy with other lookalike searches. Try again shortly." });
    return;
  }
  try {
    sendJson(response, 200, await runLookalike(rawName));
  } catch (error) {
    if (error.statusCode) sendJson(response, error.statusCode, { error: error.message });
    else {
      console.error("Lookalike search failed:", error);
      sendJson(response, 500, { error: "Unable to complete the lookalike search." });
    }
  } finally {
    releaseHeavyJob("lookalike");
  }
}

// ---------------------------------------------------------------- Certificate Transparency (monitor)

async function fetchCertificateIssuances(domain) {
  const normalize = (entries) => entries.map((entry) => `${entry.notBefore.slice(0, 10)}|${[...new Set(entry.names)].sort().join(",").slice(0, 300)}|${entry.issuer.slice(0, 80)}`);
  try {
    const lists = await Promise.all([domain, `%.${domain}`].map((query) => {
      const url = new URL("https://crt.sh/");
      url.searchParams.set("q", query);
      url.searchParams.set("output", "json");
      url.searchParams.set("exclude", "expired");
      return fetchCertificateTransparencyJson(url);
    }));
    const entries = lists.flat().filter((entry) => entry && typeof entry.name_value === "string").map((entry) => ({
      notBefore: String(entry.not_before || ""),
      names: entry.name_value.split(/\n/).map((name) => name.trim().toLowerCase()).filter(Boolean),
      issuer: (String(entry.issuer_name || "").match(/O=([^,]+)/)?.[1] || String(entry.issuer_name || "")).replace(/"/g, ""),
    }));
    return { source: "crt.sh", certificates: [...new Set(normalize(entries))] };
  } catch {
    const url = new URL("https://api.certspotter.com/v1/issuances");
    url.searchParams.set("domain", domain);
    url.searchParams.set("include_subdomains", "true");
    url.searchParams.append("expand", "dns_names");
    url.searchParams.append("expand", "issuer");
    const entries = await fetchCertificateTransparencyJson(url);
    if (!Array.isArray(entries)) throw new Error("Certificate Transparency service returned invalid data.");
    return {
      source: "CertSpotter",
      certificates: [...new Set(normalize(entries.map((entry) => ({
        notBefore: String(entry.not_before || ""),
        names: (entry.dns_names || []).map((name) => String(name).toLowerCase()),
        issuer: String(entry.issuer?.friendly_name || entry.issuer?.name || "").replace(/^.*O=([^,]+).*$/, "$1"),
      }))))],
    };
  }
}

// ---------------------------------------------------------------- SPF flattener

async function flattenSpf(domain) {
  const ip4 = new Set();
  const ip6 = new Set();
  const kept = [];
  const notes = [];
  let lookups = 0;
  const visited = new Set();
  async function addHostAddresses(host, why) {
    lookups += 1;
    const [v4, v6] = await Promise.all([dohAnswers(host, "A"), dohAnswers(host, "AAAA")]);
    v4.values.forEach((address) => ip4.add(address));
    v6.values.forEach((address) => ip6.add(address));
    if (!v4.values.length && !v6.values.length) notes.push(`${why} ${host} has no addresses.`);
  }
  async function walk(name, depth) {
    if (depth > 10 || visited.has(name) || lookups > 60) return;
    visited.add(name);
    const records = (await queryTxtRecords(name).catch(() => ({ records: [] }))).records.filter((record) => /^v=spf1\b/i.test(record.trim()));
    if (records.length !== 1) {
      notes.push(records.length ? `${name} publishes more than one SPF record.` : `${name} has no SPF record.`);
      return;
    }
    for (const term of records[0].trim().split(/\s+/).slice(1)) {
      const match = term.match(/^([+\-~?]?)([a-z0-9]+)(?:[:=](.*))?$/i);
      if (!match) continue;
      const [, qualifier, mechanismRaw, value] = match;
      const mechanism = mechanismRaw.toLowerCase();
      if (qualifier && qualifier !== "+" && mechanism !== "all") {
        kept.push(term);
        continue;
      }
      if (mechanism === "ip4") ip4.add(value);
      else if (mechanism === "ip6") ip6.add(value);
      else if (mechanism === "include" || mechanism === "redirect") {
        lookups += 1;
        await walk(String(value).toLowerCase(), depth + 1);
      } else if (mechanism === "a") await addHostAddresses(value ? value.split("/")[0] : name, "a:");
      else if (mechanism === "mx") {
        lookups += 1;
        const hosts = (await dohAnswers(value ? value.split("/")[0] : name, "MX")).values.map((entry) => entry.split(/\s+/)[1]).filter(Boolean);
        for (const host of hosts.slice(0, 10)) await addHostAddresses(host, "MX host");
      } else if (["ptr", "exists"].includes(mechanism)) {
        kept.push(term);
        notes.push(`${term} (in ${name}) cannot be flattened and is kept as is.`);
      }
    }
  }
  await walk(domain, 0);
  const root = (await queryTxtRecords(domain).catch(() => ({ records: [] }))).records.find((record) => /^v=spf1\b/i.test(record.trim())) || null;
  const all = root?.match(/\s([-~?+]?all)\b/i)?.[1] || "~all";
  const terms = [...[...ip4].sort().map((value) => `ip4:${value}`), ...[...ip6].sort().map((value) => `ip6:${value}`), ...kept];
  const chunks = [];
  let current = [];
  for (const term of terms) {
    if ([...current, term].join(" ").length > 220) {
      chunks.push(current);
      current = [];
    }
    current.push(term);
  }
  if (current.length) chunks.push(current);
  const single = `v=spf1 ${terms.join(" ")} ${all}`.replace(/\s+/g, " ");
  const records = single.length <= 255
    ? [{ name: domain, value: single }]
    : [
      { name: domain, value: `v=spf1 ${chunks.map((_chunk, index) => `include:_spf${index + 1}.${domain}`).join(" ")} ${all}` },
      ...chunks.map((chunk, index) => ({ name: `_spf${index + 1}.${domain}`, value: `v=spf1 ${chunk.join(" ")} -all` })),
    ];
  if (chunks.length > 9) notes.push("Too many addresses to fit in nine include records; remove senders you no longer use.");
  return {
    domain,
    original: root,
    originalLookups: lookups,
    ip4: ip4.size,
    ip6: ip6.size,
    kept,
    records,
    flattenedLookups: (records.length > 1 ? records.length - 1 : 0) + kept.filter((term) => /^[-~?+]?(ptr|exists|include|a|mx|redirect)\b/i.test(term)).length,
    notes,
  };
}

async function spfFlattenCheck(url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  const domain = normalizeDomain(hostFromInput(rawName));
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name." });
    return;
  }
  sendJson(response, 200, await flattenSpf(domain));
}

// ---------------------------------------------------------------- Website previews (proxied, sanitized live view)

// The page is fetched by the server, cleaned of scripts and active content, and shown in a
// sandboxed frame. Images, styles and fonts are loaded through a signed asset proxy, so the
// visitor's browser never contacts the site and the proxy only serves URLs it handed out.
const previewConfig = {
  enabled: process.env.PREVIEWS !== "false",
  pageBytes: 3 * 1024 * 1024,
  assetBytes: 3 * 1024 * 1024,
  pagesPerUserHour: 200,
  assetsPerClientHour: 6000,
  assetLinkSeconds: 7200,
  timeoutMs: 10000,
};
const previewSecret = crypto.randomBytes(32);
const previewUsage = new Map();
const previewAssetTypes = /^(image\/(png|jpe?g|gif|webp|avif|svg\+xml|x-icon|vnd\.microsoft\.icon|bmp)|text\/css|font\/[\w.+-]+|application\/(font-woff2?|x-font-[\w-]+|vnd\.ms-fontobject|font-sfnt))\b/i;

function previewsAvailable() {
  return previewConfig.enabled;
}

// Asset links are authorized by their signature alone: the sandboxed preview has an opaque
// origin, so the browser sends no session cookie with its requests.
function signPreviewUrl(value, expires) {
  return crypto.createHmac("sha256", previewSecret).update(`${expires}|${value}`).digest("base64url").slice(0, 32);
}

function previewAssetUrl(raw, base) {
  let target;
  try {
    target = new URL(String(raw).trim().replace(/&amp;/g, "&"), base);
  } catch {
    return null;
  }
  if (target.protocol === "data:") return target.href.length < 200000 && /^data:(image|font)\//i.test(target.href) ? target.href : null;
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password) return null;
  target.hash = "";
  const expires = String(Math.floor(Date.now() / 1000) + previewConfig.assetLinkSeconds);
  return `/api/preview/asset?${new URLSearchParams({ url: target.href, exp: expires, sig: signPreviewUrl(target.href, expires) })}`;
}

function rewriteCssUrls(css, base) {
  return css
    .replace(/@import\s+(?:url\()?\s*["']?([^"')\s;]+)["']?\s*\)?/gi, (_whole, link) => {
      const proxied = previewAssetUrl(link, base);
      return proxied ? `@import url("${proxied}")` : "";
    })
    .replace(/url\(\s*(["']?)([^"')]+)\1\s*\)/gi, (_whole, _quote, link) => {
      const proxied = previewAssetUrl(link, base);
      return proxied ? `url("${proxied}")` : "url()";
    })
    .replace(/expression\s*\(|behavior\s*:|-moz-binding/gi, "");
}

function escapeAttribute(value) {
  return String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Removes everything that could run code, navigate or embed other documents, and routes
// the remaining resources through the asset proxy.
function sanitizePreviewHtml(html, base) {
  let output = String(html)
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|template|iframe|frame|frameset|object|embed|applet|portal|audio|video|canvas)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<(script|iframe|frame|object|embed|applet|portal|base|meta|link(?![^>]*\bstylesheet\b)|param|source|track|audio|video)\b[^>]*>/gi, (tag) => (/^<link\b/i.test(tag) && /\bicon\b/i.test(tag) ? "" : /^<meta\b/i.test(tag) && /charset|viewport/i.test(tag) && !/http-equiv/i.test(tag) ? tag : ""))
    .replace(/<\/?noscript\b[^>]*>/gi, "");
  output = output.replace(/<style\b([^>]*)>([\s\S]*?)<\/style\s*>/gi, (_whole, attributes, css) => `<style${attributes.replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")}>${rewriteCssUrls(css, base)}</style>`);
  output = output.replace(/<([a-z][\w-]*)(\s[^<>]*?)?(\/?)>/gi, (whole, tag, attributes = "", selfClosing) => {
    const name = tag.toLowerCase();
    const kept = [];
    for (const match of attributes.matchAll(/([^\s"'=<>\/]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+))?/g)) {
      const attribute = match[1].toLowerCase();
      let value = match[2] === undefined ? null : match[2].replace(/^["']|["']$/g, "");
      if (attribute.startsWith("on") || attribute === "formaction" || attribute === "action" || attribute === "srcdoc" || attribute === "ping" || attribute === "target") continue;
      if (value !== null && /^\s*(javascript|vbscript|data:text\/html)/i.test(value)) continue;
      if (attribute === "href") {
        if (name === "link") {
          const proxied = previewAssetUrl(value, base);
          if (!proxied) continue;
          value = proxied;
        } else {
          // Links are shown but do not navigate the preview.
          kept.push(`title="${escapeAttribute(value)}"`);
          continue;
        }
      } else if (["src", "poster", "background", "data-src", "lowsrc"].includes(attribute)) {
        const proxied = previewAssetUrl(value, base);
        if (!proxied) continue;
        value = proxied;
        if (attribute !== "src" && attribute !== "poster") {
          kept.push(`src="${escapeAttribute(value)}"`);
          continue;
        }
      } else if (attribute === "srcset" || attribute === "data-srcset" || attribute === "imagesrcset") {
        value = value.split(",").map((part) => {
          const [link, size] = part.trim().split(/\s+/);
          const proxied = previewAssetUrl(link, base);
          return proxied ? `${proxied}${size ? ` ${size}` : ""}` : null;
        }).filter(Boolean).join(", ");
        if (!value) continue;
        if (attribute !== "srcset") {
          kept.push(`srcset="${escapeAttribute(value)}"`);
          continue;
        }
      } else if (attribute === "style" && value !== null) {
        value = rewriteCssUrls(value, base);
      }
      kept.push(value === null ? attribute : `${attribute}="${escapeAttribute(value)}"`);
    }
    return `<${name}${kept.length ? ` ${kept.join(" ")}` : ""}${selfClosing}>`;
  });
  return output;
}

function previewMessagePage(title, message) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>body{margin:0;display:grid;place-items:center;height:100vh;font:15px/1.5 system-ui,sans-serif;color:#555;background:#f4f4f4;text-align:center}strong{display:block;color:#222;font-size:17px;margin-bottom:6px}</style></head><body><div><strong>${escapeAttribute(title)}</strong>${escapeAttribute(message)}</div></body></html>`;
}

function sendPreviewDocument(response, status, html) {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    // An opaque origin with no scripts: the page cannot touch this site or the visitor's session.
    "content-security-policy": "sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; media-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'",
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "private, max-age=300",
  });
  response.end(html);
}

function countPreviewUse(user, kind, limit) {
  const key = `${user.id}:${kind}`;
  const now = Date.now();
  const recent = (previewUsage.get(key) || []).filter((time) => now - time < 3600000);
  if (recent.length >= limit) return false;
  recent.push(now);
  previewUsage.set(key, recent);
  return true;
}

function parsePreviewTarget(raw) {
  let target;
  try {
    target = new URL(/^https?:\/\//i.test(String(raw).trim()) ? String(raw).trim() : `http://${String(raw).trim()}/`);
  } catch {
    return null;
  }
  const host = target.hostname.replace(/^\[|\]$/g, "");
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password ||
    (target.port && !["80", "443"].includes(target.port)) || !(isIP(host) ? isPublicAddress(host) : normalizeDomain(host))) return null;
  target.hash = "";
  return target;
}

async function handlePreviewPage(request, url, response) {
  if (!previewsAvailable()) {
    sendPreviewDocument(response, 501, previewMessagePage("Previews are turned off", "An administrator has disabled website previews."));
    return;
  }
  const raw = queryInput(url, "url", 2048, response);
  if (raw === null) return;
  const target = parsePreviewTarget(raw);
  if (!target) {
    sendPreviewDocument(response, 400, previewMessagePage("No preview", "Previews are available for public websites on ports 80 and 443."));
    return;
  }
  if (!countPreviewUse(currentUser(request), "page", previewConfig.pagesPerUserHour)) {
    sendPreviewDocument(response, 429, previewMessagePage("Too many previews", "Try again in a while."));
    return;
  }
  const { hops, final } = await followWebRedirects(target, false, { maxBytes: previewConfig.pageBytes, timeoutMs: previewConfig.timeoutMs });
  if (!final) {
    sendPreviewDocument(response, 200, previewMessagePage("The site could not be loaded", hops.at(-1)?.error || "No response."));
    return;
  }
  const type = String(final.response.headers["content-type"] || "");
  if (!/text\/html|application\/xhtml/i.test(type)) {
    sendPreviewDocument(response, 200, previewMessagePage("Not a web page", `The address returns ${type.split(";")[0] || "an unknown type"} (HTTP ${final.response.status}).`));
    return;
  }
  const html = decodeBody(final.response.body, String(final.response.headers["content-encoding"] || ""));
  sendPreviewDocument(response, 200, sanitizePreviewHtml(html, final.url));
}

async function handlePreviewAsset(request, url, response) {
  const raw = url.searchParams.get("url") || "";
  const signature = url.searchParams.get("sig") || "";
  const expires = url.searchParams.get("exp") || "";
  const expected = signPreviewUrl(raw, expires);
  if (!previewsAvailable() || !/^\d{1,12}$/.test(expires) || Number(expires) * 1000 < Date.now() ||
    signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    response.writeHead(403, { "content-type": "text/plain" }).end("Forbidden");
    return;
  }
  let target;
  try {
    target = new URL(raw);
  } catch {
    response.writeHead(400).end();
    return;
  }
  if (!countPreviewUse({ id: getClientAddress(request) || "unknown" }, "asset", previewConfig.assetsPerClientHour)) {
    response.writeHead(429).end();
    return;
  }
  const { final } = await followWebRedirects(target, false, { maxBytes: previewConfig.assetBytes, timeoutMs: previewConfig.timeoutMs });
  const type = String(final?.response.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (!final || final.response.status >= 400 || final.response.truncated || !previewAssetTypes.test(type)) {
    response.writeHead(404, { "content-type": "text/plain" }).end("Not available");
    return;
  }
  let body = final.response.body;
  const encoding = String(final.response.headers["content-encoding"] || "");
  if (type === "text/css") body = Buffer.from(rewriteCssUrls(decodeBody(body, encoding), final.url));
  else if (encoding) body = zlibDecodeBuffer(body, encoding);
  response.writeHead(200, {
    "content-type": type,
    "content-length": body.length,
    // Served from this site, so make sure an SVG opened directly cannot run script.
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "x-content-type-options": "nosniff",
    // The sandboxed preview has an opaque origin, so it needs a cross-origin resource policy.
    "cross-origin-resource-policy": "cross-origin",
    "cache-control": "private, max-age=3600",
  });
  response.end(body);
}

function zlibDecodeBuffer(body, encoding) {
  const options = { maxOutputLength: previewConfig.assetBytes * 4 };
  try {
    if (/\bbr\b/i.test(encoding)) return zlib.brotliDecompressSync(body, options);
    if (/gzip/i.test(encoding)) return zlib.gunzipSync(body, options);
    if (/deflate/i.test(encoding)) return zlib.inflateSync(body, options);
  } catch {
    return Buffer.alloc(0);
  }
  return body;
}

// ---------------------------------------------------------------- Passkeys (WebAuthn)

database.exec(`
  CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    algorithm INTEGER NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
  );
  CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(user_id);
  CREATE TABLE IF NOT EXISTS oidc_identities (
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, subject)
  );
`);
const passkeyLimits = { perUser: 10, challengeMs: 5 * 60_000 };
const passkeyChallenges = new Map();

function newPasskeyChallenge(entry) {
  const now = Date.now();
  for (const [id, challenge] of passkeyChallenges) if (challenge.expiresAt < now) passkeyChallenges.delete(id);
  if (passkeyChallenges.size > 5000) passkeyChallenges.clear();
  const id = crypto.randomBytes(18).toString("base64url");
  const challenge = crypto.randomBytes(32).toString("base64url");
  passkeyChallenges.set(id, { ...entry, challenge, expiresAt: now + passkeyLimits.challengeMs });
  return { id, challenge };
}

function takePasskeyChallenge(id, type) {
  const entry = typeof id === "string" ? passkeyChallenges.get(id) : null;
  if (entry) passkeyChallenges.delete(id);
  if (!entry || entry.type !== type || entry.expiresAt < Date.now()) throw new Error("This passkey request has expired; try again.");
  return entry;
}

// The site a passkey belongs to is the origin the browser is on, which sameOrigin()
// has already matched against the Host header.
const passkeySite = (request) => {
  const origin = request.headers.origin;
  return { origin, rpId: new URL(origin).hostname };
};

const passkeyUserHandle = (userId) => crypto.createHmac("sha256", publicLookupHashKey).update(`passkey-user:${userId}`).digest().subarray(0, 16).toString("base64url");

function describePasskey(row) {
  return { id: row.id, name: row.name, createdAt: new Date(row.created_at).toISOString(), lastUsedAt: row.last_used_at ? new Date(row.last_used_at).toISOString() : null };
}

async function handlePasskeys(request, response, url) {
  const path = url.pathname;
  if (path === "/api/auth/passkeys/login/options" || path === "/api/auth/passkeys/login") {
    if (request.method !== "POST") return sendJson(response, 405, { error: "Method not allowed." });
    if (!enforceSameOrigin(request, response)) return;
    if (!allowAuthAttempt(request)) return sendJson(response, 429, { error: "Too many login attempts. Try again in 15 minutes." });
    const body = await readAuthBody(request, response, 16384);
    if (!body) return;
    const { origin, rpId } = passkeySite(request);
    if (path.endsWith("/options")) {
      const { id, challenge } = newPasskeyChallenge({ type: "login", origin });
      return sendJson(response, 200, { challengeId: id, publicKey: { challenge, rpId, timeout: 120000, userVerification: "preferred", allowCredentials: [] } });
    }
    try {
      const pending = takePasskeyChallenge(body.challengeId, "login");
      if (pending.origin !== origin) throw new Error("The passkey request came from a different site.");
      const row = typeof body.id === "string" && body.id.length <= 1400
        ? database.prepare("SELECT passkeys.*, users.username, users.role, users.must_change_password FROM passkeys JOIN users ON users.id = passkeys.user_id WHERE credential_id = ? AND users.active = 1").get(body.id)
        : null;
      if (!row) throw new Error("This passkey is not registered here. Log in with your password and add it on the My account page.");
      if (body.userHandle && body.userHandle !== passkeyUserHandle(row.user_id)) throw new Error("This passkey belongs to a different account.");
      const result = webauthn.verifyAuthentication({
        clientDataJSON: body.clientDataJSON, authenticatorData: body.authenticatorData, signature: body.signature,
        challenge: pending.challenge, origin, rpId, credential: { publicKey: row.public_key, algorithm: row.algorithm, signCount: row.sign_count },
      });
      database.prepare("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?").run(result.signCount, Date.now(), row.id);
      resetAuthAttempts(request);
      const user = { id: row.user_id, username: row.username, role: row.role, must_change_password: row.must_change_password };
      // A passkey that verified the user (PIN, fingerprint or face) counts as two factors.
      if (!result.userVerified && twoFactorStatus(user.id).enabled) {
        recordAdminLog("login", request, "Passkey accepted, two-factor code requested", "", 200, user.username);
        return sendJson(response, 200, { twoFactorRequired: true, challenge: createTwoFactorChallenge(user) });
      }
      await establishSession(user.id, response);
      if (!user.must_change_password) recordNmapLoginIp(request, user.username);
      recordAdminLog("login", request, "Login successful (passkey)", row.name, 200, user.username);
      return sendJson(response, 200, { user: { username: user.username, role: user.role }, mustChangePassword: Boolean(user.must_change_password), featureAccess: getFeatureAccess() });
    } catch (error) {
      recordAdminLog("login", request, "Passkey login failed", error.message.slice(0, 120), 401, null);
      return sendJson(response, 401, { error: error.message });
    }
  }

  const user = currentUser(request);
  if (!user || request.apiUser) return sendJson(response, 401, { error: "Log in to manage passkeys.", loginRequired: true });
  if (path === "/api/auth/passkeys" && request.method === "GET") {
    const rows = database.prepare("SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at").all(user.id);
    return sendJson(response, 200, { passkeys: rows.map(describePasskey) });
  }
  if (!enforceSameOrigin(request, response)) return;
  const deleteMatch = path.match(/^\/api\/auth\/passkeys\/(\d+)$/);
  if (deleteMatch && request.method === "DELETE") {
    const row = database.prepare("SELECT * FROM passkeys WHERE id = ? AND user_id = ?").get(Number(deleteMatch[1]), user.id);
    if (!row) return sendJson(response, 404, { error: "Passkey not found." });
    database.prepare("DELETE FROM passkeys WHERE id = ?").run(row.id);
    recordAdminLog("audit", request, "Passkey removed", row.name, 200, user.username);
    return sendJson(response, 200, { deleted: true });
  }
  if (request.method !== "POST") return sendJson(response, 405, { error: "Method not allowed." });
  const body = await readAuthBody(request, response, 65536);
  if (!body) return;
  const { origin, rpId } = passkeySite(request);
  if (path === "/api/auth/passkeys/register/options") {
    const existing = database.prepare("SELECT credential_id FROM passkeys WHERE user_id = ?").all(user.id);
    if (existing.length >= passkeyLimits.perUser) return sendJson(response, 400, { error: `You can have at most ${passkeyLimits.perUser} passkeys.` });
    const { id, challenge } = newPasskeyChallenge({ type: "register", userId: user.id, origin });
    return sendJson(response, 200, {
      challengeId: id,
      publicKey: {
        challenge,
        rp: { name: getSiteTitle(), id: rpId },
        user: { id: passkeyUserHandle(user.id), name: user.username, displayName: user.username },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }, { type: "public-key", alg: -257 }],
        timeout: 120000,
        attestation: "none",
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred" },
        excludeCredentials: existing.map((row) => ({ type: "public-key", id: row.credential_id })),
      },
    });
  }
  if (path === "/api/auth/passkeys/register") {
    try {
      const pending = takePasskeyChallenge(body.challengeId, "register");
      if (pending.userId !== user.id || pending.origin !== origin) throw new Error("The passkey request does not match this session.");
      const name = typeof body.name === "string" && body.name.trim() ? body.name.trim().replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 60) : "Passkey";
      const credential = webauthn.verifyRegistration({ clientDataJSON: body.clientDataJSON, attestationObject: body.attestationObject, challenge: pending.challenge, origin, rpId });
      if (database.prepare("SELECT 1 FROM passkeys WHERE credential_id = ?").get(credential.credentialId)) throw new Error("This passkey is already registered.");
      if (database.prepare("SELECT COUNT(*) AS count FROM passkeys WHERE user_id = ?").get(user.id).count >= passkeyLimits.perUser) throw new Error(`You can have at most ${passkeyLimits.perUser} passkeys.`);
      database.prepare("INSERT INTO passkeys (user_id, credential_id, public_key, algorithm, sign_count, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(user.id, credential.credentialId, credential.publicKey, credential.algorithm, credential.signCount, name, Date.now());
      recordAdminLog("audit", request, "Passkey added", name, 201, user.username);
      const rows = database.prepare("SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at").all(user.id);
      return sendJson(response, 201, { passkeys: rows.map(describePasskey) });
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
  }
  sendJson(response, 404, { error: "Not found." });
}

// ---------------------------------------------------------------- Single sign-on (OpenID Connect)

const ssoDefaults = { enabled: false, issuer: "", clientId: "", clientSecret: "", label: "Single sign-on", scopes: "openid email profile",
  publicUrl: "", autoCreate: false, defaultRole: "user", allowedDomains: "", linkByEmail: false };
const ssoStates = new Map();

function readSsoConfig() {
  let saved = {};
  try {
    saved = JSON.parse(database.prepare("SELECT value FROM app_settings WHERE key = 'sso_config'").get()?.value || "{}");
  } catch {
    saved = {};
  }
  return { ...ssoDefaults, ...saved };
}

function ssoPublicUrl(request, config = readSsoConfig()) {
  if (config.publicUrl) return config.publicUrl;
  const remote = normalizeIpAddress(request.socket.remoteAddress);
  const forwarded = String(request.headers["x-forwarded-proto"] || "").split(",")[0].trim().toLowerCase();
  const secure = request.socket.encrypted || process.env.COOKIE_SECURE === "true" || (remote && isTrustedProxy(remote) && forwarded === "https");
  return `${secure ? "https" : "http"}://${request.headers.host}`;
}

const ssoRedirectUri = (request, config) => `${ssoPublicUrl(request, config)}/api/auth/oidc/callback`;

function ssoLoginError(response, message) {
  sendRedirect(response, `/login.html?${new URLSearchParams({ sso_error: message.slice(0, 200) })}`);
}

function ssoUsernameFrom(claims) {
  const base = String(claims.preferred_username || (claims.email || "").split("@")[0] || claims.name || "user")
    .normalize("NFKD").replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 28) || "user";
  const padded = base.length >= 3 ? base : `${base}user`.slice(0, 28);
  for (let suffix = 0; suffix < 1000; suffix += 1) {
    const name = suffix ? `${padded}${suffix}` : padded;
    if (!database.prepare("SELECT 1 FROM users WHERE username = ?").get(name)) return name;
  }
  return `user${crypto.randomBytes(4).toString("hex")}`;
}

async function handleOidc(request, response, url) {
  const config = readSsoConfig();
  if (!config.enabled || !config.issuer || !config.clientId) return ssoLoginError(response, "Single sign-on is not set up.");
  if (url.pathname === "/api/auth/oidc/start") {
    try {
      const next = String(url.searchParams.get("next") || "/");
      const redirectUri = ssoRedirectUri(request, config);
      const login = await oidc.startLogin({ issuer: config.issuer, clientId: config.clientId, redirectUri, scopes: config.scopes });
      const now = Date.now();
      for (const [state, entry] of ssoStates) if (entry.expiresAt < now) ssoStates.delete(state);
      if (ssoStates.size > 5000) ssoStates.clear();
      const browser = crypto.randomBytes(24).toString("base64url");
      ssoStates.set(login.state, { nonce: login.nonce, verifier: login.verifier, redirectUri, browser, next: /^\/(?!\/)[^\s\\]*$/.test(next) ? next : "/", expiresAt: now + 10 * 60_000 });
      // The cookie ties the callback to the browser that started the sign-in.
      response.setHeader("set-cookie", `bnglookup_sso=${browser}; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=600${cookieSecureAttribute(response)}`);
      response.writeHead(302, { location: login.url, "cache-control": "no-store" });
      return response.end();
    } catch (error) {
      return ssoLoginError(response, `Single sign-on failed: ${error.message}`);
    }
  }
  // Callback from the identity provider.
  const state = url.searchParams.get("state") || "";
  const pending = ssoStates.get(state);
  ssoStates.delete(state);
  response.setHeader("set-cookie", `bnglookup_sso=; Path=/api/auth/oidc; HttpOnly; SameSite=Lax; Max-Age=0${cookieSecureAttribute(response)}`);
  if (!pending || pending.expiresAt < Date.now() || readCookie(request, "bnglookup_sso") !== pending.browser) {
    return ssoLoginError(response, "The sign-in took too long or was started in another browser. Try again.");
  }
  if (url.searchParams.get("error")) return ssoLoginError(response, `The identity provider refused the sign-in: ${url.searchParams.get("error_description") || url.searchParams.get("error")}`);
  let claims;
  try {
    claims = await oidc.finishLogin({ issuer: config.issuer, clientId: config.clientId, clientSecret: config.clientSecret, redirectUri: pending.redirectUri, code: url.searchParams.get("code") || "", verifier: pending.verifier, nonce: pending.nonce });
  } catch (error) {
    recordAdminLog("login", request, "Single sign-on failed", error.message.slice(0, 120), 401, null);
    return ssoLoginError(response, `Single sign-on failed: ${error.message}`);
  }
  const email = typeof claims.email === "string" && claims.email_verified !== false ? claims.email.trim().toLowerCase() : "";
  let row = database.prepare("SELECT users.* FROM oidc_identities JOIN users ON users.id = oidc_identities.user_id WHERE issuer = ? AND subject = ?").get(config.issuer, claims.sub);
  // Users enter their own email address, so linking by email trusts those addresses; it is
  // off by default and never links when more than one account uses the address.
  if (!row && config.linkByEmail && email && claims.email_verified === true) {
    const matches = database.prepare("SELECT * FROM users WHERE lower(email) = ? LIMIT 2").all(email);
    row = matches.length === 1 ? matches[0] : null;
    if (matches.length > 1) return ssoLoginError(response, "More than one account uses your email address. Ask an administrator to link your sign-in.");
    if (row) database.prepare("INSERT OR IGNORE INTO oidc_identities (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)").run(config.issuer, claims.sub, row.id, Date.now());
  }
  if (!row && config.autoCreate) {
    const domains = config.allowedDomains.split(/[\s,]+/).map((domain) => domain.trim().toLowerCase()).filter(Boolean);
    if (domains.length && !domains.includes(email.split("@")[1] || "")) {
      return ssoLoginError(response, "Your account is not from an allowed email domain. Ask an administrator for access.");
    }
    const username = ssoUsernameFrom(claims);
    const salt = crypto.randomBytes(16).toString("hex");
    const unusable = crypto.randomBytes(64).toString("hex");
    const created = database.prepare("INSERT INTO users (username, password_hash, password_salt, role, email) VALUES (?, ?, ?, ?, ?)")
      .run(username, unusable, salt, config.defaultRole === "admin" ? "admin" : "user", email || null);
    database.prepare("INSERT INTO oidc_identities (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)").run(config.issuer, claims.sub, created.lastInsertRowid, Date.now());
    row = database.prepare("SELECT * FROM users WHERE id = ?").get(created.lastInsertRowid);
    recordAdminLog("audit", request, "User created by single sign-on", `${username}${email ? ` (${email})` : ""}`, 201, username);
  }
  if (!row) {
    recordAdminLog("login", request, "Single sign-on: no matching account", email || claims.sub, 403, null);
    return ssoLoginError(response, "There is no account for this sign-in. Ask an administrator to create one or to link it to your email address.");
  }
  if (!row.active) return ssoLoginError(response, "This account is disabled.");
  await establishSession(row.id, response);
  recordNmapLoginIp(request, row.username);
  recordAdminLog("login", request, "Login successful (single sign-on)", email || claims.sub, 200, row.username);
  // The session cookie is SameSite=Strict, so it is not sent on a redirect chain that began
  // at the identity provider. A same-site page that moves on by itself starts a fresh navigation.
  const next = pending.next.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
  response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(`<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${next}"><title>Signing in</title><p>Signing you in… <a href="${next}">Continue</a></p>`);
}

function ssoAdminResponse(request) {
  const config = readSsoConfig();
  return { ...config, clientSecret: "", clientSecretSet: Boolean(config.clientSecret), redirectUri: ssoRedirectUri(request, config) };
}

function handleAdminSso(request, response, url) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") return sendJson(response, 200, ssoAdminResponse(request));
  if (!["PUT", "POST"].includes(request.method)) return sendJson(response, 405, { error: "Method not allowed." });
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response, 16384).then(async (body) => {
    if (!body) return;
    const current = readSsoConfig();
    let issuer = "";
    try {
      issuer = body.issuer ? oidc.issuerUrl(body.issuer) : "";
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
    if (url.pathname === "/api/admin/sso/test") {
      if (!issuer) return sendJson(response, 400, { error: "Enter the issuer URL first." });
      try {
        const config = await oidc.discover(issuer);
        return sendJson(response, 200, { ok: true, authorization: config.authorization_endpoint, token: config.token_endpoint, jwks: config.jwks_uri });
      } catch (error) {
        return sendJson(response, 400, { error: `Discovery failed: ${error.message}` });
      }
    }
    const text = (value, max) => (typeof value === "string" ? value.trim().replace(/[\u0000-\u001f\u007f]/g, "").slice(0, max) : "");
    let publicUrl = text(body.publicUrl, 200).replace(/\/$/, "");
    if (publicUrl) {
      try {
        const parsed = new URL(publicUrl);
        if (!["http:", "https:"].includes(parsed.protocol) || parsed.pathname !== "/" || parsed.search) throw new Error();
        publicUrl = parsed.origin;
      } catch {
        return sendJson(response, 400, { error: "The public address must look like https://lookup.example.com." });
      }
    }
    const next = {
      enabled: body.enabled === true,
      issuer,
      clientId: text(body.clientId, 200),
      clientSecret: typeof body.clientSecret === "string" && body.clientSecret ? body.clientSecret.slice(0, 500) : current.clientSecret,
      label: text(body.label, 40) || ssoDefaults.label,
      scopes: /^[\w :./-]{6,200}$/.test(body.scopes || "") && /\bopenid\b/.test(body.scopes) ? body.scopes.trim() : ssoDefaults.scopes,
      publicUrl,
      autoCreate: body.autoCreate === true,
      defaultRole: body.defaultRole === "admin" ? "admin" : "user",
      allowedDomains: text(body.allowedDomains, 500),
      linkByEmail: body.linkByEmail === true,
    };
    if (body.clearSecret === true) next.clientSecret = "";
    if (next.enabled && (!next.issuer || !next.clientId)) return sendJson(response, 400, { error: "Enter the issuer and client ID before turning single sign-on on." });
    database.prepare("INSERT INTO app_settings (key, value) VALUES ('sso_config', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(JSON.stringify(next));
    recordAdminLog("audit", request, "Single sign-on settings saved", `${next.enabled ? "on" : "off"} ${next.issuer}`, 200, admin.username);
    sendJson(response, 200, ssoAdminResponse(request));
  });
}

// ---------------------------------------------------------------- Backup and restore

const backupLimits = { uploadBytes: 256 * 1024 * 1024, fileBytes: 2 * 1024 * 1024 * 1024 };
let backupBusy = false;

function tarHeader(name, size, mtime = Date.now()) {
  const header = Buffer.alloc(512);
  const write = (value, offset, length) => header.write(value, offset, length, "utf8");
  const octal = (value, length) => `${value.toString(8).padStart(length - 1, "0")}\0`;
  write(name, 0, 100);
  write(octal(0o600, 8), 100, 8);
  write(octal(0, 8), 108, 8);
  write(octal(0, 8), 116, 8);
  write(octal(size, 12), 124, 12);
  write(octal(Math.floor(mtime / 1000), 12), 136, 12);
  write("        ", 148, 8);
  write("0", 156, 1);
  write("ustar\0", 257, 6);
  write("00", 263, 2);
  let sum = 0;
  for (const byte of header) sum += byte;
  write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8);
  return header;
}

async function* tarStream(entries) {
  for (const entry of entries) {
    yield tarHeader(entry.name, entry.size);
    if (entry.data) yield entry.data;
    else for await (const chunk of fs.createReadStream(entry.file)) yield chunk;
    if (entry.size % 512) yield Buffer.alloc(512 - (entry.size % 512));
  }
  yield Buffer.alloc(1024);
}

async function handleAdminBackup(request, response, admin) {
  if (backupBusy) return sendJson(response, 409, { error: "A backup or restore is already running." });
  backupBusy = true;
  const snapshot = path.join(dataDir, `.backup-${crypto.randomBytes(6).toString("hex")}.sqlite`);
  try {
    database.exec(`VACUUM INTO '${snapshot.replace(/'/g, "''")}'`);
    const entries = [];
    const addFile = (name, file) => entries.push({ name, file, size: fs.statSync(file).size });
    addFile("bnglookup.sqlite", snapshot);
    if (fs.existsSync(landingBackgroundFile)) addFile("landing-background", landingBackgroundFile);
    const acmeDir = path.join(dataDir, "acme");
    if (fs.existsSync(acmeDir)) {
      for (const name of fs.readdirSync(acmeDir)) {
        if (/^[\w.-]+$/.test(name) && fs.statSync(path.join(acmeDir, name)).isFile()) addFile(`acme/${name}`, path.join(acmeDir, name));
      }
    }
    const manifest = Buffer.from(JSON.stringify({
      app: "BNGlookup", version: appBuild.version, createdAt: new Date().toISOString(), createdBy: admin.username,
      files: entries.map(({ name, size }) => ({ name, size })),
    }, null, 2));
    entries.unshift({ name: "manifest.json", data: manifest, size: manifest.length });
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
    response.writeHead(200, {
      "content-type": "application/gzip",
      "content-disposition": `attachment; filename="bnglookup-backup-${stamp}.tar.gz"`,
    });
    await pipeline(Readable.from(tarStream(entries)), zlib.createGzip(), response);
    recordAdminLog("audit", request, "Backup downloaded", `${entries.length} files`, 200, admin.username);
  } catch (error) {
    if (!response.headersSent) sendJson(response, 500, { error: `The backup failed: ${error.message}` });
    else response.destroy(error);
  } finally {
    fs.rmSync(snapshot, { force: true });
    backupBusy = false;
  }
}

// Unpacks a .tar.gz into dir, accepting only the files a backup contains.
async function extractBackup(archiveFile, dir) {
  const found = new Set();
  let buffer = Buffer.alloc(0);
  let current = null;
  let ended = false;
  const allowedName = (name) => ["manifest.json", "bnglookup.sqlite", "landing-background"].includes(name) || /^acme\/[\w.-]+$/.test(name);
  for await (const chunk of fs.createReadStream(archiveFile).pipe(zlib.createGunzip())) {
    buffer = Buffer.concat([buffer, chunk]);
    while (!ended) {
      if (current) {
        const take = Math.min(current.remaining, buffer.length);
        if (take) {
          fs.writeSync(current.fd, buffer.subarray(0, take));
          buffer = buffer.subarray(take);
          current.remaining -= take;
        }
        if (current.remaining) break;
        if (buffer.length < current.padding) break;
        buffer = buffer.subarray(current.padding);
        fs.closeSync(current.fd);
        current = null;
        continue;
      }
      if (buffer.length < 512) break;
      const header = buffer.subarray(0, 512);
      buffer = buffer.subarray(512);
      if (header.every((byte) => byte === 0)) {
        ended = true;
        break;
      }
      const field = (offset, length) => header.subarray(offset, offset + length).toString("utf8").replace(/\0.*$/s, "");
      const prefix = field(345, 155);
      const name = (prefix ? `${prefix}/` : "") + field(0, 100);
      const size = parseInt(field(124, 12).trim() || "0", 8);
      const type = field(156, 1) || "0";
      if (type !== "0" || !allowedName(name) || name.includes("..") || !Number.isSafeInteger(size) || size > backupLimits.fileBytes) {
        throw new Error(`This is not a BNGlookup backup (unexpected entry "${name.slice(0, 60)}").`);
      }
      if (found.has(name)) throw new Error(`The backup contains "${name}" twice.`);
      found.add(name);
      const target = path.join(dir, name);
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      current = { fd: fs.openSync(target, "wx", 0o600), remaining: size, padding: (512 - (size % 512)) % 512 };
      if (!size && !current.padding) {
        fs.closeSync(current.fd);
        current = null;
      }
    }
  }
  if (current) throw new Error("The backup file is incomplete.");
  return found;
}

function handleAdminRestore(request, response, admin) {
  if (backupBusy) return sendJson(response, 409, { error: "A backup or restore is already running." });
  backupBusy = true;
  const upload = path.join(dataDir, `.restore-upload-${crypto.randomBytes(6).toString("hex")}`);
  const staging = path.join(dataDir, `.restore-staging-${crypto.randomBytes(6).toString("hex")}`);
  const finish = (status, body) => {
    fs.rmSync(upload, { force: true });
    fs.rmSync(staging, { recursive: true, force: true });
    backupBusy = false;
    sendJson(response, status, body);
  };
  if (Number(request.headers["content-length"] || 0) > backupLimits.uploadBytes) {
    request.resume();
    return finish(413, { error: "The backup file is larger than 256 MB." });
  }
  let received = 0;
  const output = fs.createWriteStream(upload, { mode: 0o600 });
  request.on("data", (chunk) => {
    received += chunk.length;
    if (received > backupLimits.uploadBytes) request.destroy(new Error("too large"));
  });
  pipeline(request, output).then(async () => {
    fs.mkdirSync(staging, { mode: 0o700 });
    const found = await extractBackup(upload, staging);
    if (!found.has("manifest.json") || !found.has("bnglookup.sqlite")) throw new Error("This is not a BNGlookup backup (the manifest or database is missing).");
    const manifest = JSON.parse(fs.readFileSync(path.join(staging, "manifest.json"), "utf8"));
    if (manifest.app !== "BNGlookup") throw new Error("This is not a BNGlookup backup.");
    const check = new DatabaseSync(path.join(staging, "bnglookup.sqlite"), { readOnly: true });
    try {
      if (check.prepare("PRAGMA integrity_check").get()?.integrity_check !== "ok") throw new Error("The database in the backup is damaged.");
      const admins = check.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").get().count;
      if (!admins) throw new Error("The backup has no administrator account, so nobody could log in after restoring it.");
    } catch (error) {
      throw new Error(/no such table/i.test(error.message) ? "The database in the backup is not a BNGlookup database." : error.message);
    } finally {
      check.close();
    }
    fs.rmSync(path.join(staging, "manifest.json"));
    fs.rmSync(restorePendingDir, { recursive: true, force: true });
    fs.renameSync(staging, restorePendingDir);
    fs.writeFileSync(path.join(restorePendingDir, "ready"), new Date().toISOString(), { mode: 0o600 });
    recordAdminLog("audit", request, "Backup restore scheduled", `backup from ${String(manifest.createdAt || "unknown").slice(0, 19)}`, 200, admin.username);
    finish(200, { restarting: true, createdAt: manifest.createdAt || null, version: manifest.version || null });
    console.log("A backup restore was uploaded; restarting to apply it.");
    setTimeout(() => shutdown("restore"), 500);
  }).catch((error) => {
    const message = error.code === "Z_DATA_ERROR" || /incorrect header check/i.test(error.message)
      ? "The file is not a .tar.gz backup."
      : error.message === "too large" ? "The backup file is larger than 256 MB." : error.message;
    finish(400, { error: message });
  });
}

function handleAdminBackupRoutes(request, response, url) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method !== "POST") return sendJson(response, 405, { error: "Method not allowed." });
  if (!enforceSameOrigin(request, response)) return;
  if (url.pathname === "/api/admin/backup") return void handleAdminBackup(request, response, admin);
  return handleAdminRestore(request, response, admin);
}

// ---------------------------------------------------------------- Public lookup limits and IP lists

const publicAccessDefaults = { dailyLimit: 15, unlimited: [], blocked: [], blockSite: false };
let publicAccessCache = null;

// Parses one CIDR or address per line; minPrefix stops a block list from covering everyone.
function parseAccessRanges(value, label, minPrefix) {
  if (typeof value !== "string" || value.length > 12288) throw new Error(`The ${label} list is too long.`);
  const entries = [...new Set(value.split(/[,\s]+/).map((entry) => entry.trim()).filter(Boolean))];
  if (entries.length > 500) throw new Error(`The ${label} list may contain at most 500 entries.`);
  const ranges = new net.BlockList();
  for (const entry of entries) {
    const [address, prefixText, ...extra] = entry.split("/");
    const family = isIP(address);
    const maxPrefix = family === 4 ? 32 : 128;
    const prefix = prefixText === undefined ? maxPrefix : Number(prefixText);
    const lowest = family === 4 ? minPrefix.ipv4 : minPrefix.ipv6;
    if (!family || extra.length || (prefixText !== undefined && !/^\d+$/.test(prefixText)) || prefix < lowest || prefix > maxPrefix) {
      throw new Error(`Invalid ${label} entry: ${entry}. Use an address or CIDR (IPv4 /${minPrefix.ipv4}–/32, IPv6 /${minPrefix.ipv6}–/128).`);
    }
    ranges.addSubnet(address, prefix, family === 4 ? "ipv4" : "ipv6");
  }
  return { entries, ranges };
}

function getPublicAccess() {
  if (publicAccessCache) return publicAccessCache;
  let saved = {};
  try {
    saved = JSON.parse(database.prepare("SELECT value FROM app_settings WHERE key = 'public_access'").get()?.value || "{}");
  } catch {
    saved = {};
  }
  const safe = (list, label, minPrefix) => {
    try {
      return parseAccessRanges((Array.isArray(list) ? list : []).join("\n"), label, minPrefix);
    } catch {
      return { entries: [], ranges: new net.BlockList() };
    }
  };
  publicAccessCache = {
    dailyLimit: Number.isInteger(saved.dailyLimit) ? saved.dailyLimit : publicAccessDefaults.dailyLimit,
    unlimited: safe(saved.unlimited, "unlimited", { ipv4: 0, ipv6: 0 }),
    blocked: safe(saved.blocked, "blocked", { ipv4: 8, ipv6: 16 }),
    blockSite: saved.blockSite === true,
  };
  return publicAccessCache;
}

function addressInRanges(ranges, address) {
  const plain = String(address || "").replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, "");
  const family = isIP(plain);
  return Boolean(family) && ranges.check(plain, family === 4 ? "ipv4" : "ipv6");
}

function publicAccessResponse(request) {
  const access = getPublicAccess();
  return {
    dailyLimit: access.dailyLimit,
    unlimited: access.unlimited.entries.join("\n"),
    blocked: access.blocked.entries.join("\n"),
    blockSite: access.blockSite,
    yourAddress: getClientAddress(request) || null,
  };
}

function handleAdminPublicAccess(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    sendJson(response, 200, publicAccessResponse(request));
    return;
  }
  if (request.method !== "PUT") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response, 65536).then((body) => {
    if (!body) return;
    const dailyLimit = Number(body.dailyLimit);
    if (!Number.isInteger(dailyLimit) || dailyLimit < 1 || dailyLimit > 100000) {
      return sendJson(response, 400, { error: "The daily limit must be a whole number from 1 to 100,000." });
    }
    if (typeof body.blockSite !== "boolean") return sendJson(response, 400, { error: "Choose what blocked networks may do." });
    let unlimited;
    let blocked;
    try {
      unlimited = parseAccessRanges(body.unlimited ?? "", "unlimited", { ipv4: 0, ipv6: 0 });
      blocked = parseAccessRanges(body.blocked ?? "", "blocked", { ipv4: 8, ipv6: 16 });
    } catch (error) {
      return sendJson(response, 400, { error: error.message });
    }
    const own = getClientAddress(request);
    if (body.blockSite && own && addressInRanges(blocked.ranges, own)) {
      return sendJson(response, 400, { error: `Your own address (${own}) is in the blocked list, so this would lock you out. Remove it or only block public lookups.` });
    }
    database.prepare(`
      INSERT INTO app_settings (key, value) VALUES ('public_access', ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(JSON.stringify({ dailyLimit, unlimited: unlimited.entries, blocked: blocked.entries, blockSite: body.blockSite }));
    publicAccessCache = null;
    recordAdminLog("audit", request, "Public access limits updated",
      `${dailyLimit}/day, ${unlimited.entries.length} unlimited, ${blocked.entries.length} blocked${body.blockSite ? " (whole site)" : ""}`, 200, admin.username);
    sendJson(response, 200, publicAccessResponse(request));
  });
}

// ---------------------------------------------------------------- Site files (robots.txt, security.txt, …)

const siteFiles = {
  robots: { label: "robots.txt", paths: ["/robots.txt"] },
  security: { label: "security.txt", paths: ["/.well-known/security.txt", "/security.txt"] },
  humans: { label: "humans.txt", paths: ["/humans.txt"] },
};
const siteFileLimit = 16384;
const robotsDirectives = /^(user-agent|allow|disallow|sitemap|crawl-delay|host|clean-param|request-rate|visit-time|noindex)$/i;

function readSiteFileSettings() {
  let saved = {};
  try {
    saved = JSON.parse(database.prepare("SELECT value FROM app_settings WHERE key = 'site_files'").get()?.value || "{}");
  } catch {
    saved = {};
  }
  const files = Object.fromEntries(Object.keys(siteFiles).map((id) => {
    const file = saved.files?.[id] || {};
    return [id, { enabled: file.enabled === true, content: typeof file.content === "string" ? file.content : "", updatedAt: file.updatedAt || null }];
  }));
  return { files, changePassword: saved.changePassword !== false };
}

function saveSiteFileSettings(settings) {
  database.prepare(`
    INSERT INTO app_settings (key, value) VALUES ('site_files', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(JSON.stringify(settings));
}

// Returns { errors, warnings } for a file's content; errors block publishing it.
function checkSiteFile(id, content) {
  const errors = [];
  const warnings = [];
  const lines = content.split("\n");
  if (id === "robots") {
    lines.forEach((line, index) => {
      const text = line.replace(/#.*/, "").trim();
      if (!text) return;
      const directive = text.match(/^([A-Za-z-]+)\s*:/)?.[1];
      if (!directive || !robotsDirectives.test(directive)) warnings.push(`Line ${index + 1} is not a robots.txt rule: "${text.slice(0, 60)}".`);
    });
    if (/user-agent\s*:\s*\*\s*\n(?:\s*(?:allow|disallow)\s*:.*\n)*?\s*disallow\s*:\s*\/\s*(\n|$)/im.test(`${content}\n`)) {
      warnings.push("All crawlers are blocked from the whole site (Disallow: /).");
    }
  }
  if (id === "security") {
    const field = (name) => lines.map((line) => line.match(new RegExp(`^\\s*${name}\\s*:\\s*(.+?)\\s*$`, "i"))?.[1]).filter(Boolean);
    const contacts = field("contact");
    const expires = field("expires");
    if (!contacts.length) errors.push("Add at least one Contact field (an email as mailto:, an https: URL or a tel: number).");
    for (const contact of contacts) {
      if (!/^(mailto:\S+@\S+|https:\/\/\S+|tel:\+?[\d\s()-]+)$/i.test(contact)) errors.push(`Contact "${contact.slice(0, 60)}" must start with mailto:, https:// or tel:.`);
    }
    if (expires.length !== 1) {
      errors.push("Add exactly one Expires field, such as Expires: 2027-10-30T00:00:00Z (required by RFC 9116).");
    } else {
      const time = Date.parse(expires[0]);
      if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/.test(expires[0]) || Number.isNaN(time)) {
        errors.push("Expires must be a date and time such as 2027-10-30T00:00:00Z.");
      } else if (time < Date.now()) {
        errors.push("The Expires date is in the past.");
      } else if (time - Date.now() > 366 * 86400000) {
        warnings.push("Expires is more than a year away; RFC 9116 recommends less than a year.");
      } else if (time - Date.now() < 30 * 86400000) {
        warnings.push(`security.txt expires in ${Math.ceil((time - Date.now()) / 86400000)} days.`);
      }
    }
    for (const url of [...field("policy"), ...field("encryption"), ...field("acknowledgments"), ...field("canonical"), ...field("hiring")]) {
      if (/^http:\/\//i.test(url)) warnings.push(`${url.slice(0, 60)} should use https://.`);
    }
    if (!field("canonical").length) warnings.push("No Canonical field with the address where this file is published.");
  }
  return { errors, warnings };
}

function siteFilesResponse(request) {
  const settings = readSiteFileSettings();
  return {
    changePassword: settings.changePassword,
    files: Object.fromEntries(Object.entries(siteFiles).map(([id, definition]) => [id, {
      ...settings.files[id],
      label: definition.label,
      paths: definition.paths,
      ...checkSiteFile(id, settings.files[id].content),
    }])),
    limit: siteFileLimit,
  };
}

function handleAdminSiteFiles(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    sendJson(response, 200, siteFilesResponse(request));
    return;
  }
  if (request.method !== "PUT") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response, 65536).then((body) => {
    if (!body) return;
    const settings = readSiteFileSettings();
    if (body.id === "change-password") {
      if (typeof body.enabled !== "boolean") return sendJson(response, 400, { error: "Choose whether to publish the redirect." });
      settings.changePassword = body.enabled;
      saveSiteFileSettings(settings);
      recordAdminLog("audit", request, "Site file updated", `change-password redirect ${body.enabled ? "on" : "off"}`, 200, admin.username);
      return sendJson(response, 200, siteFilesResponse(request));
    }
    if (!Object.hasOwn(siteFiles, body.id)) return sendJson(response, 400, { error: "Unknown site file." });
    if (typeof body.enabled !== "boolean" || typeof body.content !== "string") return sendJson(response, 400, { error: "Send the file content and whether it is published." });
    const content = body.content.replace(/\r\n?/g, "\n");
    if (Buffer.byteLength(content) > siteFileLimit) return sendJson(response, 400, { error: `The file must be ${siteFileLimit / 1024} KB or smaller.` });
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content)) return sendJson(response, 400, { error: "The file contains control characters." });
    if (body.enabled && !content.trim()) return sendJson(response, 400, { error: "Add content before publishing the file." });
    const check = checkSiteFile(body.id, content);
    if (body.enabled && check.errors.length) return sendJson(response, 400, { error: check.errors[0], errors: check.errors, warnings: check.warnings });
    settings.files[body.id] = { enabled: body.enabled, content, updatedAt: new Date().toISOString() };
    saveSiteFileSettings(settings);
    recordAdminLog("audit", request, "Site file updated", `${siteFiles[body.id].label} ${body.enabled ? "published" : "off"}`, 200, admin.username);
    sendJson(response, 200, siteFilesResponse(request));
  });
}

// Serves a published site file or the change-password redirect; returns false otherwise.
function serveSiteFile(request, response, pathname) {
  const settings = readSiteFileSettings();
  if (pathname === "/.well-known/change-password" && settings.changePassword) {
    sendRedirect(response, "/my-account.html");
    return true;
  }
  const id = Object.keys(siteFiles).find((key) => siteFiles[key].paths.includes(pathname));
  const file = id && settings.files[id];
  if (!file?.enabled || !file.content.trim()) return false;
  const body = file.content.endsWith("\n") ? file.content : `${file.content}\n`;
  response.writeHead(200, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "public, max-age=3600",
    "cross-origin-resource-policy": "cross-origin",
    "access-control-allow-origin": "*",
  });
  response.end(request.method === "HEAD" ? undefined : body);
  return true;
}

// ---------------------------------------------------------------- Simple landing page

const landingFonts = {
  system: "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif",
  rounded: "ui-rounded, \"SF Pro Rounded\", \"Nunito\", system-ui, sans-serif",
  serif: "\"Iowan Old Style\", \"Palatino Linotype\", Georgia, serif",
  mono: "ui-monospace, \"SF Mono\", \"Cascadia Code\", Menlo, monospace",
  geometric: "\"Avenir Next\", \"Montserrat\", \"Century Gothic\", system-ui, sans-serif",
};
const landingDefaults = {
  enabled: true,
  userInterface: "full",
  theme: {
    background: "#06080f", background2: "#11203d", surface: "#0f1524", text: "#eef2ff", muted: "#8b96b2",
    accent: "#7c5cff", accent2: "#22d3ee", success: "#34d399", warning: "#fbbf24", danger: "#f87171",
    font: "system", radius: 18, animations: true, glass: true,
    backgroundMode: "aurora", overlay: 55, blur: 0,
  },
  content: {
    headline: "Check any domain in seconds",
    subheadline: "DNS, email security, HTTPS, reputation and more, in one scan.",
    placeholder: "example.com, an IP address or a MAC address",
    button: "Scan",
    login: "Log in",
    footer: "",
    examples: "example.com, 1.1.1.1, wikipedia.org",
    empty: "No checks are available without an account yet. Log in to use all tools.",
    tabOverview: "Overview", tabDns: "DNS", tabEmail: "Email", tabWeb: "Web & TLS", tabSecurity: "Security", tabNetwork: "Network",
  },
};
const landingContentLimits = { headline: 120, subheadline: 240, placeholder: 80, button: 24, login: 24, footer: 300, examples: 200, empty: 240 };
const landingBackgroundTypes = { "image/png": [0x89, 0x50, 0x4e, 0x47], "image/jpeg": [0xff, 0xd8, 0xff], "image/webp": [0x52, 0x49, 0x46, 0x46], "image/gif": [0x47, 0x49, 0x46] };
const landingBackgroundFile = path.join(dataDir, "landing-background");
const landingScanTokens = new Map();
const landingTokenLimits = { lifetimeMs: 5 * 60 * 1000, uses: 30, perFeature: 8 };

function readLandingConfig() {
  let saved = {};
  try {
    saved = JSON.parse(database.prepare("SELECT value FROM app_settings WHERE key = 'landing_config'").get()?.value || "{}");
  } catch {
    saved = {};
  }
  return {
    enabled: typeof saved.enabled === "boolean" ? saved.enabled : landingDefaults.enabled,
    userInterface: saved.userInterface === "simple" ? "simple" : "full",
    theme: { ...landingDefaults.theme, ...(saved.theme || {}) },
    content: { ...landingDefaults.content, ...(saved.content || {}) },
    background: saved.background || null,
  };
}

function validateLandingConfig(body) {
  const theme = {};
  const content = {};
  const source = body && typeof body === "object" ? body : {};
  for (const key of ["background", "background2", "surface", "text", "muted", "accent", "accent2", "success", "warning", "danger"]) {
    const value = source.theme?.[key];
    if (typeof value !== "string" || !/^#[0-9a-f]{6}$/i.test(value)) return { error: `Choose a valid color for ${key}.` };
    theme[key] = value.toLowerCase();
  }
  if (!Object.hasOwn(landingFonts, source.theme?.font)) return { error: "Choose one of the listed fonts." };
  theme.font = source.theme.font;
  if (!["aurora", "gradient", "solid", "image"].includes(source.theme?.backgroundMode)) return { error: "Choose a background style." };
  theme.backgroundMode = source.theme.backgroundMode;
  for (const [key, min, max] of [["radius", 0, 32], ["overlay", 0, 95], ["blur", 0, 24]]) {
    const value = Number(source.theme?.[key]);
    if (!Number.isInteger(value) || value < min || value > max) {
      return { error: `${{ radius: "Rounding", overlay: "Image dimming", blur: "Image blur" }[key]} must be between ${min} and ${max}.` };
    }
    theme[key] = value;
  }
  theme.animations = source.theme?.animations !== false;
  theme.glass = source.theme?.glass !== false;
  for (const key of Object.keys(landingDefaults.content)) {
    const value = source.content?.[key];
    const limit = landingContentLimits[key] || 30;
    if (typeof value !== "string" || value.length > limit || /[\u0000-\u0008\u000b-\u001f\u007f]/.test(value)) {
      return { error: `The text for "${key}" must be at most ${limit} characters.` };
    }
    content[key] = value.trim();
  }
  for (const key of ["headline", "button", "placeholder", "tabOverview", "tabDns", "tabEmail", "tabWeb", "tabSecurity", "tabNetwork"]) {
    if (!content[key]) return { error: `The text for "${key}" cannot be empty.` };
  }
  if (!["full", "simple"].includes(source.userInterface)) return { error: "Choose the interface logged-in users start in." };
  return { value: { enabled: source.enabled !== false, userInterface: source.userInterface, theme, content } };
}

function publicLandingConfig(config = readLandingConfig()) {
  const access = getFeatureAccess();
  return {
    enabled: config.enabled,
    userInterface: config.userInterface,
    siteTitle: getSiteTitle(),
    iconUrl: getSiteIconUrl(),
    theme: { ...config.theme, fontStack: landingFonts[config.theme.font] || landingFonts.system },
    content: config.content,
    background: config.background ? { url: `/landing/background?v=${encodeURIComponent(config.background.updatedAt)}` } : null,
    publicFeatures: Object.entries(access).filter(([, level]) => level === "public").map(([feature]) => feature),
    dailyLimit: getPublicAccess().dailyLimit,
  };
}

function saveLandingConfig(config) {
  database.prepare(`
    INSERT INTO app_settings (key, value) VALUES ('landing_config', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(JSON.stringify(config));
}

function handleAdminLanding(request, response, url) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  const config = readLandingConfig();
  if (url.pathname === "/api/admin/landing" && request.method === "GET") {
    sendJson(response, 200, { ...publicLandingConfig(config), defaults: landingDefaults, fonts: landingFonts });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  if (url.pathname === "/api/admin/landing" && request.method === "PUT") {
    void readAuthBody(request, response, 32768).then((body) => {
      if (!body) return;
      const result = validateLandingConfig(body);
      if (result.error) return sendJson(response, 400, { error: result.error });
      saveLandingConfig({ ...result.value, background: config.background });
      recordAdminLog("audit", request, "Landing page updated", result.value.enabled ? "enabled" : "disabled", 200, admin.username);
      sendJson(response, 200, publicLandingConfig());
    });
    return;
  }
  if (url.pathname === "/api/admin/landing/background" && request.method === "PUT") {
    void readAuthBody(request, response, 8 * 1024 * 1024).then((body) => {
      if (!body) return;
      const match = String(body.image || "").match(/^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+/=]+)$/);
      const data = match ? Buffer.from(match[2], "base64") : null;
      const magic = match ? landingBackgroundTypes[match[1]] : null;
      if (!data || !magic || !magic.every((byte, index) => data[index] === byte) || (match[1] === "image/webp" && data.subarray(8, 12).toString() !== "WEBP")) {
        return sendJson(response, 400, { error: "Upload a PNG, JPEG, WebP or GIF image." });
      }
      if (data.length > 5 * 1024 * 1024) return sendJson(response, 400, { error: "The image must be 5 MB or smaller." });
      fs.writeFileSync(landingBackgroundFile, data, { mode: 0o600 });
      const background = { type: match[1], bytes: data.length, updatedAt: new Date().toISOString() };
      saveLandingConfig({ ...config, background, theme: { ...config.theme, backgroundMode: "image" } });
      recordAdminLog("audit", request, "Landing page background uploaded", `${Math.round(data.length / 1024)} KB`, 200, admin.username);
      sendJson(response, 200, publicLandingConfig());
    });
    return;
  }
  if (url.pathname === "/api/admin/landing/background" && request.method === "DELETE") {
    fs.rmSync(landingBackgroundFile, { force: true });
    saveLandingConfig({ ...config, background: null, theme: { ...config.theme, backgroundMode: config.theme.backgroundMode === "image" ? "aurora" : config.theme.backgroundMode } });
    recordAdminLog("audit", request, "Landing page background removed", null, 200, admin.username);
    sendJson(response, 200, publicLandingConfig());
    return;
  }
  sendJson(response, 405, { error: "Method not allowed." });
}

function serveLandingBackground(request, response) {
  const background = readLandingConfig().background;
  if (!background || !fs.existsSync(landingBackgroundFile)) {
    response.writeHead(404, { "content-type": "text/plain" }).end("Not found");
    return;
  }
  const data = fs.readFileSync(landingBackgroundFile);
  response.writeHead(200, {
    "content-type": background.type,
    "content-length": data.length,
    "cache-control": "public, max-age=86400",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; sandbox",
  });
  response.end(request.method === "HEAD" ? undefined : data);
}

// Shared landing page scans: stored results anyone with the link can open at /s/<id>.
// Anonymous visitors may share too, with a per-IP daily limit and a shorter lifetime.
database.exec(`
  CREATE TABLE IF NOT EXISTS landing_shares (
    id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    client_hash TEXT,
    title TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS landing_shares_client ON landing_shares(client_hash, created_at);
`);
const landingShareLimits = { payloadBytes: 768 * 1024, anonymousPerDay: 10, anonymousTotal: 5000, userLifetimeMs: 30 * 86400000, anonymousLifetimeMs: 7 * 86400000 };
const landingJobIds = new Set(["records", "dnssec", "whois", "propagation", "dns-health", "email", "mail-server", "web", "tls", "reputation", "lookalike", "ping", "asn", "reverse", "mac"]);

function validLandingSharePayload(body) {
  const target = body?.target;
  if (!target || !["domain", "ip", "mac"].includes(target.kind) || typeof target.value !== "string" || !target.value || target.value.length > 253 ||
    /[\s\u0000-\u001f<>"]/.test(target.value)) return null;
  if (!Array.isArray(body.jobs) || !body.jobs.length || body.jobs.length > 20) return null;
  const jobs = [];
  for (const job of body.jobs) {
    if (!job || !landingJobIds.has(job.id) || jobs.some((item) => item.id === job.id)) return null;
    if (job.error !== undefined) {
      if (typeof job.error !== "string") return null;
      jobs.push({ id: job.id, error: job.error.slice(0, 300) });
    } else if (job.data && typeof job.data === "object") {
      jobs.push({ id: job.id, data: job.data });
    } else {
      return null;
    }
  }
  return { target: { kind: target.kind, value: target.value }, jobs, createdAt: new Date().toISOString() };
}

async function handleLandingShares(request, url, response) {
  const now = Date.now();
  database.prepare("DELETE FROM landing_shares WHERE expires_at <= ?").run(now);
  if (url.pathname.startsWith("/api/landing/shares/")) {
    const id = url.pathname.slice("/api/landing/shares/".length);
    const row = /^[A-Za-z0-9_-]{22}$/.test(id) && request.method === "GET" ? database.prepare("SELECT * FROM landing_shares WHERE id = ?").get(id) : null;
    if (!row) return sendJson(response, request.method === "GET" ? 404 : 405, { error: "This shared result does not exist or has expired." });
    response.setHeader("x-robots-tag", "noindex");
    return sendJson(response, 200, { id: row.id, title: row.title, expiresAt: new Date(row.expires_at).toISOString(), ...JSON.parse(row.payload) });
  }
  if (request.method !== "POST") return sendJson(response, 405, { error: "Method not allowed." });
  if (!enforceSameOrigin(request, response)) return;
  const user = currentUser(request);
  if (!user && !readLandingConfig().enabled) return sendJson(response, 404, { error: "The landing page is turned off." });
  let body;
  try {
    body = await readJsonRequest(request, landingShareLimits.payloadBytes + 4096);
  } catch (error) {
    return sendJson(response, error.statusCode || 400, { error: error.message });
  }
  const payload = validLandingSharePayload(body);
  if (!payload) return sendJson(response, 400, { error: "This result cannot be shared." });
  const text = JSON.stringify(payload);
  if (Buffer.byteLength(text) > landingShareLimits.payloadBytes) return sendJson(response, 413, { error: "This result is too large to share." });
  let clientHash = null;
  if (!user) {
    clientHash = crypto.createHmac("sha256", publicLookupHashKey).update(getClientAddress(request) || "unknown").digest("hex");
    const today = database.prepare("SELECT COUNT(*) AS count FROM landing_shares WHERE client_hash = ? AND created_at > ?").get(clientHash, now - 86400000).count;
    if (today >= landingShareLimits.anonymousPerDay) {
      return sendJson(response, 429, { error: `You can share ${landingShareLimits.anonymousPerDay} results per day without an account.` });
    }
    const total = database.prepare("SELECT COUNT(*) AS count FROM landing_shares WHERE user_id IS NULL").get().count;
    if (total >= landingShareLimits.anonymousTotal) {
      database.prepare("DELETE FROM landing_shares WHERE id IN (SELECT id FROM landing_shares WHERE user_id IS NULL ORDER BY created_at LIMIT ?)").run(total - landingShareLimits.anonymousTotal + 1);
    }
  }
  const id = crypto.randomBytes(16).toString("base64url").slice(0, 22);
  const expiresAt = now + (user ? landingShareLimits.userLifetimeMs : landingShareLimits.anonymousLifetimeMs);
  database.prepare("INSERT INTO landing_shares (id, user_id, client_hash, title, payload, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(id, user?.id ?? null, clientHash, payload.target.value, text, now, expiresAt);
  recordAdminLog("audit", request, "Landing scan shared", payload.target.value, 201, user?.username ?? null);
  sendJson(response, 201, { id, url: `/s/${id}`, expiresAt: new Date(expiresAt).toISOString() });
}

// A combined landing scan counts as one public lookup: the token it returns lets the
// browser call the public tools for a few minutes without using more of the daily quota.
function handleLandingStart(request, response) {
  if (!readLandingConfig().enabled && !currentUser(request)) {
    sendJson(response, 404, { error: "The landing page is turned off." });
    return;
  }
  const now = Date.now();
  for (const [token, entry] of landingScanTokens) if (entry.expiresAt < now) landingScanTokens.delete(token);
  if (landingScanTokens.size > 20000) landingScanTokens.clear();
  if (!currentUser(request) && !consumePublicLookup(request, response)) return;
  const token = crypto.randomBytes(24).toString("base64url");
  landingScanTokens.set(token, { client: getClientAddress(request) || "unknown", expiresAt: now + landingTokenLimits.lifetimeMs, uses: 0, features: {} });
  sendJson(response, 200, { token, expiresInSeconds: landingTokenLimits.lifetimeMs / 1000 });
}

function landingTokenAllows(request, feature) {
  const token = String(request.headers["x-landing-scan"] || "");
  const entry = token && landingScanTokens.get(token);
  if (!entry || entry.expiresAt < Date.now() || entry.client !== (getClientAddress(request) || "unknown")) return false;
  if (entry.uses >= landingTokenLimits.uses || (entry.features[feature] || 0) >= landingTokenLimits.perFeature) return false;
  entry.uses += 1;
  entry.features[feature] = (entry.features[feature] || 0) + 1;
  return true;
}

const ripeStatCache = new Map();

async function ripeStat(dataCall, params) {
  const url = new URL(`https://stat.ripe.net/data/${dataCall}/data.json`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  url.searchParams.set("sourceapp", "bnglookup");
  const cached = ripeStatCache.get(url.href);
  if (cached && Date.now() - cached.at < 10 * 60_000) return cached.data;
  const response = await fetch(url, {
    headers: { accept: "application/json", "user-agent": "BNGlookup (+https://github.com/BANAANGA/BNGlookup)" },
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`RIPE Stat returned HTTP ${response.status}.`);
  const body = await response.json();
  if (body.status !== "ok" || !body.data) throw new Error("RIPE Stat returned no data.");
  if (ripeStatCache.size > 500) ripeStatCache.clear();
  ripeStatCache.set(url.href, { data: body.data, at: Date.now() });
  return body.data;
}

function prefixAddressCount(prefix) {
  const [network, length] = prefix.split("/");
  const bits = (isIP(network) === 4 ? 32 : 128) - Number(length);
  return isIP(network) === 4 ? 2 ** bits : null;
}

async function asnLookup(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  // Check for an AS number first: URL parsing would read a bare number such as 13335 as an IPv4 address.
  const asMatch = rawName.trim().match(/^(?:as)?\s*(\d{1,10})$/i);
  const input = asMatch ? rawName.trim() : hostFromInput(rawName.trim());
  const started = Date.now();
  try {
    let asn = null;
    let address = null;
    let target = input;
    if (asMatch && Number(asMatch[1]) <= 4294967295) {
      asn = Number(asMatch[1]);
      target = `AS${asn}`;
    } else if (isIP(input)) {
      address = input;
    } else {
      const domain = normalizeDomain(input);
      if (!domain) {
        sendJson(response, 400, { error: "Enter an IP address, a domain name or an AS number (for example AS13335)." });
        return;
      }
      target = domain;
      const answers = (await queryDohDns(domain, "A")).answers.filter((answer) => answer.type === 1 || answer.typeName === "A");
      address = answers.map((answer) => answer.data).find((value) => isPublicAddress(value)) || null;
      if (!address) {
        sendJson(response, 400, { error: `${domain} has no public IPv4 address to look up.` });
        return;
      }
    }
    if (address && !isPublicAddress(address)) {
      sendJson(response, 400, { error: "This is a private or reserved address. It is not announced on the internet, so it has no ASN." });
      return;
    }
    let network = null;
    if (address) {
      const info = await ripeStat("network-info", { resource: address });
      const asns = (Array.isArray(info.asns) ? info.asns : []).map(Number).filter(Number.isInteger);
      network = { address, prefix: typeof info.prefix === "string" ? info.prefix : null, asns };
      if (!asns.length) {
        sendJson(response, 200, { target, network, as: null, prefixes: null, durationMs: Date.now() - started });
        return;
      }
      asn = asns[0];
    }
    const settle = (promise) => promise.catch((error) => ({ error: error.message }));
    const [overview, announced, rpki] = await Promise.all([
      settle(ripeStat("as-overview", { resource: `AS${asn}` })),
      settle(ripeStat("announced-prefixes", { resource: `AS${asn}`, min_peers_seeing: "3" })),
      network?.prefix ? settle(ripeStat("rpki-validation", { resource: `AS${asn}`, prefix: network.prefix })) : Promise.resolve(null),
    ]);
    if (network && rpki && !rpki.error) {
      network.rpki = {
        status: typeof rpki.status === "string" ? rpki.status : null,
        roas: (Array.isArray(rpki.validating_roas) ? rpki.validating_roas : []).slice(0, 10).map((roa) => ({
          origin: roa.origin, prefix: roa.prefix, maxLength: roa.max_length, validity: roa.validity,
        })),
      };
    }
    const prefixList = (Array.isArray(announced.prefixes) ? announced.prefixes : [])
      .map((entry) => entry?.prefix)
      .filter((prefix) => typeof prefix === "string" && /^[0-9a-f:.]+\/\d{1,3}$/i.test(prefix));
    const ipv4 = prefixList.filter((prefix) => isIP(prefix.split("/")[0]) === 4).sort((left, right) => {
      const toNumber = (value) => value.split("/")[0].split(".").reduce((total, octet) => total * 256 + Number(octet), 0);
      return toNumber(left) - toNumber(right);
    });
    const ipv6 = prefixList.filter((prefix) => isIP(prefix.split("/")[0]) === 6).sort();
    const limit = 3000;
    sendJson(response, 200, {
      target,
      network,
      as: overview.error ? { asn, error: overview.error } : {
        asn,
        holder: typeof overview.holder === "string" ? overview.holder : null,
        announced: Boolean(overview.announced),
        registry: typeof overview.block?.desc === "string" ? overview.block.desc : null,
      },
      prefixes: announced.error ? { error: announced.error } : {
        ipv4Count: ipv4.length,
        ipv6Count: ipv6.length,
        ipv4Addresses: ipv4.reduce((total, prefix) => total + (prefixAddressCount(prefix) || 0), 0),
        ipv4: ipv4.slice(0, limit),
        ipv6: ipv6.slice(0, limit),
        truncated: ipv4.length > limit || ipv6.length > limit,
      },
      durationMs: Date.now() - started,
    });
  } catch (error) {
    sendJson(response, 502, { error: error.name === "TimeoutError" ? "RIPE Stat did not respond in time." : `Unable to look up routing data: ${error.message}` });
  }
}

const propagationTypes = new Set(["A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "HTTPS", "MX", "NS", "PTR", "SOA", "SRV", "SVCB", "TLSA", "TXT"]);

function propagationAnswerKey(type, answers) {
  const typeCode = dnsTypeCodes[type];
  return answers
    .filter((answer) => answer.type === typeCode || answer.typeName === type)
    .map((answer) => {
      const value = String(answer.data).trim();
      return type === "SOA"
        ? value.split(/\s+/).slice(0, 3).join(" ").toLowerCase()
        : type === "TXT" ? txtRecordText(value) : value.toLowerCase().replace(/\.$/, "").replace(/\.(\s|$)/g, "$1");
    })
    .sort();
}

async function findAuthoritativeServers(name) {
  const labels = name.replace(/\.$/, "").split(".");
  for (let index = 0; index < labels.length - 1; index += 1) {
    const zone = labels.slice(index).join(".");
    let data;
    try {
      data = await queryDohDns(zone, "NS");
    } catch {
      continue;
    }
    const hosts = data.answers
      .filter((answer) => (answer.type === 2 || answer.typeName === "NS") && String(answer.name).toLowerCase().replace(/\.$/, "") === zone.toLowerCase())
      .map((answer) => String(answer.data).replace(/\.$/, "").toLowerCase());
    if (!hosts.length) continue;
    const servers = await Promise.all(hosts.slice(0, 6).map(async (host) => {
      try {
        const addresses = (await queryDohDns(host, "A")).answers
          .filter((answer) => answer.type === 1 || answer.typeName === "A")
          .map((answer) => answer.data);
        return { host, address: addresses.find((address) => isPublicAddress(address)) || null, skipped: addresses.length > 0 && !addresses.some((address) => isPublicAddress(address)) };
      } catch {
        return { host, address: null, skipped: false };
      }
    }));
    return { zone, servers };
  }
  return { zone: null, servers: [] };
}

async function propagationCheck(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  const rawType = queryInput(url, "type", 16, response);
  if (rawName === null || rawType === null) return;
  const type = (rawType || "A").trim().toUpperCase();
  const name = rawName.trim().replace(/\.$/, "").toLowerCase();
  if (!propagationTypes.has(type)) {
    sendJson(response, 400, { error: `Choose one of: ${[...propagationTypes].join(", ")}.` });
    return;
  }
  if (!name || !validDnsName(name)) {
    sendJson(response, 400, { error: "Enter a valid DNS name." });
    return;
  }
  const started = Date.now();
  const publicResolvers = [
    ...Object.entries(dnsResolvers).map(([id, resolver]) => ({ id, ...resolver, format: "wire" })),
    ...(customDohEndpoint ? [{ id: "custom", label: "Custom DoH", endpoint: customDohEndpoint, format: "json" }] : []),
  ];
  const describe = (data) => ({
    status: data.statusText,
    answers: propagationAnswerKey(type, data.answers),
    ttl: data.answers.length ? Math.min(...data.answers.map((answer) => Number(answer.TTL) || 0)) : null,
  });
  const failure = (error) => ({
    status: "ERROR",
    answers: [],
    ttl: null,
    error: error.name === "TimeoutError" || /timeout/i.test(error.message || "")
      ? "Timed out"
      : /ENOTFOUND|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|canceled/i.test(error.message || "")
        ? "Resolver unreachable"
        : (error.message || "Query failed").slice(0, 120),
  });
  const [publicResults, authority] = await Promise.all([
    Promise.all(publicResolvers.map(async (resolver) => {
      try {
        return { source: resolver.label, kind: "resolver", ...describe(await queryDohDns(name, type, { resolver })) };
      } catch (error) {
        return { source: resolver.label, kind: "resolver", ...failure(error) };
      }
    })),
    findAuthoritativeServers(name),
  ]);
  const authoritativeResults = await Promise.all(authority.servers.map(async (server) => {
    const source = `${server.host}${server.address ? ` (${server.address})` : ""}`;
    if (!server.address) {
      return { source, kind: "authoritative", status: "SKIPPED", answers: [], ttl: null, error: server.skipped ? "Private or reserved address; not queried" : "No IPv4 address" };
    }
    try {
      return { source, kind: "authoritative", ...describe(await directDnsLookup(name, type, { address: server.address, family: 4, port: 53 })) };
    } catch (error) {
      return { source, kind: "authoritative", ...failure(error) };
    }
  }));
  const results = [...publicResults, ...authoritativeResults];
  const groups = new Map();
  for (const result of results.filter((entry) => !["ERROR", "SKIPPED"].includes(entry.status))) {
    const key = `${result.status}|${result.answers.join("\n")}`;
    groups.set(key, (groups.get(key) || 0) + 1);
  }
  const ranked = [...groups.entries()].sort((left, right) => right[1] - left[1]);
  const groupIndex = new Map(ranked.map(([key], index) => [key, index]));
  for (const result of results) {
    const key = `${result.status}|${result.answers.join("\n")}`;
    result.group = groupIndex.has(key) ? groupIndex.get(key) : null;
  }
  sendJson(response, 200, {
    name,
    type,
    zone: authority.zone,
    consistent: ranked.length <= 1,
    distinctAnswers: ranked.length,
    answered: results.filter((result) => result.group !== null).length,
    results,
    durationMs: Date.now() - started,
  });
}

const ipBlocklists = [
  { zone: "zen.spamhaus.org", name: "Spamhaus ZEN", info: "https://check.spamhaus.org/", kind: "spamhaus" },
  { zone: "bl.spamcop.net", name: "SpamCop", info: "https://www.spamcop.net/bl.shtml" },
  { zone: "b.barracudacentral.org", name: "Barracuda", info: "https://www.barracudacentral.org/lookups" },
  { zone: "psbl.surriel.com", name: "PSBL", info: "https://psbl.org/" },
  { zone: "dnsbl-1.uceprotect.net", name: "UCEPROTECT Level 1", info: "https://www.uceprotect.net/en/rblcheck.php" },
  { zone: "dnsbl.dronebl.org", name: "DroneBL", info: "https://dronebl.org/lookup" },
  { zone: "ix.dnsbl.manitu.net", name: "NiX Spam", info: "https://www.nixspam.net/" },
  { zone: "bl.mailspike.net", name: "Mailspike", info: "https://mailspike.org/" },
  { zone: "truncate.gbudb.net", name: "GBUdb Truncate", info: "https://www.gbudb.com/" },
  { zone: "spam.dnsbl.anonmails.de", name: "Anonmails", info: "https://anonmails.de/dnsbl.php" },
  { zone: "db.wpbl.info", name: "WPBL", info: "https://www.wpbl.info/" },
  { zone: "all.s5h.net", name: "s5h.net", info: "https://www.usenix.org.uk/content/rbl.html" },
];
const domainBlocklists = [
  { zone: "dbl.spamhaus.org", name: "Spamhaus DBL", info: "https://check.spamhaus.org/", kind: "spamhaus" },
  { zone: "multi.uribl.com", name: "URIBL", info: "https://admin.uribl.com/", kind: "uribl" },
  { zone: "multi.surbl.org", name: "SURBL", info: "https://www.surbl.org/surbl-analysis", kind: "surbl" },
  { zone: "dbl.nordspam.com", name: "NordSpam DBL", info: "https://www.nordspam.com/" },
];
const blocklistAddressLimit = 4;
let blocklistResolver = null;

function getBlocklistResolver() {
  if (blocklistResolver) return blocklistResolver;
  blocklistResolver = new DnsResolver({ timeout: 4000, tries: 1 });
  const servers = (process.env.BLOCKLIST_RESOLVER || "").split(/[\s,]+/).filter(Boolean);
  if (servers.length) {
    try {
      blocklistResolver.setServers(servers);
    } catch (error) {
      console.error(`Ignoring invalid BLOCKLIST_RESOLVER: ${error.message}`);
    }
  }
  return blocklistResolver;
}

// Blocklists answer with 127.x codes; some use reserved codes to say a query was refused
// (for example because it came through a large public resolver) rather than listed.
function interpretBlocklistAnswer(list, codes) {
  if (codes.some((code) => !code.startsWith("127."))) {
    return { status: "error", detail: "Unexpected answer; the resolver may rewrite NXDOMAIN responses." };
  }
  if (list.kind === "spamhaus" && codes.some((code) => code.startsWith("127.255.255."))) {
    return { status: "refused", detail: "Spamhaus refused the query (public or high-volume resolver). Set BLOCKLIST_RESOLVER to a private resolver or a Spamhaus DQS mirror." };
  }
  if ((list.kind === "uribl" || list.kind === "surbl") && codes.includes("127.0.0.1")) {
    return { status: "refused", detail: `${list.name} refused the query (public or high-volume resolver).` };
  }
  return { status: "listed" };
}

async function queryBlocklist(list, queryName) {
  const resolver = getBlocklistResolver();
  try {
    const codes = await resolver.resolve4(`${queryName}.${list.zone}`);
    const result = interpretBlocklistAnswer(list, codes);
    let reason = null;
    if (result.status === "listed") {
      try {
        reason = (await resolver.resolveTxt(`${queryName}.${list.zone}`)).map((parts) => parts.join("")).join(" ").slice(0, 300) || null;
      } catch {
        reason = null;
      }
    }
    return { name: list.name, zone: list.zone, info: list.info, codes, reason, ...result };
  } catch (error) {
    if (error.code === "ENOTFOUND" || error.code === "ENODATA") {
      return { name: list.name, zone: list.zone, info: list.info, status: "clean" };
    }
    return {
      name: list.name,
      zone: list.zone,
      info: list.info,
      status: "error",
      detail: error.code === "ETIMEOUT" ? "The blocklist did not answer in time." : `Lookup failed (${error.code || "error"}).`,
    };
  }
}

function summarizeBlocklistResults(results) {
  return {
    listed: results.filter((result) => result.status === "listed").length,
    clean: results.filter((result) => result.status === "clean").length,
    unavailable: results.filter((result) => result.status === "refused" || result.status === "error").length,
    checked: results.length,
  };
}

async function checkBlocklists({ addresses = [], domain = null }) {
  const ipv4 = [...new Set(addresses)].filter((address) => isIP(address) === 4 && isPublicAddress(address));
  const skipped = [...new Set(addresses)].filter((address) => !ipv4.includes(address));
  const targets = ipv4.slice(0, blocklistAddressLimit);
  const [ipResults, domainLists] = await Promise.all([
    Promise.all(targets.map(async (address) => {
      const reversed = address.split(".").reverse().join(".");
      const lists = await Promise.all(ipBlocklists.map((list) => queryBlocklist(list, reversed)));
      return { address, ...summarizeBlocklistResults(lists), lists };
    })),
    domain ? Promise.all(domainBlocklists.map((list) => queryBlocklist(list, domain))) : Promise.resolve(null),
  ]);
  return {
    resolver: process.env.BLOCKLIST_RESOLVER ? "custom resolver (BLOCKLIST_RESOLVER)" : "the server's system resolver",
    ips: ipResults,
    domain: domainLists ? { domain, ...summarizeBlocklistResults(domainLists), lists: domainLists } : null,
    skipped: [...skipped, ...ipv4.slice(blocklistAddressLimit)],
  };
}

async function blocklistLookup(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  const name = rawName.trim().replace(/^\[(.*)\]$/, "$1");
  try {
    if (isIP(name)) {
      if (!isPublicAddress(name)) {
        sendJson(response, 400, { error: "Blocklists only cover public IP addresses." });
        return;
      }
      if (isIP(name) === 6) {
        sendJson(response, 200, { ips: [], domain: null, skipped: [name], ipv6: true });
        return;
      }
      sendJson(response, 200, await checkBlocklists({ addresses: [name] }));
      return;
    }
    const domain = normalizeDomain(name);
    if (!domain) {
      sendJson(response, 400, { error: "Enter a valid domain name or public IP address." });
      return;
    }
    let addresses = [];
    try {
      addresses = (await queryDohDns(domain, "A")).answers
        .filter((answer) => answer.type === 1 || answer.typeName === "A")
        .map((answer) => answer.data);
    } catch {
      addresses = [];
    }
    sendJson(response, 200, await checkBlocklists({ addresses, domain }));
  } catch (error) {
    console.error("Blocklist check failed:", error);
    sendJson(response, 500, { error: "Unable to complete the blocklist check." });
  }
}

async function fetchPtr(address, nameserver = null) {
  if (nameserver) return directDnsLookup(reverseName(address), "PTR", nameserver);
  const data = await queryDohDns(reverseName(address), "PTR");
  return {
    status: data.statusText,
    answers: data.answers.map((answer) => answer.data),
  };
}

async function fetchPtrLookups(addresses, nameserver = null) {
  const uniqueAddresses = [...new Set(addresses.filter((address) => isIP(address)))];
  const results = [];
  for (let index = 0; index < uniqueAddresses.length; index += 8) {
    const batch = uniqueAddresses.slice(index, index + 8);
    results.push(...await Promise.all(batch.map(async (address) => {
      try {
        return [address, await fetchPtr(address, nameserver)];
      } catch (error) {
        return [address, { error: error.message || "Unable to retrieve PTR record." }];
      }
    })));
  }
  return Object.fromEntries(results);
}

function normalizeIpAddress(value) {
  const address = typeof value === "string" ? value.trim() : "";
  const mappedIpv4 = address.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mappedIpv4 && isIP(mappedIpv4[1]) === 4) return mappedIpv4[1];
  return isIP(address) ? address : null;
}

function isTrustedProxy(address) {
  const family = isIP(address);
  return family !== 0 && trustedProxyRanges.check(address, family === 4 ? "ipv4" : "ipv6");
}

function getClientAddress(request) {
  const socketAddress = normalizeIpAddress(request.socket.remoteAddress);
  if (!socketAddress || !isTrustedProxy(socketAddress)) return socketAddress;

  const cloudflareAddress = normalizeIpAddress(request.headers["cf-connecting-ip"]);
  if (cloudflareAddress) return cloudflareAddress;
  const realIpAddress = normalizeIpAddress(request.headers["x-real-ip"]);
  if (realIpAddress) return realIpAddress;

  const forwardedFor = request.headers["x-forwarded-for"];
  if (typeof forwardedFor !== "string") return socketAddress;
  const chain = forwardedFor.split(",").map(normalizeIpAddress);
  if (!chain.length || chain.length > 20 || chain.some((address) => !address)) {
    return socketAddress;
  }
  for (let index = chain.length - 1; index >= 0; index -= 1) {
    const address = chain[index];
    if (!isTrustedProxy(address)) return address;
  }
  return socketAddress;
}

async function handleClientInfo(request, response) {
  const address = getClientAddress(request);
  if (!address) {
    sendJson(response, 200, { address: null, isPublic: false, ptr: [], ptrError: null });
    return;
  }
  if (!isPublicAddress(address)) {
    sendJson(response, 200, { address, isPublic: false, ptr: [], ptrError: null });
    return;
  }
  const [ptrResult, rdapResult] = await Promise.allSettled([
    fetchPtr(address),
    fetchIpRdap(address),
  ]);
  sendJson(response, 200, {
    address,
    isPublic: true,
    ptr: ptrResult.status === "fulfilled" ? ptrResult.value.answers : [],
    ptrError: ptrResult.status === "rejected" ? "PTR lookup is unavailable." : null,
    ipRegistration: rdapResult.status === "fulfilled" ? rdapResult.value : null,
    ipRegistrationError: rdapResult.status === "rejected"
      ? rdapResult.reason.message || "Unable to retrieve IP registration details."
      : null,
  });
}

async function queryDnsRecords(name, type) {
  return (await queryDohDns(name, type)).answers;
}

function isPublicAddress(address) {
  const family = isIP(address);
  return family !== 0 &&
    !address.toLowerCase().startsWith("::ffff:") &&
    !nonPublicAddressRanges.check(address, family === 4 ? "ipv4" : "ipv6");
}

function isLocalAddress(address) {
  const family = isIP(address);
  return family !== 0 &&
    !address.toLowerCase().startsWith("::ffff:") &&
    localAddressRanges.check(address, family === 4 ? "ipv4" : "ipv6");
}

function isScannableAddress(address, allowLocal) {
  return isPublicAddress(address) || (allowLocal && isLocalAddress(address));
}

function checkTcpPort(address, port) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host: address, port, family: isIP(address) }, () => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(true);
      }
    });
    socket.setTimeout(900, () => socket.destroy());
    socket.once("error", () => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    });
    socket.once("close", () => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    });
  });
}

async function scanCommonTcpPorts(domain, addresses, policy) {
  const ports = commonTcpPorts.slice(0, policy.maxPorts);
  return scanTcpTargets(domain, addresses, ports, 8, () => domain, policy.allowLocal);
}

async function scanTcpTargets(scanLabel, addresses, ports, addressLimit, targetForAddress = () => scanLabel, allowLocal = false) {
  const uniqueAddresses = [...new Set(addresses)];
  const eligibleAddresses = uniqueAddresses.filter((address) => isScannableAddress(address, allowLocal));
  const targets = eligibleAddresses.slice(0, addressLimit);
  const tasks = targets.flatMap((address) =>
    ports.map((port) => ({ address, port })),
  );
  const openPortsByAddress = new Map(targets.map((address) => [address, []]));
  let nextTask = 0;

  async function runWorker() {
    while (nextTask < tasks.length) {
      const task = tasks[nextTask];
      nextTask += 1;
      if (await checkTcpPort(task.address, task.port)) {
        openPortsByAddress.get(task.address).push(task.port);
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(32, tasks.length) }, () => runWorker()),
  );
  return {
    enabled: true,
    scanLabel,
    portsChecked: ports.length,
    addressesScanned: targets.length,
    addressesSkipped: uniqueAddresses.length - targets.length,
    results: targets.map((address) => ({
      target: targetForAddress(address),
      address,
      openPorts: openPortsByAddress.get(address).sort((left, right) => left - right),
    })),
  };
}

function invalidScanRequest(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

async function readJsonRequest(request, maximumBodySize = 65536) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] || "")) {
    throw invalidScanRequest("Content-Type must be application/json.", 415);
  }
  const contentLengthHeader = request.headers["content-length"];
  if (contentLengthHeader !== undefined && !/^\d+$/.test(contentLengthHeader)) {
    throw invalidScanRequest("Content-Length must be a valid non-negative integer.");
  }
  const contentLength = Number(contentLengthHeader || 0);
  if (!Number.isSafeInteger(contentLength) || contentLength > maximumBodySize) {
    throw invalidScanRequest(`Request body must not exceed ${Math.floor(maximumBodySize / 1024)} KB.`, 413);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > maximumBodySize) {
        tooLarge = true;
      } else if (!tooLarge) {
        chunks.push(chunk);
      }
    });
    request.once("error", reject);
    request.once("aborted", () => reject(invalidScanRequest("Request body was interrupted.")));
    request.once("end", () => {
      if (tooLarge) {
        reject(invalidScanRequest(`Request body must not exceed ${Math.floor(maximumBodySize / 1024)} KB.`, 413));
        return;
      }
      try {
        const decoded = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
        const value = JSON.parse(decoded);
        if (!value || typeof value !== "object" || Array.isArray(value)) {
          throw invalidScanRequest("Request body must be a JSON object.");
        }
        resolve(value);
      } catch (error) {
        reject(error.statusCode
          ? error
          : invalidScanRequest("Request body contains invalid JSON."));
      }
    });
  });
}

function parseCustomPortList(input, maxPorts) {
  if (input.length > 65536) {
    throw invalidScanRequest("Port list must not exceed 65,536 characters.");
  }
  const segments = input.split(",");
  if (!segments.length || segments.some((segment) => !segment.trim())) {
    throw invalidScanRequest("Enter comma-separated TCP ports or port ranges.");
  }
  const ports = new Set();
  for (const segment of segments) {
    const match = segment.trim().match(/^(\d+)(?:\s*-\s*(\d+))?$/);
    if (!match) throw invalidScanRequest("Use port numbers or ranges such as 80,443,8000-8010.");
    const start = Number(match[1]);
    const end = Number(match[2] || match[1]);
    if (!Number.isInteger(start) || !Number.isInteger(end) ||
      start < 1 || end > 65535 || end < start) {
      throw invalidScanRequest("TCP ports must be between 1 and 65535, with ranges in ascending order.");
    }
    for (let port = start; port <= end; port += 1) {
      ports.add(port);
      if (ports.size > maxPorts) {
        throw invalidScanRequest(`Your role is limited to ${maxPorts} unique TCP ports per target.`);
      }
    }
  }
  return [...ports].sort((left, right) => left - right);
}

function ipv6ToBigInt(address) {
  const sections = address.toLowerCase().split("::");
  if (sections.length > 2 || address.includes(".")) {
    throw invalidScanRequest("Enter valid IPv6 CIDR blocks without embedded IPv4 addresses.");
  }
  const left = sections[0] ? sections[0].split(":") : [];
  const right = sections.length === 2 && sections[1] ? sections[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((sections.length === 1 && missing !== 0) || (sections.length === 2 && missing < 1)) {
    throw invalidScanRequest("Enter a valid IPv6 CIDR block.");
  }
  const groups = sections.length === 2
    ? [...left, ...Array(missing).fill("0"), ...right]
    : left;
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    throw invalidScanRequest("Enter a valid IPv6 CIDR block.");
  }
  return BigInt(`0x${groups.map((group) => group.padStart(4, "0")).join("")}`);
}

function addressFromBigInt(value, family) {
  if (family === 4) {
    return [24n, 16n, 8n, 0n]
      .map((shift) => Number((value >> shift) & 255n))
      .join(".");
  }
  const hex = value.toString(16).padStart(32, "0");
  return Array.from({ length: 8 }, (_, index) =>
    Number.parseInt(hex.slice(index * 4, index * 4 + 4), 16).toString(16),
  ).join(":");
}

function parseBulkScanTargets(
  input,
  largestCidrPrefix = portScanPolicyDefaults.largestBulkCidrPrefix,
  limits = { 4: bulkScanLimits.tcpConnect, 6: bulkScanLimits.tcpConnect, total: bulkScanLimits.tcpConnect },
) {
  if (input.length > 8192) {
    throw invalidScanRequest("Target list must not exceed 8,192 characters.");
  }
  const tokens = input.split(/[\s,]+/).filter(Boolean);
  if (!tokens.length) throw invalidScanRequest("Enter at least one IP address or CIDR block.");
  if (tokens.length > 256) {
    throw invalidScanRequest("Enter no more than 256 IP addresses or CIDR blocks.");
  }
  const targets = new Set();
  const counts = { 4: 0, 6: 0 };
  const limitError = (family) => invalidScanRequest(limits[family] < limits.total
    ? `Bulk scans are limited to ${limits[family].toLocaleString("en-US")} unique IPv${family} addresses.`
    : `Bulk scans are limited to ${limits.total.toLocaleString("en-US")} unique IP addresses.`);
  const addTarget = (address, family) => {
    if (targets.has(address)) return;
    targets.add(address);
    counts[family] += 1;
    if (counts[family] > limits[family] || targets.size > limits.total) throw limitError(family);
  };
  for (const token of tokens) {
    const slash = token.indexOf("/");
    if (slash < 0) {
      if (!isIP(token)) {
        throw invalidScanRequest(`Invalid IP address or CIDR block: ${token}`);
      }
      addTarget(token, isIP(token));
      continue;
    }
    const address = token.slice(0, slash);
    const family = isIP(address);
    const prefixText = token.slice(slash + 1);
    if (!family || !/^\d+$/.test(prefixText)) {
      throw invalidScanRequest(`Invalid IP address or CIDR block: ${token}`);
    }
    const prefix = Number(prefixText);
    const width = family === 4 ? 32 : 128;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > width) {
      throw invalidScanRequest(`Invalid CIDR prefix: ${token}`);
    }
    const minimumPrefix = family === 4 ? largestCidrPrefix.ipv4 : largestCidrPrefix.ipv6;
    if (prefix < minimumPrefix) {
      throw invalidScanRequest(`Bulk scan CIDRs must be /${minimumPrefix} or narrower.`);
    }
    const hostBits = BigInt(width - prefix);
    const count = 1n << hostBits;
    if (count > BigInt(Math.min(limits[family], limits.total))) throw limitError(family);
    const rawAddress = family === 4
      ? BigInt(address.split(".").reduce((value, octet) => (value << 8n) | BigInt(octet), 0n))
      : ipv6ToBigInt(address);
    const network = (rawAddress >> hostBits) << hostBits;
    for (let offset = 0n; offset < count; offset += 1n) {
      addTarget(addressFromBigInt(network + offset, family), family);
    }
  }
  return [...targets];
}

function runZmap(addresses, port, rate) {
  return new Promise((resolve, reject) => {
    let directory;
    let child;
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let finished = false;
    let timer;
    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (directory) fs.rm(directory, { recursive: true, force: true }, () => {});
      if (error) reject(error);
      else resolve(value);
    };
    try {
      directory = fs.mkdtempSync(path.join(os.tmpdir(), "zmap-"));
      const allowlist = path.join(directory, "allowlist.txt");
      const blocklist = path.join(directory, "blocklist.txt");
      // Eligibility is enforced by isScannableAddress; the empty blocklist stops
      // zmap's default list from dropping private targets an admin has allowed.
      fs.writeFileSync(allowlist, addresses.map((address) => `${address}/32`).join("\n") + "\n");
      fs.writeFileSync(blocklist, "");
      const args = [
        "-p", String(port),
        "-r", String(rate),
        "-w", allowlist,
        "-b", blocklist,
        "-c", "5",
        "-f", "saddr",
        "-o", "-",
        "-q",
      ];
      if (process.env.ZMAP_INTERFACE) args.push("-i", process.env.ZMAP_INTERFACE);
      if (process.env.ZMAP_GATEWAY_MAC) args.push("-G", process.env.ZMAP_GATEWAY_MAC);
      if (process.env.ZMAP_SOURCE_IP) args.push("-S", process.env.ZMAP_SOURCE_IP);
      child = spawn(process.env.ZMAP_PATH || "zmap", args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch (error) {
      finish(error);
      return;
    }
    const timeoutMs = Math.ceil(addresses.length / rate) * 1000 + 30000;
    timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      if (stdout.length < 4 * 1024 * 1024) stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 16384) stderr += chunk;
    });
    child.on("error", (error) => finish(error.code === "ENOENT"
      ? invalidScanRequest("zmap is enabled but is not installed on this server.", 503)
      : error));
    child.on("close", (code) => {
      if (timedOut) {
        finish(invalidScanRequest("The zmap scan took too long and was stopped.", 504));
        return;
      }
      if (code !== 0) {
        console.error(`zmap exited with code ${code}: ${stderr.trim().split("\n").slice(-3).join(" | ")}`);
        const permission = /permission|operation not permitted|pcap|socket/i.test(stderr);
        finish(invalidScanRequest(permission
          ? "zmap could not open a raw socket. Run the container with compose.zmap.yaml (NET_RAW and NET_ADMIN)."
          : "zmap could not complete the scan. Check the server log for details.", 503));
        return;
      }
      const eligible = new Set(addresses);
      finish(null, new Set(stdout.split("\n").map((line) => line.trim()).filter((line) => eligible.has(line))));
    });
  });
}

async function runCustomPortScan(request, response) {
  try {
    const user = currentUser(request);
    if (!user) throw invalidScanRequest("Log in to scan ports.", 401);
    const policy = getPortScanPolicy();
    const body = await readJsonRequest(request);
    const target = typeof body.target === "string" ? body.target.trim() : "";
    if (!target || target.length > 253) {
      throw invalidScanRequest("Enter a domain name or IP address no longer than 253 characters.");
    }
    const portsInput = typeof body.ports === "string" ? body.ports : "";
    const ports = parseCustomPortList(portsInput, policy.maxPortsByRole[user.role]);
    request.logDetails = JSON.stringify({ target, ports: portsInput });
    let addresses;
    if (isIP(target)) {
      addresses = [target];
    } else {
      const domain = normalizeDomain(target);
      if (!domain) throw invalidScanRequest("Enter a valid domain name or IP address.");
      try {
        addresses = (await resolveHost(domain, { all: true, verbatim: true }))
          .map((entry) => entry.address);
      } catch (error) {
        throw invalidScanRequest(`Could not resolve target domain: ${error.message}`);
      }
    }
    const data = await scanTcpTargets(
      target,
      addresses,
      ports,
      8,
      () => target,
      policy.localScanByRole[user.role],
    );
    sendJson(response, 200, data);
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("Port scan failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to complete the port scan." : error.message,
    });
  }
}

async function runBulkPortScan(request, response) {
  try {
    const user = currentUser(request);
    if (!user) throw invalidScanRequest("Log in to scan ports.", 401);
    const policy = getPortScanPolicy();
    const body = await readJsonRequest(request);
    const port = typeof body.port === "string" && /^\d+$/.test(body.port)
      ? Number(body.port)
      : body.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw invalidScanRequest("Enter a TCP port between 1 and 65535.");
    }
    const targetsInput = typeof body.targets === "string" ? body.targets : "";
    const limits = zmapEnabled
      ? { 4: bulkScanLimits.zmapIpv4, 6: bulkScanLimits.tcpConnect, total: bulkScanLimits.zmapIpv4 + bulkScanLimits.tcpConnect }
      : { 4: bulkScanLimits.tcpConnect, 6: bulkScanLimits.tcpConnect, total: bulkScanLimits.tcpConnect };
    let addresses;
    try {
      addresses = parseBulkScanTargets(targetsInput, policy.largestBulkCidrPrefix, limits);
    } catch (error) {
      if (!zmapEnabled && error.statusCode === 400 && /limited to/.test(error.message)) {
        error.message += " Larger IPv4 ranges need the zmap engine (see compose.zmap.yaml).";
      }
      throw error;
    }
    request.logDetails = JSON.stringify({
      targets: addresses.length > 256 ? targetsInput.slice(0, 2048) : addresses,
      addressCount: addresses.length,
      port,
      engine: zmapEnabled ? "zmap" : "tcp-connect",
    });
    if (!zmapEnabled) {
      const data = await scanTcpTargets(
        "Bulk IP targets",
        addresses,
        [port],
        bulkScanLimits.tcpConnect,
        (address) => address,
        policy.localScanByRole[user.role],
      );
      sendJson(response, 200, { ...data, engine: "tcp-connect" });
      return;
    }

    const allowLocal = policy.localScanByRole[user.role];
    const eligible = addresses.filter((address) => isScannableAddress(address, allowLocal));
    const ipv4 = eligible.filter((address) => isIP(address) === 4);
    const ipv6 = eligible.filter((address) => isIP(address) === 6);
    let openIpv4 = new Set();
    if (ipv4.length) {
      if (!acquireHeavyJob("zmap")) {
        throw invalidScanRequest("Another bulk port scan is running. Try again shortly.", 503);
      }
      try {
        openIpv4 = await runZmap(ipv4, port, policy.zmapRate);
      } finally {
        releaseHeavyJob("zmap");
      }
    }
    const ipv6Data = ipv6.length
      ? await scanTcpTargets("Bulk IP targets", ipv6, [port], bulkScanLimits.tcpConnect, (address) => address, allowLocal)
      : { results: [] };
    const results = [
      ...ipv4.filter((address) => openIpv4.has(address))
        .map((address) => ({ target: address, address, openPorts: [port] })),
      ...ipv6Data.results.filter((result) => result.openPorts.length),
    ];
    sendJson(response, 200, {
      enabled: true,
      engine: "zmap",
      openOnly: true,
      scanLabel: "Bulk IP targets",
      portsChecked: 1,
      addressesScanned: eligible.length,
      addressesSkipped: addresses.length - eligible.length,
      results,
    });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("Bulk port scan failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to complete the bulk port scan." : error.message,
    });
  }
}

async function fetchIpGeolocation(address) {
  if (!isPublicAddress(address)) {
    return {
      error: "Private or reserved IP address; not sent to the geolocation provider.",
    };
  }

  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const response = await fetch(`https://ipwho.is/${encodeURIComponent(address)}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) {
        return { error: `Geolocation provider returned HTTP ${response.status}.` };
      }
      const data = await response.json();
      if (data.success !== true || typeof data.country !== "string") {
        return {
          error: typeof data.message === "string"
            ? data.message
            : "Geolocation provider returned no country information.",
        };
      }
      return {
        country: data.country,
        countryCode: typeof data.country_code === "string" ? data.country_code : null,
        region: typeof data.region === "string" ? data.region : null,
        city: typeof data.city === "string" ? data.city : null,
        latitude: Number.isFinite(data.latitude) ? data.latitude : null,
        longitude: Number.isFinite(data.longitude) ? data.longitude : null,
      };
    } catch (error) {
      lastError = error;
    }
  }
  return {
    error: lastError?.name === "TimeoutError"
      ? "Geolocation provider timed out."
      : lastError?.message || "Unable to retrieve IP geolocation.",
  };
}

async function fetchIpGeolocations(addresses) {
  const uniqueAddresses = [...new Set(addresses.filter((address) => isIP(address)))];
  const results = {};
  let nextAddress = 0;

  async function runWorker() {
    while (nextAddress < uniqueAddresses.length) {
      const address = uniqueAddresses[nextAddress];
      nextAddress += 1;
      results[address] = await fetchIpGeolocation(address);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(8, uniqueAddresses.length) }, () => runWorker()),
  );
  return results;
}

async function fetchCertificateTransparencyJson(url) {
  const response = await fetch(url, {
    headers: {
      accept: "application/json",
      "user-agent": "BNGlookup/0.6 (+https://github.com/BANAANGA/BNGlookup)",
    },
    signal: AbortSignal.timeout(12000),
  });
  if (!response.ok) {
    throw new Error(`Certificate Transparency service returned HTTP ${response.status}.`);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  const maximumResponseSize = 2 * 1024 * 1024;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maximumResponseSize) {
        await reader.cancel();
        throw new Error("Certificate Transparency response exceeded 2 MB.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function normalizeCertificateTransparencyNames(entries, domain, readEntryNames) {
  if (!Array.isArray(entries)) {
    throw new Error("Certificate Transparency service returned invalid data.");
  }
  const names = new Set();
  for (const entry of entries) {
    for (const rawName of readEntryNames(entry)) {
      if (typeof rawName !== "string") continue;
      for (const name of rawName.split(/\r?\n/)) {
        const candidate = domainToASCII(
          name.trim().replace(/^\*\./, "").replace(/\.$/, "").toLowerCase(),
        );
        if (
          candidate &&
          candidate !== domain &&
          candidate.length <= 253 &&
          candidate.endsWith(`.${domain}`) &&
          validDnsName(candidate)
        ) {
          names.add(candidate);
        }
      }
    }
  }
  return [...names].sort().slice(0, certificateTransparencyCandidateLimit);
}

async function discoverCertificateTransparencySubdomains(domain) {
  const providers = [
    {
      name: "crt.sh",
      createUrl() {
        const url = new URL("https://crt.sh/");
        url.searchParams.set("q", `%.${domain}`);
        url.searchParams.set("output", "json");
        return url;
      },
      readEntryNames: (entry) => {
        if (typeof entry?.name_value !== "string") {
          throw new Error("Certificate Transparency service returned invalid data.");
        }
        return [entry.name_value];
      },
    },
    {
      name: "CertSpotter",
      createUrl() {
        const url = new URL("https://api.certspotter.com/v1/issuances");
        url.searchParams.set("domain", domain);
        url.searchParams.set("include_subdomains", "true");
        url.searchParams.set("expand", "dns_names");
        return url;
      },
      readEntryNames: (entry) => {
        if (!Array.isArray(entry?.dns_names)) {
          throw new Error("Certificate Transparency service returned invalid data.");
        }
        return entry.dns_names;
      },
    },
  ];
  let lastError;
  for (const provider of providers) {
    try {
      const entries = await fetchCertificateTransparencyJson(provider.createUrl());
      return {
        names: normalizeCertificateTransparencyNames(
          entries,
          domain,
          provider.readEntryNames,
        ),
        source: provider.name,
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("Certificate Transparency services are unavailable.");
}

async function bulkScan(request, url, response) {
  const rawDomain = queryInput(url, "name", 2048, response);
  const portScanOption = queryInput(url, "ports", 10, response);
  const rawNameserver = queryInput(url, "nameserver", 300, response);
  if ([rawDomain, portScanOption, rawNameserver].includes(null)) return;
  if (rawNameserver.trim() && currentUser(request)?.role !== "admin") {
    sendJson(response, 403, { error: "Custom nameservers are available to administrators only." });
    return;
  }
  const host = hostFromInput(rawDomain);
  if (isIP(host)) {
    sendJson(response, 400, { error: "Magic scan works on domain names. For an IP address, use Auto lookup or Reverse lookup." });
    return;
  }
  const domain = normalizeDomain(host);
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name or a URL." });
    return;
  }

  if (portScanOption && portScanOption !== "common") {
    sendJson(response, 400, { error: "Unsupported port scan option." });
    return;
  }

  let nameserver;
  try {
    nameserver = await resolveNameserver(parseNameserver(rawNameserver));
  } catch (error) {
    sendJson(response, 400, { error: error.message });
    return;
  }

  const registrationPromise = fetchRegistration(domain).then(
    (registration) => ({ registration, error: null }),
    (error) => ({
      registration: null,
      error: error.message || "Unable to retrieve registration details.",
      registryUrl: error.registryUrl || null,
    }),
  );
  const dnssecPromise = checkDnssec(domain).catch((error) => {
    console.error("DNSSEC check failed:", error.message);
    return { domain, status: "error", summary: "The DNSSEC check could not be completed.", ds: [], dnskeys: [], signatures: [], issues: [] };
  });
  const certificateTransparencyPromise = discoverCertificateTransparencySubdomains(domain).then(
    ({ names, source }) => ({ names, source, error: null }),
    (error) => ({
      names: [],
      source: null,
      error: error.name === "TimeoutError"
        ? "Certificate Transparency lookup timed out."
        : "Certificate Transparency lookup is temporarily unavailable.",
    }),
  );
  const hostCandidates = new Map([
    [domain, { name: domain, providers: [], types: scanRecordTypes }],
  ]);
  for (const label of commonSubdomains) {
    const name = `${label}.${domain}`;
    if (name.length <= 253 && validDnsName(name)) {
      hostCandidates.set(name, { name, providers: [], types: scanRecordTypes });
    }
  }
  const scanCandidates = [
    ...providerCandidates,
    ...dkimSelectors.map(([selector, provider]) => ({
      name: `${selector}._domainkey`,
      provider: `DKIM / ${provider}`,
      types: ["TXT", "CNAME"],
    })),
  ];
  for (const candidate of scanCandidates) {
    const name = `${candidate.name}.${domain}`;
    if (!validDnsName(name)) continue;
    const existing = hostCandidates.get(name);
    if (existing) {
      if (!existing.providers.includes(candidate.provider)) {
        existing.providers.push(candidate.provider);
      }
      existing.types = [...new Set([...existing.types, ...candidate.types])];
    } else {
      hostCandidates.set(name, {
        name,
        providers: [candidate.provider],
        types: candidate.types,
      });
    }
  }
  const certificateTransparencyResult = await certificateTransparencyPromise;
  for (const name of certificateTransparencyResult.names) {
    const existing = hostCandidates.get(name);
    if (existing) {
      if (!existing.providers.includes("Certificate Transparency")) {
        existing.providers.push("Certificate Transparency");
      }
      existing.types = [...new Set([...existing.types, ...certificateTransparencyRecordTypes])];
    } else {
      hostCandidates.set(name, {
        name,
        providers: ["Certificate Transparency"],
        types: certificateTransparencyRecordTypes,
      });
    }
  }
  const candidates = [...hostCandidates.values()];
  const recordsByHost = new Map(candidates.map(({ name }) => [name, []]));
  const tasks = candidates.flatMap(({ name, providers, types }) =>
    types.map((type) => ({ name, providers, type })),
  );
  let nextTask = 0;
  let failedQueries = 0;

  async function runWorker() {
    while (nextTask < tasks.length) {
      const task = tasks[nextTask];
      nextTask += 1;
      try {
        const answers = nameserver
          ? (await directDnsLookup(task.name, task.type, nameserver)).answers
          : await queryDnsRecords(task.name, task.type);
        if (answers.length) {
          recordsByHost.get(task.name).push({
            type: task.type,
            answers,
            providers: task.providers,
          });
        }
      } catch {
        failedQueries += 1;
      }
    }
  }

  await Promise.all(
    Array.from(
      { length: Math.min(scanConcurrency, tasks.length) },
      () => runWorker(),
    ),
  );
  for (const records of recordsByHost.values()) {
    records.sort(
      (left, right) =>
        scanRecordTypes.indexOf(left.type) - scanRecordTypes.indexOf(right.type),
    );
  }

  const hosts = candidates.map(({ name, providers }) => ({
    name,
    providers,
    records: recordsByHost.get(name),
  }));
  const spfRecords = hosts.flatMap((host) =>
    host.records
      .filter((record) => record.type === "TXT")
      .flatMap((record) => record.answers
        .filter((answer) => answer.data.replace(/^"|"$/g, "").trim().toLowerCase().startsWith("v=spf1"))
        .map((answer) => ({ name: host.name, data: answer.data }))),
  );
  const dkimRecords = hosts
    .filter((host) => host.name.includes("._domainkey."))
    .map((host) => ({
      name: host.name,
      records: host.records
        .filter((record) => record.type === "TXT" || record.type === "CNAME")
        .flatMap((record) => record.answers.map((answer) => ({
          type: record.type,
          data: answer.data,
        })))
        .filter((record) =>
          record.type === "CNAME" ||
          (/v=DKIM1/i.test(record.data) &&
            /(?:^|[;\s])p\s*=\s*"?[^"\s;]/i.test(record.data)),
        ),
    }));
  const addresses = hosts.flatMap((host) =>
    host.records.flatMap((record) =>
      record.answers.map((answer) => answer.data),
    ),
  );
  const rootAddresses = recordsByHost.get(domain)
    .filter((record) => record.type === "A" || record.type === "AAAA")
    .flatMap((record) => record.answers.map((answer) => answer.data))
    .filter((address) => isIP(address) !== 0);
  const user = currentUser(request);
  const portScanPolicy = getPortScanPolicy();
  const rolePolicy = user ? {
    maxPorts: portScanPolicy.maxPortsByRole[user.role],
    allowLocal: portScanPolicy.localScanByRole[user.role],
  } : { maxPorts: 0, allowLocal: false };
  const mailSecurityPromise = analyzeMailSecurity(domain).catch((error) => {
    console.error("Mail security check failed:", error.message);
    return null;
  });
  const blocklistPromise = checkBlocklists({ addresses: rootAddresses, domain }).catch((error) => {
    console.error("Blocklist check failed:", error.message);
    return null;
  });
  const takeoverPromise = checkSubdomainTakeover(hosts, rolePolicy.allowLocal).catch((error) => {
    console.error("Subdomain takeover check failed:", error.message);
    return null;
  });
  const portScan = portScanOption === "common"
    ? await scanCommonTcpPorts(domain, rootAddresses, rolePolicy)
    : null;
  const registrationResult = await registrationPromise;

  const takeover = await takeoverPromise;
  for (const finding of takeover?.findings || []) {
    if (finding.status !== "ok") {
      recordDomainRating("takeover", finding.host, finding.status === "vulnerable" ? "risk" : "dangling", finding.status === "vulnerable" ? 0 : 30,
        `${finding.cname}${finding.service ? ` (${finding.service})` : ""}`);
    }
  }
  sendJson(response, 200, {
    domain,
    recordTypes: scanRecordTypes,
    subdomainsChecked: candidates.length - 1,
    certificateTransparencySubdomains: certificateTransparencyResult.names.length,
    certificateTransparencySource: certificateTransparencyResult.source,
    subdomainDiscoveryError: certificateTransparencyResult.error,
    providerCandidatesChecked: providerCandidates.length,
    providerNames: [...new Set(providerCandidates.map((candidate) => candidate.provider))],
    hosts,
    hostsWithRecords: hosts.filter((host) => host.records.length).length,
    registration: registrationResult.registration,
    registrationError: registrationResult.error,
    registryUrl: registrationResult.registryUrl || null,
    dnssec: await dnssecPromise,
    blocklists: await blocklistPromise,
    takeover,
    emailSecurity: {
      spfRecords,
      rootSpfFound: spfRecords.some((record) => record.name === domain),
      dkimSelectorsChecked: dkimRecords.length,
      dkimRecords: dkimRecords.filter((entry) => entry.records.length),
      ...(await mailSecurityPromise),
    },
    portScan,
    ipGeolocations: await fetchIpGeolocations(addresses),
    failedQueries,
    ptrLookups: await fetchPtrLookups(addresses, nameserver),
    nameserver: nameserver
      ? `${nameserver.family === 6 ? `[${nameserver.address}]` : nameserver.address}:${nameserver.port}`
      : null,
  });
}

async function fetchNameservers(domain) {
  const data = await queryDohDns(domain, "NS");
  const records = data.answers.map((answer) => ({
    name: answer.data,
    ttl: answer.TTL,
  }));
  const addressResults = await Promise.allSettled(
    records.map(async (nameserver) => {
      const [ipv4, ipv6] = await Promise.all(["A", "AAAA"].map(async (type) => {
        const addressData = await queryDohDns(nameserver.name, type);
        return addressData.answers.map((answer) => answer.data);
      }));
      return { ipv4, ipv6 };
    }),
  );

  const enrichedRecords = records.map((record, index) => {
    const result = addressResults[index];
    return {
      ...record,
      ipv4: result?.status === "fulfilled" ? result.value.ipv4 : [],
      ipv6: result?.status === "fulfilled" ? result.value.ipv6 : [],
    };
  });

  return {
    status: data.statusText,
    records: enrichedRecords,
    addressesIncomplete: addressResults.some((result) => result.status === "rejected"),
  };
}

async function domainInfo(url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  const name = rawName.trim();
  if (isIP(name)) {
    try {
      const registration = await fetchIpRdap(name);
      sendJson(response, 200, { ip: name, ipRegistration: registration, registrationError: null });
    } catch (error) {
      sendJson(response, 200, {
        ip: name,
        ipRegistration: null,
        registrationError: error.message || "Unable to retrieve IP registration details.",
      });
    }
    return;
  }

  const domain = normalizeDomain(name);
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name or IP address." });
    return;
  }

  const [rdapResult, nameserverResult] = await Promise.allSettled([
    fetchRegistration(domain),
    fetchNameservers(domain),
  ]);
  const nameserverRecords = nameserverResult.status === "fulfilled"
    ? nameserverResult.value.records
    : [];
  const registrationNameservers = rdapResult.status === "fulfilled"
    ? rdapResult.value.nameservers
    : [];
  const ptrLookups = await fetchPtrLookups(
    [
      ...nameserverRecords.flatMap((nameserver) => [...nameserver.ipv4, ...nameserver.ipv6]),
      ...registrationNameservers.flatMap((nameserver) => [...nameserver.ipv4, ...nameserver.ipv6]),
    ],
  );
  sendJson(response, 200, {
    domain,
    registration: rdapResult.status === "fulfilled" ? rdapResult.value : null,
    registrationError: rdapResult.status === "rejected"
      ? rdapResult.reason.message || "Unable to retrieve registration details."
      : null,
    registryUrl: rdapResult.status === "rejected" ? rdapResult.reason.registryUrl || null : null,
    dnsNameservers: nameserverResult.status === "fulfilled" ? nameserverResult.value : null,
    dnsNameserversError: nameserverResult.status === "rejected"
      ? nameserverResult.reason.message || "Unable to retrieve DNS nameservers."
      : null,
    ptrLookups,
  });
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(JSON.stringify(body));
}

function queryInput(url, name, maximumLength, response) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) {
    sendJson(response, 400, { error: `Provide ${name} only once.` });
    return null;
  }
  const value = values[0] || "";
  if (value.length > maximumLength) {
    sendJson(response, 400, { error: `${name} must not exceed ${maximumLength} characters.` });
    return null;
  }
  if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    sendJson(response, 400, { error: `${name} contains unsupported control characters.` });
    return null;
  }
  return value;
}

function sendRedirect(response, location) {
  response.writeHead(303, { location, "cache-control": "no-store" });
  response.end();
}

function appSetupRequired() {
  return database.prepare("SELECT COUNT(*) AS count FROM users").get().count === 0;
}

function getFeatureAccess() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'feature_access'").get();
  if (!row) return { ...featureAccessDefaults };
  try {
    const saved = JSON.parse(row.value);
    return Object.fromEntries(Object.entries(featureAccessDefaults).map(([feature, fallback]) => [
      feature,
      ["public", "user", "admin"].includes(saved[feature]) ? saved[feature] : fallback,
    ]));
  } catch {
    return { ...featureAccessDefaults };
  }
}

function getPortScanPolicy() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'port_scan_policy'").get();
  if (!row) return structuredClone(portScanPolicyDefaults);
  try {
    const saved = JSON.parse(row.value);
    return {
      maxPortsByRole: Object.fromEntries(["admin", "user"].map((role) => {
        const limit = saved.maxPortsByRole?.[role];
        return [role, Number.isInteger(limit) && limit >= 1 && limit <= 65535
          ? limit
          : portScanPolicyDefaults.maxPortsByRole[role]];
      })),
      localScanByRole: Object.fromEntries(["admin", "user"].map((role) => [
        role,
        typeof saved.localScanByRole?.[role] === "boolean"
          ? saved.localScanByRole[role]
          : portScanPolicyDefaults.localScanByRole[role],
      ])),
      largestBulkCidrPrefix: Object.fromEntries(["ipv4", "ipv6"].map((family) => {
        const minimumPrefix = family === "ipv4" ? 16 : 120;
        const maximumPrefix = family === "ipv4" ? 32 : 128;
        const prefix = saved.largestBulkCidrPrefix?.[family];
        return [family, Number.isInteger(prefix) && prefix >= minimumPrefix && prefix <= maximumPrefix
          ? prefix
          : portScanPolicyDefaults.largestBulkCidrPrefix[family]];
      })),
      zmapRate: Number.isInteger(saved.zmapRate) &&
        saved.zmapRate >= zmapRateLimits.min && saved.zmapRate <= zmapRateLimits.max
        ? saved.zmapRate
        : portScanPolicyDefaults.zmapRate,
    };
  } catch {
    return structuredClone(portScanPolicyDefaults);
  }
}

function getManualNmapAllowedCidrs() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'nmap_allowed_cidrs'").get();
  if (!row) return { entries: [], ranges: new net.BlockList() };
  try {
    return parseNmapAllowedCidrs(row.value);
  } catch (error) {
    console.error("Stored Nmap network allowlist is invalid:", error.message);
    return { entries: [], ranges: new net.BlockList() };
  }
}

const nmapLoginIpLifetimeMs = 30 * 24 * 60 * 60 * 1000;

function pruneNmapLoginIps(manualEntries, { makeRoom = false } = {}) {
  const now = Date.now();
  database.prepare("DELETE FROM nmap_login_ips WHERE expires_at <= ?").run(now);
  const capacity = Math.max(0, 254 - manualEntries.length);
  const rows = database.prepare(`
    SELECT address, last_seen_at, expires_at FROM nmap_login_ips
    ORDER BY last_seen_at DESC, address ASC
  `).all();
  const manualRanges = parseNmapAllowedCidrs(manualEntries.join("\n")).ranges;
  for (const row of rows) {
    const family = isIP(row.address);
    if (!family || manualRanges.check(row.address, family === 4 ? "ipv4" : "ipv6")) {
      database.prepare("DELETE FROM nmap_login_ips WHERE address = ?").run(row.address);
    }
  }
  const activeRows = database.prepare(`
    SELECT address, last_seen_at, expires_at FROM nmap_login_ips
    ORDER BY last_seen_at DESC, address ASC
  `).all();
  if (makeRoom && activeRows.length >= capacity) {
    const removeCount = activeRows.length - capacity + 1;
    for (const row of activeRows.slice(-removeCount)) {
      database.prepare("DELETE FROM nmap_login_ips WHERE address = ?").run(row.address);
    }
  } else if (activeRows.length > capacity) {
    for (const row of activeRows.slice(capacity)) {
      database.prepare("DELETE FROM nmap_login_ips WHERE address = ?").run(row.address);
    }
  }
}

function getNmapLoginIps() {
  const manual = getManualNmapAllowedCidrs();
  pruneNmapLoginIps(manual.entries);
  return database.prepare(`
    SELECT address, last_seen_at AS lastSeenAt, expires_at AS expiresAt
    FROM nmap_login_ips ORDER BY last_seen_at DESC, address ASC
  `).all();
}

function getNmapAllowedCidrs() {
  const manual = getManualNmapAllowedCidrs();
  pruneNmapLoginIps(manual.entries);
  const automatic = database.prepare("SELECT address FROM nmap_login_ips ORDER BY last_seen_at DESC").all();
  const automaticEntries = automatic.map(({ address }) => `${address}/${isIP(address) === 4 ? 32 : 128}`);
  try {
    return parseNmapAllowedCidrs([...manual.entries, ...automaticEntries].join("\n"));
  } catch (error) {
    console.error("Combined Nmap network allowlist is invalid:", error.message);
    return { entries: [], ranges: new net.BlockList() };
  }
}

function addNmapLoginIp(request) {
  const address = normalizeIpAddress(getClientAddress(request));
  if (!address) return;
  const manual = getManualNmapAllowedCidrs();
  if (manual.entries.length >= 254) return;
  const family = isIP(address);
  if (manual.ranges.check(address, family === 4 ? "ipv4" : "ipv6")) return;
  pruneNmapLoginIps(manual.entries);
  const existing = database.prepare("SELECT address FROM nmap_login_ips WHERE address = ?").get(address);
  if (!existing) pruneNmapLoginIps(manual.entries, { makeRoom: true });
  const now = Date.now();
  database.prepare(`
    INSERT INTO nmap_login_ips (address, last_seen_at, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT(address) DO UPDATE SET last_seen_at = excluded.last_seen_at,
      expires_at = excluded.expires_at
  `).run(address, now, now + nmapLoginIpLifetimeMs);
}

function recordNmapLoginIp(request, username) {
  try {
    addNmapLoginIp(request);
  } catch (error) {
    console.error("Unable to add successful login address to the Nmap allowlist:", error);
    recordAdminLog(
      "audit",
      request,
      "Automatic Nmap IP allowlisting failed",
      error.message || "Unknown error",
      500,
      username,
    );
  }
}

function getDefaultResolverId() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'default_dns_resolver'").get();
  if (row && (Object.hasOwn(dnsResolvers, row.value) || (row.value === "custom" && customDohEndpoint))) {
    return row.value;
  }
  return customResolverOption.length ? "custom" : "cloudflare";
}

function getAcmeConfig() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'acme_config'").get();
  if (!row) return null;
  try {
    const config = JSON.parse(row.value);
    return config && typeof config.domain === "string" ? config : null;
  } catch {
    return null;
  }
}

const maxAcmeDomains = 20;

function parseAcmeConfig(body) {
  const raw = Array.isArray(body.domains) ? body.domains.join("\n") : typeof body.domains === "string" ? body.domains : typeof body.domain === "string" ? body.domain : "";
  const entries = raw.split(/[\s,;]+/).filter(Boolean);
  if (!entries.length) return { error: "Enter at least one domain name." };
  if (entries.length > maxAcmeDomains * 2) return { error: `Enter at most ${maxAcmeDomains} domain names.` };
  const domains = [];
  for (const entry of entries) {
    const name = normalizeDomain(entry);
    if (!name || isIP(name) || /\.(?:local|localhost|internal|lan|home|test|invalid|example)$/.test(name)) {
      return { error: `"${entry.slice(0, 80)}" is not valid. Enter public fully qualified domain names, for example lookup.example.com. Wildcards and IP addresses are not supported.` };
    }
    if (!domains.includes(name)) domains.push(name);
  }
  if (domains.length > maxAcmeDomains) return { error: `Enter at most ${maxAcmeDomains} domain names.` };
  const domain = domains[0];
  const email = typeof body.email === "string" ? body.email.trim() : "";
  if (email && (email.length > 254 || !/^[^\s@<>",;:\\]+@[^\s@<>",;:\\]+\.[^\s@<>",;:\\]+$/.test(email))) {
    return { error: "Enter a valid contact email address or leave it blank." };
  }
  if (!["staging", "production"].includes(body.environment)) {
    return { error: "Choose the staging or production certificate authority." };
  }
  if (body.acceptTerms !== true) {
    return { error: "You must accept the certificate authority's subscriber agreement." };
  }
  return {
    config: {
      domain,
      domains,
      email,
      environment: body.environment,
      autoRenew: body.autoRenew !== false,
      termsAccepted: true,
    },
  };
}

let httpsServer = null;
let httpsError = null;
const acme = createAcmeManager({
  dataDir,
  getConfig: getAcmeConfig,
  onCertificate: (credentials) => applyTlsCertificate(credentials),
});

function certificateStatusPayload() {
  return {
    config: getAcmeConfig(),
    certificate: acme.describeCertificate(),
    status: { ...acme.status, steps: [...acme.status.steps] },
    running: acme.isRunning(),
    httpsPort,
    httpsListening: Boolean(httpsServer?.listening),
    httpsError,
  };
}

function handleAdminCertificate(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  request.logClientAddress = getClientAddress(request);
  if (request.method === "GET") {
    sendJson(response, 200, certificateStatusPayload());
    return;
  }
  if (request.method !== "PUT" && request.method !== "POST") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  if (request.method === "POST") {
    const config = getAcmeConfig();
    if (!config?.termsAccepted) {
      sendJson(response, 400, { error: "Save the certificate settings before requesting a certificate." });
      return;
    }
    const result = acme.start("manual");
    if (!result.started) {
      sendJson(response, 409, { error: result.reason });
      return;
    }
    recordAdminLog("audit", request, "Certificate requested", `${config.domain} (${config.environment})`, 202, admin.username);
    sendJson(response, 202, certificateStatusPayload());
    return;
  }
  void readAuthBody(request, response, 8192).then((body) => {
    if (!body) return;
    const parsed = parseAcmeConfig(body);
    if (parsed.error) {
      sendJson(response, 400, { error: parsed.error });
      return;
    }
    database.prepare(`
      INSERT INTO app_settings (key, value) VALUES ('acme_config', ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(JSON.stringify(parsed.config));
    recordAdminLog("audit", request, "Certificate settings updated", `${parsed.config.domain} (${parsed.config.environment})`, 200, admin.username);
    sendJson(response, 200, certificateStatusPayload());
  }).catch((error) => {
    console.error("Certificate settings update failed:", error);
    sendJson(response, 500, { error: "Unable to save certificate settings." });
  });
}

function getSiteTitle() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'site_title'").get();
  return row && row.value.trim() ? row.value : "DNSLookup";
}

function isValidIconDataUrl(value) {
  const match = typeof value === "string" &&
    value.match(/^data:(image\/(?:png|jpeg|gif|webp|x-icon|vnd\.microsoft\.icon));base64,([A-Za-z0-9+/]+=*)$/);
  if (!match || match[2].length > 4 * Math.ceil((256 * 1024) / 3)) return false;
  const data = Buffer.from(match[2], "base64");
  if (!data.length || data.length > 256 * 1024 || data.toString("base64") !== match[2]) return false;

  switch (match[1]) {
    case "image/png":
      return data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    case "image/jpeg":
      return data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
    case "image/gif":
      return ["GIF87a", "GIF89a"].includes(data.toString("ascii", 0, 6));
    case "image/webp":
      return data.toString("ascii", 0, 4) === "RIFF" &&
        data.toString("ascii", 8, 12) === "WEBP";
    case "image/x-icon":
    case "image/vnd.microsoft.icon":
      return data.subarray(0, 4).equals(Buffer.from([0, 0, 1, 0]));
    default:
      return false;
  }
}

function getSiteIconUrl() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'site_icon'").get();
  if (!row) return "/favicon.svg";
  if (isValidIconDataUrl(row.value)) return row.value;
  try {
    const iconUrl = new URL(row.value);
    if (iconUrl.protocol === "https:" && !iconUrl.username && !iconUrl.password) {
      return iconUrl.href;
    }
  } catch {
    return "/favicon.svg";
  }
  return "/favicon.svg";
}

function getSiteBranding() {
  return { title: getSiteTitle(), iconUrl: getSiteIconUrl() };
}

function validateSiteIconUrl(value) {
  if (typeof value !== "string" || value.length > 2048 || /[\u0000-\u0020\u007f]/.test(value)) {
    return null;
  }
  try {
    const iconUrl = new URL(value);
    return iconUrl.protocol === "https:" && !iconUrl.username && !iconUrl.password
      ? iconUrl.href
      : null;
  } catch {
    return null;
  }
}

function getDnsResolver() {
  const id = getDefaultResolverId();
  if (id === "custom") {
    return { id, ...dnsResolvers.cloudflare, endpoint: customDohEndpoint, format: "json" };
  }
  return { id, ...dnsResolvers[id], format: "wire" };
}

function getDnsResolverOptions() {
  return [
    ...Object.entries(dnsResolvers).map(([id, resolver]) => ({ id, label: resolver.label })),
    ...customResolverOption,
  ];
}

function readCookie(request, name) {
  const cookieHeader = request.headers.cookie || "";
  for (const item of cookieHeader.split(";")) {
    const separator = item.indexOf("=");
    if (separator < 0) continue;
    if (item.slice(0, separator).trim() === name) {
      return item.slice(separator + 1).trim();
    }
  }
  return "";
}

function currentUser(request, { allowPending = false } = {}) {
  if (request.apiUser) return request.apiUser;
  const token = readCookie(request, sessionCookieName);
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const session = database.prepare(`
    SELECT users.id, users.username, users.role, users.must_change_password, users.email,
      user_sessions.expires_at
    FROM user_sessions JOIN users ON users.id = user_sessions.user_id
    WHERE user_sessions.token_hash = ? AND users.active = 1
  `).get(tokenHash);
  if (!session) return null;
  if (session.expires_at <= Date.now()) {
    database.prepare("DELETE FROM user_sessions WHERE token_hash = ?").run(tokenHash);
    return null;
  }
  if (session.must_change_password && !allowPending) return null;
  return {
    id: session.id,
    username: session.username,
    role: session.role,
    mustChangePassword: Boolean(session.must_change_password),
    email: session.email || "",
  };
}

function cookieSecureAttribute(response) {
  return process.env.COOKIE_SECURE === "true" || response.req?.socket?.encrypted ? "; Secure" : "";
}

function setSessionCookie(response, token) {
  const secure = cookieSecureAttribute(response);
  response.setHeader("set-cookie", `${sessionCookieName}=${token}; Path=/; Max-Age=${sessionDurationMs / 1000}; HttpOnly; SameSite=Strict${secure}`);
}

function clearSessionCookie(response) {
  const secure = cookieSecureAttribute(response);
  response.setHeader("set-cookie", `${sessionCookieName}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict${secure}`);
}

function sameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin || !request.headers.host) return false;
  try {
    const parsedOrigin = new URL(origin);
    return ["http:", "https:"].includes(parsedOrigin.protocol) &&
      !parsedOrigin.username &&
      !parsedOrigin.password &&
      parsedOrigin.pathname === "/" &&
      !parsedOrigin.search &&
      !parsedOrigin.hash &&
      parsedOrigin.origin === origin.toLowerCase() &&
      parsedOrigin.host === request.headers.host.toLowerCase();
  } catch {
    return false;
  }
}

function enforceSameOrigin(request, response) {
  if (sameOrigin(request)) return true;
  sendJson(response, 403, { error: "Cross-origin requests are not allowed." });
  return false;
}

const authAttempts = new Map();
function allowAuthAttempt(request) {
  const key = getClientAddress(request) || request.socket.remoteAddress || "unknown";
  const now = Date.now();
  if (authAttempts.size > 10000) {
    for (const [address, attempt] of authAttempts) {
      if (attempt.blockedUntil < now && now - attempt.startedAt > 15 * 60 * 1000) {
        authAttempts.delete(address);
      }
    }
  }
  const attempt = authAttempts.get(key);
  if (attempt && attempt.blockedUntil > now) return false;
  if (!attempt && authAttempts.size >= 10000) return false;
  if (!attempt || now - attempt.startedAt > 15 * 60 * 1000) {
    authAttempts.set(key, { startedAt: now, count: 1, blockedUntil: 0 });
    return true;
  }
  attempt.count += 1;
  if (attempt.count > 10) {
    attempt.blockedUntil = now + 15 * 60 * 1000;
    return false;
  }
  return true;
}

// Per-account limit on failed logins, so attempts spread across many IP addresses
// (which the per-IP limit cannot see) still cannot guess one account's password.
const accountLoginFailures = new Map();
const accountLoginLimit = { failures: 30, windowMs: 15 * 60 * 1000 };

function accountLoginBlocked(username) {
  const key = String(username || "").toLowerCase();
  const entry = accountLoginFailures.get(key);
  if (!entry) return false;
  if (Date.now() - entry.startedAt > accountLoginLimit.windowMs) {
    accountLoginFailures.delete(key);
    return false;
  }
  return entry.count >= accountLoginLimit.failures;
}

function recordAccountLoginFailure(username) {
  const key = String(username || "").toLowerCase();
  if (!key) return;
  const now = Date.now();
  if (accountLoginFailures.size > 10000) {
    for (const [name, entry] of accountLoginFailures) {
      if (now - entry.startedAt > accountLoginLimit.windowMs) accountLoginFailures.delete(name);
    }
    if (accountLoginFailures.size > 10000) return;
  }
  const entry = accountLoginFailures.get(key);
  if (!entry || now - entry.startedAt > accountLoginLimit.windowMs) {
    accountLoginFailures.set(key, { startedAt: now, count: 1 });
  } else {
    entry.count += 1;
  }
}

function resetAuthAttempts(request) {
  authAttempts.delete(getClientAddress(request) || request.socket.remoteAddress || "unknown");
}

function validateUsername(username) {
  return typeof username === "string" &&
    /^[a-zA-Z0-9_.-]{3,32}$/.test(username);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 12 && password.length <= 128;
}

async function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = await scrypt(password, salt, 64);
  return { salt, hash: hash.toString("hex") };
}

async function readAuthBody(request, response, maximumBodySize = 65536) {
  try {
    return await readJsonRequest(request, maximumBodySize);
  } catch (error) {
    sendJson(response, error.statusCode || 400, { error: error.message });
    return null;
  }
}

function handleAuthStatus(request, response) {
  const setupRequired = appSetupRequired();
  const user = setupRequired ? null : currentUser(request);
  sendJson(response, 200, {
    setupRequired,
    setupTokenRequired: setupRequired && Boolean(setupToken),
    user,
    mailEnabled: Boolean(getMailConfig()),
    featureAccess: getFeatureAccess(),
    features: featureNames,
    previewAvailable: previewsAvailable(),
    publicLookupLimit: getPublicAccess().dailyLimit,
    sso: readSsoConfig().enabled ? { label: readSsoConfig().label } : null,
  });
}

// Optional secret that must be entered during first-run setup, so a freshly started
// instance that is reachable from the internet cannot be claimed by a stranger.
const setupToken = (process.env.SETUP_TOKEN || "").trim();

function setupTokenMatches(value) {
  if (!setupToken) return true;
  const supplied = crypto.createHash("sha256").update(String(value || "")).digest();
  const expected = crypto.createHash("sha256").update(setupToken).digest();
  return crypto.timingSafeEqual(supplied, expected);
}

async function handleInitialSetup(request, response) {
  if (!enforceSameOrigin(request, response)) return;
  if (appSetupRequired() && !allowAuthAttempt(request)) {
    sendJson(response, 429, { error: "Too many setup attempts. Try again later." });
    return;
  }
  const body = await readAuthBody(request, response);
  if (!body) return;
  if (!setupTokenMatches(body.setupToken)) {
    recordAdminLog("login", request, "Initial setup rejected (wrong setup token)", "", 403, null);
    sendJson(response, 403, { error: "The setup token is incorrect. It is the SETUP_TOKEN value configured on the server." });
    return;
  }
  const { username, password } = body;
  if (typeof body.confirmPassword !== "string" || body.confirmPassword !== password) {
    sendJson(response, 400, { error: "The passwords do not match." });
    return;
  }
  if (!validateUsername(username)) {
    sendJson(response, 400, { error: "Username must be 3–32 characters using letters, numbers, dot, underscore, or hyphen." });
    return;
  }
  if (!validatePassword(password)) {
    sendJson(response, 400, { error: "Password must be between 12 and 128 characters." });
    return;
  }
  const credentials = await hashPassword(password);
  database.exec("BEGIN IMMEDIATE");
  try {
    if (!appSetupRequired()) {
      database.exec("ROLLBACK");
      sendJson(response, 409, { error: "Initial admin setup has already been completed." });
      return;
    }
    const result = database.prepare(`
      INSERT INTO users (username, password_hash, password_salt, role)
      VALUES (?, ?, ?, 'admin')
    `).run(username, credentials.hash, credentials.salt);
    database.exec("COMMIT");
    await establishSession(Number(result.lastInsertRowid), response);
    recordNmapLoginIp(request, username);
    resetAuthAttempts(request);
    recordAdminLog(
      "audit",
      request,
      "Initial administrator created",
      username,
      201,
      username,
    );
    recordAdminLog("login", request, "Initial setup successful", "", 201, username);
    sendJson(response, 201, {
      user: { username, role: "admin" },
      featureAccess: getFeatureAccess(),
    });
  } catch (error) {
    database.exec("ROLLBACK");
    if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
      sendJson(response, 409, { error: "That username is already in use." });
      return;
    }
    console.error("Initial admin setup failed:", error);
    sendJson(response, 500, { error: "Unable to complete initial admin setup." });
  }
}

// ---------------------------------------------------------------- Two-factor login (TOTP, RFC 6238)

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const twoFactorChallenges = new Map();
const twoFactorLimits = { challengeMs: 5 * 60 * 1000, attempts: 5, recoveryCodes: 10 };

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += base32Alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(text) {
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const character of String(text).replace(/=+$/, "").toUpperCase()) {
    const index = base32Alphabet.indexOf(character);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpCode(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hmac = crypto.createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 15;
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

// Accepts the current 30-second code or one step either side, and never the same step twice.
function verifyTotp(secret, code, lastStep) {
  if (!/^\d{6}$/.test(String(code || ""))) return null;
  const now = Math.floor(Date.now() / 30000);
  for (const step of [now, now - 1, now + 1]) {
    if (step <= (lastStep || 0)) continue;
    const expected = Buffer.from(totpCode(secret, step));
    if (crypto.timingSafeEqual(expected, Buffer.from(String(code)))) return step;
  }
  return null;
}

function hashRecoveryCode(code) {
  return crypto.createHash("sha256").update(String(code).toUpperCase().replace(/[^A-Z0-9]/g, "")).digest("hex");
}

function newRecoveryCodes() {
  return Array.from({ length: twoFactorLimits.recoveryCodes }, () => {
    const raw = base32Encode(crypto.randomBytes(7)).slice(0, 10);
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  });
}

function twoFactorStatus(userId) {
  const row = database.prepare("SELECT totp_enabled, totp_recovery FROM users WHERE id = ?").get(userId);
  let recovery = [];
  try {
    recovery = JSON.parse(row?.totp_recovery || "[]");
  } catch {
    recovery = [];
  }
  return { enabled: Boolean(row?.totp_enabled), recoveryCodesLeft: recovery.length };
}

// Checks a TOTP or recovery code for a user and records it as used. Returns "totp", "recovery" or null.
function consumeSecondFactor(userId, code) {
  const row = database.prepare("SELECT totp_secret, totp_enabled, totp_last_step, totp_recovery FROM users WHERE id = ?").get(userId);
  if (!row?.totp_enabled || !row.totp_secret) return null;
  const step = verifyTotp(row.totp_secret, String(code || "").replace(/\s+/g, ""), row.totp_last_step);
  if (step !== null) {
    database.prepare("UPDATE users SET totp_last_step = ? WHERE id = ?").run(step, userId);
    return "totp";
  }
  let recovery = [];
  try {
    recovery = JSON.parse(row.totp_recovery || "[]");
  } catch {
    recovery = [];
  }
  const hash = hashRecoveryCode(code);
  if (String(code || "").replace(/[^A-Za-z0-9]/g, "").length === 10 && recovery.includes(hash)) {
    database.prepare("UPDATE users SET totp_recovery = ? WHERE id = ?").run(JSON.stringify(recovery.filter((entry) => entry !== hash)), userId);
    return "recovery";
  }
  return null;
}

function createTwoFactorChallenge(user) {
  const now = Date.now();
  for (const [id, challenge] of twoFactorChallenges) if (challenge.expiresAt < now) twoFactorChallenges.delete(id);
  if (twoFactorChallenges.size > 5000) twoFactorChallenges.clear();
  const id = crypto.randomBytes(24).toString("base64url");
  twoFactorChallenges.set(id, { userId: user.id, username: user.username, mustChangePassword: Boolean(user.must_change_password), role: user.role, attempts: 0, expiresAt: now + twoFactorLimits.challengeMs });
  return id;
}

async function handleTwoFactorLogin(request, response) {
  if (!enforceSameOrigin(request, response)) return;
  if (!allowAuthAttempt(request)) {
    sendJson(response, 429, { error: "Too many login attempts. Try again in 15 minutes." });
    return;
  }
  const body = await readAuthBody(request, response);
  if (!body) return;
  const challenge = twoFactorChallenges.get(typeof body.challenge === "string" ? body.challenge : "");
  if (!challenge || challenge.expiresAt < Date.now()) {
    sendJson(response, 401, { error: "The sign-in has expired. Enter your password again.", restart: true });
    return;
  }
  challenge.attempts += 1;
  const method = consumeSecondFactor(challenge.userId, body.code);
  if (!method) {
    if (challenge.attempts >= twoFactorLimits.attempts) twoFactorChallenges.delete(body.challenge);
    recordAccountLoginFailure(challenge.username);
    recordAdminLog("login", request, "Two-factor code rejected", "", 401, challenge.username);
    sendJson(response, 401, { error: challenge.attempts >= twoFactorLimits.attempts ? "Too many wrong codes. Enter your password again." : "That code is not valid.", restart: challenge.attempts >= twoFactorLimits.attempts });
    return;
  }
  twoFactorChallenges.delete(body.challenge);
  resetAuthAttempts(request);
  await establishSession(challenge.userId, response);
  if (!challenge.mustChangePassword) recordNmapLoginIp(request, challenge.username);
  recordAdminLog("login", request, method === "recovery" ? "Login successful (recovery code)" : "Login successful (two-factor)", "", 200, challenge.username);
  sendJson(response, 200, {
    user: { username: challenge.username, role: challenge.role },
    mustChangePassword: challenge.mustChangePassword,
    recoveryCodeUsed: method === "recovery",
    recoveryCodesLeft: twoFactorStatus(challenge.userId).recoveryCodesLeft,
  });
}

async function verifyAccountPassword(userId, password) {
  const row = database.prepare("SELECT password_hash, password_salt FROM users WHERE id = ?").get(userId);
  if (!row || typeof password !== "string" || password.length > 128) return false;
  const supplied = await scrypt(password, row.password_salt, 64);
  const stored = Buffer.from(row.password_hash, "hex");
  return stored.length === supplied.length && crypto.timingSafeEqual(stored, supplied);
}

async function handleAccountTwoFactor(request, response, action) {
  if (!enforceSameOrigin(request, response)) return;
  const user = currentUser(request);
  if (!user || request.apiUser) {
    sendJson(response, 401, { error: "Log in to continue." });
    return;
  }
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!allowAuthAttempt(request)) {
    sendJson(response, 429, { error: "Too many attempts. Try again in 15 minutes." });
    return;
  }
  const body = await readAuthBody(request, response);
  if (!body) return;
  const status = twoFactorStatus(user.id);
  if (action === "setup") {
    if (status.enabled) return sendJson(response, 409, { error: "Two-factor login is already on." });
    if (!await verifyAccountPassword(user.id, body.password)) return sendJson(response, 401, { error: "The password is incorrect." });
    const secret = base32Encode(crypto.randomBytes(20));
    database.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_last_step = 0 WHERE id = ?").run(secret, user.id);
    const issuer = getSiteTitle().replace(/[:]/g, "") || "BNGlookup";
    const label = `${issuer}:${user.username}`;
    sendJson(response, 200, {
      secret,
      uri: `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`,
    });
    return;
  }
  if (action === "enable") {
    const row = database.prepare("SELECT totp_secret, totp_enabled FROM users WHERE id = ?").get(user.id);
    if (row.totp_enabled) return sendJson(response, 409, { error: "Two-factor login is already on." });
    const step = row.totp_secret ? verifyTotp(row.totp_secret, String(body.code || "").replace(/\s+/g, ""), 0) : null;
    if (step === null) return sendJson(response, 400, { error: "That code is not valid. Check the time on your phone and try the next code." });
    const codes = newRecoveryCodes();
    database.prepare("UPDATE users SET totp_enabled = 1, totp_last_step = ?, totp_recovery = ? WHERE id = ?").run(step, JSON.stringify(codes.map(hashRecoveryCode)), user.id);
    recordAdminLog("audit", request, "Two-factor login enabled", "", 200, user.username);
    sendJson(response, 200, { enabled: true, recoveryCodes: codes });
    return;
  }
  if (action === "disable" || action === "recovery-codes") {
    if (!status.enabled) return sendJson(response, 409, { error: "Two-factor login is off." });
    if (!await verifyAccountPassword(user.id, body.password)) return sendJson(response, 401, { error: "The password is incorrect." });
    if (!consumeSecondFactor(user.id, body.code)) return sendJson(response, 401, { error: "That code is not valid." });
    if (action === "disable") {
      database.prepare("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_recovery = NULL, totp_last_step = 0 WHERE id = ?").run(user.id);
      recordAdminLog("audit", request, "Two-factor login disabled", "", 200, user.username);
      sendJson(response, 200, { enabled: false });
    } else {
      const codes = newRecoveryCodes();
      database.prepare("UPDATE users SET totp_recovery = ? WHERE id = ?").run(JSON.stringify(codes.map(hashRecoveryCode)), user.id);
      recordAdminLog("audit", request, "Two-factor recovery codes replaced", "", 200, user.username);
      sendJson(response, 200, { enabled: true, recoveryCodes: codes });
    }
    return;
  }
  sendJson(response, 404, { error: "Not found." });
}

// ---------------------------------------------------------------- API tokens

const apiTokenLimits = { perUser: 10, requestsPerHour: 600 };
const apiTokenPaths = new Set([
  "/api/lookup", "/api/domain-info", "/api/scan", "/api/custom-port-scan", "/api/bulk-port-scan", "/api/mac-lookup",
  "/api/dig", "/api/blocklist", "/api/propagation", "/api/email-check", "/api/asn", "/api/web-check", "/api/email-headers",
  "/api/dmarc-sources", "/api/record-import", "/api/bulk-domain-check", "/api/dns-health", "/api/reputation",
  "/api/lookalike", "/api/spf-flatten", "/api/ping", "/api/sslscan", "/api/ping-scan", "/api/traceroute", "/api/multi-traceroute",
  "/api/mail-server",
]);
const apiTokenUsage = new Map();

function apiTokenFromRequest(request) {
  const header = String(request.headers.authorization || "");
  const match = header.match(/^Bearer\s+(bngl_[A-Za-z0-9_-]{40,60})$/);
  return match ? match[1] : null;
}

// Resolves a bearer token to its user (with the same role checks as a session).
function authenticateApiToken(token) {
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const row = database.prepare(`
    SELECT api_tokens.id AS tokenId, api_tokens.expires_at AS expiresAt, users.id, users.username, users.role, users.email, users.must_change_password
    FROM api_tokens JOIN users ON users.id = api_tokens.user_id
    WHERE api_tokens.token_hash = ? AND users.active = 1
  `).get(tokenHash);
  if (!row || row.must_change_password || (row.expiresAt && row.expiresAt < Date.now())) return null;
  database.prepare("UPDATE api_tokens SET last_used_at = ? WHERE id = ?").run(Date.now(), row.tokenId);
  return { id: row.id, username: row.username, role: row.role, email: row.email || "", mustChangePassword: false, tokenId: row.tokenId };
}

function allowApiTokenRequest(tokenId) {
  const now = Date.now();
  const recent = (apiTokenUsage.get(tokenId) || []).filter((time) => now - time < 3600000);
  if (recent.length >= apiTokenLimits.requestsPerHour) return false;
  recent.push(now);
  apiTokenUsage.set(tokenId, recent);
  return true;
}

async function handleAccountTokens(request, response, tokenId) {
  const user = currentUser(request);
  if (!user || request.apiUser) {
    sendJson(response, 401, { error: "Log in to manage API tokens." });
    return;
  }
  if (!checkFeatureAccess(request, response, "api-tokens", true)) return;
  const describe = (row) => ({
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    createdAt: new Date(row.created_at).toISOString(),
    lastUsedAt: row.last_used_at ? new Date(row.last_used_at).toISOString() : null,
    expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
  });
  if (!tokenId && request.method === "GET") {
    sendJson(response, 200, { tokens: database.prepare("SELECT * FROM api_tokens WHERE user_id = ? ORDER BY id DESC").all(user.id).map(describe), limit: apiTokenLimits.perUser, requestsPerHour: apiTokenLimits.requestsPerHour });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  if (!tokenId && request.method === "POST") {
    const body = await readAuthBody(request, response, 2048);
    if (!body) return;
    const name = typeof body.name === "string" ? body.name.trim().replace(/[\u0000-\u001f]/g, "").slice(0, 60) : "";
    const days = body.expiresInDays === null || body.expiresInDays === undefined ? null : Number(body.expiresInDays);
    if (!name) return sendJson(response, 400, { error: "Give the token a name, such as the script that uses it." });
    if (days !== null && ![30, 90, 365].includes(days)) return sendJson(response, 400, { error: "Choose an expiry of 30, 90 or 365 days, or none." });
    if (database.prepare("SELECT COUNT(*) AS count FROM api_tokens WHERE user_id = ?").get(user.id).count >= apiTokenLimits.perUser) {
      return sendJson(response, 400, { error: `You can have up to ${apiTokenLimits.perUser} tokens. Revoke one first.` });
    }
    const token = `bngl_${crypto.randomBytes(32).toString("base64url")}`;
    const created = database.prepare("INSERT INTO api_tokens (user_id, name, token_hash, prefix, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(user.id, name, crypto.createHash("sha256").update(token).digest("hex"), token.slice(0, 12), Date.now(), days ? Date.now() + days * 86400000 : null);
    recordAdminLog("audit", request, "API token created", name, 200, user.username);
    sendJson(response, 201, { token, ...describe(database.prepare("SELECT * FROM api_tokens WHERE id = ?").get(Number(created.lastInsertRowid))) });
    return;
  }
  if (tokenId && request.method === "DELETE") {
    const row = database.prepare("SELECT * FROM api_tokens WHERE id = ? AND user_id = ?").get(tokenId, user.id);
    if (!row) return sendJson(response, 404, { error: "Token not found." });
    database.prepare("DELETE FROM api_tokens WHERE id = ?").run(tokenId);
    apiTokenUsage.delete(tokenId);
    recordAdminLog("audit", request, "API token revoked", row.name, 200, user.username);
    sendJson(response, 200, { revoked: true });
    return;
  }
  sendJson(response, 405, { error: "Method not allowed." });
}

async function establishSession(userId, response) {
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  database.prepare("DELETE FROM user_sessions WHERE expires_at <= ?").run(Date.now());
  database.prepare(`
    INSERT INTO user_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)
  `).run(tokenHash, userId, Date.now() + sessionDurationMs);
  setSessionCookie(response, token);
}

async function handleLogin(request, response) {
  if (!enforceSameOrigin(request, response)) {
    recordAdminLog("login", request, "Login request rejected", "", response.statusCode, null);
    return;
  }
  if (!allowAuthAttempt(request)) {
    recordAdminLog("login", request, "Login rate limited", "", 429, null);
    sendJson(response, 429, { error: "Too many login attempts. Try again in 15 minutes." });
    return;
  }
  const body = await readAuthBody(request, response);
  if (!body) {
    recordAdminLog("login", request, "Login request rejected", "", response.statusCode, null);
    return;
  }
  const username = typeof body.username === "string" && body.username.length <= 32
    ? body.username.trim()
    : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (accountLoginBlocked(username)) {
    recordAdminLog("login", request, "Login rate limited (account)", "", 429, username || null);
    sendJson(response, 429, { error: "Too many login attempts. Try again in 15 minutes." });
    return;
  }
  const user = database.prepare(`
    SELECT id, username, password_hash, password_salt, role, must_change_password
    FROM users WHERE username = ? AND active = 1
  `).get(username);
  const storedHash = user?.password_hash || "00".repeat(64);
  const salt = user?.password_salt || "00".repeat(16);
  const supplied = await scrypt(password.length <= 128 ? password : "", salt, 64);
  const validHash = Buffer.from(storedHash, "hex");
  const valid = validHash.length === supplied.length &&
    crypto.timingSafeEqual(validHash, supplied);
  if (!user || !valid || password.length > 128) {
    recordAccountLoginFailure(username);
    recordAdminLog("login", request, "Login failed", "", 401, username || null);
    sendJson(response, 401, { error: "Invalid username or password." });
    return;
  }
  resetAuthAttempts(request);
  accountLoginFailures.delete(username.toLowerCase());
  if (twoFactorStatus(user.id).enabled) {
    recordAdminLog("login", request, "Password accepted, two-factor code requested", "", 200, user.username);
    sendJson(response, 200, { twoFactorRequired: true, challenge: createTwoFactorChallenge(user) });
    return;
  }
  await establishSession(user.id, response);
  if (!user.must_change_password) recordNmapLoginIp(request, user.username);
  recordAdminLog("login", request, "Login successful", "", 200, user.username);
  sendJson(response, 200, {
    user: { username: user.username, role: user.role },
    mustChangePassword: Boolean(user.must_change_password),
    featureAccess: getFeatureAccess(),
  });
}

async function handleChangePassword(request, response) {
  if (!enforceSameOrigin(request, response)) return;
  const user = currentUser(request, { allowPending: true });
  if (!user) {
    sendJson(response, 401, { error: "Log in to continue." });
    return;
  }
  if (!allowAuthAttempt(request)) {
    sendJson(response, 429, { error: "Too many attempts. Try again in 15 minutes." });
    return;
  }
  const body = await readAuthBody(request, response);
  if (!body) return;
  const current = typeof body.currentPassword === "string" ? body.currentPassword : "";
  if (typeof body.newPassword !== "string" || body.newPassword !== body.confirmPassword) {
    sendJson(response, 400, { error: "The new passwords do not match." });
    return;
  }
  if (!validatePassword(body.newPassword)) {
    sendJson(response, 400, { error: "Password must be between 12 and 128 characters." });
    return;
  }
  if (body.newPassword === current) {
    sendJson(response, 400, { error: "Choose a password different from the current one." });
    return;
  }
  const row = database.prepare(
    "SELECT password_hash, password_salt FROM users WHERE id = ? AND active = 1",
  ).get(user.id);
  const supplied = await scrypt(current.length <= 128 ? current : "", row.password_salt, 64);
  const stored = Buffer.from(row.password_hash, "hex");
  if (current.length > 128 || stored.length !== supplied.length ||
    !crypto.timingSafeEqual(stored, supplied)) {
    recordAdminLog("login", request, "Password change failed", "", 401, user.username);
    sendJson(response, 401, { error: "The current password is incorrect." });
    return;
  }
  const credentials = await hashPassword(body.newPassword);
  database.prepare(`
    UPDATE users SET password_hash = ?, password_salt = ?, must_change_password = 0
    WHERE id = ?
  `).run(credentials.hash, credentials.salt, user.id);
  database.prepare("DELETE FROM user_sessions WHERE user_id = ?").run(user.id);
  resetAuthAttempts(request);
  await establishSession(user.id, response);
  recordNmapLoginIp(request, user.username);
  recordAdminLog("login", request, "Password changed", "", 200, user.username);
  sendJson(response, 200, { changed: true, role: user.role });
}

function handleLogout(request, response) {
  const user = currentUser(request);
  const token = readCookie(request, sessionCookieName);
  if (token) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    database.prepare("DELETE FROM user_sessions WHERE token_hash = ?").run(tokenHash);
  }
  clearSessionCookie(response);
  if (user) recordAdminLog("login", request, "Logout", "", 200, user.username);
  sendJson(response, 200, { loggedOut: true });
}

function requireAdmin(request, response) {
  const user = currentUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Log in to continue." });
    return null;
  }
  if (user.role !== "admin") {
    sendJson(response, 403, { error: "Administrator access is required." });
    return null;
  }
  return user;
}

function handleAdminSettings(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  request.logClientAddress = getClientAddress(request);
  if (request.method === "GET") {
    sendJson(response, 200, {
      featureAccess: getFeatureAccess(),
      features: featureNames,
      portScanPolicy: getPortScanPolicy(),
      zmapEnabled,
      nmapAllowedCidrs: getManualNmapAllowedCidrs().entries.join("\n"),
      nmapLoginIps: getNmapLoginIps(),
      defaultDnsResolver: getDefaultResolverId(),
      dnsResolvers: getDnsResolverOptions(),
      trustedProxies: trustedProxyEntries.join("\n"),
      trustCloudflareProxies: cloudflareProxyTrustEnabled,
      cloudflareProxyUpdatedAt,
      branding: getSiteBranding(),
    });
    return;
  }
  if (request.method !== "PUT") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response, 384 * 1024).then(async (body) => {
    if (!body) return;
    const access = Object.hasOwn(body, "featureAccess") ? body.featureAccess : getFeatureAccess();
    const portScanPolicy = Object.hasOwn(body, "portScanPolicy")
      ? body.portScanPolicy
      : getPortScanPolicy();
    if (portScanPolicy && typeof portScanPolicy === "object" && !Object.hasOwn(portScanPolicy, "zmapRate")) {
      portScanPolicy.zmapRate = getPortScanPolicy().zmapRate;
    }
    let nmapAllowedCidrs = getManualNmapAllowedCidrs();
    if (Object.hasOwn(body, "nmapAllowedCidrs")) {
      try {
        nmapAllowedCidrs = parseNmapAllowedCidrs(body.nmapAllowedCidrs);
      } catch (error) {
        sendJson(response, 400, { error: error.message });
        return;
      }
    }
    const defaultDnsResolver = Object.hasOwn(body, "defaultDnsResolver")
      ? body.defaultDnsResolver
      : getDefaultResolverId();
    const siteTitle = Object.hasOwn(body, "siteTitle") ? body.siteTitle : getSiteTitle();
    let trustedProxyConfig = { entries: trustedProxyEntries, ranges: trustedProxyRanges };
    if (Object.hasOwn(body, "trustedProxies")) {
      try {
        trustedProxyConfig = parseTrustedProxyEntries(body.trustedProxies);
      } catch (error) {
        sendJson(response, 400, { error: error.message });
        return;
      }
    }
    const trustCloudflareProxies = Object.hasOwn(body, "trustCloudflareProxies")
      ? body.trustCloudflareProxies
      : cloudflareProxyTrustEnabled;
    if (typeof trustCloudflareProxies !== "boolean") {
      sendJson(response, 400, { error: "Choose whether to trust Cloudflare proxy ranges." });
      return;
    }
    if (trustCloudflareProxies &&
      (!cloudflareProxyTrustEnabled || !cloudflareProxyEntries.length)) {
      try {
        await refreshCloudflareProxyRanges();
      } catch (error) {
        console.error("Unable to load Cloudflare proxy ranges:", error);
        sendJson(response, 502, { error: "Unable to retrieve Cloudflare proxy ranges. The setting was not enabled." });
        return;
      }
    }
    let combinedTrustedProxyConfig;
    try {
      combinedTrustedProxyConfig = combineTrustedProxyRanges(
        trustedProxyConfig.entries,
        trustCloudflareProxies ? cloudflareProxyEntries : [],
      );
    } catch (error) {
      sendJson(response, 400, { error: error.message });
      return;
    }
    let siteIconUrl;
    if (body.resetSiteIcon === true) {
      if (Object.hasOwn(body, "siteIconUrl") || Object.hasOwn(body, "siteIconUpload")) {
        sendJson(response, 400, { error: "Choose either the default icon or a custom icon." });
        return;
      }
      siteIconUrl = "/favicon.svg";
    } else if (Object.hasOwn(body, "siteIconUpload")) {
      if (Object.hasOwn(body, "siteIconUrl") ||
        typeof body.siteIconUpload !== "string" ||
        !isValidIconDataUrl(body.siteIconUpload)) {
        sendJson(response, 400, { error: "Upload a valid PNG, JPEG, GIF, WebP, or ICO image no larger than 256 KB." });
        return;
      }
      siteIconUrl = body.siteIconUpload;
    } else if (Object.hasOwn(body, "siteIconUrl")) {
      siteIconUrl = validateSiteIconUrl(body.siteIconUrl);
      if (!siteIconUrl) {
        sendJson(response, 400, { error: "Site icon URL must be a valid HTTPS URL without credentials." });
        return;
      }
    }
    if (!portScanPolicy?.largestBulkCidrPrefix ||
      !Number.isInteger(portScanPolicy.largestBulkCidrPrefix.ipv4) ||
      portScanPolicy.largestBulkCidrPrefix.ipv4 < 16 ||
      portScanPolicy.largestBulkCidrPrefix.ipv4 > 32 ||
      !Number.isInteger(portScanPolicy.largestBulkCidrPrefix.ipv6) ||
      portScanPolicy.largestBulkCidrPrefix.ipv6 < 120 ||
      portScanPolicy.largestBulkCidrPrefix.ipv6 > 128) {
      sendJson(response, 400, {
        error: "Bulk scan CIDR limits must be IPv4 /16–/32 and IPv6 /120–/128.",
      });
      return;
    }
    if (!Number.isInteger(portScanPolicy.zmapRate) ||
      portScanPolicy.zmapRate < zmapRateLimits.min ||
      portScanPolicy.zmapRate > zmapRateLimits.max) {
      sendJson(response, 400, {
        error: `The zmap send rate must be between ${zmapRateLimits.min.toLocaleString("en-US")} and ${zmapRateLimits.max.toLocaleString("en-US")} packets per second.`,
      });
      return;
    }
    if (!access || typeof access !== "object" || Array.isArray(access) ||
      Object.keys(access).length !== Object.keys(featureAccessDefaults).length ||
      Object.entries(featureAccessDefaults).some(([feature]) =>
        !["public", "user", "admin"].includes(access[feature]),
      ) ||
      !portScanPolicy || typeof portScanPolicy !== "object" ||
      !portScanPolicy.maxPortsByRole || !portScanPolicy.localScanByRole ||
      !["admin", "user"].every((role) =>
        Number.isInteger(portScanPolicy.maxPortsByRole[role]) &&
        portScanPolicy.maxPortsByRole[role] >= 1 &&
        portScanPolicy.maxPortsByRole[role] <= 65535 &&
        typeof portScanPolicy.localScanByRole[role] === "boolean",
      ) ||
      (!Object.hasOwn(dnsResolvers, defaultDnsResolver) &&
        !(defaultDnsResolver === "custom" && customDohEndpoint)) ||
      typeof siteTitle !== "string" || siteTitle !== siteTitle.trim() ||
      siteTitle.length < 1 || siteTitle.length > 60 ||
      /[\u0000-\u001f\u007f-\u009f]/.test(siteTitle)) {
      sendJson(response, 400, {
        error: "Choose a valid site title and resolver, an access level for every feature, and each role's port limit from 1 to 65,535 with a local-scan permission.",
      });
      return;
    }
    database.exec("BEGIN IMMEDIATE");
    try {
      const saveSetting = database.prepare(`
        INSERT INTO app_settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `);
      if (Object.hasOwn(body, "featureAccess")) {
        saveSetting.run("feature_access", JSON.stringify(access));
      }
      if (Object.hasOwn(body, "portScanPolicy")) {
        // Store only the validated fields, not whatever else the request body contained.
        saveSetting.run("port_scan_policy", JSON.stringify({
          maxPortsByRole: { admin: portScanPolicy.maxPortsByRole.admin, user: portScanPolicy.maxPortsByRole.user },
          localScanByRole: { admin: portScanPolicy.localScanByRole.admin, user: portScanPolicy.localScanByRole.user },
          largestBulkCidrPrefix: { ipv4: portScanPolicy.largestBulkCidrPrefix.ipv4, ipv6: portScanPolicy.largestBulkCidrPrefix.ipv6 },
          zmapRate: portScanPolicy.zmapRate,
        }));
      }
      if (Object.hasOwn(body, "nmapAllowedCidrs")) {
        saveSetting.run("nmap_allowed_cidrs", nmapAllowedCidrs.entries.join("\n"));
      }
      if (Object.hasOwn(body, "defaultDnsResolver")) {
        saveSetting.run("default_dns_resolver", defaultDnsResolver);
      }
      if (Object.hasOwn(body, "trustedProxies")) {
        saveSetting.run("trusted_proxies", JSON.stringify(trustedProxyConfig.entries));
      }
      if (Object.hasOwn(body, "trustCloudflareProxies")) {
        saveSetting.run("cloudflare_proxy_trust", JSON.stringify(trustCloudflareProxies));
      }
      if (Object.hasOwn(body, "siteTitle")) {
        saveSetting.run("site_title", siteTitle);
      }
      if (siteIconUrl !== undefined) {
        if (siteIconUrl === "/favicon.svg") {
          database.prepare("DELETE FROM app_settings WHERE key = 'site_icon'").run();
        } else {
          saveSetting.run("site_icon", siteIconUrl);
        }
      }
      database.exec("COMMIT");
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
    trustedProxyEntries = trustedProxyConfig.entries;
    cloudflareProxyTrustEnabled = trustCloudflareProxies;
    trustedProxyRanges = combinedTrustedProxyConfig.ranges;
    if (Object.hasOwn(body, "nmapAllowedCidrs")) {
      pruneNmapLoginIps(nmapAllowedCidrs.entries);
    }
    recordAdminLog(
      "audit",
      request,
      "Settings updated",
      "Site branding, feature access, port scan policy, DNS resolver, and trusted proxies updated.",
      200,
      admin.username,
    );
    sendJson(response, 200, {
      featureAccess: access,
      portScanPolicy,
      nmapAllowedCidrs: nmapAllowedCidrs.entries.join("\n"),
      nmapLoginIps: getNmapLoginIps(),
      defaultDnsResolver,
      trustedProxies: trustedProxyEntries.join("\n"),
      trustCloudflareProxies: cloudflareProxyTrustEnabled,
      cloudflareProxyUpdatedAt,
      branding: getSiteBranding(),
    });
  }).catch((error) => {
    console.error("Application settings update failed:", error);
    sendJson(response, 500, { error: "Unable to save application settings." });
  });
}

const mailRateLimit = new Map();

function getMailConfig(includeSecret = false) {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'smtp_config'").get();
  if (!row) return null;
  try {
    const saved = JSON.parse(row.value);
    if (!saved.enabled || !saved.host || !saved.from) return null;
    return includeSecret ? saved : { ...saved, password: undefined };
  } catch {
    return null;
  }
}

function readMailSettings() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'smtp_config'").get();
  let saved = {};
  try { saved = row ? JSON.parse(row.value) : {}; } catch { saved = {}; }
  return saved;
}

function publicMailSettings(saved) {
  return {
    enabled: Boolean(saved.enabled),
    host: saved.host || "",
    port: saved.port || 587,
    security: saved.security || "starttls",
    username: saved.username || "",
    passwordSet: Boolean(saved.password),
    from: saved.from || "",
    fromName: saved.fromName || "",
  };
}

function validateMailSettings(body, previous) {
  const host = typeof body.host === "string" ? body.host.trim() : "";
  const port = Number(body.port);
  const security = body.security;
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const from = typeof body.from === "string" ? body.from.trim() : "";
  const fromName = typeof body.fromName === "string" ? body.fromName.trim() : "";
  if (!/^[A-Za-z0-9._:-]{1,253}$/.test(host)) return { error: "Enter a valid mail server host name." };
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: "Enter a port from 1 to 65,535." };
  if (!["starttls", "tls", "none"].includes(security)) return { error: "Choose a connection security mode." };
  if (!validAddress(from)) return { error: "Enter a valid sender email address." };
  if (fromName.length > 60 || /[\u0000-\u001f\u007f-\u009f]/.test(fromName)) {
    return { error: "The sender name is too long or contains control characters." };
  }
  if (username.length > 254 || /[\u0000-\u001f\u007f-\u009f]/.test(username)) {
    return { error: "Enter a valid SMTP username." };
  }
  let password = previous.password || "";
  if (typeof body.password === "string" && body.password !== "") password = body.password;
  if (body.clearPassword === true) password = "";
  if (password.length > 256 || /[\u0000-\u001f]/.test(password)) {
    return { error: "Enter a valid SMTP password." };
  }
  if (!username) password = "";
  return { value: { enabled: body.enabled === true, host, port, security, username, password, from, fromName } };
}

function handleAdminMail(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    sendJson(response, 200, publicMailSettings(readMailSettings()));
    return;
  }
  if (request.method !== "PUT" && request.method !== "POST") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response).then(async (body) => {
    if (!body) return;
    const previous = readMailSettings();
    if (request.method === "PUT") {
      const result = validateMailSettings(body, previous);
      if (result.error) {
        sendJson(response, 400, { error: result.error });
        return;
      }
      database.prepare(`
        INSERT INTO app_settings (key, value) VALUES ('smtp_config', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `).run(JSON.stringify(result.value));
      recordAdminLog("audit", request, "Mail settings updated",
        `${result.value.host}:${result.value.port} (${result.value.enabled ? "enabled" : "disabled"})`,
        200, admin.username);
      sendJson(response, 200, publicMailSettings(result.value));
      return;
    }
    const recipient = typeof body.to === "string" ? body.to.trim() : "";
    const config = readMailSettings();
    if (!config.host || !config.from) {
      sendJson(response, 400, { error: "Save the mail server settings first." });
      return;
    }
    if (!validAddress(recipient)) {
      sendJson(response, 400, { error: "Enter a valid recipient email address." });
      return;
    }
    try {
      await sendMail(config, {
        from: config.from,
        fromName: config.fromName,
        to: recipient,
        subject: "Test email",
        text: "This is a test email from your DNS lookup server. Mail delivery is working.",
      });
      recordAdminLog("audit", request, "Test email sent", recipient, 200, admin.username);
      sendJson(response, 200, { sent: true });
    } catch (error) {
      recordAdminLog("audit", request, "Test email failed", String(error.message).slice(0, 200), 502, admin.username);
      sendJson(response, 502, { error: `Could not send: ${String(error.message).slice(0, 200)}` });
    }
  }).catch((error) => {
    console.error("Mail settings failed:", error);
    sendJson(response, 500, { error: "Unable to process mail settings." });
  });
}

function handleAccount(request, response) {
  const user = currentUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Log in to continue." });
    return;
  }
  if (request.method === "GET") {
    sendJson(response, 200, {
      username: user.username,
      role: user.role,
      email: user.email,
      mailEnabled: Boolean(getMailConfig()),
      twoFactor: twoFactorStatus(user.id),
      apiTokensAllowed: (() => {
        const access = getFeatureAccess()["api-tokens"] || "admin";
        return access !== "admin" || user.role === "admin";
      })(),
    });
    return;
  }
  if (request.method !== "PUT") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response).then((body) => {
    if (!body) return;
    const email = typeof body.email === "string" ? body.email.trim() : null;
    if (email === null || (email !== "" && !validAddress(email))) {
      sendJson(response, 400, { error: "Enter a valid email address, or leave it empty to remove it." });
      return;
    }
    database.prepare("UPDATE users SET email = ? WHERE id = ?").run(email || null, user.id);
    recordAdminLog("audit", request, "Email address updated", email ? "set" : "removed", 200, user.username);
    sendJson(response, 200, { email });
  }).catch((error) => {
    console.error("Account update failed:", error);
    sendJson(response, 500, { error: "Unable to update your account." });
  });
}

async function handleMailResults(request, response) {
  if (!enforceSameOrigin(request, response)) return;
  const user = currentUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Log in to continue." });
    return;
  }
  const config = getMailConfig(true);
  if (!config) {
    sendJson(response, 503, { error: "Email is not configured on this server." });
    return;
  }
  if (!user.email) {
    sendJson(response, 400, { error: "Add your email address on the My account page first." });
    return;
  }
  const now = Date.now();
  const recent = (mailRateLimit.get(user.id) || []).filter((time) => now - time < 3600000);
  if (recent.length >= 10) {
    sendJson(response, 429, { error: "You can email up to 10 results per hour." });
    return;
  }
  const body = await readAuthBody(request, response, 256 * 1024);
  if (!body) return;
  const text = typeof body.text === "string" ? body.text.trim() : "";
  const subject = typeof body.subject === "string"
    ? body.subject.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").trim().slice(0, 120)
    : "";
  if (!text || text.length > 200000) {
    sendJson(response, 400, { error: "There are no results to send, or they are too large." });
    return;
  }
  recent.push(now);
  mailRateLimit.set(user.id, recent);
  try {
    await sendMail(config, {
      from: config.from,
      fromName: config.fromName,
      to: user.email,
      subject: subject || "DNS lookup results",
      text,
    });
    recordAdminLog("audit", request, "Results emailed", subject, 200, user.username);
    sendJson(response, 200, { sent: true });
  } catch (error) {
    console.error("Result email failed:", error.message);
    recordAdminLog("audit", request, "Results email failed", String(error.message).slice(0, 200), 502, user.username);
    sendJson(response, 502, { error: "The email could not be sent. Ask an administrator to check the mail settings." });
  }
}

function handleAdminUsers(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    const users = database.prepare(`
      SELECT id, username, role, active, email, created_at AS createdAt, totp_enabled AS twoFactor
      FROM users ORDER BY id
    `).all();
    sendJson(response, 200, { users });
    return;
  }
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response).then(async (body) => {
    if (!body) return;
    if (!validateUsername(body.username)) {
      sendJson(response, 400, { error: "Username must be 3–32 characters using letters, numbers, dot, underscore, or hyphen." });
      return;
    }
    if (!validatePassword(body.password)) {
      sendJson(response, 400, { error: "Password must be between 12 and 128 characters." });
      return;
    }
    if (!["admin", "user"].includes(body.role)) {
      sendJson(response, 400, { error: "Choose the admin or user role." });
      return;
    }
    const email = typeof body.email === "string" ? body.email.trim() : "";
    if (email && !validAddress(email)) {
      sendJson(response, 400, { error: "Enter a valid email address." });
      return;
    }
    const credentials = await hashPassword(body.password);
    try {
      database.prepare(`
        INSERT INTO users (username, password_hash, password_salt, role, must_change_password, email)
        VALUES (?, ?, ?, ?, 1, ?)
      `).run(body.username, credentials.hash, credentials.salt, body.role, email || null);
      recordAdminLog(
        "audit",
        request,
        "User account created",
        `${body.username} (${body.role})`,
        201,
        admin.username,
      );
      sendJson(response, 201, { created: true });
    } catch (error) {
      if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
        sendJson(response, 409, { error: "That username is already in use." });
        return;
      }
      console.error("User creation failed:", error);
      sendJson(response, 500, { error: "Unable to create user." });
    }
  }).catch((error) => {
    console.error("User creation failed:", error);
    sendJson(response, 500, { error: "Unable to create user." });
  });
}

function handleAdminUser(request, response, userId) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "DELETE") {
    if (!enforceSameOrigin(request, response)) return;
    const target = database.prepare(
      "SELECT id, username, role, active FROM users WHERE id = ?",
    ).get(userId);
    if (!target) {
      sendJson(response, 404, { error: "User not found." });
      return;
    }
    if (target.id === admin.id) {
      sendJson(response, 409, { error: "You cannot remove your own account." });
      return;
    }
    if (target.role === "admin" && target.active === 1 && database.prepare(
      "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1",
    ).get().count <= 1) {
      sendJson(response, 409, { error: "The last active administrator cannot be removed." });
      return;
    }
    database.prepare("DELETE FROM users WHERE id = ?").run(userId);
    mailRateLimit.delete(userId);
    recordAdminLog("audit", request, "User account removed", target.username, 200, admin.username);
    sendJson(response, 200, { removed: true });
    return;
  }
  if (request.method !== "PATCH") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response).then(async (body) => {
    if (!body) return;
    const target = database.prepare(
      "SELECT id, username, role, active FROM users WHERE id = ?",
    ).get(userId);
    if (!target) {
      sendJson(response, 404, { error: "User not found." });
      return;
    }
    const role = body.role === undefined ? target.role : body.role;
    const active = body.active === undefined
      ? target.active
      : body.active === true || body.active === 1
        ? 1
        : body.active === false || body.active === 0
          ? 0
          : null;
    if (!["admin", "user"].includes(role) || ![0, 1].includes(active)) {
      sendJson(response, 400, { error: "Choose a valid role and account status." });
      return;
    }
    let email;
    if (body.email !== undefined) {
      email = typeof body.email === "string" ? body.email.trim() : null;
      if (email === null || (email && !validAddress(email))) {
        sendJson(response, 400, { error: "Enter a valid email address." });
        return;
      }
    }
    const hasPassword = body.password !== undefined && body.password !== "";
    if (hasPassword && !validatePassword(body.password)) {
      sendJson(response, 400, { error: "Password must be between 12 and 128 characters." });
      return;
    }
    const removesAdmin = target.role === "admin" && target.active === 1 &&
      (role !== "admin" || active !== 1);
    if (removesAdmin) {
      const activeAdmins = database.prepare(`
        SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1
      `).get().count;
      if (activeAdmins <= 1) {
        sendJson(response, 409, { error: "The last active administrator cannot be disabled or demoted." });
        return;
      }
    }
    if (hasPassword) {
      const credentials = await hashPassword(body.password);
      database.prepare(`
        UPDATE users SET role = ?, active = ?, password_hash = ?, password_salt = ?,
          must_change_password = ?
        WHERE id = ?
      `).run(role, active, credentials.hash, credentials.salt, userId === admin.id ? 0 : 1, userId);
    } else {
      database.prepare("UPDATE users SET role = ?, active = ? WHERE id = ?")
        .run(role, active, userId);
    }
    if (email !== undefined) {
      database.prepare("UPDATE users SET email = ? WHERE id = ?").run(email || null, userId);
    }
    const resetTwoFactor = body.resetTwoFactor === true;
    if (resetTwoFactor) {
      database.prepare("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_recovery = NULL, totp_last_step = 0 WHERE id = ?").run(userId);
    }
    if (!active || hasPassword) {
      database.prepare("DELETE FROM user_sessions WHERE user_id = ?").run(userId);
    }
    const changes = [
      target.role !== role ? `role ${target.role} → ${role}` : "",
      target.active !== active ? `active ${target.active ? "yes" : "no"} → ${active ? "yes" : "no"}` : "",
      hasPassword ? "password reset" : "",
      email !== undefined ? "email updated" : "",
      resetTwoFactor ? "two-factor login reset" : "",
    ].filter(Boolean);
    recordAdminLog(
      "audit",
      request,
      "User account updated",
      `${target.username}${changes.length ? `: ${changes.join(", ")}` : ": no changes"}`,
      200,
      admin.username,
    );
    sendJson(response, 200, { updated: true });
  }).catch((error) => {
    console.error("User update failed:", error);
    sendJson(response, 500, { error: "Unable to update user." });
  });
}

function handleAdminLogs(request, url, response) {
  if (!requireAdmin(request, response)) return;
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  const category = url.searchParams.get("category");
  if (!["login", "audit", "query"].includes(category)) {
    sendJson(response, 400, { error: "Choose login, audit, or query logs." });
    return;
  }
  const rawLimit = url.searchParams.get("limit") || "200";
  if (!/^\d+$/.test(rawLimit) || Number(rawLimit) < 1 || Number(rawLimit) > 500) {
    sendJson(response, 400, { error: "Log limit must be between 1 and 500." });
    return;
  }
  const search = (url.searchParams.get("q") || "").trim();
  const outcome = url.searchParams.get("status") || "";
  const from = url.searchParams.get("from") || "";
  const to = url.searchParams.get("to") || "";
  const before = url.searchParams.get("before") || "";
  if (search.length > 200) {
    sendJson(response, 400, { error: "The search text must not exceed 200 characters." });
    return;
  }
  if (!["", "success", "failure"].includes(outcome)) {
    sendJson(response, 400, { error: "Status must be success or failure." });
    return;
  }
  const validDate = (value) => !value || (/^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`)));
  if (!validDate(from) || !validDate(to)) {
    sendJson(response, 400, { error: "Dates must use the YYYY-MM-DD format." });
    return;
  }
  if (before && !/^\d{1,15}$/.test(before)) {
    sendJson(response, 400, { error: "Invalid page cursor." });
    return;
  }
  const conditions = ["category = ?"];
  const params = [category];
  // Every word must appear in the user, client IP, action or details (case-insensitive).
  for (const term of search.split(/\s+/).filter(Boolean).slice(0, 8)) {
    const pattern = `%${term.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
    conditions.push("(COALESCE(username, '') LIKE ? ESCAPE '\\' OR COALESCE(client_ip, '') LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\' OR COALESCE(details, '') LIKE ? ESCAPE '\\')");
    params.push(pattern, pattern, pattern, pattern);
  }
  if (outcome === "success") conditions.push("status_code < 400");
  if (outcome === "failure") conditions.push("status_code >= 400");
  if (from) {
    conditions.push("created_at >= ?");
    params.push(`${from} 00:00:00`);
  }
  if (to) {
    conditions.push("created_at <= ?");
    params.push(`${to} 23:59:59`);
  }
  const where = conditions.join(" AND ");
  const total = database.prepare(`SELECT COUNT(*) AS count FROM admin_logs WHERE ${where}`).get(...params).count;
  const pageConditions = before ? `${where} AND id < ?` : where;
  const pageParams = before ? [...params, Number(before)] : params;
  const logs = database.prepare(`
    SELECT id, created_at AS timestamp, username, client_ip AS clientIp,
      action, details, status_code AS statusCode
    FROM admin_logs
    WHERE ${pageConditions}
    ORDER BY id DESC
    LIMIT ?
  `).all(...pageParams, Number(rawLimit));
  sendJson(response, 200, {
    logs,
    total,
    filtered: conditions.length > 1,
    nextBefore: logs.length === Number(rawLimit) ? logs.at(-1).id : null,
  });
}

let cpuSample = { idle: 0, total: 0, processMicros: 0, at: Date.now() };
const cpuUsage = { system: 0, process: 0 };

function sampleCpu() {
  let idle = 0;
  let total = 0;
  for (const { times } of os.cpus()) {
    idle += times.idle;
    total += times.user + times.nice + times.sys + times.idle + times.irq;
  }
  const usage = process.cpuUsage();
  const processMicros = usage.user + usage.system;
  const now = Date.now();
  if (cpuSample.total && total > cpuSample.total) {
    cpuUsage.system = Math.round((1 - (idle - cpuSample.idle) / (total - cpuSample.total)) * 1000) / 10;
    const elapsedMicros = (now - cpuSample.at) * 1000 * Math.max(1, os.cpus().length);
    cpuUsage.process = Math.round(Math.min(100, ((processMicros - cpuSample.processMicros) / elapsedMicros) * 100) * 10) / 10;
  }
  cpuSample = { idle, total, processMicros, at: now };
}
sampleCpu();
setInterval(sampleCpu, 2000).unref();

function readNumberFile(file) {
  try {
    const value = fs.readFileSync(file, "utf8").trim();
    return /^\d+$/.test(value) ? Number(value) : null;
  } catch {
    return null;
  }
}

function memoryInfo() {
  const hostTotal = os.totalmem();
  const limit = readNumberFile("/sys/fs/cgroup/memory.max");
  const used = readNumberFile("/sys/fs/cgroup/memory.current");
  if (limit && used !== null && limit < hostTotal) {
    return { scope: "container", total: limit, used: Math.min(used, limit) };
  }
  if (used !== null) return { scope: "container", total: hostTotal, used };
  return { scope: "host", total: hostTotal, used: hostTotal - os.freemem() };
}

const appRepository = /^[\w.-]+\/[\w.-]+$/.test(process.env.UPDATE_REPOSITORY || "")
  ? process.env.UPDATE_REPOSITORY
  : "BANAANGA/BNGlookup";
const appBuild = {
  version: (process.env.APP_VERSION || "").trim() || "dev",
  commit: /^[0-9a-f]{7,40}$/i.test(process.env.APP_COMMIT || "") ? process.env.APP_COMMIT : null,
  buildDate: Number.isNaN(Date.parse(process.env.APP_BUILD_DATE || "")) ? null : new Date(process.env.APP_BUILD_DATE).toISOString(),
};
const updateCheckEnabled = process.env.UPDATE_CHECK !== "false";
const updateCheckCacheMs = { success: 6 * 3600_000, failure: 30 * 60_000 };
let updateCheckState = null;
let updateCheckPromise = null;

function parseVersion(value) {
  const match = String(value || "").trim().match(/^v?(\d+(?:\.\d+){0,3})$/i);
  return match ? match[1].split(".").map(Number) : null;
}

function compareVersions(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) return null;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] || 0) - (b[index] || 0);
    if (difference) return Math.sign(difference);
  }
  return 0;
}

async function fetchLatestRelease() {
  const response = await fetch(`https://api.github.com/repos/${appRepository}/releases/latest`, {
    headers: { accept: "application/vnd.github+json", "user-agent": "BNGlookup-update-check" },
    signal: AbortSignal.timeout(10000),
  });
  if (response.status === 404) throw new Error("No published release was found.");
  if (!response.ok) throw new Error(`GitHub returned HTTP ${response.status}.`);
  const release = await response.json();
  if (typeof release.tag_name !== "string") throw new Error("GitHub returned an invalid release.");
  return {
    version: release.tag_name.slice(0, 64),
    url: typeof release.html_url === "string" && release.html_url.startsWith("https://github.com/")
      ? release.html_url
      : `https://github.com/${appRepository}/releases`,
    publishedAt: typeof release.published_at === "string" ? release.published_at : null,
  };
}

async function getUpdateCheck(force = false) {
  if (!updateCheckEnabled) return { enabled: false };
  const age = updateCheckState ? Date.now() - updateCheckState.checkedAt : Infinity;
  const maxAge = updateCheckState?.error ? updateCheckCacheMs.failure : updateCheckCacheMs.success;
  if (force || age > maxAge) {
    updateCheckPromise ||= fetchLatestRelease()
      .then((latest) => ({ checkedAt: Date.now(), latest }))
      .catch((error) => ({
        checkedAt: Date.now(),
        latest: updateCheckState?.latest || null,
        error: error.name === "TimeoutError" ? "GitHub did not respond in time." : error.message,
      }))
      .then((state) => {
        updateCheckState = state;
        return state;
      })
      .finally(() => { updateCheckPromise = null; });
    await updateCheckPromise;
  }
  const latest = updateCheckState?.latest || null;
  const comparison = latest ? compareVersions(latest.version, appBuild.version) : null;
  return {
    enabled: true,
    checkedAt: updateCheckState ? new Date(updateCheckState.checkedAt).toISOString() : null,
    latestVersion: latest?.version || null,
    latestUrl: latest?.url || null,
    publishedAt: latest?.publishedAt || null,
    updateAvailable: comparison === null ? null : comparison > 0,
    error: updateCheckState?.error || null,
  };
}

async function handleAdminVersion(request, url, response) {
  if (!requireAdmin(request, response)) return;
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  sendJson(response, 200, {
    ...appBuild,
    repositoryUrl: `https://github.com/${appRepository}`,
    updateCheck: await getUpdateCheck(url.searchParams.get("refresh") === "1"),
  });
}

const bimiLogoLimits = { maxBytes: 65536, bimiBytes: 32768 };

// Checks an uploaded SVG for anything that could run code or load content when the file is
// opened from this site (errors), and for BIMI "SVG Tiny Portable/Secure" problems (warnings).
function validateBimiSvg(svg) {
  const errors = [];
  const warnings = [];
  if (typeof svg !== "string" || !svg.trim()) return { errors: ["Choose an SVG file."], warnings };
  const bytes = Buffer.byteLength(svg);
  if (bytes > bimiLogoLimits.maxBytes) errors.push(`The file is ${Math.ceil(bytes / 1024)} KB; the limit is 64 KB.`);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(svg)) errors.push("The file contains binary or control characters.");
  const body = svg.replace(/^﻿/, "").replace(/<\?xml[^>]*\?>/i, "").replace(/<!--[\s\S]*?-->/g, "").trim();
  if (!/^<svg[\s>]/i.test(body)) errors.push("The file must be an SVG document whose root element is <svg>.");
  if (/<!ENTITY|<!DOCTYPE[^>]*\[/i.test(svg)) errors.push("Entity and DTD declarations are not allowed.");
  const forbiddenElements = svg.match(/<\s*(script|foreignObject|iframe|embed|object|image|img|audio|video|canvas|animate\w*|set|a|handler|listener|discard)\b/gi);
  if (forbiddenElements) errors.push(`Not allowed: ${[...new Set(forbiddenElements.map((tag) => `<${tag.replace(/[<\s]/g, "").toLowerCase()}>`))].join(", ")} (scripts, embedded content, links and animation).`);
  if (/\son[a-z]+\s*=/i.test(svg)) errors.push("Event handler attributes (such as onload) are not allowed.");
  if (/javascript\s*:|data\s*:\s*text\/html|vbscript\s*:/i.test(svg)) errors.push("Script URLs are not allowed.");
  if (/\b(?:xlink:)?href\s*=\s*["']\s*(?!#)/i.test(svg)) errors.push("References to other files (href) are not allowed; only internal #references are.");
  if (/@import|url\(\s*["']?\s*(?!#)/i.test(svg)) errors.push("External references in styles (@import or url()) are not allowed.");
  if (errors.length) return { errors, warnings };
  const root = body.match(/^<svg\b[^>]*>/i)?.[0] || "";
  const attribute = (name) => root.match(new RegExp(`\\s${name}\\s*=\\s*["']([^"']*)["']`, "i"))?.[1];
  if (attribute("version") !== "1.2" || attribute("baseProfile") !== "tiny-ps") {
    warnings.push('BIMI requires SVG Tiny Portable/Secure: the root element needs version="1.2" baseProfile="tiny-ps".');
  }
  if (!/<title[\s>][\s\S]*?<\/title>/i.test(svg)) warnings.push("BIMI requires a <title> element (usually the company name).");
  if (attribute("x") !== undefined || attribute("y") !== undefined) warnings.push("The root <svg> element must not have x or y attributes.");
  const viewBox = attribute("viewBox")?.trim().split(/[\s,]+/).map(Number);
  if (!viewBox || viewBox.length !== 4 || viewBox.some((value) => !Number.isFinite(value))) {
    warnings.push("Add a viewBox; BIMI logos must be square.");
  } else if (viewBox[2] !== viewBox[3]) {
    warnings.push(`The viewBox is ${viewBox[2]} × ${viewBox[3]}; BIMI logos must be square.`);
  }
  if (/<style[\s>]/i.test(svg)) warnings.push("SVG Tiny PS does not allow <style> elements; use presentation attributes such as fill instead.");
  if (bytes > bimiLogoLimits.bimiBytes) warnings.push(`The file is ${Math.ceil(bytes / 1024)} KB; BIMI recommends at most 32 KB.`);
  return { errors, warnings };
}

function readBimiLogo() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'bimi_logo'").get();
  if (!row) return null;
  try {
    const saved = JSON.parse(row.value);
    return typeof saved.svg === "string" ? saved : null;
  } catch {
    return null;
  }
}

function serveBimiLogo(request, response) {
  const logo = readBimiLogo();
  if (!logo) return false;
  // A sandboxed CSP so the SVG can never run script, even when opened directly.
  response.writeHead(200, {
    "content-type": "image/svg+xml; charset=utf-8",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "x-content-type-options": "nosniff",
    "cache-control": "public, max-age=300",
    "access-control-allow-origin": "*",
  });
  response.end(request.method === "HEAD" ? undefined : logo.svg);
  return true;
}

function bimiLogoStatus(request, logo = readBimiLogo()) {
  const host = String(request.headers.host || "your-site.example").replace(/[^a-z0-9.:[\]-]/gi, "");
  return {
    custom: Boolean(logo),
    updatedAt: logo?.updatedAt || null,
    bytes: logo ? Buffer.byteLength(logo.svg) : null,
    warnings: logo ? validateBimiSvg(logo.svg).warnings : [],
    url: `https://${host}/logo.svg`,
    record: `v=BIMI1; l=https://${host}/logo.svg;`,
  };
}

function handleAdminLogo(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    sendJson(response, 200, bimiLogoStatus(request));
    return;
  }
  if (request.method !== "PUT" && request.method !== "DELETE") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  if (request.method === "DELETE") {
    database.prepare("DELETE FROM app_settings WHERE key = 'bimi_logo'").run();
    recordAdminLog("audit", request, "BIMI logo removed", null, 200, admin.username);
    sendJson(response, 200, bimiLogoStatus(request, null));
    return;
  }
  void readAuthBody(request, response, bimiLogoLimits.maxBytes * 2 + 1024).then((body) => {
    if (!body) return;
    const svg = typeof body.svg === "string" ? body.svg.replace(/\r\n/g, "\n") : "";
    const { errors, warnings } = validateBimiSvg(svg);
    if (errors.length) {
      sendJson(response, 400, { error: errors.join(" "), errors, warnings });
      return;
    }
    const saved = { svg, updatedAt: new Date().toISOString() };
    database.prepare(`
      INSERT INTO app_settings (key, value) VALUES ('bimi_logo', ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(JSON.stringify(saved));
    recordAdminLog("audit", request, "BIMI logo uploaded", `${Buffer.byteLength(svg)} bytes, ${warnings.length} BIMI warning(s)`, 200, admin.username);
    sendJson(response, 200, bimiLogoStatus(request, saved));
  });
}

const aboutContentLimit = 20000;
const defaultAboutContent = `# About this site

This site runs **BNGlookup**, a self-hosted DNS and network toolkit: DNS and reverse lookups, Whois, DNSSEC checks, dig, ping, traceroute, TLS tests and more.

The administrator has not written a custom About page yet.

Source code: [github.com/BANAANGA/BNGlookup](https://github.com/BANAANGA/BNGlookup)`;

function readAboutContent() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'about_page'").get();
  if (!row) return { content: defaultAboutContent, custom: false, updatedAt: null };
  try {
    const saved = JSON.parse(row.value);
    return { content: String(saved.content || ""), custom: true, updatedAt: saved.updatedAt || null };
  } catch {
    return { content: defaultAboutContent, custom: false, updatedAt: null };
  }
}

function handleAbout(request, response) {
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (appSetupRequired()) {
    sendJson(response, 503, { error: "Complete initial administrator setup first.", setupRequired: true });
    return;
  }
  sendJson(response, 200, readAboutContent());
}

function handleAdminAbout(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    sendJson(response, 200, { ...readAboutContent(), defaultContent: defaultAboutContent, limit: aboutContentLimit });
    return;
  }
  if (request.method !== "PUT" && request.method !== "DELETE") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  if (request.method === "DELETE") {
    database.prepare("DELETE FROM app_settings WHERE key = 'about_page'").run();
    recordAdminLog("audit", request, "About page reset", null, 200, admin.username);
    sendJson(response, 200, { ...readAboutContent(), defaultContent: defaultAboutContent, limit: aboutContentLimit });
    return;
  }
  void readAuthBody(request, response).then((body) => {
    if (!body) return;
    const content = typeof body.content === "string" ? body.content.replace(/\r\n/g, "\n") : null;
    if (content === null || content.length > aboutContentLimit) {
      sendJson(response, 400, { error: `About page content must be text of at most ${aboutContentLimit.toLocaleString("en-US")} characters.` });
      return;
    }
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(content)) {
      sendJson(response, 400, { error: "About page content contains unsupported control characters." });
      return;
    }
    const saved = { content, updatedAt: new Date().toISOString() };
    database.prepare(`
      INSERT INTO app_settings (key, value) VALUES ('about_page', ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(JSON.stringify(saved));
    recordAdminLog("audit", request, "About page updated", `${content.length} characters`, 200, admin.username);
    sendJson(response, 200, { ...saved, custom: true, defaultContent: defaultAboutContent, limit: aboutContentLimit });
  });
}

const shareableModes = new Set([
  "forward", "reverse", "details", "mac", "dig", "propagation", "ping", "sslscan", "ping-scan",
  "traceroute", "multi-traceroute", "scan", "custom-port", "bulk-port", "nmap", "dnssec", "email", "asn",
  "web", "email-headers", "dmarc-reports", "bulk-domains", "dns-health", "reputation", "lookalike", "spf-flatten", "ip-calc", "mail-server", "tlsrpt-reports",
]);
const shareLimits = { payloadBytes: 1024 * 1024, perUser: 200, lifetimeMs: 30 * 24 * 3600_000 };

function pruneSharedResults() {
  database.prepare("DELETE FROM shared_results WHERE expires_at <= ?").run(Date.now());
}

function describeShare(row) {
  return {
    id: row.id,
    url: `/?share=${row.id}`,
    mode: row.mode,
    title: row.title,
    createdAt: new Date(row.created_at).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
  };
}

async function handleShares(request, url, response) {
  const id = url.pathname.slice("/api/shares/".length);
  const user = currentUser(request);
  if (url.pathname.startsWith("/api/shares/")) {
    if (!/^[A-Za-z0-9_-]{22}$/.test(id)) {
      sendJson(response, 404, { error: "This shared result does not exist or has expired." });
      return;
    }
    pruneSharedResults();
    const row = database.prepare("SELECT * FROM shared_results WHERE id = ?").get(id);
    if (request.method === "GET") {
      if (!row) {
        sendJson(response, 404, { error: "This shared result does not exist or has expired." });
        return;
      }
      let data;
      try {
        data = JSON.parse(row.payload);
      } catch {
        sendJson(response, 500, { error: "This shared result is damaged." });
        return;
      }
      response.setHeader("x-robots-tag", "noindex");
      sendJson(response, 200, { ...describeShare(row), data });
      return;
    }
    if (request.method === "DELETE") {
      if (!user) {
        sendJson(response, 401, { error: "Log in to continue.", loginRequired: true });
        return;
      }
      if (!enforceSameOrigin(request, response)) return;
      if (!row || (row.user_id !== user.id && user.role !== "admin")) {
        sendJson(response, 404, { error: "This shared result does not exist or has expired." });
        return;
      }
      database.prepare("DELETE FROM shared_results WHERE id = ?").run(id);
      recordAdminLog("audit", request, "Shared result deleted", `${row.mode}: ${row.title}`, 200, user.username);
      sendJson(response, 200, { deleted: true });
      return;
    }
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!user) {
    sendJson(response, 401, { error: "Log in to share results.", loginRequired: true });
    return;
  }
  pruneSharedResults();
  if (request.method === "GET") {
    const rows = database.prepare("SELECT id, mode, title, created_at, expires_at FROM shared_results WHERE user_id = ? ORDER BY created_at DESC").all(user.id);
    sendJson(response, 200, { shares: rows.map(describeShare) });
    return;
  }
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  let body;
  try {
    body = await readJsonRequest(request, shareLimits.payloadBytes + 4096);
  } catch (error) {
    sendJson(response, error.statusCode || 400, { error: error.message });
    return;
  }
  const mode = typeof body.mode === "string" ? body.mode : "";
  const title = typeof body.title === "string" ? body.title.trim().replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 200) : "";
  if (!shareableModes.has(mode) || !title || !body.data || typeof body.data !== "object") {
    sendJson(response, 400, { error: "This result cannot be shared." });
    return;
  }
  const payload = JSON.stringify(body.data);
  if (Buffer.byteLength(payload) > shareLimits.payloadBytes) {
    sendJson(response, 413, { error: "This result is too large to share (limit 1 MB)." });
    return;
  }
  const count = database.prepare("SELECT COUNT(*) AS count FROM shared_results WHERE user_id = ?").get(user.id).count;
  if (count >= shareLimits.perUser) {
    sendJson(response, 429, { error: `You already have ${shareLimits.perUser} shared results. Delete some on the My account page first.` });
    return;
  }
  const now = Date.now();
  const row = {
    id: crypto.randomBytes(16).toString("base64url").slice(0, 22),
    user_id: user.id,
    mode,
    title,
    payload,
    created_at: now,
    expires_at: now + shareLimits.lifetimeMs,
  };
  database.prepare(`
    INSERT INTO shared_results (id, user_id, mode, title, payload, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(row.id, row.user_id, row.mode, row.title, row.payload, row.created_at, row.expires_at);
  recordAdminLog("audit", request, "Result shared", `${mode}: ${title}`, 200, user.username);
  sendJson(response, 201, describeShare(row));
}

const historyLimits = { perUser: 100, lifetimeMs: 30 * 24 * 3600_000, payloadBytes: 512 * 1024 };
const historyParamKeys = ["type", "method", "port", "selectors", "ports", "targets", "bulkPort", "scanType", "ptr", "tlsGrade", "scanPorts", "scanEmail", "scanSsl", "scanTlsGrade", "scanWeb", "scanDnsHealth", "domains"];

function cleanHistoryParams(params) {
  const clean = {};
  if (!params || typeof params !== "object") return clean;
  for (const key of historyParamKeys) {
    const value = params[key];
    if (typeof value === "boolean") clean[key] = value;
    else if (typeof value === "string" && value.length <= 8192) clean[key] = value;
  }
  return clean;
}

function describeHistory(row, withData = false) {
  let params = {};
  try {
    params = JSON.parse(row.params);
  } catch {
    params = {};
  }
  const entry = {
    id: row.id,
    mode: row.mode,
    title: row.title,
    query: row.query,
    params,
    createdAt: new Date(row.created_at).toISOString(),
    hasResult: row.payload !== null && row.payload !== undefined,
  };
  if (withData && entry.hasResult) {
    try {
      entry.data = JSON.parse(row.payload);
    } catch {
      entry.hasResult = false;
    }
  }
  return entry;
}

async function handleHistory(request, url, response) {
  const user = currentUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Log in to use your lookup history.", loginRequired: true });
    return;
  }
  database.prepare("DELETE FROM lookup_history WHERE created_at <= ?").run(Date.now() - historyLimits.lifetimeMs);
  const idText = url.pathname.slice("/api/history/".length);
  if (url.pathname.startsWith("/api/history/")) {
    if (!/^\d{1,15}$/.test(idText)) {
      sendJson(response, 404, { error: "This history entry was not found." });
      return;
    }
    const row = database.prepare("SELECT * FROM lookup_history WHERE id = ? AND user_id = ?").get(Number(idText), user.id);
    if (!row) {
      sendJson(response, 404, { error: "This history entry was not found." });
      return;
    }
    if (request.method === "GET") {
      sendJson(response, 200, describeHistory(row, true));
    } else if (request.method === "DELETE") {
      database.prepare("DELETE FROM lookup_history WHERE id = ?").run(row.id);
      sendJson(response, 200, { deleted: true });
    } else if (request.method === "PUT") {
      // Later updates add results that finish after the main one (TLS grade, blocklists).
      const body = await readJsonRequest(request, historyLimits.payloadBytes + 4096);
      const payload = JSON.stringify(body.data ?? null);
      if (!body.data || typeof body.data !== "object" || Buffer.byteLength(payload) > historyLimits.payloadBytes) {
        sendJson(response, 400, { error: "The result is missing or too large to store." });
        return;
      }
      database.prepare("UPDATE lookup_history SET payload = ? WHERE id = ?").run(payload, row.id);
      sendJson(response, 200, { updated: true });
    } else {
      sendJson(response, 405, { error: "Method not allowed." });
    }
    return;
  }
  if (request.method === "GET") {
    const rows = database.prepare(`
      SELECT id, mode, title, query, params, created_at, payload IS NOT NULL AS has_payload
      FROM lookup_history WHERE user_id = ? ORDER BY id DESC LIMIT ?
    `).all(user.id, historyLimits.perUser);
    sendJson(response, 200, { entries: rows.map((row) => describeHistory({ ...row, payload: row.has_payload ? "" : null })) });
    return;
  }
  if (request.method === "DELETE") {
    const result = database.prepare("DELETE FROM lookup_history WHERE user_id = ?").run(user.id);
    sendJson(response, 200, { deleted: Number(result.changes) });
    return;
  }
  if (request.method !== "POST") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  const access = getFeatureAccess().history;
  if (access === "admin" && user.role !== "admin") {
    sendJson(response, 403, { error: "Lookup history is restricted to administrators." });
    return;
  }
  const body = await readJsonRequest(request, historyLimits.payloadBytes + 16384);
  const mode = typeof body.mode === "string" ? body.mode : "";
  const clip = (value, length) => typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, length) : "";
  const title = clip(body.title, 200);
  const query = clip(body.query, 2048);
  if (!shareableModes.has(mode) || !title) {
    sendJson(response, 400, { error: "This result cannot be stored in history." });
    return;
  }
  let payload = body.data && typeof body.data === "object" ? JSON.stringify(body.data) : null;
  if (payload && Buffer.byteLength(payload) > historyLimits.payloadBytes) payload = null;
  const insert = database.prepare(`
    INSERT INTO lookup_history (user_id, mode, title, query, params, payload, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(user.id, mode, title, query, JSON.stringify(cleanHistoryParams(body.params)), payload, Date.now());
  database.prepare(`
    DELETE FROM lookup_history WHERE user_id = ? AND id NOT IN (
      SELECT id FROM lookup_history WHERE user_id = ? ORDER BY id DESC LIMIT ?
    )
  `).run(user.id, user.id, historyLimits.perUser);
  sendJson(response, 201, { id: Number(insert.lastInsertRowid), stored: payload !== null });
}

function handleAdminSystem(request, response) {
  if (!requireAdmin(request, response)) return;
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  const memory = memoryInfo();
  const processMemory = process.memoryUsage();
  let disk = null;
  try {
    const stats = fs.statfsSync(dataDir);
    const total = stats.blocks * stats.bsize;
    const free = stats.bavail * stats.bsize;
    disk = { total, used: total - free, free };
  } catch {
    disk = null;
  }
  const fileSize = (file) => {
    try {
      return fs.statSync(file).size;
    } catch {
      return 0;
    }
  };
  const databasePath = path.join(dataDir, "bnglookup.sqlite");
  const since = (hours) => new Date(Date.now() - hours * 3600_000).toISOString().slice(0, 19).replace("T", " ");
  const day = database.prepare(`
    SELECT COUNT(*) AS queries, COUNT(DISTINCT client_ip) AS visitors,
      SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS failures
    FROM admin_logs WHERE category = 'query' AND created_at >= ?
  `).get(since(24));
  const hour = database.prepare(
    "SELECT COUNT(*) AS queries FROM admin_logs WHERE category = 'query' AND created_at >= ?",
  ).get(since(1));
  const loginFailures = database.prepare(
    "SELECT COUNT(*) AS count FROM admin_logs WHERE category = 'login' AND status_code >= 400 AND created_at >= ?",
  ).get(since(24));
  const counts = {
    users: database.prepare("SELECT COUNT(*) AS count FROM users").get().count,
    sessions: database.prepare("SELECT COUNT(*) AS count FROM user_sessions").get().count,
    logs: database.prepare("SELECT COUNT(*) AS count FROM admin_logs").get().count,
  };
  const topActions = database.prepare(`
    SELECT action, COUNT(*) AS count FROM admin_logs
    WHERE category = 'query' AND created_at >= ?
    GROUP BY action ORDER BY count DESC LIMIT 5
  `).all(since(24));
  const latest = database.prepare(`
    SELECT id, created_at AS timestamp, username, client_ip AS clientIp, action, details,
      status_code AS statusCode
    FROM admin_logs WHERE category = 'query' ORDER BY id DESC LIMIT 15
  `).all();
  sendJson(response, 200, {
    time: new Date().toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    systemUptimeSeconds: Math.round(os.uptime()),
    node: process.version,
    platform: `${os.type()} ${os.arch()}`,
    cpu: { cores: os.cpus().length, system: cpuUsage.system, process: cpuUsage.process },
    load: os.loadavg().map((value) => Math.round(value * 100) / 100),
    memory: {
      ...memory,
      process: { rss: processMemory.rss, heapUsed: processMemory.heapUsed, heapTotal: processMemory.heapTotal },
    },
    disk,
    database: { size: fileSize(databasePath) + fileSize(`${databasePath}-wal`) },
    stats: {
      queries24h: day.queries,
      visitors24h: day.visitors,
      failures24h: day.failures || 0,
      queriesLastHour: hour.queries,
      loginFailures24h: loginFailures.count,
      heavyJobs: { ...heavyJobsActive },
      ...counts,
    },
    topActions,
    latest,
  });
}

function handleAdminInsights(request, url, response) {
  if (!requireAdmin(request, response)) return;
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  const rawDays = url.searchParams.get("days") || "30";
  if (!["7", "30", "90"].includes(rawDays)) {
    sendJson(response, 400, { error: "Choose a range of 7, 30, or 90 days." });
    return;
  }
  const since = Date.now() - Number(rawDays) * 86400000;
  database.prepare("DELETE FROM domain_ratings WHERE checked_at < ?").run(Date.now() - ratingRetentionMs);
  const describe = (row) => ({ domain: row.domain, grade: row.grade, score: row.score, detail: row.detail, checkedAt: new Date(row.checked_at).toISOString() });
  const ratings = {};
  for (const kind of ["web", "tls", "email", "dns"]) {
    const summary = database.prepare("SELECT COUNT(*) AS count, AVG(score) AS average FROM domain_ratings WHERE kind = ? AND checked_at >= ?").get(kind, since);
    ratings[kind] = {
      label: ratingKinds[kind],
      count: summary.count,
      average: summary.average === null ? null : Math.round(summary.average),
      grades: Object.fromEntries(database.prepare("SELECT grade, COUNT(*) AS count FROM domain_ratings WHERE kind = ? AND checked_at >= ? GROUP BY grade").all(kind, since).map((row) => [row.grade, row.count])),
      best: database.prepare("SELECT * FROM domain_ratings WHERE kind = ? AND checked_at >= ? ORDER BY score DESC, checked_at DESC LIMIT 5").all(kind, since).map(describe),
      worst: database.prepare("SELECT * FROM domain_ratings WHERE kind = ? AND checked_at >= ? ORDER BY score ASC, checked_at DESC LIMIT 5").all(kind, since).map(describe),
    };
  }
  const takeoverRisks = database.prepare("SELECT * FROM domain_ratings WHERE kind = 'takeover' AND checked_at >= ? ORDER BY score ASC, checked_at DESC LIMIT 10").all(since).map(describe);
  const cutoff = new Date(since).toISOString().replace("T", " ").slice(0, 19);
  const usageActions = ["Web check", "Email check", "Email header analysis", "DMARC report sources", "Record builder import", "Bulk domain check", "Magic scan", "TLS test and grade", "DNS health check", "Reputation check", "Lookalike domains", "SPF flattener"];
  const usageRows = database.prepare(`
    SELECT action, COUNT(*) AS count FROM admin_logs
    WHERE category = 'query' AND created_at >= ? AND action IN (${usageActions.map(() => "?").join(", ")})
    GROUP BY action
  `).all(cutoff, ...usageActions);
  const usage = usageActions.map((action) => ({ action, count: usageRows.find((row) => row.action === action)?.count || 0 }))
    .sort((left, right) => right.count - left.count);
  const monitorRows = database.prepare("SELECT kind, enabled, last_status AS status FROM monitors").all();
  const countBy = (rows, key) => rows.reduce((counts, row) => ({ ...counts, [row[key] || "pending"]: (counts[row[key] || "pending"] || 0) + 1 }), {});
  const eventCounts = Object.fromEntries(database.prepare("SELECT level, COUNT(*) AS count FROM monitor_events WHERE created_at >= ? GROUP BY level").all(since).map((row) => [row.level, row.count]));
  const failing = database.prepare(`
    SELECT monitors.kind, monitors.target, monitors.last_status AS status, monitors.last_summary AS summary, monitors.last_change_at AS changedAt, users.username
    FROM monitors JOIN users ON users.id = monitors.user_id
    WHERE monitors.enabled = 1 AND monitors.last_status IN ('fail', 'warn')
    ORDER BY CASE monitors.last_status WHEN 'fail' THEN 0 ELSE 1 END, monitors.last_change_at DESC LIMIT 10
  `).all().map((row) => ({ ...row, kindLabel: monitorKinds[row.kind] || row.kind, changedAt: row.changedAt ? new Date(row.changedAt).toISOString() : null }));
  sendJson(response, 200, {
    days: Number(rawDays),
    ratings,
    takeoverRisks,
    usage,
    monitors: {
      total: monitorRows.length,
      enabled: monitorRows.filter((row) => row.enabled).length,
      byStatus: countBy(monitorRows.filter((row) => row.enabled), "status"),
      byKind: Object.fromEntries(Object.entries(countBy(monitorRows, "kind")).map(([kind, count]) => [monitorKinds[kind] || kind, count])),
      alerts: eventCounts.alert || 0,
      changes: eventCounts.change || 0,
      failing,
    },
  });
}

function handleAdminStats(request, url, response) {
  if (!requireAdmin(request, response)) return;
  if (request.method !== "GET") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  const rawDays = url.searchParams.get("days") || "30";
  if (!["7", "30", "90"].includes(rawDays)) {
    sendJson(response, 400, { error: "Choose a stats range of 7, 30, or 90 days." });
    return;
  }
  const days = Number(rawDays);
  const startDate = new Date();
  startDate.setUTCHours(0, 0, 0, 0);
  startDate.setUTCDate(startDate.getUTCDate() - days + 1);
  const cutoff = startDate.toISOString().slice(0, 10);
  const entries = database.prepare(`
    SELECT substr(created_at, 1, 10) AS date, username, client_ip AS clientIp,
      action, details, status_code AS statusCode
    FROM admin_logs
    WHERE category = 'query' AND created_at >= ?
    ORDER BY id DESC
  `).all(cutoff);
  const timelineMap = new Map();
  for (let offset = 0; offset < days; offset += 1) {
    const date = new Date(startDate);
    date.setUTCDate(startDate.getUTCDate() + offset);
    timelineMap.set(date.toISOString().slice(0, 10), {
      date: date.toISOString().slice(0, 10),
      visitors: new Set(),
      queries: 0,
    });
  }
  const queryTypes = new Map();
  const queryTargets = new Map();
  const visitors = new Set();
  const authenticatedVisitors = new Set();
  let failedQueries = 0;
  for (const entry of entries) {
    const timeline = timelineMap.get(entry.date);
    if (timeline) {
      timeline.queries += 1;
      if (entry.clientIp) timeline.visitors.add(entry.clientIp);
    }
    if (entry.clientIp) visitors.add(entry.clientIp);
    if (entry.username) authenticatedVisitors.add(entry.username);
    if (entry.statusCode >= 400) failedQueries += 1;

    let details = {};
    try {
      details = JSON.parse(entry.details);
    } catch {
      // Older or malformed log details do not prevent aggregate statistics.
    }
    const type = entry.action === "DNS lookup"
      ? details.reverse === "true" ? "PTR" : String(details.type || "DNS").toUpperCase()
      : entry.action;
    queryTypes.set(type, (queryTypes.get(type) || 0) + 1);
    const target = typeof details.name === "string"
      ? details.name
      : typeof details.target === "string"
        ? details.target
        : null;
    if (target) queryTargets.set(target, (queryTargets.get(target) || 0) + 1);
  }

  sendJson(response, 200, {
    days,
    startDate: cutoff,
    endDate: new Date().toISOString().slice(0, 10),
    totals: {
      queries: entries.length,
      visitors: visitors.size,
      signedInUsers: authenticatedVisitors.size,
      failedQueries,
    },
    timeline: [...timelineMap.values()].map((day) => ({
      date: day.date,
      visitors: day.visitors.size,
      queries: day.queries,
    })),
    queryTypes: [...queryTypes.entries()]
      .map(([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label)),
    topQueries: [...queryTargets.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((left, right) => right.count - left.count || left.name.localeCompare(right.name))
      .slice(0, 10),
  });
}

function checkFeatureAccess(request, response, feature, requireLogin = false) {
  if (appSetupRequired()) {
    sendJson(response, 503, { error: "Complete initial administrator setup before using the app.", setupRequired: true });
    return false;
  }
  const access = getFeatureAccess()[feature] || "admin";
  const user = currentUser(request);
  if (access === "public" && (!requireLogin || user)) {
    const expectedMethod = ["/api/custom-port-scan", "/api/bulk-port-scan", "/api/ping-scan", "/api/multi-traceroute", "/api/nmap-scan", "/api/email-headers", "/api/dmarc-sources", "/api/bulk-domain-check"]
      .includes(new URL(request.url, "http://localhost").pathname)
      ? "POST"
      : "GET";
    if (!user && request.method === expectedMethod && !landingTokenAllows(request, feature) &&
      !consumePublicLookup(request, response)) return false;
    return true;
  }
  if (!user) {
    sendJson(response, 401, { error: "Log in to use this feature.", loginRequired: true });
    return false;
  }
  if (access === "admin" && user.role !== "admin") {
    sendJson(response, 403, { error: "This feature is restricted to administrators." });
    return false;
  }
  return true;
}

let lastPublicQuotaCleanupDate = "";
function consumePublicLookup(request, response) {
  const now = new Date();
  const utcDate = now.toISOString().slice(0, 10);
  if (lastPublicQuotaCleanupDate !== utcDate) {
    database.prepare("DELETE FROM public_lookup_usage WHERE utc_date < ?").run(utcDate);
    lastPublicQuotaCleanupDate = utcDate;
  }
  const clientAddress = getClientAddress(request) || "unknown";
  const access = getPublicAccess();
  const publicLookupDailyLimit = access.dailyLimit;
  if (addressInRanges(access.blocked.ranges, clientAddress)) {
    sendJson(response, 403, { error: "Public lookups from your network are blocked by the administrator. Log in to continue." });
    return false;
  }
  if (addressInRanges(access.unlimited.ranges, clientAddress)) return true;
  const clientHash = crypto
    .createHmac("sha256", publicLookupHashKey)
    .update(clientAddress)
    .digest("hex");
  const result = database.prepare(`
    INSERT INTO public_lookup_usage (client_hash, utc_date, lookup_count)
    VALUES (?, ?, 1)
    ON CONFLICT(client_hash, utc_date) DO UPDATE
      SET lookup_count = lookup_count + 1
      WHERE lookup_count < ?
    RETURNING lookup_count
  `).get(clientHash, utcDate, publicLookupDailyLimit);
  const resetAt = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
  );
  const remaining = result ? publicLookupDailyLimit - result.lookup_count : 0;
  response.setHeader("x-ratelimit-limit", String(publicLookupDailyLimit));
  response.setHeader("x-ratelimit-remaining", String(remaining));
  response.setHeader("x-ratelimit-reset", String(Math.floor(resetAt / 1000)));
  if (result) return true;

  response.setHeader("retry-after", String(Math.ceil((resetAt - now.getTime()) / 1000)));
  sendJson(response, 429, {
    error: `Daily public lookup limit reached (${publicLookupDailyLimit} lookups per IP). Try again after 00:00 UTC.`,
    limit: publicLookupDailyLimit,
    remaining: 0,
    resetAt: new Date(resetAt).toISOString(),
  });
  return false;
}

const pingMethods = new Set(["icmp", "https", "http"]);
const pingSampleHistory = new Map();
const pingSampleIntervalMs = 3000;
const pingSampleWindowMs = 5 * 60 * 1000;
const pingSampleLimit = 100;
const pingSampleConcurrencyLimit = 4;
let pingSamplesActive = 0;

function allowPingSample(user, target, address) {
  const now = Date.now();
  const key = user.id;
  const previous = pingSampleHistory.get(key);
  const history = (previous?.timestamps || []).filter(
    (timestamp) => now - timestamp < pingSampleWindowMs,
  );
  if (history.length && (previous.target !== target || previous.address !== address)) {
    pingSampleHistory.set(key, { ...previous, timestamps: history });
    return "target";
  }
  if (history.length && now - history.at(-1) < pingSampleIntervalMs - 200) {
    pingSampleHistory.set(key, { target, address, timestamps: history });
    return "interval";
  }
  if (history.length >= pingSampleLimit) {
    pingSampleHistory.set(key, { target, address, timestamps: history });
    return "limit";
  }
  history.push(now);
  pingSampleHistory.set(key, { target, address, timestamps: history });
  if (pingSampleHistory.size > 10000) {
    for (const [id, samples] of pingSampleHistory) {
      if (!samples.timestamps.length || now - samples.timestamps.at(-1) >= pingSampleWindowMs) {
        pingSampleHistory.delete(id);
      }
    }
  }
  return null;
}

function runIcmpPing(address, packetCount = 4) {
  const command = isIP(address) === 6 ? "ping6" : "ping";
  return new Promise((resolve) => {
    execFile(command, ["-c", String(packetCount), "-W", "1", address], {
      timeout: packetCount === 1 ? 2500 : 8000,
      maxBuffer: 65536,
    }, (error, stdout) => {
      const output = String(stdout || "");
      const sent = output.match(/(\d+) packets transmitted/);
      const received = output.match(/(\d+) (?:packets )?received/);
      const summary = output.match(/min\/avg\/max(?:\/mdev)? = ([\d.]+)\/([\d.]+)\/([\d.]+)/);
      const times = [...output.matchAll(/time=([\d.]+) ms/g)].map((match) => Number(match[1]));
      if (!sent && error) {
        resolve({
          up: false,
          error: error.code === "ENOENT"
            ? "ICMP ping is not available on this server."
            : "ICMP ping could not be run. The host may block ICMP or the server may lack permission.",
        });
        return;
      }
      const transmitted = Number(sent?.[1] || 0);
      const replies = Number(received?.[1] || 0);
      resolve({
        up: replies > 0,
        transmitted,
        received: replies,
        lossPercent: transmitted ? Math.round(((transmitted - replies) / transmitted) * 100) : 100,
        times,
        minMs: summary ? Number(summary[1]) : null,
        avgMs: summary ? Number(summary[2]) : null,
        maxMs: summary ? Number(summary[3]) : null,
      });
    });
  });
}

function runHttpCheck(hostname, address, scheme) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const transport = scheme === "https" ? https : http;
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ scheme, ...result });
    };
    const request = transport.request({
      host: hostname,
      method: "GET",
      path: "/",
      timeout: 8000,
      headers: { "user-agent": "BNGlookup-host-check/1.0", accept: "*/*", connection: "close" },
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address, family: isIP(address) }]);
        else callback(null, address, isIP(address));
      },
      rejectUnauthorized: false,
      servername: isIP(hostname) ? undefined : hostname,
    }, (reply) => {
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
      const status = reply.statusCode;
      finish({
        up: true,
        status,
        statusText: reply.statusMessage || "",
        responseMs: Math.round(elapsedMs * 10) / 10,
        redirect: status >= 300 && status < 400 && typeof reply.headers.location === "string"
          ? reply.headers.location.slice(0, 500)
          : null,
        server: typeof reply.headers.server === "string" ? reply.headers.server.slice(0, 200) : null,
        tlsAuthorized: scheme === "https" ? Boolean(reply.socket?.authorized) : null,
      });
      reply.destroy();
    });
    request.on("timeout", () => {
      finish({ up: false, error: "The request timed out." });
      request.destroy();
    });
    request.on("error", (error) => {
      finish({ up: false, error: error.code ? `Connection failed (${error.code}).` : "Connection failed." });
    });
    request.end();
  });
}

async function pingHost(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  const method = (url.searchParams.get("method") || "icmp").toLowerCase();
  if (!pingMethods.has(method)) {
    sendJson(response, 400, { error: "Choose ICMP, HTTPS, or HTTP." });
    return;
  }
  const sample = url.searchParams.get("sample") === "1";
  const user = currentUser(request);
  if (sample && !user) {
    sendJson(response, 401, { error: "Log in to monitor a host.", loginRequired: true });
    return;
  }
  let target = rawName.trim();
  const bracketed = target.match(/^\[([0-9a-f:.]+)\]$/i);
  if (bracketed) target = bracketed[1];
  try {
    const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
    let addresses;
    if (isIP(target)) {
      addresses = [target];
    } else {
      const domain = normalizeDomain(target);
      if (!domain) {
        sendJson(response, 400, { error: "Enter a valid domain name or IP address." });
        return;
      }
      target = domain;
      try {
        addresses = (await resolveHost(domain, { all: true, verbatim: true })).map((entry) => entry.address);
      } catch {
        sendJson(response, 200, { target, method, up: false, error: "The host name could not be resolved." });
        return;
      }
    }
    const eligible = addresses.filter((address) => isScannableAddress(address, allowLocal));
    eligible.sort((left, right) => isIP(left) - isIP(right));
    if (!eligible.length) {
      sendJson(response, 400, { error: "This target resolves to a private or reserved address that cannot be checked." });
      return;
    }
    if (sample && pingSamplesActive >= pingSampleConcurrencyLimit) {
      sendJson(response, 503, { error: "Live monitoring is busy. Try again shortly." });
      return;
    }
    const address = eligible[0];
    if (sample) {
      const sampleError = allowPingSample(user, target, address);
      if (sampleError === "target") {
        sendJson(response, 409, { error: "A monitoring window can only sample the same target and resolved address." });
        return;
      }
      if (sampleError) {
        sendJson(response, 429, {
          error: "Host monitoring is limited to one sample every 3 seconds and 100 samples per 5 minutes.",
        });
        return;
      }
    }
    if (sample) pingSamplesActive += 1;
    try {
      const started = process.hrtime.bigint();
      const result = method === "icmp"
        ? await runIcmpPing(address, sample ? 1 : 4)
        : await runHttpCheck(target, address, method);
      if (sample && method !== "icmp" && result.responseMs === undefined) {
        result.responseMs = Number(process.hrtime.bigint() - started) / 1e6;
      }
      sendJson(response, 200, { target, address, method, ...result });
    } finally {
      if (sample) pingSamplesActive = Math.max(0, pingSamplesActive - 1);
    }
  } catch (error) {
    console.error("Ping failed:", error);
    sendJson(response, 500, { error: "Unable to complete the host check." });
  }
}

function describeTlsCertificate(certificate) {
  const describeName = (name) => Object.entries(name || {})
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(", ") : value}`)
    .join(", ");
  return {
    subject: describeName(certificate.subject),
    issuer: describeName(certificate.issuer),
    subjectAltName: certificate.subjectaltname || "",
    validFrom: certificate.valid_from || "",
    validTo: certificate.valid_to || "",
    serialNumber: certificate.serialNumber || "",
    fingerprint256: certificate.fingerprint256 || "",
  };
}

function runTlsHandshake(hostname, address, port) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const socket = tls.connect({
      host: hostname,
      port,
      servername: isIP(hostname) ? undefined : hostname,
      rejectUnauthorized: false,
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address, family: isIP(address) }]);
        else callback(null, address, isIP(address));
      },
    });
    socket.setTimeout(8000, () => finish({ handshake: false, error: "The TLS handshake timed out." }));
    socket.once("secureConnect", () => {
      const chain = [];
      const seen = new Set();
      let certificate = socket.getPeerCertificate(true);
      while (certificate?.raw && chain.length < 10) {
        const fingerprint = certificate.fingerprint256 || certificate.serialNumber;
        if (!fingerprint || seen.has(fingerprint)) break;
        seen.add(fingerprint);
        chain.push(describeTlsCertificate(certificate));
        const issuer = certificate.issuerCertificate;
        if (!issuer || issuer === certificate) break;
        certificate = issuer;
      }
      finish({
        handshake: true,
        authorized: socket.authorized,
        authorizationError: socket.authorized ? null : String(socket.authorizationError || "Certificate is not trusted."),
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        certificateChain: chain,
      });
    });
    socket.once("error", (error) => finish({
      handshake: false,
      error: error.code ? `TLS handshake failed (${error.code}).` : "TLS handshake failed.",
    }));
  });
}

async function sslScanHost(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  const rawPort = queryInput(url, "port", 5, response);
  if (rawPort === null) return;
  const port = rawPort ? Number(rawPort) : 443;
  if ((rawPort && !/^\d{1,5}$/.test(rawPort)) || !Number.isInteger(port) || port < 1 || port > 65535) {
    sendJson(response, 400, { error: "Enter a TCP port between 1 and 65535." });
    return;
  }
  let target = rawName.trim();
  const bracketed = target.match(/^\[([0-9a-f:.]+)\]$/i);
  if (bracketed) target = bracketed[1];
  try {
    const user = currentUser(request);
    const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
    let addresses;
    if (isIP(target)) {
      addresses = [target];
    } else {
      const domain = normalizeDomain(target);
      if (!domain) {
        sendJson(response, 400, { error: "Enter a valid domain name or IP address." });
        return;
      }
      target = domain;
      try {
        addresses = (await resolveHost(domain, { all: true, verbatim: true })).map((entry) => entry.address);
      } catch {
        sendJson(response, 200, { target, port, handshake: false, error: "The host name could not be resolved." });
        return;
      }
    }
    const eligible = addresses.filter((address) => isScannableAddress(address, allowLocal));
    eligible.sort((left, right) => isIP(left) - isIP(right));
    if (!eligible.length) {
      sendJson(response, 400, { error: "This target resolves to a private or reserved address that cannot be checked." });
      return;
    }
    if (!acquireHeavyJob("sslscan")) {
      sendJson(response, 503, { error: "The server is busy with other TLS checks. Try again shortly." });
      return;
    }
    try {
      const result = await runTlsHandshake(target, eligible[0], port);
      sendJson(response, 200, { target, address: eligible[0], port, ...result });
    } finally {
      releaseHeavyJob("sslscan");
    }
  } catch (error) {
    console.error("SSL/TLS check failed:", error);
    sendJson(response, 500, { error: "Unable to complete the SSL/TLS check." });
  }
}

const testsslPath = process.env.TESTSSL_PATH || "testssl.sh";
const tlsGradeJobs = new Map();
const tlsGradeJobLimits = { runtimeMs: 6 * 60 * 1000, retainMs: 30 * 60 * 1000 };
const tlsGradeStages = [
  [/^Testing protocols/, "Protocols"],
  [/^Testing cipher categories/, "Cipher categories"],
  [/^Testing server's cipher preferences/, "Cipher preferences"],
  [/^Testing robust forward secrecy/, "Forward secrecy"],
  [/^Testing server defaults/, "Certificate and server defaults"],
  [/^Testing HTTP header/, "HTTP headers"],
  [/^Testing vulnerabilities/, "Vulnerabilities"],
  [/^Running client simulations/, "Client simulations"],
  [/^Rating/, "Rating"],
];

function pruneTlsGradeJobs() {
  const now = Date.now();
  for (const [id, job] of tlsGradeJobs) {
    if (job.finishedAt && now - job.finishedAt > tlsGradeJobLimits.retainMs) tlsGradeJobs.delete(id);
  }
}

function summarizeTestsslFindings(findings) {
  const value = (id) => findings.find((finding) => finding.id === id)?.finding ?? null;
  const score = (id) => {
    const number = Number(value(id));
    return Number.isFinite(number) ? number : null;
  };
  return {
    grade: value("overall_grade"),
    scores: {
      protocol: score("protocol_support_score"),
      keyExchange: score("key_exchange_score"),
      cipher: score("cipher_strength_score"),
      final: score("final_score"),
    },
    capReasons: findings.filter((finding) => /^grade_cap_reason_\d+$/.test(finding.id)).map((finding) => finding.finding),
    warnings: findings.filter((finding) => /^grade_cap_warning_\d+$/.test(finding.id)).map((finding) => finding.finding),
    scanTime: score("scanTime"),
    findings: findings
      .filter((finding) => finding.id !== "engine_problem" && !/^(rating_|grade_cap_)/.test(finding.id))
      .map((finding) => ({
        id: String(finding.id),
        severity: String(finding.severity || "INFO"),
        finding: String(finding.finding ?? ""),
        ...(finding.cve ? { cve: String(finding.cve) } : {}),
      })),
  };
}

function runTestssl(job, hostname, address, port) {
  return new Promise((resolve) => {
    let directory;
    let child;
    let stdout = "";
    let timedOut = false;
    let finished = false;
    let timer;
    const finish = (result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (directory) fs.rm(directory, { recursive: true, force: true }, () => {});
      resolve(result);
    };
    try {
      directory = fs.mkdtempSync(path.join(os.tmpdir(), "testssl-"));
      const jsonFile = path.join(directory, "result.json");
      const args = [
        "--jsonfile", jsonFile,
        "--quiet",
        "--color", "0",
        "--warnings", "off",
        "--connect-timeout", "10",
        "--openssl-timeout", "10",
        "--ip", address,
        ...(isIP(address) === 6 ? ["-6"] : []),
        `${isIP(hostname) === 6 ? `[${hostname}]` : hostname}:${port}`,
      ];
      child = spawn(testsslPath, args, {
        stdio: ["ignore", "pipe", "ignore"],
        env: { ...process.env, TERM: "dumb", TMPDIR: directory },
      });
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 5000).unref();
      }, tlsGradeJobLimits.runtimeMs);
      child.stdout.on("data", (chunk) => {
        stdout = (stdout + chunk).slice(-4096);
        for (const line of stdout.split("\n")) {
          const stage = tlsGradeStages.find(([pattern]) => pattern.test(line.trim()));
          if (stage) job.stage = stage[1];
        }
      });
      child.on("error", (error) => finish({
        error: error.code === "ENOENT"
          ? "testssl.sh is not installed on this server."
          : "The TLS test could not be started.",
      }));
      child.on("close", (code) => {
        if (timedOut) {
          finish({ error: "The TLS test took longer than 6 minutes and was stopped." });
          return;
        }
        let findings;
        try {
          findings = JSON.parse(fs.readFileSync(jsonFile, "utf8"));
        } catch {
          finish({ error: code ? `The TLS test failed (exit code ${code}). The host may not speak TLS on this port.` : "The TLS test produced no results." });
          return;
        }
        if (!Array.isArray(findings)) {
          finish({ error: "The TLS test produced an invalid result." });
          return;
        }
        const scanProblem = findings.find((finding) => finding.id === "scanProblem")?.finding;
        if (scanProblem && !findings.some((finding) => finding.id === "overall_grade")) {
          finish({ error: `The TLS test could not complete: ${String(scanProblem).slice(0, 300)}` });
          return;
        }
        const offersProtocol = findings.some((finding) =>
          ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"].includes(finding.id) &&
          /offered/i.test(finding.finding) && !/not offered/i.test(finding.finding));
        if (!offersProtocol) {
          finish({ error: "No SSL or TLS protocol was offered on this port, so there is nothing to grade." });
          return;
        }
        finish({ result: summarizeTestsslFindings(findings) });
      });
    } catch (error) {
      console.error("TLS test failed to start:", error.message);
      finish({ error: "The TLS test could not be started." });
    }
  });
}

async function startTlsGrade(request, response) {
  try {
    const user = currentUser(request);
    if (!user) throw invalidScanRequest("Log in to run the TLS test.", 401);
    const body = await readJsonRequest(request);
    let target = typeof body.target === "string" ? body.target.trim() : "";
    const port = typeof body.port === "string" && /^\d{1,5}$/.test(body.port) ? Number(body.port) : body.port ?? 443;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw invalidScanRequest("Enter a TCP port between 1 and 65535.");
    if (!target || target.length > 253) throw invalidScanRequest("Enter a domain name or IP address.");
    const bracketed = target.match(/^\[([0-9a-f:.]+)\]$/i);
    if (bracketed) target = bracketed[1];
    request.logDetails = JSON.stringify({ target, port });
    pruneTlsGradeJobs();
    if ([...tlsGradeJobs.values()].some((job) => job.userId === user.id && !job.finishedAt)) {
      throw invalidScanRequest("You already have a TLS test running. Wait for it to finish.", 429);
    }
    let addresses;
    if (isIP(target)) {
      addresses = [target];
    } else {
      const domain = normalizeDomain(target);
      if (!domain) throw invalidScanRequest("Enter a valid domain name or IP address.");
      target = domain;
      try {
        addresses = (await resolveHost(domain, { all: true, verbatim: true })).map((entry) => entry.address);
      } catch {
        throw invalidScanRequest("The host name could not be resolved.");
      }
    }
    const allowLocal = getPortScanPolicy().localScanByRole[user.role];
    const eligible = addresses.filter((address) => isScannableAddress(address, allowLocal));
    eligible.sort((left, right) => isIP(left) - isIP(right));
    if (!eligible.length) {
      throw invalidScanRequest("This target resolves to a private or reserved address that cannot be checked.");
    }
    if (!acquireHeavyJob("tlsGrade")) {
      throw invalidScanRequest("The server is busy with other TLS tests. Try again shortly.", 503);
    }
    const id = crypto.randomBytes(16).toString("hex");
    const job = { id, userId: user.id, target, address: eligible[0], port, stage: "Starting", startedAt: Date.now(), finishedAt: null };
    tlsGradeJobs.set(id, job);
    runTestssl(job, target, eligible[0], port).then((outcome) => {
      Object.assign(job, outcome, { finishedAt: Date.now() });
      const grade = outcome?.result?.grade;
      if (grade && tlsGradeScores[grade] !== undefined) {
        recordDomainRating("tls", port === 443 ? target : `${target}:${port}`, grade, outcome.result.scores?.final ?? tlsGradeScores[grade],
          outcome.result.capReasons?.[0] || `Final score ${outcome.result.scores?.final ?? "?"}`);
      }
    }).finally(() => releaseHeavyJob("tlsGrade"));
    sendJson(response, 202, { id, target, address: eligible[0], port });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("TLS test failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to start the TLS test." : error.message,
    });
  }
}

function tlsGradeStatus(request, url, response) {
  const user = currentUser(request);
  const job = tlsGradeJobs.get(url.searchParams.get("id") || "");
  if (!user || !job || job.userId !== user.id) {
    sendJson(response, 404, { error: "This TLS test was not found or has expired." });
    return;
  }
  sendJson(response, 200, {
    id: job.id,
    target: job.target,
    address: job.address,
    port: job.port,
    status: !job.finishedAt ? "running" : job.error ? "error" : "done",
    stage: job.stage,
    elapsedMs: (job.finishedAt || Date.now()) - job.startedAt,
    ...(job.error ? { error: job.error } : {}),
    ...(job.result ? { result: job.result } : {}),
  });
}

function runSinglePing(address) {
  const command = isIP(address) === 6 ? "ping6" : "ping";
  return new Promise((resolve) => {
    execFile(command, ["-c", "1", "-W", "1", address], { timeout: 5000, maxBuffer: 16384 }, (error, stdout) => {
      const time = String(stdout || "").match(/time=([\d.]+) ms/);
      resolve({ address, up: Boolean(time), rttMs: time ? Number(time[1]) : null });
    });
  });
}

const heavyJobLimits = { traceroute: 8, pingScan: 2, nmap: 1, sslscan: 4, zmap: 1, tlsGrade: 2, dig: 8, emailCheck: 4, webCheck: 6, bulkDomains: 1, dnsHealth: 4, lookalike: 2, reputation: 6, mailServer: 3 };
const heavyJobsActive = Object.fromEntries(Object.keys(heavyJobLimits).map((kind) => [kind, 0]));
const nmapScanStatuses = new Map();
const nmapStatusCleanupTimers = new Map();

function updateNmapScanStatus(userId, updates) {
  const cleanupTimer = nmapStatusCleanupTimers.get(userId);
  if (cleanupTimer) {
    clearTimeout(cleanupTimer);
    nmapStatusCleanupTimers.delete(userId);
  }
  const status = {
    ...nmapScanStatuses.get(userId),
    ...updates,
    updatedAt: Date.now(),
  };
  nmapScanStatuses.set(userId, status);
  return status;
}

function scheduleNmapStatusCleanup(userId) {
  const status = nmapScanStatuses.get(userId);
  if (!status) return;
  const timer = setTimeout(() => {
    if (nmapScanStatuses.get(userId) === status) nmapScanStatuses.delete(userId);
    nmapStatusCleanupTimers.delete(userId);
  }, 60_000);
  timer.unref();
  nmapStatusCleanupTimers.set(userId, timer);
}

function handleNmapStatus(request, response) {
  const user = currentUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Log in to view Nmap scan status." });
    return;
  }
  sendJson(response, 200, nmapScanStatuses.get(user.id) || { state: "idle" });
}

function acquireHeavyJob(kind) {
  if (heavyJobsActive[kind] >= heavyJobLimits[kind]) return false;
  heavyJobsActive[kind] += 1;
  return true;
}

function releaseHeavyJob(kind) {
  heavyJobsActive[kind] = Math.max(0, heavyJobsActive[kind] - 1);
}

const nmapProfiles = {
  "tcp-top-20": {
    label: "TCP connect — top 20 ports",
    options: ["-sT", "--top-ports", "20"],
    timeoutMs: 45000,
  },
  "tcp-top-100": {
    label: "TCP connect — top 100 ports",
    options: ["-sT", "--top-ports", "100"],
    timeoutMs: 60000,
  },
  "tcp-top-1000": {
    label: "TCP connect — top 1000 ports",
    options: ["-sT", "--top-ports", "1000"],
    timingTemplate: 3,
    timeoutMs: 90000,
  },
  "service-top-20": {
    label: "Service detection — top 20 ports (light)",
    options: ["-sT", "-sV", "--version-light", "--top-ports", "20"],
    timeoutMs: 60000,
  },
};

function nmapAllowedAddress(address, allowlist) {
  const family = isIP(address);
  return family !== 0 &&
    allowlist.ranges.check(address, family === 4 ? "ipv4" : "ipv6");
}

function runNmap(address, profile) {
  const args = [
    ...profile.options,
    "-Pn",
    "-n",
    `-T${profile.timingTemplate || 2}`,
    "--max-retries",
    "1",
    "--host-timeout",
    `${Math.floor(profile.timeoutMs / 1000)}s`,
    "-oX",
    "-",
    address,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn("nmap", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let finished = false;
    let failure = null;
    const timer = setTimeout(() => {
      failure = new Error("The Nmap scan exceeded its time limit.");
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 1500).unref();
    }, profile.timeoutMs + 3000);
    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };
    child.stdout.on("data", (chunk) => {
      if (stdout.length + chunk.length > 256 * 1024) {
        failure = new Error("Nmap output exceeded the allowed size.");
        child.kill("SIGTERM");
        return;
      }
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 8192) stderr += chunk.toString().slice(0, 8192 - stderr.length);
    });
    child.on("error", (error) => {
      failure = invalidScanRequest(error.code === "ENOENT"
        ? "Nmap is unavailable on this server."
        : "Nmap could not be started.", 503);
    });
    child.on("close", (code) => {
      if (failure) {
        finish(failure);
        return;
      }
      if (code !== 0) {
        finish(new Error(stderr.trim().slice(0, 300) || `Nmap exited with code ${code}.`));
        return;
      }
      finish(null, stdout);
    });
  });
}

function nmapXmlAttribute(tag, name) {
  const match = tag.match(new RegExp(`(?:^|\\s)${name}="([^"]*)"`));
  return match ? match[1].replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&") : "";
}

function parseNmapXml(xml) {
  const hosts = [];
  for (const hostXml of xml.match(/<host\b[\s\S]*?<\/host>/g) || []) {
    const statusTag = hostXml.match(/<status\b[^>]*>/)?.[0] || "";
    const addressTag = hostXml.match(/<address\b[^>]*>/)?.[0] || "";
    const hostnames = [...hostXml.matchAll(/<hostname\b[^>]*>/g)]
      .map(([tag]) => nmapXmlAttribute(tag, "name"))
      .filter(Boolean);
    const ports = [];
    for (const portXml of hostXml.match(/<port\b[\s\S]*?<\/port>/g) || []) {
      const portTag = portXml.match(/<port\b[^>]*>/)?.[0] || "";
      const stateTag = portXml.match(/<state\b[^>]*>/)?.[0] || "";
      const serviceTag = portXml.match(/<service\b[^>]*>/)?.[0] || "";
      ports.push({
        port: nmapXmlAttribute(portTag, "portid"),
        protocol: nmapXmlAttribute(portTag, "protocol"),
        state: nmapXmlAttribute(stateTag, "state"),
        service: nmapXmlAttribute(serviceTag, "name"),
        product: nmapXmlAttribute(serviceTag, "product"),
        version: nmapXmlAttribute(serviceTag, "version"),
      });
    }
    hosts.push({
      address: nmapXmlAttribute(addressTag, "addr"),
      status: nmapXmlAttribute(statusTag, "state"),
      hostnames,
      ports,
    });
  }
  return hosts;
}

async function handleNmapScan(request, response) {
  try {
    if (!enforceSameOrigin(request, response)) return;
    const user = currentUser(request);
    if (!user) throw invalidScanRequest("Log in to run an Nmap scan.", 401);
    const body = await readJsonRequest(request);
    const rawTarget = typeof body.target === "string" ? body.target.trim() : "";
    const profile = nmapProfiles[body.scanType];
    if (!rawTarget || rawTarget.length > 253 || /[\\s,\\/\\\\]/.test(rawTarget)) {
      throw invalidScanRequest("Enter one IP address or hostname. CIDR ranges and target lists are not accepted.");
    }
    if (!profile) throw invalidScanRequest("Choose one of the available Nmap scan profiles.");
    const allowlist = getNmapAllowedCidrs();
    if (!allowlist.entries.length) {
      throw invalidScanRequest("No authorized Nmap CIDRs or automatic login IPs are available.", 403);
    }
    let target = rawTarget.replace(/^\\[|\\]$/g, "");
    let addresses;
    if (isIP(target)) {
      addresses = [target];
    } else {
      target = normalizeDomain(target);
      if (!target) throw invalidScanRequest("Enter a valid IP address or hostname.");
      try {
        addresses = (await resolveHost(target, { all: true, verbatim: true }))
          .map((entry) => entry.address);
      } catch {
        throw invalidScanRequest("The hostname could not be resolved.");
      }
    }
    const address = addresses.find((candidate) => nmapAllowedAddress(candidate, allowlist));
    if (!address) {
      throw invalidScanRequest("The target does not resolve to an address in the authorized Nmap allowlist.", 403);
    }
    if (!acquireHeavyJob("nmap")) {
      throw invalidScanRequest("An Nmap scan is already running. Try again shortly.", 503);
    }
    request.logDetails = JSON.stringify({ target, address, scanType: body.scanType });
    const startedAt = Date.now();
    updateNmapScanStatus(user.id, {
      state: "scanning",
      stage: "Nmap scan running",
      target,
      address,
      scanType: body.scanType,
      profile: profile.label,
      startedAt,
    });
    try {
      const xml = await runNmap(address, profile);
      updateNmapScanStatus(user.id, { stage: "Reading scan results" });
      const hosts = parseNmapXml(xml);
      const elapsedMs = Date.now() - startedAt;
      updateNmapScanStatus(user.id, {
        state: "completed",
        stage: "Complete",
        elapsedMs,
      });
      sendJson(response, 200, {
        target,
        address,
        scanType: body.scanType,
        profile: profile.label,
        elapsedMs,
        hosts,
      });
    } catch (error) {
      updateNmapScanStatus(user.id, {
        state: "failed",
        stage: "Failed",
        error: error.message || "Unable to complete the Nmap scan.",
        elapsedMs: Date.now() - startedAt,
      });
      throw error;
    } finally {
      releaseHeavyJob("nmap");
      scheduleNmapStatusCleanup(user.id);
    }
  } catch (error) {
    if (error.statusCode) {
      sendJson(response, error.statusCode, { error: error.message });
      return;
    }
    console.error("Nmap scan failed:", error);
    sendJson(response, 500, { error: error.message || "Unable to complete the Nmap scan." });
  }
}

async function runPingScan(request, response) {
  try {
    const user = currentUser(request);
    if (!user) throw invalidScanRequest("Log in to run a ping scan.", 401);
    const body = await readJsonRequest(request);
    const addresses = parseBulkScanTargets(typeof body.targets === "string" ? body.targets : "");
    const allowLocal = getPortScanPolicy().localScanByRole[user.role];
    const eligible = addresses.filter((address) => isScannableAddress(address, allowLocal));
    request.logDetails = JSON.stringify({ targets: addresses.slice(0, 256) });
    if (!acquireHeavyJob("pingScan")) throw invalidScanRequest("The server is busy with other ping scans. Try again shortly.", 503);
    const results = new Array(eligible.length);
    let next = 0;
    try {
      await Promise.all(Array.from({ length: Math.min(32, eligible.length) }, async () => {
        while (next < eligible.length) {
          const index = next;
          next += 1;
          results[index] = await runSinglePing(eligible[index]);
        }
      }));
    } finally {
      releaseHeavyJob("pingScan");
    }
    sendJson(response, 200, {
      scanned: eligible.length,
      skipped: addresses.length - eligible.length,
      up: results.filter((result) => result.up).length,
      results,
    });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("Ping scan failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to complete the ping scan." : error.message,
    });
  }
}

async function resolveCheckTarget(rawTarget, allowLocal) {
  let target = String(rawTarget || "").trim();
  const bracketed = target.match(/^\[([0-9a-f:.]+)\]$/i);
  if (bracketed) target = bracketed[1];
  let addresses;
  if (isIP(target)) {
    addresses = [target];
  } else {
    const domain = normalizeDomain(target);
    if (!domain) throw invalidScanRequest("Enter a valid domain name or IP address.");
    target = domain;
    try {
      addresses = (await resolveHost(domain, { all: true, verbatim: true })).map((entry) => entry.address);
    } catch {
      return { target, error: "The host name could not be resolved." };
    }
  }
  const eligible = addresses.filter((address) => isScannableAddress(address, allowLocal));
  eligible.sort((left, right) => isIP(left) - isIP(right));
  if (!eligible.length) {
    return { target, error: "This target resolves to a private or reserved address that cannot be traced." };
  }
  return { target, address: eligible[0] };
}

const maxTraceHops = 20;

function parseTracepath(output, destination, trim = true) {
  const hops = new Map();
  let reached = false;
  for (const line of String(output || "").split("\n")) {
    if (/^\s*Resume:/.test(line) && !/Too many hops/.test(output)) reached = true;
    const match = line.match(/^\s*(\d+)\??:\s+(.*)$/);
    if (!match) continue;
    const hop = Number(match[1]);
    if (hop < 1 || hop > maxTraceHops) continue;
    const rest = match[2].trim();
    if (rest.startsWith("[")) continue;
    if (/^no reply/i.test(rest)) {
      if (!hops.has(hop)) hops.set(hop, { hop, address: null, rttMs: null });
      continue;
    }
    const address = rest.split(/\s+/)[0];
    if (!isIP(address)) continue;
    const rtt = rest.match(/([\d.]+)ms/);
    const existing = hops.get(hop);
    if (!existing || !existing.address) {
      hops.set(hop, { hop, address, rttMs: rtt ? Number(rtt[1]) : null });
    }
    if (address === destination) reached = true;
  }
  const sorted = [...hops.values()].sort((left, right) => left.hop - right.hop);
  while (trim && sorted.length && !sorted.at(-1).address) sorted.pop();
  return { hops: sorted, reached };
}

function runTraceroute(address, { onUpdate, signal } = {}) {
  const args = ["-n", "-m", String(maxTraceHops), isIP(address) === 6 ? "-6" : "-4", address];
  if (!acquireHeavyJob("traceroute")) {
    return Promise.resolve({ error: "The server is busy with other traceroutes. Try again shortly." });
  }
  return new Promise((resolve) => {
    let output = "";
    let timedOut = false;
    let spawnFailed = false;
    let child;
    const start = (command, commandArgs) => {
      child = spawn(command, commandArgs, { stdio: ["ignore", "pipe", "ignore"] });
      child.stdout.on("data", (chunk) => {
        if (output.length < 65536) output += chunk;
        if (onUpdate) onUpdate(parseTracepath(output, address, false));
      });
      child.on("error", (error) => {
        if (error.code === "ENOENT" && command === "stdbuf") {
          start("tracepath", args);
          return;
        }
        spawnFailed = error.code === "ENOENT" ? "missing" : "failed";
        finish(null);
      });
      child.on("close", (code) => finish(code));
    };
    let finished = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child?.kill();
    }, 45000);
    const finish = (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      releaseHeavyJob("traceroute");
      if (spawnFailed === "missing") {
        resolve({ error: "Traceroute is not available on this server." });
        return;
      }
      const parsed = parseTracepath(output, address);
      if (!parsed.hops.length && (spawnFailed || code)) {
        resolve({ error: "The traceroute could not be run. The server may lack permission or network access." });
        return;
      }
      resolve({ ...parsed, partial: timedOut });
    };
    signal?.addEventListener("abort", () => child?.kill());
    start("stdbuf", ["-oL", "tracepath", ...args]);
  });
}

function startNdjson(request, response) {
  response.writeHead(200, {
    "content-type": "application/x-ndjson; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-accel-buffering": "no",
  });
  const controller = new AbortController();
  response.on("close", () => controller.abort());
  const send = (event) => {
    if (!response.writableEnded && !response.destroyed) response.write(`${JSON.stringify(event)}\n`);
  };
  return { send, signal: controller.signal };
}

async function lookupHopPtr(address) {
  try {
    const result = await fetchPtr(address);
    return { names: result.answers.map((name) => String(name).replace(/\.$/, "")) };
  } catch (error) {
    return { names: [], error: error.message || "Unable to retrieve PTR record." };
  }
}

async function addHopPtrNames(result) {
  if (!result.hops?.length) return result;
  const names = new Map();
  const addresses = [...new Set(result.hops.map((hop) => hop.address).filter(Boolean))];
  for (let offset = 0; offset < addresses.length; offset += 8) {
    await Promise.all(addresses.slice(offset, offset + 8).map(async (address) => {
      names.set(address, await lookupHopPtr(address));
    }));
  }
  return {
    ...result,
    hops: result.hops.map((hop) => {
      const lookup = hop.address && names.get(hop.address);
      return lookup ? { ...hop, ptr: lookup.names, ...(lookup.error ? { ptrError: lookup.error } : {}) } : hop;
    }),
  };
}

async function streamTrace(stream, index, targetInput, allowLocal, ptr = false) {
  try {
    const resolved = await resolveCheckTarget(targetInput, allowLocal);
    if (resolved.error) {
      stream.send({ type: "done", index, target: resolved.target, hops: [], reached: false, error: resolved.error });
      return;
    }
    stream.send({ type: "start", index, target: resolved.target, address: resolved.address });
    const ptrLookups = new Map();
    const queuePtrLookups = (hops) => {
      for (const hop of hops) {
        if (!hop.address || ptrLookups.has(hop.address) || ptrLookups.size >= maxTraceHops * 2) continue;
        ptrLookups.set(hop.address, lookupHopPtr(hop.address).then((lookup) => {
          stream.send({ type: "ptr", index, address: hop.address, ...lookup });
        }));
      }
    };
    const result = await runTraceroute(resolved.address, {
      signal: stream.signal,
      onUpdate: (update) => {
        stream.send({ type: "hops", index, hops: update.hops, reached: update.reached });
        if (ptr) queuePtrLookups(update.hops);
      },
    });
    if (ptr && result.hops) queuePtrLookups(result.hops);
    await Promise.all(ptrLookups.values());
    stream.send({ type: "done", index, target: resolved.target, address: resolved.address, hops: [], reached: false, ...result });
  } catch (error) {
    stream.send({ type: "done", index, target: String(targetInput).slice(0, 80), hops: [], reached: false, error: error.message });
  }
}

async function tracerouteHost(request, url, response) {
  const rawName = queryInput(url, "name", 253, response);
  if (rawName === null) return;
  try {
    const user = currentUser(request);
    const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
    const ptr = url.searchParams.get("ptr") === "1";
    if (url.searchParams.get("stream") === "1") {
      const stream = startNdjson(request, response);
      await streamTrace(stream, 0, rawName, allowLocal, ptr);
      response.end();
      return;
    }
    const resolved = await resolveCheckTarget(rawName, allowLocal);
    if (resolved.error) {
      sendJson(response, 200, { target: resolved.target, hops: [], reached: false, error: resolved.error });
      return;
    }
    let result = await runTraceroute(resolved.address);
    if (ptr) result = await addHopPtrNames(result);
    sendJson(response, 200, { target: resolved.target, address: resolved.address, hops: [], reached: false, ...result });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("Traceroute failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to complete the traceroute." : error.message,
    });
  }
}

async function runMultiTraceroute(request, response) {
  try {
    const user = currentUser(request);
    if (!user) throw invalidScanRequest("Log in to run a traceroute.", 401);
    const body = await readJsonRequest(request);
    const raw = typeof body.targets === "string" ? body.targets : "";
    if (raw.length > 4096) throw invalidScanRequest("Target list must not exceed 4,096 characters.");
    const targets = [...new Set(raw.split(/[\s,;]+/).filter(Boolean))];
    if (!targets.length) throw invalidScanRequest("Enter at least one domain name or IP address.");
    if (targets.length > 10) throw invalidScanRequest("Enter no more than 10 targets.");
    const allowLocal = getPortScanPolicy().localScanByRole[user.role];
    const ptr = body.ptr === true;
    request.logDetails = JSON.stringify({ targets, ptr });
    if (body.stream === true) {
      const stream = startNdjson(request, response);
      let nextStream = 0;
      await Promise.all(Array.from({ length: Math.min(4, targets.length) }, async () => {
        while (nextStream < targets.length) {
          const index = nextStream;
          nextStream += 1;
          await streamTrace(stream, index, targets[index], allowLocal, ptr);
        }
      }));
      response.end();
      return;
    }
    const results = new Array(targets.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(4, targets.length) }, async () => {
      while (next < targets.length) {
        const index = next;
        next += 1;
        try {
          const resolved = await resolveCheckTarget(targets[index], allowLocal);
          if (resolved.error) {
            results[index] = { target: resolved.target, hops: [], reached: false, error: resolved.error };
          } else {
            let result = await runTraceroute(resolved.address);
            if (ptr) result = await addHopPtrNames(result);
            results[index] = { target: resolved.target, address: resolved.address, hops: [], reached: false, ...result };
          }
        } catch (error) {
          results[index] = { target: targets[index].slice(0, 80), hops: [], reached: false, error: error.message };
        }
      }
    }));
    sendJson(response, 200, { results });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("Multi traceroute failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to complete the traceroute." : error.message,
    });
  }
}

const digBooleanOptions = new Set([
  "aaflag", "aaonly", "additional", "adflag", "all", "answer", "authority", "besteffort", "cdflag", "class",
  "cmd", "comments", "cookie", "crypto", "dnssec", "edns", "expire", "header-only", "identify", "idnin",
  "idnout", "ignore", "multiline", "nsid", "nssearch", "onesoa", "qr", "question", "raflag", "rdflag",
  "rec", "recurse", "rrcomments", "short", "showsearch", "stats", "tcflag", "tcp", "trace", "ttlid",
  "ttlunits", "unknownformat", "vc", "yaml", "zflag",
]);
const digValueOptions = {
  bufsize: /^\d{1,5}$/,
  edns: /^\d{1,3}$/,
  opcode: /^(?:\d{1,2}|query|iquery|status|notify|update)$/i,
  padding: /^\d{1,3}$/,
  qid: /^\d{1,5}$/,
  retry: /^[0-2]$/,
  split: /^\d{1,3}$/,
  subnet: /^[0-9a-f.:]{1,45}(?:\/\d{1,3})?$/i,
  time: /^(?:[1-9]|10)$/,
  tries: /^[1-3]$/,
};
const digRecordClasses = new Set(["IN", "CH", "HS", "ANY", "NONE"]);
const digRecordTypes = new Set([
  "A", "AAAA", "AFSDB", "ANY", "APL", "AXFR", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", "CSYNC", "DHCID",
  "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO", "HIP", "HTTPS", "IPSECKEY", "IXFR", "KEY",
  "KX", "LOC", "MX", "NAPTR", "NS", "NSEC", "NSEC3", "NSEC3PARAM", "NULL", "OPENPGPKEY", "PTR", "RP",
  "RRSIG", "SIG", "SMIMEA", "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", "TXT",
  "URI", "ZONEMD",
]);
const digOutputLimit = 256 * 1024;

function isDigRecordType(token) {
  const upper = token.toUpperCase();
  return digRecordTypes.has(upper) || /^TYPE\d{1,5}$/.test(upper) || /^IXFR=\d{1,10}$/.test(upper);
}

async function parseDigCommand(input, allowLocal) {
  const text = String(input || "").trim();
  if (!text) throw invalidScanRequest("Enter a dig command, for example: example.com MX +short");
  if (text.length > 512) throw invalidScanRequest("The dig command must not exceed 512 characters.");
  const tokens = text.split(/\s+/);
  if (tokens[0].toLowerCase() === "dig") tokens.shift();
  if (tokens.length > 24) throw invalidScanRequest("The dig command has too many arguments.");
  const args = [];
  let server = null;
  let name = null;
  let type = null;
  let recordClass = null;
  let reverse = false;
  const setName = (value) => {
    if (name !== null) throw invalidScanRequest("Only one query name is allowed per dig command.");
    const normalized = value === "." ? "." : value.replace(/\.$/, "");
    if (normalized !== "." && !validDnsName(normalized)) throw invalidScanRequest(`Invalid query name: ${value}`);
    name = value;
  };
  const setType = (value) => {
    if (type !== null) throw invalidScanRequest("Only one record type is allowed per dig command.");
    if (!isDigRecordType(value)) throw invalidScanRequest(`Unsupported record type: ${value}`);
    type = value.toUpperCase();
  };
  const setClass = (value) => {
    if (recordClass !== null) throw invalidScanRequest("Only one query class is allowed per dig command.");
    if (!digRecordClasses.has(value.toUpperCase())) throw invalidScanRequest(`Unsupported query class: ${value}`);
    recordClass = value.toUpperCase();
  };
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!/^[A-Za-z0-9.:_@+=\/\-\[\]*]+$/.test(token)) {
      throw invalidScanRequest(`Unsupported characters in argument: ${token.slice(0, 40)}`);
    }
    const next = () => {
      index += 1;
      if (index >= tokens.length) throw invalidScanRequest(`The ${token} option needs a value.`);
      return tokens[index];
    };
    if (token.startsWith("@")) {
      if (server) throw invalidScanRequest("Only one @server is allowed.");
      server = token.slice(1).replace(/^\[(.*)\]$/, "$1");
      if (!server) throw invalidScanRequest("Enter a nameserver after @.");
    } else if (token.startsWith("+")) {
      const match = token.slice(1).toLowerCase().match(/^(no)?([a-z-]+)(?:=(.*))?$/);
      if (!match) throw invalidScanRequest(`Unsupported dig option: ${token}`);
      const [, negated, option, value] = match;
      if (value === undefined && digBooleanOptions.has(option)) {
        args.push(`+${negated || ""}${option}`);
      } else if (value !== undefined && !negated && digValueOptions[option]?.test(value)) {
        args.push(`+${option}=${value}`);
      } else if (option in digValueOptions && value !== undefined) {
        throw invalidScanRequest(`Invalid value for +${option}: ${value}`);
      } else {
        throw invalidScanRequest(`Unsupported dig option: ${token}`);
      }
    } else if (token === "-4" || token === "-6" || token === "-u") {
      args.push(token);
    } else if (token === "-t") {
      setType(next());
    } else if (token === "-c") {
      setClass(next());
    } else if (token === "-q") {
      setName(next());
    } else if (token === "-x") {
      const address = next();
      if (!isIP(address)) throw invalidScanRequest("The -x option needs an IPv4 or IPv6 address.");
      if (name !== null) throw invalidScanRequest("Only one query name is allowed per dig command.");
      name = address;
      reverse = true;
    } else if (token === "-p") {
      const port = next();
      if (!/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
        throw invalidScanRequest("The -p option needs a port between 1 and 65535.");
      }
      args.push("-p", port);
    } else if (token.startsWith("-")) {
      throw invalidScanRequest(`Unsupported dig flag: ${token}. Allowed flags: -t, -c, -q, -x, -p, -4, -6, -u.`);
    } else if (name !== null && type === null && isDigRecordType(token)) {
      setType(token);
    } else if (name !== null && recordClass === null && digRecordClasses.has(token.toUpperCase())) {
      setClass(token);
    } else if (name === null && type === null && isDigRecordType(token) && !token.includes(".")) {
      setType(token);
    } else if (name !== null) {
      throw invalidScanRequest(`Unrecognized argument: ${token}. Expected a record type, class or option, and only one query name.`);
    } else {
      setName(token);
    }
  }
  if (name === null && type !== null && type !== "NS") name = ".";
  let serverAddress = null;
  if (server) {
    let addresses;
    if (isIP(server)) {
      addresses = [server];
    } else {
      const domain = normalizeDomain(server);
      if (!domain) throw invalidScanRequest(`Invalid nameserver: ${server}`);
      try {
        addresses = (await resolveHost(domain, { all: true, verbatim: true })).map((entry) => entry.address);
      } catch {
        throw invalidScanRequest(`The nameserver ${server} could not be resolved.`);
      }
    }
    serverAddress = addresses.find((address) => isScannableAddress(address, allowLocal));
    if (!serverAddress) {
      throw invalidScanRequest("This nameserver is a private or reserved address that your role may not query.");
    }
  }
  const queryArgs = [
    ...(serverAddress ? [`@${serverAddress}`] : []),
    ...(reverse ? ["-x", name] : name !== null ? ["-q", name] : []),
    ...(type ? ["-t", type] : []),
    ...(recordClass ? ["-c", recordClass] : []),
    ...args,
  ];
  const display = [
    "dig",
    ...(server ? [`@${server}`] : []),
    ...(reverse ? ["-x", name] : name !== null ? [name] : []),
    ...(type ? [type] : []),
    ...(recordClass ? [recordClass] : []),
    ...args,
  ].join(" ");
  return { args: queryArgs, display, server, serverAddress };
}

async function digCommand(request, url, response) {
  const rawCommand = queryInput(url, "command", 512, response);
  if (rawCommand === null) return;
  try {
    const user = currentUser(request);
    const allowLocal = Boolean(user) && getPortScanPolicy().localScanByRole[user.role];
    const parsed = await parseDigCommand(rawCommand, allowLocal);
    if (!acquireHeavyJob("dig")) throw invalidScanRequest("The server is busy with other dig commands. Try again shortly.", 503);
    const started = Date.now();
    let result;
    try {
      result = await new Promise((resolve) => {
        execFile("dig", ["-r", ...parsed.args], { timeout: 30000, maxBuffer: digOutputLimit, killSignal: "SIGKILL" }, (error, stdout, stderr) => {
          resolve({ error, stdout: String(stdout || ""), stderr: String(stderr || "") });
        });
      });
    } finally {
      releaseHeavyJob("dig");
    }
    if (result.error?.code === "ENOENT") {
      sendJson(response, 503, { error: "dig is not installed on this server." });
      return;
    }
    const truncated = result.error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER";
    const timedOut = Boolean(result.error?.killed) && !truncated;
    const output = `${result.stdout}${result.stderr ? `\n${result.stderr}` : ""}`.slice(0, digOutputLimit);
    const status = output.match(/status: ([A-Z]+)/)?.[1] || null;
    sendJson(response, 200, {
      command: parsed.display,
      serverAddress: parsed.serverAddress,
      output,
      status,
      exitCode: typeof result.error?.code === "number" ? result.error.code : result.error ? null : 0,
      durationMs: Date.now() - started,
      truncated,
      timedOut,
    });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (statusCode === 500) console.error("dig failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to run the dig command." : error.message,
    });
  }
}

// Prefixes that identify the kind of address rather than a hardware vendor.
const macSpecialPrefixes = [
  [/^FFFFFFFFFFFF$/, { category: "Broadcast address", examples: [], confidence: "high", basis: "Every bit set: sent to all devices on the network segment, not a device address." }],
  [/^01005E/, { category: "IPv4 multicast group", examples: [], confidence: "high", basis: "01:00:5E is reserved for IPv4 multicast traffic, not a single device." }],
  [/^3333/, { category: "IPv6 multicast group", examples: [], confidence: "high", basis: "33:33 is reserved for IPv6 multicast traffic, not a single device." }],
  [/^0180C2/, { category: "Network protocol group address", examples: ["Spanning Tree (STP)", "LLDP", "802.1X"], confidence: "high", basis: "01:80:C2 is an IEEE 802.1 group address used by switches." }],
  [/^01000C/, { category: "Cisco protocol group address", examples: ["CDP", "VTP", "PVST+"], confidence: "high", basis: "01:00:0C is used by Cisco discovery and spanning-tree protocols." }],
  [/^(?:005056|000C29|000569|001C14)/, { category: "Virtual machine", examples: ["VMware virtual machine"], confidence: "high", basis: "This prefix is assigned to VMware virtual network adapters." }],
  [/^080027/, { category: "Virtual machine", examples: ["VirtualBox virtual machine"], confidence: "high", basis: "08:00:27 is used by VirtualBox virtual network adapters." }],
  [/^00155D/, { category: "Virtual machine", examples: ["Hyper-V virtual machine", "WSL 2", "Windows Sandbox"], confidence: "high", basis: "00:15:5D is used by Microsoft Hyper-V virtual adapters." }],
  [/^525400/, { category: "Virtual machine", examples: ["QEMU/KVM virtual machine", "Proxmox VM", "libvirt guest"], confidence: "high", basis: "52:54:00 is the default prefix for QEMU/KVM virtual network cards." }],
  [/^00163E/, { category: "Virtual machine", examples: ["Xen virtual machine"], confidence: "high", basis: "00:16:3E is used by Xen virtual network interfaces." }],
  [/^001C42/, { category: "Virtual machine", examples: ["Parallels Desktop virtual machine"], confidence: "high", basis: "00:1C:42 is used by Parallels virtual adapters." }],
  [/^0242/, { category: "Container", examples: ["Docker container"], confidence: "high", basis: "02:42 is the prefix Docker gives container network interfaces." }],
];

// Vendor name patterns mapped to the kind of device they usually make. Only a guess:
// an OUI identifies the manufacturer, never the exact model.
const macVendorRules = [
  [/raspberry pi/i, "Single-board computer", ["Raspberry Pi"], "high"],
  [/espressif/i, "IoT / smart-home device (ESP8266 / ESP32 chip)", ["Smart plug", "Smart bulb", "Sensor", "DIY / ESPHome / Tasmota device"], "high"],
  [/arduino/i, "Microcontroller board", ["Arduino with Wi-Fi or Ethernet"], "high"],
  [/shelly|allterco/i, "Smart relay / smart-home device", ["Shelly relay or plug"], "high"],
  [/tuya/i, "Smart-home device", ["Smart plug", "Bulb", "Sensor (Tuya / Smart Life)"], "high"],
  [/sonos/i, "Wireless speaker", ["Sonos speaker or soundbar"], "high"],
  [/\bbose\b/i, "Audio device", ["Bose speaker or soundbar"], "high"],
  [/signify|philips lighting/i, "Smart lighting", ["Philips Hue Bridge", "WiZ / Hue light"], "high"],
  [/ubiquiti/i, "Network equipment", ["UniFi access point", "UniFi switch or gateway", "UniFi Protect camera"], "high"],
  [/mikrotik|routerboard/i, "Router / switch", ["MikroTik router or switch"], "high"],
  [/juniper/i, "Enterprise network equipment", ["Juniper router, switch or firewall"], "high"],
  [/fortinet|palo alto|sonicwall|watchguard|check point/i, "Firewall / security appliance", ["Firewall or VPN gateway"], "high"],
  [/aruba|ruckus|extreme networks|cambium|meraki/i, "Enterprise Wi-Fi / network equipment", ["Access point", "Switch"], "high"],
  [/cisco/i, "Network equipment or IP phone", ["Cisco switch or router", "Cisco IP phone", "Wi-Fi access point"], "medium"],
  [/tp-link|netgear|zyxel|d-link|linksys|asus.*router|avm\b|draytek|tenda|cudy/i, "Home / small-office network equipment", ["Wi-Fi router", "Mesh node", "Switch", "Range extender", "Smart plug (TP-Link Kasa / Tapo)"], "medium"],
  [/synology/i, "Network storage (NAS)", ["Synology NAS"], "high"],
  [/qnap/i, "Network storage (NAS)", ["QNAP NAS"], "high"],
  [/western digital/i, "Storage device", ["WD My Cloud NAS"], "medium"],
  [/nintendo/i, "Game console", ["Nintendo Switch", "Joy-Con controller"], "high"],
  [/sony interactive|sony computer entertainment/i, "Game console", ["PlayStation 5", "PlayStation 4"], "high"],
  [/valve/i, "Gaming device", ["Steam Deck", "Valve Index"], "high"],
  [/roku/i, "Streaming player / smart TV", ["Roku streaming stick", "Roku TV"], "high"],
  [/tesla/i, "Vehicle or energy product", ["Tesla car", "Powerwall", "Wall Connector"], "high"],
  [/\bring\b/i, "Video doorbell / security camera", ["Ring doorbell", "Ring camera"], "high"],
  [/nest labs/i, "Smart-home device", ["Nest thermostat", "Nest camera or doorbell", "Nest speaker"], "high"],
  [/ecobee/i, "Smart thermostat", ["ecobee thermostat"], "high"],
  [/hikvision|dahua|axis communications|reolink|ezviz|wyze|amcrest|hanwha|uniview|vivotek/i, "IP camera / video recorder", ["Security camera", "NVR"], "high"],
  [/polycom|yealink|grandstream|snom|avaya|mitel|fanvil/i, "VoIP phone / conferencing", ["Desk phone", "Conference phone"], "high"],
  [/brother|seiko epson|\bepson\b|lexmark|kyocera|xerox|ricoh|konica|sharp corp/i, "Printer / scanner", ["Network printer", "Multifunction printer"], "high"],
  [/canon/i, "Printer or camera", ["Canon printer", "Canon camera"], "medium"],
  [/zebra technologies|honeywell|datalogic/i, "Barcode scanner / label printer", ["Handheld scanner", "Label printer"], "medium"],
  [/fitbit|garmin/i, "Wearable / fitness device", ["Smartwatch", "Fitness tracker"], "medium"],
  [/super ?micro/i, "Server", ["Supermicro server or BMC"], "high"],
  [/dell|lenovo|asustek|acer|micro-star|gigabyte|framework computer|hewlett packard enterprise/i, "Computer", ["Laptop", "Desktop PC", "Server"], "medium"],
  [/hewlett packard|\bhp inc/i, "Computer or printer", ["HP printer", "HP laptop or desktop", "HP/Aruba network gear"], "low"],
  [/intel corporate|intel corp/i, "Computer (Intel network adapter)", ["Laptop or desktop Wi-Fi / Ethernet"], "medium"],
  [/microsoft/i, "Computer or game console", ["Surface", "Xbox", "PC network adapter"], "medium"],
  [/apple/i, "Apple device", ["iPhone", "iPad", "Mac", "Apple Watch", "Apple TV", "HomePod / AirPods"], "low", "Apple uses the same OUIs across its product lines, so the model cannot be told from the address. iPhone, iPad and Apple Watch use a private (randomized) Wi-Fi address by default, so a real Apple address on Wi-Fi more often points to a Mac, Apple TV or HomePod, or a device with Private Wi-Fi Address turned off."],
  [/samsung/i, "Samsung device", ["Galaxy phone or tablet", "Smart TV", "Appliance", "Galaxy Watch"], "low", "Samsung OUIs are shared between phones, TVs and appliances. Galaxy phones use a randomized address on Wi-Fi by default."],
  [/google/i, "Google device", ["Pixel phone", "Chromecast / Google TV", "Nest speaker or display"], "low", "Pixel phones use a randomized address on Wi-Fi by default, so a real Google address is more often a Chromecast or Nest device."],
  [/amazon/i, "Amazon device", ["Echo speaker", "Fire TV", "Kindle", "Ring / Blink camera"], "medium"],
  [/xiaomi|huawei|honor device|oneplus|oppo|vivo mobile|motorola|realme|nokia|fairphone|htc|lg electronics/i, "Phone, tablet or consumer electronics", ["Smartphone", "Tablet", "Smart TV or IoT device"], "low", "Android phones use a randomized address on Wi-Fi by default, so a real vendor address is more common on tablets, TVs and IoT devices."],
  [/realtek|qualcomm|atheros|mediatek|broadcom|marvell|azurewave|liteon|lite-on|hon hai|foxconn|murata|universal global|wistron|quanta|compal|pegatron|askey|gemtek|ampak|sercomm|arcadyan|sagemcom|technicolor/i, "Device with a third-party network chip", ["Laptop or PC adapter", "Router or set-top box", "IoT module"], "low", "This vendor makes network chips or builds devices for other brands, so the address says little about the finished product."],
];

function guessMacDevice({ hex, company, locallyAdministered, multicast, blockType }) {
  for (const [pattern, guess] of macSpecialPrefixes) {
    if (pattern.test(hex)) return { ...guess, notes: [] };
  }
  if (multicast) {
    return { category: "Multicast / group address", examples: [], confidence: "high", basis: "The group bit is set, so this addresses a group of devices rather than one.", notes: [] };
  }
  if (locallyAdministered) {
    return {
      category: "Private (randomized) address",
      examples: ["iPhone / iPad (Private Wi-Fi Address)", "Android phone (MAC randomization)", "Windows or macOS laptop (random hardware address)", "Virtual machine or container"],
      confidence: "medium",
      basis: "The locally administered bit is set, so the address was generated by software rather than burned in by a manufacturer.",
      notes: ["Phones and many laptops pick a random address per Wi-Fi network to prevent tracking, so neither vendor nor model can be determined from it."],
    };
  }
  if (!company) {
    return { category: "Unknown", examples: [], confidence: "none", basis: "No vendor is registered for this prefix.", notes: [] };
  }
  const rule = macVendorRules.find(([pattern]) => pattern.test(company));
  const notes = [];
  if (blockType && /MA-S|IAB|MA-M/i.test(blockType)) {
    notes.push(`This prefix is a small ${blockType} block, which companies usually buy for a single product line.`);
  }
  if (!rule) {
    return { category: "Unknown device type", examples: [], confidence: "none", basis: `No device-type pattern is known for ${company.replace(/\.+$/, "")}.`, notes };
  }
  const [, category, examples, confidence, caveat] = rule;
  if (caveat) notes.unshift(caveat);
  return { category, examples, confidence, basis: `Based on the registered vendor: ${company.replace(/\.+$/, "")}.`, notes };
}

async function macLookup(url, response) {
  const rawInput = queryInput(url, "name", 32, response);
  if (rawInput === null) return;
  const input = rawInput.trim();
  const validMac = /^(?:[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4})$/i;
  if (!validMac.test(input)) {
    sendJson(response, 400, {
      error: "Enter a valid MAC address in colon, hyphen, dotted, or plain hexadecimal format.",
    });
    return;
  }

  const hex = input.replace(/[^0-9a-f]/gi, "").toUpperCase();
  const firstOctet = Number.parseInt(hex.slice(0, 2), 16);
  const mac = hex.match(/.{2}/g).join(":");
  let result;
  try {
    result = await fetch(`https://api.maclookup.app/v2/macs/${hex}`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
  } catch (error) {
    const timedOut = error.name === "TimeoutError";
    sendJson(response, 502, {
      error: timedOut
        ? "MAC vendor lookup timed out. Please try again."
        : "Unable to reach the MAC vendor lookup service.",
    });
    return;
  }

  if (!result.ok) {
    sendJson(response, 502, { error: `MAC vendor service returned HTTP ${result.status}.` });
    return;
  }

  let data;
  try {
    data = await result.json();
  } catch {
    sendJson(response, 502, { error: "MAC vendor service returned invalid JSON." });
    return;
  }

  if (typeof data.success !== "boolean" || typeof data.found !== "boolean") {
    sendJson(response, 502, { error: "MAC vendor service returned an invalid response." });
    return;
  }

  const found = data.success && data.found;
  const deviceGuess = guessMacDevice({
    hex,
    company: found ? data.company || null : null,
    locallyAdministered: Boolean(firstOctet & 2),
    multicast: Boolean(firstOctet & 1),
    blockType: data.blockType || null,
  });
  sendJson(response, 200, {
    mac,
    oui: hex.slice(0, 6),
    multicast: Boolean(firstOctet & 1),
    locallyAdministered: Boolean(firstOctet & 2),
    found,
    company: data.company || null,
    country: data.country || null,
    address: data.address || null,
    blockType: data.blockType || null,
    deviceGuess,
  });
}

async function lookup(request, url, response) {
  const rawInput = queryInput(url, "name", 253, response);
  const rawType = queryInput(url, "type", 32, response);
  const rawNameserver = queryInput(url, "nameserver", 300, response);
  const rawReverse = queryInput(url, "reverse", 5, response);
  if ([rawInput, rawType, rawNameserver, rawReverse].includes(null)) return;
  if (rawNameserver.trim() && currentUser(request)?.role !== "admin") {
    sendJson(response, 403, { error: "Custom nameservers are available to administrators only." });
    return;
  }
  const input = rawInput.trim();
  const recordType = (rawType || "A").trim().toUpperCase();
  const reverse = rawReverse === "true";

  if (rawReverse && rawReverse !== "true" && rawReverse !== "false") {
    sendJson(response, 400, { error: "Reverse must be true or false." });
    return;
  }
  if (!input || input.length > 253) {
    sendJson(response, 400, { error: "Enter a DNS name or IP address." });
    return;
  }

  if (!/^(?:[A-Z][A-Z0-9-]{0,31}|[0-9]{1,5})$/.test(recordType) ||
      (Number(recordType) > 65535)) {
    sendJson(response, 400, { error: "Enter a valid DNS record type." });
    return;
  }

  let queryName = input;
  let queryType = recordType;
  try {
    if (reverse) {
      queryName = reverseName(input);
      queryType = "PTR";
    } else if (!validDnsName(input)) {
      sendJson(response, 400, {
        error: "Enter a valid DNS name (letters, numbers, hyphens, and underscores).",
      });
      return;
    }
  } catch (error) {
    sendJson(response, 400, { error: error.message });
    return;
  }

  if (queryType === "DNSSEC") {
    if (rawNameserver.trim()) {
      sendJson(response, 400, { error: "The DNSSEC check uses the validating DNS-over-HTTPS resolver. Clear the custom nameserver." });
      return;
    }
    sendJson(response, 200, { name: queryName, type: "DNSSEC", dnssecCheck: await checkDnssec(queryName.replace(/\.$/, "")) });
    return;
  }

  let nameserver;
  try {
    nameserver = await resolveNameserver(parseNameserver(rawNameserver));
  } catch (error) {
    sendJson(response, 400, { error: error.message });
    return;
  }

  if (nameserver) {
    let data;
    try {
      data = await directDnsLookup(queryName, queryType, nameserver);
    } catch (error) {
      sendJson(response, 502, {
        error: error.message || "Unable to query the selected nameserver.",
      });
      return;
    }
    const ptrLookups = await fetchPtrLookups(
      [...data.answers, ...data.authority, ...data.additional].map((answer) => answer.data),
      nameserver,
    );
    sendJson(response, 200, {
      ...data,
      ptrLookups,
      nameserver: `${nameserver.family === 6 ? `[${nameserver.address}]` : nameserver.address}:${nameserver.port}`,
    });
    return;
  }

  let data;
  try {
    data = await queryDohDns(queryName, queryType);
  } catch (error) {
    const timedOut = error.name === "TimeoutError";
    sendJson(response, 502, {
      error: timedOut
        ? "DNS lookup timed out. Please try again."
        : error.message || "Unable to reach the DNS provider.",
    });
    return;
  }
  const ptrLookups = await fetchPtrLookups(
    [...data.answers, ...data.authority, ...data.additional]
      .map((answer) => answer.data),
  );
  sendJson(response, 200, {
    ...data,
    ptrLookups,
  });
}

// TLS 1.2 suites: forward-secret AEAD only (no CBC). TLS 1.3 suites are unaffected.
const tlsCiphers = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
].join(":");

// TLS session resumption: tickets are on by default; this adds a bounded
// in-memory session-ID cache (Node leaves server-side caching to the app).
const tlsSessionTimeoutSeconds = 300;
const tlsSessionCacheLimit = 2000;
const tlsSessionCache = new Map();

function attachTlsSessionCache(secureServer) {
  secureServer.on("newSession", (id, data, callback) => {
    const key = id.toString("hex");
    tlsSessionCache.delete(key);
    tlsSessionCache.set(key, { data, expires: Date.now() + tlsSessionTimeoutSeconds * 1000 });
    while (tlsSessionCache.size > tlsSessionCacheLimit) {
      tlsSessionCache.delete(tlsSessionCache.keys().next().value);
    }
    callback();
  });
  secureServer.on("resumeSession", (id, callback) => {
    const key = id.toString("hex");
    const entry = tlsSessionCache.get(key);
    if (entry && entry.expires > Date.now()) {
      callback(null, entry.data);
      return;
    }
    tlsSessionCache.delete(key);
    callback(null, null);
  });
}

const server = http.createServer({ maxHeaderSize: 8192 }, (request, response) => {
  response.setHeader("content-security-policy", [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: https:",
    "connect-src 'self'",
  ].join("; "));
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("cross-origin-opener-policy", "same-origin");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("cross-origin-resource-policy", "same-origin");
  response.setHeader("cache-control", "no-store");
  if (process.env.COOKIE_SECURE === "true" || request.socket.encrypted) {
    response.setHeader("strict-transport-security", "max-age=31536000");
  }

  if (request.url.length > 4096) {
    sendJson(response, 414, { error: "Request URL must not exceed 4,096 characters." });
    return;
  }
  let url;
  try {
    url = new URL(request.url, "http://localhost");
  } catch {
    sendJson(response, 400, { error: "Malformed request URL." });
    return;
  }
  if (url.pathname === "/healthz" && (request.method === "GET" || request.method === "HEAD")) {
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(request.method === "HEAD" ? undefined : "ok\n");
    return;
  }
  const publicAccess = getPublicAccess();
  if (publicAccess.blockSite && publicAccess.blocked.entries.length && addressInRanges(publicAccess.blocked.ranges, getClientAddress(request))) {
    response.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
    response.end("Access from your network is blocked.\n");
    return;
  }
  const challengePrefix = "/.well-known/acme-challenge/";
  if (url.pathname.startsWith(challengePrefix)) {
    const keyAuthorization = request.method === "GET"
      ? acme.challenges.get(url.pathname.slice(challengePrefix.length))
      : undefined;
    if (!keyAuthorization) {
      response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }
    response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    response.end(keyAuthorization);
    return;
  }
  // API tokens (Authorization: Bearer bngl_…) may only call the lookup tools and monitors.
  const apiToken = apiTokenFromRequest(request);
  if (apiToken) {
    if (!apiTokenPaths.has(url.pathname) && !url.pathname.startsWith("/api/monitors")) {
      sendJson(response, 403, { error: "API tokens can only call lookup tools and monitors." });
      return;
    }
    const tokenUser = authenticateApiToken(apiToken);
    if (!tokenUser) {
      sendJson(response, 401, { error: "The API token is invalid, expired or revoked." });
      return;
    }
    const tokenAccess = getFeatureAccess()["api-tokens"] || "admin";
    if (tokenAccess === "admin" && tokenUser.role !== "admin") {
      sendJson(response, 403, { error: "API tokens are restricted to administrators." });
      return;
    }
    if (!allowApiTokenRequest(tokenUser.tokenId)) {
      sendJson(response, 429, { error: `API tokens are limited to ${apiTokenLimits.requestsPerHour} requests per hour.` });
      return;
    }
    request.apiUser = tokenUser;
  }
  // Defence in depth against CSRF: every state-changing API request must come from this
  // site, even endpoints that are also protected by JSON-only bodies and SameSite cookies.
  // Token requests carry no cookies, so they cannot be forged by another site.
  if (url.pathname.startsWith("/api/") && !["GET", "HEAD", "OPTIONS"].includes(request.method) &&
    !request.apiUser && !enforceSameOrigin(request, response)) {
    return;
  }
  const queryKeys = new Set();
  for (const key of url.searchParams.keys()) {
    if (queryKeys.has(key)) {
      sendJson(response, 400, { error: "Each query parameter may only be provided once." });
      return;
    }
    queryKeys.add(key);
  }

  const queryLogRoutes = {
    "/api/lookup": { method: "GET", action: "DNS lookup", keys: ["name", "type", "reverse"] },
    "/api/domain-info": { method: "GET", action: "Domain/IP registration lookup", keys: ["name"] },
    "/api/scan": { method: "GET", action: "Magic scan", keys: ["name", "ports"] },
    "/api/custom-port-scan": { method: "POST", action: "Port scan" },
    "/api/bulk-port-scan": { method: "POST", action: "Bulk port scan" },
    "/api/nmap-scan": { method: "POST", action: "Nmap scan" },
    "/api/mac-lookup": { method: "GET", action: "MAC lookup", keys: ["name"] },
    "/api/dig": { method: "GET", action: "Dig command", keys: ["command"] },
    "/api/blocklist": { method: "GET", action: "Blocklist check", keys: ["name"] },
    "/api/propagation": { method: "GET", action: "Propagation check", keys: ["name", "type"] },
    "/api/email-check": { method: "GET", action: "Email check", keys: ["name", "selectors"] },
    "/api/asn": { method: "GET", action: "ASN lookup", keys: ["name"] },
    "/api/web-check": { method: "GET", action: "Web check", keys: ["name"] },
    "/api/email-headers": { method: "POST", action: "Email header analysis" },
    "/api/dmarc-sources": { method: "POST", action: "DMARC report sources" },
    "/api/record-import": { method: "GET", action: "Record builder import", keys: ["name"] },
    "/api/bulk-domain-check": { method: "POST", action: "Bulk domain check" },
    "/api/dns-health": { method: "GET", action: "DNS health check", keys: ["name"] },
    "/api/mail-server": { method: "GET", action: "Mail server check", keys: ["name"] },
    "/api/reputation": { method: "GET", action: "Reputation check", keys: ["name"] },
    "/api/lookalike": { method: "GET", action: "Lookalike domains", keys: ["name"] },
    "/api/spf-flatten": { method: "GET", action: "SPF flattener", keys: ["name"] },
    "/api/ping": { method: "GET", action: "Ping", keys: ["name", "method"] },
    "/api/sslscan": { method: "GET", action: "SSL/TLS check", keys: ["name", "port"] },
    "/api/tls-grade": { method: "POST", action: "TLS test and grade" },
    "/api/ping-scan": { method: "POST", action: "Ping scan" },
    "/api/traceroute": { method: "GET", action: "Traceroute", keys: ["name"] },
    "/api/multi-traceroute": { method: "POST", action: "Multi traceroute" },
  };
  const queryLogRoute = queryLogRoutes[url.pathname];
  if (queryLogRoute && request.method === queryLogRoute.method) {
    request.logUsername = currentUser(request)?.username || null;
    request.logClientAddress = getClientAddress(request);
    request.logDetails = JSON.stringify(Object.fromEntries(
      (queryLogRoute.keys || [])
        .filter((key) => url.searchParams.has(key))
        .map((key) => [key, url.searchParams.get(key)]),
    ));
    response.once("finish", () => recordAdminLog(
      "query",
      request,
      queryLogRoute.action,
      request.logDetails,
      response.statusCode,
      request.logUsername,
    ));
  }

  if (url.pathname === "/api/auth/status") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    handleAuthStatus(request, response);
    return;
  }

  if (url.pathname === "/api/history" || url.pathname.startsWith("/api/history/")) {
    void handleHistory(request, url, response).catch((error) => {
      if (!response.headersSent) sendJson(response, error.statusCode || 500, { error: error.statusCode ? error.message : "Unable to complete the request." });
      if (!error.statusCode) console.error("History request failed:", error);
    });
    return;
  }

  if (url.pathname === "/api/shares" || url.pathname.startsWith("/api/shares/")) {
    void handleShares(request, url, response).catch((error) => {
      console.error("Shared result request failed:", error);
      sendJson(response, 500, { error: "Unable to complete the request." });
    });
    return;
  }

  if (url.pathname === "/api/about") {
    handleAbout(request, response);
    return;
  }

  if (url.pathname === "/api/branding") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    sendJson(response, 200, getSiteBranding());
    return;
  }

  if (url.pathname === "/api/client-info") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleClientInfo(request, response);
    return;
  }

  if (url.pathname === "/api/auth/setup") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleInitialSetup(request, response).catch((error) => {
      console.error("Initial admin setup failed:", error);
      sendJson(response, 500, { error: "Unable to complete initial admin setup." });
    });
    return;
  }

  if (url.pathname === "/api/auth/login/2fa") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleTwoFactorLogin(request, response).catch((error) => {
      console.error("Two-factor login failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "Unable to sign in." });
    });
    return;
  }

  const twoFactorMatch = url.pathname.match(/^\/api\/account\/2fa\/(setup|enable|disable|recovery-codes)$/);
  if (twoFactorMatch) {
    void handleAccountTwoFactor(request, response, twoFactorMatch[1]).catch((error) => {
      console.error("Two-factor setting failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "Unable to change two-factor login." });
    });
    return;
  }

  const tokenMatch = url.pathname.match(/^\/api\/account\/tokens(?:\/(\d+))?$/);
  if (tokenMatch) {
    void handleAccountTokens(request, response, tokenMatch[1] ? Number(tokenMatch[1]) : null).catch((error) => {
      console.error("API token request failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "Unable to manage API tokens." });
    });
    return;
  }

  if (url.pathname === "/api/auth/passkeys" || url.pathname.startsWith("/api/auth/passkeys/")) {
    void handlePasskeys(request, response, url).catch((error) => {
      console.error("Passkey request failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "The passkey request could not be completed." });
    });
    return;
  }

  if (url.pathname === "/api/auth/oidc/start" || url.pathname === "/api/auth/oidc/callback") {
    if (request.method !== "GET") return sendJson(response, 405, { error: "Method not allowed." });
    void handleOidc(request, response, url).catch((error) => {
      console.error("Single sign-on failed:", error);
      if (!response.headersSent) ssoLoginError(response, "Single sign-on failed.");
    });
    return;
  }

  if (url.pathname === "/api/admin/sso" || url.pathname === "/api/admin/sso/test") {
    handleAdminSso(request, response, url);
    return;
  }

  if (url.pathname === "/api/auth/login") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleLogin(request, response).catch((error) => {
      console.error("Login failed:", error);
      sendJson(response, 500, { error: "Unable to sign in." });
    });
    return;
  }

  if (url.pathname === "/api/auth/change-password") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleChangePassword(request, response).catch((error) => {
      console.error("Password change failed:", error);
      sendJson(response, 500, { error: "Unable to change password." });
    });
    return;
  }

  if (url.pathname === "/api/account") {
    handleAccount(request, response);
    return;
  }

  if (url.pathname === "/api/mail/results") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleMailResults(request, response).catch((error) => {
      console.error("Result email failed:", error);
      sendJson(response, 500, { error: "Unable to send email." });
    });
    return;
  }

  if (url.pathname === "/api/auth/logout") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    if (!enforceSameOrigin(request, response)) return;
    handleLogout(request, response);
    return;
  }

  if (url.pathname === "/api/admin/settings") {
    handleAdminSettings(request, response);
    return;
  }

  if (url.pathname === "/api/admin/logs") {
    handleAdminLogs(request, url, response);
    return;
  }

  if (url.pathname === "/api/admin/certificate") {
    handleAdminCertificate(request, response);
    return;
  }

  if (url.pathname === "/api/admin/system") {
    handleAdminSystem(request, response);
    return;
  }

  if (url.pathname === "/api/monitors" || url.pathname.startsWith("/api/monitors/")) {
    void handleMonitors(request, response, url).catch((error) => {
      console.error("Monitor request failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "The monitor request failed." });
    });
    return;
  }

  if (url.pathname === "/api/admin/mta-sts") {
    handleAdminMtaSts(request, response);
    return;
  }

  if (url.pathname === "/api/landing/config") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    sendJson(response, 200, publicLandingConfig());
    return;
  }

  if (url.pathname === "/api/landing/share" || url.pathname.startsWith("/api/landing/shares/")) {
    void handleLandingShares(request, url, response);
    return;
  }

  if (url.pathname === "/api/landing/start") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    handleLandingStart(request, response);
    return;
  }

  if (url.pathname === "/api/admin/backup" || url.pathname === "/api/admin/restore") {
    handleAdminBackupRoutes(request, response, url);
    return;
  }

  if (url.pathname === "/api/admin/public-access") {
    handleAdminPublicAccess(request, response);
    return;
  }

  if (url.pathname === "/api/admin/site-files") {
    handleAdminSiteFiles(request, response);
    return;
  }

  if (url.pathname === "/api/admin/landing" || url.pathname === "/api/admin/landing/background") {
    handleAdminLanding(request, response, url);
    return;
  }

  if (url.pathname === "/api/admin/logo") {
    handleAdminLogo(request, response);
    return;
  }

  if (url.pathname === "/api/admin/about") {
    handleAdminAbout(request, response);
    return;
  }

  if (url.pathname === "/api/admin/version") {
    void handleAdminVersion(request, url, response);
    return;
  }

  if (url.pathname === "/api/admin/insights") {
    handleAdminInsights(request, url, response);
    return;
  }

  if (url.pathname === "/api/admin/stats") {
    handleAdminStats(request, url, response);
    return;
  }

  if (url.pathname === "/api/admin/mail") {
    handleAdminMail(request, response);
    return;
  }

  if (url.pathname === "/api/admin/users") {
    handleAdminUsers(request, response);
    return;
  }

  const adminUserMatch = url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
  if (adminUserMatch) {
    const userId = Number(adminUserMatch[1]);
    if (!Number.isSafeInteger(userId) || userId < 1) {
      sendJson(response, 400, { error: "Invalid user ID." });
      return;
    }
    handleAdminUser(request, response, userId);
    return;
  }

  const protectedFeatures = {
    "/api/lookup": url.searchParams.get("reverse") === "true" ? "reverse" : "forward",
    "/api/domain-info": "whois",
    "/api/scan": "scan",
    "/api/custom-port-scan": "custom-port",
    "/api/bulk-port-scan": "bulk-port",
    "/api/nmap-scan": "nmap",
    "/api/nmap-status": "nmap",
    "/api/mac-lookup": "mac",
    "/api/dig": "dig",
    "/api/blocklist": "blocklist",
    "/api/propagation": "propagation",
    "/api/email-check": "email",
    "/api/asn": "asn",
    "/api/web-check": "web",
    "/api/email-headers": "email-headers",
    "/api/dmarc-sources": "dmarc-reports",
    "/api/record-import": "record-builder",
    "/api/bulk-domain-check": "bulk-domains",
    "/api/dns-health": "dns-health",
    "/api/mail-server": "mail-server",
    "/api/reputation": "reputation",
    "/api/lookalike": "lookalike",
    "/api/spf-flatten": "record-builder",
    "/api/ping": "ping",
    "/api/sslscan": "sslscan",
    "/api/tls-grade": "sslscan",
    "/api/ping-scan": "ping-scan",
    "/api/traceroute": "traceroute",
    "/api/multi-traceroute": "multi-traceroute",
  };
  const feature = protectedFeatures[url.pathname];
  const requiresPortScanLogin =
    ["/api/custom-port-scan", "/api/bulk-port-scan", "/api/ping-scan", "/api/multi-traceroute", "/api/nmap-scan", "/api/nmap-status"].includes(url.pathname) ||
    url.pathname === "/api/tls-grade" ||
    url.pathname === "/api/blocklist" ||
    url.pathname === "/api/bulk-domain-check" ||
    (url.pathname === "/api/ping" && url.searchParams.get("sample") === "1") ||
    (url.pathname === "/api/scan" && url.searchParams.get("ports") === "common");
  if (feature && !checkFeatureAccess(request, response, feature, requiresPortScanLogin)) return;

  if (url.pathname === "/api/lookup") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    lookup(request, url, response);
    return;
  }

  if (url.pathname === "/api/domain-info") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    domainInfo(url, response);
    return;
  }

  if (url.pathname === "/api/scan") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    bulkScan(request, url, response);
    return;
  }

  if (url.pathname === "/api/custom-port-scan") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    runCustomPortScan(request, response);
    return;
  }

  if (url.pathname === "/api/bulk-port-scan") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    runBulkPortScan(request, response);
    return;
  }

  if (url.pathname === "/api/nmap-scan") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void handleNmapScan(request, response);
    return;
  }

  if (url.pathname === "/api/nmap-status") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    handleNmapStatus(request, response);
    return;
  }

  if (url.pathname === "/api/ping") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    pingHost(request, url, response);
    return;
  }

  if (url.pathname === "/api/sslscan") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void sslScanHost(request, url, response);
    return;
  }

  if (url.pathname === "/api/tls-grade") {
    if (request.method === "POST") void startTlsGrade(request, response);
    else if (request.method === "GET") tlsGradeStatus(request, url, response);
    else sendJson(response, 405, { error: "Method not allowed." });
    return;
  }

  if (url.pathname === "/api/ping-scan") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    runPingScan(request, response);
    return;
  }

  if (url.pathname === "/api/traceroute") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    tracerouteHost(request, url, response);
    return;
  }

  if (url.pathname === "/api/multi-traceroute") {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    runMultiTraceroute(request, response);
    return;
  }

  if (url.pathname === "/api/web-check") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void webCheck(request, url, response);
    return;
  }

  const postRoutes = {
    "/api/email-headers": emailHeadersCheck,
    "/api/dmarc-sources": dmarcSourceLookup,
    "/api/bulk-domain-check": bulkDomainCheck,
  };
  if (postRoutes[url.pathname]) {
    if (request.method !== "POST") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void postRoutes[url.pathname](request, response).catch((error) => {
      console.error(`${url.pathname} failed:`, error);
      if (!response.headersSent) sendJson(response, 500, { error: "The request could not be completed." });
    });
    return;
  }

  const getRoutes = {
    "/api/dns-health": (request, url, response) => dnsHealthCheck(request, url, response),
    "/api/mail-server": (request, url, response) => mailServerCheck(request, url, response),
    "/api/reputation": (request, url, response) => reputationCheck(request, url, response),
    "/api/lookalike": (request, url, response) => lookalikeCheck(request, url, response),
    "/api/spf-flatten": (_request, url, response) => spfFlattenCheck(url, response),
  };
  if (getRoutes[url.pathname]) {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void getRoutes[url.pathname](request, url, response).catch((error) => {
      console.error(`${url.pathname} failed:`, error);
      if (!response.headersSent) sendJson(response, 500, { error: "The request could not be completed." });
    });
    return;
  }

  if (url.pathname === "/api/preview" || url.pathname === "/api/preview/asset") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    // Pages need the feature; asset links carry their own short-lived signature.
    if (url.pathname === "/api/preview" && !checkFeatureAccess(request, response, "preview", true)) return;
    const handler = url.pathname === "/api/preview" ? handlePreviewPage : handlePreviewAsset;
    void handler(request, url, response).catch((error) => {
      console.error("Preview failed:", error);
      if (!response.headersSent) sendJson(response, 500, { error: "The preview could not be created." });
    });
    return;
  }

  if (url.pathname === "/api/record-import") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void recordImport(url, response).catch(() => sendJson(response, 500, { error: "Unable to read the current records." }));
    return;
  }

  if (url.pathname === "/api/asn") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void asnLookup(request, url, response);
    return;
  }

  if (url.pathname === "/api/email-check") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void emailCheck(request, url, response);
    return;
  }

  if (url.pathname === "/api/propagation") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void propagationCheck(request, url, response);
    return;
  }

  if (url.pathname === "/api/blocklist") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void blocklistLookup(request, url, response);
    return;
  }

  if (url.pathname === "/api/dig") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    void digCommand(request, url, response);
    return;
  }

  if (url.pathname === "/api/mac-lookup") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    macLookup(url, response);
    return;
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { allow: "GET, HEAD" });
    response.end();
    return;
  }

  if (appSetupRequired() && (url.pathname === "/" || url.pathname === "/index.html")) {
    sendRedirect(response, "/setup.html");
    return;
  }
  if (url.pathname === "/setup.html") {
    if (!appSetupRequired()) {
      sendRedirect(response, "/login.html");
      return;
    }
  }
  if (url.pathname === "/login.html" && appSetupRequired()) {
    sendRedirect(response, "/setup.html");
    return;
  }
  if (url.pathname === "/my-account.html") {
    const user = currentUser(request, { allowPending: true });
    if (!user) {
      sendRedirect(response, appSetupRequired() ? "/setup.html" : "/login.html?next=%2Fmy-account.html");
      return;
    }
    if (user.mustChangePassword) {
      sendRedirect(response, "/change-password.html");
      return;
    }
  }
  if (url.pathname === "/change-password.html") {
    const user = currentUser(request, { allowPending: true });
    if (!user) {
      sendRedirect(response, appSetupRequired() ? "/setup.html" : "/login.html");
      return;
    }
  }
  if ((url.pathname === "/monitors.html" || url.pathname === "/monitors") && !currentUser(request)) {
    sendRedirect(response, `/login.html?next=${encodeURIComponent("/monitors.html")}`);
    return;
  }
  if ((url.pathname === "/history.html" || url.pathname === "/history") && !currentUser(request)) {
    sendRedirect(response, `/login.html?next=${encodeURIComponent("/history.html")}`);
    return;
  }
  if (url.pathname === "/login.html") {
    const user = currentUser(request);
    if (!user && currentUser(request, { allowPending: true })) {
      sendRedirect(response, "/change-password.html");
      return;
    }
    if (user) {
      sendRedirect(response, user.role === "admin" ? "/admin.html" : "/");
      return;
    }
  }
  if (url.pathname === "/admin.html" ||
    url.pathname === "/admin-logs.html" ||
    url.pathname === "/admin-stats.html" ||
    url.pathname === "/admin-dashboard.html") {
    if (appSetupRequired()) {
      sendRedirect(response, "/setup.html");
      return;
    }
    const user = currentUser(request);
    if (!user && currentUser(request, { allowPending: true })) {
      sendRedirect(response, "/change-password.html");
      return;
    }
    if (!user) {
      const nextPath = encodeURIComponent(url.pathname);
      sendRedirect(response, `/login.html?next=${nextPath}`);
      return;
    }
    if (user.role !== "admin") {
      sendRedirect(response, "/");
      return;
    }
  }
  if (url.pathname === "/logo.svg" && (request.method === "GET" || request.method === "HEAD") && serveBimiLogo(request, response)) {
    return;
  }
  if (url.pathname === "/.well-known/mta-sts.txt" && (request.method === "GET" || request.method === "HEAD") && serveMtaStsPolicy(request, response)) {
    return;
  }
  if (["/robots.txt", "/humans.txt", "/security.txt", "/.well-known/security.txt", "/.well-known/change-password"].includes(url.pathname) &&
    (request.method === "GET" || request.method === "HEAD") && serveSiteFile(request, response, url.pathname)) {
    return;
  }
  if (url.pathname === "/landing/background" && (request.method === "GET" || request.method === "HEAD")) {
    serveLandingBackground(request, response);
    return;
  }
  // Visitors who are not logged in get the simple landing page at "/", unless they follow a
  // link into the full interface (?mode=, ?share=, ?q=, …) or the landing page is turned off.
  // Logged-in users choose with the switch at the top right (a cookie per browser); the
  // administrator decides which interface they start in.
  let landingRoot = false;
  if (url.pathname === "/" && !url.search) {
    const config = readLandingConfig();
    if (!currentUser(request)) {
      landingRoot = config.enabled;
    } else {
      const choice = readCookie(request, "bng_ui");
      landingRoot = (choice === "simple" || choice === "full" ? choice : config.userInterface) === "simple";
    }
  }
  if (url.pathname === "/landing") {
    // The admin settings page shows a live preview of the landing page in a frame.
    response.setHeader("content-security-policy", response.getHeader("content-security-policy").replace("frame-ancestors 'none'", "frame-ancestors 'self'"));
    response.setHeader("x-frame-options", "SAMEORIGIN");
  }
  const sharedScan = /^\/s\/[A-Za-z0-9_-]{22}$/.test(url.pathname);
  const requestedPath = url.pathname === "/landing" || landingRoot || sharedScan ? "/landing.html" : url.pathname === "/" ? "/index.html" : url.pathname === "/about" ? "/about.html" : url.pathname === "/history" ? "/history.html" : url.pathname === "/monitors" ? "/monitors.html" : url.pathname;
  if (!staticFiles.has(requestedPath)) {
    response.writeHead(404);
    response.end();
    return;
  }
  const filePath = path.join(publicDir, requestedPath.slice(1));

  fs.lstat(filePath, (statError, stats) => {
    if (statError || !stats.isFile()) {
      response.writeHead(404);
      response.end("Not found");
      return;
    }
    fs.readFile(filePath, (readError, content) => {
      if (readError) {
        response.writeHead(404);
        response.end("Not found");
        return;
      }
      response.writeHead(200, {
        "content-type": contentTypes[path.extname(filePath)] || "application/octet-stream",
        "x-content-type-options": "nosniff",
      });
      if (request.method === "HEAD") response.end();
      else response.end(content);
    });
  });
});

server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxConnections = 1024;

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled rejection:", reason);
});

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}, shutting down.`);
  server.close(() => process.exit(0));
  server.closeIdleConnections?.();
  setTimeout(() => process.exit(0), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

server.listen(port, host, () => {
  console.log(`DNS lookup ${appBuild.version} listening on ${host}:${port}`);
});

function applyTlsCertificate(credentials) {
  if (httpsServer) {
    httpsServer.setSecureContext(credentials);
    return;
  }
  httpsError = null;
  const secureServer = https.createServer(
    { ...credentials, minVersion: "TLSv1.2", ciphers: tlsCiphers, honorCipherOrder: true, sessionTimeout: tlsSessionTimeoutSeconds, maxHeaderSize: 8192 },
    (request, response) => server.emit("request", request, response),
  );
  attachTlsSessionCache(secureServer);
  secureServer.headersTimeout = 10_000;
  secureServer.requestTimeout = 30_000;
  secureServer.on("error", (error) => {
    console.error("HTTPS listener failed:", error);
    httpsError = `Unable to listen on HTTPS port ${httpsPort}: ${error.code || error.message}`;
    if (httpsServer === secureServer) httpsServer = null;
  });
  httpsServer = secureServer;
  secureServer.listen(httpsPort, host, () => {
    console.log(`DNS lookup HTTPS listening on ${host}:${httpsPort}`);
  });
}

const storedCertificate = acme.loadStored();
if (storedCertificate) {
  try {
    applyTlsCertificate(storedCertificate);
  } catch (error) {
    console.error("Unable to start HTTPS with the stored certificate:", error);
  }
}
acme.startRenewalTimer();
