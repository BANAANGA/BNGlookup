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
const { promisify } = require("node:util");
const { DatabaseSync } = require("node:sqlite");
const { lookup: resolveHost } = require("node:dns/promises");
const { domainToASCII } = require("node:url");
const { createAcmeManager } = require("./acme");
const { sendMail, validAddress } = require("./mail");

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
]);
const dataDir = path.resolve(process.env.DATA_DIR || "/data");
fs.mkdirSync(dataDir, { recursive: true });
process.umask(0o077);
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
const publicLookupDailyLimit = 15;
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

async function fetchRdap(domain) {
  const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: {
      accept: "application/rdap+json, application/json",
      "user-agent": "BNGlookup/0.1 (+https://github.com/BANAANGA/BNGlookup)",
    },
    signal: AbortSignal.timeout(10000),
  });
  if (response.status === 404) {
    throw new Error("No registration record was found for this domain.");
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

function encodeDnsQuery(name, typeCode) {
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
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const questionTail = Buffer.alloc(4);
  questionTail.writeUInt16BE(typeCode, 0);
  questionTail.writeUInt16BE(1, 2);
  return Buffer.concat([header, encodedName, questionTail]);
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
    truncated: Boolean(flags & 0x0200),
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

async function queryDohDns(name, type) {
  const resolver = getDnsResolver();
  if (resolver.format === "json") {
    const queryUrl = new URL(resolver.endpoint);
    queryUrl.searchParams.set("name", name);
    queryUrl.searchParams.set("type", type);
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
      answers: data.Answer || [],
      authority: data.Authority || [],
      additional: data.Additional || [],
    };
  }

  const query = encodeDnsQuery(name, dnsQuestionType(type));
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
    answers: result.answers,
    authority: result.authority,
    additional: result.additional,
  };
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
  const rawDomain = queryInput(url, "name", 253, response);
  const portScanOption = queryInput(url, "ports", 10, response);
  const rawNameserver = queryInput(url, "nameserver", 300, response);
  if ([rawDomain, portScanOption, rawNameserver].includes(null)) return;
  if (rawNameserver.trim() && currentUser(request)?.role !== "admin") {
    sendJson(response, 403, { error: "Custom nameservers are available to administrators only." });
    return;
  }
  const domain = normalizeDomain(rawDomain);
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name." });
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

  const registrationPromise = fetchRdap(domain).then(
    (registration) => ({ registration, error: null }),
    (error) => ({
      registration: null,
      error: error.message || "Unable to retrieve registration details.",
    }),
  );
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
  const portScan = portScanOption === "common"
    ? await scanCommonTcpPorts(domain, rootAddresses, rolePolicy)
    : null;
  const registrationResult = await registrationPromise;

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
    emailSecurity: {
      spfRecords,
      rootSpfFound: spfRecords.some((record) => record.name === domain),
      dkimSelectorsChecked: dkimRecords.length,
      dkimRecords: dkimRecords.filter((entry) => entry.records.length),
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
    fetchRdap(domain),
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
    user,
    mailEnabled: Boolean(getMailConfig()),
    featureAccess: getFeatureAccess(),
    features: featureNames,
  });
}

async function handleInitialSetup(request, response) {
  if (!enforceSameOrigin(request, response)) return;
  if (appSetupRequired() && !allowAuthAttempt(request)) {
    sendJson(response, 429, { error: "Too many setup attempts. Try again later." });
    return;
  }
  const body = await readAuthBody(request, response);
  if (!body) return;
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
    recordAdminLog("login", request, "Login failed", "", 401, username || null);
    sendJson(response, 401, { error: "Invalid username or password." });
    return;
  }
  resetAuthAttempts(request);
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
        saveSetting.run("port_scan_policy", JSON.stringify(portScanPolicy));
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
      SELECT id, username, role, active, email, created_at AS createdAt
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
    if (!active || hasPassword) {
      database.prepare("DELETE FROM user_sessions WHERE user_id = ?").run(userId);
    }
    const changes = [
      target.role !== role ? `role ${target.role} → ${role}` : "",
      target.active !== active ? `active ${target.active ? "yes" : "no"} → ${active ? "yes" : "no"}` : "",
      hasPassword ? "password reset" : "",
      email !== undefined ? "email updated" : "",
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
  const logs = database.prepare(`
    SELECT id, created_at AS timestamp, username, client_ip AS clientIp,
      action, details, status_code AS statusCode
    FROM admin_logs
    WHERE category = ?
    ORDER BY id DESC
    LIMIT ?
  `).all(category, Number(rawLimit));
  sendJson(response, 200, { logs });
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
    const expectedMethod = ["/api/custom-port-scan", "/api/bulk-port-scan", "/api/ping-scan", "/api/multi-traceroute", "/api/nmap-scan"]
      .includes(new URL(request.url, "http://localhost").pathname)
      ? "POST"
      : "GET";
    if (!user && request.method === expectedMethod &&
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
    error: "Daily public lookup limit reached (15 lookups per IP). Try again after 00:00 UTC.",
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

const heavyJobLimits = { traceroute: 8, pingScan: 2, nmap: 1, sslscan: 4, zmap: 1, tlsGrade: 2, dig: 8 };
const heavyJobsActive = { traceroute: 0, pingScan: 0, nmap: 0, sslscan: 0, zmap: 0, tlsGrade: 0, dig: 0 };
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
      failure = new Error(error.code === "ENOENT"
        ? "Nmap is unavailable on this server."
        : "Nmap could not be started.");
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

  sendJson(response, 200, {
    mac,
    oui: hex.slice(0, 6),
    multicast: Boolean(firstOctet & 1),
    locallyAdministered: Boolean(firstOctet & 2),
    found: data.success && data.found,
    company: data.company || null,
    country: data.country || null,
    address: data.address || null,
    blockType: data.blockType || null,
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

  if (url.pathname === "/api/admin/version") {
    void handleAdminVersion(request, url, response);
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
  const requestedPath = url.pathname === "/" ? "/index.html" : url.pathname;
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
