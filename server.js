const http = require("node:http");
const https = require("node:https");
const { execFile } = require("node:child_process");
const fs = require("node:fs");
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

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}
function parseTrustedProxyEntries(value) {
  if (typeof value !== "string" || value.length > 2048) {
    throw new Error("Trusted proxies must be a list no longer than 2,048 characters.");
  }
  const entries = [...new Set(value.split(/[,\r\n]+/).map((entry) => entry.trim()).filter(Boolean))];
  if (entries.length > 50) {
    throw new Error("Trusted proxies may contain no more than 50 IP addresses or CIDRs.");
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
  "/admin.html",
  "/admin-logs.html",
  "/admin-stats.html",
  "/styles.css",
  "/app.js",
  "/account.js",
  "/admin.js",
  "/admin-logs.js",
  "/admin-stats.js",
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
  scan: "admin",
  "custom-port": "admin",
  "bulk-port": "admin",
};
const featureNames = {
  forward: "DNS lookup",
  reverse: "Reverse lookup",
  whois: "Whois",
  mac: "MAC lookup",
  ping: "Ping / host check",
  scan: "Magic scan",
  "custom-port": "Custom port scan",
  "bulk-port": "Bulk port scan",
};
const portScanPolicyDefaults = {
  maxPortsByRole: { admin: 100, user: 25 },
  localScanByRole: { admin: true, user: false },
};
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
database.prepare(`
  INSERT OR IGNORE INTO app_settings (key, value)
  VALUES ('public_lookup_hash_key', ?)
`).run(crypto.randomBytes(32).toString("hex"));
const publicLookupHashKey = database.prepare(
  "SELECT value FROM app_settings WHERE key = 'public_lookup_hash_key'",
).get().value;

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
      if (typeof asn === "string" && /^AS\d+$/i.test(asn)) {
        asNumbers.push(asn.toUpperCase());
      } else {
        throw new Error("ASN provider returned no autonomous system number.");
      }
    } catch (error) {
      asnError = error.message || "Unable to retrieve the autonomous system number.";
    }
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

function parseBulkScanTargets(input) {
  if (input.length > 8192) {
    throw invalidScanRequest("Target list must not exceed 8,192 characters.");
  }
  const tokens = input.split(/[\s,]+/).filter(Boolean);
  if (!tokens.length) throw invalidScanRequest("Enter at least one IP address or CIDR block.");
  if (tokens.length > 256) {
    throw invalidScanRequest("Enter no more than 256 IP addresses or CIDR blocks.");
  }
  const targets = new Set();
  for (const token of tokens) {
    const slash = token.indexOf("/");
    if (slash < 0) {
      if (!isIP(token)) {
        throw invalidScanRequest(`Invalid IP address or CIDR block: ${token}`);
      }
      targets.add(token);
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
    const hostBits = BigInt(width - prefix);
    const count = 1n << hostBits;
    if (count > 256n) {
      throw invalidScanRequest("Bulk scans are limited to 256 unique IP addresses.");
    }
    const rawAddress = family === 4
      ? BigInt(address.split(".").reduce((value, octet) => (value << 8n) | BigInt(octet), 0n))
      : ipv6ToBigInt(address);
    const network = (rawAddress >> hostBits) << hostBits;
    for (let offset = 0n; offset < count; offset += 1n) {
      targets.add(addressFromBigInt(network + offset, family));
      if (targets.size > 256) {
        throw invalidScanRequest("Bulk scans are limited to 256 unique IP addresses.");
      }
    }
  }
  if (targets.size > 256) {
    throw invalidScanRequest("Bulk scans are limited to 256 unique IP addresses.");
  }
  return [...targets];
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
    if (statusCode === 500) console.error("Custom port scan failed:", error);
    sendJson(response, statusCode, {
      error: statusCode === 500 ? "Unable to complete the custom port scan." : error.message,
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
    const addresses = parseBulkScanTargets(targetsInput);
    request.logDetails = JSON.stringify({ targets: addresses, port });
    const data = await scanTcpTargets(
      "Bulk IP targets",
      addresses,
      [port],
      256,
      (address) => address,
      policy.localScanByRole[user.role],
    );
    sendJson(response, 200, data);
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
    };
  } catch {
    return structuredClone(portScanPolicyDefaults);
  }
}

function getDefaultResolverId() {
  const row = database.prepare("SELECT value FROM app_settings WHERE key = 'default_dns_resolver'").get();
  if (row && (Object.hasOwn(dnsResolvers, row.value) || (row.value === "custom" && customDohEndpoint))) {
    return row.value;
  }
  return customResolverOption.length ? "custom" : "cloudflare";
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

function currentUser(request) {
  const token = readCookie(request, sessionCookieName);
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return null;
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const session = database.prepare(`
    SELECT users.id, users.username, users.role, user_sessions.expires_at
    FROM user_sessions JOIN users ON users.id = user_sessions.user_id
    WHERE user_sessions.token_hash = ? AND users.active = 1
  `).get(tokenHash);
  if (!session) return null;
  if (session.expires_at <= Date.now()) {
    database.prepare("DELETE FROM user_sessions WHERE token_hash = ?").run(tokenHash);
    return null;
  }
  return { id: session.id, username: session.username, role: session.role };
}

function setSessionCookie(response, token) {
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  response.setHeader("set-cookie", `${sessionCookieName}=${token}; Path=/; Max-Age=${sessionDurationMs / 1000}; HttpOnly; SameSite=Strict${secure}`);
}

function clearSessionCookie(response) {
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
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
    SELECT id, username, password_hash, password_salt, role
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
  recordAdminLog("login", request, "Login successful", "", 200, user.username);
  sendJson(response, 200, {
    user: { username: user.username, role: user.role },
    featureAccess: getFeatureAccess(),
  });
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
      defaultDnsResolver: getDefaultResolverId(),
      dnsResolvers: getDnsResolverOptions(),
      trustedProxies: trustedProxyEntries.join("\n"),
      branding: getSiteBranding(),
    });
    return;
  }
  if (request.method !== "PUT") {
    sendJson(response, 405, { error: "Method not allowed." });
    return;
  }
  if (!enforceSameOrigin(request, response)) return;
  void readAuthBody(request, response, 384 * 1024).then((body) => {
    if (!body) return;
    const access = Object.hasOwn(body, "featureAccess") ? body.featureAccess : getFeatureAccess();
    const portScanPolicy = Object.hasOwn(body, "portScanPolicy")
      ? body.portScanPolicy
      : getPortScanPolicy();
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
      if (Object.hasOwn(body, "defaultDnsResolver")) {
        saveSetting.run("default_dns_resolver", defaultDnsResolver);
      }
      if (Object.hasOwn(body, "trustedProxies")) {
        saveSetting.run("trusted_proxies", JSON.stringify(trustedProxyConfig.entries));
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
    trustedProxyRanges = trustedProxyConfig.ranges;
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
      defaultDnsResolver,
      trustedProxies: trustedProxyEntries.join("\n"),
      branding: getSiteBranding(),
    });
  }).catch((error) => {
    console.error("Application settings update failed:", error);
    sendJson(response, 500, { error: "Unable to save application settings." });
  });
}

function handleAdminUsers(request, response) {
  const admin = requireAdmin(request, response);
  if (!admin) return;
  if (request.method === "GET") {
    const users = database.prepare(`
      SELECT id, username, role, active, created_at AS createdAt
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
    const credentials = await hashPassword(body.password);
    try {
      database.prepare(`
        INSERT INTO users (username, password_hash, password_salt, role)
        VALUES (?, ?, ?, ?)
      `).run(body.username, credentials.hash, credentials.salt, body.role);
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
        UPDATE users SET role = ?, active = ?, password_hash = ?, password_salt = ?
        WHERE id = ?
      `).run(role, active, credentials.hash, credentials.salt, userId);
    } else {
      database.prepare("UPDATE users SET role = ?, active = ? WHERE id = ?")
        .run(role, active, userId);
    }
    if (!active || hasPassword) {
      database.prepare("DELETE FROM user_sessions WHERE user_id = ?").run(userId);
    }
    const changes = [
      target.role !== role ? `role ${target.role} → ${role}` : "",
      target.active !== active ? `active ${target.active ? "yes" : "no"} → ${active ? "yes" : "no"}` : "",
      hasPassword ? "password reset" : "",
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
    const expectedMethod = ["/api/custom-port-scan", "/api/bulk-port-scan"]
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

function runIcmpPing(address) {
  const command = isIP(address) === 6 ? "ping6" : "ping";
  return new Promise((resolve) => {
    execFile(command, ["-c", "4", "-W", "2", address], { timeout: 12000, maxBuffer: 65536 }, (error, stdout) => {
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
    const address = eligible[0];
    const result = method === "icmp"
      ? await runIcmpPing(address)
      : await runHttpCheck(target, address, method);
    sendJson(response, 200, { target, address, method, ...result });
  } catch (error) {
    console.error("Ping failed:", error);
    sendJson(response, 500, { error: "Unable to complete the host check." });
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
  if (process.env.COOKIE_SECURE === "true") {
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
    "/api/custom-port-scan": { method: "POST", action: "Custom port scan" },
    "/api/bulk-port-scan": { method: "POST", action: "Bulk port scan" },
    "/api/mac-lookup": { method: "GET", action: "MAC lookup", keys: ["name"] },
    "/api/ping": { method: "GET", action: "Ping", keys: ["name", "method"] },
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

  if (url.pathname === "/api/admin/stats") {
    handleAdminStats(request, url, response);
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
    "/api/mac-lookup": "mac",
    "/api/ping": "ping",
  };
  const feature = protectedFeatures[url.pathname];
  const requiresPortScanLogin =
    ["/api/custom-port-scan", "/api/bulk-port-scan"].includes(url.pathname) ||
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

  if (url.pathname === "/api/ping") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    pingHost(request, url, response);
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
  if (url.pathname === "/login.html") {
    const user = currentUser(request);
    if (user) {
      sendRedirect(response, user.role === "admin" ? "/admin.html" : "/");
      return;
    }
  }
  if (url.pathname === "/admin.html" ||
    url.pathname === "/admin-logs.html" ||
    url.pathname === "/admin-stats.html") {
    if (appSetupRequired()) {
      sendRedirect(response, "/setup.html");
      return;
    }
    const user = currentUser(request);
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
server.listen(port, host, () => {
  console.log(`DNS lookup listening on ${host}:${port}`);
});
