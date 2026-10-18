const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { isIP } = require("node:net");
const { domainToASCII } = require("node:url");

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "0.0.0.0";
const dohEndpoint = process.env.DOH_ENDPOINT || "https://cloudflare-dns.com/dns-query";
const publicDir = path.join(__dirname, "public");
const dnsStatusNames = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
};
const scanRecordTypes = ["A", "AAAA", "CAA", "CNAME", "HTTPS", "MX", "NS", "SOA", "SRV", "TXT"];
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
const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
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
        Array.isArray(field[3]) ? field[3].join(", ") : field[3],
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

async function fetchPtr(address) {
  const queryUrl = new URL(dohEndpoint);
  queryUrl.searchParams.set("name", reverseName(address));
  queryUrl.searchParams.set("type", "PTR");
  const response = await fetch(queryUrl, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    throw new Error(`DNS provider returned HTTP ${response.status}.`);
  }
  const data = await response.json();
  if (typeof data.Status !== "number" || !Array.isArray(data.Answer || [])) {
    throw new Error("DNS provider returned an invalid response.");
  }
  return {
    status: dnsStatusNames[data.Status] || `DNS status ${data.Status}`,
    answers: (data.Answer || []).map((answer) => answer.data),
  };
}

async function fetchPtrLookups(addresses) {
  const uniqueAddresses = [...new Set(addresses.filter((address) => isIP(address)))];
  const results = [];
  for (let index = 0; index < uniqueAddresses.length; index += 8) {
    const batch = uniqueAddresses.slice(index, index + 8);
    results.push(...await Promise.all(batch.map(async (address) => {
      try {
        return [address, await fetchPtr(address)];
      } catch (error) {
        return [address, { error: error.message || "Unable to retrieve PTR record." }];
      }
    })));
  }
  return Object.fromEntries(results);
}

async function queryDnsRecords(name, type) {
  const queryUrl = new URL(dohEndpoint);
  queryUrl.searchParams.set("name", name);
  queryUrl.searchParams.set("type", type);
  const response = await fetch(queryUrl, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    throw new Error(`DNS provider returned HTTP ${response.status}.`);
  }
  const data = await response.json();
  if (typeof data.Status !== "number" || !Array.isArray(data.Answer || [])) {
    throw new Error("DNS provider returned an invalid response.");
  }
  return data.Answer || [];
}

async function bulkScan(url, response) {
  const domain = normalizeDomain(url.searchParams.get("name") || "");
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name." });
    return;
  }

  const registrationPromise = fetchRdap(domain).then(
    (registration) => ({ registration, error: null }),
    (error) => ({
      registration: null,
      error: error.message || "Unable to retrieve registration details.",
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
        const answers = await queryDnsRecords(task.name, task.type);
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
  const registrationResult = await registrationPromise;

  sendJson(response, 200, {
    domain,
    recordTypes: scanRecordTypes,
    subdomainsChecked: candidates.length - 1,
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
    failedQueries,
    ptrLookups: await fetchPtrLookups(addresses),
  });
}

async function fetchNameservers(domain) {
  const queryUrl = new URL(dohEndpoint);
  queryUrl.searchParams.set("name", domain);
  queryUrl.searchParams.set("type", "NS");
  const response = await fetch(queryUrl, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    throw new Error(`DNS provider returned HTTP ${response.status}.`);
  }
  const data = await response.json();
  if (typeof data.Status !== "number" || !Array.isArray(data.Answer || [])) {
    throw new Error("DNS provider returned an invalid response.");
  }

  const records = (data.Answer || []).map((answer) => ({
    name: answer.data,
    ttl: answer.TTL,
  }));
  const addressResults = await Promise.allSettled(
    records.map(async (nameserver) => {
      const [ipv4, ipv6] = await Promise.all(["A", "AAAA"].map(async (type) => {
        const addressUrl = new URL(dohEndpoint);
        addressUrl.searchParams.set("name", nameserver.name);
        addressUrl.searchParams.set("type", type);
        const addressResponse = await fetch(addressUrl, {
          headers: { accept: "application/dns-json" },
          signal: AbortSignal.timeout(8000),
        });
        if (!addressResponse.ok) return [];
        const addressData = await addressResponse.json();
        return Array.isArray(addressData.Answer)
          ? addressData.Answer.map((answer) => answer.data)
          : [];
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
    status: dnsStatusNames[data.Status] || `DNS status ${data.Status}`,
    records: enrichedRecords,
    addressesIncomplete: addressResults.some((result) => result.status === "rejected"),
  };
}

async function domainInfo(url, response) {
  const domain = normalizeDomain(url.searchParams.get("name") || "");
  if (!domain) {
    sendJson(response, 400, { error: "Enter a valid domain name." });
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

async function macLookup(url, response) {
  const input = (url.searchParams.get("name") || "").trim();
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

async function lookup(url, response) {
  const input = (url.searchParams.get("name") || "").trim();
  const recordType = (url.searchParams.get("type") || "A").trim().toUpperCase();
  const reverse = url.searchParams.get("reverse") === "true";

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

  let queryUrl;
  try {
    queryUrl = new URL(dohEndpoint);
  } catch {
    sendJson(response, 500, { error: "The DNS-over-HTTPS endpoint is not a valid URL." });
    return;
  }
  queryUrl.searchParams.set("name", queryName);
  queryUrl.searchParams.set("type", queryType);

  let result;
  try {
    result = await fetch(queryUrl, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(8000),
    });
  } catch (error) {
    const timedOut = error.name === "TimeoutError";
    sendJson(response, 502, {
      error: timedOut ? "DNS lookup timed out. Please try again." : "Unable to reach the DNS provider.",
    });
    return;
  }

  if (!result.ok) {
    sendJson(response, 502, { error: `DNS provider returned HTTP ${result.status}.` });
    return;
  }

  let data;
  try {
    data = await result.json();
  } catch {
    sendJson(response, 502, { error: "DNS provider returned invalid JSON." });
    return;
  }

  if (
    typeof data.Status !== "number" ||
    !Array.isArray(data.Answer || []) ||
    !Array.isArray(data.Authority || []) ||
    !Array.isArray(data.Additional || [])
  ) {
    sendJson(response, 502, { error: "DNS provider returned an invalid response." });
    return;
  }

  const ptrLookups = await fetchPtrLookups(
    [...(data.Answer || []), ...(data.Authority || []), ...(data.Additional || [])]
      .map((answer) => answer.data),
  );
  sendJson(response, 200, {
    name: queryName,
    type: queryType,
    status: data.Status,
    statusText: dnsStatusNames[data.Status] || `DNS status ${data.Status}`,
    answers: data.Answer || [],
    authority: data.Authority || [],
    additional: data.Additional || [],
    ptrLookups,
  });
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);

  if (url.pathname === "/api/lookup") {
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "Method not allowed." });
      return;
    }
    lookup(url, response);
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
    bulkScan(url, response);
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

  const requestedPath = url.pathname === "/" ? "/index.html" : url.pathname;
  const filePath = path.resolve(publicDir, `.${requestedPath}`);
  if (!filePath.startsWith(`${publicDir}${path.sep}`)) {
    response.writeHead(404);
    response.end();
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
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

server.listen(port, host, () => {
  console.log(`DNS lookup listening on ${host}:${port}`);
});
