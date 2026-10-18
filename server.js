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
