"use strict";

const { isIP } = require("node:net");

const twoLevelSuffixes = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au", "net.au", "org.au", "edu.au",
  "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "com.br", "net.br", "com.mx", "co.za", "com.tr", "com.cn", "com.hk",
  "co.in", "co.kr", "com.sg", "com.ar", "co.il", "com.pl", "com.ua",
]);

// Approximates the organizational domain used for DMARC alignment (without the full public suffix list).
function organizationalDomain(domain) {
  const labels = String(domain || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return twoLevelSuffixes.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

function addressDomain(value) {
  const match = String(value || "").match(/@([a-z0-9.-]+\.[a-z]{2,})\b/i);
  return match ? match[1].toLowerCase() : null;
}

function decodeMimeWords(value) {
  return String(value).replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (whole, charset, encoding, text) => {
    try {
      const bytes = encoding.toLowerCase() === "b"
        ? Buffer.from(text, "base64")
        : Buffer.from(text.replace(/_/g, " ").replace(/=([0-9a-f]{2})/gi, (_hex, code) => String.fromCharCode(parseInt(code, 16))), "latin1");
      return new TextDecoder(/utf-?8/i.test(charset) ? "utf-8" : charset.toLowerCase(), { fatal: false }).decode(bytes);
    } catch {
      return whole;
    }
  });
}

function parseHeaderBlock(raw) {
  const text = String(raw).replace(/\r\n?/g, "\n");
  const headerPart = text.split(/\n\s*\n/)[0];
  const headers = [];
  for (const line of headerPart.split("\n")) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers.at(-1).value += ` ${line.trim()}`;
      continue;
    }
    const index = line.indexOf(":");
    if (index <= 0) continue;
    const name = line.slice(0, index).trim();
    if (!/^[\x21-\x39\x3b-\x7e]+$/.test(name)) continue;
    headers.push({ name, value: line.slice(index + 1).trim() });
  }
  return headers;
}

function extractAddresses(text) {
  const found = [];
  for (const match of String(text).matchAll(/\[(?:IPv6:)?([0-9a-f:.]+)\]|\(([0-9a-f:.]+)\)|\b(\d{1,3}(?:\.\d{1,3}){3})\b/gi)) {
    const value = match[1] || match[2] || match[3];
    if (value && isIP(value) && !found.includes(value)) found.push(value);
  }
  return found;
}

function parseReceived(value) {
  const semicolon = value.lastIndexOf(";");
  const dateText = semicolon >= 0 ? value.slice(semicolon + 1).trim() : "";
  const body = semicolon >= 0 ? value.slice(0, semicolon) : value;
  const date = dateText ? new Date(dateText.replace(/\s*\([^)]*\)\s*$/, "")) : null;
  const fromPart = body.match(/\bfrom\s+([\s\S]*?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|$)/i)?.[1] || "";
  const byPart = body.match(/\bby\s+([^\s;]+)/i)?.[1] || null;
  const protocol = body.match(/\bwith\s+([A-Za-z0-9_-]+)/i)?.[1] || null;
  const tlsVersion = body.match(/\b(TLSv?1(?:[._]\d)?|TLS1_[0-3])\b/i)?.[1] || null;
  return {
    from: fromPart.match(/^([^\s(]+)/)?.[1] || null,
    fromDetail: fromPart.slice(0, 300) || null,
    by: byPart,
    protocol,
    tls: Boolean(tlsVersion) || /^(E?SMTPSA?|UTF8SMTPSA?|LMTPS|HTTPS)$/i.test(protocol || "") || /Transport Security|\bcipher=|\bversion=TLS/i.test(body),
    tlsVersion: tlsVersion ? tlsVersion.replace(/_/g, ".").toUpperCase() : null,
    ip: extractAddresses(fromPart)[0] || null,
    date: date && !Number.isNaN(date.getTime()) ? date.toISOString() : null,
    raw: value.slice(0, 1000),
  };
}

function parseAuthenticationResults(value) {
  const parts = value.split(";").map((part) => part.trim()).filter(Boolean);
  const authservId = parts[0]?.split(/\s+/)[0] || null;
  const results = [];
  for (const part of parts.slice(1)) {
    const match = part.match(/^([a-z0-9-]+)\s*=\s*([a-z]+)/i);
    if (!match) continue;
    const properties = {};
    for (const property of part.matchAll(/\b((?:header|smtp|policy)\.[a-z-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi)) {
      properties[property[1].toLowerCase()] = property[2].replace(/^"|"$/g, "");
    }
    results.push({ method: match[1].toLowerCase(), result: match[2].toLowerCase(), properties, comment: part.match(/\(([^)]*)\)/)?.[1]?.slice(0, 200) || null });
  }
  return { authservId, results };
}

function parseTags(value) {
  const tags = {};
  for (const part of value.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) tags[part.slice(0, index).trim().toLowerCase()] = part.slice(index + 1).replace(/\s+/g, "").trim();
  }
  return tags;
}

function parseSpamHeaders(lookup) {
  const signals = [];
  const status = lookup("x-spam-status");
  if (status) {
    signals.push({
      source: "SpamAssassin",
      verdict: /^yes/i.test(status) ? "spam" : "not spam",
      score: status.match(/score=(-?[\d.]+)/i)?.[1] || null,
      threshold: status.match(/required=(-?[\d.]+)/i)?.[1] || null,
      detail: status.match(/tests=([^\s]+)/i)?.[1]?.split(",").slice(0, 30).join(", ") || null,
    });
  }
  const rspamd = lookup("x-rspamd-score") || lookup("x-rspamd-action");
  if (rspamd) signals.push({ source: "Rspamd", verdict: lookup("x-rspamd-action") || null, score: lookup("x-rspamd-score") || null });
  const forefront = lookup("x-forefront-antispam-report");
  const scl = lookup("x-ms-exchange-organization-scl") || forefront?.match(/SCL:(-?\d+)/)?.[1];
  if (scl !== undefined && scl !== null) {
    const level = Number(scl);
    signals.push({
      source: "Microsoft 365",
      verdict: level >= 5 ? "spam" : level === -1 ? "trusted (bypassed filtering)" : "not spam",
      score: `SCL ${scl}`,
      detail: [forefront?.match(/SFV:([A-Z]+)/)?.[1] ? `SFV ${forefront.match(/SFV:([A-Z]+)/)[1]}` : null,
        forefront?.match(/CTRY:([A-Z]{2})/)?.[1] ? `country ${forefront.match(/CTRY:([A-Z]{2})/)[1]}` : null,
        lookup("x-microsoft-antispam")?.match(/BCL:(\d+)/)?.[1] ? `BCL ${lookup("x-microsoft-antispam").match(/BCL:(\d+)/)[1]}` : null].filter(Boolean).join(" · ") || null,
    });
  }
  const flag = lookup("x-spam-flag");
  if (flag && !status) signals.push({ source: "Spam filter", verdict: /yes/i.test(flag) ? "spam" : "not spam", score: lookup("x-spam-score") || null });
  return signals;
}

function analyzeEmailHeaders(raw) {
  const headers = parseHeaderBlock(raw);
  if (!headers.length) throw Object.assign(new Error("No email headers were found. Paste the full header block (from Show original / View source)."), { statusCode: 400 });
  const all = (name) => headers.filter((header) => header.name.toLowerCase() === name).map((header) => header.value);
  const first = (name) => all(name)[0];
  const received = all("received").map(parseReceived).reverse();
  const dateHeader = first("date") ? new Date(first("date")) : null;
  let previous = dateHeader && !Number.isNaN(dateHeader.getTime()) ? dateHeader.getTime() : null;
  received.forEach((hop, index) => {
    const time = hop.date ? Date.parse(hop.date) : null;
    hop.index = index + 1;
    hop.delaySeconds = time !== null && previous !== null ? Math.round((time - previous) / 1000) : null;
    if (time !== null) previous = time;
  });
  const authentication = all("authentication-results").map(parseAuthenticationResults);
  const primary = authentication[0] || { results: [] };
  const resultFor = (method) => primary.results.find((entry) => entry.method === method) || null;
  const dkimSignatures = all("dkim-signature").map(parseTags).map((tags) => ({ domain: tags.d || null, selector: tags.s || null, algorithm: tags.a || null, headers: tags.h ? tags.h.split(":").length : null }));
  const from = decodeMimeWords(first("from") || "");
  const fromDomain = addressDomain(from);
  const returnPath = first("return-path") || null;
  const returnPathDomain = addressDomain(returnPath) || resultFor("spf")?.properties["smtp.mailfrom"]?.split("@").pop()?.toLowerCase() || null;
  const replyTo = first("reply-to") || null;
  const replyToDomain = addressDomain(replyTo);
  const spf = resultFor("spf") || (first("received-spf") ? { method: "spf", result: first("received-spf").split(/\s/)[0].toLowerCase(), properties: {} } : null);
  const dkim = primary.results.filter((entry) => entry.method === "dkim");
  const dmarc = resultFor("dmarc");
  const orgFrom = organizationalDomain(fromDomain);
  const alignment = {
    spf: returnPathDomain && fromDomain ? organizationalDomain(returnPathDomain) === orgFrom : null,
    dkim: fromDomain && dkimSignatures.length ? dkimSignatures.some((signature) => signature.domain && organizationalDomain(signature.domain) === orgFrom) : null,
  };
  const spamSignals = parseSpamHeaders(first);
  const issues = [];
  if (dmarc && dmarc.result !== "pass") issues.push({ severity: "high", message: `DMARC ${dmarc.result}: the message failed the sender domain's DMARC policy.` });
  if (spf && ["fail", "softfail", "permerror", "temperror"].includes(spf.result)) issues.push({ severity: spf.result === "fail" ? "high" : "medium", message: `SPF ${spf.result}: the sending server is not authorized by ${returnPathDomain || "the envelope domain"}'s SPF record.` });
  if (dkim.length && !dkim.some((entry) => entry.result === "pass")) issues.push({ severity: "medium", message: `DKIM ${dkim.map((entry) => entry.result).join(", ")}: no valid DKIM signature.` });
  if (!dkimSignatures.length) issues.push({ severity: "medium", message: "The message is not DKIM-signed." });
  else if (alignment.dkim === false) issues.push({ severity: "low", message: `No DKIM signature from ${orgFrom}, so DKIM does not align with the From domain.` });
  if (alignment.spf === false && alignment.dkim !== true) issues.push({ severity: "medium", message: `Neither SPF (${returnPathDomain}) nor DKIM aligns with the From domain ${fromDomain}; DMARC cannot pass.` });
  if (replyToDomain && fromDomain && organizationalDomain(replyToDomain) !== orgFrom) issues.push({ severity: "low", message: `Replies go to a different domain (${replyToDomain}) than the sender (${fromDomain}); common in newsletters, but also in phishing.` });
  if (/bulk|list/i.test(first("precedence") || "") && !first("list-unsubscribe")) issues.push({ severity: "medium", message: "Bulk mail without a List-Unsubscribe header; Gmail and Yahoo require one-click unsubscribe for bulk senders." });
  else if (first("list-unsubscribe") && !/one-click/i.test(first("list-unsubscribe-post") || "")) issues.push({ severity: "low", message: "List-Unsubscribe is present but without List-Unsubscribe-Post (one-click unsubscribe)." });
  const slow = received.filter((hop) => hop.delaySeconds !== null && hop.delaySeconds > 300);
  if (slow.length) issues.push({ severity: "low", message: `${slow.length} hop(s) took more than 5 minutes; see the delivery path.` });
  if (received.some((hop) => hop.delaySeconds !== null && hop.delaySeconds < -120)) issues.push({ severity: "low", message: "Some hop clocks are out of order (negative delay); a server's clock may be wrong." });
  if (received.some((hop) => hop.index > 1 && hop.protocol && !hop.tls && !/^(local|LMTP|HTTP)/i.test(hop.protocol))) issues.push({ severity: "low", message: "At least one hop was not encrypted with TLS." });
  for (const signal of spamSignals) {
    if (/^spam/i.test(signal.verdict || "")) issues.push({ severity: "high", message: `${signal.source} classified the message as spam (${signal.score || "no score"}).` });
  }
  const times = received.map((hop) => hop.date && Date.parse(hop.date)).filter(Number.isFinite);
  return {
    summary: {
      subject: decodeMimeWords(first("subject") || "").slice(0, 300) || null,
      from: from.slice(0, 300) || null,
      fromDomain,
      to: decodeMimeWords(first("to") || "").slice(0, 300) || null,
      date: dateHeader && !Number.isNaN(dateHeader.getTime()) ? dateHeader.toISOString() : null,
      messageId: first("message-id")?.slice(0, 300) || null,
      returnPath: returnPath?.slice(0, 300) || null,
      replyTo: replyTo?.slice(0, 300) || null,
      mailer: (first("x-mailer") || first("user-agent"))?.slice(0, 200) || null,
      totalDelaySeconds: dateHeader && times.length ? Math.round((Math.max(...times) - dateHeader.getTime()) / 1000) : null,
      listUnsubscribe: Boolean(first("list-unsubscribe")),
      oneClickUnsubscribe: /one-click/i.test(first("list-unsubscribe-post") || ""),
    },
    authentication: {
      authservId: primary.authservId || null,
      spf: spf ? { result: spf.result, domain: returnPathDomain } : null,
      dkim: dkim.map((entry) => ({ result: entry.result, domain: entry.properties["header.d"] || entry.properties["header.i"]?.split("@").pop() || null, selector: entry.properties["header.s"] || null })),
      dmarc: dmarc ? { result: dmarc.result, policy: dmarc.comment?.match(/p=([a-z]+)/i)?.[1] || null, domain: dmarc.properties["header.from"] || fromDomain } : null,
      arc: resultFor("arc")?.result || null,
      compauth: resultFor("compauth")?.result || null,
      alignment,
      all: authentication.slice(0, 10),
    },
    dkimSignatures: dkimSignatures.slice(0, 10),
    hops: received.slice(0, 40),
    spam: spamSignals,
    headerCount: headers.length,
    headers: headers.slice(0, 200).map((header) => [header.name.slice(0, 100), header.value.slice(0, 2000)]),
    issues,
  };
}

module.exports = { analyzeEmailHeaders, organizationalDomain };
