const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const directoryUrls = {
  production: "https://acme-v02.api.letsencrypt.org/directory",
  staging: "https://acme-staging-v02.api.letsencrypt.org/directory",
};
const renewBeforeMs = 30 * 24 * 60 * 60 * 1000;

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function derLength(length) {
  if (length < 128) return Buffer.from([length]);
  const bytes = [];
  for (let remaining = length; remaining > 0; remaining = Math.floor(remaining / 256)) {
    bytes.unshift(remaining % 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, ...parts) {
  const content = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derOid(oid) {
  const parts = oid.split(".").map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const encoded = [part & 0x7f];
    for (let rest = part >> 7; rest > 0; rest >>= 7) encoded.unshift((rest & 0x7f) | 0x80);
    bytes.push(...encoded);
  }
  return der(0x06, Buffer.from(bytes));
}

function buildCsr(domain, privateKey, publicKey) {
  const subject = der(0x30, der(0x31, der(0x30, derOid("2.5.4.3"), der(0x0c, Buffer.from(domain)))));
  const subjectAltName = der(0x30, der(0x82, Buffer.from(domain)));
  const extensions = der(0x30, der(0x30, derOid("2.5.29.17"), der(0x04, subjectAltName)));
  const attributes = der(0xa0, der(0x30, derOid("1.2.840.113549.1.9.14"), der(0x31, extensions)));
  const info = der(
    0x30,
    der(0x02, Buffer.from([0])),
    subject,
    publicKey.export({ type: "spki", format: "der" }),
    attributes,
  );
  const signature = crypto.sign("sha256", info, privateKey);
  return der(
    0x30,
    info,
    der(0x30, derOid("1.2.840.10045.4.3.2")),
    der(0x03, Buffer.from([0]), signature),
  );
}

function createAcmeManager({ dataDir, getConfig, onCertificate, log = console }) {
  const acmeDir = path.join(dataDir, "acme");
  const certPath = path.join(acmeDir, "certificate.pem");
  const keyPath = path.join(acmeDir, "private-key.pem");
  const metaPath = path.join(acmeDir, "certificate.json");
  const challenges = new Map();
  const status = { state: "idle", message: "", steps: [], finishedAt: null };
  let running = false;

  fs.mkdirSync(acmeDir, { recursive: true, mode: 0o700 });

  function writePrivate(file, content) {
    fs.writeFileSync(file, content, { mode: 0o600 });
    fs.chmodSync(file, 0o600);
  }

  function step(message) {
    status.steps.push(message);
    if (status.steps.length > 30) status.steps.shift();
    status.message = message;
  }

  function directoryUrl(environment) {
    return process.env.ACME_DIRECTORY_URL || directoryUrls[environment];
  }

  function loadAccount(environment) {
    const file = path.join(acmeDir, `account-${environment}.json`);
    try {
      const saved = JSON.parse(fs.readFileSync(file, "utf8"));
      const privateKey = crypto.createPrivateKey(saved.privateKeyPem);
      return { file, privateKey, kid: saved.kid || null, directory: saved.directory || null };
    } catch {
      const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
      return { file, privateKey, kid: null, directory: null };
    }
  }

  function saveAccount(account, directory) {
    writePrivate(account.file, JSON.stringify({
      privateKeyPem: account.privateKey.export({ type: "pkcs8", format: "pem" }),
      kid: account.kid,
      directory,
    }));
  }

  function publicJwk(privateKey) {
    const { crv, kty, x, y } = crypto.createPublicKey(privateKey).export({ format: "jwk" });
    return { crv, kty, x, y };
  }

  async function acmeRequest(client, url, payload, { useJwk = false } = {}) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      if (!client.nonce) {
        const head = await fetch(client.directory.newNonce, { method: "HEAD", signal: AbortSignal.timeout(15000) });
        client.nonce = head.headers.get("replay-nonce");
      }
      const protectedHeader = {
        alg: "ES256",
        nonce: client.nonce,
        url,
        ...(useJwk ? { jwk: publicJwk(client.account.privateKey) } : { kid: client.account.kid }),
      };
      const encodedHeader = base64url(JSON.stringify(protectedHeader));
      const encodedPayload = payload === "" ? "" : base64url(JSON.stringify(payload));
      const signature = crypto.sign("sha256", Buffer.from(`${encodedHeader}.${encodedPayload}`), {
        key: client.account.privateKey,
        dsaEncoding: "ieee-p1363",
      });
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/jose+json", accept: "application/json, application/pem-certificate-chain" },
        body: JSON.stringify({ protected: encodedHeader, payload: encodedPayload, signature: base64url(signature) }),
        signal: AbortSignal.timeout(30000),
      });
      client.nonce = response.headers.get("replay-nonce");
      const text = await response.text();
      const contentType = response.headers.get("content-type") || "";
      let body = text;
      if (contentType.includes("json")) {
        try { body = JSON.parse(text); } catch { body = {}; }
      }
      if (response.status === 400 && body?.type === "urn:ietf:params:acme:error:badNonce" && attempt < 2) continue;
      if (!response.ok) {
        const detail = typeof body === "object" && body?.detail ? body.detail : `HTTP ${response.status}`;
        throw new Error(`ACME server error: ${String(detail).slice(0, 400)}`);
      }
      return { body, headers: response.headers };
    }
    throw new Error("ACME server rejected the request nonce repeatedly.");
  }

  async function pollUntil(client, url, isDone, label) {
    const deadline = Date.now() + 120000;
    for (;;) {
      const { body } = await acmeRequest(client, url, "");
      const outcome = isDone(body);
      if (outcome) return body;
      if (Date.now() > deadline) throw new Error(`Timed out waiting for ${label}.`);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }

  async function issue(config) {
    const { domain, email, environment } = config;
    step(`Contacting ${environment === "production" ? "Let's Encrypt" : "the staging ACME server"}…`);
    const directoryResponse = await fetch(directoryUrl(environment), { signal: AbortSignal.timeout(15000) });
    if (!directoryResponse.ok) throw new Error(`ACME directory returned HTTP ${directoryResponse.status}.`);
    const directory = await directoryResponse.json();
    const account = loadAccount(environment);
    const client = { directory, account, nonce: null };

    if (!account.kid || account.directory !== directoryUrl(environment)) {
      step("Registering ACME account…");
      const registration = await acmeRequest(client, directory.newAccount, {
        termsOfServiceAgreed: true,
        ...(email ? { contact: [`mailto:${email}`] } : {}),
      }, { useJwk: true });
      account.kid = registration.headers.get("location");
      saveAccount(account, directoryUrl(environment));
    }

    step(`Creating order for ${domain}…`);
    const order = await acmeRequest(client, directory.newOrder, {
      identifiers: [{ type: "dns", value: domain }],
    });
    const orderUrl = order.headers.get("location");
    const authorizationUrl = order.body.authorizations?.[0];
    if (!authorizationUrl) throw new Error("The ACME server returned no authorization.");

    const authorization = (await acmeRequest(client, authorizationUrl, "")).body;
    let challenge;
    if (authorization.status !== "valid") {
      challenge = authorization.challenges?.find((item) => item.type === "http-01");
      if (!challenge) throw new Error("The ACME server did not offer an HTTP-01 challenge.");
      const thumbprint = crypto.createHash("sha256")
        .update(JSON.stringify(publicJwk(account.privateKey)))
        .digest("base64url");
      challenges.set(challenge.token, `${challenge.token}.${thumbprint}`);
      step("Answering the HTTP-01 challenge on /.well-known/acme-challenge/ …");
      try {
        await acmeRequest(client, challenge.url, {});
        await pollUntil(client, authorizationUrl, (body) => {
          if (body.status === "valid") return true;
          if (body.status === "invalid") {
            const failure = body.challenges?.find((item) => item.error)?.error?.detail;
            throw new Error(`Domain validation failed: ${failure || "the ACME server could not reach this host on port 80."}`);
          }
          return false;
        }, "domain validation");
      } finally {
        challenges.delete(challenge.token);
      }
      step("Domain validated.");
    }

    step("Generating certificate key and signing request…");
    const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const csr = buildCsr(domain, keyPair.privateKey, keyPair.publicKey);
    await acmeRequest(client, order.body.finalize, { csr: base64url(csr) });
    const finished = await pollUntil(client, orderUrl, (body) => {
      if (body.status === "valid") return true;
      if (body.status === "invalid") throw new Error("The ACME server rejected the certificate order.");
      return false;
    }, "certificate issuance");

    step("Downloading certificate…");
    const chain = (await acmeRequest(client, finished.certificate, "")).body;
    if (typeof chain !== "string" || !chain.includes("BEGIN CERTIFICATE")) {
      throw new Error("The ACME server returned an invalid certificate.");
    }
    const keyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" });
    const certificate = new crypto.X509Certificate(chain);
    if (!certificate.checkPrivateKey(keyPair.privateKey)) {
      throw new Error("The issued certificate does not match the generated key.");
    }
    writePrivate(keyPath, keyPem);
    writePrivate(certPath, chain);
    writePrivate(metaPath, JSON.stringify({ environment, domain, issuedAt: new Date().toISOString() }));
    step("Certificate installed.");
    onCertificate({ key: keyPem, cert: chain });
  }

  function start(source = "manual") {
    if (running) return { started: false, reason: "A certificate request is already in progress." };
    const config = getConfig();
    if (!config?.domain) return { started: false, reason: "Save a domain name first." };
    running = true;
    status.state = "running";
    status.steps = [];
    status.message = "";
    status.finishedAt = null;
    step(source === "renewal" ? "Automatic renewal started." : "Certificate request started.");
    issue(config).then(() => {
      status.state = "success";
    }).catch((error) => {
      log.error("ACME issuance failed:", error);
      status.state = "error";
      status.message = error.message || "Certificate request failed.";
      status.steps.push(status.message);
    }).finally(() => {
      running = false;
      status.finishedAt = new Date().toISOString();
    });
    return { started: true };
  }

  function loadStored() {
    try {
      const key = fs.readFileSync(keyPath, "utf8");
      const cert = fs.readFileSync(certPath, "utf8");
      return { key, cert };
    } catch {
      return null;
    }
  }

  function describeCertificate() {
    const stored = loadStored();
    if (!stored) return null;
    try {
      const certificate = new crypto.X509Certificate(stored.cert);
      let meta = {};
      try { meta = JSON.parse(fs.readFileSync(metaPath, "utf8")); } catch { /* optional */ }
      const validTo = new Date(certificate.validTo);
      return {
        subject: (certificate.subject || "").replace(/^CN=/, ""),
        issuer: (certificate.issuer || "").replace(/\n/g, ", "),
        domains: (certificate.subjectAltName || "").split(",").map((item) => item.trim().replace(/^DNS:/, "")).filter(Boolean),
        validFrom: new Date(certificate.validFrom).toISOString(),
        validTo: validTo.toISOString(),
        daysRemaining: Math.floor((validTo.getTime() - Date.now()) / 86400000),
        environment: meta.environment || null,
        domain: meta.domain || null,
      };
    } catch {
      return null;
    }
  }

  function renewalDue() {
    const config = getConfig();
    const info = describeCertificate();
    if (!config?.domain || !config.autoRenew) return false;
    if (!info) return false;
    if (info.domain && info.domain !== config.domain) return false;
    return new Date(info.validTo).getTime() - Date.now() < renewBeforeMs;
  }

  function startRenewalTimer() {
    const check = () => {
      if (!running && renewalDue()) start("renewal");
    };
    setTimeout(check, 60 * 1000).unref();
    setInterval(check, 12 * 60 * 60 * 1000).unref();
  }

  return {
    challenges,
    status,
    start,
    loadStored,
    describeCertificate,
    startRenewalTimer,
    isRunning: () => running,
  };
}

module.exports = { createAcmeManager };
