// OpenID Connect sign-in (authorization code flow with PKCE) without external libraries:
// provider discovery, the token request and ID token verification against the
// provider's published keys (RS256, PS256, ES256 and EdDSA).
const crypto = require("node:crypto");

const discoveryCache = new Map();
const jwksCache = new Map();
const cacheMs = 3600_000;
const timeoutMs = 10_000;

function issuerUrl(value) {
  let url;
  try {
    url = new URL(String(value || "").trim());
  } catch {
    throw new Error("Enter the issuer as a full URL, such as https://login.example.com/realms/main.");
  }
  // Plain HTTP is only allowed for a provider on this machine (for testing).
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Error("The issuer must use https://.");
  if (url.username || url.password || url.search || url.hash) throw new Error("The issuer URL must not contain credentials, a query or a fragment.");
  return url.href.replace(/\/$/, "");
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json", ...options.headers } });
  const text = await response.text();
  if (text.length > 1024 * 1024) throw new Error("The provider sent too much data.");
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`The provider did not return JSON (HTTP ${response.status}).`);
  }
  if (!response.ok) throw new Error(data.error_description || data.error || `The provider returned HTTP ${response.status}.`);
  return data;
}

async function discover(issuer) {
  const cached = discoveryCache.get(issuer);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  const config = await fetchJson(`${issuer}/.well-known/openid-configuration`);
  if (String(config.issuer || "").replace(/\/$/, "") !== issuer) throw new Error(`The provider says its issuer is "${config.issuer}", not "${issuer}".`);
  for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
    try {
      const url = new URL(config[key]);
      if (url.protocol !== "https:" && new URL(issuer).protocol === "https:") throw new Error();
    } catch {
      throw new Error(`The provider's ${key} is missing or not https.`);
    }
  }
  discoveryCache.set(issuer, { value: config, expiresAt: Date.now() + cacheMs });
  return config;
}

async function signingKey(jwksUri, kid, alg) {
  for (const refresh of [false, true]) {
    let cached = jwksCache.get(jwksUri);
    if (refresh || !cached || cached.expiresAt < Date.now()) {
      const jwks = await fetchJson(jwksUri);
      cached = { keys: Array.isArray(jwks.keys) ? jwks.keys : [], expiresAt: Date.now() + cacheMs };
      jwksCache.set(jwksUri, cached);
    }
    const jwk = cached.keys.find((key) => (kid ? key.kid === kid : true) && (!key.use || key.use === "sig") && (!key.alg || key.alg === alg));
    if (jwk) return crypto.createPublicKey({ key: jwk, format: "jwk" });
  }
  throw new Error("The provider's signing key for this token was not found.");
}

async function verifyIdToken(idToken, { issuer, clientId, nonce, jwksUri }) {
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) throw new Error("The provider returned an invalid ID token.");
  let header;
  let claims;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new Error("The ID token could not be read.");
  }
  const algorithms = {
    RS256: (key) => ["sha256", key],
    PS256: (key) => ["sha256", { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }],
    ES256: (key) => ["sha256", { key, dsaEncoding: "ieee-p1363" }],
    EdDSA: (key) => [null, key],
  };
  if (!algorithms[header.alg]) throw new Error(`ID tokens signed with ${header.alg} are not supported.`);
  const key = await signingKey(jwksUri, header.kid, header.alg);
  const [digest, verifyKey] = algorithms[header.alg](key);
  const valid = crypto.verify(digest, Buffer.from(`${parts[0]}.${parts[1]}`), verifyKey, Buffer.from(parts[2], "base64url"));
  if (!valid) throw new Error("The ID token signature is not valid.");
  const now = Math.floor(Date.now() / 1000);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (String(claims.iss || "").replace(/\/$/, "") !== issuer) throw new Error("The ID token comes from a different issuer.");
  if (!audiences.includes(clientId)) throw new Error("The ID token was issued for a different application.");
  if (audiences.length > 1 && claims.azp && claims.azp !== clientId) throw new Error("The ID token was issued for a different application.");
  if (typeof claims.exp !== "number" || claims.exp < now - 60) throw new Error("The ID token has expired.");
  if (typeof claims.iat === "number" && claims.iat > now + 300) throw new Error("The ID token is dated in the future; check the server clocks.");
  if (claims.nonce !== nonce) throw new Error("The sign-in response does not match this request.");
  if (typeof claims.sub !== "string" || !claims.sub) throw new Error("The ID token has no subject.");
  return claims;
}

// Returns the authorization URL and the values that must be kept until the callback.
async function startLogin({ issuer, clientId, redirectUri, scopes }) {
  const config = await discover(issuer);
  const state = crypto.randomBytes(24).toString("base64url");
  const nonce = crypto.randomBytes(24).toString("base64url");
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const url = new URL(config.authorization_endpoint);
  for (const [name, value] of Object.entries({
    response_type: "code", client_id: clientId, redirect_uri: redirectUri, scope: scopes,
    state, nonce, code_challenge: challenge, code_challenge_method: "S256",
  })) url.searchParams.set(name, value);
  return { url: url.href, state, nonce, verifier };
}

async function finishLogin({ issuer, clientId, clientSecret, redirectUri, code, verifier, nonce }) {
  const config = await discover(issuer);
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier });
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  const methods = config.token_endpoint_auth_methods_supported || ["client_secret_basic"];
  if (clientSecret && !methods.includes("client_secret_basic") && methods.includes("client_secret_post")) body.set("client_secret", clientSecret);
  else if (clientSecret) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString("base64")}`;
  const tokens = await fetchJson(config.token_endpoint, { method: "POST", headers, body: body.toString() });
  return verifyIdToken(tokens.id_token, { issuer, clientId, nonce, jwksUri: config.jwks_uri });
}

module.exports = { issuerUrl, discover, startLogin, finishLogin };
