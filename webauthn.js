// Minimal WebAuthn (passkey) verification without external libraries: a CBOR decoder,
// COSE key conversion and the registration and authentication checks of the WebAuthn
// Level 2 specification. Attestation statements are not verified (the server asks for
// attestation "none"), so a passkey proves possession of a key, not its maker.
const crypto = require("node:crypto");

const b64url = {
  encode: (buffer) => Buffer.from(buffer).toString("base64url"),
  decode: (text) => {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("Invalid base64url data.");
    return Buffer.from(text, "base64url");
  },
};

// Decodes one CBOR item and returns [value, nextOffset]. Supports what WebAuthn uses:
// integers, byte and text strings, arrays, maps, booleans and null.
function decodeCbor(buffer, offset = 0, depth = 0) {
  if (depth > 16) throw new Error("CBOR data is nested too deeply.");
  if (offset >= buffer.length) throw new Error("CBOR data ended early.");
  const initial = buffer[offset];
  const major = initial >> 5;
  const info = initial & 0x1f;
  let position = offset + 1;
  let length;
  if (info < 24) length = info;
  else if (info === 24) length = buffer.readUInt8(position), position += 1;
  else if (info === 25) length = buffer.readUInt16BE(position), position += 2;
  else if (info === 26) length = buffer.readUInt32BE(position), position += 4;
  else if (info === 27) {
    const big = buffer.readBigUInt64BE(position);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("CBOR integer is too large.");
    length = Number(big);
    position += 8;
  } else throw new Error("Unsupported CBOR encoding.");
  if (major === 0) return [length, position];
  if (major === 1) return [-1 - length, position];
  if (major === 2 || major === 3) {
    if (position + length > buffer.length) throw new Error("CBOR string runs past the end.");
    const bytes = buffer.subarray(position, position + length);
    return [major === 2 ? Buffer.from(bytes) : bytes.toString("utf8"), position + length];
  }
  if (major === 4) {
    if (length > 1024) throw new Error("CBOR array is too long.");
    const items = [];
    for (let index = 0; index < length; index += 1) {
      const [item, next] = decodeCbor(buffer, position, depth + 1);
      items.push(item);
      position = next;
    }
    return [items, position];
  }
  if (major === 5) {
    if (length > 256) throw new Error("CBOR map is too long.");
    const map = new Map();
    for (let index = 0; index < length; index += 1) {
      const [key, afterKey] = decodeCbor(buffer, position, depth + 1);
      const [value, afterValue] = decodeCbor(buffer, afterKey, depth + 1);
      map.set(key, value);
      position = afterValue;
    }
    return [map, position];
  }
  if (major === 7) {
    if (info === 20) return [false, position];
    if (info === 21) return [true, position];
    if (info === 22) return [null, position];
  }
  throw new Error("Unsupported CBOR item.");
}

// COSE_Key (RFC 9053) to a Node public key. Supported: ES256 (-7), EdDSA/Ed25519 (-8), RS256 (-257).
function coseToPublicKey(cose) {
  if (!(cose instanceof Map)) throw new Error("The credential public key is not a COSE key.");
  const kty = cose.get(1);
  const alg = cose.get(3);
  let jwk;
  if (kty === 2 && alg === -7 && cose.get(-1) === 1) {
    jwk = { kty: "EC", crv: "P-256", x: b64url.encode(cose.get(-2)), y: b64url.encode(cose.get(-3)) };
  } else if (kty === 1 && alg === -8 && cose.get(-1) === 6) {
    jwk = { kty: "OKP", crv: "Ed25519", x: b64url.encode(cose.get(-2)) };
  } else if (kty === 3 && alg === -257) {
    jwk = { kty: "RSA", n: b64url.encode(cose.get(-1)), e: b64url.encode(cose.get(-2)) };
  } else {
    throw new Error("This passkey uses an unsupported algorithm.");
  }
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  if (kty === 3 && key.asymmetricKeyDetails?.modulusLength < 2048) throw new Error("The passkey's RSA key is too short.");
  return { key, alg };
}

function parseAuthenticatorData(data) {
  if (data.length < 37) throw new Error("The authenticator data is too short.");
  const flags = data[32];
  const result = {
    rpIdHash: data.subarray(0, 32),
    userPresent: Boolean(flags & 0x01),
    userVerified: Boolean(flags & 0x04),
    attested: Boolean(flags & 0x40),
    signCount: data.readUInt32BE(33),
  };
  if (result.attested) {
    if (data.length < 55) throw new Error("The attested credential data is too short.");
    const idLength = data.readUInt16BE(53);
    if (idLength < 16 || idLength > 1023 || data.length < 55 + idLength) throw new Error("The credential ID is invalid.");
    result.credentialId = data.subarray(55, 55 + idLength);
    const [cose] = decodeCbor(data, 55 + idLength);
    result.credentialPublicKey = cose;
  }
  return result;
}

function checkClientData(clientDataJSON, { type, challenge, origin }) {
  let clientData;
  try {
    clientData = JSON.parse(clientDataJSON.toString("utf8"));
  } catch {
    throw new Error("The browser response could not be read.");
  }
  if (clientData.type !== type) throw new Error("The browser response is of the wrong type.");
  if (clientData.challenge !== challenge) throw new Error("The challenge does not match; try again.");
  if (clientData.origin !== origin) throw new Error("The passkey was used on a different site.");
  if (clientData.crossOrigin === true) throw new Error("Passkeys cannot be used from an embedded frame.");
}

function checkRpId(authData, rpId) {
  const expected = crypto.createHash("sha256").update(rpId).digest();
  if (!crypto.timingSafeEqual(expected, authData.rpIdHash)) throw new Error("The passkey belongs to a different site.");
  if (!authData.userPresent) throw new Error("The passkey did not confirm user presence.");
}

// Verifies a navigator.credentials.create() response and returns the credential to store.
function verifyRegistration({ clientDataJSON, attestationObject, challenge, origin, rpId }) {
  const clientData = b64url.decode(clientDataJSON);
  checkClientData(clientData, { type: "webauthn.create", challenge, origin });
  const [attestation] = decodeCbor(b64url.decode(attestationObject));
  if (!(attestation instanceof Map) || !Buffer.isBuffer(attestation.get("authData"))) throw new Error("The attestation could not be read.");
  const authData = parseAuthenticatorData(attestation.get("authData"));
  checkRpId(authData, rpId);
  if (!authData.attested || !authData.credentialPublicKey) throw new Error("The passkey did not include its public key.");
  const { key, alg } = coseToPublicKey(authData.credentialPublicKey);
  return {
    credentialId: b64url.encode(authData.credentialId),
    publicKey: key.export({ type: "spki", format: "pem" }),
    algorithm: alg,
    signCount: authData.signCount,
    userVerified: authData.userVerified,
  };
}

// Verifies a navigator.credentials.get() response against a stored credential.
function verifyAuthentication({ clientDataJSON, authenticatorData, signature, challenge, origin, rpId, credential }) {
  const clientData = b64url.decode(clientDataJSON);
  checkClientData(clientData, { type: "webauthn.get", challenge, origin });
  const authBytes = b64url.decode(authenticatorData);
  const authData = parseAuthenticatorData(authBytes);
  checkRpId(authData, rpId);
  const signed = Buffer.concat([authBytes, crypto.createHash("sha256").update(clientData).digest()]);
  const key = crypto.createPublicKey(credential.publicKey);
  const sig = b64url.decode(signature);
  const valid = credential.algorithm === -8
    ? crypto.verify(null, signed, key, sig)
    : crypto.verify("sha256", signed, credential.algorithm === -7 ? { key, dsaEncoding: "der" } : key, sig);
  if (!valid) throw new Error("The passkey signature is not valid.");
  if (credential.signCount > 0 && authData.signCount <= credential.signCount) {
    throw new Error("This passkey's counter went backwards; it may have been copied. Remove it and add it again.");
  }
  return { signCount: authData.signCount, userVerified: authData.userVerified };
}

module.exports = { b64url, decodeCbor, verifyRegistration, verifyAuthentication };
