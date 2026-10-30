// Browser side of passkeys: converts the server's JSON options to the binary form the
// WebAuthn API expects, and the browser's answer back to JSON.
(function exportPasskeys(global) {
  const toBytes = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=")), (c) => c.charCodeAt(0));
  const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  function passkeysSupported() {
    return Boolean(global.isSecureContext && global.PublicKeyCredential && navigator.credentials);
  }

  async function postJson(path, body) {
    const response = await fetch(path, { method: "POST", credentials: "same-origin", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "The passkey request failed.");
    return result;
  }

  function explain(error) {
    if (error?.name === "NotAllowedError") return new Error("The passkey request was cancelled or timed out.");
    if (error?.name === "InvalidStateError") return new Error("This device already has a passkey for your account.");
    if (error?.name === "SecurityError") return new Error("Passkeys need HTTPS (or localhost) and the site's real host name.");
    return error;
  }

  async function registerPasskey(name) {
    const { challengeId, publicKey } = await postJson("/api/auth/passkeys/register/options");
    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: {
          ...publicKey,
          challenge: toBytes(publicKey.challenge),
          user: { ...publicKey.user, id: toBytes(publicKey.user.id) },
          excludeCredentials: publicKey.excludeCredentials.map((item) => ({ ...item, id: toBytes(item.id) })),
        },
      });
    } catch (error) {
      throw explain(error);
    }
    return postJson("/api/auth/passkeys/register", {
      challengeId,
      name,
      clientDataJSON: toText(credential.response.clientDataJSON),
      attestationObject: toText(credential.response.attestationObject),
    });
  }

  async function signInWithPasskey() {
    const { challengeId, publicKey } = await postJson("/api/auth/passkeys/login/options");
    let credential;
    try {
      credential = await navigator.credentials.get({ publicKey: { ...publicKey, challenge: toBytes(publicKey.challenge), allowCredentials: [] } });
    } catch (error) {
      throw explain(error);
    }
    return postJson("/api/auth/passkeys/login", {
      challengeId,
      id: toText(credential.rawId),
      clientDataJSON: toText(credential.response.clientDataJSON),
      authenticatorData: toText(credential.response.authenticatorData),
      signature: toText(credential.response.signature),
      userHandle: credential.response.userHandle ? toText(credential.response.userHandle) : null,
    });
  }

  global.bngPasskeys = { passkeysSupported, registerPasskey, signInWithPasskey };
}(window));
