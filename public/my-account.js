const form = document.querySelector("#email-form");
const errorMessage = document.querySelector("#auth-error");
const successMessage = document.querySelector("#auth-success");
const hint = document.querySelector("#mail-hint");

async function load() {
  const response = await fetch("/api/account", { credentials: "same-origin" });
  if (response.status === 401) {
    window.location.assign("/login.html?next=%2Fmy-account.html");
    return;
  }
  const account = await response.json();
  form.elements.email.value = account.email || "";
  renderTwoFactor(account.twoFactor || { enabled: false });
  if (account.apiTokensAllowed) loadTokens();
  hint.textContent = account.mailEnabled
    ? "With an email address saved, an “Email these results to me” button appears below your results."
    : "Email is not configured on this server yet; an administrator can enable it in Settings.";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  successMessage.hidden = true;
  try {
    const response = await fetch("/api/account", {
      method: "PUT",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: form.elements.email.value }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Unable to save.");
    successMessage.textContent = result.email ? "Email address saved." : "Email address removed.";
    successMessage.hidden = false;
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
});

const shareList = document.querySelector("#share-list");

function escapeAccountHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

async function loadShares() {
  try {
    const response = await fetch("/api/shares", { credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load shared links.");
    shareList.innerHTML = data.shares.length
      ? data.shares.map((share) => `
        <div class="share-row">
          <div><a href="${escapeAccountHtml(share.url)}">${escapeAccountHtml(share.title)}</a>
            <span>${escapeAccountHtml(`Created ${new Date(share.createdAt).toLocaleString()} · expires ${new Date(share.expiresAt).toLocaleDateString()}`)}</span></div>
          <button type="button" data-share-id="${escapeAccountHtml(share.id)}">Delete</button>
        </div>`).join("")
      : '<p class="form-hint">You have not shared any results.</p>';
  } catch (error) {
    shareList.innerHTML = `<p class="error-message">${escapeAccountHtml(error.message)}</p>`;
  }
}

shareList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-share-id]");
  if (!button || !window.confirm("Delete this share link? Anyone using it will no longer see the result.")) return;
  button.disabled = true;
  try {
    const response = await fetch(`/api/shares/${encodeURIComponent(button.dataset.shareId)}`, { method: "DELETE", credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to delete the link.");
    await loadShares();
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
    button.disabled = false;
  }
});

// ---------------------------------------------------------------- Two-factor login

const twoFactorPanel = document.querySelector("#twofactor-panel");

async function postAccount(path, body, method = "POST") {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function recoveryCodesHtml(codes) {
  return `
    <div class="recovery-codes">
      <p><strong>Save these recovery codes now.</strong> Each one signs you in once if you lose your phone. They are not shown again.</p>
      <ol>${codes.map((code) => `<li><code>${escapeAccountHtml(code)}</code></li>`).join("")}</ol>
      <button type="button" class="dash-version-check" id="copy-recovery">Copy codes</button>
    </div>`;
}

function renderTwoFactor(status, extra = "") {
  if (status.enabled) {
    twoFactorPanel.innerHTML = `
      <p class="twofactor-state on">✓ Two-factor login is on. ${escapeAccountHtml(`${status.recoveryCodesLeft} recovery code(s) left.`)}</p>
      ${extra}
      <form class="account-form" id="twofactor-manage">
        <label for="tf-password">Password</label>
        <input id="tf-password" name="password" type="password" maxlength="128" autocomplete="current-password" required>
        <label for="tf-code">Code from your app</label>
        <input id="tf-code" name="code" type="text" maxlength="16" inputmode="numeric" autocomplete="one-time-code" required>
        <div class="twofactor-actions">
          <button type="submit" class="dash-version-check" name="action" value="recovery-codes">New recovery codes</button>
          <button type="submit" class="dash-version-check danger" name="action" value="disable">Turn off</button>
        </div>
      </form>`;
    return;
  }
  twoFactorPanel.innerHTML = `
    <p class="twofactor-state">Two-factor login is off. Turn it on to require a code from an authenticator app (such as Google Authenticator, Microsoft Authenticator, 1Password or Aegis) after your password.</p>
    <form class="account-form" id="twofactor-start">
      <label for="tf-start-password">Confirm your password</label>
      <input id="tf-start-password" name="password" type="password" maxlength="128" autocomplete="current-password" required>
      <button type="submit" class="submit-button"><span>Set up two-factor login</span><span aria-hidden="true">→</span></button>
    </form>`;
}

twoFactorPanel.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  errorMessage.hidden = true;
  successMessage.hidden = true;
  try {
    if (form.id === "twofactor-start") {
      const setup = await postAccount("/api/account/2fa/setup", { password: form.elements.password.value });
      twoFactorPanel.innerHTML = `
        <div class="twofactor-setup">
          <div class="twofactor-qr">${window.qrSvg ? window.qrSvg(setup.uri) : ""}</div>
          <div>
            <p>1. Scan this code with your authenticator app, or enter the key by hand:</p>
            <p><code class="twofactor-secret">${escapeAccountHtml(setup.secret.replace(/(.{4})/g, "$1 ").trim())}</code></p>
            <p>2. Enter the 6-digit code the app shows:</p>
            <form class="account-form" id="twofactor-confirm">
              <input name="code" type="text" maxlength="6" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required aria-label="6-digit code">
              <button type="submit" class="submit-button"><span>Turn on</span><span aria-hidden="true">→</span></button>
            </form>
          </div>
        </div>`;
      twoFactorPanel.querySelector("input[name=code]").focus();
    } else if (form.id === "twofactor-confirm") {
      const result = await postAccount("/api/account/2fa/enable", { code: form.elements.code.value });
      renderTwoFactor({ enabled: true, recoveryCodesLeft: result.recoveryCodes.length }, recoveryCodesHtml(result.recoveryCodes));
    } else if (form.id === "twofactor-manage") {
      const action = event.submitter?.value || "recovery-codes";
      if (action === "disable" && !window.confirm("Turn off two-factor login? Your account will be protected by the password only.")) return;
      const result = await postAccount(`/api/account/2fa/${action}`, { password: form.elements.password.value, code: form.elements.code.value });
      if (action === "disable") {
        renderTwoFactor({ enabled: false });
        successMessage.textContent = "Two-factor login is off.";
        successMessage.hidden = false;
      } else {
        renderTwoFactor({ enabled: true, recoveryCodesLeft: result.recoveryCodes.length }, recoveryCodesHtml(result.recoveryCodes));
      }
    }
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
    errorMessage.scrollIntoView({ block: "center" });
  }
});

twoFactorPanel.addEventListener("click", async (event) => {
  if (!event.target.closest("#copy-recovery")) return;
  const codes = [...twoFactorPanel.querySelectorAll(".recovery-codes code")].map((code) => code.textContent).join("\n");
  try {
    await navigator.clipboard.writeText(codes);
    event.target.textContent = "Copied";
  } catch {
    event.target.textContent = "Select and copy the codes manually";
  }
});

// ---------------------------------------------------------------- API tokens

const tokensPanel = document.querySelector("#tokens-panel");

async function loadTokens() {
  document.querySelector("#tokens-heading").hidden = false;
  tokensPanel.hidden = false;
  try {
    const response = await fetch("/api/account/tokens", { credentials: "same-origin" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load tokens.");
    renderTokens(data);
  } catch (error) {
    tokensPanel.innerHTML = `<p class="error-message">${escapeAccountHtml(error.message)}</p>`;
  }
}

function renderTokens(data, created = null) {
  const origin = window.location.origin;
  tokensPanel.innerHTML = `
    <p class="form-hint">Tokens let scripts call the lookup tools as you, with your access rights: send <code>Authorization: Bearer &lt;token&gt;</code>. They cannot change your account or admin settings. Up to ${escapeAccountHtml(data.limit)} tokens, ${escapeAccountHtml(data.requestsPerHour)} requests per hour each.</p>
    ${created ? `
      <div class="recovery-codes">
        <p><strong>Copy your new token now.</strong> It is not shown again.</p>
        <p><code class="token-value">${escapeAccountHtml(created.token)}</code></p>
        <p class="form-hint">Example: <code>curl -H "Authorization: Bearer ${escapeAccountHtml(created.token.slice(0, 12))}…" "${escapeAccountHtml(origin)}/api/lookup?name=example.com&amp;type=A"</code></p>
      </div>` : ""}
    <form class="token-form" id="token-form">
      <input name="name" type="text" maxlength="60" placeholder="Token name, e.g. monitoring script" required aria-label="Token name">
      <select name="expires" aria-label="Expiry">
        <option value="90">Expires in 90 days</option>
        <option value="30">Expires in 30 days</option>
        <option value="365">Expires in 1 year</option>
        <option value="">Never expires</option>
      </select>
      <button type="submit" class="dash-version-check">Create token</button>
    </form>
    ${data.tokens.length ? `<div class="share-list">${data.tokens.map((token) => `
      <div class="share-row">
        <div><strong>${escapeAccountHtml(token.name)}</strong>
          <span>${escapeAccountHtml(`${token.prefix}… · created ${new Date(token.createdAt).toLocaleDateString()} · ${token.lastUsedAt ? `last used ${new Date(token.lastUsedAt).toLocaleString()}` : "never used"} · ${token.expiresAt ? `expires ${new Date(token.expiresAt).toLocaleDateString()}` : "no expiry"}`)}</span></div>
        <button type="button" data-token-id="${escapeAccountHtml(token.id)}">Revoke</button>
      </div>`).join("")}</div>` : '<p class="form-hint">No tokens yet.</p>'}`;
}

tokensPanel.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const created = await postAccount("/api/account/tokens", { name: form.elements.name.value, expiresInDays: form.elements.expires.value ? Number(form.elements.expires.value) : null });
    const response = await fetch("/api/account/tokens", { credentials: "same-origin" });
    renderTokens(await response.json(), created);
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
});

tokensPanel.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-token-id]");
  if (!button || !window.confirm("Revoke this token? Scripts using it will stop working immediately.")) return;
  try {
    const response = await fetch(`/api/account/tokens/${encodeURIComponent(button.dataset.tokenId)}`, { method: "DELETE", credentials: "same-origin" });
    if (!response.ok) throw new Error((await response.json()).error || "Unable to revoke the token.");
    await loadTokens();
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
});

load();
loadShares();
