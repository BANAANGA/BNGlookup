const setupForm = document.querySelector("#setup-form");
const loginForm = document.querySelector("#login-form");
const changeForm = document.querySelector("#change-form");
const errorMessage = document.querySelector("#auth-error");

function showAuthError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function safeNextPath() {
  const requested = new URLSearchParams(window.location.search).get("next") || "/";
  // Browsers drop tabs and newlines from URLs, so "/\t/evil.example" would become
  // "//evil.example". Resolve the value the way the browser will and require our origin.
  if (!requested.startsWith("/") || /[\u0000-\u001f\u007f\\]/.test(requested)) return "/";
  try {
    const resolved = new URL(requested, window.location.origin);
    return resolved.origin === window.location.origin
      ? `${resolved.pathname}${resolved.search}${resolved.hash}`
      : "/";
  } catch {
    return "/";
  }
}

async function submitAccountForm(form, endpoint, includePasswordConfirmation = false) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorMessage.hidden = true;
    const values = Object.fromEntries(new FormData(form));
    if (includePasswordConfirmation && (values.password ?? values.newPassword) !== values.confirmPassword) {
      showAuthError("The passwords do not match.");
      return;
    }
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(values),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Unable to sign in.");
      if (result.twoFactorRequired) {
        startTwoFactor(result.challenge);
        return;
      }
      if (result.mustChangePassword) {
        window.location.assign("/change-password.html");
        return;
      }
      window.location.assign(
        endpoint.endsWith("/setup") ? "/admin.html"
          : endpoint.endsWith("/change-password") ? (result.role === "admin" ? "/admin.html" : "/")
            : safeNextPath(),
      );
    } catch (error) {
      showAuthError(error.message || "Unable to complete the request.");
    } finally {
      button.disabled = false;
    }
  });
}

if (setupForm) {
  submitAccountForm(setupForm, "/api/auth/setup", true);
  fetch("/api/auth/status", { credentials: "same-origin" })
    .then((response) => response.json())
    .then((status) => {
      if (!status.setupTokenRequired) return;
      document.querySelector("#setup-token-field").hidden = false;
      document.querySelector("#setup-token").required = true;
    })
    .catch(() => {});
}
// Second sign-in step for accounts with two-factor login.
function startTwoFactor(challenge) {
  const twoFactorForm = document.querySelector("#twofactor-form");
  const codeInput = document.querySelector("#twofactor-code");
  const twoFactorError = document.querySelector("#twofactor-error");
  loginForm.hidden = true;
  twoFactorForm.hidden = false;
  codeInput.value = "";
  codeInput.focus();
  twoFactorForm.onsubmit = async (event) => {
    event.preventDefault();
    twoFactorError.hidden = true;
    const button = twoFactorForm.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const response = await fetch("/api/auth/login/2fa", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ challenge, code: codeInput.value.trim() }),
      });
      const result = await response.json();
      if (!response.ok) {
        if (result.restart) {
          twoFactorForm.hidden = true;
          loginForm.hidden = false;
          loginForm.elements.password.value = "";
          showAuthError(result.error);
          return;
        }
        throw new Error(result.error || "That code is not valid.");
      }
      if (result.recoveryCodeUsed) {
        window.alert(`You signed in with a recovery code. ${result.recoveryCodesLeft} recovery code(s) left; create new ones on My account if you are running low.`);
      }
      window.location.assign(result.mustChangePassword ? "/change-password.html" : safeNextPath());
    } catch (error) {
      twoFactorError.textContent = error.message;
      twoFactorError.hidden = false;
      codeInput.select();
    } finally {
      button.disabled = false;
    }
  };
}

if (loginForm) {
  submitAccountForm(loginForm, "/api/auth/login");
  const ssoError = new URLSearchParams(window.location.search).get("sso_error");
  if (ssoError) showAuthError(ssoError);
  const altLogins = document.querySelector("#alt-logins");
  const passkeyButton = document.querySelector("#passkey-login");
  const ssoLink = document.querySelector("#sso-login");
  if (window.bngPasskeys?.passkeysSupported()) {
    passkeyButton.hidden = false;
    altLogins.hidden = false;
    passkeyButton.addEventListener("click", async () => {
      errorMessage.hidden = true;
      passkeyButton.disabled = true;
      try {
        const result = await window.bngPasskeys.signInWithPasskey();
        if (result.twoFactorRequired) {
          startTwoFactor(result.challenge);
          return;
        }
        window.location.assign(result.mustChangePassword ? "/change-password.html" : safeNextPath());
      } catch (error) {
        showAuthError(error.message);
      } finally {
        passkeyButton.disabled = false;
      }
    });
  }
  fetch("/api/auth/status", { credentials: "same-origin" })
    .then((response) => response.json())
    .then((status) => {
      if (!status.sso) return;
      ssoLink.textContent = `Sign in with ${status.sso.label}`;
      ssoLink.href = `/api/auth/oidc/start?${new URLSearchParams({ next: safeNextPath() })}`;
      ssoLink.hidden = false;
      altLogins.hidden = false;
    })
    .catch(() => {});
}
if (changeForm) submitAccountForm(changeForm, "/api/auth/change-password", true);
