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
if (loginForm) submitAccountForm(loginForm, "/api/auth/login");
if (changeForm) submitAccountForm(changeForm, "/api/auth/change-password", true);
