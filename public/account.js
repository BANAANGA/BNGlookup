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
  return requested.startsWith("/") && !requested.startsWith("//") && !requested.includes("\\")
    ? requested
    : "/";
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

if (setupForm) submitAccountForm(setupForm, "/api/auth/setup", true);
if (loginForm) submitAccountForm(loginForm, "/api/auth/login");
if (changeForm) submitAccountForm(changeForm, "/api/auth/change-password", true);
