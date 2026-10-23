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

load();
