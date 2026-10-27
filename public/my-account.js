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

load();
loadShares();
