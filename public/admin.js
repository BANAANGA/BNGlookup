const errorPanel = document.querySelector("#admin-error");
const successPanel = document.querySelector("#admin-success");
const featureSettings = document.querySelector("#feature-settings");
const dnsResolverSetting = document.querySelector("#dns-resolver-setting");
const trustedProxySetting = document.querySelector("#trusted-proxies");
const trustCloudflareProxiesSetting = document.querySelector("#trust-cloudflare-proxies");
const cloudflareProxyStatus = document.querySelector("#cloudflare-proxy-status");
const portScanSettings = document.querySelector("#port-scan-settings");
const nmapAllowedCidrs = document.querySelector("#nmap-allowed-cidrs");
const userList = document.querySelector("#user-list");
const settingsTabs = [...document.querySelectorAll(".settings-tab")];
const siteTitleSetting = document.querySelector("#site-title");
const siteIconUrlSetting = document.querySelector("#site-icon-url");
const siteIconUploadSetting = document.querySelector("#site-icon-upload");
const resetSiteIconSetting = document.querySelector("#reset-site-icon");
const brandingPreview = document.querySelector("#branding-preview");

function setSettingsTab(tab) {
  settingsTabs.forEach((item) => {
    const selected = item === tab;
    item.classList.toggle("active", selected);
    item.setAttribute("aria-selected", String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.querySelector(`#${item.getAttribute("aria-controls")}`).hidden = !selected;
  });
}

function renderBrandingPreview(iconUrl, note = "") {
  brandingPreview.replaceChildren();
  if (iconUrl) {
    const image = document.createElement("img");
    image.src = iconUrl;
    image.alt = "Current site icon preview";
    image.width = 40;
    image.height = 40;
    brandingPreview.append(image);
  }
  const caption = document.createElement("span");
  caption.textContent = note || (iconUrl ? "Current site icon" : "Using the default icon");
  brandingPreview.append(caption);
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      if (typeof reader.result !== "string") {
        reject(new Error("The selected icon could not be read."));
        return;
      }
      resolve(reader.result);
    });
    reader.addEventListener("error", () => reject(new Error("The selected icon could not be read.")));
    reader.readAsDataURL(file);
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function showAdminError(message) {
  successPanel.hidden = true;
  errorPanel.textContent = message;
  errorPanel.hidden = false;
}

function showAdminSuccess(message) {
  errorPanel.hidden = true;
  successPanel.textContent = message;
  successPanel.hidden = false;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...options.headers,
    },
  });
  const data = await response.json();
  if (response.status === 401) {
    window.location.assign(`/login.html?next=${encodeURIComponent("/admin.html")}`);
    throw new Error("Log in to continue.");
  }
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function renderFeatureSettings(features, access) {
  featureSettings.innerHTML = Object.entries(features).map(([key, label]) => `
    <label class="feature-setting" for="access-${escapeHtml(key)}">
      <span>${escapeHtml(label)}</span>
      <select id="access-${escapeHtml(key)}" name="${escapeHtml(key)}">
        <option value="public" ${access[key] === "public" ? "selected" : ""}>Public</option>
        <option value="user" ${access[key] === "user" ? "selected" : ""}>Logged-in users</option>
        <option value="admin" ${access[key] === "admin" ? "selected" : ""}>Administrators</option>
      </select>
    </label>
  `).join("");
}

function renderDnsResolverSetting(resolvers, selectedResolver) {
  dnsResolverSetting.innerHTML = `
    <label class="feature-setting" for="default-dns-resolver">
      <span>Default DNS resolver</span>
      <select id="default-dns-resolver" name="defaultDnsResolver">
        ${resolvers.map((resolver) => `
          <option value="${escapeHtml(resolver.id)}" ${selectedResolver === resolver.id ? "selected" : ""}>
            ${escapeHtml(resolver.label)}
          </option>
        `).join("")}
      </select>
    </label>
  `;
}

function renderPortScanSettings(policy) {
  portScanSettings.innerHTML = ["admin", "user"].map((role) => `
    <fieldset class="port-scan-role">
      <legend>${role === "admin" ? "Administrators" : "Users"}</legend>
      <label for="max-ports-${role}">Maximum unique TCP ports per target</label>
      <input id="max-ports-${role}" name="maxPorts-${role}" type="number" min="1" max="65535" value="${policy.maxPortsByRole[role]}" required>
      <label class="local-scan-setting" for="local-scan-${role}">
        <input id="local-scan-${role}" name="localScan-${role}" type="checkbox" ${policy.localScanByRole[role] ? "checked" : ""}>
        Allow private/local network targets
      </label>
    </fieldset>
  `).join("");
}

function renderUsers(users) {
  userList.innerHTML = users.map((user) => `
    <form class="user-row" data-user-id="${user.id}">
      <strong>${escapeHtml(user.username)}</strong>
      <label class="sr-only" for="user-role-${user.id}">Role for ${escapeHtml(user.username)}</label>
      <select id="user-role-${user.id}" name="role">
        <option value="user" ${user.role === "user" ? "selected" : ""}>User</option>
        <option value="admin" ${user.role === "admin" ? "selected" : ""}>Admin</option>
      </select>
      <input class="user-email" name="email" type="email" maxlength="254" value="${escapeHtml(user.email || "")}" placeholder="Email (optional)" autocomplete="off" aria-label="Email address for ${escapeHtml(user.username)}">
      <label class="user-active"><input type="checkbox" name="active" ${user.active ? "checked" : ""}> Active</label>
      <input class="user-reset-password" name="password" type="password" minlength="12" maxlength="128" placeholder="New password (optional)" autocomplete="new-password" aria-label="Set a new password for ${escapeHtml(user.username)}">
      <button type="submit">Save</button>
      <button type="button" class="user-delete" data-delete="${user.id}" data-name="${escapeHtml(user.username)}">Remove</button>
    </form>
  `).join("");
  userList.querySelectorAll(".user-row").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const values = Object.fromEntries(new FormData(form));
      values.active = form.elements.active.checked;
      if (!values.password) delete values.password;
      try {
        await api(`/api/admin/users/${form.dataset.userId}`, {
          method: "PATCH",
          body: JSON.stringify(values),
        });
        showAdminSuccess("User account updated.");
        await loadUsers();
      } catch (error) {
        showAdminError(error.message);
      }
    });
  });
}

userList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-delete]");
  if (!button) return;
  if (!window.confirm(`Permanently remove user "${button.dataset.name}"? This cannot be undone. To keep the account, disable it instead.`)) return;
  try {
    await api(`/api/admin/users/${button.dataset.delete}`, { method: "DELETE" });
    showAdminSuccess("User account removed.");
    await loadUsers();
  } catch (error) {
    showAdminError(error.message);
  }
});

const mailForm = document.querySelector("#mail-form");
const mailTestForm = document.querySelector("#mail-test-form");

function renderMailSettings(mail) {
  mailForm.elements.enabled.checked = mail.enabled;
  mailForm.elements.host.value = mail.host;
  mailForm.elements.port.value = mail.port;
  mailForm.elements.security.value = mail.security;
  mailForm.elements.username.value = mail.username;
  mailForm.elements.password.value = "";
  mailForm.elements.password.placeholder = mail.passwordSet
    ? "Password saved — leave empty to keep it"
    : "Leave empty if the server needs no login";
  mailForm.elements.from.value = mail.from;
  mailForm.elements.fromName.value = mail.fromName;
}

mailForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const values = Object.fromEntries(new FormData(mailForm));
    values.enabled = mailForm.elements.enabled.checked;
    values.port = Number(values.port);
    renderMailSettings(await api("/api/admin/mail", { method: "PUT", body: JSON.stringify(values) }));
    showAdminSuccess("Email settings saved.");
  } catch (error) {
    showAdminError(error.message);
  }
});

mailTestForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = mailTestForm.querySelector("button");
  button.disabled = true;
  try {
    await api("/api/admin/mail", {
      method: "POST",
      body: JSON.stringify({ to: mailTestForm.elements.to.value }),
    });
    showAdminSuccess("Test email sent.");
  } catch (error) {
    showAdminError(error.message);
  } finally {
    button.disabled = false;
  }
});

async function loadUsers() {
  const { users } = await api("/api/admin/users");
  renderUsers(users);
}

function setCloudflareProxyStatus(updatedAt) {
  cloudflareProxyStatus.textContent = updatedAt
    ? `Cloudflare IPv4 and IPv6 ranges were last refreshed ${new Date(updatedAt).toLocaleString()}. Cloudflare Tunnel users must also trust the local cloudflared connector address.`
    : "When enabled, official Cloudflare IPv4 and IPv6 ranges are refreshed automatically. Cloudflare Tunnel users must also trust the local cloudflared connector address.";
}

async function initializeAdmin() {
  try {
    const [settings, users, mail] = await Promise.all([
      api("/api/admin/settings"),
      api("/api/admin/users"),
      api("/api/admin/mail"),
    ]);
    renderMailSettings(mail);
    renderFeatureSettings(settings.features, settings.featureAccess);
    renderDnsResolverSetting(settings.dnsResolvers, settings.defaultDnsResolver);
    trustedProxySetting.value = settings.trustedProxies;
    trustCloudflareProxiesSetting.checked = settings.trustCloudflareProxies;
    setCloudflareProxyStatus(settings.cloudflareProxyUpdatedAt);
    renderPortScanSettings(settings.portScanPolicy);
    nmapAllowedCidrs.value = settings.nmapAllowedCidrs;
    siteTitleSetting.value = settings.branding.title;
    const customIcon = settings.branding.iconUrl !== "/favicon.svg";
    if (customIcon && !settings.branding.iconUrl.startsWith("data:image/")) {
      siteIconUrlSetting.value = settings.branding.iconUrl;
    }
    renderBrandingPreview(
      customIcon ? settings.branding.iconUrl : "/favicon.svg",
      customIcon ? "Current custom site icon" : "Using the default icon",
    );
    renderUsers(users.users);
  } catch (error) {
    if (!errorPanel.hidden) return;
    showAdminError(error.message);
  }
}

document.querySelector("#settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const activeTab = settingsTabs.find((tab) => tab.getAttribute("aria-selected") === "true");
    const activePanel = activeTab?.getAttribute("aria-controls");
    const settings = {};
    let iconFile = null;
    let siteIconUrl = "";
    if (activePanel === "general-panel") {
      iconFile = siteIconUploadSetting.files[0];
      if (iconFile && iconFile.size > 256 * 1024) {
        throw new Error("Choose an icon image no larger than 256 KB.");
      }
      siteIconUrl = siteIconUrlSetting.value.trim();
      if (iconFile && siteIconUrl) {
        throw new Error("Choose an icon URL or upload an icon, not both.");
      }
      settings.siteTitle = siteTitleSetting.value.trim();
      settings.defaultDnsResolver = dnsResolverSetting.querySelector("select").value;
      if (resetSiteIconSetting.checked) {
        settings.resetSiteIcon = true;
      } else if (iconFile) {
        settings.siteIconUpload = await readFileAsDataUrl(iconFile);
      } else if (siteIconUrl) {
        settings.siteIconUrl = siteIconUrl;
      }
    } else if (activePanel === "access-panel") {
      settings.featureAccess = Object.fromEntries(
        [...featureSettings.querySelectorAll("select")].map((select) => [select.name, select.value]),
      );
      settings.trustedProxies = trustedProxySetting.value;
      settings.trustCloudflareProxies = trustCloudflareProxiesSetting.checked;
    } else if (activePanel === "port-scan-panel") {
      settings.nmapAllowedCidrs = nmapAllowedCidrs.value;
      settings.portScanPolicy = {
        maxPortsByRole: Object.fromEntries(["admin", "user"].map((role) => [
          role,
          Number(portScanSettings.querySelector(`[name="maxPorts-${role}"]`).value),
        ])),
        localScanByRole: Object.fromEntries(["admin", "user"].map((role) => [
          role,
          portScanSettings.querySelector(`[name="localScan-${role}"]`).checked,
        ])),
      };
    } else {
      throw new Error("Select a settings category first.");
    }
    const savedSettings = await api("/api/admin/settings", {
      method: "PUT",
      body: JSON.stringify(settings),
    });
    if (activePanel === "access-panel") {
      setCloudflareProxyStatus(savedSettings.cloudflareProxyUpdatedAt);
    }
    if (activePanel === "general-panel") {
      await window.applySiteBranding();
      if (resetSiteIconSetting.checked) {
        siteIconUrlSetting.value = "";
        siteIconUploadSetting.value = "";
        resetSiteIconSetting.checked = false;
        renderBrandingPreview("/favicon.svg", "Using the default icon");
      } else if (iconFile) {
        siteIconUrlSetting.value = "";
        siteIconUploadSetting.value = "";
        renderBrandingPreview(await readFileAsDataUrl(iconFile), "Uploaded site icon");
      } else if (siteIconUrl) {
        renderBrandingPreview(siteIconUrl, "Current custom site icon");
      }
    }
    showAdminSuccess(`${activeTab.textContent.trim()} settings saved.`);
  } catch (error) {
    showAdminError(error.message);
  }
});

settingsTabs.forEach((tab, index) => {
  tab.addEventListener("click", () => setSettingsTab(tab));
  tab.addEventListener("keydown", (event) => {
    const nextIndex = event.key === "ArrowRight"
      ? (index + 1) % settingsTabs.length
      : event.key === "ArrowLeft"
        ? (index + settingsTabs.length - 1) % settingsTabs.length
        : event.key === "Home"
          ? 0
          : event.key === "End"
            ? settingsTabs.length - 1
            : -1;
    if (nextIndex < 0) return;
    event.preventDefault();
    const nextTab = settingsTabs[nextIndex];
    setSettingsTab(nextTab);
    nextTab.focus();
  });
});

siteIconUrlSetting.addEventListener("input", () => {
  if (siteIconUrlSetting.value) {
    siteIconUploadSetting.value = "";
    resetSiteIconSetting.checked = false;
  }
});

siteIconUploadSetting.addEventListener("change", () => {
  const file = siteIconUploadSetting.files[0];
  if (!file) return;
  siteIconUrlSetting.value = "";
  resetSiteIconSetting.checked = false;
  if (file.size > 256 * 1024) {
    showAdminError("Choose an icon image no larger than 256 KB.");
    return;
  }
  const previewUrl = URL.createObjectURL(file);
  renderBrandingPreview(previewUrl, file.name);
  brandingPreview.querySelector("img").addEventListener("load", () => URL.revokeObjectURL(previewUrl), { once: true });
});

resetSiteIconSetting.addEventListener("change", () => {
  if (resetSiteIconSetting.checked) {
    siteIconUrlSetting.value = "";
    siteIconUploadSetting.value = "";
    renderBrandingPreview("");
  }
});

document.querySelector("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  try {
    await api("/api/admin/users", {
      method: "POST",
      body: JSON.stringify(values),
    });
    form.reset();
    showAdminSuccess("User account created.");
    await loadUsers();
  } catch (error) {
    showAdminError(error.message);
  }
});

document.querySelector("#admin-logout").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.assign("/");
});

const certificateForm = document.querySelector("#certificate-form");
const certificateCurrent = document.querySelector("#certificate-current");
const acmeSteps = document.querySelector("#acme-steps");
const acmeRequestButton = document.querySelector("#acme-request");
let certificatePollTimer = null;

function renderCertificate(data) {
  if (data.config) {
    certificateForm.elements.domain.value = (data.config.domains || [data.config.domain]).join("\n");
    certificateForm.elements.email.value = data.config.email || "";
    certificateForm.elements.environment.value = data.config.environment;
    certificateForm.elements.autoRenew.checked = data.config.autoRenew !== false;
    certificateForm.elements.acceptTerms.checked = Boolean(data.config.termsAccepted);
  }
  const certificate = data.certificate;
  const lines = [];
  if (certificate) {
    const staging = /STAGING|Fake/i.test(certificate.issuer);
    lines.push(
      `<strong>${escapeHtml(certificate.subject || (certificate.domains && certificate.domains[0]) || "")}</strong>`,
      `Domains: ${escapeHtml((certificate.domains || []).join(", "))}`,
      `Issuer: ${escapeHtml(certificate.issuer)}${staging ? " (staging, not trusted by browsers)" : ""}`,
      `Valid until ${escapeHtml(new Date(certificate.validTo).toLocaleString())} (${certificate.daysRemaining} days remaining)`,
    );
  } else {
    lines.push("No certificate has been issued yet.");
  }
  lines.push(data.httpsListening
    ? `HTTPS is active on port ${data.httpsPort} inside the container.`
    : certificate ? "HTTPS is not currently listening." : "");
  if (data.httpsError) lines.push(escapeHtml(data.httpsError));
  certificateCurrent.innerHTML = lines.filter(Boolean).map((line) => `<p>${line}</p>`).join("");
  acmeSteps.replaceChildren(...(data.status?.steps || []).map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
  if (data.status?.state === "error") acmeSteps.lastElementChild?.classList.add("certificate-error");
  acmeRequestButton.disabled = Boolean(data.running) || !data.config;
  clearTimeout(certificatePollTimer);
  if (data.running) certificatePollTimer = setTimeout(loadCertificate, 2000);
}

async function loadCertificate() {
  try {
    renderCertificate(await api("/api/admin/certificate"));
  } catch (error) {
    showAdminError(error.message);
  }
}

certificateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = certificateForm.elements;
  try {
    renderCertificate(await api("/api/admin/certificate", {
      method: "PUT",
      body: JSON.stringify({
        domains: form.domain.value,
        email: form.email.value,
        environment: form.environment.value,
        autoRenew: form.autoRenew.checked,
        acceptTerms: form.acceptTerms.checked,
      }),
    }));
    showAdminSuccess("Certificate settings saved.");
  } catch (error) {
    showAdminError(error.message);
  }
});

acmeRequestButton.addEventListener("click", async () => {
  try {
    renderCertificate(await api("/api/admin/certificate", { method: "POST" }));
    showAdminSuccess("Certificate request started.");
  } catch (error) {
    showAdminError(error.message);
  }
});

loadCertificate();

initializeAdmin();
