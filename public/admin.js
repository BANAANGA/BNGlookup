const errorPanel = document.querySelector("#admin-error");
const successPanel = document.querySelector("#admin-success");
const featureSettings = document.querySelector("#feature-settings");
const dnsResolverSetting = document.querySelector("#dns-resolver-setting");
const trustedProxySetting = document.querySelector("#trusted-proxies");
const trustCloudflareProxiesSetting = document.querySelector("#trust-cloudflare-proxies");
const cloudflareProxyStatus = document.querySelector("#cloudflare-proxy-status");
const portScanSettings = document.querySelector("#port-scan-settings");
const nmapAllowedCidrs = document.querySelector("#nmap-allowed-cidrs");
const nmapLoginIpStatus = document.querySelector("#nmap-login-ip-status");
const nmapLoginIpList = document.querySelector("#nmap-login-ip-list");
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

function renderPortScanSettings(policy, zmapEnabled) {
  const roleSettings = ["admin", "user"].map((role) => `
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
  const cidrSettings = `
    <fieldset class="port-scan-role bulk-cidr-policy">
      <legend>Bulk port scan CIDR limits</legend>
      <label for="bulk-cidr-prefix-ipv4">Largest IPv4 CIDR</label>
      <select id="bulk-cidr-prefix-ipv4" name="largestBulkCidrPrefixIpv4">
        ${Array.from({ length: 9 }, (_, index) => 16 + index).map((prefix) => `
          <option value="${prefix}" ${policy.largestBulkCidrPrefix.ipv4 === prefix ? "selected" : ""}>
            /${prefix} (${2 ** (32 - prefix)} addresses max)
          </option>
        `).join("")}
      </select>
      <label for="bulk-cidr-prefix-ipv6">Largest IPv6 CIDR</label>
      <select id="bulk-cidr-prefix-ipv6" name="largestBulkCidrPrefixIpv6">
        ${Array.from({ length: 9 }, (_, index) => 120 + index).map((prefix) => `
          <option value="${prefix}" ${policy.largestBulkCidrPrefix.ipv6 === prefix ? "selected" : ""}>
            /${prefix} (${2 ** (128 - prefix)} addresses max)
          </option>
        `).join("")}
      </select>
      <label for="zmap-rate">zmap send rate (packets per second)</label>
      <input id="zmap-rate" name="zmapRate" type="number" min="1000" max="100000" step="1" value="${policy.zmapRate}" required>
      <p class="form-hint">${zmapEnabled
    ? "zmap engine: enabled. IPv4 targets are SYN-scanned with zmap, up to 65,536 addresses (IPv4 /16). IPv6 targets still use TCP connect, capped at 256 addresses (/120)."
    : "zmap engine: disabled. Scans use TCP connect and are capped at 256 addresses total, so IPv4 CIDRs broader than /24 will be rejected. Run with compose.zmap.yaml to enable zmap."}</p>
    </fieldset>
  `;
  portScanSettings.innerHTML = roleSettings + cidrSettings;
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
      <span class="user-2fa ${user.twoFactor ? "on" : ""}" title="Two-factor login">${user.twoFactor ? "2FA on" : "2FA off"}</span>
      <button type="submit">Save</button>
      ${user.twoFactor ? `<button type="button" class="user-reset-2fa" data-reset-2fa="${user.id}" data-name="${escapeHtml(user.username)}">Reset 2FA</button>` : ""}
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
  const reset = event.target.closest("[data-reset-2fa]");
  if (reset) {
    if (!window.confirm(`Turn off two-factor login for "${reset.dataset.name}"? Use this when they lost their phone and recovery codes; they can set it up again afterwards.`)) return;
    try {
      await api(`/api/admin/users/${reset.dataset.reset2fa}`, { method: "PATCH", body: JSON.stringify({ resetTwoFactor: true }) });
      showAdminSuccess("Two-factor login was turned off for this user.");
      await loadUsers();
    } catch (error) {
      showAdminError(error.message);
    }
    return;
  }
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

function renderNmapLoginIps(ips) {
  const entries = Array.isArray(ips) ? ips : [];
  const manualCount = nmapAllowedCidrs.value.split(/[\s,]+/).filter(Boolean).length;
  const automaticCapacity = Math.max(0, 254 - manualCount);
  nmapLoginIpStatus.textContent = `${entries.length} automatically added login IP${entries.length === 1 ? "" : "s"}; up to ${automaticCapacity} automatic slot${automaticCapacity === 1 ? "" : "s"} available. Entries expire after 30 days.`;
  nmapLoginIpList.replaceChildren();
  if (!entries.length) {
    nmapLoginIpList.textContent = "No login IPs have been added yet.";
    return;
  }
  for (const entry of entries) {
    const row = document.createElement("div");
    row.className = "nmap-login-ip";
    const address = document.createElement("strong");
    address.textContent = `${entry.address}/${entry.address.includes(":") ? 128 : 32}`;
    const expiry = document.createElement("span");
    expiry.textContent = `Expires ${new Date(entry.expiresAt).toLocaleString()}`;
    row.append(address, expiry);
    nmapLoginIpList.append(row);
  }
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
    renderPortScanSettings(settings.portScanPolicy, settings.zmapEnabled);
    nmapAllowedCidrs.value = settings.nmapAllowedCidrs;
    renderNmapLoginIps(settings.nmapLoginIps);
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
        largestBulkCidrPrefix: {
          ipv4: Number(portScanSettings.querySelector('[name="largestBulkCidrPrefixIpv4"]').value),
          ipv6: Number(portScanSettings.querySelector('[name="largestBulkCidrPrefixIpv6"]').value),
        },
        zmapRate: Number(portScanSettings.querySelector('[name="zmapRate"]').value),
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
    } else if (activePanel === "port-scan-panel") {
      renderNmapLoginIps(savedSettings.nmapLoginIps);
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

const aboutForm = document.querySelector("#about-form");
const aboutInput = document.querySelector("#about-content-input");
const aboutPreview = document.querySelector("#about-preview");
const aboutStatus = document.querySelector("#about-status");

function renderAboutEditor(data) {
  aboutInput.value = data.content;
  aboutInput.maxLength = data.limit || 20000;
  aboutPreview.innerHTML = renderAboutMarkdown(data.content);
  aboutStatus.textContent = data.custom
    ? `Custom content, last saved ${new Date(data.updatedAt).toLocaleString()}.`
    : "Showing the default content. Save to publish your own.";
}

async function loadAboutEditor() {
  try {
    renderAboutEditor(await api("/api/admin/about"));
  } catch (error) {
    aboutStatus.textContent = error.message;
  }
}

aboutInput.addEventListener("input", () => {
  aboutPreview.innerHTML = renderAboutMarkdown(aboutInput.value);
  aboutStatus.textContent = `${aboutInput.value.length.toLocaleString()} / ${aboutInput.maxLength.toLocaleString()} characters · unsaved changes`;
});

aboutForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    renderAboutEditor(await api("/api/admin/about", {
      method: "PUT",
      body: JSON.stringify({ content: aboutInput.value }),
    }));
    showAdminSuccess("About page saved.");
  } catch (error) {
    showAdminError(error.message);
  }
});

document.querySelector("#about-reset").addEventListener("click", async () => {
  if (!window.confirm("Replace the About page with the default content?")) return;
  try {
    renderAboutEditor(await api("/api/admin/about", { method: "DELETE" }));
    showAdminSuccess("About page reset to the default content.");
  } catch (error) {
    showAdminError(error.message);
  }
});

const bimiLogoUpload = document.querySelector("#bimi-logo-upload");
const bimiLogoSave = document.querySelector("#bimi-logo-save");
const bimiLogoRemove = document.querySelector("#bimi-logo-remove");
const bimiLogoPreview = document.querySelector("#bimi-logo-preview");
const bimiLogoStatus = document.querySelector("#bimi-logo-status");
const bimiLogoWarnings = document.querySelector("#bimi-logo-warnings");
const bimiRecord = document.querySelector("#bimi-record");

function renderBimiLogo(data) {
  bimiLogoPreview.src = `/logo.svg?v=${encodeURIComponent(data.updatedAt || "default")}`;
  document.querySelector("#bimi-logo-url").textContent = data.url;
  bimiRecord.value = data.record;
  bimiLogoRemove.hidden = !data.custom;
  bimiLogoStatus.textContent = data.custom
    ? `Custom logo (${(data.bytes / 1024).toFixed(1)} KB), uploaded ${new Date(data.updatedAt).toLocaleString()}.`
    : "Showing the default logo.";
  renderBimiWarnings(data.warnings, data.custom ? "Accepted, but BIMI validators may reject it:" : "");
}

function renderBimiWarnings(warnings = [], heading = "") {
  bimiLogoWarnings.hidden = !warnings.length;
  bimiLogoWarnings.innerHTML = warnings.length
    ? `${heading ? `<li class="bimi-logo-warning-heading">${escapeHtml(heading)}</li>` : ""}${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}`
    : "";
}

async function loadBimiLogo() {
  try {
    renderBimiLogo(await api("/api/admin/logo"));
  } catch (error) {
    bimiLogoStatus.textContent = error.message;
  }
}

bimiLogoUpload.addEventListener("change", () => {
  const file = bimiLogoUpload.files[0];
  bimiLogoSave.disabled = !file;
  if (file) bimiLogoStatus.textContent = `${file.name} selected (${(file.size / 1024).toFixed(1)} KB). Upload it to publish.`;
});

bimiLogoSave.addEventListener("click", async () => {
  const file = bimiLogoUpload.files[0];
  if (!file) return;
  bimiLogoSave.disabled = true;
  try {
    const data = await api("/api/admin/logo", { method: "PUT", body: JSON.stringify({ svg: await file.text() }) });
    bimiLogoUpload.value = "";
    renderBimiLogo(data);
    showAdminSuccess(data.warnings.length ? "Logo uploaded. See the BIMI notes below it." : "Logo uploaded; it meets the BIMI SVG checks.");
  } catch (error) {
    bimiLogoSave.disabled = false;
    renderBimiWarnings([]);
    showAdminError(`Logo rejected: ${error.message}`);
  }
});

bimiLogoRemove.addEventListener("click", async () => {
  if (!window.confirm("Remove the custom logo and use the default one?")) return;
  try {
    renderBimiLogo(await api("/api/admin/logo", { method: "DELETE" }));
    showAdminSuccess("Custom logo removed.");
  } catch (error) {
    showAdminError(error.message);
  }
});

loadCertificate();
loadAboutEditor();
loadBimiLogo();

initializeAdmin();

const landingForm = document.querySelector("#landing-form");
const landingFrame = document.querySelector("#landing-preview-frame");
const landingBackgroundUpload = document.querySelector("#landing-background-upload");
const landingBackgroundRemove = document.querySelector("#landing-background-remove");
const landingBackgroundStatus = document.querySelector("#landing-background-status");
const landingColorFields = [
  ["background", "Background"], ["background2", "Background 2"], ["surface", "Cards"], ["text", "Text"], ["muted", "Muted text"],
  ["accent", "Accent"], ["accent2", "Accent 2"], ["success", "Good"], ["warning", "Warning"], ["danger", "Problem"],
];
const landingTextFields = [
  ["headline", "Headline"], ["subheadline", "Subheading", true], ["placeholder", "Search hint"], ["button", "Search button"],
  ["login", "Login button"], ["examples", "Example searches"], ["empty", "No public tools", true], ["footer", "Footer", true],
  ["tabOverview", "Tab: overview"], ["tabDns", "Tab: DNS"], ["tabEmail", "Tab: email"], ["tabWeb", "Tab: web"],
  ["tabSecurity", "Tab: security"], ["tabNetwork", "Tab: network"],
];
const landingTextLimits = { headline: 120, subheadline: 240, placeholder: 80, button: 24, login: 24, footer: 300, examples: 200, empty: 240 };
const landingPresets = {
  Midnight: { background: "#06080f", background2: "#11203d", surface: "#0f1524", text: "#eef2ff", muted: "#8b96b2", accent: "#7c5cff", accent2: "#22d3ee", success: "#34d399", warning: "#fbbf24", danger: "#f87171" },
  Daylight: { background: "#f5f7fb", background2: "#dbe7ff", surface: "#ffffff", text: "#111827", muted: "#5b6478", accent: "#4f46e5", accent2: "#0ea5e9", success: "#059669", warning: "#d97706", danger: "#dc2626" },
  Ocean: { background: "#031b26", background2: "#073b4c", surface: "#08303d", text: "#e6fbff", muted: "#87b5c2", accent: "#06b6d4", accent2: "#3b82f6", success: "#2dd4bf", warning: "#facc15", danger: "#fb7185" },
  Sunset: { background: "#1a0b16", background2: "#4a1530", surface: "#2a1022", text: "#fff1f2", muted: "#c59aae", accent: "#f97316", accent2: "#ec4899", success: "#4ade80", warning: "#fde047", danger: "#f43f5e" },
  Forest: { background: "#07130d", background2: "#163a26", surface: "#0e2117", text: "#ecfdf5", muted: "#8fb5a0", accent: "#22c55e", accent2: "#a3e635", success: "#34d399", warning: "#fbbf24", danger: "#f87171" },
  Mono: { background: "#0a0a0a", background2: "#262626", surface: "#141414", text: "#fafafa", muted: "#a3a3a3", accent: "#e5e5e5", accent2: "#737373", success: "#a3e635", warning: "#facc15", danger: "#f87171" },
};
let landingState = null;

function landingDraft() {
  const value = (name) => landingForm.elements[name].value;
  const theme = Object.fromEntries(landingColorFields.map(([key]) => [key, value(`color-${key}`)]));
  Object.assign(theme, {
    font: value("font"),
    radius: Number(value("radius")),
    animations: landingForm.elements.animations.checked,
    glass: landingForm.elements.glass.checked,
    backgroundMode: value("backgroundMode"),
    overlay: Number(value("overlay")),
    blur: Number(value("blur")),
  });
  const content = Object.fromEntries(landingTextFields.map(([key]) => [key, value(`text-${key}`)]));
  return { enabled: landingForm.elements.enabled.checked, userInterface: value("userInterface"), theme, content };
}

function sendLandingPreview() {
  if (!landingState) return;
  const draft = landingDraft();
  landingFrame.contentWindow?.postMessage({
    type: "landing-preview",
    config: { theme: { ...draft.theme, fontStack: landingState.fonts[draft.theme.font] }, content: draft.content, background: landingState.background },
  }, window.location.origin);
}

function fillLandingForm(config) {
  landingForm.elements.enabled.checked = config.enabled;
  landingForm.elements.userInterface.value = config.userInterface || "full";
  for (const [key] of landingColorFields) landingForm.elements[`color-${key}`].value = config.theme[key];
  for (const name of ["font", "radius", "backgroundMode", "overlay", "blur"]) landingForm.elements[name].value = config.theme[name];
  landingForm.elements.animations.checked = config.theme.animations;
  landingForm.elements.glass.checked = config.theme.glass;
  for (const [key] of landingTextFields) landingForm.elements[`text-${key}`].value = config.content[key] ?? "";
  sendLandingPreview();
}

function renderLandingBackground() {
  const background = landingState.background;
  landingBackgroundRemove.hidden = !background;
  landingBackgroundStatus.textContent = background
    ? "A background image is uploaded. Choose \"Uploaded image\" as the style to show it."
    : "PNG, JPEG, WebP or GIF up to 5 MB. Uploading saves the image straight away.";
}

async function loadLandingEditor() {
  try {
    landingState = await api("/api/admin/landing");
  } catch (error) {
    landingBackgroundStatus.textContent = error.message;
    return;
  }
  document.querySelector("#landing-font").innerHTML = Object.keys(landingState.fonts)
    .map((font) => `<option value="${escapeHtml(font)}">${escapeHtml(font[0].toUpperCase() + font.slice(1))}</option>`).join("");
  document.querySelector("#landing-colors").innerHTML = landingColorFields.map(([key, label]) => `
    <label class="landing-color"><input type="color" name="color-${key}"> ${escapeHtml(label)}</label>`).join("");
  document.querySelector("#landing-texts").innerHTML = landingTextFields.map(([key, label, multiline]) => {
    const limit = landingTextLimits[key] || 30;
    return `<label for="landing-text-${key}">${escapeHtml(label)}</label>${multiline
      ? `<textarea id="landing-text-${key}" name="text-${key}" maxlength="${limit}" rows="2"></textarea>`
      : `<input id="landing-text-${key}" name="text-${key}" type="text" maxlength="${limit}">`}`;
  }).join("");
  const presets = document.querySelector("#landing-presets");
  presets.innerHTML = Object.keys(landingPresets).map((name) => `
    <button class="landing-preset" type="button" data-preset="${name}"><span class="landing-preset-swatch"></span>${name}</button>`).join("");
  presets.querySelectorAll(".landing-preset").forEach((button) => {
    const colors = landingPresets[button.dataset.preset];
    button.querySelector(".landing-preset-swatch").style.background = `linear-gradient(135deg, ${colors.background} 45%, ${colors.accent} 45% 70%, ${colors.accent2} 70%)`;
    button.addEventListener("click", () => {
      for (const [key, color] of Object.entries(colors)) landingForm.elements[`color-${key}`].value = color;
      sendLandingPreview();
    });
  });
  fillLandingForm(landingState);
  renderLandingBackground();
}

landingForm.addEventListener("input", sendLandingPreview);
landingForm.addEventListener("change", sendLandingPreview);
window.addEventListener("message", (event) => {
  if (event.origin === window.location.origin && event.source === landingFrame.contentWindow && event.data?.type === "landing-preview-ready") sendLandingPreview();
});

landingForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const saved = await api("/api/admin/landing", { method: "PUT", body: JSON.stringify(landingDraft()) });
    landingState = { ...landingState, ...saved };
    showAdminSuccess("Landing page saved.");
  } catch (error) {
    showAdminError(error.message);
  }
});

document.querySelector("#landing-reset").addEventListener("click", () => {
  if (!landingState || !window.confirm("Reset the theme and all texts to the defaults? Nothing is saved until you click Save.")) return;
  fillLandingForm({ ...landingState.defaults, enabled: landingForm.elements.enabled.checked, userInterface: landingForm.elements.userInterface.value });
});

landingBackgroundUpload.addEventListener("change", async () => {
  const file = landingBackgroundUpload.files[0];
  if (!file) return;
  try {
    if (file.size > 5 * 1024 * 1024) throw new Error("The image must be 5 MB or smaller.");
    landingBackgroundStatus.textContent = "Uploading…";
    const saved = await api("/api/admin/landing/background", { method: "PUT", body: JSON.stringify({ image: await readFileAsDataUrl(file) }) });
    landingState = { ...landingState, ...saved };
    landingForm.elements.backgroundMode.value = "image";
    renderLandingBackground();
    sendLandingPreview();
    showAdminSuccess("Background image uploaded.");
  } catch (error) {
    renderLandingBackground();
    showAdminError(error.message);
  } finally {
    landingBackgroundUpload.value = "";
  }
});

landingBackgroundRemove.addEventListener("click", async () => {
  if (!window.confirm("Remove the background image?")) return;
  try {
    const saved = await api("/api/admin/landing/background", { method: "DELETE" });
    landingState = { ...landingState, ...saved };
    if (landingForm.elements.backgroundMode.value === "image") landingForm.elements.backgroundMode.value = "aurora";
    renderLandingBackground();
    sendLandingPreview();
    showAdminSuccess("Background image removed.");
  } catch (error) {
    showAdminError(error.message);
  }
});

loadLandingEditor();

const siteFilesList = document.querySelector("#site-files");
const siteChangePassword = document.querySelector("#site-change-password");
const siteFileHelp = {
  robots: "Tells search engines and other crawlers what they may index.",
  security: "Tells security researchers how to report vulnerabilities (RFC 9116). Contact and Expires are required.",
  humans: "Credits the people behind the site.",
};
const robotsTemplates = {
  "Keep private pages out": "User-agent: *\nDisallow: /api/\nDisallow: /admin\nDisallow: /login.html\nDisallow: /my-account.html\nDisallow: /history.html\nDisallow: /monitors.html\nAllow: /\n",
  "Allow everything": "User-agent: *\nAllow: /\n",
  "Block all crawlers": "User-agent: *\nDisallow: /\n",
};

function siteFileMessages(element, data) {
  element.innerHTML = [
    ...(data.errors || []).map((message) => `<li class="error">${escapeHtml(message)}</li>`),
    ...(data.warnings || []).map((message) => `<li class="warning">${escapeHtml(message)}</li>`),
  ].join("");
  element.hidden = !element.children.length;
}

function securityBuilderHtml() {
  const nextYear = new Date(Date.now() + 364 * 86400000).toISOString().slice(0, 10);
  return `<div class="security-builder">
    <p class="form-hint">Fill in the fields and click <strong>Build file</strong>, or edit the text directly.</p>
    <label for="sec-contact">Contact</label><input id="sec-contact" type="text" placeholder="mailto:security@example.com, https://example.com/report">
    <label for="sec-expires">Expires</label><input id="sec-expires" type="date" value="${nextYear}">
    <label for="sec-encryption">Encryption key URL</label><input id="sec-encryption" type="url" placeholder="https://example.com/pgp-key.txt">
    <label for="sec-policy">Policy URL</label><input id="sec-policy" type="url" placeholder="https://example.com/security-policy">
    <label for="sec-ack">Acknowledgments URL</label><input id="sec-ack" type="url" placeholder="https://example.com/hall-of-fame">
    <label for="sec-languages">Preferred languages</label><input id="sec-languages" type="text" placeholder="en, nl">
    <div class="site-file-actions"><button class="dash-version-check" id="sec-build" type="button">Build file</button></div>
  </div>`;
}

function buildSecurityTxt() {
  const value = (id) => document.querySelector(id).value.trim();
  const contacts = value("#sec-contact").split(/[,\s]+/).filter(Boolean)
    .map((contact) => (/^[^:\s]+@[^\s]+$/.test(contact) ? `mailto:${contact}` : contact));
  const lines = contacts.map((contact) => `Contact: ${contact}`);
  if (value("#sec-expires")) lines.push(`Expires: ${value("#sec-expires")}T00:00:00Z`);
  if (value("#sec-encryption")) lines.push(`Encryption: ${value("#sec-encryption")}`);
  if (value("#sec-policy")) lines.push(`Policy: ${value("#sec-policy")}`);
  if (value("#sec-ack")) lines.push(`Acknowledgments: ${value("#sec-ack")}`);
  if (value("#sec-languages")) lines.push(`Preferred-Languages: ${value("#sec-languages")}`);
  lines.push(`Canonical: ${window.location.origin}/.well-known/security.txt`);
  return `${lines.join("\n")}\n`;
}

function renderSiteFiles(data) {
  siteChangePassword.checked = data.changePassword;
  siteFilesList.innerHTML = Object.entries(data.files).map(([id, file]) => `
    <section class="site-file" data-file="${id}">
      <div class="site-file-head">
        <h3>${escapeHtml(file.label)}</h3>
        <span class="site-file-state${file.enabled ? " on" : ""}">${file.enabled ? "Published" : "Off"}</span>
      </div>
      <p class="form-hint">${escapeHtml(siteFileHelp[id] || "")} Served at
        ${file.paths.map((path) => `<a href="${escapeHtml(path)}" target="_blank" rel="noopener"><code>${escapeHtml(path)}</code></a>`).join(" and ")}.</p>
      ${id === "robots" ? `<div class="site-file-templates">Templates: ${Object.keys(robotsTemplates).map((name) => `<button class="dash-version-check" type="button" data-template="${escapeHtml(name)}">${escapeHtml(name)}</button>`).join("")}</div>` : ""}
      ${id === "security" ? securityBuilderHtml() : ""}
      <label class="visually-hidden" for="site-file-${id}">${escapeHtml(file.label)} content</label>
      <textarea id="site-file-${id}" maxlength="${data.limit}" spellcheck="false"></textarea>
      <label class="branding-reset site-file-toggle" for="site-file-enabled-${id}"><input id="site-file-enabled-${id}" type="checkbox"${file.enabled ? " checked" : ""}> Publish this file</label>
      <ul class="site-file-messages" hidden></ul>
      <div class="site-file-actions">
        <button class="submit-button" type="button" data-save><span>Save ${escapeHtml(file.label)}</span><span aria-hidden="true">→</span></button>
        <span class="form-hint">${file.updatedAt ? `Last saved ${escapeHtml(new Date(file.updatedAt).toLocaleString())}` : "Not saved yet"}</span>
      </div>
    </section>`).join("");
  for (const section of siteFilesList.querySelectorAll(".site-file")) {
    const id = section.dataset.file;
    const textarea = section.querySelector("textarea");
    textarea.value = data.files[id].content;
    siteFileMessages(section.querySelector(".site-file-messages"), data.files[id].enabled ? data.files[id] : {});
    section.querySelectorAll("[data-template]").forEach((button) => button.addEventListener("click", () => {
      if (textarea.value.trim() && !window.confirm("Replace the current content with this template?")) return;
      textarea.value = robotsTemplates[button.dataset.template];
    }));
    section.querySelector("#sec-build")?.addEventListener("click", () => {
      if (textarea.value.trim() && !window.confirm("Replace the current content with the built file?")) return;
      textarea.value = buildSecurityTxt();
    });
    section.querySelector("[data-save]").addEventListener("click", async () => {
      const messages = section.querySelector(".site-file-messages");
      try {
        const response = await fetch("/api/admin/site-files", {
          method: "PUT",
          credentials: "same-origin",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ id, enabled: section.querySelector('input[type="checkbox"]').checked, content: textarea.value }),
        });
        const result = await response.json();
        if (!response.ok) {
          siteFileMessages(messages, result.errors ? result : { errors: [result.error] });
          throw new Error(result.error || "The file could not be saved.");
        }
        renderSiteFiles(result);
        showAdminSuccess(`${data.files[id].label} saved.`);
      } catch (error) {
        showAdminError(error.message);
      }
    });
  }
}

async function loadSiteFiles() {
  try {
    renderSiteFiles(await api("/api/admin/site-files"));
  } catch (error) {
    siteFilesList.textContent = error.message;
  }
}

siteChangePassword.addEventListener("change", async () => {
  try {
    renderSiteFiles(await api("/api/admin/site-files", { method: "PUT", body: JSON.stringify({ id: "change-password", enabled: siteChangePassword.checked }) }));
    showAdminSuccess("Change-password link saved.");
  } catch (error) {
    siteChangePassword.checked = !siteChangePassword.checked;
    showAdminError(error.message);
  }
});

loadSiteFiles();

const publicAccessFields = {
  dailyLimit: document.querySelector("#public-daily-limit"),
  unlimited: document.querySelector("#public-unlimited"),
  blocked: document.querySelector("#public-blocked"),
  blockSite: document.querySelector("#public-block-site"),
};
const publicAccessStatus = document.querySelector("#public-access-status");

function renderPublicAccess(data) {
  publicAccessFields.dailyLimit.value = data.dailyLimit;
  publicAccessFields.unlimited.value = data.unlimited;
  publicAccessFields.blocked.value = data.blocked;
  publicAccessFields.blockSite.checked = data.blockSite;
  publicAccessStatus.textContent = data.yourAddress ? `Your address as seen by the server: ${data.yourAddress}` : "";
}

async function loadPublicAccess() {
  try {
    renderPublicAccess(await api("/api/admin/public-access"));
  } catch (error) {
    publicAccessStatus.textContent = error.message;
  }
}

document.querySelector("#public-access-save").addEventListener("click", async () => {
  try {
    renderPublicAccess(await api("/api/admin/public-access", {
      method: "PUT",
      body: JSON.stringify({
        dailyLimit: Number(publicAccessFields.dailyLimit.value),
        unlimited: publicAccessFields.unlimited.value,
        blocked: publicAccessFields.blocked.value,
        blockSite: publicAccessFields.blockSite.checked,
      }),
    }));
    showAdminSuccess("Public lookup limits saved.");
  } catch (error) {
    showAdminError(error.message);
  }
});

loadPublicAccess();

const backupStatus = document.querySelector("#backup-status");

document.querySelector("#backup-download").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  backupStatus.textContent = "Preparing the backup…";
  try {
    const response = await fetch("/api/admin/backup", { method: "POST", credentials: "same-origin" });
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || "The backup failed.");
    const blob = await response.blob();
    const name = (response.headers.get("content-disposition") || "").match(/filename="([^"]+)"/)?.[1] || "bnglookup-backup.tar.gz";
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 10000);
    backupStatus.textContent = `Downloaded ${name} (${(blob.size / 1048576).toFixed(1)} MB).`;
  } catch (error) {
    backupStatus.textContent = "";
    showAdminError(error.message);
  } finally {
    button.disabled = false;
  }
});

async function waitForRestart() {
  const started = Date.now();
  await new Promise((resolve) => setTimeout(resolve, 2500));
  while (Date.now() - started < 120000) {
    try {
      const response = await fetch("/healthz", { cache: "no-store" });
      if (response.ok) {
        window.location.assign("/login.html?next=%2Fadmin.html");
        return;
      }
    } catch {
      // Still restarting.
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  backupStatus.textContent = "BNGlookup has not come back yet. If it does not run under Docker or a process manager, start it again.";
}

document.querySelector("#restore-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = document.querySelector("#restore-file").files[0];
  if (!file) return;
  if (!window.confirm(`Replace ALL current data with "${file.name}" and restart BNGlookup? Everyone will be logged out.`)) return;
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  backupStatus.textContent = "Uploading and checking the backup…";
  try {
    const response = await fetch("/api/admin/restore", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/gzip" },
      body: file,
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || "The restore failed.");
    backupStatus.textContent = `Backup${result.createdAt ? ` from ${new Date(result.createdAt).toLocaleString()}` : ""} accepted. Restarting BNGlookup…`;
    await waitForRestart();
  } catch (error) {
    backupStatus.textContent = "";
    showAdminError(error.message);
    button.disabled = false;
  }
});
