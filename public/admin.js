const errorPanel = document.querySelector("#admin-error");
const successPanel = document.querySelector("#admin-success");
const featureSettings = document.querySelector("#feature-settings");
const dnsResolverSetting = document.querySelector("#dns-resolver-setting");
const trustedProxySetting = document.querySelector("#trusted-proxies");
const portScanSettings = document.querySelector("#port-scan-settings");
const userList = document.querySelector("#user-list");

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
      <label class="user-active"><input type="checkbox" name="active" ${user.active ? "checked" : ""}> Active</label>
      <input class="user-reset-password" name="password" type="password" minlength="12" maxlength="128" placeholder="New password (optional)" autocomplete="new-password" aria-label="Set a new password for ${escapeHtml(user.username)}">
      <button type="submit">Save</button>
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

async function loadUsers() {
  const { users } = await api("/api/admin/users");
  renderUsers(users);
}

async function initializeAdmin() {
  try {
    const [settings, users] = await Promise.all([
      api("/api/admin/settings"),
      api("/api/admin/users"),
    ]);
    renderFeatureSettings(settings.features, settings.featureAccess);
    renderDnsResolverSetting(settings.dnsResolvers, settings.defaultDnsResolver);
    trustedProxySetting.value = settings.trustedProxies;
    renderPortScanSettings(settings.portScanPolicy);
    renderUsers(users.users);
  } catch (error) {
    if (!errorPanel.hidden) return;
    showAdminError(error.message);
  }
}

document.querySelector("#settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const featureAccess = Object.fromEntries(
    [...featureSettings.querySelectorAll("select")].map((select) => [select.name, select.value]),
  );
  const defaultDnsResolver = dnsResolverSetting.querySelector("select").value;
  const trustedProxies = trustedProxySetting.value;
  const portScanPolicy = {
    maxPortsByRole: Object.fromEntries(["admin", "user"].map((role) => [
      role,
      Number(portScanSettings.querySelector(`[name="maxPorts-${role}"]`).value),
    ])),
    localScanByRole: Object.fromEntries(["admin", "user"].map((role) => [
      role,
      portScanSettings.querySelector(`[name="localScan-${role}"]`).checked,
    ])),
  };
  try {
    await api("/api/admin/settings", {
      method: "PUT",
      body: JSON.stringify({ featureAccess, portScanPolicy, defaultDnsResolver, trustedProxies }),
    });
    showAdminSuccess("Feature access, DNS resolver, trusted proxies, and port scan settings saved.");
  } catch (error) {
    showAdminError(error.message);
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
  window.location.assign("/login.html");
});

initializeAdmin();
