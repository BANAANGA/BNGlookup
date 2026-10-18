const form = document.querySelector("#lookup-form");
const input = document.querySelector("#name-input");
const nameLabel = document.querySelector("#name-label");
const primaryInputWrap = document.querySelector("#primary-input-wrap");
const recordType = document.querySelector("#record-type");
const customType = document.querySelector("#custom-type");
const typeControl = document.querySelector("#type-control");
const nameserverControl = document.querySelector("#nameserver-control");
const nameserverInput = document.querySelector("#nameserver-input");
const portScanControl = document.querySelector("#port-scan-control");
const portScanInput = document.querySelector("#port-scan-input");
const customPortsControl = document.querySelector("#custom-ports-control");
const customPortsInput = document.querySelector("#custom-ports-input");
const bulkTargetsControl = document.querySelector("#bulk-targets-control");
const bulkTargetsInput = document.querySelector("#bulk-targets-input");
const bulkPortControl = document.querySelector("#bulk-port-control");
const bulkPortInput = document.querySelector("#bulk-port-input");
const resultPanel = document.querySelector("#result");
const errorMessage = document.querySelector("#error-message");
const submitButton = document.querySelector("#submit-button");
const formHint = document.querySelector("#form-hint");
const tabs = [...document.querySelectorAll(".mode-tab")];
const modeTabs = document.querySelector(".mode-tabs");
const lookupForm = document.querySelector("#lookup-form");
const loginRequiredNotice = document.querySelector("#login-required-notice");
const loginRequiredMessage = document.querySelector("#login-required-message");
const toolsLoginLink = document.querySelector("#tools-login-link");
const guestUsageNotice = document.querySelector("#guest-usage-notice");
const accountNav = document.querySelector("#account-nav");
const accountName = document.querySelector("#account-name");
const adminLink = document.querySelector("#admin-link");
const loginLink = document.querySelector("#login-link");
const logoutButton = document.querySelector("#logout-button");
const clientInfo = document.querySelector("#client-info");
const clientInfoLabel = document.querySelector("#client-info-label");
const clientIp = document.querySelector("#client-ip");
const clientPtr = document.querySelector("#client-ptr");
let mode = "scan";
let authState = null;

async function loadClientInfo() {
  try {
    const response = await fetch("/api/client-info", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Unable to load connection information.");
    const data = await response.json();
    if (!data.address) return;
    clientInfoLabel.textContent = data.isPublic ? "Your public IP" : "Connection IP";
    clientIp.textContent = data.address;
    clientPtr.textContent = data.isPublic
      ? data.ptr?.length
        ? data.ptr.join(", ")
        : data.ptrError || "No PTR record"
      : "PTR lookup is available for public IP addresses only.";
    clientInfo.hidden = false;
  } catch {
    clientInfoLabel.textContent = "Client IP";
    clientIp.textContent = "Unable to determine";
    clientPtr.textContent = "PTR lookup unavailable.";
    clientInfo.hidden = false;
  }
}

function setMode(nextMode) {
  mode = nextMode;
  const reverse = mode === "reverse";
  const details = mode === "details";
  const mac = mode === "mac";
  const scan = mode === "scan";
  const customPortScan = mode === "custom-port";
  const bulkPortScan = mode === "bulk-port";
  const portScan = customPortScan || bulkPortScan;
  const supportsNameserver = ["forward", "reverse", "scan"].includes(mode);
  tabs.forEach((tab) => {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  nameLabel.hidden = bulkPortScan;
  primaryInputWrap.hidden = bulkPortScan;
  input.required = !bulkPortScan;
  nameLabel.textContent = reverse ? "IP address" : mac ? "MAC address" : "Domain name or IP address";
  input.placeholder = reverse
    ? "e.g. 8.8.8.8 or 2001:4860:4860::8888"
    : mac
      ? "e.g. 00:1A:2B:3C:4D:5E"
    : customPortScan
      ? "e.g. example.com or 8.8.8.8"
      : "e.g. example.com";
  input.autocomplete = reverse || mac || portScan ? "off" : "url";
  typeControl.hidden = reverse || details || mac || scan || portScan;
  customType.hidden = reverse || details || mac || scan || portScan || recordType.value !== "custom";
  nameserverControl.hidden = !supportsNameserver;
  portScanControl.hidden = !scan || !authState?.user;
  customPortsControl.hidden = !customPortScan;
  bulkTargetsControl.hidden = !bulkPortScan;
  bulkPortControl.hidden = !bulkPortScan;
  customPortsInput.required = customPortScan;
  bulkTargetsInput.required = bulkPortScan;
  bulkPortInput.required = bulkPortScan;
  formHint.textContent = reverse
    ? "Find the PTR record associated with an IPv4 or IPv6 address."
    : details
      ? "View public domain registration (RDAP/WHOIS) and authoritative nameserver details."
      : mac
        ? "Find the registered hardware vendor and MAC address type."
      : scan
        ? "Scan DNS records, cloud-provider hostnames, SPF, and DKIM. Optionally choose the nameserver."
      : customPortScan
        ? "Scan a custom list or range of TCP ports on one domain or IP address."
      : bulkPortScan
        ? "Check one TCP port across an explicit list or CIDR block of IP addresses."
        : "Choose a record type or enter a custom DNS type. ANY returns records the DNS server makes available.";
  submitButton.innerHTML = `<span>${scan ? "Magic scan" : customPortScan ? "Custom port scan" : bulkPortScan ? "Bulk port scan" : mac ? "Lookup MAC" : "Lookup"}</span><span aria-hidden="true">→</span>`;
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  input.focus();
}

async function initializeAccount() {
  try {
    const response = await fetch("/api/auth/status", { credentials: "same-origin" });
    authState = await response.json();
    if (authState.setupRequired) {
      window.location.replace("/setup.html");
      return;
    }
    accountNav.hidden = false;
    loginLink.hidden = Boolean(authState.user);
    logoutButton.hidden = !authState.user;
    adminLink.hidden = authState.user?.role !== "admin";
    accountName.textContent = authState.user
      ? `${authState.user.username} (${authState.user.role})`
      : "Guest";
    const availableTabs = [];
    tabs.forEach((tab) => {
      const feature = tab.dataset.mode === "details" ? "whois" : tab.dataset.mode;
      const access = authState.featureAccess[feature] || "user";
      const portScanRequiresUser = ["custom-port", "bulk-port"].includes(tab.dataset.mode);
      const canUse = Boolean(authState.user) &&
        (access !== "admin" || authState.user.role === "admin") ||
        access === "public" && !portScanRequiresUser;
      tab.hidden = !canUse;
      tab.setAttribute("aria-hidden", String(!canUse));
      tab.classList.remove("restricted-tab");
      tab.title = "";
      if (canUse) availableTabs.push(tab);
    });
    const initialTab = availableTabs.find((tab) => tab.dataset.mode === mode) || availableTabs[0];
    modeTabs.hidden = !initialTab;
    lookupForm.hidden = !initialTab;
    loginRequiredNotice.hidden = Boolean(initialTab);
    guestUsageNotice.hidden = !initialTab || Boolean(authState.user);
    if (!initialTab && authState.user) {
      loginRequiredMessage.textContent = "No lookup tools are available to your account. Contact an administrator.";
      toolsLoginLink.hidden = true;
    }
    if (initialTab) setMode(initialTab.dataset.mode);
  } catch {
    lookupForm.hidden = true;
    modeTabs.hidden = true;
    tabs.forEach((tab) => { tab.hidden = true; });
    loginRequiredNotice.hidden = false;
    loginRequiredMessage.textContent = "Unable to load account access. Refresh the page to try again.";
    toolsLoginLink.hidden = true;
    errorMessage.textContent = "Unable to load account status. Refresh the page to try again.";
    errorMessage.hidden = false;
  }
}

logoutButton.addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.reload();
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function renderRecords(records, ptrLookups = {}) {
  if (!records.length) {
    return '<p class="empty-result">No records were returned for this query.</p>';
  }
  const recordRows = records.map((record) => {
    const reverse = ptrLookups[record.data];
    const ptrContent = reverse
      ? reverse.error
        ? `<span class="ptr-result">PTR lookup: ${escapeHtml(reverse.error)}</span>`
        : reverse.answers.length
          ? `<span class="ptr-result">PTR: ${reverse.answers.map(escapeHtml).join(", ")}</span>`
          : `<span class="ptr-result">PTR: no record (${escapeHtml(reverse.status)})</span>`
      : "";
    return `
    <div class="record-row">
      <span class="record-name">${escapeHtml(record.name)}</span>
      <span class="record-ttl">${escapeHtml(record.TTL)}s</span>
      <span class="record-data">${escapeHtml(record.data)}${ptrContent}</span>
    </div>`;
  }).join("");
  return `<div class="records">${recordRows}</div>`;
}

function renderSection(title, records, ptrLookups) {
  if (!records.length) return "";
  return `<section class="record-section"><h3>${escapeHtml(title)}<span>${escapeHtml(records.length)}</span></h3>${renderRecords(records, ptrLookups)}</section>`;
}

function showResult(data) {
  const statusClass = data.status === 0 ? "success" : "warning";
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div>
        <p class="eyebrow">LOOKUP RESULT</p>
        <h2>${escapeHtml(data.name)}</h2>
      </div>
      <span class="status-badge ${statusClass}">${escapeHtml(data.statusText)}</span>
    </div>
    ${data.nameserver ? `<div class="query-meta"><span>Queried nameserver</span><strong>${escapeHtml(data.nameserver)}</strong></div>` : ""}
    <div class="query-meta"><span>Record type</span><strong>${escapeHtml(data.type)}</strong></div>
    ${renderSection("Answers", data.answers, data.ptrLookups)}
    ${renderSection("Authority", data.authority, data.ptrLookups)}
    ${renderSection("Additional", data.additional, data.ptrLookups)}
    ${data.status === 0 && !data.answers.length ? '<p class="empty-result">The query succeeded, but no matching records were returned.</p>' : ""}`;
  resultPanel.hidden = false;
}

function renderScanResult(data) {
  const foundHosts = data.hosts.filter((host) => host.records.length);
  const hostCards = foundHosts.map((host) => {
    const providerBadges = host.providers.map((provider) =>
      `<span class="scan-provider-tag">${escapeHtml(provider)}</span>`,
    ).join("");
    const recordGroups = host.records.map((record) => `
      <div class="scan-record">
        <span class="scan-record-type">${escapeHtml(record.type)}</span>
        <div class="scan-record-answers">${record.answers.map((answer) => {
          const ptr = data.ptrLookups?.[answer.data];
          const ptrText = ptr
            ? ptr.error
              ? `PTR lookup: ${ptr.error}`
              : ptr.answers.length
                ? `PTR: ${ptr.answers.join(", ")}`
                : `PTR: no record (${ptr.status})`
            : "";
          const geolocation = data.ipGeolocations?.[answer.data];
          const locationText = geolocation
            ? geolocation.country
              ? `Country: ${[
                geolocation.city,
                geolocation.region,
                geolocation.country,
              ].filter(Boolean).join(", ")}${geolocation.countryCode ? ` (${geolocation.countryCode})` : ""}`
              : `Geolocation: ${geolocation.error}`
            : "";
          return `<div class="scan-answer">
            <span>${escapeHtml(answer.data)}</span>
            ${ptrText ? `<small>${escapeHtml(ptrText)}</small>` : ""}
            ${locationText ? `<small class="geo-result">${escapeHtml(locationText)}</small>` : ""}
          </div>`;
        }).join("")}</div>
      </div>`).join("");
    return `<article class="scan-host">
      <h3>${escapeHtml(host.name)}${host.name === data.domain ? '<span class="scan-root-tag">domain</span>' : ""}${providerBadges}</h3>
      <div class="scan-records">${recordGroups}</div>
    </article>`;
  }).join("");
  const emailSecurity = data.emailSecurity;
  const spfRecords = emailSecurity.spfRecords.map((record) => `
    <div class="email-auth-record"><strong>${escapeHtml(record.name)}</strong><span>${escapeHtml(record.data)}</span></div>
  `).join("");
  const dkimRecords = emailSecurity.dkimRecords.map((entry) => `
    <div class="email-auth-record">
      <strong>${escapeHtml(entry.name)}</strong>
      <span>${entry.records.map((record) => `${escapeHtml(record.type)}: ${escapeHtml(record.data)}`).join("<br>")}</span>
    </div>
  `).join("");
  const portScan = data.portScan;
  const portScanResults = portScan?.results.map((result) => {
    const geolocation = data.ipGeolocations?.[result.address];
    const location = geolocation?.country
      ? `Country: ${[
        geolocation.city,
        geolocation.region,
        geolocation.country,
      ].filter(Boolean).join(", ")}${geolocation.countryCode ? ` (${geolocation.countryCode})` : ""}`
      : geolocation?.error
        ? `Geolocation: ${geolocation.error}`
        : "";
    return `
      <div class="port-scan-address">
        <div class="port-scan-target">
          <strong>${escapeHtml(result.domain)}</strong>
          <small>${escapeHtml(result.address)}</small>
        </div>
        <span>${result.openPorts.length
    ? result.openPorts.map((port) => `<span class="port-badge">${escapeHtml(port)}</span>`).join("")
    : "No open ports found in the checked set"}
          ${location ? `<small class="geo-result">${escapeHtml(location)}</small>` : ""}
        </span>
      </div>
    `;
  }).join("");
  const portScanSection = portScan?.enabled
    ? `<section class="email-auth port-scan-results">
        <h3>TCP port scan <span class="email-auth-status ${portScan.results.some((result) => result.openPorts.length) ? "found" : "missing"}">${escapeHtml(portScan.results.reduce((count, result) => count + result.openPorts.length, 0))} open</span></h3>
        <p class="scan-disclaimer">Checked ${escapeHtml(portScan.addressesScanned)} eligible domain IP address(es) across ${escapeHtml(portScan.portsChecked)} common TCP ports.${portScan.addressesSkipped ? ` Skipped ${escapeHtml(portScan.addressesSkipped)} disallowed, reserved, or excess address(es).` : ""}</p>
        ${portScanResults || '<p class="empty-result">No public domain IP addresses were available to scan.</p>'}
        <p class="scan-disclaimer">Only ports that accepted a TCP connection are listed. Scan only systems you are authorized to test.</p>
      </section>`
    : "";
  const registration = data.registration;
  const registrationDates = registration?.dates || {};
  const whoisDateLabels = {
    registration: "Registered",
    expiration: "Expires",
    "last changed": "Last updated",
    "last update of RDAP database": "RDAP record updated",
  };
  const registrationContacts = (registration?.contacts || []).map((contact) => {
    const role = contact.roles.length ? contact.roles.join(", ") : "Contact";
    const values = [
      contact.name,
      contact.organization,
      contact.email,
      contact.phone,
      contact.address,
    ].filter(Boolean);
    return values.length
      ? `<div class="contact-row"><span>${escapeHtml(role)}</span><strong>${values.map(escapeHtml).join(" · ")}</strong></div>`
      : "";
  }).join("");
  const registrationNameservers = (registration?.nameservers || []).map((nameserver) => `
    <div class="detail-row">
      <span>Nameserver</span>
      <strong>${escapeHtml(nameserver.name)}${[...nameserver.ipv4, ...nameserver.ipv6].length
    ? ` · ${[...nameserver.ipv4, ...nameserver.ipv6].map(escapeHtml).join(", ")}`
    : ""}</strong>
    </div>
  `).join("");
  const registrationDetails = registration
    ? `<div class="detail-list">
        ${renderDetail("Registrar", registration.registrar?.organization || registration.registrar?.name)}
        ${renderDetail("Registry handle", registration.handle)}
        ${Object.entries(registrationDates).map(([action, date]) =>
    renderDetail(whoisDateLabels[action] || action, new Date(date).toLocaleDateString()),
  ).join("")}
        ${registrationNameservers}
      </div>
      ${registration.statuses.length
    ? `<div class="status-list">${registration.statuses.map((status) => `<span>${escapeHtml(status)}</span>`).join("")}</div>`
    : ""}
      ${registrationContacts ? `<div class="contact-list">${registrationContacts}</div>` : ""}`
    : `<p class="detail-notice">${escapeHtml(data.registrationError || "No registration details were returned.")}</p>`;

  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">MAGIC SCAN</p><h2>${escapeHtml(data.domain)}</h2></div>
      <span class="status-badge success">${escapeHtml(data.hostsWithRecords)} hosts found</span>
    </div>
    <div class="scan-summary">
      <span>${escapeHtml(data.subdomainsChecked)} subdomains checked</span>
      <span>${data.recordTypes.map(escapeHtml).join(" · ")} plus provider checks</span>
    </div>
    ${data.nameserver ? `<div class="query-meta"><span>Queried nameserver</span><strong>${escapeHtml(data.nameserver)}</strong></div>` : ""}
    <p class="scan-disclaimer">IP geolocation (including country) is approximate. Public IP addresses found in scan results are sent to ipwho.is; private and reserved addresses are not sent.</p>
    ${data.failedQueries ? `<p class="detail-notice">${escapeHtml(data.failedQueries)} DNS queries could not be completed.</p>` : ""}
    <section class="email-auth">
      <h3>Domain registration <span class="email-auth-status ${registration ? "found" : "missing"}">${registration ? "WHOIS / RDAP" : "Unavailable"}</span></h3>
      ${registrationDetails}
      <p class="scan-disclaimer">Registration information is provided by RDAP, the modern WHOIS service. Contact details may be redacted or unavailable.</p>
    </section>
    <section class="email-auth">
      <h3>Email authentication</h3>
      <div class="email-auth-grid">
        <div>
          <h4>SPF <span class="email-auth-status ${emailSecurity.rootSpfFound ? "found" : "missing"}">${emailSecurity.rootSpfFound ? "Found" : "No root record"}</span></h4>
          ${spfRecords || '<p class="empty-result">No SPF policy found in scanned TXT records.</p>'}
        </div>
        <div>
          <h4>DKIM <span class="email-auth-status ${emailSecurity.dkimRecords.length ? "found" : "missing"}">${emailSecurity.dkimRecords.length ? `${escapeHtml(emailSecurity.dkimRecords.length)} found` : "No records found"}</span></h4>
          ${dkimRecords || `          <p class="empty-result">No DKIM records found for ${escapeHtml(emailSecurity.dkimSelectorsChecked)} common selectors.</p>`}
        </div>
      </div>
      <p class="scan-disclaimer">SPF is checked on the domain and scanned hosts. DKIM checks common selectors; your mail provider may use a custom selector that is not included.</p>
    </section>
    ${portScanSection}
    ${hostCards || '<p class="empty-result">No records found for the domain or the checked subdomains.</p>'}
    <p class="scan-disclaimer">Subdomain discovery checks a built-in list of common names; it does not enumerate every subdomain. IP geolocation is provided by ipwho.is and may be unavailable or approximate.</p>`;
  resultPanel.hidden = false;
}

function renderPortScanResult(data, title) {
  const results = data.results.map((result) => `
    <div class="port-scan-address">
      <div class="port-scan-target">
        <strong>${escapeHtml(result.target)}</strong>
        ${result.target !== result.address ? `<small>${escapeHtml(result.address)}</small>` : ""}
      </div>
      <span>${result.openPorts.length
    ? result.openPorts.map((port) => `<span class="port-badge">${escapeHtml(port)}</span>`).join("")
    : "No open ports found"}
      </span>
    </div>
  `).join("");
  const openPortCount = data.results.reduce((count, result) => count + result.openPorts.length, 0);
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">${escapeHtml(title.toUpperCase())}</p><h2>${escapeHtml(data.scanLabel)}</h2></div>
      <span class="status-badge ${openPortCount ? "success" : "warning"}">${escapeHtml(openPortCount)} open</span>
    </div>
    <div class="scan-summary">
      <span>${escapeHtml(data.addressesScanned)} eligible IP address(es) scanned</span>
      <span>${escapeHtml(data.portsChecked)} TCP port(s) checked per address</span>
    </div>
    ${data.addressesSkipped ? `<p class="detail-notice">${escapeHtml(data.addressesSkipped)} disallowed, reserved, or excess IP address(es) were skipped.</p>` : ""}
    ${results || '<p class="empty-result">No eligible IP addresses were available to scan.</p>'}
    <p class="scan-disclaimer">Only ports that accepted a TCP connection are listed. Scan only systems you are authorized to test.</p>`;
  resultPanel.hidden = false;
}

function renderMacResult(data) {
  const addressType = data.multicast ? "Multicast address" : "Unicast address";
  const administration = data.locallyAdministered
    ? "Locally administered"
    : "Universally administered";
  const vendorDetails = data.found
    ? `<section class="record-section">
        <h3>Vendor details</h3>
        <div class="detail-list">
          ${renderDetail("Vendor", data.company)}
          ${renderDetail("Country", data.country)}
          ${renderDetail("OUI block type", data.blockType)}
          ${renderDetail("Registered address", data.address)}
        </div>
      </section>`
    : '<p class="empty-result">No registered vendor was found for this MAC prefix. The address may be locally assigned or unregistered.</p>';

  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">MAC ADDRESS LOOKUP</p><h2>${escapeHtml(data.mac)}</h2></div>
      <span class="status-badge ${data.found ? "success" : "warning"}">${data.found ? "Vendor found" : "Vendor unknown"}</span>
    </div>
    <div class="detail-list mac-address-details">
      ${renderDetail("Address type", addressType)}
      ${renderDetail("Administration", administration)}
      ${renderDetail("OUI prefix", data.oui)}
    </div>
    ${vendorDetails}
    <p class="scan-disclaimer">Vendor information is retrieved from maclookup.app. The submitted MAC address is sent to that service.</p>`;
  resultPanel.hidden = false;
}

function renderDetail(label, value) {
  if (!value) return "";
  return `<div class="detail-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function renderDomainInfo(data) {
  const registration = data.registration;
  const dnsNameservers = data.dnsNameservers;
  const dates = registration?.dates || {};
  const dateLabels = {
    registration: "Registered",
    expiration: "Expires",
    "last changed": "Last updated",
    "last update of RDAP database": "RDAP record updated",
  };
  const registrar = registration?.registrar;
  const contacts = registration?.contacts || [];
  const normalizeNameserver = (name) => name.toLowerCase().replace(/\.$/, "");
  const nameserverNames = new Set([
    ...(registration?.nameservers || []).map((nameserver) => normalizeNameserver(nameserver.name)),
    ...(dnsNameservers?.records || []).map((nameserver) => normalizeNameserver(nameserver.name)),
  ]);
  const nameservers = [...nameserverNames].map((name) => {
    const rdapEntry = registration?.nameservers?.find(
      (nameserver) => normalizeNameserver(nameserver.name) === name,
    );
    const dnsEntry = dnsNameservers?.records?.find(
      (nameserver) => normalizeNameserver(nameserver.name) === name,
    );
    const addresses = [...new Set([
      ...(rdapEntry?.ipv4 || []),
      ...(rdapEntry?.ipv6 || []),
      ...(dnsEntry?.ipv4 || []),
      ...(dnsEntry?.ipv6 || []),
    ])];
    const ptrEntries = addresses
      .map((address) => ({ address, result: data.ptrLookups?.[address] }))
      .filter((entry) => entry.result);
    const ptrMarkup = ptrEntries.map(({ address, result }) => {
      const value = result.error
        ? `PTR lookup: ${result.error}`
        : result.answers.length
          ? `PTR: ${result.answers.join(", ")}`
          : `PTR: no record (${result.status})`;
      return `<span class="nameserver-ptr">${escapeHtml(address)} — ${escapeHtml(value)}</span>`;
    }).join("");
    return `<div class="nameserver-row">
      <strong>${escapeHtml(name)}</strong>
      ${dnsEntry ? `<span class="record-ttl">TTL ${escapeHtml(dnsEntry.ttl)}s</span>` : ""}
      ${ptrMarkup || (addresses.length ? `<span class="nameserver-addresses">${addresses.map(escapeHtml).join(" · ")}</span>` : "")}
    </div>`;
  }).join("");
  const contactRows = contacts.map((contact) => {
    const label = contact.roles.length ? contact.roles.join(", ") : "Contact";
    const values = [
      contact.name,
      contact.organization,
      contact.email,
      contact.phone,
      contact.address,
    ].filter(Boolean);
    return `<div class="contact-row"><span>${escapeHtml(label)}</span><strong>${values.map(escapeHtml).join(" · ")}</strong></div>`;
  }).join("");
  const formattedDates = Object.entries(dates).map(([action, date]) =>
    renderDetail(dateLabels[action] || action, new Date(date).toLocaleDateString()),
  ).join("");

  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">DOMAIN DETAILS</p><h2>${escapeHtml(data.domain)}</h2></div>
    </div>
    ${data.registrationError ? `<p class="detail-notice">${escapeHtml(data.registrationError)}</p>` : ""}
    ${registration ? `<section class="record-section">
      <h3>Registration <span>RDAP / WHOIS</span></h3>
      <div class="detail-list">
        ${renderDetail("Registrar", registrar?.organization || registrar?.name)}
        ${renderDetail("Registry handle", registration.handle)}
        ${formattedDates}
      </div>
      ${registration.statuses.length ? `<div class="status-list">${registration.statuses.map((status) => `<span>${escapeHtml(status)}</span>`).join("")}</div>` : ""}
      ${contactRows ? `<div class="contact-list">${contactRows}</div>` : ""}
    </section>` : ""}
    ${data.dnsNameserversError ? `<p class="detail-notice">${escapeHtml(data.dnsNameserversError)}</p>` : ""}
    ${dnsNameservers?.status && dnsNameservers.status !== "NOERROR" ? `<p class="detail-notice">Nameserver query status: ${escapeHtml(dnsNameservers.status)}</p>` : ""}
    ${dnsNameservers?.addressesIncomplete ? '<p class="detail-notice">Some nameserver IP address lookups could not be completed.</p>' : ""}
    ${(registration?.nameservers?.length || dnsNameservers?.records?.length) ? `<section class="record-section">
      <h3>Nameservers <span>${nameservers.length}</span></h3>
      <div class="nameserver-list">${nameservers}</div>
    </section>` : ""}
    ${!registration && !dnsNameservers ? '<p class="empty-result">No domain details could be retrieved.</p>' : ""}`;
  resultPanel.hidden = false;
}

tabs.forEach((tab) => tab.addEventListener("click", () => {
  const feature = tab.dataset.mode === "details" ? "whois" : tab.dataset.mode;
  const requiredRole = authState?.featureAccess?.[feature] || "user";
  if (requiredRole !== "public" && !authState?.user) {
    const next = `${window.location.pathname}${window.location.search}`;
    window.location.assign(`/login.html?next=${encodeURIComponent(next)}`);
    return;
  }
  if (requiredRole === "admin" && authState?.user?.role !== "admin") {
    errorMessage.textContent = "This feature is restricted to administrators.";
    errorMessage.hidden = false;
    return;
  }
  setMode(tab.dataset.mode);
}));
recordType.addEventListener("change", () => {
  customType.hidden = mode === "reverse" || recordType.value !== "custom";
  if (!customType.hidden) customType.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  submitButton.disabled = true;
  const customPortScan = mode === "custom-port";
  const bulkPortScan = mode === "bulk-port";
  const isPortScan = customPortScan || bulkPortScan;
  submitButton.innerHTML = `<span class="spinner" aria-hidden="true"></span><span>${mode === "scan" ? "Scanning" : isPortScan ? "Scanning ports" : "Looking up"}</span>`;

  const params = new URLSearchParams({
    name: input.value.trim(),
    type: recordType.value === "custom" ? customType.value.trim() : recordType.value,
    reverse: String(mode === "reverse"),
    nameserver: mode === "forward" || mode === "reverse" || mode === "scan"
      ? nameserverInput.value.trim()
      : "",
  });
  if (mode === "scan" && portScanInput.checked) {
    params.set("ports", "common");
  }

  try {
    const endpoint = customPortScan
      ? "/api/custom-port-scan"
      : bulkPortScan
        ? "/api/bulk-port-scan"
      : mode === "details"
      ? "/api/domain-info"
      : mode === "mac"
        ? "/api/mac-lookup"
      : mode === "scan"
        ? "/api/scan"
        : "/api/lookup";
    const requestOptions = customPortScan
      ? {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          target: input.value.trim(),
          ports: customPortsInput.value.trim(),
        }),
      }
      : bulkPortScan
        ? {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            targets: bulkTargetsInput.value,
            port: bulkPortInput.value,
          }),
        }
        : {};
    const response = await fetch(isPortScan ? endpoint : `${endpoint}?${params}`, requestOptions);
    const data = await response.json();
    if (response.status === 401) {
      const next = `${window.location.pathname}${window.location.search}`;
      window.location.assign(`/login.html?next=${encodeURIComponent(next)}`);
      return;
    }
    if (!response.ok) throw new Error(data.error || "DNS lookup failed.");
    if (mode === "details") renderDomainInfo(data);
    else if (mode === "mac") renderMacResult(data);
    else if (mode === "scan") renderScanResult(data);
    else if (isPortScan) renderPortScanResult(data, customPortScan ? "Custom port scan" : "Bulk port scan");
    else showResult(data);
  } catch (error) {
    errorMessage.textContent = error.message || "Unable to complete the lookup.";
    errorMessage.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = `<span>${mode === "scan" ? "Magic scan" : mode === "custom-port" ? "Custom port scan" : mode === "bulk-port" ? "Bulk port scan" : mode === "mac" ? "Lookup MAC" : "Lookup"}</span><span aria-hidden="true">→</span>`;
  }
});

initializeAccount();
loadClientInfo();
