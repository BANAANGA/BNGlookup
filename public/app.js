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
const pingMethodControl = document.querySelector("#ping-method-control");
const pingMethodInput = document.querySelector("#ping-method-input");
const resultPanel = document.querySelector("#result");
const errorMessage = document.querySelector("#error-message");
const submitButton = document.querySelector("#submit-button");
const formHint = document.querySelector("#form-hint");
const tabs = [...document.querySelectorAll(".mode-tab")];
const autoTab = document.querySelector("#auto-tab");
const autoDetectHint = document.querySelector("#auto-detect-hint");
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
const clientWhois = document.querySelector("#client-whois");
let mode = "auto";
let authState = null;

async function readApiResponse(response) {
  const body = await response.text();
  try {
    return JSON.parse(body);
  } catch {
    if (/^\s*</.test(body)) {
      throw new Error(
        `The lookup API returned a web page instead of JSON (HTTP ${response.status}). ` +
        "Check that the Cloudflare Tunnel routes /api/* requests to BNGlookup and that Cloudflare Access allows them.",
      );
    }
    throw new Error(`The lookup API returned an invalid response (HTTP ${response.status}).`);
  }
}

async function loadClientInfo() {
  try {
    const response = await fetch("/api/client-info", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Unable to load connection information.");
    const data = await response.json();
    if (!data.address) return;
    clientInfoLabel.textContent = data.isPublic ? "Your public IP" : "Connection IP";
    clientIp.textContent = data.address;
    clientIp.classList.add("copy-result");
    clientIp.dataset.copyValue = data.address;
    clientIp.setAttribute("role", "button");
    clientIp.setAttribute("tabindex", "0");
    clientIp.setAttribute("aria-label", "Copy result");
    clientIp.title = "Click to copy";
    clientPtr.textContent = data.isPublic
      ? data.ptr?.length
        ? data.ptr.join(", ")
        : data.ptrError || "No PTR record"
      : "PTR lookup is available for public IP addresses only.";
    if (data.isPublic && data.ipRegistration) {
      clientWhois.replaceChildren(buildIpRegistrationTable(data.ipRegistration));
    } else {
      clientWhois.textContent = data.isPublic
        ? data.ipRegistrationError || "No IP registration details were returned."
        : "IP registration lookup is available for public IP addresses only.";
    }
    if (data.isPublic) {
      clientPtr.classList.add("copy-result");
      clientPtr.dataset.copyValue = data.ptr?.length
        ? data.ptr.join(", ")
        : clientPtr.textContent;
      clientPtr.setAttribute("role", "button");
      clientPtr.setAttribute("tabindex", "0");
      clientPtr.setAttribute("aria-label", "Copy result");
      clientPtr.title = "Click to copy";
    }
    clientInfo.hidden = false;
  } catch {
    clientInfoLabel.textContent = "Client IP";
    clientIp.textContent = "Unable to determine";
    clientPtr.textContent = "PTR lookup unavailable.";
    clientWhois.textContent = "IP registration lookup unavailable.";
    clientInfo.hidden = false;
  }
}

function setMode(nextMode) {
  mode = nextMode;
  const automatic = mode === "auto";
  const reverse = mode === "reverse";
  const details = mode === "details";
  const mac = mode === "mac";
  const ping = mode === "ping";
  const scan = mode === "scan";
  const customPortScan = mode === "custom-port";
  const bulkPortScan = mode === "bulk-port";
  const portScan = customPortScan || bulkPortScan;
  const isAdmin = authState?.user?.role === "admin";
  const supportsNameserver = isAdmin && ["forward", "reverse", "scan"].includes(mode);
  tabs.forEach((tab) => {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  nameLabel.hidden = bulkPortScan;
  primaryInputWrap.hidden = bulkPortScan;
  input.required = !bulkPortScan;
  nameLabel.textContent = automatic
    ? "Search"
    : reverse ? "IP address" : mac ? "MAC address" : "Domain name or IP address";
  input.placeholder = reverse
    ? "e.g. 8.8.8.8 or 2001:4860:4860::8888"
    : mac
      ? "e.g. 00:1A:2B:3C:4D:5E"
    : details || ping
      ? "e.g. example.com or 8.8.8.8"
    : automatic
      ? "Domain, IP address, or MAC address"
    : customPortScan
      ? "e.g. example.com or 8.8.8.8"
      : "e.g. example.com";
  input.autocomplete = reverse || mac || portScan ? "off" : "url";
  typeControl.hidden = automatic || reverse || details || mac || ping || scan || portScan;
  customType.hidden = automatic || reverse || details || mac || ping || scan || portScan || recordType.value !== "custom";
  nameserverControl.hidden = !supportsNameserver;
  if (!isAdmin) nameserverInput.value = "";
  pingMethodControl.hidden = !ping;
  portScanControl.hidden = !scan || !authState?.user;
  customPortsControl.hidden = !customPortScan;
  bulkTargetsControl.hidden = !bulkPortScan;
  bulkPortControl.hidden = !bulkPortScan;
  customPortsInput.required = customPortScan;
  bulkTargetsInput.required = bulkPortScan;
  bulkPortInput.required = bulkPortScan;
  autoDetectHint.hidden = !automatic;
  formHint.hidden = automatic;
  formHint.textContent = automatic
    ? "Automatic lookup: domains use DNS, IP addresses use reverse DNS, and MAC addresses use vendor lookup."
    : reverse
    ? "Find the PTR record associated with an IPv4 or IPv6 address."
    : details
      ? "View public domain or IP registration (RDAP/WHOIS) and authoritative nameserver details."
      : ping
        ? "Check whether a remote host is up using ICMP ping or an HTTP(S) GET request."
      : mac
        ? "Find the registered hardware vendor and MAC address type."
      : scan
        ? "Scan DNS records, cloud-provider hostnames, SPF, and DKIM. Optionally choose the nameserver."
      : customPortScan
        ? "Scan a custom list or range of TCP ports on one domain or IP address."
      : bulkPortScan
        ? "Check one TCP port across an explicit list or CIDR block of IP addresses."
        : "Choose a record type or enter a custom DNS type. ANY returns records the DNS server makes available.";
  submitButton.innerHTML = `<span>${automatic ? "Auto lookup" : scan ? "Magic scan" : customPortScan ? "Custom port scan" : bulkPortScan ? "Bulk port scan" : mac ? "Lookup MAC" : ping ? "Ping host" : "Lookup"}</span><span aria-hidden="true">→</span>`;
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  if (automatic) updateAutoDetectHint();
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
    tabs.filter((tab) => tab !== autoTab).forEach((tab) => {
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
    autoTab.hidden = availableTabs.length === 0;
    const initialTab = availableTabs.length ? autoTab : null;
    modeTabs.hidden = !initialTab;
    lookupForm.hidden = !initialTab;
    loginRequiredNotice.hidden = Boolean(initialTab);
    guestUsageNotice.hidden = !initialTab || Boolean(authState.user);
    if (!initialTab && authState.user) {
      loginRequiredMessage.textContent = "No lookup tools are available to your account. Contact an administrator.";
      toolsLoginLink.hidden = true;
    }
    if (initialTab) setMode("auto");
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

function copyableResult(value, className = "") {
  const text = String(value);
  return `<span class="copy-result ${className}" data-copy-value="${escapeHtml(text)}" role="button" tabindex="0" aria-label="Copy result" title="Click to copy">${escapeHtml(text)}</span>`;
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Use the legacy clipboard path when browser permissions block Clipboard API access.
    }
  }
  const temporaryInput = document.createElement("textarea");
  temporaryInput.value = value;
  temporaryInput.setAttribute("readonly", "");
  temporaryInput.style.position = "fixed";
  temporaryInput.style.opacity = "0";
  document.body.append(temporaryInput);
  temporaryInput.select();
  const copied = document.execCommand("copy");
  temporaryInput.remove();
  if (!copied) throw new Error("Clipboard access is unavailable.");
}

async function copyResult(element) {
  try {
    await copyText(element.dataset.copyValue);
    element.classList.add("copied");
    element.title = "Copied!";
    element.setAttribute("aria-label", "Copied to clipboard");
    let feedback = document.querySelector("#copy-feedback");
    if (!feedback) {
      feedback = document.createElement("div");
      feedback.id = "copy-feedback";
      feedback.className = "copy-feedback";
      feedback.setAttribute("role", "status");
      feedback.setAttribute("aria-live", "polite");
      document.body.append(feedback);
    }
    feedback.textContent = "Copied to clipboard";
    feedback.classList.add("visible");
    window.clearTimeout(feedback.hideTimeout);
    feedback.hideTimeout = window.setTimeout(() => feedback.classList.remove("visible"), 1400);
    window.setTimeout(() => {
      if (!element.isConnected) return;
      element.classList.remove("copied");
      element.title = "Click to copy";
      element.setAttribute("aria-label", "Copy result");
    }, 1400);
  } catch {
    errorMessage.textContent = "Unable to copy this result. Check clipboard permissions and try again.";
    errorMessage.hidden = false;
  }
}

const dnsRecordTypeNames = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  39: "DNAME",
  43: "DS",
  44: "SSHFP",
  46: "RRSIG",
  47: "NSEC",
  48: "DNSKEY",
  52: "TLSA",
  64: "SVCB",
  65: "HTTPS",
  257: "CAA",
};

function renderDnsResults(sections, ptrLookups = {}) {
  const records = sections.flatMap(({ title, records: sectionRecords }) =>
    sectionRecords.map((record) => ({ ...record, section: title })),
  );
  if (!records.length) {
    return '<p class="empty-result">No records were returned for this query.</p>';
  }
  const recordRows = records.map((record, index) => {
    const reverse = ptrLookups[record.data];
    const ptrContent = reverse
      ? reverse.error
        ? copyableResult(`PTR lookup: ${reverse.error}`, "ptr-result")
        : reverse.answers.length
          ? copyableResult(`PTR: ${reverse.answers.join(", ")}`, "ptr-result")
          : copyableResult(`PTR: no record (${reverse.status})`, "ptr-result")
      : "";
    const type = dnsRecordTypeNames[record.type] || `TYPE${record.type}`;
    return `
    <tr>
      <td class="dns-row-number">${index + 1}</td>
      <td>${copyableResult(record.section)}</td>
      <td class="record-name">${copyableResult(record.name)}</td>
      <td>${copyableResult(type)}</td>
      <td data-sort-value="${escapeHtml(record.TTL)}">${copyableResult(`${record.TTL}s`)}</td>
      <td class="record-data">${copyableResult(record.data)}${ptrContent}</td>
    </tr>`;
  }).join("");
  return `
    <section class="record-section dns-results">
      <div class="dns-results-toolbar">
        <h3>DNS records <span class="dns-results-count">${records.length}</span></h3>
        <label class="dns-results-search-label">
          <span class="sr-only">Search DNS results</span>
          <input class="dns-results-search" type="search" placeholder="Search results…" autocomplete="off">
        </label>
      </div>
      <div class="dns-results-table-wrap">
        <table class="dns-results-table">
          <thead><tr>
            <th scope="col">#</th>
            <th scope="col"><button type="button" data-sort-column="1" data-sort-type="text">Section</button></th>
            <th scope="col"><button type="button" data-sort-column="2" data-sort-type="text">Name</button></th>
            <th scope="col"><button type="button" data-sort-column="3" data-sort-type="text">Type</button></th>
            <th scope="col"><button type="button" data-sort-column="4" data-sort-type="number">TTL</button></th>
            <th scope="col"><button type="button" data-sort-column="5" data-sort-type="text">Data</button></th>
          </tr></thead>
          <tbody>${recordRows}</tbody>
        </table>
      </div>
      <p class="empty-result dns-results-empty" hidden>No records match your search.</p>
    </section>`;
}

function showResult(data) {
  const statusClass = data.status === 0 ? "success" : "warning";
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div>
        <p class="eyebrow">LOOKUP RESULT</p>
        <h2>${copyableResult(data.name)}</h2>
      </div>
      <span class="status-badge ${statusClass}">${copyableResult(data.statusText)}</span>
    </div>
    ${data.nameserver ? `<div class="query-meta"><span>Queried nameserver</span>${copyableResult(data.nameserver)}</div>` : ""}
    <div class="query-meta"><span>Record type</span>${copyableResult(data.type)}</div>
    ${renderDnsResults([
      { title: "Answers", records: data.answers },
      { title: "Authority", records: data.authority },
      { title: "Additional", records: data.additional },
    ], data.ptrLookups)}
    ${data.status === 0 && !data.answers.length ? '<p class="empty-result">The query succeeded, but no matching records were returned.</p>' : ""}`;
  resultPanel.hidden = false;
}

resultPanel.addEventListener("input", (event) => {
  if (!event.target.matches(".dns-results-search")) return;
  const table = resultPanel.querySelector(".dns-results-table");
  const query = event.target.value.trim().toLocaleLowerCase();
  let visibleCount = 0;
  for (const row of table.tBodies[0].rows) {
    row.hidden = !row.textContent.toLocaleLowerCase().includes(query);
    if (!row.hidden) {
      visibleCount += 1;
      row.cells[0].textContent = visibleCount;
    }
  }
  resultPanel.querySelector(".dns-results-empty").hidden = visibleCount !== 0;
  resultPanel.querySelector(".dns-results-count").textContent = visibleCount;
});

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-copy-value]");
  if (target) void copyResult(target);
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const target = event.target.closest("[data-copy-value]");
  if (!target) return;
  event.preventDefault();
  void copyResult(target);
});

resultPanel.addEventListener("click", (event) => {
  const button = event.target.closest(".dns-results-table button[data-sort-column]");
  if (!button) return;
  const table = button.closest("table");
  const body = table.tBodies[0];
  const column = Number(button.dataset.sortColumn);
  const numeric = button.dataset.sortType === "number";
  const ascending = button.getAttribute("aria-sort") !== "ascending";
  const rows = [...body.rows];
  rows.sort((left, right) => {
    const leftCell = left.cells[column];
    const rightCell = right.cells[column];
    const leftValue = leftCell.dataset.sortValue ?? leftCell.textContent.trim();
    const rightValue = rightCell.dataset.sortValue ?? rightCell.textContent.trim();
    const comparison = numeric
      ? Number(leftValue) - Number(rightValue)
      : leftValue.localeCompare(rightValue, undefined, { numeric: true, sensitivity: "base" });
    return ascending ? comparison : -comparison;
  });
  rows.forEach((row, index) => {
    row.cells[0].textContent = index + 1;
    body.append(row);
  });
  table.querySelectorAll("th button[aria-sort]").forEach((sortButton) => {
    sortButton.removeAttribute("aria-sort");
  });
  button.setAttribute("aria-sort", ascending ? "ascending" : "descending");
  const search = resultPanel.querySelector(".dns-results-search");
  if (search.value) search.dispatchEvent(new Event("input", { bubbles: true }));
});

function renderScanResult(data) {
  const foundHosts = data.hosts.filter((host) => host.records.length);
  const scanRecordCount = foundHosts.reduce(
    (count, host) => count + host.records.reduce(
      (recordCount, record) => recordCount + record.answers.length,
      0,
    ),
    0,
  );
  let rowNumber = 0;
  const scanRows = foundHosts.flatMap((host) =>
    host.records.flatMap((record) => record.answers.map((answer) => {
      const ptr = data.ptrLookups?.[answer.data];
      const ptrText = ptr
        ? ptr.error
          ? `PTR lookup: ${ptr.error}`
          : ptr.answers.length
            ? ptr.answers.join(", ")
            : `No PTR record (${ptr.status})`
        : "";
      const geolocation = data.ipGeolocations?.[answer.data];
      const locationText = geolocation
        ? geolocation.country
          ? [
            geolocation.city,
            geolocation.region,
            geolocation.country,
          ].filter(Boolean).join(", ") +
            (geolocation.countryCode ? ` (${geolocation.countryCode})` : "")
          : geolocation.error
        : "";
      const ttl = answer.TTL ?? answer.ttl;
      const sources = host.providers.length ? host.providers : ["Built-in"];
      return `<tr>
        <td class="dns-row-number">${++rowNumber}</td>
        <td class="magic-host">${copyableResult(host.name)}</td>
        <td class="magic-type">${copyableResult(record.type, "magic-type-badge")}</td>
        <td class="magic-ttl" data-sort-value="${escapeHtml(ttl ?? "")}">${ttl === undefined ? "—" : copyableResult(`${ttl}s`)}</td>
        <td class="magic-data">${copyableResult(answer.data, "record-data")}</td>
        <td class="magic-ptr">${ptrText ? copyableResult(ptrText, "ptr-result") : "—"}</td>
        <td class="magic-location">${locationText ? copyableResult(locationText, "geo-result") : "—"}</td>
        <td class="magic-source">${sources.map((source) => copyableResult(source, "magic-source-badge")).join(" ")}</td>
      </tr>`;
    })),
  ).join("");
  const hostResults = scanRows
    ? `<section class="record-section dns-results">
        <div class="dns-results-toolbar">
          <h3>Discovered DNS records <span class="dns-results-count">${scanRecordCount}</span></h3>
          <label class="dns-results-search-label">
            <span class="sr-only">Search Magic scan results</span>
            <input class="dns-results-search" type="search" placeholder="Search results…" autocomplete="off">
          </label>
        </div>
        <div class="dns-results-table-wrap">
          <table class="dns-results-table magic-scan-table">
            <thead><tr>
              <th class="magic-number-heading" scope="col">#</th>
              <th class="magic-host-heading" scope="col"><button type="button" data-sort-column="1" data-sort-type="text">Host</button></th>
              <th class="magic-type-heading" scope="col"><button type="button" data-sort-column="2" data-sort-type="text">Type</button></th>
              <th class="magic-ttl-heading" scope="col"><button type="button" data-sort-column="3" data-sort-type="number">TTL</button></th>
              <th class="magic-data-heading" scope="col"><button type="button" data-sort-column="4" data-sort-type="text">Record data</button></th>
              <th class="magic-ptr-heading" scope="col"><button type="button" data-sort-column="5" data-sort-type="text">PTR</button></th>
              <th class="magic-location-heading" scope="col"><button type="button" data-sort-column="6" data-sort-type="text">Geolocation</button></th>
              <th class="magic-source-heading" scope="col"><button type="button" data-sort-column="7" data-sort-type="text">Source</button></th>
            </tr></thead>
            <tbody>${scanRows}</tbody>
          </table>
        </div>
        <p class="empty-result dns-results-empty" hidden>No records match your search.</p>
      </section>`
    : '<p class="empty-result">No DNS records found for the domain or checked subdomains.</p>';
  const emailSecurity = data.emailSecurity;
  const spfRecords = emailSecurity.spfRecords.map((record) => `
    <div class="email-auth-record"><strong>${copyableResult(record.name)}</strong>${copyableResult(record.data)}</div>
  `).join("");
  const dkimRecords = emailSecurity.dkimRecords.map((entry) => `
    <div class="email-auth-record">
      <strong>${copyableResult(entry.name)}</strong>
      ${copyableResult(entry.records.map((record) => `${record.type}: ${record.data}`).join("\n"))}
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
          ${copyableResult(result.domain, "port-target-domain")}
          ${copyableResult(result.address, "port-target-address")}
        </div>
        <div class="port-scan-open-ports">${result.openPorts.length
    ? result.openPorts.map((port) => copyableResult(port, "port-badge")).join("")
    : "No open ports found in the checked set"}
          ${location ? copyableResult(location, "geo-result scan-result-detail") : ""}
        </div>
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
      ? `<div class="contact-row"><span>${escapeHtml(role)}</span><strong>${copyableResult(values.join(" · "))}</strong></div>`
      : "";
  }).join("");
  const registrationNameservers = (registration?.nameservers || []).map((nameserver) => `
    <div class="detail-row">
      <span>Nameserver</span>
      <strong>${copyableResult(
    `${nameserver.name}${[...nameserver.ipv4, ...nameserver.ipv6].length
      ? ` · ${[...nameserver.ipv4, ...nameserver.ipv6].join(", ")}`
      : ""}`,
  )}
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
    ? `<div class="status-list">${registration.statuses.map((status) => copyableResult(status)).join("")}</div>`
    : ""}
      ${registrationContacts ? `<div class="contact-list">${registrationContacts}</div>` : ""}`
    : `<p class="detail-notice">${escapeHtml(data.registrationError || "No registration details were returned.")}</p>`;

  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">MAGIC SCAN</p><h2>${copyableResult(data.domain)}</h2></div>
      <span class="status-badge success">${copyableResult(`${data.hostsWithRecords} hosts found`)}</span>
    </div>
    <div class="scan-summary">
      ${copyableResult(`${data.subdomainsChecked} subdomains checked`)}
      ${copyableResult(`${data.certificateTransparencySubdomains} additional names from ${data.certificateTransparencySource || "certificate logs"}`)}
      ${copyableResult(`${data.recordTypes.join(" · ")} plus provider checks`)}
    </div>
    ${data.nameserver ? `<div class="query-meta"><span>Queried nameserver</span>${copyableResult(data.nameserver)}</div>` : ""}
    <p class="scan-disclaimer">IP geolocation (including country) is approximate. Public IP addresses found in scan results are sent to ipwho.is; private and reserved addresses are not sent.</p>
    ${data.failedQueries ? `<p class="detail-notice">${escapeHtml(data.failedQueries)} DNS queries could not be completed.</p>` : ""}
    ${data.subdomainDiscoveryError ? `<p class="detail-notice">${escapeHtml(data.subdomainDiscoveryError)}</p>` : ""}
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
    ${hostResults}
    <p class="scan-disclaimer">Subdomain discovery checks a built-in list and up to 25 names from public Certificate Transparency logs, trying crt.sh and then CertSpotter if needed, before verifying them with DNS. It does not enumerate every subdomain. The queried domain is sent to crt.sh and, if it fails, also to CertSpotter; IP geolocation is provided by ipwho.is and may be unavailable or approximate.</p>`;
  resultPanel.hidden = false;
}

function renderPortScanResult(data, title) {
  const results = data.results.map((result) => `
    <div class="port-scan-address">
      <div class="port-scan-target">
        ${copyableResult(result.target)}
        ${result.target !== result.address ? copyableResult(result.address, "port-target-address") : ""}
      </div>
      <div class="port-scan-open-ports">${result.openPorts.length
    ? result.openPorts.map((port) => copyableResult(port, "port-badge")).join("")
    : "No open ports found"}
      </div>
    </div>
  `).join("");
  const openPortCount = data.results.reduce((count, result) => count + result.openPorts.length, 0);
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">${escapeHtml(title.toUpperCase())}</p><h2>${copyableResult(data.scanLabel)}</h2></div>
      <span class="status-badge ${openPortCount ? "success" : "warning"}">${copyableResult(`${openPortCount} open`)}</span>
    </div>
    <div class="scan-summary">
      <span>${copyableResult(`${data.addressesScanned} eligible IP address(es) scanned`)}</span>
      <span>${copyableResult(`${data.portsChecked} TCP port(s) checked per address`)}</span>
    </div>
    ${data.addressesSkipped ? `<p class="detail-notice">${escapeHtml(data.addressesSkipped)} disallowed, reserved, or excess IP address(es) were skipped.</p>` : ""}
    ${results || '<p class="empty-result">No eligible IP addresses were available to scan.</p>'}
    <p class="scan-disclaimer">Only ports that accepted a TCP connection are listed. Scan only systems you are authorized to test.</p>`;
  resultPanel.hidden = false;
}

function renderPingResult(data) {
  const methodLabels = { icmp: "ICMP ping", https: "HTTPS GET", http: "HTTP GET" };
  const up = Boolean(data.up);
  const details = [];
  if (data.method === "icmp") {
    if (data.transmitted !== undefined) {
      details.push(
        renderDetail("Packets", `${data.received} received of ${data.transmitted} sent`),
        renderDetail("Packet loss", `${data.lossPercent}%`),
        renderDetail("Round trip (min / avg / max)", data.avgMs === null || data.avgMs === undefined
          ? ""
          : `${data.minMs} / ${data.avgMs} / ${data.maxMs} ms`),
      );
    }
  } else if (data.status) {
    details.push(
      renderDetail("HTTP status", `${data.status} ${data.statusText || ""}`.trim()),
      renderDetail("Response time", `${data.responseMs} ms`),
      renderDetail("Redirects to", data.redirect),
      renderDetail("Server", data.server),
      data.tlsAuthorized === null || data.tlsAuthorized === undefined
        ? ""
        : renderDetail("TLS certificate", data.tlsAuthorized ? "Trusted" : "Not trusted or name mismatch"),
    );
  }
  const times = data.times?.length
    ? `<div class="ping-times">${data.times.map((time) => `<span>${escapeHtml(String(time))} ms</span>`).join("")}</div>`
    : "";
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">HOST CHECK</p><h2>${copyableResult(data.target)}</h2></div>
      <span class="status-badge ${up ? "success" : "warning"}">${up ? "Host is up" : "No response"}</span>
    </div>
    <section class="record-section">
      <h3>${escapeHtml(methodLabels[data.method] || "Ping")}</h3>
      <div class="detail-list">
        ${renderDetail("Target address", data.address)}
        ${details.join("")}
      </div>
      ${times}
      ${data.error ? `<p class="detail-notice">${escapeHtml(data.error)}</p>` : ""}
      ${!up && !data.error ? '<p class="detail-notice">No replies were received. The host may be down or may block this type of check.</p>' : ""}
    </section>`;
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
      <div><p class="eyebrow">MAC ADDRESS LOOKUP</p><h2>${copyableResult(data.mac)}</h2></div>
      <span class="status-badge ${data.found ? "success" : "warning"}">${copyableResult(data.found ? "Vendor found" : "Vendor unknown")}</span>
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
  return `<div class="detail-row"><span>${escapeHtml(label)}</span><strong>${copyableResult(value)}</strong></div>`;
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
      return copyableResult(`${address} — ${value}`, "nameserver-ptr");
    }).join("");
    return `<div class="nameserver-row">
      ${copyableResult(name, "nameserver-name")}
      ${dnsEntry ? copyableResult(`TTL ${dnsEntry.ttl}s`, "record-ttl") : ""}
      ${ptrMarkup || (addresses.length ? copyableResult(addresses.join(" · "), "nameserver-addresses") : "")}
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
    return `<div class="contact-row"><span>${escapeHtml(label)}</span><strong>${copyableResult(values.join(" · "))}</strong></div>`;
  }).join("");
  const formattedDates = Object.entries(dates).map(([action, date]) =>
    renderDetail(dateLabels[action] || action, new Date(date).toLocaleDateString()),
  ).join("");

  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">DOMAIN DETAILS</p><h2>${copyableResult(data.domain)}</h2></div>
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

function buildIpRegistrationTable(registration) {
  const rows = [
    ["Network", registration.name],
    ["Handle", registration.handle],
    ["AS number", registration.asNumbers?.length ? registration.asNumbers.map((asn) => `AS ${String(asn).replace(/^AS/i, "")}`).join(", ") : ""],
    ["Subnet / CIDR", registration.cidrs?.join(", ")],
    ["Address range", formatIpAddressRange(registration)],
    ["Country", registration.country],
    ["Network type", registration.type],
  ].filter(([, value]) => value);
  const table = document.createElement("table");
  table.className = "client-whois-table";
  const body = table.createTBody();
  for (const [label, value] of rows) {
    const row = body.insertRow();
    const th = document.createElement("th");
    th.scope = "row";
    th.textContent = label;
    row.append(th);
    const cell = row.insertCell();
    cell.textContent = value;
    cell.className = "copy-result";
    cell.dataset.copyValue = value;
    cell.setAttribute("role", "button");
    cell.tabIndex = 0;
    cell.title = "Click to copy";
  }
  if (registration.asnError && !registration.asNumbers?.length) {
    const row = body.insertRow();
    const th = document.createElement("th");
    th.scope = "row";
    th.textContent = "AS number";
    row.append(th);
    row.insertCell().textContent = `Unavailable (${registration.asnError})`;
  }
  return table;
}

function formatIpAddressRange(registration) {
  return [registration.startAddress, registration.endAddress]
    .filter(Boolean)
    .filter((address, index, addresses) => addresses.indexOf(address) === index)
    .join(" – ");
}

function ipRegistrationHtml(data) {
  const registration = data.ipRegistration;
  const dateLabels = {
    registration: "Registered",
    "last changed": "Last updated",
    "last update of RDAP database": "RDAP record updated",
  };
  const contacts = (registration?.contacts || []).map((contact) => {
    const role = contact.roles.length ? contact.roles.join(", ") : "Contact";
    const values = [
      contact.name,
      contact.organization,
      contact.email,
      contact.phone,
      contact.address,
    ].filter(Boolean);
    return values.length
      ? `<div class="contact-row"><span>${escapeHtml(role)}</span><strong>${copyableResult(values.join(" · "))}</strong></div>`
      : "";
  }).join("");

  return `
    ${data.registrationError ? `<p class="detail-notice">${escapeHtml(data.registrationError)}</p>` : ""}
    ${registration ? `<section class="record-section">
      <h3>Network registration</h3>
      <div class="detail-list">
        ${renderDetail("Network", registration.name)}
        ${renderDetail("Registry handle", registration.handle)}
        ${renderDetail("AS number", registration.asNumbers?.join(", "))}
        ${renderDetail("Subnet / CIDR", registration.cidrs?.join(", "))}
        ${registration.asnError ? `<p class="detail-notice">${escapeHtml(registration.asnError)}</p>` : ""}
        ${renderDetail("Address range", formatIpAddressRange(registration))}
        ${renderDetail("IP version", registration.ipVersion)}
        ${renderDetail("Country", registration.country)}
        ${renderDetail("Network type", registration.type)}
        ${renderDetail("Parent network", registration.parentHandle)}
        ${Object.entries(registration.dates || {}).map(([action, date]) =>
    renderDetail(dateLabels[action] || action, new Date(date).toLocaleDateString()),
  ).join("")}
        ${renderDetail("WHOIS server", registration.port43)}
      </div>
      ${registration.statuses?.length
    ? `<div class="status-list">${registration.statuses.map((status) => copyableResult(status)).join("")}</div>`
    : ""}
      ${contacts ? `<div class="contact-list">${contacts}</div>` : ""}
    </section>` : '<p class="empty-result">No IP registration details could be retrieved.</p>'}
    <p class="scan-disclaimer">IP registration information is retrieved from RDAP, the modern WHOIS service. Contact details may be redacted or unavailable.</p>`;
}

function renderIpInfo(data) {
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">IP WHOIS / RDAP</p><h2>${copyableResult(data.ip)}</h2></div>
    </div>
    ${ipRegistrationHtml(data)}`;
  resultPanel.hidden = false;
}

async function appendIpRegistration(ip) {
  const access = authState?.featureAccess?.whois || "user";
  const permitted = Boolean(authState?.user) &&
    (access !== "admin" || authState.user.role === "admin") ||
    access === "public";
  if (!permitted) return;
  const section = document.createElement("section");
  section.className = "ip-whois-section";
  section.innerHTML = '<p class="detail-notice">Looking up IP WHOIS / RDAP…</p>';
  resultPanel.append(section);
  try {
    const response = await fetch(`/api/domain-info?${new URLSearchParams({ name: ip })}`, { credentials: "same-origin" });
    const data = await readApiResponse(response);
    if (!response.ok || !data.ip) throw new Error(data.error || "IP WHOIS lookup failed.");
    if (!section.isConnected) return;
    section.innerHTML = `<p class="eyebrow">IP WHOIS / RDAP</p>${ipRegistrationHtml(data)}`;
  } catch (error) {
    if (section.isConnected) section.innerHTML = `<p class="detail-notice">${escapeHtml(error.message)}</p>`;
  }
}

function detectAutomaticLookup(value) {
  const candidate = value.trim();
  const macPattern = /^(?:[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4})$/i;
  if (macPattern.test(candidate)) return { mode: "mac", name: candidate };

  const ipv4Parts = candidate.split(".");
  if (ipv4Parts.length === 4 && ipv4Parts.every((part) => /^\d{1,3}$/.test(part))) {
    if (ipv4Parts.every((part) => Number(part) <= 255)) {
      return { mode: "reverse", name: candidate };
    }
    throw new Error("Enter a valid IPv4 address.");
  }

  if (!/^https?:\/\//i.test(candidate)) {
    try {
      const ipv6Candidate = candidate.startsWith("[") && candidate.endsWith("]")
        ? candidate.slice(1, -1)
        : candidate;
      const ipv6 = new URL(`http://[${ipv6Candidate}]/`).hostname;
      if (ipv6.startsWith("[") && ipv6.endsWith("]")) {
        return { mode: "reverse", name: ipv6Candidate };
      }
    } catch {
      if (candidate.includes(":")) throw new Error("Enter a valid IPv6 address.");
    }
  }

  if (!candidate || /\s/.test(candidate)) {
    throw new Error("Enter a domain name, an IP address, or a MAC address.");
  }

  try {
    const isUrl = /^https?:\/\//i.test(candidate);
    const url = new URL(isUrl ? candidate : `https://${candidate}`);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      (!isUrl && url.port)
    ) {
      throw new Error();
    }
    const hostname = url.hostname;
    if (hostname.startsWith("[") && hostname.endsWith("]")) {
      return { mode: "reverse", name: hostname.slice(1, -1) };
    }
    const hostnameParts = hostname.split(".");
    if (
      hostnameParts.length === 4 &&
      hostnameParts.every((part) => /^\d{1,3}$/.test(part)) &&
      hostnameParts.every((part) => Number(part) <= 255)
    ) {
      return { mode: "reverse", name: hostname };
    }
    return { mode: "forward", name: hostname };
  } catch {
    throw new Error("Enter a valid domain name, an IP address, or a MAC address.");
  }
}

function updateAutoDetectHint() {
  const value = input.value.trim();
  if (!value) {
    autoDetectHint.textContent = "Enter a domain for DNS, an IP address for reverse DNS, or a MAC address for vendor details.";
    return;
  }
  try {
    const { mode: detectedMode } = detectAutomaticLookup(value);
    const labels = {
      forward: "DNS lookup",
      reverse: "reverse DNS lookup",
      mac: "MAC vendor lookup",
    };
    autoDetectHint.textContent = `Detected: ${labels[detectedMode]}.`;
  } catch (error) {
    autoDetectHint.textContent = error.message;
  }
}

tabs.forEach((tab) => tab.addEventListener("click", () => {
  if (tab === autoTab) {
    setMode("auto");
    return;
  }
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
input.addEventListener("input", () => {
  if (mode === "auto") updateAutoDetectHint();
});
recordType.addEventListener("change", () => {
  customType.hidden = mode === "reverse" || recordType.value !== "custom";
  if (!customType.hidden) customType.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  let requestMode = mode;
  let lookupName = input.value.trim();
  if (mode === "auto") {
    try {
      ({ mode: requestMode, name: lookupName } = detectAutomaticLookup(lookupName));
    } catch (error) {
      errorMessage.textContent = error.message;
      errorMessage.hidden = false;
      return;
    }
    const feature = requestMode === "mac" ? "mac" : requestMode;
    const access = authState?.featureAccess?.[feature] || "user";
    const permitted = Boolean(authState?.user) &&
      (access !== "admin" || authState.user.role === "admin") ||
      access === "public";
    if (!permitted) {
      if (access !== "public" && !authState?.user) {
        const next = `${window.location.pathname}${window.location.search}`;
        window.location.assign(`/login.html?next=${encodeURIComponent(next)}`);
        return;
      }
      errorMessage.textContent = "This lookup is restricted by the administrator.";
      errorMessage.hidden = false;
      return;
    }
  }
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  submitButton.disabled = true;
  const customPortScan = requestMode === "custom-port";
  const bulkPortScan = requestMode === "bulk-port";
  const isPortScan = customPortScan || bulkPortScan;
  submitButton.innerHTML = `<span class="spinner" aria-hidden="true"></span><span>${requestMode === "scan" ? "Scanning" : isPortScan ? "Scanning ports" : "Looking up"}</span>`;

  const params = new URLSearchParams({
    name: lookupName,
    type: recordType.value === "custom" ? customType.value.trim() : recordType.value,
    reverse: String(requestMode === "reverse"),
    nameserver: authState?.user?.role === "admin" &&
      ["forward", "reverse", "scan"].includes(requestMode)
      ? nameserverInput.value.trim()
      : "",
  });
  if (requestMode === "ping") params.set("method", pingMethodInput.value);
  if (requestMode === "scan" && portScanInput.checked) {
    params.set("ports", "common");
  }

  try {
    const endpoint = customPortScan
      ? "/api/custom-port-scan"
      : bulkPortScan
        ? "/api/bulk-port-scan"
        : requestMode === "details"
      ? "/api/domain-info"
        : requestMode === "ping"
        ? "/api/ping"
        : requestMode === "mac"
        ? "/api/mac-lookup"
        : requestMode === "scan"
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
    const data = await readApiResponse(response);
    if (response.status === 401) {
      const next = `${window.location.pathname}${window.location.search}`;
      window.location.assign(`/login.html?next=${encodeURIComponent(next)}`);
      return;
    }
    if (!response.ok) throw new Error(data.error || "DNS lookup failed.");
    if (requestMode === "details" && data.ip) renderIpInfo(data);
    else if (requestMode === "details") renderDomainInfo(data);
    else if (requestMode === "ping") renderPingResult(data);
    else if (requestMode === "mac") renderMacResult(data);
    else if (requestMode === "scan") renderScanResult(data);
    else if (isPortScan) renderPortScanResult(data, customPortScan ? "Custom port scan" : "Bulk port scan");
    else {
      showResult(data);
      if (requestMode === "reverse") appendIpRegistration(lookupName.replace(/^\[|\]$/g, ""));
    }
  } catch (error) {
    errorMessage.textContent = error.message || "Unable to complete the lookup.";
    errorMessage.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = `<span>${mode === "auto" ? "Auto lookup" : mode === "scan" ? "Magic scan" : mode === "custom-port" ? "Custom port scan" : mode === "bulk-port" ? "Bulk port scan" : mode === "mac" ? "Lookup MAC" : mode === "ping" ? "Ping host" : "Lookup"}</span><span aria-hidden="true">→</span>`;
  }
});

initializeAccount();
loadClientInfo();
