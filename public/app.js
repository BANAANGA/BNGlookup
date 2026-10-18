const form = document.querySelector("#lookup-form");
const input = document.querySelector("#name-input");
const recordType = document.querySelector("#record-type");
const customType = document.querySelector("#custom-type");
const typeControl = document.querySelector("#type-control");
const resultPanel = document.querySelector("#result");
const errorMessage = document.querySelector("#error-message");
const submitButton = document.querySelector("#submit-button");
const nameLabel = document.querySelector("#name-label");
const formHint = document.querySelector("#form-hint");
const tabs = [...document.querySelectorAll(".mode-tab")];
let mode = "forward";

function setMode(nextMode) {
  mode = nextMode;
  const reverse = mode === "reverse";
  const details = mode === "details";
  tabs.forEach((tab) => {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  nameLabel.textContent = reverse ? "IP address" : "Domain name";
  input.placeholder = reverse
    ? "e.g. 8.8.8.8 or 2001:4860:4860::8888"
    : "e.g. example.com";
  input.autocomplete = reverse ? "off" : "url";
  typeControl.hidden = reverse || details;
  customType.hidden = reverse || details || recordType.value !== "custom";
  formHint.textContent = reverse
    ? "Find the PTR record associated with an IPv4 or IPv6 address."
    : details
      ? "View public domain registration (RDAP/WHOIS) and authoritative nameserver details."
      : "Choose a record type or enter a custom DNS type. ANY returns records the DNS server makes available.";
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  input.focus();
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
  return `<section class="record-section"><h3>${title}<span>${records.length}</span></h3>${renderRecords(records, ptrLookups)}</section>`;
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
    <div class="query-meta"><span>Record type</span><strong>${escapeHtml(data.type)}</strong></div>
    ${renderSection("Answers", data.answers, data.ptrLookups)}
    ${renderSection("Authority", data.authority, data.ptrLookups)}
    ${renderSection("Additional", data.additional, data.ptrLookups)}
    ${data.status === 0 && !data.answers.length ? '<p class="empty-result">The query succeeded, but no matching records were returned.</p>' : ""}`;
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

tabs.forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));
recordType.addEventListener("change", () => {
  customType.hidden = mode === "reverse" || recordType.value !== "custom";
  if (!customType.hidden) customType.focus();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  submitButton.disabled = true;
  submitButton.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>Looking up</span>';

  const params = new URLSearchParams({
    name: input.value.trim(),
    type: recordType.value === "custom" ? customType.value.trim() : recordType.value,
    reverse: String(mode === "reverse"),
  });

  try {
    const endpoint = mode === "details" ? "/api/domain-info" : "/api/lookup";
    const response = await fetch(`${endpoint}?${params}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "DNS lookup failed.");
    if (mode === "details") renderDomainInfo(data);
    else showResult(data);
  } catch (error) {
    errorMessage.textContent = error.message || "Unable to complete the lookup.";
    errorMessage.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = '<span>Lookup</span><span aria-hidden="true">→</span>';
  }
});
