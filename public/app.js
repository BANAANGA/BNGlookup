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
  tabs.forEach((tab) => {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  nameLabel.textContent = reverse ? "IP address" : "Domain name";
  input.placeholder = reverse ? "e.g. 8.8.8.8 or 2001:4860:4860::8888" : "e.g. example.com";
  input.autocomplete = reverse ? "off" : "url";
  typeControl.hidden = reverse;
  customType.hidden = reverse || recordType.value !== "custom";
  formHint.textContent = reverse
    ? "Find the PTR record associated with an IPv4 or IPv6 address."
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

function renderRecords(records) {
  if (!records.length) {
    return '<p class="empty-result">No records were returned for this query.</p>';
  }
  return `<div class="records">${records.map((record) => `
    <div class="record-row">
      <span class="record-name">${escapeHtml(record.name)}</span>
      <span class="record-ttl">${escapeHtml(record.TTL)}s</span>
      <span class="record-data">${escapeHtml(record.data)}</span>
    </div>`).join("")}</div>`;
}

function renderSection(title, records) {
  if (!records.length) return "";
  return `<section class="record-section"><h3>${title}<span>${records.length}</span></h3>${renderRecords(records)}</section>`;
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
    ${renderSection("Answers", data.answers)}
    ${renderSection("Authority", data.authority)}
    ${renderSection("Additional", data.additional)}
    ${data.status === 0 && !data.answers.length ? '<p class="empty-result">The query succeeded, but no matching records were returned.</p>' : ""}`;
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
    const response = await fetch(`/api/lookup?${params}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "DNS lookup failed.");
    showResult(data);
  } catch (error) {
    errorMessage.textContent = error.message || "Unable to complete the lookup.";
    errorMessage.hidden = false;
  } finally {
    submitButton.disabled = false;
    submitButton.innerHTML = '<span>Lookup</span><span aria-hidden="true">→</span>';
  }
});
