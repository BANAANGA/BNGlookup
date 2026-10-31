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
const nmapControl = document.querySelector("#nmap-control");
const nmapScanType = document.querySelector("#nmap-scan-type");
const multiTraceControl = document.querySelector("#multi-trace-control");
const multiTraceInput = document.querySelector("#multi-trace-input");
const tracePtrControl = document.querySelector("#trace-ptr-control");
const tracePtrInput = document.querySelector("#trace-ptr-input");
const bulkTargetsHint = document.querySelector("#bulk-targets-hint");
const pingMethodControl = document.querySelector("#ping-method-control");
const pingMethodInput = document.querySelector("#ping-method-input");
const sslScanControl = document.querySelector("#sslscan-control");
const sslScanPort = document.querySelector("#sslscan-port");
const emailControl = document.querySelector("#email-control");
const dkimSelectorsInput = document.querySelector("#dkim-selectors");
const scanIncludesControl = document.querySelector("#scan-includes-control");
const scanEmailInput = document.querySelector("#scan-email-input");
const scanSslInput = document.querySelector("#scan-ssl-input");
const scanTlsGradeInput = document.querySelector("#scan-tls-grade-input");
const scanWebInput = document.querySelector("#scan-web-input");
const modeSubtabs = document.querySelector("#mode-subtabs");
const scanDnsHealthInput = document.querySelector("#scan-dns-health-input");
const headersControl = document.querySelector("#headers-control");
const headersInput = document.querySelector("#headers-input");
const dmarcControl = document.querySelector("#dmarc-control");
const dmarcFilesInput = document.querySelector("#dmarc-files");
const tlsrptControl = document.querySelector("#tlsrpt-control");
const tlsrptFilesInput = document.querySelector("#tlsrpt-files");
const bulkDomainsControl = document.querySelector("#bulk-domains-control");
const bulkDomainsInput = document.querySelector("#bulk-domains-input");
const recordBuilderPanel = document.querySelector("#record-builder");
const monitorsLink = document.querySelector("#monitors-link");
const watchResultLink = document.querySelector("#watch-result");
// Tabs that group several tools, shown as sub-tabs under the main tab bar.
const modeGroups = {
  email: [["email", "Domain check"], ["mail-server", "Mail server"], ["email-headers", "Header analyzer"], ["dmarc-reports", "DMARC reports"], ["tlsrpt-reports", "TLS reports"], ["record-builder", "Record builder"], ["spf-flatten", "SPF flattener"]],
  security: [["dns-health", "DNS health"], ["subdomains", "Subdomains"], ["reputation", "Reputation"], ["lookalike", "Lookalike domains"]],
};
const modeFeatures = { details: "whois", "spf-flatten": "record-builder" };
// Tools whose requests and rendering live in tools.js.
const toolModes = new Set(["web", "bulk-domains", "email-headers", "dmarc-reports", "tlsrpt-reports", "dns-health", "mail-server", "subdomains", "ipv6", "reputation", "lookalike", "spf-flatten", "ip-calc"]);

function featureForMode(toolMode) {
  return modeFeatures[toolMode] || toolMode;
}

function groupOfMode(toolMode) {
  return Object.keys(modeGroups).find((group) => modeGroups[group].some(([member]) => member === toolMode)) || null;
}

function groupAllowed(group) {
  return modeGroups[group].some(([member]) => featureAllowed(featureForMode(member)));
}

function firstGroupMode(group) {
  return (modeGroups[group].find(([member]) => featureAllowed(featureForMode(member))) || modeGroups[group][0])[0];
}
const tlsGradeControl = document.querySelector("#tls-grade-control");
const tlsGradeInput = document.querySelector("#tls-grade-input");
let tlsGradeRun = 0;
const pingMonitorControl = document.querySelector("#ping-monitor-control");
const pingMonitorStart = document.querySelector("#ping-monitor-start");
const pingMonitorStop = document.querySelector("#ping-monitor-stop");
const pingMonitorSound = document.querySelector("#ping-monitor-sound");
const pingMonitorHint = document.querySelector("#ping-monitor-hint");
const pingMonitorPanel = document.querySelector("#ping-monitor-panel");
const pingMonitorTarget = document.querySelector("#ping-monitor-target");
const pingMonitorState = document.querySelector("#ping-monitor-state");
const pingMonitorStatus = document.querySelector("#ping-monitor-status");
const pingMonitorSummary = document.querySelector("#ping-monitor-summary");
const pingMonitorChart = document.querySelector("#ping-monitor-chart");
const resultPanel = document.querySelector("#result");
const shareResults = document.querySelector("#share-results");
const shareResultsButton = document.querySelector("#share-results-button");
const shareResultsLink = document.querySelector("#share-results-link");
const shareResultsStatus = document.querySelector("#share-results-status");
let lastResult = null;
const historyLink = document.querySelector("#history-link");
let viewingShare = false;
const shareModeLabels = {
  forward: "DNS lookup", reverse: "Reverse lookup", details: "Whois", mac: "MAC lookup", dig: "Dig",
  propagation: "Propagation", email: "Email check", asn: "ASN", ping: "Ping", sslscan: "SSLscan", "ping-scan": "Ping scan", traceroute: "Traceroute",
  "multi-traceroute": "Multi traceroute", scan: "Magic scan", "custom-port": "Port scan", "bulk-port": "Bulk port scan",
  nmap: "Nmap", dnssec: "DNSSEC check", web: "Web check", "email-headers": "Header analysis",
  "dmarc-reports": "DMARC reports", "tlsrpt-reports": "TLS reports", "bulk-domains": "Bulk domain check", "dns-health": "DNS health",
  "mail-server": "Mail server check", subdomains: "Subdomain discovery", ipv6: "IPv6 readiness", reputation: "Reputation", lookalike: "Lookalike domains", "spf-flatten": "SPF flattener", "ip-calc": "IP calculator",
};

function historyEnabled() {
  const access = authState?.featureAccess?.history || "user";
  return Boolean(authState?.user) && (access !== "admin" || authState.user.role === "admin");
}

// The form state needed to run the same lookup again from the history page.
function currentHistoryParams(resultMode) {
  const params = {};
  if (["forward", "propagation"].includes(resultMode)) params.type = recordType.value === "custom" ? customType.value.trim() : recordType.value;
  if (resultMode === "dnssec") params.type = "DNSSEC";
  if (resultMode === "ping") params.method = pingMethodInput.value;
  if (resultMode === "sslscan") {
    params.port = sslScanPort.value.trim();
    params.tlsGrade = tlsGradeInput.checked;
  }
  if (resultMode === "email") params.selectors = dkimSelectorsInput.value.trim();
  if (resultMode === "custom-port") params.ports = customPortsInput.value.trim();
  if (resultMode === "bulk-port") {
    params.targets = bulkTargetsInput.value;
    params.bulkPort = bulkPortInput.value.trim();
  }
  if (resultMode === "ping-scan") params.targets = bulkTargetsInput.value;
  if (resultMode === "multi-traceroute") {
    params.targets = multiTraceInput.value;
    params.ptr = tracePtrInput.checked;
  }
  if (resultMode === "traceroute") params.ptr = tracePtrInput.checked;
  if (resultMode === "nmap") params.scanType = nmapScanType.value;
  if (resultMode === "scan") {
    params.scanPorts = portScanInput.checked;
    params.scanEmail = scanEmailInput.checked;
    params.scanSsl = scanSslInput.checked;
    params.scanTlsGrade = scanTlsGradeInput.checked;
    params.scanWeb = scanWebInput.checked;
    params.scanDnsHealth = scanDnsHealthInput.checked;
  }
  if (resultMode === "bulk-domains") params.domains = bulkDomainsInput.value;
  return params;
}

async function saveHistory() {
  const entry = lastResult;
  if (!entry || viewingShare || !historyEnabled()) return;
  try {
    if (entry.historyId) {
      await fetch(`/api/history/${entry.historyId}`, {
        method: "PUT",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: entry.data }),
      });
      return;
    }
    const response = await fetch("/api/history", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: entry.mode, title: entry.title, query: entry.query, params: entry.params, data: entry.data }),
    });
    if (response.ok) entry.historyId = (await response.json()).id;
  } catch {
    // History is a convenience; a failed save must not disturb the result.
  }
}

function rememberResult(resultMode, data, subject) {
  lastResult = {
    mode: resultMode,
    data: { result: data, extras: {} },
    title: `${shareModeLabels[resultMode] || resultMode}: ${String(subject || "").slice(0, 150)}`,
    query: ["ping-scan", "bulk-port", "multi-traceroute", "bulk-domains", "email-headers", "dmarc-reports", "tlsrpt-reports"].includes(resultMode) ? "" : input.value.trim(),
    params: currentHistoryParams(resultMode),
  };
  shareResultsLink.hidden = true;
  shareResultsStatus.textContent = "";
  updateShareResults();
  updateWatchLink(resultMode, data);
  void saveHistory();
}

// Offers to turn the current result into a monitor on the Monitors page.
function updateWatchLink(resultMode, data) {
  const kinds = {
    forward: () => ["dns", data?.name],
    scan: () => ["dns", data?.domain],
    sslscan: () => ["certificate", data?.target ? `${data.target}:${data.port || 443}` : null],
    email: () => ["email", data?.domain],
    web: () => ["website", data?.finalUrl || data?.startUrl],
    reputation: () => ["blocklist", data?.target],
    lookalike: () => ["ct", data?.domain],
    "dns-health": () => ["dns", data?.zone],
  };
  const [kind, target] = kinds[resultMode]?.() || [];
  const allowed = Boolean(kind && target && authState?.user && featureAllowed("monitors"));
  watchResultLink.hidden = !allowed;
  if (allowed) watchResultLink.href = `/monitors.html?${new URLSearchParams({ kind, target })}`;
}

function updateShareResults() {
  shareResults.hidden = resultPanel.hidden || !lastResult && !viewingShare;
  shareResultsButton.hidden = !(authState?.user && lastResult && !viewingShare);
  if (!lastResult || viewingShare) watchResultLink.hidden = true;
}
const nmapLiveStatus = document.querySelector("#nmap-live-status");
const errorMessage = document.querySelector("#error-message");
const submitButton = document.querySelector("#submit-button");
const formHint = document.querySelector("#form-hint");
const tabs = [...document.querySelectorAll(".mode-tab[data-mode]")];
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
const mailResults = document.querySelector("#mail-results");
const mailResultsButton = document.querySelector("#mail-results-button");
const mailResultsStatus = document.querySelector("#mail-results-status");
const adminTabs = document.querySelector("#admin-tabs");
const loginLink = document.querySelector("#login-link");
const logoutButton = document.querySelector("#logout-button");
const clientInfo = document.querySelector("#client-info");
const clientInfoLabel = document.querySelector("#client-info-label");
const clientIp = document.querySelector("#client-ip");
const clientPtr = document.querySelector("#client-ptr");
const clientWhois = document.querySelector("#client-whois");
let mode = "auto";
let authState = null;
let pingMonitorActive = false;
let pingMonitorTimer = null;
let pingMonitorStartedAt = 0;
let pingMonitorTargetValue = "";
let pingMonitorSamples = [];
let pingMonitorPreviousState = null;
let pingMonitorAbortController = null;
let pingMonitorAudioContext = null;
let nmapStatusPolling = false;
let nmapStatusTimer = null;

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

function submitLabel(currentMode) {
  return {
    auto: "Auto lookup",
    scan: "Magic scan",
    "custom-port": "Port scan",
    "bulk-port": "Bulk port scan",
    nmap: "Run Nmap scan",
    mac: "Lookup MAC",
    dig: "Run dig",
    propagation: "Check propagation",
    email: "Check email",
    "email-headers": "Analyze headers",
    "dmarc-reports": "Read reports",
    "tlsrpt-reports": "Read reports",
    web: "Check website",
    "bulk-domains": "Check domains",
    "dns-health": "Check DNS health",
    "mail-server": "Check mail servers",
    subdomains: "Find subdomains",
    ipv6: "Check IPv6",
    reputation: "Check reputation",
    lookalike: "Find lookalikes",
    "spf-flatten": "Flatten SPF",
    "ip-calc": "Calculate",
    asn: "Look up ASN",
    ping: "Ping host",
    sslscan: "Check SSL/TLS",
    "ping-scan": "Run ping scan",
    traceroute: "Trace route",
    "multi-traceroute": "Trace routes",
  }[currentMode] || "Lookup";
}

function setMode(nextMode) {
  if (mode !== nextMode) stopPingMonitor("Monitoring stopped because the lookup mode changed.");
  mode = nextMode;
  const automatic = mode === "auto";
  const reverse = mode === "reverse";
  const details = mode === "details";
  const mac = mode === "mac";
  const dig = mode === "dig";
  const propagation = mode === "propagation";
  const email = mode === "email";
  const emailHeaders = mode === "email-headers";
  const dmarcReports = mode === "dmarc-reports";
  const tlsrptReports = mode === "tlsrpt-reports";
  const recordBuilder = mode === "record-builder";
  const webCheck = mode === "web";
  const bulkDomains = mode === "bulk-domains";
  const group = groupOfMode(mode);
  const toolInputMode = emailHeaders || dmarcReports || tlsrptReports || recordBuilder || bulkDomains;
  const plainInputMode = ["web", "dns-health", "mail-server", "subdomains", "ipv6", "reputation", "lookalike", "spf-flatten", "ip-calc"].includes(mode);
  const asnMode = mode === "asn";
  const ping = mode === "ping";
  const sslscan = mode === "sslscan";
  const scan = mode === "scan";
  const customPortScan = mode === "custom-port";
  const bulkPortScan = mode === "bulk-port";
  const nmapScan = mode === "nmap";
  const pingScan = mode === "ping-scan";
  const traceroute = mode === "traceroute";
  const multiTraceroute = mode === "multi-traceroute";
  const portScan = customPortScan || bulkPortScan || nmapScan;
  const listMode = bulkPortScan || pingScan || multiTraceroute || toolInputMode;
  const isAdmin = authState?.user?.role === "admin";
  const supportsNameserver = isAdmin && ["forward", "reverse", "scan"].includes(mode);
  tabs.forEach((tab) => {
    const selected = tab.dataset.mode === mode || Boolean(group && tab.dataset.group === group);
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  nameLabel.hidden = listMode;
  primaryInputWrap.hidden = listMode;
  input.required = !listMode;
  nameLabel.textContent = automatic
    ? "Search"
    : reverse ? "IP address" : mac ? "MAC address" : dig ? "dig command" : propagation ? "DNS name" : email ? "Domain or email address" : asnMode ? "IP address, domain or AS number"
    : ["dns-health", "lookalike", "spf-flatten", "subdomains", "ipv6"].includes(mode) ? "Domain name"
    : mode === "mail-server" ? "Domain or email address"
    : mode === "reputation" ? "Domain, URL or IP address"
    : mode === "ip-calc" ? "IP address or prefix"
    : webCheck ? "Domain or URL" : "Domain name or IP address";
  input.placeholder = dig
    ? "e.g. @1.1.1.1 example.com MX +dnssec"
    : email
    ? "e.g. example.com or someone@example.com"
    : asnMode
    ? "e.g. 1.1.1.1, example.com or AS13335"
    : reverse
    ? "e.g. 8.8.8.8 or 2001:4860:4860::8888"
    : mac
      ? "e.g. 00:1A:2B:3C:4D:5E"
    : webCheck
      ? "e.g. example.com or https://example.com/page"
    : mode === "reputation"
      ? "e.g. example.com, a URL or 203.0.113.7"
    : mode === "ip-calc"
      ? "e.g. 192.168.10.0/22, 10.1.2.3 255.255.255.0 or 2001:db8::/48"
    : ["dns-health", "lookalike", "spf-flatten", "mail-server", "subdomains", "ipv6"].includes(mode)
      ? "e.g. example.com"
    : details || ping || sslscan || traceroute || nmapScan
      ? "e.g. example.com or 8.8.8.8"
    : automatic
      ? "Domain, IP address, or MAC address"
    : customPortScan
      ? "e.g. example.com or 8.8.8.8"
      : "e.g. example.com";
  input.autocomplete = reverse || mac || dig || portScan ? "off" : "url";
  input.classList.toggle("dig-input", dig);
  typeControl.hidden = automatic || reverse || details || mac || dig || email || asnMode || ping || sslscan || traceroute || listMode || scan || portScan || plainInputMode;
  customType.hidden = automatic || reverse || details || mac || dig || email || asnMode || ping || sslscan || traceroute || listMode || scan || portScan || plainInputMode || recordType.value !== "custom";
  modeSubtabs.hidden = !group;
  modeSubtabs.setAttribute("aria-label", group === "security" ? "Security tools" : "Email tools");
  modeSubtabs.innerHTML = group
    ? modeGroups[group].filter(([member]) => featureAllowed(featureForMode(member))).map(([member, label]) => `
      <button class="email-subtab${member === mode ? " active" : ""}" type="button" role="tab" aria-selected="${member === mode}" data-mode="${member}">${escapeHtml(label)}</button>`).join("")
    : "";
  headersControl.hidden = !emailHeaders;
  headersInput.required = emailHeaders;
  dmarcControl.hidden = !dmarcReports;
  dmarcFilesInput.required = dmarcReports;
  tlsrptControl.hidden = !tlsrptReports;
  tlsrptFilesInput.required = tlsrptReports;
  bulkDomainsControl.hidden = !bulkDomains;
  bulkDomainsInput.required = bulkDomains;
  submitButton.hidden = recordBuilder;
  recordBuilderPanel.hidden = !recordBuilder;
  if (recordBuilder && typeof initRecordBuilder === "function") initRecordBuilder(recordBuilderPanel);
  nameserverControl.hidden = !supportsNameserver;
  if (!isAdmin) nameserverInput.value = "";
  pingMethodControl.hidden = !ping;
  sslScanControl.hidden = !sslscan;
  tlsGradeControl.hidden = !sslscan || !authState?.user;
  tlsGradeRun += 1;
  sslScanPort.disabled = !sslscan;
  sslScanPort.required = sslscan;
  pingMonitorControl.hidden = !ping;
  pingMonitorStart.disabled = pingMonitorActive || !authState?.user;
  pingMonitorStop.disabled = !pingMonitorActive;
  pingMonitorHint.textContent = authState?.user
    ? "One sample every 3 seconds; monitoring stops after 5 minutes or 100 samples."
    : "Sign in to use live monitoring. One sample every 3 seconds; maximum 5 minutes.";
  portScanControl.hidden = !scan || !authState?.user;
  updateScanIncludes(scan);
  customPortsControl.hidden = !customPortScan;
  bulkTargetsControl.hidden = !(bulkPortScan || pingScan);
  bulkPortControl.hidden = !bulkPortScan;
  nmapControl.hidden = !nmapScan;
  multiTraceControl.hidden = !multiTraceroute;
  emailControl.hidden = !email;
  tracePtrControl.hidden = !(traceroute || multiTraceroute);
  bulkTargetsHint.textContent = pingScan
    ? "Separate targets with commas or new lines. IPv4 and IPv6 are supported; each CIDR must contain at most 256 addresses."
    : "Separate targets with commas or new lines. IPv4 and IPv6 are supported; CIDR size follows the administrator's prefix limit (up to /16 for IPv4 when the server runs zmap).";
  customPortsInput.required = customPortScan;
  bulkTargetsInput.required = bulkPortScan || pingScan;
  multiTraceInput.required = multiTraceroute;
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
      : sslscan
        ? "Test one TLS handshake and inspect the remote server's negotiated protocol, cipher, certificate chain, and trust status."
      : mac
        ? "Find the registered hardware vendor and MAC address type."
      : asnMode
        ? "See which network (AS) announces an IP address, and every IPv4 and IPv6 range that network announces. Routing data comes from RIPE Stat."
      : emailHeaders
        ? "Paste the headers of a received message to see how it was delivered and why it passed or failed SPF, DKIM and DMARC."
      : tlsrptReports
        ? "Read SMTP TLS reports (TLS-RPT) to see whether other mail servers could deliver to yours over an encrypted, verified connection, and why sessions failed, before you switch MTA-STS to enforce."
      : dmarcReports
        ? "Read DMARC aggregate (rua) reports to see who sends mail as your domain and whether it passes, before you tighten your DMARC policy."
      : recordBuilder
        ? "Build correct SPF, DMARC, MTA-STS, TLS-RPT and BIMI records. Load a domain's current records to start from them."
      : mode === "ipv6"
        ? "Check whether a domain works for visitors and mail servers that only have IPv6: AAAA records and IPv6 reachability of the website, IPv6 mail servers with reverse DNS, and name servers with IPv6 addresses."
      : mode === "subdomains"
        ? "Find a domain's subdomains in Certificate Transparency logs and by trying common names, see where each one points, and check for subdomains that can be taken over or reveal internal addresses."
      : mode === "mail-server"
        ? "Connect to each mail server (MX) on port 25: STARTTLS and its certificate, whether it is an open relay (no message is sent), forward-confirmed reverse DNS, the name it introduces itself with, and password login offered before encryption."
      : mode === "dns-health"
        ? "Query each of the domain's name servers directly: delegation from the parent zone, glue, matching SOA serials, TCP support, open zone transfers (AXFR) and open recursion."
      : mode === "reputation"
        ? "Check whether security services consider a domain or IP address malicious: filtering DNS resolvers, spam blocklists, and URLhaus, VirusTotal or Google Safe Browsing when configured."
      : mode === "lookalike"
        ? "Generate typo, homoglyph, hyphen, TLD and added-word variants of a domain and show which are registered, with web or mail servers that could be used for phishing."
      : mode === "spf-flatten"
        ? "Replace include, a and mx mechanisms with the IP ranges they resolve to, to get under SPF's limit of 10 DNS lookups. Flattened records must be refreshed when your providers change their addresses."
      : mode === "ip-calc"
        ? "Work out the network, broadcast, host range and size of an IPv4 or IPv6 prefix, convert a netmask or wildcard, and split a network into smaller subnets. Calculated in your browser."
      : webCheck
        ? "Follow a site's redirects and check its HTTPS setup, security headers, cookies, compression and HTTP/2 and HTTP/3 support."
      : bulkDomains
        ? "Check MX, SPF, DMARC, the HTTPS certificate and blocklists for a list of domains at once."
      : email
        ? "Check a domain's mail setup: MX servers, SMTP STARTTLS on port 25, SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI, and which email providers it uses."
      : propagation
        ? "Compare the record across Cloudflare, Google, Quad9, DNS4EU and the zone's authoritative nameservers to see whether a change has propagated."
      : dig
        ? "Run a dig command: [@server] name [type] [class] with +options such as +short, +dnssec, +trace, +tcp, +nsid or +subnet=, and the flags -t, -c, -x, -p, -4, -6. Without @server the server's own resolver is used."
      : scan
        ? "Scan DNS records, cloud-provider hostnames, SPF, and DKIM. Optionally choose the nameserver. You can paste a full URL; only its domain is scanned."
      : customPortScan
        ? "Scan a custom list or range of TCP ports on one domain or IP address."
      : bulkPortScan
        ? "Check one TCP port across an explicit list or CIDR block of IP addresses."
        : nmapScan
          ? "Scan one target from an administrator-approved network or a host IP captured at login using a bounded Nmap profile."
      : pingScan
        ? "Send a single ICMP echo request to every address in a list or CIDR block to find which hosts are up."
      : traceroute
        ? "Show the network path (each router hop and its response time) to a host."
      : multiTraceroute
        ? "Trace the path to several hosts at once and compare the routes."
        : "Choose a record type or enter a custom DNS type. ANY returns records the DNS server makes available.";
  delete formHint.dataset.defaultText;
  submitButton.innerHTML = `<span>${submitLabel(mode)}</span><span aria-hidden="true">→</span>`;
  errorMessage.hidden = true;
  resultPanel.hidden = true;
  if (automatic) updateAutoDetectHint();
  input.focus();
}

// Logged-in users switch between the simple and the full interface; the choice is kept
// in a cookie for this browser and "/" serves the chosen one.
function setupInterfaceSwitch(button, target) {
  button.hidden = false;
  button.addEventListener("click", () => {
    button.setAttribute("aria-checked", String(target === "full"));
    const secure = window.location.protocol === "https:" ? "; secure" : "";
    document.cookie = `bng_ui=${target}; path=/; max-age=31536000; samesite=lax${secure}`;
    window.setTimeout(() => window.location.assign("/"), 280);
  });
}

async function initializeAccount() {
  const sharedId = new URLSearchParams(window.location.search).get("share");
  const historyId = new URLSearchParams(window.location.search).get("history");
  const rerunId = new URLSearchParams(window.location.search).get("rerun");
  try {
    const response = await fetch("/api/auth/status", { credentials: "same-origin" });
    authState = await response.json();
    if (authState.setupRequired) {
      window.location.replace("/setup.html");
      return;
    }
    accountNav.hidden = false;
    loginLink.hidden = Boolean(authState.user);
    historyLink.hidden = !historyEnabled();
    monitorsLink.hidden = !(authState.user && featureAllowed("monitors"));
    logoutButton.hidden = !authState.user;
    if (authState.user) setupInterfaceSwitch(document.querySelector("#ui-switch"), "simple");
    adminTabs.hidden = authState.user?.role !== "admin";
    accountName.textContent = authState.user
      ? `${authState.user.username} (${authState.user.role})`
      : "Guest";
    const availableTabs = [];
    tabs.filter((tab) => tab !== autoTab).forEach((tab) => {
      const feature = tab.dataset.mode === "details" ? "whois" : tab.dataset.mode;
      const access = authState.featureAccess[feature] || "user";
      const portScanRequiresUser = ["custom-port", "bulk-port", "ping-scan", "multi-traceroute", "nmap", "bulk-domains"].includes(tab.dataset.mode);
      const canUse = tab.dataset.group
        ? groupAllowed(tab.dataset.group)
        : Boolean(authState.user) &&
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
    modeTabs.hidden = !initialTab && adminTabs.hidden;
    lookupForm.hidden = !initialTab;
    loginRequiredNotice.hidden = Boolean(initialTab);
    guestUsageNotice.hidden = !initialTab || Boolean(authState.user);
    if (authState.publicLookupLimit) {
      guestUsageNotice.textContent = `Public lookups are limited to ${authState.publicLookupLimit.toLocaleString()} per IP address each day (reset at 00:00 UTC).`;
    }
    if (!initialTab && authState.user) {
      loginRequiredMessage.textContent = "No lookup tools are available to your account. Contact an administrator.";
      toolsLoginLink.hidden = true;
    }
    if (initialTab) {
      const requested = new URLSearchParams(window.location.search).get("mode");
      const requestedGroup = modeGroups[requested] ? requested : groupOfMode(requested);
      const groupTab = requestedGroup && availableTabs.find((tab) => tab.dataset.group === requestedGroup);
      const directTab = availableTabs.find((tab) => tab.dataset.mode === requested && !tab.dataset.group);
      setMode(groupTab
        ? (featureAllowed(featureForMode(requested)) && groupOfMode(requested) ? requested : firstGroupMode(requestedGroup))
        : directTab ? requested : "auto");
      const query = new URLSearchParams(window.location.search).get("q");
      if (sharedId || historyId || rerunId) {
        // A shared link shows the stored result instead of running a query.
      } else if (query) {
        input.value = query.slice(0, 2048);
        if (mode === "auto") updateAutoDetectHint();
        form.requestSubmit();
      }
    }
    if (sharedId) await loadSharedResult(sharedId);
    else if (historyId && authState.user) await loadHistoryEntry(historyId, false);
    else if (rerunId && authState.user) await loadHistoryEntry(rerunId, true);
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

function renderDnssecSection(check) {
  if (!check) return "";
  const labels = {
    secure: ["found", "Secure"],
    unsigned: ["missing", "Not enabled"],
    insecure: ["warning", "No chain of trust"],
    bogus: ["danger", "Validation fails"],
    indeterminate: ["warning", "Not validated"],
    error: ["missing", "Unavailable"],
  };
  const [statusClass, statusLabel] = labels[check.status] || ["missing", check.status];
  const table = (head, rows) => rows.length ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table">
    <thead><tr>${head.map((cell) => `<th>${escapeHtml(cell)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>` : "";
  const dsRows = (check.ds || []).map((entry) => `
    <tr>
      <td>${copyableResult(entry.keyTag)}</td>
      <td>${escapeHtml(`${entry.algorithm} · ${entry.algorithmName}`)}</td>
      <td>${escapeHtml(`${entry.digestType} · ${entry.digestTypeName}`)}</td>
      <td>${entry.matchesKey ? '<span class="dnssec-ok">Matches DNSKEY</span>' : '<span class="dnssec-bad">No matching key</span>'}</td>
      <td class="dnssec-digest">${copyableResult(entry.digest)}</td>
    </tr>`);
  const keyRows = (check.dnskeys || []).map((key) => `
    <tr>
      <td>${copyableResult(key.keyTag)}</td>
      <td>${escapeHtml(`${key.role} (flags ${key.flags})`)}</td>
      <td>${escapeHtml(`${key.algorithm} · ${key.algorithmName}`)}</td>
      <td>${escapeHtml(`${key.keyBytes} bytes`)}</td>
    </tr>`);
  const signatureRows = (check.signatures || []).map((signature) => `
    <tr>
      <td>${escapeHtml(signature.typeCovered)}</td>
      <td>${copyableResult(signature.keyTag)}</td>
      <td>${escapeHtml(signature.signer)}</td>
      <td>${escapeHtml(signature.inception ? signature.inception.replace("T", " ").replace("Z", " UTC") : "")}</td>
      <td>${escapeHtml(signature.expiration ? signature.expiration.replace("T", " ").replace("Z", " UTC") : "")}</td>
    </tr>`);
  const issues = (check.issues || []).map((issue) => `<li class="dnssec-issue ${escapeHtml(issue.severity)}">${escapeHtml(issue.message)}</li>`).join("");
  return `
    <section class="email-auth dnssec-section">
      <h3>DNSSEC <span class="email-auth-status ${statusClass}">${escapeHtml(statusLabel)}</span></h3>
      <p class="dnssec-summary">${escapeHtml(check.summary || "")}</p>
      ${issues ? `<ul class="dnssec-issues">${issues}</ul>` : ""}
      ${dsRows.length ? `<h4>DS records at the parent zone</h4>${table(["Key tag", "Algorithm", "Digest", "Match", "Digest value"], dsRows)}` : ""}
      ${keyRows.length ? `<h4>DNSKEY records</h4>${table(["Key tag", "Role", "Algorithm", "Key size"], keyRows)}` : ""}
      ${signatureRows.length ? `<h4>Signatures (RRSIG)</h4>${table(["Covers", "Key tag", "Signer", "Valid from", "Expires"], signatureRows)}` : ""}
      <p class="scan-disclaimer">Validated by ${escapeHtml(check.resolver || "the DNS-over-HTTPS resolver")} (AD flag ${check.authenticated ? "set" : "not set"}). A bogus result means validating resolvers refuse to answer for this domain.</p>
    </section>`;
}

function renderFacts(pairs) {
  const items = pairs.filter(([, value]) => value !== null && value !== undefined && value !== "");
  if (!items.length) return "";
  return `<dl class="mail-facts">${items.map(([label, value]) => `<div><dt>${escapeHtml(label)}</dt><dd>${copyableResult(value)}</dd></div>`).join("")}</dl>`;
}

const mailSeverityOrder = { high: 0, medium: 1, low: 2 };

// One tile per area with a pass/warn/fail state, so the result can be read at a glance.
function mailScorecard(data) {
  const smtp = (data.smtp || []).filter((result) => !result.error);
  const mxCount = data.mx?.records?.length || 0;
  const unresolved = (data.mx?.records || []).filter((record) => !record.addresses.length).length;
  const spf = data.spf || {};
  const dmarc = data.dmarc || {};
  const dkim = data.dkim?.records || [];
  const sts = data.mtaSts || {};
  const rpt = data.tlsRpt || {};
  const bimi = data.bimi || {};
  const hasHigh = (issues) => (issues || []).some((issue) => issue.severity === "high");
  return [
    ["mx", "MX", data.mx?.nullMx ? ["none", "Null MX"] : !mxCount ? ["bad", "None"] : unresolved ? ["warn", `${unresolved} of ${mxCount} unresolved`] : ["ok", `${mxCount} server${mxCount === 1 ? "" : "s"}`]],
    ["smtp", "STARTTLS", !smtp.length ? ["none", "Not tested"]
      : smtp.some((result) => !result.starttls) ? ["bad", "Not offered"]
      : smtp.some((result) => result.issues?.length) ? ["warn", "Certificate issue"] : ["ok", "Trusted TLS"]],
    ["spf", "SPF", spf.error ? ["none", "Unavailable"] : !spf.found ? ["bad", "Missing"]
      : spf.lookups === null || spf.lookups > 10 ? ["bad", spf.lookups === null ? "Invalid" : `${spf.lookups}/10 lookups`]
      : hasHigh(spf.issues) || spf.lookups >= 8 ? ["warn", `${spf.lookups}/10 lookups`] : ["ok", spf.all ? `${spf.all} · ${spf.lookups}/10` : `${spf.lookups}/10 lookups`]],
    ["dmarc", "DMARC", dmarc.error ? ["none", "Unavailable"] : !dmarc.found ? ["bad", "Missing"]
      : dmarc.policy === "reject" || dmarc.policy === "quarantine" ? [hasHigh(dmarc.issues) ? "warn" : "ok", `p=${dmarc.policy}`] : ["warn", `p=${dmarc.policy || "?"}`]],
    ["dkim", "DKIM", !dkim.length ? ["warn", "No keys found"] : dkim.some((record) => hasHigh(record.issues)) ? ["warn", `${dkim.length} key${dkim.length === 1 ? "" : "s"} · issues`] : ["ok", `${dkim.length} key${dkim.length === 1 ? "" : "s"}`]],
    ["mta-sts", "MTA-STS", sts.error ? ["none", "Unavailable"] : !sts.found ? ["none", "Not configured"] : sts.policy?.mode === "enforce" && !hasHigh(sts.issues) ? ["ok", "enforce"] : ["warn", sts.policy?.mode || "Policy problem"]],
    ["tls-rpt", "TLS-RPT", rpt.error ? ["none", "Unavailable"] : !rpt.found ? ["none", "Not configured"] : rpt.issues?.length ? ["warn", "Found"] : ["ok", "Found"]],
    ["bimi", "BIMI", bimi.error ? ["none", "Unavailable"] : !bimi.found ? ["none", "Not configured"] : hasHigh(bimi.issues) ? ["bad", "Problems"] : bimi.certificateCheck?.kind ? ["ok", bimi.certificateCheck.kind] : ["warn", "No certificate"]],
  ];
}

function renderMailScorecard(data) {
  const icons = { ok: "✓", warn: "!", bad: "✕", none: "–" };
  return `<div class="mail-scorecard">${mailScorecard(data).map(([id, label, [state, value]]) => `
    <button type="button" class="mail-score ${state}" data-scroll-to="${id}">
      <span class="mail-score-icon" aria-hidden="true">${icons[state]}</span>
      <span class="mail-score-text"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></span>
    </button>`).join("")}</div>`;
}

function renderMailFixList(groups) {
  const issues = groups.flatMap(([area, list]) => (list || []).map((issue) => ({ area, ...issue })))
    .sort((left, right) => (mailSeverityOrder[left.severity] ?? 3) - (mailSeverityOrder[right.severity] ?? 3));
  if (!issues.length) return '<p class="mail-all-good">✓ No problems found in the checks below.</p>';
  const shown = issues.slice(0, 12);
  return `
    <section class="email-auth mail-fix-list">
      <h3>What to fix <span class="email-auth-status ${issues.some((issue) => issue.severity === "high") ? "danger" : "warning"}">${escapeHtml(`${issues.length} item${issues.length === 1 ? "" : "s"}`)}</span></h3>
      <ul>${shown.map((issue) => `<li class="${escapeHtml(issue.severity)}">${issue.area ? `<span class="mail-fix-area">${escapeHtml(issue.area)}</span>` : ""}${escapeHtml(issue.message)}</li>`).join("")}</ul>
      ${issues.length > shown.length ? `<p class="scan-disclaimer">${escapeHtml(`${issues.length - shown.length} more below, in their sections.`)}</p>` : ""}
    </section>`;
}

resultPanel.addEventListener("click", (event) => {
  const tile = event.target.closest("[data-scroll-to]");
  if (!tile) return;
  const target = tile.closest(".email-result")?.querySelector(`[data-mail-section="${tile.dataset.scrollTo}"]`);
  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "start" });
  target.classList.remove("mail-flash");
  void target.offsetWidth;
  target.classList.add("mail-flash");
});

function renderMailIssues(issues) {
  if (!issues?.length) return "";
  return `<ul class="dnssec-issues">${issues.map((issue) => `<li class="dnssec-issue ${escapeHtml(issue.severity)}">${escapeHtml(issue.message)}</li>`).join("")}</ul>`;
}

function renderMailSecurity(security) {
  if (!security || (!security.dmarc && !security.spf)) return "";
  const card = (title, found, label, body) => `
    <div data-mail-section="${escapeHtml({ DMARC: "dmarc", "SPF evaluation": "spf", "MTA-STS": "mta-sts", "TLS-RPT": "tls-rpt" }[title] || "")}">
      <h4>${escapeHtml(title)} <span class="email-auth-status ${found}">${escapeHtml(label)}</span></h4>
      ${body}
    </div>`;
  const recordLine = (record) => record ? `<div class="email-auth-record"><span>${escapeHtml(record)}</span></div>` : "";
  const dmarc = security.dmarc || {};
  const dmarcLabel = dmarc.error ? "Unavailable" : !dmarc.found ? "Missing" : dmarc.policy ? `p=${dmarc.policy}` : "Invalid";
  const dmarcClass = !dmarc.found || dmarc.error ? "missing" : dmarc.policy === "reject" || dmarc.policy === "quarantine" ? "found" : "warning";
  const spf = security.spf || {};
  const spfTree = (spf.tree || []).length > 1 ? `<ul class="spf-tree">${spf.tree.map((node) => `
    <li class="spf-depth-${Math.min(node.depth, 6)}">${escapeHtml(`${node.via ? `${node.via}: ` : ""}${node.name}`)}${node.error ? ` <span class="dnssec-bad">${escapeHtml(node.error)}</span>` : ` <span class="trace-silent">${escapeHtml(`${node.lookups} lookup(s)`)}</span>`}</li>`).join("")}</ul>` : "";
  const spfClass = !spf.found || spf.error ? "missing" : spf.lookups > 10 || spf.lookups === null ? "danger" : spf.lookups >= 8 ? "warning" : "found";
  const spfLabel = spf.error ? "Unavailable" : !spf.found ? "Missing" : spf.lookups === null ? "Invalid" : `${spf.lookups}/10 lookups`;
  const sts = security.mtaSts || {};
  const stsMode = sts.policy?.mode;
  const stsClass = !sts.found || sts.error ? "missing" : stsMode === "enforce" && !sts.issues.some((issue) => issue.severity === "high") ? "found" : "warning";
  const stsBody = sts.found ? `${recordLine(sts.record)}${sts.policy ? `<p class="dnssec-summary">${escapeHtml(`Mode ${stsMode || "?"} · max_age ${sts.policy.maxAge || "?"} · mx: ${sts.policy.mx.join(", ") || "none"}`)}</p>` : ""}` : '<p class="empty-result">No MTA-STS policy. Senders may deliver over unencrypted or unverified connections.</p>';
  const rpt = security.tlsRpt || {};
  return `
    <div class="email-auth-grid mail-security-grid">
      ${card("DMARC", dmarcClass, dmarcLabel, `${recordLine(dmarc.record)}${dmarc.error ? `<p class="detail-notice">${escapeHtml(dmarc.error)}</p>` : ""}${renderMailIssues(dmarc.issues)}`)}
      ${card("SPF evaluation", spfClass, spfLabel, `${spf.all ? `<p class="dnssec-summary">${escapeHtml(`Ends with ${spf.all}`)}</p>` : ""}${spfTree}${spf.truncated ? '<p class="detail-notice">Stopped after 30 queries; the count may be higher.</p>' : ""}${renderMailIssues(spf.issues)}`)}
      ${card("MTA-STS", stsClass, sts.error ? "Unavailable" : sts.found ? stsMode || "Policy problem" : "Not configured", `${stsBody}${renderMailIssues(sts.issues)}`)}
      ${card("TLS-RPT", rpt.found && !rpt.issues?.length ? "found" : rpt.found ? "warning" : "missing", rpt.error ? "Unavailable" : rpt.found ? "Found" : "Not configured", rpt.found ? `${recordLine(rpt.record)}${renderMailIssues(rpt.issues)}` : '<p class="empty-result">No TLS-RPT record, so you get no reports about failed encrypted deliveries.</p>')}
    </div>`;
}

function renderBlocklistTable(lists) {
  const labels = { listed: ["danger", "Listed"], clean: ["found", "Not listed"], refused: ["warning", "Refused"], error: ["missing", "Unavailable"] };
  const order = { listed: 0, refused: 1, error: 2, clean: 3 };
  const rows = [...lists].sort((left, right) => order[left.status] - order[right.status]).map((list) => {
    const [statusClass, label] = labels[list.status] || ["missing", list.status];
    const detail = list.status === "listed"
      ? [list.codes?.join(", "), list.reason].filter(Boolean).join(" · ")
      : list.detail || "";
    return `
      <tr>
        <td>${/^https:\/\//i.test(String(list.info || "")) ? `<a href="${escapeHtml(list.info)}" target="_blank" rel="noopener noreferrer">${escapeHtml(list.name)}</a>` : escapeHtml(list.name)}<br><span class="trace-silent">${escapeHtml(list.zone)}</span></td>
        <td><span class="email-auth-status ${statusClass}">${escapeHtml(label)}</span></td>
        <td>${escapeHtml(detail)}</td>
      </tr>`;
  }).join("");
  return `<div class="dns-results-table-wrap"><table class="dns-results-table net-table blocklist-table">
    <thead><tr><th>Blocklist</th><th>Status</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderBlocklistSection(data) {
  if (!data) return "";
  const summary = (entry) => entry.listed
    ? `<span class="email-auth-status danger">${escapeHtml(`Listed on ${entry.listed} of ${entry.checked}`)}</span>`
    : `<span class="email-auth-status found">${escapeHtml(`Not listed (${entry.clean} of ${entry.checked} answered)`)}</span>`;
  const domainSection = data.domain ? `
    <h4>Domain ${copyableResult(data.domain.domain)} ${summary(data.domain)}</h4>
    ${renderBlocklistTable(data.domain.lists)}` : "";
  const ipSections = (data.ips || []).map((entry) => `
    <h4>IP ${copyableResult(entry.address)} ${summary(entry)}</h4>
    ${renderBlocklistTable(entry.lists)}`).join("");
  const anyListed = (data.domain?.listed || 0) + (data.ips || []).reduce((total, entry) => total + entry.listed, 0);
  const empty = !domainSection && !ipSections;
  return `
    <section class="email-auth blocklist-section">
      <h3>Blocklists <span class="email-auth-status ${anyListed ? "danger" : empty ? "missing" : "found"}">${anyListed ? escapeHtml(`${anyListed} listing(s)`) : empty ? "Not checked" : "Clean"}</span></h3>
      ${empty ? `<p class="empty-result">${data.ipv6 ? "Most blocklists only cover IPv4; IPv6 addresses are not checked." : "No public IPv4 address was available to check."}</p>` : ""}
      ${domainSection}
      ${ipSections}
      ${data.skipped?.length ? `<p class="detail-notice">${escapeHtml(`Not checked: ${data.skipped.join(", ")} (only up to four public IPv4 addresses are checked).`)}</p>` : ""}
      <p class="scan-disclaimer">Queried through ${escapeHtml(data.resolver || "the server's resolver")}. "Refused" means the blocklist operator rejected the query, usually because it came through a large public resolver, not that the address is clean.</p>
    </section>`;
}

async function appendBlocklistCheck(name) {
  const access = authState?.featureAccess?.blocklist || "user";
  const permitted = Boolean(authState?.user) && (access !== "admin" || authState.user.role === "admin");
  if (!permitted) return;
  const section = document.createElement("div");
  section.className = "blocklist-append";
  section.innerHTML = '<p class="detail-notice">Checking blocklists…</p>';
  resultPanel.append(section);
  try {
    const response = await fetch(`/api/blocklist?${new URLSearchParams({ name })}`, { credentials: "same-origin" });
    const data = await readApiResponse(response);
    if (!response.ok) throw new Error(data.error || "Blocklist check failed.");
    if (section.isConnected) section.innerHTML = renderBlocklistSection(data);
    if (lastResult && section.isConnected) {
      lastResult.data.extras.blocklist = data;
      void saveHistory();
    }
  } catch (error) {
    if (section.isConnected) section.innerHTML = `<p class="detail-notice">${escapeHtml(error.message)}</p>`;
  }
}

portScanInput.addEventListener("change", () => {
  if (portScanInput.checked && !window.confirm("Are you sure you want to scan 26 common TCP ports on this domain's IP addresses?\n\nPort scans actively connect to the target and can be logged or flagged by its owner. Only scan systems you are authorized to test.")) {
    portScanInput.checked = false;
  }
});

function featureAllowed(feature) {
  const access = authState?.featureAccess?.[feature] || "user";
  return access === "public" || Boolean(authState?.user) && (access !== "admin" || authState.user.role === "admin");
}

// Magic scan can include the Email check and SSLscan for users who may use those tools.
function updateScanIncludes(scan = mode === "scan") {
  const email = featureAllowed("email");
  const ssl = featureAllowed("sslscan");
  const web = featureAllowed("web");
  const dnsHealth = featureAllowed("dns-health");
  const grade = ssl && Boolean(authState?.user);
  document.querySelector("#scan-web-option").hidden = !web;
  if (!web) scanWebInput.checked = false;
  document.querySelector("#scan-dns-health-option").hidden = !dnsHealth;
  if (!dnsHealth) scanDnsHealthInput.checked = false;
  document.querySelector("#scan-email-option").hidden = !email;
  document.querySelector("#scan-ssl-option").hidden = !ssl;
  document.querySelector("#scan-tls-grade-option").hidden = !grade;
  if (!email) scanEmailInput.checked = false;
  if (!ssl) scanSslInput.checked = false;
  if (!grade) scanTlsGradeInput.checked = false;
  scanIncludesControl.hidden = !scan || !(email || ssl || web || dnsHealth);
}

function scanIncludeSection(kind, html) {
  return `<section class="scan-include" data-include="${kind}">${html}</section>`;
}

async function appendScanIncludes(domain) {
  const jobs = [];
  if (scanEmailInput.checked && featureAllowed("email")) {
    jobs.push(["email", "Running the Email check…", `/api/email-check?${new URLSearchParams({ name: domain, selectors: "" })}`, emailResultHtml]);
  }
  if (scanSslInput.checked && featureAllowed("sslscan")) {
    jobs.push(["sslscan", "Running SSLscan on port 443…", `/api/sslscan?${new URLSearchParams({ name: domain, port: "443" })}`, sslScanResultHtml]);
  }
  if (scanDnsHealthInput.checked && featureAllowed("dns-health")) {
    jobs.push(["dnsHealth", "Running the DNS health check…", `/api/dns-health?${new URLSearchParams({ name: domain })}`, dnsHealthHtml]);
  }
  if (scanWebInput.checked && featureAllowed("web")) {
    jobs.push(["web", "Running the Web check…", `/api/web-check?${new URLSearchParams({ name: domain })}`, webCheckHtml]);
  }
  if (scanTlsGradeInput.checked && featureAllowed("sslscan") && authState?.user) void runTlsGrade(domain, 443);
  await Promise.all(jobs.map(async ([kind, pending, url, render]) => {
    const section = document.createElement("section");
    section.className = "scan-include";
    section.dataset.include = kind;
    section.innerHTML = `<p class="detail-notice">${escapeHtml(pending)}</p>`;
    resultPanel.append(section);
    try {
      const response = await fetch(url, { credentials: "same-origin" });
      const data = await readApiResponse(response);
      if (!response.ok) throw new Error(data.error || "The check failed.");
      if (!section.isConnected) return;
      section.innerHTML = render(data);
      if (lastResult?.mode === "scan") {
        lastResult.data.extras[kind] = data;
        void saveHistory();
      }
    } catch (error) {
      if (section.isConnected) section.innerHTML = `<p class="detail-notice">${escapeHtml(`${{ email: "Email check", sslscan: "SSLscan", web: "Web check", dnsHealth: "DNS health check" }[kind]}: ${error.message}`)}</p>`;
    }
  }));
}

function renderDnssecResult(data) {
  const check = data.dnssecCheck;
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">DNSSEC CHECK</p><h2>${copyableResult(check.domain)}</h2></div>
    </div>
    ${renderDnssecSection(check)}`;
  resultPanel.hidden = false;
}

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
    : `<p class="detail-notice">${escapeHtml(data.registrationError || "No registration details were returned.")}${registryLinkHtml(data.registryUrl)}</p>`;

  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">MAGIC SCAN</p><h2>${copyableResult(data.domain)}</h2></div>
      <span class="status-badge success">${copyableResult(`${data.hostsWithRecords} hosts found`)}</span>
    </div>
    ${data.hosts.some((host) => host.name === data.domain && host.records.some((record) => ["A", "AAAA"].includes(record.type))) ? sitePreviewHtml(`http://${data.domain}/`, { caption: `Live view of ${data.domain} through this server (scripts and links disabled)`, size: "medium" }) : ""}
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
      <h3>Domain registration <span class="email-auth-status ${registration ? "found" : "missing"}">${registration ? escapeHtml(registrationSourceLabel(registration)) : "Unavailable"}</span></h3>
      ${registrationDetails}
      ${renderRawWhois(registration)}
      <p class="scan-disclaimer">Registration information comes from RDAP, or from the registry's WHOIS server for domains whose registry has no RDAP service (many country-code domains). Contact details may be redacted or unavailable.</p>
    </section>
    ${renderDnssecSection(data.dnssec)}
    ${renderBlocklistSection(data.blocklists)}
    ${renderTakeoverSection(data.takeover)}
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
      ${renderMailSecurity(emailSecurity)}
      <p class="scan-disclaimer">SPF is checked on the domain and scanned hosts, and the domain's SPF is evaluated through its includes to count DNS lookups (limit 10). DKIM checks common selectors; your mail provider may use a custom selector that is not included. The MTA-STS policy is fetched from https://mta-sts.&lt;domain&gt;.</p>
    </section>
    ${hostResults}
    ${portScanSection}
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
    ${results || (data.openOnly && data.addressesScanned
    ? '<p class="empty-result">The port was not open on any scanned address.</p>'
    : '<p class="empty-result">No eligible IP addresses were available to scan.</p>')}
    <p class="scan-disclaimer">${data.engine === "zmap"
    ? "IPv4 addresses were scanned with zmap (TCP SYN); only addresses that answered with SYN-ACK are listed."
    : "Only ports that accepted a TCP connection are listed."} Scan only systems you are authorized to test.</p>`;
  resultPanel.hidden = false;
}

function renderNmapResult(data) {
  const hosts = (data.hosts || []).map((host) => {
    const hostname = host.hostnames?.length ? ` (${host.hostnames.join(", ")})` : "";
    const rows = (host.ports || []).map((port) => `
      <tr>
        <td>${escapeHtml(`${port.port}/${port.protocol}`)}</td>
        <td>${escapeHtml(port.state)}</td>
        <td>${escapeHtml([port.service, port.product, port.version].filter(Boolean).join(" "))}</td>
      </tr>
    `).join("");
    return `
      <section class="record-section">
        <h3>${copyableResult(host.address || data.address)}${escapeHtml(hostname)}
          <span class="status-badge ${host.status === "up" ? "success" : "warning"}">${escapeHtml(host.status || "unknown")}</span>
        </h3>
        ${rows
          ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table">
              <thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
              <tbody>${rows}</tbody>
            </table></div>`
          : '<p class="empty-result">No ports were reported open.</p>'}
      </section>`;
  }).join("");
  const openPorts = (data.hosts || []).reduce(
    (count, host) => count + (host.ports || []).filter((port) => port.state === "open").length,
    0,
  );
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">NMAP SCAN</p><h2>${copyableResult(data.target)}</h2></div>
      <span class="status-badge ${openPorts ? "success" : "warning"}">${openPorts} open</span>
    </div>
    <div class="scan-summary">
      <span>Resolved target: ${copyableResult(data.address)}</span>
      <span>${escapeHtml(data.profile)}</span>
    </div>
    ${hosts || '<p class="empty-result">Nmap did not return host results.</p>'}
    <p class="scan-disclaimer">Only the authorized target was scanned. Scan only systems you are authorized to test.</p>`;
  resultPanel.hidden = false;
}

function setNmapLiveStatus(message, running = false) {
  nmapLiveStatus.textContent = message;
  nmapLiveStatus.hidden = !message;
  nmapLiveStatus.classList.toggle("is-running", running);
  nmapLiveStatus.setAttribute("aria-live", running ? "off" : "polite");
}

function stopNmapStatusPolling() {
  nmapStatusPolling = false;
  clearTimeout(nmapStatusTimer);
  nmapStatusTimer = null;
}

async function pollNmapStatus() {
  if (!nmapStatusPolling) return;
  try {
    const response = await fetch("/api/nmap-status", {
      credentials: "same-origin",
      cache: "no-store",
    });
    const data = await readApiResponse(response);
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    if (!nmapStatusPolling) return;
    if (data.state === "scanning") {
      const elapsedSeconds = Math.max(0, Math.floor((Date.now() - data.startedAt) / 1000));
      setNmapLiveStatus(
        `${data.stage || "Nmap scan running"}: ${data.target} — ${data.profile}. Elapsed ${elapsedSeconds}s.`,
        true,
      );
    } else if (data.state === "completed") {
      stopNmapStatusPolling();
      setNmapLiveStatus(`Nmap scan complete in ${(data.elapsedMs / 1000).toFixed(1)}s.`);
    } else if (data.state === "failed") {
      stopNmapStatusPolling();
      setNmapLiveStatus(`Nmap scan failed: ${data.error || "Unable to complete the scan."}`);
    }
  } catch (error) {
    if (!nmapStatusPolling) return;
    setNmapLiveStatus(`Live Nmap status unavailable: ${error.message}`, true);
  } finally {
    if (nmapStatusPolling) nmapStatusTimer = setTimeout(pollNmapStatus, 1000);
  }
}

function startNmapStatusPolling() {
  stopNmapStatusPolling();
  nmapStatusPolling = true;
  setNmapLiveStatus("Checking target authorization before the scan starts…", true);
  void pollNmapStatus();
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

function sslScanResultHtml(data) {
  const handshakeSucceeded = Boolean(data.handshake);
  const trusted = handshakeSucceeded && Boolean(data.authorized);
  const certificates = Array.isArray(data.certificateChain) ? data.certificateChain : [];
  const certificateSections = certificates.map((certificate, index) => `
    <section class="record-section">
      <h3>${index === 0 ? "Server certificate" : `Certificate ${index + 1}`}</h3>
      <div class="detail-list">
        ${renderDetail("Subject", certificate.subject)}
        ${renderDetail("Subject alternative names", certificate.subjectAltName)}
        ${renderDetail("Issuer", certificate.issuer)}
        ${renderDetail("Valid from", certificate.validFrom)}
        ${renderDetail("Valid until", certificate.validTo)}
        ${renderDetail("Serial number", certificate.serialNumber)}
        ${renderDetail("SHA-256 fingerprint", certificate.fingerprint256)}
      </div>
    </section>
  `).join("");
  return `
    <div class="result-heading">
      <div><p class="eyebrow">SSL/TLS CHECK</p><h2>${copyableResult(data.target)}:${escapeHtml(String(data.port))}</h2></div>
      <span class="status-badge ${trusted ? "success" : "warning"}">${!handshakeSucceeded
    ? "Handshake failed"
    : trusted ? "Certificate trusted" : "Certificate not trusted"}</span>
    </div>
    <section class="record-section">
      <h3>Negotiated connection</h3>
      <div class="detail-list">
        ${renderDetail("Resolved address", data.address)}
        ${renderDetail("TLS protocol", data.protocol)}
        ${renderDetail("Cipher", data.cipher?.name)}
        ${renderDetail("Cipher protocol", data.cipher?.version)}
        ${renderDetail("Cipher strength", data.cipher?.bits ? `${data.cipher.bits} bits` : "")}
        ${renderDetail("Certificate verification", handshakeSucceeded ? (trusted ? "Trusted" : "Failed") : "Not completed")}
        ${renderDetail("Verification detail", data.authorizationError)}
      </div>
      ${data.error ? `<p class="detail-notice">${escapeHtml(data.error)}</p>` : ""}
    </section>
    ${certificateSections || (handshakeSucceeded
    ? '<p class="empty-result">The server did not provide a certificate.</p>'
    : "")}
    <p class="scan-disclaimer">This performs one TLS handshake only. It does not enumerate supported protocol versions or cipher suites, or test for TLS vulnerabilities.</p>`;
}

function renderSslScanResult(data) {
  resultPanel.innerHTML = sslScanResultHtml(data);
  resultPanel.hidden = false;
}

const tlsSeverityRank = { OK: 0, INFO: 1, LOW: 2, MEDIUM: 3, WARN: 3, HIGH: 4, CRITICAL: 5, FATAL: 5 };
const tlsProtocolIds = [["SSLv2", "SSL 2.0"], ["SSLv3", "SSL 3.0"], ["TLS1", "TLS 1.0"], ["TLS1_1", "TLS 1.1"], ["TLS1_2", "TLS 1.2"], ["TLS1_3", "TLS 1.3"]];
const tlsVulnerabilityIds = [
  ["heartbleed", "Heartbleed"], ["CCS", "CCS injection"], ["ticketbleed", "Ticketbleed"], ["ROBOT", "ROBOT"],
  ["secure_renego", "Secure renegotiation"], ["secure_client_renego", "Client-initiated renegotiation"],
  ["CRIME_TLS", "CRIME (TLS compression)"], ["BREACH", "BREACH (HTTP compression)"], ["POODLE_SSL", "POODLE (SSLv3)"],
  ["fallback_SCSV", "Downgrade protection (TLS_FALLBACK_SCSV)"], ["SWEET32", "SWEET32"], ["FREAK", "FREAK"],
  ["DROWN", "DROWN"], ["LOGJAM", "Logjam"], ["BEAST", "BEAST"], ["LUCKY13", "Lucky Thirteen"], ["winshock", "Winshock"],
  ["RC4", "RC4"], ["opossum", "Opossum"],
];
const tlsCertificateIds = [
  ["cert_chain_of_trust", "Chain of trust"], ["cert_trust", "Host name match"], ["cert_commonName", "Common name"],
  ["cert_subjectAltName", "Subject alternative names"], ["cert_caIssuers", "Issuer"], ["cert_keySize", "Key"],
  ["cert_signatureAlgorithm", "Signature algorithm"], ["cert_notBefore", "Valid from"], ["cert_notAfter", "Valid until"],
  ["cert_expirationStatus", "Expiration"], ["cert_revocation", "Revocation information"], ["OCSP_stapling", "OCSP stapling"],
  ["certificate_transparency", "Certificate Transparency"], ["DNS_CAArecord", "DNS CAA record"],
  ["HSTS_time", "HSTS"], ["HSTS_preload", "HSTS preload"], ["FS", "Forward secrecy"],
];

function tlsSeverityClass(severity) {
  const rank = tlsSeverityRank[severity] ?? 1;
  return rank >= 4 ? "danger" : rank >= 2 ? "warning" : rank === 0 ? "success" : "";
}

function tlsGradeClass(grade) {
  if (!grade) return "";
  if (grade.startsWith("A")) return "success";
  if (grade === "B" || grade === "C") return "warning";
  return "danger";
}

function renderTlsFindingRows(rows) {
  return rows.map(([label, finding]) => `
    <tr>
      <td>${escapeHtml(label)}</td>
      <td><span class="tls-severity ${tlsSeverityClass(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(finding.finding)}${finding.cve ? `<br><span class="trace-silent">${escapeHtml(finding.cve)}</span>` : ""}</td>
    </tr>`).join("");
}

function renderTlsGradeReport(result) {
  const byId = new Map(result.findings.map((finding) => [finding.id, finding]));
  const pick = (ids) => ids.filter(([id]) => byId.has(id)).map(([id, label]) => [label, byId.get(id)]);
  const scoreBar = (label, value) => value === null ? "" : `
    <div class="tls-score"><span>${escapeHtml(label)}</span>
      <div class="tls-score-bar"><div data-score="${Math.max(0, Math.min(100, Number(value) || 0))}"></div></div>
      <strong>${escapeHtml(String(value))}</strong></div>`;
  const ciphers = result.findings.filter((finding) => finding.id.startsWith("cipher-tls") || finding.id.startsWith("cipher-ssl"))
    .map((finding) => {
      const parts = finding.finding.trim().split(/\s{2,}/);
      const kx = parts.length >= 7 ? parts[3] : (parts[3] || "").replace(/\s+\S+$/, "");
      return { finding, protocol: parts[0] || "", name: parts.at(-1) || finding.finding, bits: (parts.at(-2) || "").trim(), kx };
    });
  const cipherRows = ciphers.map(({ finding, protocol, name, bits, kx }) => `
    <tr>
      <td>${escapeHtml(protocol)}</td>
      <td><span class="tls-severity ${tlsSeverityClass(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
      <td>${escapeHtml(name)}</td>
      <td>${escapeHtml(kx)}</td>
      <td>${escapeHtml(/^\d+$/.test(bits) ? `${bits} bits` : "")}</td>
    </tr>`).join("");
  const sortedFindings = [...result.findings]
    .filter((finding) => !finding.id.startsWith("clientsimulation-"))
    .sort((left, right) => (tlsSeverityRank[right.severity] ?? 1) - (tlsSeverityRank[left.severity] ?? 1));
  const table = (head, rows) => rows ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table">
    <thead><tr>${head.map((cell) => `<th>${escapeHtml(cell)}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table></div>` : "";
  return `
    <div class="tls-grade-summary">
      <span class="ssllabs-grade tls-grade-large ${tlsGradeClass(result.grade)}">${escapeHtml(result.grade || "?")}</span>
      <div class="tls-scores">
        ${scoreBar("Protocol support (30%)", result.scores.protocol)}
        ${scoreBar("Key exchange (30%)", result.scores.keyExchange)}
        ${scoreBar("Cipher strength (40%)", result.scores.cipher)}
        ${scoreBar("Final score", result.scores.final)}
      </div>
    </div>
    ${result.capReasons.map((reason) => `<p class="detail-notice">${escapeHtml(reason)}</p>`).join("")}
    ${result.warnings.map((warning) => `<p class="detail-notice">${escapeHtml(warning)}</p>`).join("")}
    <h4 class="tls-subheading">Protocols</h4>
    ${table(["Protocol", "Severity", "Result"], renderTlsFindingRows(pick(tlsProtocolIds)))}
    <h4 class="tls-subheading">Cipher suites</h4>
    ${table(["Protocol", "Severity", "Cipher suite", "Key exchange", "Strength"], cipherRows) || '<p class="empty-result">No cipher suites were reported.</p>'}
    <h4 class="tls-subheading">Certificate, HSTS and forward secrecy</h4>
    ${table(["Check", "Severity", "Result"], renderTlsFindingRows(pick(tlsCertificateIds)))}
    <h4 class="tls-subheading">Vulnerabilities</h4>
    ${table(["Test", "Severity", "Result"], renderTlsFindingRows(pick(tlsVulnerabilityIds)))}
    <details class="tls-all-findings">
      <summary>All ${escapeHtml(String(sortedFindings.length))} findings</summary>
      ${table(["Test", "Severity", "Result"], renderTlsFindingRows(sortedFindings.map((finding) => [finding.id, finding])))}
    </details>
    <p class="scan-disclaimer">Grade calculated with testssl.sh using the SSL Labs SSL Server Rating Guide${result.scanTime ? `; the test took ${escapeHtml(String(result.scanTime))} seconds` : ""}. Grades can differ slightly from SSL Labs, which tests every IP address of a host and runs some extra checks.</p>`;
}

function renderTlsGradeSection(state) {
  const section = document.querySelector("#tls-grade-section");
  if (!section) return false;
  const elapsed = state.elapsedMs ? ` · ${Math.round(state.elapsedMs / 1000)} s` : "";
  const badge = state.error
    ? '<span class="status-badge warning">Not completed</span>'
    : state.result
      ? '<span class="status-badge success">Complete</span>'
      : `<span class="status-badge live">${escapeHtml(`${state.stage || "Starting"}${elapsed}`)}</span>`;
  section.innerHTML = `
    <div class="trace-heading"><h3>TLS test and grade${state.address ? ` ${copyableResult(state.address, "port-target-address")}` : ""}</h3>${badge}</div>
    ${state.error ? `<p class="detail-notice">${escapeHtml(state.error)}</p>` : ""}
    ${!state.error && !state.result ? '<p class="detail-notice">Testing protocols, cipher suites, the certificate and known vulnerabilities. This usually takes one to three minutes.</p>' : ""}
    ${state.result ? renderTlsGradeReport(state.result) : ""}`;
  // The CSP forbids inline style attributes, so bar widths are set through the CSSOM.
  section.querySelectorAll(".tls-score-bar [data-score]").forEach((bar) => {
    bar.style.width = `${bar.dataset.score}%`;
  });
  return true;
}

// The full TLS test is the most useful part of the result, so it goes directly under the heading.
function insertTlsGradeSection() {
  const section = '<section class="record-section trace-section tls-grade-top" id="tls-grade-section"></section>';
  const heading = resultPanel.querySelector(".result-heading");
  if (heading) heading.insertAdjacentHTML("afterend", section);
  else resultPanel.insertAdjacentHTML("afterbegin", section);
}

async function runTlsGrade(target, port) {
  const run = tlsGradeRun;
  insertTlsGradeSection();
  const state = { stage: "Starting" };
  renderTlsGradeSection(state);
  try {
    const startResponse = await fetch("/api/tls-grade", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, port: String(port) }),
    });
    const started = await readApiResponse(startResponse);
    if (!startResponse.ok) throw new Error(started.error || "The TLS test could not be started.");
    Object.assign(state, { address: started.address });
    while (run === tlsGradeRun) {
      await new Promise((resolve) => setTimeout(resolve, 4000));
      if (run !== tlsGradeRun) return;
      const response = await fetch(`/api/tls-grade?${new URLSearchParams({ id: started.id })}`);
      const data = await readApiResponse(response);
      if (run !== tlsGradeRun) return;
      if (!response.ok) throw new Error(data.error || "The TLS test failed.");
      Object.assign(state, { stage: data.stage, elapsedMs: data.elapsedMs, error: data.error, result: data.result });
      if (data.result && ["sslscan", "scan"].includes(lastResult?.mode)) {
        lastResult.data.extras.tlsGrade = { result: data.result, address: data.address };
        void saveHistory();
      }
      if (!renderTlsGradeSection(state) || data.status !== "running") return;
    }
  } catch (error) {
    if (run !== tlsGradeRun) return;
    state.error = error.message;
    renderTlsGradeSection(state);
  }
}

function drawPingMonitorChart() {
  const bounds = pingMonitorChart.getBoundingClientRect();
  if (!bounds.width || !bounds.height) return;
  const ratio = window.devicePixelRatio || 1;
  pingMonitorChart.width = Math.round(bounds.width * ratio);
  pingMonitorChart.height = Math.round(bounds.height * ratio);
  const context = pingMonitorChart.getContext("2d");
  context.scale(ratio, ratio);
  const width = bounds.width;
  const height = bounds.height;
  const padding = { top: 14, right: 12, bottom: 30, left: 48 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const latencies = pingMonitorSamples.map((sample) => sample.latency).filter(Number.isFinite);
  const maxLatency = Math.max(100, ...latencies) * 1.15;
  context.clearRect(0, 0, width, height);
  context.font = "13px sans-serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  context.strokeStyle = "#343434";
  context.fillStyle = "#999";
  for (let index = 0; index <= 4; index += 1) {
    const y = padding.top + chartHeight * index / 4;
    const label = `${(maxLatency * (4 - index) / 4).toFixed(0)} ms`;
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
    context.fillText(label, padding.left - 7, y);
  }
  context.textAlign = "center";
  context.textBaseline = "top";
  context.fillText("oldest", padding.left, height - padding.bottom + 8);
  context.fillText("latest", width - padding.right, height - padding.bottom + 8);
  if (pingMonitorSamples.length < 1) return;
  const xAt = (index) => padding.left + (pingMonitorSamples.length < 2
    ? chartWidth
    : chartWidth * index / (pingMonitorSamples.length - 1));
  const yAt = (latency) => padding.top + chartHeight * (1 - latency / maxLatency);
  let segmentOpen = false;
  pingMonitorSamples.forEach((sample, index) => {
    if (!Number.isFinite(sample.latency)) {
      segmentOpen = false;
      return;
    }
    const x = xAt(index);
    const y = yAt(sample.latency);
    if (!segmentOpen) {
      context.beginPath();
      context.moveTo(x, y);
      segmentOpen = true;
    } else {
      context.lineTo(x, y);
    }
  });
  context.strokeStyle = "#65d993";
  context.lineWidth = 2;
  context.stroke();
  pingMonitorSamples.forEach((sample, index) => {
    const x = xAt(index);
    const y = Number.isFinite(sample.latency) ? yAt(sample.latency) : height - padding.bottom;
    context.beginPath();
    context.arc(x, y, 3, 0, Math.PI * 2);
    context.fillStyle = sample.up ? "#65d993" : "#fa8390";
    context.fill();
  });
  const latest = pingMonitorSamples.at(-1);
  pingMonitorChart.setAttribute(
    "aria-label",
    `Latency history: ${pingMonitorSamples.length} samples; latest ${latest.up && Number.isFinite(latest.latency) ? `${latest.latency.toFixed(1)} milliseconds` : "host down"}.`,
  );
}

function updatePingMonitorSummary() {
  const up = pingMonitorSamples.filter((sample) => sample.up).length;
  const down = pingMonitorSamples.length - up;
  const latencies = pingMonitorSamples.map((sample) => sample.latency).filter(Number.isFinite);
  const average = latencies.length
    ? latencies.reduce((total, latency) => total + latency, 0) / latencies.length
    : null;
  pingMonitorSummary.textContent = `${pingMonitorSamples.length} samples · ${up} up · ${down} down · ${
    average === null ? "no latency samples" : `average ${average.toFixed(1)} ms`
  }`;
  drawPingMonitorChart();
}

function playPingMonitorTone(up) {
  if (!pingMonitorSound.checked || !pingMonitorAudioContext) return;
  const oscillator = pingMonitorAudioContext.createOscillator();
  const gain = pingMonitorAudioContext.createGain();
  oscillator.frequency.value = up ? 880 : 440;
  gain.gain.setValueAtTime(0.0001, pingMonitorAudioContext.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.12, pingMonitorAudioContext.currentTime + 0.02);
  gain.gain.exponentialRampToValueAtTime(0.0001, pingMonitorAudioContext.currentTime + 0.22);
  oscillator.connect(gain);
  gain.connect(pingMonitorAudioContext.destination);
  oscillator.start();
  oscillator.stop(pingMonitorAudioContext.currentTime + 0.23);
}

function stopPingMonitor(message = "Monitoring stopped.") {
  if (pingMonitorTimer) clearTimeout(pingMonitorTimer);
  pingMonitorTimer = null;
  pingMonitorActive = false;
  pingMonitorAbortController?.abort();
  pingMonitorAbortController = null;
  pingMonitorStart.disabled = !authState?.user;
  pingMonitorStop.disabled = true;
  if (!pingMonitorPanel.hidden && message) pingMonitorStatus.textContent = message;
}

async function pollPingMonitor() {
  if (!pingMonitorActive) return;
  if (Date.now() - pingMonitorStartedAt >= 5 * 60 * 1000 ||
    pingMonitorSamples.length >= 100) {
    stopPingMonitor("The 5-minute monitoring limit was reached.");
    return;
  }
  const sampleNumber = pingMonitorSamples.length;
  const requestedAt = pingMonitorStartedAt + sampleNumber * 3000;
  pingMonitorAbortController = new AbortController();
  let sample;
  try {
    const params = new URLSearchParams({
      name: pingMonitorTargetValue,
      method: pingMethodInput.value,
      sample: "1",
    });
    const response = await fetch(`/api/ping?${params}`, {
      credentials: "same-origin",
      signal: pingMonitorAbortController.signal,
    });
    const data = await readApiResponse(response);
    if (response.status === 401) {
      stopPingMonitor("Sign in again to continue monitoring.");
      return;
    }
    if (response.status === 429) {
      stopPingMonitor(data.error || "The monitoring rate limit was reached.");
      return;
    }
    if ([400, 403].includes(response.status)) {
      stopPingMonitor(data.error || "This target cannot be monitored.");
      return;
    }
    if (!response.ok) throw new Error(data.error || "The host check failed.");
    const latency = data.method === "icmp"
      ? data.times?.length
        ? data.times.reduce((sum, time) => sum + time, 0) / data.times.length
        : null
      : Number.isFinite(data.responseMs) ? data.responseMs : null;
    sample = {
      up: Boolean(data.up),
      latency: data.up && Number.isFinite(latency) ? latency : null,
      address: data.address,
      error: data.error || "",
    };
  } catch (error) {
    if (!pingMonitorActive || error.name === "AbortError") return;
    sample = { up: false, latency: null, address: "", error: error.message || "Request failed." };
  } finally {
    pingMonitorAbortController = null;
  }
  if (!pingMonitorActive) return;
  pingMonitorSamples.push(sample);
  if (sample.up !== pingMonitorPreviousState) {
    if (pingMonitorPreviousState !== null) playPingMonitorTone(sample.up);
    pingMonitorPreviousState = sample.up;
  }
  pingMonitorState.textContent = sample.up ? "Host is up" : "Host is down";
  pingMonitorState.classList.toggle("success", sample.up);
  pingMonitorState.classList.toggle("warning", !sample.up);
  const elapsedSeconds = Math.floor((Date.now() - pingMonitorStartedAt) / 1000);
  pingMonitorStatus.textContent = `${sample.address ? `${sample.address} · ` : ""}${
    sample.up && Number.isFinite(sample.latency)
      ? `${sample.latency.toFixed(1)} ms`
      : sample.error || "No response"
  } · ${elapsedSeconds}s elapsed · monitoring ends after 5 minutes`;
  updatePingMonitorSummary();
  if (pingMonitorSamples.length >= 100) {
    stopPingMonitor("The 5-minute monitoring limit was reached.");
    return;
  }
  const delay = Math.max(0, requestedAt + 3000 - Date.now());
  pingMonitorTimer = setTimeout(pollPingMonitor, delay);
}

pingMonitorStart.addEventListener("click", async () => {
  if (!authState?.user) {
    pingMonitorStatus.textContent = "Sign in to use live host monitoring.";
    pingMonitorPanel.hidden = false;
    return;
  }
  if (pingMonitorActive) return;
  pingMonitorTargetValue = input.value.trim();
  if (!pingMonitorTargetValue) {
    input.focus();
    errorMessage.textContent = "Enter a domain name or IP address to monitor.";
    errorMessage.hidden = false;
    return;
  }
  if (pingMonitorSound.checked && window.AudioContext) {
    pingMonitorAudioContext ||= new AudioContext();
    await pingMonitorAudioContext.resume();
  }
  pingMonitorActive = true;
  pingMonitorStartedAt = Date.now();
  pingMonitorSamples = [];
  pingMonitorPreviousState = null;
  pingMonitorTarget.textContent = pingMonitorTargetValue;
  pingMonitorState.textContent = "Checking…";
  pingMonitorState.classList.remove("success");
  pingMonitorState.classList.add("warning");
  pingMonitorStatus.textContent = "Starting host checks…";
  pingMonitorSummary.textContent = "No samples yet.";
  resultPanel.hidden = true;
  pingMonitorPanel.hidden = false;
  pingMonitorStart.disabled = true;
  pingMonitorStop.disabled = false;
  drawPingMonitorChart();
  void pollPingMonitor();
});

pingMonitorStop.addEventListener("click", () => stopPingMonitor());
window.addEventListener("resize", drawPingMonitorChart);
document.addEventListener("visibilitychange", () => {
  if (document.hidden && pingMonitorActive) {
    stopPingMonitor("Monitoring stopped because the page is no longer visible.");
  }
});

function renderPingScanResult(data) {
  const rows = data.results.map((result) => `
    <tr>
      <td>${copyableResult(result.address)}</td>
      <td><span class="status-badge ${result.up ? "success" : "warning"}">${result.up ? "Up" : "No reply"}</span></td>
      <td>${result.rttMs === null ? "" : escapeHtml(`${result.rttMs} ms`)}</td>
    </tr>`).join("");
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">PING SCAN</p><h2>${escapeHtml(`${data.up} of ${data.scanned} hosts up`)}</h2></div>
      <span class="status-badge ${data.up ? "success" : "warning"}">${escapeHtml(`${data.up} up`)}</span>
    </div>
    ${data.skipped ? `<p class="detail-notice">${escapeHtml(data.skipped)} disallowed or reserved IP address(es) were skipped.</p>` : ""}
    ${rows ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table">
      <thead><tr><th>Address</th><th>Status</th><th>Round trip</th></tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="empty-result">No eligible IP addresses were available to scan.</p>'}
    <p class="scan-disclaimer">One ICMP echo request was sent per address. Hosts that block ICMP appear as no reply. Scan only networks you are authorized to test.</p>`;
  resultPanel.hidden = false;
}

function hopPtrNames(result, hop) {
  return hop.ptr || result.ptr?.[hop.address]?.names;
}

function renderHopPtr(result, hop) {
  if (!hop.address) return "";
  const names = hopPtrNames(result, hop);
  if (!names) return result.running ? '<span class="trace-silent">Looking up…</span>' : "";
  if (hop.ptrError || result.ptr?.[hop.address]?.error) return '<span class="trace-silent">Lookup failed</span>';
  if (!names.length) return '<span class="trace-silent">No PTR record</span>';
  return names.map((name) => copyableResult(name)).join("<br>");
}

function renderTraceTable(result) {
  const rows = result.hops.map((hop) => `
    <tr>
      <td>${escapeHtml(hop.hop)}</td>
      <td>${hop.address ? copyableResult(hop.address) : '<span class="trace-silent">* no reply</span>'}</td>
      ${result.showPtr ? `<td>${renderHopPtr(result, hop)}</td>` : ""}
      <td>${hop.rttMs === null ? "" : escapeHtml(`${hop.rttMs} ms`)}</td>
    </tr>`).join("");
  return `
    <section class="record-section trace-section">
      <div class="trace-heading">
        <h3>${copyableResult(result.target)}${result.address && result.address !== result.target ? ` ${copyableResult(result.address, "port-target-address")}` : ""}</h3>
        ${result.error
    ? ""
    : result.running
      ? `<span class="status-badge live">${result.address ? "Tracing…" : "Queued"}</span>`
      : `<span class="status-badge ${result.reached ? "success" : "warning"}">${result.reached ? "Destination reached" : "Destination not reached"}</span>`}
      </div>
      ${result.error ? `<p class="detail-notice">${escapeHtml(result.error)}</p>` : ""}
      ${rows ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table">
        <thead><tr><th>Hop</th><th>Address</th>${result.showPtr ? "<th>Host name (PTR)</th>" : ""}<th>Response time</th></tr></thead><tbody>${rows}</tbody></table></div>` : ""}
      ${result.partial ? '<p class="detail-notice">The trace took too long and was stopped; the path shown is incomplete.</p>' : ""}
    </section>`;
}

function renderTraceComparison(results) {
  const traced = results.filter((result) => result.hops.length);
  if (traced.length < 2) return "";
  const hopCount = Math.max(...traced.map((result) => result.hops.at(-1).hop));
  const rows = Array.from({ length: hopCount }, (_, index) => {
    const hopNumber = index + 1;
    const cells = traced.map((result) => {
      const hop = result.hops.find((item) => item.hop === hopNumber);
      const ptrName = hop?.address && result.showPtr ? hopPtrNames(result, hop)?.[0] : null;
      return `<td>${hop?.address ? copyableResult(hop.address) : hop ? '<span class="trace-silent">*</span>' : ""}${ptrName ? `<br>${copyableResult(ptrName, "port-target-address")}` : ""}</td>`;
    }).join("");
    return `<tr><td>${hopNumber}</td>${cells}</tr>`;
  }).join("");
  return `
    <section class="record-section trace-section">
      <h3>Route comparison</h3>
      <div class="dns-results-table-wrap"><table class="dns-results-table net-table">
        <thead><tr><th>Hop</th>${traced.map((result) => `<th>${escapeHtml(result.target)}</th>`).join("")}</tr></thead>
        <tbody>${rows}</tbody></table></div>
    </section>`;
}

function renderTracerouteResult(data, multiple) {
  const reached = data.results.filter((result) => result.reached).length;
  const running = data.results.some((result) => result.running);
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">${multiple ? "MULTI TRACEROUTE" : "TRACEROUTE"}</p><h2>${multiple
    ? escapeHtml(`${data.results.length} target(s) ${running ? "being traced" : "traced"}`)
    : copyableResult(data.results[0].target)}</h2></div>
      <span class="status-badge ${running ? "live" : reached ? "success" : "warning"}">${escapeHtml(running ? "Live" : multiple ? `${reached} reached` : reached ? "Destination reached" : "Not reached")}</span>
    </div>
    ${multiple ? renderTraceComparison(data.results) : ""}
    ${data.results.map(renderTraceTable).join("")}
    <p class="scan-disclaimer">Routers that do not answer probes appear as no reply. Paths are traced with UDP probes (tracepath), up to 20 hops.</p>`;
  resultPanel.hidden = false;
}

async function streamTraceroute(multiple) {
  const rawTargets = multiple ? multiTraceInput.value : input.value;
  const targets = [...new Set(rawTargets.split(multiple ? /[\s,;]+/ : /\n/).map((item) => item.trim()).filter(Boolean))].slice(0, multiple ? 10 : 1);
  const showPtr = tracePtrInput.checked;
  const newEntry = (target) => ({ target, hops: [], reached: false, running: true, showPtr, ptr: {} });
  const results = targets.map(newEntry);
  const traceParams = new URLSearchParams({ name: input.value.trim(), stream: "1" });
  if (showPtr) traceParams.set("ptr", "1");
  const response = multiple
    ? await fetch("/api/multi-traceroute", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ targets: rawTargets, stream: true, ptr: showPtr }),
    })
    : await fetch(`/api/traceroute?${traceParams}`);
  if (response.status === 401) {
    const next = `${window.location.pathname}${window.location.search}`;
    window.location.assign(`/login.html?next=${encodeURIComponent(next)}`);
    return;
  }
  if (!response.ok || !response.body) {
    const data = await readApiResponse(response);
    throw new Error(data.error || "Traceroute failed.");
  }
  if (!results.length) results.push(newEntry(input.value.trim()));
  let frame = 0;
  const draw = () => {
    frame = 0;
    renderTracerouteResult({ results }, multiple);
  };
  const apply = (event) => {
    const entry = results[event.index] || (results[event.index] = newEntry(event.target || ""));
    if (event.type === "ptr") {
      entry.ptr[event.address] = { names: event.names || [], error: event.error };
      return;
    }
    if (event.target) entry.target = event.target;
    if (event.address) entry.address = event.address;
    if (event.type === "hops") {
      entry.hops = event.hops;
      entry.reached = event.reached;
    } else if (event.type === "done") {
      Object.assign(entry, event, { running: false });
      if (!event.error && !event.hops.length) entry.hops = [];
    }
  };
  draw();
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  for (;;) {
    const { value, done } = await reader.read();
    buffered += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffered.split("\n");
    buffered = done ? "" : lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        apply(JSON.parse(line));
      } catch {
        continue;
      }
    }
    if (!frame) frame = requestAnimationFrame(draw);
    if (done) break;
  }
  results.forEach((entry) => { entry.running = false; });
  cancelAnimationFrame(frame);
  draw();
  rememberResult(multiple ? "multi-traceroute" : "traceroute", { results }, results.map((entry) => entry.target).join(", "));
}

function renderAsnResult(data) {
  const as = data.as;
  const network = data.network;
  const prefixes = data.prefixes || {};
  const rpkiLabels = { valid: ["found", "RPKI valid"], invalid: ["danger", "RPKI invalid"], "invalid_asn": ["danger", "RPKI invalid (wrong origin AS)"], "invalid_length": ["danger", "RPKI invalid (too specific)"], unknown: ["missing", "No ROA (RPKI unknown)"] };
  const rpki = network?.rpki?.status ? rpkiLabels[network.rpki.status] || ["missing", `RPKI ${network.rpki.status}`] : null;
  const list = (items, family) => items?.length ? `
    <details class="asn-prefixes" ${items.length <= 50 ? "open" : ""}>
      <summary>${escapeHtml(`${family} prefixes (${items.length.toLocaleString()}${prefixes.truncated ? "+" : ""})`)}</summary>
      <div class="asn-prefix-grid">${items.map((prefix) => `<span data-prefix="${escapeHtml(prefix)}">${copyableResult(prefix)}</span>`).join("")}</div>
    </details>` : "";
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">ASN / PREFIXES</p><h2>${copyableResult(data.target)}</h2></div>
      ${as ? `<span class="status-badge ${as.announced === false ? "warning" : "success"}">${escapeHtml(`AS${as.asn}`)}</span>` : '<span class="status-badge warning">Not announced</span>'}
    </div>
    ${network ? `<section class="record-section">
      <h3>Network for ${copyableResult(network.address)}</h3>
      <div class="detail-list">
        ${renderDetail("Announced prefix", network.prefix || "Not announced in the global routing table")}
        ${renderDetail("Origin AS", network.asns?.length ? network.asns.map((value) => `AS${value}`).join(", ") : "")}
      </div>
      ${rpki ? `<p class="dnssec-summary"><span class="email-auth-status ${rpki[0]}">${escapeHtml(rpki[1])}</span> ${escapeHtml(network.rpki.roas?.length ? `ROA: ${network.rpki.roas.map((roa) => `${roa.prefix} max /${roa.maxLength} AS${roa.origin}`).join(", ")}` : "")}</p>` : ""}
    </section>` : ""}
    ${as ? `<section class="record-section">
      <h3>${escapeHtml(`AS${as.asn}`)}</h3>
      ${as.error ? `<p class="detail-notice">${escapeHtml(as.error)}</p>` : `<div class="detail-list">
        ${renderDetail("Holder", as.holder)}
        ${renderDetail("Currently announced", as.announced ? "Yes" : "No")}
        ${renderDetail("Registry", as.registry)}
        ${renderDetail("IPv4 prefixes", prefixes.ipv4Count !== undefined ? `${prefixes.ipv4Count.toLocaleString()} (${prefixes.ipv4Addresses.toLocaleString()} addresses)` : "")}
        ${renderDetail("IPv6 prefixes", prefixes.ipv6Count !== undefined ? prefixes.ipv6Count.toLocaleString() : "")}
      </div>`}
    </section>` : ""}
    ${prefixes.error ? `<p class="detail-notice">${escapeHtml(prefixes.error)}</p>` : ""}
    ${(prefixes.ipv4?.length || prefixes.ipv6?.length) ? `<section class="record-section">
      <h3>Announced prefixes</h3>
      <input class="asn-filter" id="asn-filter" type="search" placeholder="Filter prefixes, e.g. 104.16 or 2606:" aria-label="Filter prefixes">
      ${list(prefixes.ipv4, "IPv4")}
      ${list(prefixes.ipv6, "IPv6")}
      ${prefixes.truncated ? '<p class="detail-notice">Only the first 3,000 prefixes per family are listed.</p>' : ""}
    </section>` : ""}
    <p class="scan-disclaimer">Routing data from RIPE Stat (RIS route collectors), counting prefixes seen by at least three peers. ${escapeHtml(data.durationMs ? `Took ${data.durationMs} ms.` : "")}</p>`;
  const filter = resultPanel.querySelector("#asn-filter");
  filter?.addEventListener("input", () => {
    const term = filter.value.trim().toLowerCase();
    resultPanel.querySelectorAll(".asn-prefix-grid [data-prefix]").forEach((item) => {
      item.hidden = Boolean(term) && !item.dataset.prefix.toLowerCase().includes(term);
    });
    if (term) resultPanel.querySelectorAll(".asn-prefixes").forEach((details) => { details.open = true; });
  });
  resultPanel.hidden = false;
}

function emailResultHtml(data) {
  const chips = (values) => values.length ? `<div class="status-list">${values.map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>` : "";
  const table = (head, rows) => rows.length ? `<div class="dns-results-table-wrap"><table class="dns-results-table net-table">
    <thead><tr>${head.map((cell) => `<th>${escapeHtml(cell)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>` : "";
  const ptrFor = (address) => {
    const ptr = data.ptrLookups?.[address];
    return ptr?.answers?.length ? ptr.answers.join(", ") : "";
  };
  const mxRows = (data.mx?.records || []).map((record) => `
    <tr>
      <td>${escapeHtml(record.priority)}</td>
      <td>${copyableResult(record.host)}</td>
      <td>${record.addresses.length ? record.addresses.map((address) => `${copyableResult(address)}${ptrFor(address) ? ` <span class="trace-silent">${escapeHtml(ptrFor(address))}</span>` : ""}`).join("<br>") : '<span class="dnssec-bad">Does not resolve</span>'}</td>
      <td>${escapeHtml(record.provider || "")}</td>
    </tr>`);
  const smtpCards = (data.smtp || []).map((result) => {
    const status = result.error
      ? ["missing", "Not tested"]
      : !result.starttls ? ["danger", "No STARTTLS"]
      : result.tls && result.tls.authorized && result.tls.nameMatches ? ["found", "STARTTLS · trusted"]
      : result.tls ? ["warning", "STARTTLS · certificate problem"] : ["warning", "STARTTLS"];
    const tls = result.tls;
    return `
      <div class="smtp-card">
        <h4>${copyableResult(result.host)} ${result.address ? `<span class="trace-silent">${escapeHtml(result.address)}</span>` : ""} <span class="email-auth-status ${status[0]}">${escapeHtml(status[1])}</span></h4>
        ${result.error ? `<p class="detail-notice">${escapeHtml(result.error)}</p>` : ""}
        ${renderFacts([
          ["Banner", result.banner],
          ["TLS", tls ? [tls.protocol, tls.cipher].filter(Boolean).join(" · ") : ""],
          ["Certificate", tls?.subject],
          ["Issuer", tls?.issuer],
          ["Trusted", tls ? (tls.authorized ? "Yes" : `No (${tls.authorizationError})`) : ""],
          ["Name matches", tls ? (tls.nameMatches ? "Yes" : "No") : ""],
          ["Expires", tls?.validTo ? `${new Date(tls.validTo).toLocaleDateString()} (${tls.daysRemaining} days)` : ""],
          ["Response time", result.durationMs ? `${result.durationMs} ms` : ""],
        ])}
        ${chips(result.capabilitiesAfterTls?.length ? result.capabilitiesAfterTls : result.capabilities || [])}
        ${renderMailIssues(result.issues)}
      </div>`;
  }).join("");
  const dkimRows = (data.dkim?.records || []).map((record) => `
    <tr>
      <td>${copyableResult(record.selector)}</td>
      <td>${escapeHtml(record.provider || "")}</td>
      <td>${escapeHtml(record.revoked ? "Revoked (empty key)" : `${record.keyType.toUpperCase()}${record.keyBits ? ` · ${record.keyBits} bits` : ""}`)}${record.testing ? " · test mode" : ""}</td>
      <td>${record.issues.length ? record.issues.map((issue) => `<span class="dnssec-issue ${escapeHtml(issue.severity)}">${escapeHtml(issue.message)}</span>`).join("<br>") : '<span class="dnssec-ok">Valid</span>'}</td>
    </tr>`);
  const providers = data.providers || { inbound: [], outbound: [], spfIncludes: [] };
  const allIssues = [
    ...(data.smtp || []).flatMap((result) => result.issues || []),
    ...(data.spf?.issues || []), ...(data.dmarc?.issues || []), ...(data.mtaSts?.issues || []),
    ...(data.dkim?.records || []).flatMap((record) => record.issues),
    ...(data.bimi?.issues || []),
  ];
  const serious = allIssues.filter((issue) => issue.severity === "high").length;
  const bimi = data.bimi || {};
  return `<div class="email-result">
    <div class="result-heading">
      <div><p class="eyebrow">EMAIL CHECK</p><h2>${copyableResult(data.domain)}</h2></div>
      <span class="status-badge ${serious ? "warning" : "success"}">${escapeHtml(serious ? `${serious} serious issue(s)` : allIssues.length ? `${allIssues.length} suggestion(s)` : "Looks good")}</span>
    </div>
    ${renderMailScorecard(data)}
    ${renderMailFixList([
      ["STARTTLS", (data.smtp || []).flatMap((result) => result.issues || [])],
      ["SPF", data.spf?.issues], ["DMARC", data.dmarc?.issues], ["DKIM", (data.dkim?.records || []).flatMap((record) => record.issues)],
      ["MTA-STS", data.mtaSts?.issues], ["TLS-RPT", data.tlsRpt?.issues], ["BIMI", bimi.issues],
    ])}
    <section class="email-auth">
      <h3>Email providers</h3>
      <div class="email-auth-grid">
        <div><h4>Receives mail (MX)</h4>${chips(providers.inbound) || '<p class="empty-result">No known provider; the domain may run its own mail server.</p>'}</div>
        <div><h4>Sends mail (SPF)</h4>${chips(providers.outbound) || '<p class="empty-result">No known sending service in SPF.</p>'}${providers.spfIncludes?.length ? `<p class="dnssec-summary">${escapeHtml(`SPF includes: ${providers.spfIncludes.join(", ")}`)}</p>` : ""}</div>
      </div>
    </section>
    <section class="email-auth" data-mail-section="mx">
      <h3>MX records <span class="email-auth-status ${data.mx?.records?.length ? "found" : "missing"}">${escapeHtml(data.mx?.nullMx ? "Null MX" : `${data.mx?.records?.length || 0} server(s)`)}</span></h3>
      ${data.mx?.nullMx ? '<p class="detail-notice">This domain publishes a null MX record: it explicitly does not accept email.</p>' : ""}
      ${data.mx?.implicit ? '<p class="detail-notice">No MX record. Senders fall back to the domain\'s own address (implicit MX), which is rarely intended.</p>' : ""}
      ${table(["Priority", "Server", "Addresses / reverse DNS", "Provider"], mxRows)}
    </section>
    <section class="email-auth" data-mail-section="smtp">
      <h3>SMTP and STARTTLS (port 25)</h3>
      ${smtpCards || '<p class="empty-result">No mail server could be tested.</p>'}
      <p class="scan-disclaimer">Connects to the first three MX servers on port 25, checks that STARTTLS is offered, upgrades to TLS and inspects the certificate. No mail is sent. Many cloud hosts block outbound port 25.</p>
    </section>
    <section class="email-auth">
      <h3>Authentication and transport policies</h3>
      ${renderMailSecurity({ dmarc: data.dmarc, spf: data.spf, mtaSts: data.mtaSts, tlsRpt: data.tlsRpt })}
    </section>
    <section class="email-auth" data-mail-section="dkim">
      <h3>DKIM <span class="email-auth-status ${dkimRows.length ? "found" : "missing"}">${escapeHtml(dkimRows.length ? `${dkimRows.length} key(s) found` : "No keys found")}</span></h3>
      ${table(["Selector", "Typical provider", "Key", "Validation"], dkimRows) || `<p class="empty-result">${escapeHtml(`No DKIM key was found for the ${data.dkim?.checked || 0} selectors checked. Add your provider's selector above.`)}</p>`}
    </section>
    <section class="email-auth" data-mail-section="bimi">
      <h3>BIMI ${renderBimiStatus(bimi)}</h3>
      ${bimi.error ? `<p class="detail-notice">${escapeHtml(bimi.error)}</p>` : bimi.found ? renderBimi(bimi) : '<p class="empty-result">No BIMI record (default._bimi). BIMI shows your logo in supporting inboxes once DMARC is enforced.</p>'}
    </section>
    <p class="scan-disclaimer">${escapeHtml(`Completed in ${data.durationMs} ms.`)}</p></div>`;
}

function renderEmailResult(data) {
  resultPanel.innerHTML = emailResultHtml(data);
  resultPanel.hidden = false;
}

function renderBimiStatus(bimi) {
  if (!bimi.found) return '<span class="email-auth-status missing">Not configured</span>';
  const serious = (bimi.issues || []).some((issue) => issue.severity === "high");
  const label = serious ? "Found · problems" : bimi.certificateCheck?.kind ? `Ready · ${bimi.certificateCheck.kind}` : "Found";
  return `<span class="email-auth-status ${serious ? "danger" : "found"}">${escapeHtml(label)}</span>`;
}

function renderBimi(bimi) {
  const logo = bimi.logoCheck;
  const certificate = bimi.certificateCheck;
  const yesNo = (value) => (value === null || value === undefined ? "" : value ? "Yes" : "No");
  return `
    <div class="email-auth-record"><span>${escapeHtml(bimi.record)}</span></div>
    <div class="bimi-result">
      ${logo?.preview ? `<img class="bimi-result-logo" src="${escapeHtml(logo.preview)}" alt="BIMI logo" width="96" height="96">` : ""}
      ${renderFacts([
        ["Logo (l=)", bimi.logo || "None"],
        ["Logo file", logo ? (logo.error ? `Not fetched: ${logo.error}` : `${(logo.bytes / 1024).toFixed(1)} KB · ${logo.contentType || "no content type"}`) : ""],
        ["DMARC enforced", yesNo(bimi.dmarcReady)],
        ["Mark certificate (a=)", bimi.certificate || "None"],
        ...(certificate && !certificate.error ? [
          ["Certificate type", certificate.kind ? `${certificate.kind}${certificate.markType ? ` (${certificate.markType})` : ""}` : "Unknown"],
          ["Organization", certificate.subject],
          ["Trademark", certificate.trademark],
          ["Issuer", certificate.issuer],
          ["Domains", (certificate.names || []).join(", ")],
          ["Expires", `${new Date(certificate.validTo).toLocaleDateString()} (${certificate.daysRemaining} days)`],
          ["Logo matches certificate", yesNo(certificate.embeddedLogoMatches)],
        ] : []),
      ])}
    </div>
    ${renderMailIssues(bimi.issues)}
    <p class="scan-disclaimer">Checks the default._bimi record, fetches the logo and mark certificate, validates the logo against SVG Tiny PS, compares it with the logo embedded in the certificate and checks that DMARC is enforced. The certificate chain is not checked against the BIMI root list.</p>`;
}

function renderPropagationResult(data) {
  const rows = data.results.map((result) => {
    const answers = result.answers.length
      ? result.answers.map((answer) => copyableResult(answer)).join("<br>")
      : `<span class="trace-silent">${escapeHtml(result.error || (result.status === "NOERROR" ? "No records" : result.status))}</span>`;
    const group = result.group === null ? "" : result.group === 0 ? "group-main" : `group-alt group-${Math.min(result.group, 4)}`;
    return `
      <tr class="${group}">
        <td>${escapeHtml(result.source)}<br><span class="trace-silent">${escapeHtml(result.kind === "authoritative" ? "Authoritative" : "Public resolver")}</span></td>
        <td>${escapeHtml(result.status)}</td>
        <td>${answers}</td>
        <td>${result.ttl === null ? "" : escapeHtml(`${result.ttl} s`)}</td>
        <td>${result.group === null ? "—" : result.group === 0 ? '<span class="dnssec-ok">Most common</span>' : `<span class="dnssec-bad">${escapeHtml(`Differs (variant ${result.group + 1})`)}</span>`}</td>
      </tr>`;
  }).join("");
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">DNS PROPAGATION</p><h2>${copyableResult(data.name)} ${escapeHtml(data.type)}</h2></div>
      <span class="status-badge ${data.consistent ? "success" : "warning"}">${data.consistent ? "Consistent" : escapeHtml(`${data.distinctAnswers} different answers`)}</span>
    </div>
    <div class="scan-summary">
      <span>${escapeHtml(`${data.answered} of ${data.results.length} sources answered`)}</span>
      <span>${escapeHtml(data.zone ? `Zone ${data.zone}` : "Zone not found")} · ${escapeHtml(`${data.durationMs} ms`)}</span>
    </div>
    <div class="dns-results-table-wrap"><table class="dns-results-table net-table propagation-table">
      <thead><tr><th>Source</th><th>Status</th><th>Answer</th><th>TTL</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table></div>
    <p class="scan-disclaimer">Public resolvers may serve cached answers until the old TTL expires; authoritative nameservers show what the zone publishes now. Authoritative servers on private addresses are not queried.</p>`;
  resultPanel.hidden = false;
}

function renderDigResult(data) {
  const ok = data.status === "NOERROR";
  const badge = data.timedOut
    ? '<span class="status-badge warning">Timed out</span>'
    : data.status
      ? `<span class="status-badge ${ok ? "success" : "warning"}">${escapeHtml(data.status)}</span>`
      : `<span class="status-badge ${data.exitCode === 0 ? "success" : "warning"}">${data.exitCode === 0 ? "Done" : "Failed"}</span>`;
  resultPanel.innerHTML = `
    <div class="result-heading">
      <div><p class="eyebrow">DIG</p><h2 class="dig-command">${copyableResult(data.command)}</h2></div>
      ${badge}
    </div>
    <div class="scan-summary">
      <span>${escapeHtml(data.serverAddress ? `Nameserver ${data.serverAddress}` : "Server's default resolver")}</span>
      <span>${escapeHtml(`${data.durationMs} ms`)}</span>
    </div>
    <div class="dig-output-wrap">
      <button class="dig-copy" type="button" data-copy-value="${escapeHtml(data.output)}">Copy output</button>
      <pre class="dig-output">${escapeHtml(data.output || "(no output)")}</pre>
    </div>
    ${data.truncated ? '<p class="detail-notice">The output was longer than 256 KB and was cut off.</p>' : ""}
    ${data.timedOut ? '<p class="detail-notice">dig did not finish within 30 seconds and was stopped.</p>' : ""}`;
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
    : data.locallyAdministered
      ? ""
      : '<p class="empty-result">No registered vendor was found for this MAC prefix. The address may be unregistered.</p>';

  const guess = data.deviceGuess;
  const confidenceLabels = { high: ["found", "High confidence"], medium: ["warning", "Medium confidence"], low: ["missing", "Low confidence"], none: ["missing", "No guess"] };
  const [confidenceClass, confidenceLabel] = confidenceLabels[guess?.confidence] || confidenceLabels.none;
  const deviceSection = guess ? `
    <section class="email-auth mac-device-guess">
      <h3>Likely device <span class="email-auth-status ${confidenceClass}">${escapeHtml(confidenceLabel)}</span></h3>
      <p class="mac-device-category">${escapeHtml(guess.category)}</p>
      ${guess.examples?.length ? `<div class="status-list">${guess.examples.map((example) => `<span>${escapeHtml(example)}</span>`).join("")}</div>` : ""}
      <p class="dnssec-summary">${escapeHtml(guess.basis || "")}</p>
      ${guess.notes?.length ? `<ul class="dnssec-issues">${guess.notes.map((note) => `<li class="dnssec-issue">${escapeHtml(note)}</li>`).join("")}</ul>` : ""}
      <p class="scan-disclaimer">An educated guess. A MAC prefix identifies the manufacturer, not the model, so an exact product such as "iPhone 14" cannot be determined from the address alone.</p>
    </section>` : "";
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
    ${deviceSection}
    ${vendorDetails}
    <p class="scan-disclaimer">Vendor information is retrieved from maclookup.app. The submitted MAC address is sent to that service.</p>`;
  resultPanel.hidden = false;
}

function renderDetail(label, value) {
  if (!value) return "";
  return `<div class="detail-row"><span>${escapeHtml(label)}</span><strong>${copyableResult(value)}</strong></div>`;
}

function registryLinkHtml(url) {
  if (!/^https?:\/\//i.test(String(url || ""))) return "";
  return ` <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">Registry website</a>`;
}

function registrationSourceLabel(registration) {
  return registration?.source === "whois" ? `WHOIS · ${registration.whoisServer || "port 43"}` : "RDAP";
}

function renderRawWhois(registration) {
  if (!registration?.rawWhois) return "";
  return `<details class="raw-whois"><summary>Raw WHOIS response from ${escapeHtml(registration.whoisServer || "the registry")}</summary><pre class="dig-output">${escapeHtml(registration.rawWhois)}</pre></details>`;
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
    ${data.registrationError ? `<p class="detail-notice">${escapeHtml(data.registrationError)}${registryLinkHtml(data.registryUrl)}</p>` : ""}
    ${registration ? `<section class="record-section">
      <h3>Registration <span>${escapeHtml(registrationSourceLabel(registration))}</span></h3>
      <div class="detail-list">
        ${renderDetail("Registrar", registrar?.organization || registrar?.name)}
        ${renderDetail("Registry handle", registration.handle)}
        ${formattedDates}
      </div>
      ${registration.statuses.length ? `<div class="status-list">${registration.statuses.map((status) => `<span>${escapeHtml(status)}</span>`).join("")}</div>` : ""}
      ${contactRows ? `<div class="contact-list">${contactRows}</div>` : ""}
      ${renderRawWhois(registration)}
    </section>` : ""}
    ${data.dnsNameserversError ? `<p class="detail-notice">${escapeHtml(data.dnsNameserversError)}</p>` : ""}
    ${dnsNameservers?.status && dnsNameservers.status !== "NOERROR" ? `<p class="detail-notice">Nameserver query status: ${escapeHtml(dnsNameservers.status)}</p>` : ""}
    ${dnsNameservers?.addressesIncomplete ? '<p class="detail-notice">Some nameserver IP address lookups could not be completed.</p>' : ""}
    ${(registration?.nameservers?.length || dnsNameservers?.records?.length) ? `<section class="record-section">
      <h3>Nameservers <span>${nameserverNames.size}</span></h3>
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
    ${data.registrationError ? `<p class="detail-notice">${escapeHtml(data.registrationError)}${registryLinkHtml(data.registryUrl)}</p>` : ""}
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

const hostInputModes = new Set(["scan", "forward", "reverse", "details", "sslscan", "ping", "traceroute", "nmap", "custom-port", "propagation"]);

function urlPortFromInput(value) {
  try {
    const text = String(value || "").trim();
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`).port || null;
  } catch {
    return null;
  }
}

// Reduces a pasted URL (scheme, credentials, port, path, query, fragment) to its host name or IP.
function hostFromInput(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text);
  if (!hasScheme && /^\[?[0-9a-f:.]+\]?$/i.test(text) && text.includes(":")) return text.replace(/^\[(.*)\]$/, "$1");
  try {
    const parsed = new URL(hasScheme ? text : `http://${text}`);
    if (parsed.hostname) return parsed.hostname.replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "").toLowerCase();
  } catch {
    return text;
  }
  return text;
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

modeSubtabs.addEventListener("click", (event) => {
  const button = event.target.closest(".email-subtab[data-mode]");
  if (!button) return;
  if (!featureAllowed(featureForMode(button.dataset.mode))) {
    errorMessage.textContent = "This tool is restricted by the administrator.";
    errorMessage.hidden = false;
    return;
  }
  setMode(button.dataset.mode);
});

tabs.forEach((tab) => tab.addEventListener("click", () => {
  if (tab === autoTab) {
    setMode("auto");
    return;
  }
  if (tab.dataset.group && groupAllowed(tab.dataset.group)) {
    if (groupOfMode(mode) !== tab.dataset.group) setMode(firstGroupMode(tab.dataset.group));
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
  if (pingMonitorActive) stopPingMonitor("Monitoring stopped because a new lookup was started.");
  pingMonitorPanel.hidden = true;
  let requestMode = mode;
  let lookupName = input.value.trim();
  if (hostInputModes.has(mode)) {
    const host = hostFromInput(lookupName);
    if (mode === "scan" && (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":"))) {
      errorMessage.textContent = "Magic scan works on domain names. For an IP address, use Auto lookup or Reverse lookup.";
      errorMessage.hidden = false;
      return;
    }
    formHint.dataset.defaultText ||= formHint.textContent;
    if (host && host !== lookupName) {
      const urlPort = mode === "sslscan" ? urlPortFromInput(lookupName) : null;
      if (urlPort) sslScanPort.value = urlPort;
      formHint.textContent = `Using ${host}${urlPort ? ` port ${urlPort}` : ""} from the URL you entered.`;
      input.value = host;
      lookupName = host;
    } else {
      formHint.textContent = formHint.dataset.defaultText;
    }
  }
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
  tlsGradeRun += 1;
  lastResult = null;
  viewingShare = false;
  updateShareResults();
  const customPortScan = requestMode === "custom-port";
  const bulkPortScan = requestMode === "bulk-port";
  const pingScan = requestMode === "ping-scan";
  const multiTraceroute = requestMode === "multi-traceroute";
  const nmapScan = requestMode === "nmap";
  const isPortScan = customPortScan || bulkPortScan;
  const postsJson = isPortScan || pingScan || multiTraceroute || nmapScan;
  if (toolModes.has(requestMode)) {
    submitButton.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>Working</span>';
    try {
      const { data, subject } = await runToolMode(requestMode, lookupName);
      rememberResult(requestMode, data, subject);
    } catch (error) {
      if (error.loginRequired) {
        window.location.assign(`/login.html?next=${encodeURIComponent(`${window.location.pathname}${window.location.search}`)}`);
        return;
      }
      errorMessage.textContent = error.message || "Unable to complete the request.";
      errorMessage.hidden = false;
    } finally {
      submitButton.disabled = false;
      submitButton.innerHTML = `<span>${submitLabel(mode)}</span><span aria-hidden="true">→</span>`;
    }
    return;
  }
  submitButton.innerHTML = `<span class="spinner" aria-hidden="true"></span><span>${requestMode === "scan" ? "Scanning" : isPortScan || nmapScan ? "Scanning ports" : requestMode === "sslscan" ? "Checking TLS" : pingScan ? "Pinging" : requestMode === "traceroute" || multiTraceroute ? "Tracing" : "Looking up"}</span>`;

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
  if (requestMode === "sslscan") params.set("port", sslScanPort.value.trim());
  if (requestMode === "dig") {
    [...params.keys()].forEach((key) => params.delete(key));
    params.set("command", lookupName);
  }
  if (requestMode === "asn") {
    [...params.keys()].forEach((key) => params.delete(key));
    params.set("name", lookupName);
  }
  if (requestMode === "email") {
    [...params.keys()].forEach((key) => params.delete(key));
    params.set("name", lookupName);
    params.set("selectors", dkimSelectorsInput.value.trim());
  }
  if (requestMode === "propagation") {
    const type = params.get("type");
    [...params.keys()].forEach((key) => params.delete(key));
    params.set("name", lookupName);
    params.set("type", type);
  }
  if (requestMode === "scan" && portScanInput.checked) {
    params.set("ports", "common");
  }

  try {
    if (requestMode === "traceroute" || multiTraceroute) {
      await streamTraceroute(multiTraceroute);
      return;
    }
    const endpoint = requestMode === "sslscan"
      ? "/api/sslscan"
      : customPortScan
      ? "/api/custom-port-scan"
      : bulkPortScan
        ? "/api/bulk-port-scan"
        : nmapScan
          ? "/api/nmap-scan"
        : requestMode === "details"
      ? "/api/domain-info"
        : pingScan
        ? "/api/ping-scan"
        : requestMode === "traceroute"
        ? "/api/traceroute"
        : multiTraceroute
        ? "/api/multi-traceroute"
        : requestMode === "ping"
        ? "/api/ping"
        : requestMode === "mac"
        ? "/api/mac-lookup"
        : requestMode === "dig"
        ? "/api/dig"
        : requestMode === "propagation"
        ? "/api/propagation"
        : requestMode === "email"
        ? "/api/email-check"
        : requestMode === "asn"
        ? "/api/asn"
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
        : nmapScan
          ? {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              target: input.value.trim(),
              scanType: nmapScanType.value,
            }),
          }
        : pingScan || multiTraceroute
          ? {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ targets: pingScan ? bulkTargetsInput.value : multiTraceInput.value }),
          }
          : {};
    if (nmapScan) startNmapStatusPolling();
    const response = await fetch(postsJson ? endpoint : `${endpoint}?${params}`, requestOptions);
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
    else if (requestMode === "sslscan") {
      renderSslScanResult(data);
      if (tlsGradeInput.checked && authState?.user) void runTlsGrade(data.target, data.port);
    }
    else if (pingScan) renderPingScanResult(data);
    else if (requestMode === "traceroute") renderTracerouteResult({ results: [data] }, false);
    else if (multiTraceroute) renderTracerouteResult(data, true);
    else if (nmapScan) {
      stopNmapStatusPolling();
      const elapsed = Number.isFinite(data.elapsedMs)
        ? ` in ${(data.elapsedMs / 1000).toFixed(1)}s`
        : "";
      setNmapLiveStatus(`Nmap scan complete${elapsed}.`);
      renderNmapResult(data);
    }
    else if (requestMode === "mac") renderMacResult(data);
    else if (requestMode === "dig") renderDigResult(data);
    else if (requestMode === "propagation") renderPropagationResult(data);
    else if (requestMode === "email") renderEmailResult(data);
    else if (requestMode === "asn") renderAsnResult(data);
    else if (requestMode === "scan") renderScanResult(data);
    else if (data.dnssecCheck) renderDnssecResult(data);
    else if (isPortScan) renderPortScanResult(data, customPortScan ? "Port scan" : "Bulk port scan");
    else {
      showResult(data);
      if (requestMode === "reverse") appendIpRegistration(lookupName.replace(/^\[|\]$/g, ""));
      if (mode === "auto" && (requestMode === "reverse" || requestMode === "forward")) {
        void appendBlocklistCheck(lookupName.replace(/^\[|\]$/g, ""));
      }
    }
    const shareMode = data.dnssecCheck ? "dnssec" : requestMode;
    const shareSubject = requestMode === "bulk-port" ? `port ${bulkPortInput.value} on ${bulkTargetsInput.value.trim().split(/\s+/).slice(0, 3).join(", ")}`
      : requestMode === "ping-scan" ? bulkTargetsInput.value.trim().split(/\s+/).slice(0, 3).join(", ")
      : requestMode === "custom-port" ? `${input.value.trim()} ports ${customPortsInput.value.trim()}`
      : requestMode === "forward" && !data.dnssecCheck ? `${lookupName} ${data.type || ""}`
      : lookupName;
    rememberResult(shareMode, data, shareSubject);
    if (requestMode === "scan") void appendScanIncludes(data.domain);
  } catch (error) {
    if (nmapScan) {
      stopNmapStatusPolling();
      setNmapLiveStatus("Nmap scan failed.");
    }
    errorMessage.textContent = error.message || "Unable to complete the lookup.";
    errorMessage.hidden = false;
  } finally {
    if (nmapScan) stopNmapStatusPolling();
    submitButton.disabled = false;
    submitButton.innerHTML = `<span>${submitLabel(mode)}</span><span aria-hidden="true">→</span>`;
  }
});

initializeAccount();
loadClientInfo();

function renderSharedResult(shareMode, payload) {
  const data = payload?.result;
  const extras = payload?.extras || {};
  if (!data || typeof data !== "object") throw new Error("This shared result is empty.");
  switch (shareMode) {
    case "forward":
    case "reverse": showResult(data); break;
    case "details": if (data.ip) renderIpInfo(data); else renderDomainInfo(data); break;
    case "mac": renderMacResult(data); break;
    case "dig": renderDigResult(data); break;
    case "propagation": renderPropagationResult(data); break;
    case "email": renderEmailResult(data); break;
    case "asn": renderAsnResult(data); break;
    case "ping": renderPingResult(data); break;
    case "sslscan": renderSslScanResult(data); break;
    case "ping-scan": renderPingScanResult(data); break;
    case "traceroute": renderTracerouteResult(data, false); break;
    case "multi-traceroute": renderTracerouteResult(data, true); break;
    case "scan": renderScanResult(data); break;
    case "custom-port": renderPortScanResult(data, "Port scan"); break;
    case "bulk-port": renderPortScanResult(data, "Bulk port scan"); break;
    case "nmap": renderNmapResult(data); break;
    case "dnssec": renderDnssecResult(data); break;
    case "web": renderWebCheckResult(data); break;
    case "email-headers": renderHeadersResult(data); break;
    case "dmarc-reports": renderDmarcReportResult(data); break;
    case "tlsrpt-reports": renderTlsRptResult(data); break;
    case "bulk-domains": renderBulkDomainsResult(data); break;
    case "dns-health": renderDnsHealthResult(data); break;
    case "mail-server": renderMailServerResult(data); break;
    case "subdomains": renderSubdomainsResult(data); break;
    case "ipv6": renderIpv6Result(data); break;
    case "reputation": renderReputationResult(data); break;
    case "lookalike": renderLookalikeResult(data); break;
    case "spf-flatten": renderSpfFlattenResult(data); break;
    case "ip-calc": renderIpCalcResult(data); break;
    default: throw new Error("This shared result type is not supported.");
  }
  if (extras.tlsGrade?.result) {
    insertTlsGradeSection();
    renderTlsGradeSection({ result: extras.tlsGrade.result, address: extras.tlsGrade.address });
  }
  if (extras.blocklist) resultPanel.insertAdjacentHTML("beforeend", renderBlocklistSection(extras.blocklist));
  if (extras.email) resultPanel.insertAdjacentHTML("beforeend", scanIncludeSection("email", emailResultHtml(extras.email)));
  if (extras.sslscan) resultPanel.insertAdjacentHTML("beforeend", scanIncludeSection("sslscan", sslScanResultHtml(extras.sslscan)));
  if (extras.web) resultPanel.insertAdjacentHTML("beforeend", scanIncludeSection("web", webCheckHtml(extras.web)));
  if (extras.dnsHealth) resultPanel.insertAdjacentHTML("beforeend", scanIncludeSection("dnsHealth", dnsHealthHtml(extras.dnsHealth)));
  updateShareResults();
}

async function loadHistoryEntry(id, rerun) {
  try {
    const response = await fetch(`/api/history/${encodeURIComponent(id)}`, { credentials: "same-origin" });
    const entry = await readApiResponse(response);
    if (!response.ok) throw new Error(entry.error || "This history entry could not be loaded.");
    const formMode = entry.mode === "dnssec" ? "forward" : entry.mode;
    if (rerun) {
      const tab = tabs.find((candidate) => candidate.dataset.mode === formMode && !candidate.hidden);
      if (!tab) throw new Error("You no longer have access to this tool.");
      setMode(formMode);
      const params = entry.params || {};
      input.value = entry.query || "";
      if (params.type) {
        const known = [...recordType.options].some((option) => option.value === params.type);
        recordType.value = known ? params.type : "custom";
        customType.value = known ? "" : params.type;
        customType.hidden = recordType.value !== "custom";
      }
      if (params.method) pingMethodInput.value = params.method;
      if (params.port) sslScanPort.value = params.port;
      if (typeof params.tlsGrade === "boolean") tlsGradeInput.checked = params.tlsGrade;
      if (typeof params.selectors === "string") dkimSelectorsInput.value = params.selectors;
      if (typeof params.ports === "string") customPortsInput.value = params.ports;
      if (typeof params.targets === "string") {
        bulkTargetsInput.value = params.targets;
        multiTraceInput.value = params.targets;
      }
      if (params.bulkPort) bulkPortInput.value = params.bulkPort;
      if (params.scanType) nmapScanType.value = params.scanType;
      if (typeof params.ptr === "boolean") tracePtrInput.checked = params.ptr;
      if (typeof params.scanPorts === "boolean") portScanInput.checked = params.scanPorts;
      if (typeof params.scanEmail === "boolean") scanEmailInput.checked = params.scanEmail;
      if (typeof params.scanSsl === "boolean") scanSslInput.checked = params.scanSsl;
      if (typeof params.scanTlsGrade === "boolean") scanTlsGradeInput.checked = params.scanTlsGrade;
      if (typeof params.scanWeb === "boolean") scanWebInput.checked = params.scanWeb;
      if (typeof params.scanDnsHealth === "boolean") scanDnsHealthInput.checked = params.scanDnsHealth;
      if (typeof params.domains === "string") bulkDomainsInput.value = params.domains;
      updateScanIncludes();
      history.replaceState(null, "", `/?mode=${encodeURIComponent(formMode)}`);
      form.requestSubmit();
      return;
    }
    if (!entry.hasResult) throw new Error("This result was too large to store. Use Re-run on the History page instead.");
    viewingShare = true;
    renderSharedResult(entry.mode, entry.data);
    const banner = document.createElement("div");
    banner.className = "share-banner";
    banner.innerHTML = `<strong>From your history</strong> ${escapeHtml(entry.title)}<span>${escapeHtml(`Saved ${new Date(entry.createdAt).toLocaleString()}`)}</span> <a href="/?rerun=${encodeURIComponent(entry.id)}">Run again</a>`;
    resultPanel.prepend(banner);
    resultPanel.hidden = false;
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
}

async function loadSharedResult(id) {
  viewingShare = true;
  try {
    const response = await fetch(`/api/shares/${encodeURIComponent(id)}`, { credentials: "same-origin" });
    const share = await readApiResponse(response);
    if (!response.ok) throw new Error(share.error || "This shared result could not be loaded.");
    renderSharedResult(share.mode, share.data);
    const banner = document.createElement("div");
    banner.className = "share-banner";
    banner.innerHTML = `<strong>Shared result</strong> ${escapeHtml(share.title)}<span>${escapeHtml(`Created ${new Date(share.createdAt).toLocaleString()} · link expires ${new Date(share.expiresAt).toLocaleDateString()}`)}</span>`;
    resultPanel.prepend(banner);
    resultPanel.hidden = false;
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  }
}

shareResultsButton.addEventListener("click", async () => {
  if (!lastResult) return;
  shareResultsButton.disabled = true;
  shareResultsStatus.textContent = "Creating link…";
  try {
    const response = await fetch("/api/shares", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(lastResult),
    });
    const data = await readApiResponse(response);
    if (!response.ok) throw new Error(data.error || "The share link could not be created.");
    shareResultsLink.value = new URL(data.url, window.location.origin).href;
    shareResultsLink.hidden = false;
    shareResultsLink.select();
    try {
      await navigator.clipboard.writeText(shareResultsLink.value);
      shareResultsStatus.textContent = `Copied. Anyone with the link can view it until ${new Date(data.expiresAt).toLocaleDateString()}.`;
    } catch {
      shareResultsStatus.textContent = `Anyone with the link can view it until ${new Date(data.expiresAt).toLocaleDateString()}.`;
    }
  } catch (error) {
    shareResultsStatus.textContent = error.message;
  } finally {
    shareResultsButton.disabled = false;
  }
});

function updateMailResults() {
  mailResults.hidden = !(authState?.user && authState.mailEnabled && !resultPanel.hidden);
  if (mailResults.hidden) mailResultsStatus.textContent = "";
}

new MutationObserver(updateMailResults).observe(resultPanel, { attributes: true, attributeFilter: ["hidden"] });
new MutationObserver(updateShareResults).observe(resultPanel, { attributes: true, attributeFilter: ["hidden"] });

mailResultsButton.addEventListener("click", async () => {
  if (!authState?.user?.email) {
    mailResultsStatus.textContent = "Add your email address on the My account page first.";
    return;
  }
  mailResultsButton.disabled = true;
  mailResultsStatus.textContent = "Sending…";
  try {
    const response = await fetch("/api/mail/results", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subject: `DNS lookup results: ${input.value.trim()}`.slice(0, 120),
        text: `${resultPanel.innerText}\n\nQuery: ${input.value.trim()}\n`,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "The email could not be sent.");
    mailResultsStatus.textContent = `Sent to ${authState.user.email}.`;
  } catch (error) {
    mailResultsStatus.textContent = error.message;
  } finally {
    mailResultsButton.disabled = false;
  }
});

document.querySelector("#print-result").addEventListener("click", () => {
  resultPanel.querySelectorAll("details").forEach((details) => { details.open = true; });
  window.print();
});
