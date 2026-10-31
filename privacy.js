// Privacy check: which third parties a page loads straight from its HTML, which cookies the
// server sets before the visitor could consent, and whether a consent banner is present.
// Scripts are not run, so trackers that other scripts add later (for example through a tag
// manager) are not seen; the result says so.

// [pattern for the host, name, category]
const knownThirdParties = [
  [/(^|\.)google-analytics\.com$|(^|\.)analytics\.google\.com$/, "Google Analytics", "analytics"],
  [/(^|\.)googletagmanager\.com$/, "Google Tag Manager", "tag-manager"],
  [/(^|\.)doubleclick\.net$|(^|\.)googleadservices\.com$|(^|\.)googlesyndication\.com$|(^|\.)adservice\.google\.[a-z.]+$/, "Google Ads", "advertising"],
  [/(^|\.)fonts\.googleapis\.com$|(^|\.)fonts\.gstatic\.com$/, "Google Fonts", "fonts"],
  [/(^|\.)maps\.googleapis\.com$|(^|\.)maps\.google\.[a-z.]+$/, "Google Maps", "embed"],
  [/(^|\.)recaptcha\.net$|(^|\.)www\.google\.com$|(^|\.)gstatic\.com$/, "Google (reCAPTCHA / static)", "embed"],
  [/(^|\.)youtube\.com$|(^|\.)youtube-nocookie\.com$|(^|\.)ytimg\.com$/, "YouTube", "embed"],
  [/(^|\.)connect\.facebook\.net$/, "Meta Pixel", "advertising"],
  [/(^|\.)facebook\.net$|(^|\.)facebook\.com$|(^|\.)fbcdn\.net$/, "Meta (Facebook)", "advertising"],
  [/(^|\.)instagram\.com$|(^|\.)cdninstagram\.com$/, "Instagram", "social"],
  [/(^|\.)twitter\.com$|(^|\.)x\.com$|(^|\.)twimg\.com$|(^|\.)ads-twitter\.com$/, "X (Twitter)", "social"],
  [/(^|\.)linkedin\.com$|(^|\.)licdn\.com$/, "LinkedIn", "advertising"],
  [/(^|\.)tiktok\.com$|(^|\.)tiktokcdn\.com$/, "TikTok", "advertising"],
  [/(^|\.)pinterest\.com$|(^|\.)pinimg\.com$/, "Pinterest", "advertising"],
  [/(^|\.)snapchat\.com$|(^|\.)sc-static\.net$/, "Snapchat", "advertising"],
  [/(^|\.)bing\.com$|(^|\.)clarity\.ms$/, "Microsoft (Bing / Clarity)", "analytics"],
  [/(^|\.)hotjar\.com$|(^|\.)hotjar\.io$/, "Hotjar", "session-replay"],
  [/(^|\.)fullstory\.com$/, "FullStory", "session-replay"],
  [/(^|\.)mouseflow\.com$/, "Mouseflow", "session-replay"],
  [/(^|\.)smartlook\.com$/, "Smartlook", "session-replay"],
  [/(^|\.)luckyorange\.com$/, "Lucky Orange", "session-replay"],
  [/(^|\.)crazyegg\.com$/, "Crazy Egg", "session-replay"],
  [/(^|\.)segment\.(com|io)$/, "Segment", "analytics"],
  [/(^|\.)mixpanel\.com$/, "Mixpanel", "analytics"],
  [/(^|\.)amplitude\.com$/, "Amplitude", "analytics"],
  [/(^|\.)heap(analytics)?\.(com|io)$/, "Heap", "analytics"],
  [/(^|\.)matomo\.cloud$|(^|\.)innocraft\.cloud$/, "Matomo Cloud", "analytics"],
  [/(^|\.)plausible\.io$/, "Plausible", "privacy-friendly-analytics"],
  [/(^|\.)usefathom\.com$/, "Fathom", "privacy-friendly-analytics"],
  [/(^|\.)simpleanalyticscdn\.com$|(^|\.)simpleanalytics\.com$/, "Simple Analytics", "privacy-friendly-analytics"],
  [/(^|\.)hubspot\.com$|(^|\.)hs-scripts\.com$|(^|\.)hs-analytics\.net$|(^|\.)hsforms\.net$/, "HubSpot", "analytics"],
  [/(^|\.)intercom\.io$|(^|\.)intercomcdn\.com$/, "Intercom", "chat"],
  [/(^|\.)zdassets\.com$|(^|\.)zendesk\.com$/, "Zendesk", "chat"],
  [/(^|\.)tawk\.to$/, "tawk.to", "chat"],
  [/(^|\.)criteo\.(com|net)$/, "Criteo", "advertising"],
  [/(^|\.)taboola\.com$/, "Taboola", "advertising"],
  [/(^|\.)outbrain\.com$/, "Outbrain", "advertising"],
  [/(^|\.)adnxs\.com$/, "Xandr (AppNexus)", "advertising"],
  [/(^|\.)amazon-adsystem\.com$/, "Amazon Ads", "advertising"],
  [/(^|\.)quantserve\.com$|(^|\.)quantcount\.com$/, "Quantcast", "advertising"],
  [/(^|\.)scorecardresearch\.com$/, "Comscore", "advertising"],
  [/(^|\.)cloudflareinsights\.com$/, "Cloudflare Web Analytics", "privacy-friendly-analytics"],
  [/(^|\.)cookiebot\.com$|(^|\.)cookiebot\.eu$/, "Cookiebot", "consent"],
  [/(^|\.)cookielaw\.org$|(^|\.)onetrust\.com$/, "OneTrust", "consent"],
  [/(^|\.)usercentrics\.(eu|com)$/, "Usercentrics", "consent"],
  [/(^|\.)didomi\.io$/, "Didomi", "consent"],
  [/(^|\.)iubenda\.com$/, "iubenda", "consent"],
  [/(^|\.)cookieyes\.com$/, "CookieYes", "consent"],
  [/(^|\.)consensu\.org$|(^|\.)quantcast\.mgr\.consensu\.org$/, "IAB consent framework", "consent"],
  [/(^|\.)osano\.com$/, "Osano", "consent"],
  [/(^|\.)trustarc\.com$/, "TrustArc", "consent"],
  [/(^|\.)termly\.io$/, "Termly", "consent"],
  [/(^|\.)cdn\.jsdelivr\.net$|(^|\.)unpkg\.com$|(^|\.)cdnjs\.cloudflare\.com$|(^|\.)code\.jquery\.com$|(^|\.)ajax\.googleapis\.com$|(^|\.)bootstrapcdn\.com$/, "Public CDN", "cdn"],
  [/(^|\.)use\.typekit\.net$|(^|\.)typekit\.net$/, "Adobe Fonts", "fonts"],
  [/(^|\.)vimeo\.com$|(^|\.)vimeocdn\.com$/, "Vimeo", "embed"],
];

// Inline snippets that reveal a tracker even when its script comes from elsewhere.
const inlineSignatures = [
  [/gtag\(\s*['"]config['"]\s*,\s*['"](G-|UA-)/, "Google Analytics", "analytics"],
  [/GTM-[A-Z0-9]{4,}/, "Google Tag Manager", "tag-manager"],
  [/fbq\(\s*['"]init['"]/, "Meta Pixel", "advertising"],
  [/_paq\.push|matomo\.js|piwik\.js/, "Matomo", "analytics"],
  [/hj\(\s*['"]|_hjSettings/, "Hotjar", "session-replay"],
  [/clarity\(\s*['"]|www\.clarity\.ms/, "Microsoft Clarity", "session-replay"],
  [/ttq\.load|analytics\.tiktok\.com/, "TikTok Pixel", "advertising"],
  [/_linkedin_partner_id/, "LinkedIn Insight", "advertising"],
  [/twq\(\s*['"]init/, "X (Twitter) Pixel", "advertising"],
  [/pintrk\(\s*['"]load/, "Pinterest Tag", "advertising"],
];

// Cookie names that identify trackers: [pattern, what it is]
const trackingCookies = [
  [/^_ga(_[A-Z0-9]+)?$|^_gid$|^_gat/, "Google Analytics"],
  [/^_gcl_/, "Google Ads"],
  [/^_fbp$|^_fbc$/, "Meta Pixel"],
  [/^_hj/, "Hotjar"],
  [/^_clck$|^_clsk$|^MUID$/, "Microsoft Clarity / Bing"],
  [/^__utm[a-z]$/, "Google Analytics (legacy)"],
  [/^_pk_(id|ses)/, "Matomo"],
  [/^hubspotutk$|^__hs/, "HubSpot"],
  [/^_tt_|^_ttp$/, "TikTok"],
  [/^li_|^bcookie$|^lidc$/, "LinkedIn"],
  [/^IDE$|^test_cookie$|^NID$/, "Google advertising"],
  [/^mp_.*_mixpanel$/, "Mixpanel"],
  [/^ajs_(user|anonymous)_id$/, "Segment"],
];

const trackingCategories = new Set(["analytics", "advertising", "session-replay", "social"]);
const categoryLabels = {
  analytics: "Analytics", advertising: "Advertising", "session-replay": "Session recording", social: "Social media",
  "tag-manager": "Tag manager", fonts: "Web fonts", embed: "Embedded content", chat: "Chat", consent: "Consent banner",
  cdn: "Content delivery", "privacy-friendly-analytics": "Privacy-friendly analytics", other: "Other third party",
};

function attribute(tag, name) {
  const match = tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return match ? (match[2] ?? match[3] ?? match[4] ?? "") : null;
}

function resourceUrls(html, pageUrl) {
  const found = [];
  const add = (raw, kind, tag) => {
    if (!raw || /^(data|javascript|mailto|tel|blob):/i.test(raw.trim())) return;
    try {
      const url = new URL(raw.trim().replace(/&amp;/g, "&"), pageUrl);
      if (!["http:", "https:"].includes(url.protocol)) return;
      // Scripts that only run after consent: type="text/plain" with a consent attribute.
      const gated = kind === "script" && tag && (/type\s*=\s*["']?text\/plain/i.test(tag) || /data-(cookieconsent|cookiecategory|category|consent|usercentrics|cookieyes)/i.test(tag));
      found.push({ url, kind, gated });
    } catch {
      // Ignore addresses that are not valid URLs.
    }
  };
  for (const match of html.matchAll(/<script\b[^>]*>/gi)) add(attribute(match[0], "src") ?? attribute(match[0], "data-src"), "script", match[0]);
  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    const rel = (attribute(match[0], "rel") || "").toLowerCase();
    if (/stylesheet|preconnect|dns-prefetch|preload|icon|font/.test(rel)) add(attribute(match[0], "href"), rel.includes("stylesheet") ? "stylesheet" : "link", match[0]);
  }
  for (const match of html.matchAll(/<(img|iframe|source|video|audio|embed)\b[^>]*>/gi)) {
    add(attribute(match[0], "src") ?? attribute(match[0], "data-src"), match[1].toLowerCase() === "iframe" ? "frame" : "media", match[0]);
  }
  for (const match of html.matchAll(/url\(\s*['"]?(https?:\/\/[^'")\s]+)/gi)) add(match[1], "style", null);
  for (const match of html.matchAll(/@import\s+(?:url\()?\s*['"](https?:\/\/[^'"]+)/gi)) add(match[1], "stylesheet", null);
  return found;
}

function parseSetCookie(header, pageHost) {
  const [pair, ...rest] = String(header).split(";");
  const name = pair.split("=")[0].trim();
  const attributes = Object.fromEntries(rest.map((part) => {
    const [key, ...value] = part.split("=");
    return [key.trim().toLowerCase(), value.join("=").trim()];
  }));
  let lifetimeDays = null;
  if (attributes["max-age"] && /^-?\d+$/.test(attributes["max-age"])) lifetimeDays = Math.round(Number(attributes["max-age"]) / 86400);
  else if (attributes.expires && !Number.isNaN(Date.parse(attributes.expires))) lifetimeDays = Math.round((Date.parse(attributes.expires) - Date.now()) / 86400000);
  const tracker = trackingCookies.find(([pattern]) => pattern.test(name));
  return {
    name: name.slice(0, 80),
    domain: (attributes.domain || pageHost).replace(/^\./, "").slice(0, 120),
    secure: Object.hasOwn(attributes, "secure"),
    httpOnly: Object.hasOwn(attributes, "httponly"),
    sameSite: attributes.samesite || null,
    session: lifetimeDays === null,
    lifetimeDays,
    tracker: tracker ? tracker[1] : null,
  };
}

// html: the final page; setCookies: every Set-Cookie header seen while loading it; pageUrl: final URL;
// siteDomain: the registrable domain of the site (third parties are other registrable domains).
function analyzePrivacy({ html, setCookies, pageUrl, siteDomain, organizationalDomain, headers }) {
  const pageHost = new URL(pageUrl).hostname;
  const resources = resourceUrls(html, pageUrl);
  const parties = new Map();
  for (const resource of resources) {
    const host = resource.url.hostname.toLowerCase();
    const registrable = organizationalDomain(host);
    if (registrable === siteDomain) continue;
    // gtag.js is served from the tag manager's domain but is Google Analytics itself.
    const known = /(^|\.)googletagmanager\.com$/.test(host) && resource.url.pathname.startsWith("/gtag/")
      ? [null, "Google Analytics", "analytics"]
      : knownThirdParties.find(([pattern]) => pattern.test(host));
    const key = known ? known[1] : registrable;
    const entry = parties.get(key) || { name: key, category: known ? known[2] : "other", hosts: new Set(), kinds: new Set(), gated: true, requests: 0 };
    entry.hosts.add(host);
    entry.kinds.add(resource.kind);
    entry.requests += 1;
    if (!resource.gated) entry.gated = false;
    parties.set(key, entry);
  }
  const inline = html.replace(/<script\b[^>]*\bsrc\s*=[^>]*>/gi, "");
  for (const [pattern, name, category] of inlineSignatures) {
    if (!pattern.test(inline) || parties.has(name)) continue;
    // Ignore snippets inside scripts that only run after consent.
    const gatedOnly = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
      .filter((match) => pattern.test(match[2]))
      .every((match) => /type\s*=\s*["']?text\/plain/i.test(match[1]) || /data-(cookieconsent|cookiecategory|category|consent)/i.test(match[1]));
    parties.set(name, { name, category, hosts: new Set(["(inline code)"]), kinds: new Set(["inline"]), gated: gatedOnly, requests: 0 });
  }
  const thirdParties = [...parties.values()].map((entry) => ({
    ...entry, hosts: [...entry.hosts].slice(0, 6), kinds: [...entry.kinds], categoryLabel: categoryLabels[entry.category] || entry.category,
    tracking: trackingCategories.has(entry.category),
  })).sort((left, right) => Number(right.tracking) - Number(left.tracking) || left.name.localeCompare(right.name));

  const cookies = [...new Map(setCookies.map((header) => parseSetCookie(header, pageHost)).map((cookie) => [`${cookie.domain}|${cookie.name}`, cookie])).values()];
  const consent = thirdParties.filter((party) => party.category === "consent").map((party) => party.name);
  if (!consent.length && /cookieconsent|cookie-consent|cookie_consent|cookie-banner|cookiebanner|cmp-banner|gdpr-banner|klaro|complianz|borlabs/i.test(html)) consent.push("Consent banner (recognised from the page)");
  const privacyLink = /<a\b[^>]*href=["'][^"']*(privacy|privacybeleid|privacyverklaring|datenschutz|confidentialite|cookie)[^"']*["']/i.test(html)
    || /<a\b[^>]*>[^<]*(privacy|privacybeleid|datenschutz|cookiebeleid|cookie policy)[^<]*<\/a>/i.test(html);

  const issues = [];
  const ungatedTrackers = thirdParties.filter((party) => party.tracking && !party.gated);
  for (const party of ungatedTrackers) {
    issues.push({ severity: party.category === "advertising" || party.category === "session-replay" ? "high" : "medium",
      message: `${party.name} (${party.categoryLabel.toLowerCase()}) is loaded straight away, before a visitor can give consent.` });
  }
  for (const cookie of cookies.filter((item) => item.tracker)) {
    issues.push({ severity: "high", message: `The server sets the ${cookie.tracker} cookie "${cookie.name}" before a visitor can give consent.` });
  }
  if (thirdParties.some((party) => party.name === "Google Fonts" && !party.gated)) {
    issues.push({ severity: "medium", message: "Google Fonts are loaded from Google's servers, which sends each visitor's IP address to Google; host the fonts yourself instead." });
  }
  if (thirdParties.some((party) => party.category === "tag-manager" && !party.gated)) {
    issues.push({ severity: "low", message: "A tag manager is used: it can add more trackers when the page runs, which this check cannot see." });
  }
  if (thirdParties.some((party) => party.name === "YouTube" && !party.gated && party.hosts.some((host) => /(^|\.)youtube\.com$/.test(host)) && party.kinds.includes("frame"))) {
    issues.push({ severity: "low", message: "YouTube videos are embedded from youtube.com, which sets Google cookies; youtube-nocookie.com does not until the video is played." });
  }
  if (ungatedTrackers.length && !consent.length) issues.push({ severity: "medium", message: "Trackers are used, but no consent banner was recognised." });
  if (!privacyLink) issues.push({ severity: "low", message: "No link to a privacy or cookie policy was found on the page." });
  const longCookies = cookies.filter((cookie) => cookie.lifetimeDays !== null && cookie.lifetimeDays > 395);
  if (longCookies.length) issues.push({ severity: "low", message: `${longCookies.length} cookie(s) last longer than 13 months (${longCookies.map((cookie) => cookie.name).slice(0, 4).join(", ")}).` });
  const insecureCookies = cookies.filter((cookie) => !cookie.secure && pageUrl.startsWith("https:"));
  if (insecureCookies.length) issues.push({ severity: "low", message: `${insecureCookies.length} cookie(s) lack the Secure flag (${insecureCookies.map((cookie) => cookie.name).slice(0, 4).join(", ")}).` });
  if (!headers["referrer-policy"]) issues.push({ severity: "low", message: "No Referrer-Policy header: other sites see the full address of pages your visitors come from." });

  const penalty = { high: 15, medium: 8, low: 2 };
  const score = Math.max(0, 100 - issues.reduce((sum, issue) => sum + penalty[issue.severity], 0));
  return {
    thirdParties,
    thirdPartyDomains: new Set(thirdParties.flatMap((party) => party.hosts)).size,
    trackers: thirdParties.filter((party) => party.tracking).length,
    cookies,
    consent,
    privacyLink,
    issues,
    score,
  };
}

module.exports = { analyzePrivacy };
