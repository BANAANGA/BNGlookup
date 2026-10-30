# BNGlookup wiki

A short guide to every tool in BNGlookup: what it does, how it works, what it
checks, and what the result looks like. For installation and configuration, see
the main [README](../README.md).

> Screenshots were made with test domains such as `webtest.test` and sample
> data; your results will show your own domains.

## Start page

| Page | In one sentence |
| --- | --- |
| [Landing page](landing-page.md) | A simple start page that runs all public tools at once, with tabs per category. |

## DNS and domains

| Tool | In one sentence |
| --- | --- |
| [Auto lookup](auto-lookup.md) | Recognizes a domain, IP or MAC address and runs the right lookup. |
| [DNS lookup](dns-lookup.md) | Queries any record type through an encrypted DNS resolver. |
| [DNSSEC check](dnssec.md) | Checks whether a domain is signed and validates correctly. |
| [Reverse lookup](reverse-lookup.md) | Finds the host name and owner of an IP address. |
| [Whois](whois.md) | Shows who registered a domain or IP and when it expires. |
| [Dig](dig.md) | Runs a real `dig` command for raw DNS output. |
| [Propagation](propagation.md) | Shows whether a DNS change has reached the big resolvers. |
| [ASN](asn.md) | Shows which network announces an IP, and its other ranges. |
| [Magic scan](magic-scan.md) | One-click overview of a whole domain. |

## Email

| Tool | In one sentence |
| --- | --- |
| [Email check](email-check.md) | Reviews MX, STARTTLS, SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI. |
| [Header analyzer](header-analyzer.md) | Explains how a received message was delivered and authenticated. |
| [DMARC reports](dmarc-reports.md) | Summarizes DMARC aggregate reports in your browser. |
| [Record builder](record-builder.md) | Builds SPF, DMARC, MTA-STS, TLS-RPT and BIMI records. |
| [SPF flattener](spf-flattener.md) | Rewrites SPF as IP ranges to stay under 10 lookups. |

## Web and TLS

| Tool | In one sentence |
| --- | --- |
| [Web check](web-check.md) | Grades a site's HTTPS, redirects and security headers. |
| [SSLscan and TLS grade](sslscan.md) | Tests a server's TLS and grades it like SSL Labs. |
| [Website previews](website-previews.md) | Safe live views of sites, loaded through the server. |

## Security

| Tool | In one sentence |
| --- | --- |
| [DNS health](dns-health.md) | Checks name servers for delegation errors, open transfers and open recursion. |
| [Reputation](reputation.md) | Asks security services and threat lists whether a site is malicious. |
| [Lookalike domains](lookalike-domains.md) | Finds registered typo and look-alike domains. |
| [Blocklists](blocklists.md) | Checks spam and abuse blocklists. |
| [Subdomain takeover](subdomain-takeover.md) | Finds subdomains pointing to unclaimed cloud resources. |

## Network

| Tool | In one sentence |
| --- | --- |
| [Ping](ping.md) | Checks whether a host is up, with optional live monitoring. |
| [Traceroute](traceroute.md) | Shows the route to one or more hosts. |
| [Ping scan](ping-scan.md) | Pings every address in a list or network. |
| [Port scan](port-scan.md) | Checks which TCP ports are open on a host. |
| [Bulk port scan](bulk-port-scan.md) | Checks one port across many addresses. |
| [Nmap](nmap.md) | Bounded Nmap scans of an approved host. |
| [MAC lookup](mac-lookup.md) | Identifies the vendor and likely device of a MAC address. |
| [IP calculator](ip-calculator.md) | Subnet calculator for IPv4 and IPv6. |

## Productivity

| Tool | In one sentence |
| --- | --- |
| [Bulk check](bulk-check.md) | Checks up to 50 domains at once, with CSV export. |
| [Monitors](monitors.md) | Scheduled checks with email alerts. |
| [History](history.md) | View, re-run and compare your recent lookups. |
| [Share links](share-links.md) | Share a result with anyone for 30 days. |
| [Print and PDF](print.md) | Print a result or save it as a PDF. |

## Account and administration

| Page | In one sentence |
| --- | --- |
| [Two-factor login](two-factor.md) | Adds an authenticator code to your login. |
| [API tokens](api-tokens.md) | Use the tools from scripts. |
| [Dashboard](dashboard.md) | Server status, activity and insights for administrators. |

## Who can use what

Each tool can be set by an administrator to **Public**, **Logged-in users** or
**Administrators**. Each page lists its default. Scanning tools (Magic scan, port
scans, ping scan, multi traceroute, Nmap, bulk check) are for administrators by
default and always require a login. See
[Accounts and access](../README.md#accounts-and-access) in the README.
