# BNGlookup

[![Latest release](https://img.shields.io/github/v/release/BANAANGA/BNGlookup?sort=semver)](https://github.com/BANAANGA/BNGlookup/releases/latest)
[![Release and publish Docker image](https://github.com/BANAANGA/BNGlookup/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/BANAANGA/BNGlookup/actions/workflows/docker-publish.yml)
[![Container image](https://img.shields.io/badge/image-ghcr.io%2Fbanaanga%2Fbnglookup-2b7489)](https://github.com/BANAANGA/BNGlookup/pkgs/container/bnglookup)

**BNGlookup** is a self-hosted toolkit for DNS, email, web and network
diagnostics. It runs as a single, hardened Docker container: a Node.js server
with no npm dependencies, a SQLite database and a browser interface.

- **DNS and domains**: lookups, DNSSEC, WHOIS/RDAP, dig, propagation, ASN and a
  one-click *Magic scan* of a whole domain.
- **Email**: MX and SMTP/STARTTLS, SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI;
  a header analyzer, a DMARC report viewer, a record builder and an SPF flattener.
- **Web and TLS**: redirect chain, security headers, HTTP/2 and HTTP/3, a full TLS
  test graded A+ to F, and safe live previews of websites.
- **Security**: DNS health, reputation and blocklists, lookalike domains and
  subdomain takeover detection.
- **Network**: ping, traceroute, port scans, Nmap, MAC lookup and an IP calculator.
- **Operations**: monitors with email alerts, bulk checks, history, share links,
  API tokens, two-factor login and an admin dashboard.

## Contents

Each tool is explained in more detail, with a screenshot, in the **[wiki](docs/README.md)**.

1. [Screenshots](#screenshots)
2. [Quick start](#quick-start)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Tools](#tools)
6. [Accounts and access](#accounts-and-access)
7. [Administration](#administration)
8. [API](#api)
9. [Security](#security)
10. [Privacy and external services](#privacy-and-external-services)
11. [Updating and backups](#updating-and-backups)
12. [Releases](#releases)

## Screenshots

Log and statistics screenshots use illustrative sample data.

<table>
  <tr>
    <td align="center"><strong>Lookup tools</strong><br><img src="assets/dns-lookup.png" alt="BNGlookup home page with the lookup tool tabs" width="560"></td>
    <td align="center"><strong>First-run setup</strong><br><img src="assets/first-run-setup.png" alt="First-run setup page for creating the initial administrator account" width="560"></td>
  </tr>
  <tr>
    <td align="center"><strong>Login</strong><br><img src="assets/login.png" alt="BNGlookup account login page" width="560"></td>
    <td align="center"><strong>Settings and access</strong><br><img src="assets/admin-settings.png" alt="Administrator settings page for feature access, DNS resolver, trusted proxies, and port-scan policy" width="560"></td>
  </tr>
  <tr>
    <td align="center"><strong>Logs</strong><br><img src="assets/admin-logs.png" alt="Administrator application logs page with login, audit, and query log tabs" width="560"></td>
    <td align="center"><strong>Statistics</strong><br><img src="assets/admin-stats.png" alt="Administrator usage statistics page with visitor and query charts" width="560"></td>
  </tr>
</table>

## Quick start

Requires Docker Engine with Docker Compose v2.

```sh
mkdir -p ~/bnglookup && cd ~/bnglookup
curl -fsSLO https://raw.githubusercontent.com/BANAANGA/BNGlookup/main/compose.registry.yaml
docker compose -f compose.registry.yaml up -d
```

Open `http://<host>:3000` and create the administrator account. Until you have
done so, make sure only trusted people can reach the server, or set
[`SETUP_TOKEN`](#environment-variables) before the first start.

## Installation

### Pre-built image (recommended)

Every release publishes a multi-architecture (amd64/arm64) image to
`ghcr.io/banaanga/bnglookup`, tagged with the full version (`2.4.0`), the minor
version (`2.4`) and `latest`.

```sh
mkdir -p ~/bnglookup && cd ~/bnglookup
curl -fsSLO https://raw.githubusercontent.com/BANAANGA/BNGlookup/main/compose.registry.yaml
curl -fsSLO https://raw.githubusercontent.com/BANAANGA/BNGlookup/main/compose.acme.yaml

# HTTP on port 3000 only ...
sudo docker compose -f compose.registry.yaml up -d
# ... or with ports 80 and 443 for the built-in certificate client
sudo docker compose -f compose.registry.yaml -f compose.acme.yaml up -d
```

Put settings in a `.env` file next to the compose file (for example
`PORT=8080`, `BNGLOOKUP_TAG=2.4.0` to pin a version, `COOKIE_SECURE=true`), and
use the same `-f` options in every later command, or set
`COMPOSE_FILE=compose.registry.yaml:compose.acme.yaml` in `.env`.

Without Compose:

```sh
docker run -d --name bnglookup --restart unless-stopped \
  -p 3000:3000 -v bnglookup_data:/data ghcr.io/banaanga/bnglookup:latest
# add -p 80:3000 -p 443:8443 for the certificate client
```

If the package is private, run `docker login ghcr.io` first with a GitHub token
that has the `read:packages` scope.

### Build from source

```sh
git clone https://github.com/BANAANGA/BNGlookup.git
cd BNGlookup
docker compose up --build -d             # http://localhost:3000
PORT=8080 docker compose up --build -d   # another host port
docker compose logs -f                   # follow the logs
docker compose down                      # stop (keeps the data)
```

### Clean Ubuntu 24.04 server

Run as a user with `sudo` rights.

```sh
# 1. Docker Engine and the Compose plugin
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker

# 2. The project
git clone https://github.com/BANAANGA/BNGlookup.git
cd BNGlookup

# 3. Start: port 3000 only ...
sudo docker compose up --build -d
#    ... or with ports 80 and 443 for the certificate client
sudo docker compose -f compose.yaml -f compose.acme.yaml up --build -d

# 4. Optional: open the firewall if ufw is enabled
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp

# 5. Check
sudo docker compose ps
```

`compose.acme.yaml` publishes host port 80 (HTTP and the ACME challenge) and
443 (the app's HTTPS listener on container port 8443, which only answers once a
certificate has been issued). Both ports must be free on the host and allowed by
your firewall or cloud security group.

### Optional components

| Compose file | Purpose |
| --- | --- |
| `compose.acme.yaml` | Publishes ports 80 and 443 for the [built-in certificate client](#ssl-certificate-acme). |
| `compose.zmap.yaml` | Enables the [zmap engine](#port-scan-and-bulk-port-scan) for large IPv4 port scans. Adds `NET_RAW` and `NET_ADMIN` and removes `no-new-privileges`; use it only when you need zmap. |

Combine them with `-f`, for example
`docker compose -f compose.yaml -f compose.acme.yaml -f compose.zmap.yaml up --build -d`.

### Arcane

1. **Customization → Git Repositories**: add `https://github.com/BANAANGA/BNGlookup.git`.
2. **Projects → From Git Repo → Pull**: name the project, keep **Target Type** set
   to **Project** and choose **Create a new project**.
3. Select the repository, branch `main` and **Compose File Path** `compose.yaml`.
4. Enable **Sync Files** (the build needs the whole repository), and optionally
   **Redeploy After Sync**.
5. Click **Add Sync**, open the project and choose **Build & Deploy**.
6. Open `http://<arcane-host>:3000`. Set `PORT` in the project environment to
   change the host port.

### Without Docker

Requires Node.js 22 or newer. Some tools need system packages: `dig`
(bind-tools), `tracepath`, `nmap` and `testssl.sh`; the tools whose
binary is missing report an error.

```sh
node server.js                                              # http://localhost:3000
PORT=8080 DOH_ENDPOINT=https://example.net/dns-query node server.js
```

## Configuration

### First-run setup

On first start with an empty data volume, the site opens a one-time setup page
to create the administrator. Passwords need at least 12 characters. Set
`SETUP_TOKEN` beforehand if the server is reachable by others, so nobody else can
complete the setup.

All settings, accounts and logs are stored in SQLite at `/data/bnglookup.sqlite`
in the `app_data` volume.

### Environment variables

Set these in `.env` next to the compose file, or in front of the command.

**Server**

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Host port (Compose) or listening port (without Docker). |
| `HTTPS_PORT` | `8443` | Port of the built-in HTTPS listener. |
| `COOKIE_SECURE` | `false` | Mark session cookies `Secure`. Set to `true` behind an HTTPS reverse proxy. |
| `TRUSTED_PROXIES` | empty | Initial list of trusted reverse proxies (IPs or CIDRs). The admin setting takes over once saved. |
| `SETUP_TOKEN` | empty | Secret required to complete first-run setup. Ignored once an administrator exists. |
| `BNGLOOKUP_TAG` | `latest` | Image tag used by `compose.registry.yaml`. |

**DNS and lookups**

| Variable | Default | Purpose |
| --- | --- | --- |
| `DOH_ENDPOINT` | Cloudflare | Additional custom DNS-over-HTTPS endpoint, offered as a resolver choice. |
| `BLOCKLIST_RESOLVER` | system resolver | DNS server(s) for blocklist queries, e.g. `192.168.1.53` or `10.0.0.2:5353`, comma-separated. |
| `WHOIS_SERVERS` | empty | WHOIS servers for TLDs that publish none at IANA, e.g. `ga=whois.example.ga,xyz=whois.nic.xyz`. |
| `SMTP_TEST_HELO` | `bnglookup.localdomain` | EHLO name used by the Email check's SMTP test. |

**Threat intelligence** (optional, used by the [reputation check](#reputation))

| Variable | Purpose |
| --- | --- |
| `URLHAUS_AUTH_KEY` | Free abuse.ch Auth-Key ([auth.abuse.ch](https://auth.abuse.ch/), non-commercial use). Enables the URLhaus API lookup and downloads the official URLhaus host list; without it a public mirror of the list is used. |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key. |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Safe Browsing API key. |

**Website previews**

| Variable | Default | Purpose |
| --- | --- | --- |
| `PREVIEWS` | `true` | Set to `false` to turn website previews off. |

**zmap engine** (with `compose.zmap.yaml`)

| Variable | Purpose |
| --- | --- |
| `ZMAP_INTERFACE`, `ZMAP_GATEWAY_MAC`, `ZMAP_SOURCE_IP` | Set these if zmap cannot detect the network on its own. |

**Updates and build information**

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPDATE_CHECK` | `true` | Set to `false` to stop the dashboard from checking GitHub for new releases. |
| `APP_VERSION`, `APP_COMMIT`, `APP_BUILD_DATE` | `dev` | Build information on the dashboard; set by the release workflow. |

## Tools

See the **[wiki](docs/README.md)** for a page per tool with a screenshot and a
step-by-step explanation.

Each tool is a *feature* whose access an administrator can set to Public,
Logged-in users or Administrators (see [Accounts and access](#accounts-and-access)).
Every tool that connects to a user-supplied target refuses private and reserved
addresses unless the user's role allows local targets.

### Overview

| Area | Tools |
| --- | --- |
| DNS and domains | [Auto lookup](#auto-lookup) · [DNS lookup and DNSSEC](#dns-lookup-and-dnssec) · [Reverse lookup](#reverse-lookup) · [Whois](#whois) · [Dig](#dig) · [Propagation](#propagation) · [ASN](#asn) · [Magic scan](#magic-scan) |
| Email | [Email check](#email-check) · [Mail server check](#mail-server-check) · [Header analyzer](#header-analyzer) · [DMARC reports](#dmarc-reports) · [TLS reports](#tls-reports) · [Record builder](#record-builder) · [SPF flattener](#spf-flattener) |
| Web and TLS | [Web check](#web-check) · [SSLscan and TLS grade](#sslscan-and-tls-grade) · [Website previews](#website-previews) |
| Security | [DNS health](#dns-health) · [Reputation](#reputation) · [Lookalike domains](#lookalike-domains) · [Blocklists](#blocklists) · [Subdomain takeover](#subdomain-takeover) |
| Network | [Ping](#ping) · [Traceroute](#traceroute) · [Ping scan](#ping-scan) · [Port scan and Bulk port scan](#port-scan-and-bulk-port-scan) · [Nmap](#nmap) · [MAC lookup](#mac-lookup) · [IP calculator](#ip-calculator) |
| Productivity | [Bulk check](#bulk-check) · [Monitors](#monitors) · [History](#history) · [Share links](#share-links) · [Print and PDF](#print-and-pdf) |

All result tables are searchable and sortable; click any value to copy it.

### DNS and domains

#### Auto lookup

Detects whether the input is a domain or URL, an IPv4/IPv6 address or a MAC
address and runs the matching tool. For signed-in users, a blocklist check is
shown below domain and IP results.

#### DNS lookup and DNSSEC

Queries A, AAAA, ANY, CAA, CNAME, DNSKEY, DS, HTTPS, MX, NS, PTR, SOA, SRV, SSHFP,
SVCB, TLSA, TXT or any type by name or number through the selected
DNS-over-HTTPS resolver. `ANY` may return incomplete data.

Choose **DNSSEC** to run a validation check (also part of every Magic scan). It
queries DS, DNSKEY and SOA with the DO bit and reads the resolver's AD flag, and
reports **Secure**, **Not enabled**, **No chain of trust** (signed zone without a
DS record at the parent) or **Validation fails**. It lists DS records with their
matching DNSKEY key tags, the keys (KSK/ZSK) and signature validity, and warns
about deprecated algorithms, SHA-1 DS digests, mismatched DS records and
signatures that expire within 7 days.

Administrators can query a specific name server instead (UDP with TCP fallback),
by IP or host name with an optional port, such as `1.1.1.1:53` or
`[2606:4700:4700::1111]:53`. This also works in Reverse lookup and Magic scan.

#### Reverse lookup

PTR records for IPv4 and IPv6 addresses, with the address's registration (IP WHOIS).

#### Whois

Registration data through RDAP (`rdap.org`): registrar, dates, status, network
range, ASN and contacts, plus a comparison of the authoritative name servers.

- For registries without RDAP (many country-code TLDs such as `.nl`), classic
  WHOIS on TCP port 43 is used: the TLD's server is found through
  `whois.iana.org`, one registrar referral is followed and the raw response is
  shown. Subdomains fall back to their parent domain.
- Some registries (for example `.ga`) publish neither; the result says so and
  links the registry's website. `WHOIS_SERVERS` can point such a TLD at a server.
- Missing ASNs are resolved through RIPE Stat, with `ipwho.is` as fallback.
  Contacts are often redacted by the registry.

#### Dig

Runs the real `dig` binary (without a shell) for a single query:
`[@server] name [type] [class] [+options]`.

- Supported flags: `-t -c -q -x -p -4 -6 -u`, and an allowlist of options such as
  `+short`, `+dnssec`, `+trace`, `+tcp`, `+nsid`, `+subnet=` and `+noall +answer`.
- Limits: `+time` up to 10 s, `+tries` up to 3, 30 s overall and 256 KB of output.
  File, key and bind-address flags (`-f`, `-k`, `-y`, `-b`) are rejected.
- A private `@server` follows the role's local-network setting. Without
  `@server` the container's resolver is used.

#### Propagation

Queries one name and type through each built-in DoH resolver (Cloudflare,
Google, Quad9, DNS4EU, plus `DOH_ENDPOINT`) and directly at the zone's
authoritative name servers, groups identical answers and highlights resolvers
that differ. Name servers on private addresses are not queried.

#### ASN

For an IP, a domain or an AS number, shows the announcing prefix and origin AS,
the prefix's RPKI validity, the AS holder, and every IPv4 and IPv6 prefix the AS
announces (seen by at least three RIS peers, up to 3,000 per family, filterable).
Data comes from RIPE Stat and is cached for 10 minutes.

#### Magic scan

A broad scan of one domain:

- A, AAAA, CAA, CNAME, HTTPS, MX, NS, SOA, SRV and TXT for the domain, common
  subdomains (`www`, `mail`, `api`, `staging`, …) and cloud provider
  verification names (AWS/SES, Azure, Google Cloud, Cloudflare, Vercel, Netlify,
  Heroku, DigitalOcean, …).
- Up to 25 more subdomains from Certificate Transparency logs (`crt.sh`, falling
  back to CertSpotter).
- RDAP registration, DNSSEC, blocklists, [subdomain takeover](#subdomain-takeover),
  SPF (with lookup counting), common DKIM selectors, DMARC, MTA-STS, TLS-RPT,
  PTR records, geolocation and a [website preview](#website-previews).

Optional additions, run after the DNS scan and saved with the result:

- **Email check**, **SSLscan** of port 443 (optionally with the full TLS grade),
  **Web check** and **DNS health**. Each follows the access setting of its own tool.
- **Port check**: 26 common TCP ports (including 2222 and 8443) on up to 8 of the
  domain's addresses. It asks for confirmation, needs a login, and only reports
  ports that accept a connection; it is not a vulnerability assessment.

Results are not exhaustive: custom DKIM selectors and unlisted subdomains are not found.

### Email

#### Email check

Accepts a domain or an email address and reviews the whole mail setup:

- **MX servers** with addresses and reverse DNS, and the **email providers**
  recognized in MX hosts (receiving) and SPF includes (sending).
- **SMTP and STARTTLS**: connects to the first three MX servers on port 25, reads
  the banner, sends EHLO, upgrades to TLS and reports protocol, cipher,
  certificate trust, name match, expiry and capabilities. No mail is sent. Many
  cloud hosts block outbound port 25; the result then says so. Private MX
  addresses are only tested when the role allows local targets.
- **SPF**: follows `include` and `redirect`, counts DNS lookups against the
  RFC 7208 limit of 10, and flags multiple records, `+all`, `?all` and `ptr`.
- **DMARC**: missing record, `p=none`, `sp=none`, `pct` below 100, no `rua`.
- **DKIM**: common selectors plus up to five of your own, validating key type and
  size and flagging revoked and test-mode keys.
- **MTA-STS**: the TXT record, then the policy fetched over HTTPS from
  `mta-sts.<domain>` (mode, `max_age`, MX coverage). **TLS-RPT**: the reporting record.
- **BIMI**: reads `default._bimi`, fetches the logo (`l=`) and mark certificate
  (`a=`) over HTTPS (public addresses only, no redirects, 64/128 KB limits),
  validates the logo against SVG Tiny PS and shows it, reads the VMC/CMC (mark
  type, organization, trademark, issuer, domains, expiry), compares its embedded
  logo with `l=`, and checks that DMARC is enforced. The certificate chain is not
  checked against the BIMI root list.

Results open with a scorecard and a list of problems sorted by severity.

#### Mail server check

Connects to up to three of a domain's mail servers (MX) on port 25 and reports per
server:

- **Open relay**: a foreign sender and recipient are offered; a server that
  accepts the recipient relays mail for anyone. The session stops before `DATA`,
  so no message is ever sent.
- **STARTTLS**, the negotiated TLS version and the certificate (trusted, name,
  expiry).
- **Forward-confirmed reverse DNS**: the PTR name of the address must resolve back
  to it, which many receivers require.
- The host name in the greeting, **password login offered before encryption**,
  the message size limit, extensions (PIPELINING, SMTPUTF8, REQUIRETLS, …) and
  response times.

Many hosting providers block outbound port 25; the check then explains that it
could not run from this server.

#### Header analyzer

Paste the headers of a received message (up to 256 KB) to see:

- the delivery path, oldest hop first, with the delay between hops, whether each
  hop used TLS, and each sender's reverse DNS and location;
- the SPF, DKIM, DMARC and ARC results, DKIM signatures, and whether SPF and DKIM
  align with the From domain;
- Reply-To mismatches, List-Unsubscribe (one-click) and spam filter verdicts
  (SpamAssassin, Rspamd, Microsoft 365 SCL/BCL).

Headers are not stored unless you save or share the result.

#### DMARC reports

Select up to 50 aggregate (rua) reports as `.xml`, `.xml.gz` or `.zip`. They are
unpacked and parsed in your browser; only the sending IP addresses are sent to
the server, to look up their host names. The result shows message totals,
DMARC/DKIM/SPF pass rates, every sending source with its results and
disposition, the reporting organizations, and whether the domain is ready for a
stricter policy.

#### TLS reports

Select up to 50 SMTP TLS reports (TLS-RPT, RFC 8460) as `.json`, `.json.gz` or
`.zip`, as received at the `rua=` address of your `_smtp._tls` record. They are
read in your browser and never sent to the server. The result shows the share of
sessions that were encrypted and verified, the MTA-STS or DANE policy and mode,
every failure grouped by reason and receiving server (with an explanation of each
result type), and the reporters. It tells you when MTA-STS can move from
`testing` to `enforce`: only when no session failed.

#### Record builder

Forms that produce correct SPF (with common providers and a DNS lookup
estimate), DMARC, MTA-STS (TXT record and policy file), TLS-RPT and BIMI
records. *Load current records* fills the forms from a domain's DNS.
Administrators can also [host the MTA-STS policy](#hosted-mta-sts-policy) on this server.

#### SPF flattener

Resolves a domain's SPF record (`include`, `a`, `mx`, `redirect`) into `ip4`/`ip6`
ranges to get under the 10-lookup limit. It proposes a single record, or a main
record with `_spf1.`, `_spf2.` … includes when the result exceeds 255
characters. `ptr` and `exists` cannot be flattened and are kept. Flattened
records must be refreshed whenever a provider changes its addresses.
Uses the access setting of the record builder.

### Web and TLS

#### Web check

Accepts a domain or URL. A bare domain starts at `http://` to show the HTTPS
redirect. Redirects are followed one at a time (up to 10), and every new host
must resolve to an address the user's role may reach.

- Redirect chain, certificate trust and expiry, HTTP/2 (TLS ALPN) and HTTP/3
  (Alt-Svc), compression and response time.
- **Security header grade** (A+ to F) for HSTS, Content-Security-Policy,
  clickjacking protection, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy and software version disclosure, plus cookie flags (Secure,
  HttpOnly, SameSite).
- **Site files and content**: `/.well-known/security.txt` (Contact and Expires per
  RFC 9116), `robots.txt`, the sitemap, and mixed content (scripts, images,
  frames or stylesheets loaded over `http://` on an HTTPS page).

#### SSLscan and TLS grade

**SSLscan** performs one TLS handshake with a host and port (default 443) and
reports the negotiated protocol and cipher, the certificate chain, validity dates
and trust status.

Signed-in users can add the **full TLS test**, which runs the bundled
[testssl.sh](https://github.com/testssl/testssl.sh) (v3.2.4, GPLv2) against the
resolved address: SSLv2 to TLS 1.3, every cipher suite, key exchange, certificate
and chain, HSTS, and vulnerabilities such as Heartbleed, ROBOT, POODLE, CCS
injection, DROWN, Logjam and SWEET32. It grades with the SSL Labs
[SSL Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide)
(protocol 30 %, key exchange 30 %, cipher strength 40 %, plus the guide's caps:
A+ for HSTS, T for untrusted, M for name mismatch, F for critical issues).

- A test takes about one to three minutes and runs in the background.
- One test per user and two per server at a time; no third-party service is contacted.
- Grades can differ slightly from SSL Labs, which tests every address of a host
  and runs a few extra checks.

#### Website previews

A live view of the site appears in Web check (the final page), Magic scan (the
homepage), Reputation (the site) and Lookalike domains (thumbnails of up to 12
registered lookalikes). *Open larger* shows it in a new tab.

The server fetches the page and shows a cleaned copy in a sandboxed frame, so
you can look at suspicious sites without visiting them:

- The page is fetched like in Web check: public addresses only, every redirect checked.
- Scripts, event handlers, frames, embedded objects, forms and automatic
  redirects are removed, and links are shown but do not navigate.
- Images, stylesheets and fonts are loaded through an asset proxy that only serves
  addresses the server signed itself (valid for two hours), so the visitor's
  browser never contacts the site.
- The page is served with a sandboxing Content-Security-Policy and shown in a
  sandboxed frame without scripts, so it cannot reach this site or the visitor's session.

Sites that build their content with JavaScript may look empty or unstyled.
Previews require a login; each user can open 200 per hour. Set
`PREVIEWS=false` to turn them off.

### Security

#### DNS health

Checks a zone's name server setup by querying every name server directly
(up to 8, two addresses each) over UDP and TCP, without recursion:

- the delegation and glue records published by the parent zone, compared with
  the zone's own NS records;
- lame servers (silent or not authoritative), differing SOA serials and missing TCP support;
- **open recursion** (answering queries for other domains) and **zone transfers
  (AXFR) open to anyone**;
- fewer than two name servers, all name servers in one /24, missing IPv6 and
  unusual SOA timers.

Also available as a Magic scan option. Results are rated on the dashboard.

#### Reputation

Accepts a domain, URL or public IP and asks several independent sources whether
it is malicious:

- **Filtering resolvers**: Quad9, Cloudflare for Families, DNS4EU protective DNS
  and CleanBrowsing Security are compared with an unfiltered answer; a block
  means the service considers the domain malicious.
- **Threat lists**: Spamhaus DROP (hijacked and criminal networks), abuse.ch Feodo
  Tracker (botnet command-and-control servers), abuse.ch URLhaus (hosts serving
  malware; the official list with `URLHAUS_AUTH_KEY`, otherwise the
  [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) mirror) and
  OpenPhish (phishing sites). The lists are downloaded by the server
  on first use, refreshed every six hours and checked locally; the queried name is
  not sent to them. Parent domains are matched too.
- **Spam blocklists**, as in [Blocklists](#blocklists).
- **Optional services**: URLhaus, VirusTotal and Google Safe Browsing when their
  [API keys](#environment-variables) are set.

A clean result is not a guarantee. Palo Alto URL categories (such as grayware)
require a Palo Alto firewall or subscription and are not included.

#### Lookalike domains

Generates up to 260 variants of the registrable domain (homoglyphs such as
`0`/`o` and `rn`/`m`, missing, swapped, doubled and nearby-key letters, hyphens,
added words such as `-login`, bit flips and other TLDs), checks through DNS which
are registered, and lists them with their web and mail servers. Lookalikes with
mail servers come first, as they can send phishing mail. *Monitor this* creates a
Certificate Transparency monitor for your domain.

#### Blocklists

Runs in every Magic scan and below Auto lookup results for signed-in users.

- Domains: Spamhaus DBL, URIBL, SURBL and NordSpam DBL.
- Up to four public IPv4 addresses: Spamhaus ZEN, SpamCop, Barracuda, PSBL,
  UCEPROTECT L1, DroneBL, NiX Spam, Mailspike, GBUdb, Anonmails, WPBL and s5h.net,
  with the listing's reason. IPv6 is not checked.

Queries use the container's system resolver, because Spamhaus, URIBL and SURBL
refuse queries from large public resolvers; refusals are shown as **Refused**,
never as clean. For reliable Spamhaus results, set `BLOCKLIST_RESOLVER` to your
own recursive resolver (for example a local Unbound) or a Spamhaus DQS mirror.

#### Subdomain takeover

Part of every Magic scan. The CNAMEs of found hosts (up to 25) are checked for
targets that no longer exist (NXDOMAIN) and for services such as GitHub Pages,
Heroku, Azure, S3, Shopify, Fastly, Netlify and Zendesk that show their
"unclaimed" page. Findings are listed on the dashboard.

### Network

#### Ping

ICMP (four echo requests with loss and round-trip times) or an HTTP/HTTPS GET of
`/` (redirects are reported, not followed). Signed-in users can start **live
monitoring** of one host: a sample every 3 seconds for up to 5 minutes (100
samples), with a latency chart and optional sounds when the host goes up or down.

ICMP works with Docker's default settings; if your runtime disables unprivileged
ICMP, add `cap_add: [NET_RAW]` to the Compose service.

#### Traceroute

`tracepath` (UDP), up to 20 hops and 45 seconds, with live updates and optional
reverse DNS for every hop. **Multi traceroute** traces up to 10 targets (four at
a time) and compares the paths side by side. Silent routers appear as "no reply".

#### Ping scan

One echo request to every address in a list or CIDR block, up to 256 addresses.

#### Port scan and Bulk port scan

- **Port scan**: ports and ranges (`22,80,443,8000-8010`) on one target, up to 8
  resolved addresses. The maximum number of ports is set per role (default:
  Admin 100, User 25).
- **Bulk port scan**: one TCP port across a list or CIDR blocks. The largest
  accepted CIDR is configurable (default IPv4 /24, IPv6 /120) with a cap of 256
  addresses using TCP connect.
- **zmap engine** (opt-in with `compose.zmap.yaml`): IPv4 is SYN-scanned up to /16
  (65,536 addresses) at an administrator-set rate (default 10,000 packets/s,
  1,000–100,000), and only open hosts are listed. IPv6 still uses TCP connect. One
  zmap scan runs at a time. High rates can trigger your hosting provider's abuse detection.

Port scans always require a login. Private targets follow the role setting
(default: allowed for Admins, not for Users); other reserved addresses are always
skipped. Only scan systems you are authorized to test.

#### Nmap

Bounded scans of one IP or host name at a time: TCP connect on the top 20, 100 or
1000 ports, or light service detection on the top 20, with live status and
elapsed time. Targets must be in an administrator-approved CIDR or be the exact
address a user logged in from (added automatically as a /32 or /128 entry that
expires after 30 days). The allowlist holds up to 254 entries. Custom flags,
target lists and CIDR scans are not accepted; one scan runs at a time.

#### MAC lookup

Vendor, OUI block and address type from `maclookup.app`, plus a **likely
device** guess with a confidence level (for example Raspberry Pi, Espressif IoT,
Sonos, Ubiquiti, printers, NAS, virtual machines and containers). Multicast,
broadcast and randomized private addresses are recognized. A MAC prefix
identifies the manufacturer, not the exact model.

#### IP calculator

For an IPv4 address with prefix, netmask or wildcard (`10.1.2.3/22`,
`10.1.2.3 255.255.252.0`) or an IPv6 prefix: network, broadcast, host range,
counts, binary netmask, address type, reverse DNS zone and the subnets of a
chosen size (first 256). Calculated entirely in the browser.

### Productivity

#### Bulk check

Up to 50 domains (five at a time), each with MX and providers, SPF, DMARC, the
HTTPS certificate on port 443 and a blocklist check. One bulk check runs at a
time; *Export CSV* downloads the table. Administrators only by default, and
always requires a login.

#### Monitors

Scheduled checks with a change history and email alerts, on the **Monitors**
page (requires a login). Each user can create up to 25 monitors (administrators
100), checked every 1, 6, 12 or 24 hours:

| Type | Alerts when |
| --- | --- |
| Website up | The site stops answering, returns an error or redirects elsewhere. |
| Certificate | It expires within 14 days, becomes untrusted or is replaced. |
| DNS records | A, AAAA, CNAME, MX, NS, TXT or CAA records change. |
| Email security | MX, SPF, DMARC or the MTA-STS mode change, or SPF or DMARC break. |
| Blocklists | The domain or its address is listed or delisted. |
| New certificates (CT logs) | A new certificate for the domain or a subdomain appears in Certificate Transparency logs. |

The first check runs when a monitor is added. Alerts go to the account's email
address once [email](#email-delivery) is configured. *Monitor this* below DNS,
SSLscan, Email, Web check, Magic scan, DNS health, Reputation and Lookalike results opens the
Monitors page with the target filled in.

#### History

Each signed-in user's last 100 results from the past 30 days (results over
512 KB are kept for re-running only). View a stored result, run it again with the
same options, or compare two runs of the same tool field by field (timing fields
and answer order are ignored). History is private and deleted with the account.

#### Share links

*Create a share link* stores a result (as data, not HTML) for 30 days and
re-renders it for anyone with the link. Users manage their links on *My account*
and administrators can delete any link. Up to 200 links per user and 1 MB per
result. Links are unguessable but not password-protected.

#### Print and PDF

*Print / save as PDF* below every result prints only the result, in dark-on-white
with collapsed sections expanded. Choose *Save as PDF* in the print dialog.

## Accounts and access

### Roles and feature access

Users are **Admins** or **Users**. Administrators set each feature to
**Public**, **Logged-in users** or **Administrators**:

| Default access | Features |
| --- | --- |
| Logged-in users | DNS lookup, Reverse lookup, Whois, Dig, Propagation, ASN, MAC lookup, Ping, Traceroute, SSLscan, Email check and email tools, Web check, Website previews, DNS health, Reputation, Lookalike domains, IP calculator, Blocklists, Monitors, History, API tokens |
| Administrators | Magic scan, Ping scan, Multi traceroute, Port scan, Bulk port scan, Nmap, Bulk check |

- Ping scan, Multi traceroute, both port scans, Nmap and Bulk check need a login
  even when set to Public. Monitors, website previews and API tokens always need a login.
- Public features are limited per client IP per UTC day (15 by default; see
  [Public lookup limits](#public-lookup-limits)); signed-in users are exempt.
- New accounts and password resets by an administrator require a **password
  change at first login**; until then the session has no access to any feature.
- Users can be disabled (reversible) or removed. You cannot remove yourself or
  the last active administrator.

### Two-factor login

On **My account**, confirm your password, scan the QR code with an authenticator
app (Google or Microsoft Authenticator, 1Password, Aegis, …) and enter a code.
Ten one-time recovery codes are shown once.

- At login, a 6-digit code (or a recovery code) is required after the password.
  Codes are valid for one 30-second step either side and cannot be reused.
- Turning it off or creating new recovery codes requires the password and a code.
- Administrators can reset two-factor login for a user who lost their phone
  (**Admin → Users**).

### Passkeys

On **My account**, add a passkey (fingerprint, face, device PIN or a security key,
up to 10 per user) and sign in with **Sign in with a passkey** on the login page.
Passkeys need HTTPS (or `localhost`) and are tied to the site's host name.

- A passkey that verified you (PIN, fingerprint or face) replaces the two-factor
  code; otherwise the code is still asked.
- Passkeys are checked by the server without external libraries: challenge,
  origin, host name, user presence, signature and signature counter (a counter
  that goes backwards blocks a copied passkey).

### Single sign-on

**Admin → Single sign-on** connects an OpenID Connect provider (Microsoft Entra
ID, Google, Okta, Authentik, Keycloak, Authelia, …). Register BNGlookup there as
a web application with the redirect address shown in the tab
(`https://<your-site>/api/auth/oidc/callback`), then enter the issuer URL,
client ID and secret. A **Sign in with …** button appears on the login page.

- The authorization code flow with PKCE is used; the ID token's signature
  (RS256, PS256, ES256 or EdDSA), issuer, audience, expiry and nonce are checked.
- Sign-ins are matched to users by their provider identity. New users can be
  created automatically (optionally only for listed email domains, with a chosen
  role). Linking to existing users by verified email address is off by default:
  users enter their own address on My account, so only turn it on when you trust
  those addresses. It never links when two accounts share an address.
- Sign-ins through the provider skip BNGlookup's own two-factor code; use the
  provider's multi-factor login. The client secret is never shown again.

### API tokens

On **My account**, create up to 10 named tokens that expire after 30, 90 or 365
days, or never. See [API](#api) for usage.

### Email delivery

In **Admin → Email**, configure an SMTP server (STARTTLS, TLS or none, optional
login, sender) and send a test message. The SMTP password is stored in the data
volume and never displayed.

- Users add an address on **My account**; an **Email these results to me**
  button then appears below results (only to the user's own address, at most 10
  per hour).
- Monitor alerts are sent to the same address.

## Administration

### Dashboard

Live CPU, memory (the container's limit when set), storage, system load, activity
over 24 hours, top tools and the latest queries, refreshed every 3 seconds. It also
shows the running version, commit and build date, and a banner when a newer
release is available.

The **Insights** section (7, 30 or 90 days, refreshed every minute) shows:

- the **best and worst rated domains** for web security headers, TLS grade, email
  security and DNS health, with grade distributions and averages;
- monitors that are failing or warning, with change and alert counts;
- usage of the newer tools and subdomain takeover risks found by Magic scans.

Every Web check, TLS test, Email check and DNS health check stores the latest
rating per domain (kept for 180 days). Email security is scored as 100 minus 15
per serious, 6 per medium and 2 per minor finding.

### Logs and statistics

**Logs** list login attempts, administrative actions and lookup requests (the
latest 200 per tab are shown; up to 20,000 records are kept) and can be searched.
**Stats** summarize 7, 30 or 90 days of queries: visitors, failures, daily charts,
query types and the most frequent names. Treat the database and its backups as
sensitive.

### Settings

Settings are grouped in tabs under **Admin**:

| Tab | Settings |
| --- | --- |
| General | Site title and icon (upload PNG, JPEG, GIF, WebP or ICO up to 256 KB, or an HTTPS URL), the [BIMI logo](#bimi-logo), and the default DNS resolver: Google Public DNS, Cloudflare, Quad9 or DNS4EU ([protective](https://joindns4.eu/for-public), may filter malicious domains), plus `DOH_ENDPOINT`. |
| Access & network | Public, Logged-in users or Administrators per feature, the [trusted reverse proxies](#reverse-proxies-and-cloudflare) and the [public lookup limits](#public-lookup-limits). |
| Port scans | Maximum ports and local-network access per role, the largest bulk-scan CIDR, the zmap rate and the networks approved for Nmap. |
| SSL certificate | The [built-in certificate client](#ssl-certificate-acme). |
| Users | Create, edit, disable, remove users, reset passwords and two-factor login. |
| Email | The SMTP server for emailed results and monitor alerts, with a test message. |
| About page | Content of the public [About page](#about-page). |
| Landing page | Theme, texts and background of the public [landing page](#landing-page), with a live preview. |
| Site files | [robots.txt, security.txt, humans.txt](#site-files) and the change-password link. |
| Single sign-on | The [OpenID Connect provider](#single-sign-on). |
| Backup | [Download and restore](#backup-and-restore) a full backup. |

#### Reverse proxies and Cloudflare

Only connections from trusted proxies may supply client-IP headers, and the proxy
must overwrite those headers. For a Cloudflare-proxied origin, enable
**Automatically trust Cloudflare reverse proxy ranges**: the official IPv4 and
IPv6 ranges are downloaded over HTTPS, cached, and refreshed at startup and every
12 hours (the last good list is kept if a refresh fails). With Cloudflare Tunnel,
also add the address of the `cloudflared` connector, since connections come from
that connector rather than from Cloudflare's edge.

#### Public lookup limits

In **Admin → Access & network**, set how many public lookups each IP address may
make per UTC day (1–100,000; 15 by default), networks with **no limit** (one
address or CIDR per line) and **blocked networks**. Blocked networks cannot use
public lookups, or, if you choose, the whole site. A whole-site block that would
include your own address is refused, and the tab shows the address the server
sees for you.

#### Landing page

Visitors who are not logged in see a simple landing page at `/`: one search box
that runs every tool set to **Public** at once and shows the results in animated
tabs (Overview, DNS, Email, Web & TLS, Security, Network). A whole scan counts as
a single public lookup.

- Every warning has a **How to fix** explanation, often with a ready-made record,
  header or setting for the scanned domain and a Copy button.
- Every result card expands to its **full details** (with Copy JSON and a link to
  the same tool in the full interface).
- **Share link** stores the result at `/s/<id>` (30 days, or 7 days and 10 per
  day for visitors without an account); **Save as PDF** prints a clean report with
  all categories and fixes.
- **Compare with another domain** scans two domains side by side, highlights the
  better result per check and lets you open either full result (two lookups). A small *Log in* button leads to the full interface.
Logged-in users switch between the simple and the full interface with the
*Simple / Full* switch at the top right; the choice is remembered in their
browser, and the administrator chooses which one they start in.

**Admin → Landing page** customizes it with a live preview: theme presets, every
color, font, rounding, animations and frosted glass, a background (aurora,
gradient, solid or an uploaded PNG/JPEG/WebP/GIF up to 5 MB, with dimming and
blur), all texts and tab names, and the interface logged-in users start in. It
can also be turned off for visitors who are not logged in. See the
[wiki page](docs/landing-page.md).

#### Backup and restore

**Admin → Backup** downloads a `.tar.gz` with a consistent snapshot of the
database (users, settings, monitors, history, logs and statistics), the SSL
certificate and the landing page background. It contains password hashes,
two-factor secrets and keys, so store it safely.

Restoring checks the upload first (only the files a backup contains, an intact
BNGlookup database with at least one administrator), then restarts BNGlookup and
swaps the files in at startup. Everyone is logged out. The replaced data is kept
in `pre-restore-<time>/` in the data volume (the last three). With Docker the
container restarts by itself (`restart: unless-stopped`); without a process
manager, start BNGlookup again. Uploads are limited to 256 MB and must arrive
within the server's 30-second request timeout.

#### Site files

**Admin → Site files** publishes the standard files that crawlers, security
researchers and password managers look for. Each file is only served while it is
published, and is checked when you save.

| File | Served at | Notes |
| --- | --- | --- |
| robots.txt | `/robots.txt` | Templates to keep private pages out, allow everything or block all crawlers; unknown lines are flagged. |
| security.txt | `/.well-known/security.txt` and `/security.txt` | A form builds an RFC 9116 file. Publishing needs a valid Contact (`mailto:`, `https://` or `tel:`) and one future Expires; you are warned when it expires within 30 days or is set more than a year ahead. |
| humans.txt | `/humans.txt` | Free text. |
| Change-password link | `/.well-known/change-password` | Redirects to the account page so password managers can open it (on by default). |

The [hosted MTA-STS policy](#hosted-mta-sts-policy) is managed in the record
builder. See the [wiki page](docs/site-files.md).

#### About page

**Admin → About page** edits the public `/about` page (linked in the footer) with
a live preview. It supports a small Markdown subset (headings, emphasis, code,
links, lists, quotes, rules and code blocks). HTML is shown as text, and only
`http(s)`, `mailto:` and same-site links become links. Up to 20,000 characters;
*Reset to default* restores the built-in text.

#### BIMI logo

**Admin → General → BIMI logo** uploads an SVG that is served at
`https://<your-site>/logo.svg`, ready for a BIMI record such as
`default._bimi.example.com TXT "v=BIMI1; l=https://<your-site>/logo.svg;"`. The
site icon and header logo are not changed.

- Uploads with scripts, event handlers, links, embedded content, animation,
  entities or external references are rejected (64 KB limit), and the file is
  served with a sandboxed Content-Security-Policy.
- The logo is checked against BIMI's SVG Tiny Portable/Secure profile
  (`version="1.2" baseProfile="tiny-ps"`, a `<title>`, a square `viewBox`, no
  `<style>`, at most 32 KB), and problems are listed as warnings.
- Mailbox providers also require DMARC at `p=quarantine` or `p=reject`, and some a
  Verified Mark Certificate.

#### Hosted MTA-STS policy

In the record builder, administrators can save the MTA-STS policy on the server.
It is then served at `/.well-known/mta-sts.txt`, so pointing `mta-sts.<domain>`
at BNGlookup (with a valid certificate for that name) is enough to publish it.

### SSL certificate (ACME)

The built-in client obtains a Let's Encrypt certificate with ACME (RFC 8555) and
the HTTP-01 challenge, under **Admin → SSL certificate**:

1. Point one or more public DNS names at the Docker host.
2. Publish ports 80 and 443 (`-f compose.acme.yaml`). Behind a reverse proxy,
   forward `/.well-known/acme-challenge/` to the app.
3. Enter the domains (one per line, up to 20, one shared certificate) and a
   contact email, accept the CA's terms and save. Try **Staging** first, then
   **Production**.
4. Click **Request certificate now**; progress is shown live.

The HTTPS listener reloads automatically when a certificate is issued, and the
certificate is renewed when fewer than 30 days remain. The certificate and keys
are stored with restrictive permissions in `/data/acme`. HTTPS responses include
HSTS and secure cookies.

## API

The interface is built on a JSON API under `/api/`. Scripts can use it with an
**API token** (see [Accounts and access](#api-tokens)):

```sh
TOKEN=bngl_...
curl -H "Authorization: Bearer $TOKEN" "https://lookup.example.com/api/lookup?name=example.com&type=MX"
curl -H "Authorization: Bearer $TOKEN" "https://lookup.example.com/api/email-check?name=example.com"
curl -H "Authorization: Bearer $TOKEN" "https://lookup.example.com/api/monitors"
```

- Tokens have the access rights of their account and can call the lookup tools
  and the Monitors API. They cannot reach account, history, sharing or admin
  endpoints.
- Each token is limited to 600 requests per hour. Tokens are stored only as
  hashes, revoked immediately when deleted, and their requests are logged under
  the account.
- Streaming endpoints: `GET /api/traceroute?name=…&stream=1` and
  `POST /api/multi-traceroute` with `"stream": true` return newline-delimited JSON
  events (add `ptr=1` for per-hop reverse DNS). The full TLS test is started with
  `POST /api/tls-grade` and polled with `GET /api/tls-grade?id=…`.

## Security

**Application**

- All input is validated on the server (size, duplicates, control characters,
  strict UTF-8). SQL is parameterized, output is HTML-escaped, and a strict
  Content-Security-Policy and security headers are sent.
- External programs (dig, nmap, zmap, tracepath, ping, testssl.sh) are
  started without a shell and with fixed argument lists.
- Tools that connect to a user-chosen target resolve it once, refuse private,
  reserved and loopback addresses (including IPv4-mapped, NAT64, 6to4 and
  IPv4-compatible IPv6 forms) unless the role allows local targets, and pin the
  connection to the checked address to prevent DNS rebinding. Website previews
  are cleaned of active content and shown in a sandbox with an opaque origin.
- Only an explicit list of static files is served. Expensive jobs are capped
  server-wide, and connections, header sizes and request timeouts are bounded.

**Accounts and sessions**

- Passwords are stored as salted scrypt hashes. Sessions use `HttpOnly`,
  `SameSite=Strict` cookies and expire after 12 hours. Two-factor login,
  [passkeys](#passkeys) and [single sign-on](#single-sign-on) are available.
- Logins are limited per client IP (10 per 15 minutes) and per account (30
  failures per 15 minutes from any number of IPs), with identical responses for
  unknown usernames.
- State-changing requests must come from the site itself (Origin check); API
  tokens are exempt because they carry no cookies. The post-login redirect only
  accepts same-site paths.

**Container**

- The Compose files run the container as a non-root user with a read-only root
  filesystem (only `/data` and `/tmp` are writable), all Linux capabilities
  dropped, `no-new-privileges`, PID and memory limits and a health check
  (`/healthz`). The app shuts down gracefully on `SIGTERM`.
- `compose.zmap.yaml` relaxes this (adds `NET_RAW` and `NET_ADMIN`, removes
  `no-new-privileges`); use it only when you need zmap.
- The HTTPS listener supports TLS 1.2 and 1.3 with forward-secret AEAD cipher
  suites only.

**Deployment**

- Use HTTPS (set `COOKIE_SECURE=true` behind a proxy) and network-level access
  controls; do not expose the service on an untrusted network without them.
- Behind a reverse proxy, configure [trusted proxies](#reverse-proxies-and-cloudflare)
  so client addresses and rate limits are correct.

## Privacy and external services

BNGlookup sends data to third parties only to perform the requested check:

| Data | Recipient |
| --- | --- |
| Queried names and record types | The selected DoH resolver (also for Propagation, Lookalike domains, the SPF flattener and DMARC report sources) |
| Visitor IP (landing page reverse DNS and registration) | DoH resolver, `rdap.org` |
| Domains and IPs for Whois | `rdap.org`, `ipwho.is` (ASN fallback), RIPE Stat; `whois.iana.org` and the registry's WHOIS server on TCP port 43 when RDAP is unavailable |
| Public IPs in results | `ipwho.is` (geolocation); private IPs are never sent |
| Domains in Magic scan and CT monitors | `crt.sh`, CertSpotter on failure |
| Names and IPs for blocklists | The blocklist operators, through `BLOCKLIST_RESOLVER` or the system resolver |
| Domains for Reputation | Quad9, Cloudflare for Families, DNS4EU and CleanBrowsing; URLhaus, VirusTotal and Google Safe Browsing only when their keys are set |
| Threat lists | Downloaded from Spamhaus, abuse.ch and OpenPhish; queried names are not sent |
| AS numbers and prefixes | RIPE Stat |
| MAC addresses | `maclookup.app` |
| Target sites and mail servers | Contacted by the server for Web check, SSLscan, the TLS test, website previews (the page and its images, styles and fonts), the Email check (port 25) and BIMI/MTA-STS fetches |
| Update check | The GitHub API, at most every 6 hours while an administrator views the dashboard (`UPDATE_CHECK=false` turns it off) |
| Cloudflare IP ranges | Downloaded from Cloudflare when automatic trust is enabled |

Outbound access needed for full functionality: HTTPS (443), DNS (53) for
`dig @server` and blocklists, WHOIS (43) and SMTP (25).

## Updating and backups

Accounts, settings, logs, certificates and caches live in the `app_data` volume
and survive updates.

**Pre-built image**

```sh
sudo docker compose -f compose.registry.yaml pull
sudo docker compose -f compose.registry.yaml up -d
sudo docker image prune -f
# roll back: BNGLOOKUP_TAG=2.3.0 sudo -E docker compose -f compose.registry.yaml up -d
```

**Built from source**

```sh
cd ~/BNGlookup
git pull
sudo docker compose -f compose.yaml -f compose.acme.yaml up --build -d   # omit -f if not using 80/443
sudo docker image prune -f
sudo docker compose logs --tail 50
```

To run a specific release, `git fetch --tags && git checkout v2.4.0` and rebuild;
`git checkout main && git pull` returns to the latest code.

**Backup**

The simplest way is **Admin → Backup** ([Backup and restore](#backup-and-restore)).
From the command line:

```sh
# the volume is named <folder>_app_data; check with: sudo docker volume ls
sudo docker run --rm -v bnglookup_app_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/bnglookup-data-$(date +%F).tar.gz -C /data .
```

| Command | Effect |
| --- | --- |
| `sudo docker compose restart` | Restart without rebuilding |
| `sudo docker compose down` | Stop and remove the container (keeps the data) |
| `sudo docker compose down -v` | Stop **and delete all data** (irreversible) |

## Releases

Releases are created by pushing a version tag from `main`:

```sh
git checkout main && git pull
git tag v2.4.0 && git push origin v2.4.0
```

The *Release and publish Docker image* workflow checks that the tag has the form
`v1.2.3`, creates the GitHub release with generated notes (an existing release
is kept as written) and publishes the image as `2.4.0`, `2.4` and `latest`.
Publishing a release in the GitHub interface with a new tag does the same. Tags
that do not match `v1.2.3` (for example `v.2.1.1` or `v2.3`) fail without
creating a release or an image; delete the tag and push a correct one.
