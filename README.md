# BNGlookup

A lightweight, self-hosted DNS and network lookup web interface, packaged as a
small Docker container with no application dependencies.

## Contents

[Features](#features) · [Screenshots](#screenshots) · [Install](#install) ·
[Update](#update) · [Tools](#tools) · [Accounts and access](#accounts-and-access) ·
[Admin settings](#admin-settings) · [SSL certificate (ACME)](#ssl-certificate-acme) ·
[Security](#security-and-privacy) · [Other deployments](#other-deployments)

## Features

**Lookup tools** (one tabbed header on every page, plus a search bar below it)

- **Auto lookup**: detects domains/URLs, IPv4/IPv6 and MAC addresses and picks the right tool.
- **DNS lookup**: A, AAAA, ANY, CAA, CNAME, DNSKEY, DS, HTTPS, MX, NS, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, or any type by name/number, plus a **DNSSEC** validation check.
- **Reverse lookup**: PTR records for IPv4/IPv6, with IP WHOIS data.
- **Whois**: RDAP registration data for domains and IPs (registrar, dates, status, network range, ASN, contacts) and a nameserver comparison.
- **Dig**: run a custom `dig` command (`[@server] name [type] [class] +options`) and see the raw output.
- **MAC lookup**: vendor, OUI block and address type.
- **Ping**: ICMP (4 echo requests) or HTTP/HTTPS GET check; optional live single-host monitoring at 3-second intervals, with latency chart and optional up/down sounds.
- **SSLscan**: one TLS handshake with a remote host; reports the negotiated protocol and cipher, certificate chain, validity dates and trust status, plus an optional full TLS test with an SSL Labs-style A+–F grade.
- **Ping scan**: one echo request to every host in a list or CIDR block.
- **Traceroute / Multi traceroute**: live router path to one host, or up to 10 hosts compared side by side, with optional PTR (reverse DNS) lookup for every hop.
- **Magic scan**: domain and subdomain records, cloud endpoints, RDAP, DNSSEC, SPF, DKIM, certificate-transparency names, geolocation, optional port check.
- **Port scan / Bulk port scan**: custom TCP ports on one target, or one port across many addresses.
- **Nmap**: bounded TCP profiles for one authorized target at a time, with live status and elapsed time.

**Administration**

- First-run setup, user roles, per-feature access (public / users / admins), daily public quota.
- Remove (permanently delete) or disable users; optional email addresses and **email results to yourself** through a configurable SMTP server.
- Live **Dashboard** (CPU, memory, storage, load, activity, top tools, latest queries; refreshes every 3 s).
- Stats, Logs and Admin tabs; searchable, sortable, click-to-copy result tables.
- Selectable DNS-over-HTTPS resolver, per-query nameserver, trusted proxies, port-scan limits.
- Custom site title and icon.
- Built-in ACME (Let's Encrypt) client with multiple domains and auto-renew.

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

## Install

Requires Docker Engine and Docker Compose v2.

```sh
git clone https://github.com/BANAANGA/BNGlookup.git
cd BNGlookup
docker compose up --build -d          # http://localhost:3000
PORT=8080 docker compose up --build -d   # or choose another host port
docker compose logs -f                # view logs
docker compose down                   # stop (keeps data)
```

Create the administrator on the first visit. Make sure only trusted people can
reach the server until you have done so.

### Clean Ubuntu 24.04 minimal install

Run as a user with `sudo` rights.

```sh
# 1. Docker Engine + Compose plugin
sudo apt-get update
sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker

# 2. Get the project
git clone https://github.com/BANAANGA/BNGlookup.git
cd BNGlookup

# 3a. Port 3000 only (HTTP) ...
sudo docker compose up --build -d
# 3b. ... OR ports 80 and 443 mapped (needed for the ACME certificate)
sudo docker compose -f compose.yaml -f compose.acme.yaml up --build -d

# 4. Optional: open the firewall if ufw is enabled
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp

# 5. Check
sudo docker compose ps
```

Use 3a **or** 3b. Option 3b publishes host port 80 (HTTP and ACME challenge)
and 443 (the app's HTTPS listener on container port 8443, which only answers
after a certificate is issued). Ports 80 and 443 must be free on the host and
allowed by your firewall or cloud security group.

### Deploy from the container registry

Each release publishes a multi-arch (amd64/arm64) image to
`ghcr.io/banaanga/bnglookup` (tags `latest`, `1.2.69`, `1.2`), so no clone or
build is needed. On a clean Ubuntu 24.04 host, first install Docker (step 1 of
the section above), then:

```sh
mkdir -p ~/bnglookup && cd ~/bnglookup
curl -fsSLO https://raw.githubusercontent.com/BANAANGA/BNGlookup/main/compose.registry.yaml
curl -fsSLO https://raw.githubusercontent.com/BANAANGA/BNGlookup/main/compose.acme.yaml

# Port 3000 only (HTTP) ...
sudo docker compose -f compose.registry.yaml up -d
# ... OR ports 80 and 443 mapped (needed for the ACME certificate)
sudo docker compose -f compose.registry.yaml -f compose.acme.yaml up -d

sudo docker compose -f compose.registry.yaml ps
```

Optional settings go in front of the command or in a `.env` file next to the
compose file: `PORT=8080`, `BNGLOOKUP_TAG=1.2.69` (pin a version),
`COOKIE_SECURE=true`, `TRUSTED_PROXIES=…`, `DOH_ENDPOINT=…`. Include the same
`-f` flags in every later command (or set `COMPOSE_FILE=compose.registry.yaml:compose.acme.yaml`).

Update or roll back by pulling a newer tag:

```sh
sudo docker compose -f compose.registry.yaml pull
sudo docker compose -f compose.registry.yaml up -d
sudo docker image prune -f
# roll back: BNGLOOKUP_TAG=1.2.68 sudo -E docker compose -f compose.registry.yaml up -d
```

Without Compose:

```sh
docker run -d --name bnglookup --restart unless-stopped \
  -p 3000:3000 -v bnglookup_data:/data ghcr.io/banaanga/bnglookup:latest
# add -p 80:3000 -p 443:8443 for the ACME client
```

If the package is private, run `docker login ghcr.io` with a GitHub token that
has `read:packages` first. Data lives in the `app_data` volume, as with a local
build, so back it up the same way (see Update below).

## Update

The admin **Dashboard** shows the running version, commit and build date, and
checks GitHub for the latest release. When a newer release exists it shows a
banner linking to the release notes.

Accounts, settings, logs and certificates live in the `app_data` volume and
survive updates. Use the same compose files you started with.

```sh
cd ~/BNGlookup
# optional backup (volume name is <folder>_app_data; check with `sudo docker volume ls`)
sudo docker run --rm -v bnglookup_app_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/bnglookup-data-$(date +%F).tar.gz -C /data .

git pull
sudo docker compose -f compose.yaml -f compose.acme.yaml up --build -d   # omit -f flags if not using 80/443
sudo docker image prune -f
sudo docker compose logs --tail 50
```

To pin a release: `git fetch --tags && git checkout v1.1`, then rebuild. To roll
back, check out the previous tag or commit and rebuild; `git checkout main && git pull`
returns to the latest code.

| Command | Effect |
| --- | --- |
| `sudo docker compose restart` | Restart without rebuilding |
| `sudo docker compose down` | Stop and remove the container (keeps data) |
| `sudo docker compose down -v` | Stop **and delete all data** (irreversible) |

## Tools

Several tools send data to external services; these are listed under
[Security and privacy](#security-and-privacy).

| Tool | Limits and defaults |
| --- | --- |
| DNS lookup | Common types or any type by name/code. `ANY` may return incomplete data. Choose **DNSSEC** for a validation check (see below). |
| Reverse lookup | IPv4/IPv6 PTR; shows IP WHOIS. |
| Whois | RDAP via `rdap.org`; missing ASNs are resolved through RIPE Stat, with `ipwho.is` as fallback. Contacts may be redacted. |
| Dig | Runs the real `dig` binary (no shell) with one query: `@server`, name, type, class, `-t -c -q -x -p -4 -6 -u`, and an allowlist of `+options` (`+short`, `+dnssec`, `+trace`, `+tcp`, `+nsid`, `+subnet=`, `+noall +answer`, …). `+time` ≤ 10 s, `+tries` ≤ 3, 30 s overall limit, 256 KB output. File, key and bind-address flags (`-f`, `-k`, `-y`, `-b`) are rejected. A private `@server` follows the role's local-network setting; without `@server` the container's resolver is used. |
| MAC lookup | Vendor data from `maclookup.app`. |
| Ping | ICMP: 4 echo requests with loss and RTT. HTTP/HTTPS: one GET to `/` (redirects reported, not followed). |
| SSLscan | One TLS handshake to a host and port (default 443); reports the negotiated TLS protocol, cipher, peer certificate chain and certificate verification result. Signed-in users can also run a full testssl.sh test (protocols, ciphers, certificate, vulnerabilities) graded with the SSL Labs rating guide. |
| Ping scan | One echo per host; list or CIDR, max 256 addresses. |
| Traceroute | `tracepath` (UDP), up to 20 hops, 45 s limit; live updates. Optional per-hop PTR lookup via the default DoH provider. |
| Multi traceroute | Up to 10 targets, 4 at a time; hop comparison table. |
| Magic scan | Default tab. See below. |
| Port scan | Ports and ranges (`22,80,443,8000-8010`) on one target; max ports per role (default Admin 100, User 25); up to 8 resolved IPs. |
| Bulk port scan | One TCP port across a list or CIDR blocks; largest CIDR prefix is admin-configurable (default IPv4 /24, IPv6 /120). TCP connect by default, capped at 256 addresses. With the optional zmap engine, IPv4 is SYN-scanned up to /16 (65,536 addresses) at an admin-set rate and only open hosts are listed; IPv6 still uses TCP connect (max 256). |
| Nmap | One IP or hostname within an administrator-approved CIDR or an exact IP observed at successful login (automatic entries expire after 30 days); TCP top 20/100/1000 or light TCP service detection. Live status includes elapsed time. No arbitrary flags or range scans. |

**Notes**

- **Nameserver override**: in DNS lookup, Reverse lookup and Magic scan, admins can
  query a specific server (UDP with TCP fallback) by IP or hostname, with an
  optional port: `1.1.1.1:53` or `[2606:4700:4700::1111]:53`. Other users use the
  default DoH resolver.
- **Ping and traceroute**: private and reserved addresses are refused unless
  local-network access is enabled for your role. ICMP works with Docker's default
  settings; if your runtime disables unprivileged ICMP, add `cap_add: [NET_RAW]`
  to the Compose service. Traceroute needs no extra privileges (the image installs
  `iputils-tracepath` and `coreutils`); silent routers appear as "no reply".
- **SSLscan**: checks one host and port at a time and is subject to the same
  private/reserved-address policy as other host checks. The basic check is one
  TLS handshake; tick the full-test option to enumerate protocols and ciphers
  and test for vulnerabilities.
- **TLS test and grade**: runs the bundled [testssl.sh](https://github.com/testssl/testssl.sh)
  (v3.2.4, GPLv2) inside the container against the resolved address: SSLv2–TLS 1.3,
  every cipher suite, key exchange, certificate and chain, HSTS, and
  vulnerabilities (Heartbleed, ROBOT, POODLE, CCS injection, DROWN, Logjam,
  SWEET32 and more). It grades with the SSL Labs
  [SSL Server Rating Guide](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide):
  protocol 30%, key exchange 30% and cipher strength 40%, plus the guide's caps
  (A+ for HSTS, T for untrusted, M for name mismatch, F for critical issues).
  A test takes about 1–3 minutes and runs as a background job
  (`POST /api/tls-grade`, then poll `GET /api/tls-grade?id=…`). Signed-in users
  only; one test per user and two server-wide at a time; no third-party API is
  contacted. Grades can differ slightly from SSL Labs, which tests every IP
  address of a host and runs some additional checks.
- **Live traceroute API**: `GET /api/traceroute?name=…&stream=1` and
  `POST /api/multi-traceroute` with `"stream": true` return newline-delimited JSON events.
  Add `ptr=1` (or `"ptr": true`) to resolve each hop's PTR record; results arrive as
  `{"type":"ptr","address":…,"names":[…]}` events.
- **Live Nmap status**: the authenticated UI polls `GET /api/nmap-status` for
  scan state and elapsed time; status is scoped to the signed-in user.
- **DNSSEC check** (DNS lookup type *DNSSEC* and every Magic scan) queries DS, DNSKEY and
  SOA with the EDNS DO bit through the configured DoH resolver and reads its AD
  (validated) flag. It reports **Secure**, **Not enabled**, **No chain of trust**
  (signed zone without a DS record at the parent) or **Validation fails** (the
  resolver returns SERVFAIL unless checking is disabled), lists DS records with
  their matching DNSKEY key tags, DNSKEYs (KSK/ZSK) and RRSIG validity, and warns
  about deprecated algorithms, SHA-1 DS digests, mismatched DS records and
  signatures that are expired or expire within 7 days. It does not use a custom
  nameserver, since validation needs a validating resolver.
- **Magic scan** checks A, AAAA, CAA, CNAME, HTTPS, MX, NS, SOA, SRV and TXT for the
  domain, common subdomains (`www`, `mail`, `api`, `staging`, …) and provider
  verification names (AWS/SES, Azure, Google Cloud, Cloudflare, Vercel, Netlify,
  Heroku, DigitalOcean, …). It adds RDAP data, SPF, common DKIM selectors (a
  built-in list, so custom selectors are not found), up to 25 subdomains from
  Certificate Transparency logs (`crt.sh`, falling back to CertSpotter), PTR
  records and geolocation. Results are not exhaustive.
- **Optional port check** in Magic scan: 26 common TCP ports (including 2222 and
  8443) on up to 8 eligible IPs. It reports ports that accept a connection; it is
  not a vulnerability assessment.
- **Port scans** always require a signed-in account. Private/local targets follow
  the role setting (default: allowed for Admins, not Users); other reserved
  addresses are always skipped. Only scan systems you are authorized to test.
- **Bulk port scan range limits**: admins can set the largest accepted IPv4 and
  IPv6 CIDR under Settings → Port scans. Defaults are /24 and /120; IPv4 can be
  widened to /16 and IPv6 to /120. Without zmap a hard cap of 256 unique
  addresses applies across the request; with zmap the cap is 65,536 IPv4 plus
  256 IPv6 addresses. One zmap scan runs at a time.
- **zmap engine (opt-in)**: zmap sends raw SYN packets, which needs `NET_RAW` and
  `NET_ADMIN`. Enable it with the `compose.zmap.yaml` override
  (`docker compose -f compose.yaml -f compose.zmap.yaml up --build -d`, or with
  `compose.registry.yaml`). It sets `ZMAP_ENABLED=true`, adds the two
  capabilities and removes `no-new-privileges` so the zmap binary's file
  capabilities apply; Node still runs as the unprivileged `node` user. The send
  rate (default 10,000 packets/s, 1,000–100,000) is under Settings → Port scans.
  If zmap cannot detect the network, set `ZMAP_INTERFACE`, `ZMAP_GATEWAY_MAC` or
  `ZMAP_SOURCE_IP`. High rates can trip hosting-provider abuse detection.
- **Live Ping monitoring** requires a signed-in user and checks one host every
  3 seconds for up to 5 minutes (100 samples maximum). It plots latency and
  availability, stops when the page is hidden or the user stops it, and can play
  a tone when the host changes between up and down. Server-side limits also enforce
  the sample interval and maximum volume per user. Monitor only systems you are
  authorized to check.
- **Nmap** accepts administrator-configured CIDRs and automatically adds a user's
  observed client IP after successful login as an exact `/32` (IPv4) or `/128`
  (IPv6) host entry (the observed address follows Trusted reverse proxy settings).
  Automatic entries expire after 30 days; a repeat login refreshes expiry.
  The combined allowlist is capped at 254 entries, preserving
  manual CIDRs and replacing the oldest automatic entry when full. Targets are
  resolved by the server and must match an allowlisted range. One address is
  scanned per request, with one concurrent scan and fixed timeouts. Available
  profiles are TCP connect on the top 20, 100 or 1000 ports, or light TCP service
  detection on the top 20 ports. Live status shows the running state, selected
  profile and elapsed time. The scanner does not accept custom
  command-line flags, target lists, or CIDR scans. Only scan systems you own or
  have explicit authorization to assess.
- **Result tables** are searchable and sortable; click a value to copy it.

## Accounts and access

- The first start with an empty volume opens a one-time setup page. Passwords need
  at least 12 characters and are stored as salted scrypt hashes. Sessions use
  HttpOnly, SameSite cookies and expire after 12 hours.
- Admins manage users (Admin/User role, disable, password reset) and set each
  feature to **Public**, **Logged-in users** or **Administrators**.

| Feature | Default access |
| --- | --- |
| DNS lookup, Reverse lookup, Whois, Dig, MAC lookup, Ping, SSLscan, Traceroute | Logged-in users |
| Magic scan, Ping scan, Multi traceroute, Port scan, Bulk port scan, Nmap | Administrators |

- Ping scan, Multi traceroute, both port scans and Nmap need a login even if set to Public.
- Public features are limited to 15 lookups per client IP per UTC day (stored in
  SQLite); logged-in users are exempt.
- New accounts and admin password resets require a **password change on first login**;
  until it is changed, the session has no access to any feature.
- **Users** can be disabled (reversible) or removed permanently. You cannot remove yourself
  or the last active administrator.
- **Email**: in Settings → **Email**, configure an SMTP server (STARTTLS, TLS or none, optional
  login, sender) and send a test message. Users add an optional address on **My account**
  (click their name in the header); a ✉ **Email these results to me** button then appears under
  results. Mail only goes to the user's own address, max 10 per hour per user. The SMTP password
  is stored in the data volume and never displayed.
- **Dashboard** shows live CPU, memory (container cgroup limit when set), data-volume
  storage, system load, 24 h activity and the latest queries. Admin only.
- **Logs** show login attempts, admin actions and lookup/scan requests (latest 200
  per tab; up to 20,000 records kept). **Stats** summarize 7, 30 or 90 days of
  query logs (visitors, failures, daily charts, query types, top names). Treat
  the database and its backups as sensitive.

## Admin settings

- **About page**: Settings → About page edits the public `/about` page (linked in
  the footer) with a live preview. It supports a small Markdown subset (headings,
  bold, italic, code, links, lists, quotes, rules and code blocks); HTML is shown
  as text and only `http(s)`, `mailto:` and same-site links become links. Up to
  20,000 characters; *Reset to default* restores the built-in text.

Open **Admin** (Settings & users). Settings persist in SQLite at
`/data/bnglookup.sqlite` on the `app_data` volume.

| Setting | Description |
| --- | --- |
| DNS resolver | Google Public DNS, Cloudflare, Quad9 or DNS4EU (EU, [protective](https://joindns4.eu/for-public), may filter malicious domains). Query names and types go to the chosen provider. |
| Trusted reverse proxies | Enter proxy IPs/CIDRs manually or enable automatic trust for Cloudflare's published IPv4/IPv6 reverse-proxy ranges. Cloudflare ranges are refreshed at startup and every 12 hours, and the last known-good list is retained if refresh fails. Only trusted connections can supply client-IP headers. The proxy must overwrite those headers. Cloudflare Tunnel users must also trust the local `cloudflared` connector address. |
| Port-scan policy | Max ports per role and local-network permission per role. |
| Site title and icon | Icon upload (PNG, JPEG, GIF, WebP, ICO; up to 256 KB) or HTTPS URL. |
| SSL certificate | See below. |

Environment variables:

| Variable | Purpose |
| --- | --- |
| `PORT` | Listening port (default 3000; host port in Compose). |
| `TRUSTED_PROXIES` | Initial trusted-proxy list, e.g. `TRUSTED_PROXIES=172.18.0.3 docker compose up -d --build`. The admin setting wins once stored. |
| `COOKIE_SECURE=true` | Set the cookie `Secure` attribute; use behind HTTPS. |
| `HTTPS_PORT` | HTTPS listener port (default 8443). |
| `DOH_ENDPOINT` | Extra custom DoH JSON endpoint, offered as a resolver choice. |
| `UPDATE_CHECK=false` | Disable the dashboard's check for new releases (otherwise the server asks the GitHub API at most every 6 hours, only while an admin views the dashboard). |
| `APP_VERSION`, `APP_COMMIT`, `APP_BUILD_DATE` | Build information shown on the dashboard. Set automatically by the release workflow as Docker build arguments; local builds show `dev`. |

## SSL certificate (ACME)

Get a trusted certificate from **Admin → SSL certificate**. The built-in client
uses ACME (RFC 8555) with Let's Encrypt and the HTTP-01 challenge.

1. Point one or more public DNS names at the Docker host.
2. Publish port 80 and HTTPS (`-f compose.yaml -f compose.acme.yaml`). Behind a
   reverse proxy, forward `/.well-known/acme-challenge/` to the app.
3. Enter the domains (one per line, up to 20, one shared certificate), a contact
   email, accept the CA terms and save. Try **Staging** first, then **Production**.
4. Click **Request certificate now**; progress is shown live.

The HTTPS listener reloads automatically when a certificate is issued, and
auto-renew runs when fewer than 30 days remain. Certificate, private key and
account key are stored with restrictive permissions in `/data/acme`. HTTPS
requests get HSTS and Secure cookies.

## Security and privacy

- Input is validated server-side (size, duplicates, control characters, strict
  UTF-8), SQL is parameterized, output is HTML-escaped, and a strict Content
  Security Policy plus security headers are sent.
- Only an explicit list of static files is served. State-changing requests need a
  same-origin `Origin` header.
- The Compose files run the container hardened: non-root user, read-only root
  filesystem (only `/data` and `/tmp` are writable), all Linux capabilities
  dropped, `no-new-privileges`, PID and memory limits, and a health check
  (`/healthz`). The app shuts down gracefully on `SIGTERM`. The optional
  `compose.zmap.yaml` relaxes this (adds `NET_RAW`/`NET_ADMIN`, drops
  `no-new-privileges`) and should only be used when the zmap engine is wanted.
- Expensive jobs are capped server-wide (8 concurrent traceroutes, 2 ping scans),
  and connections, header sizes and request timeouts are bounded.
- The HTTPS listener supports TLS 1.2/1.3 with forward-secret AEAD suites only and
  TLS session resumption (session tickets plus a bounded 5-minute session-ID cache).
- Use HTTPS (set `COOKIE_SECURE=true` behind a proxy) and network-level access
  controls; do not expose the service over an untrusted network without them.

| Data sent | Recipient |
| --- | --- |
| Queried names and record types | Selected DoH provider |
| Visitor IP (landing page PTR) | DoH provider; `rdap.org` for registration data |
| Domains and IPs for Whois | `rdap.org`, `ipwho.is` (ASN fallback) |
| Public IPs in scan results | `ipwho.is` (geolocation); private IPs are not sent |
| Scanned domain | `crt.sh`, then CertSpotter on failure |
| MAC address | `maclookup.app` |

Behind a reverse proxy, configure Trusted reverse proxies so the landing page
shows the real client IP.

For a standard Cloudflare-proxied origin, enable **Automatically trust
Cloudflare reverse proxy ranges** in **Admin → Feature access**. The official
Cloudflare IPv4 and IPv6 ranges are downloaded over HTTPS, cached in SQLite and
refreshed at startup and every 12 hours. This option is off by default. For
Cloudflare Tunnel, also add the `cloudflared` connector's address or CIDR:
the connection to BNGlookup comes from that local connector, not a Cloudflare
edge IP. Keep the app reachable only through your intended proxy and ensure it
overwrites client-IP headers.

## Other deployments

### Arcane

1. **Customization → Git Repositories**: add `https://github.com/BANAANGA/BNGlookup.git`.
2. **Projects → From Git Repo → Pull**: name the project, keep **Target Type** =
   **Project**, choose **Create a new project**.
3. Select the repository, branch `main`, **Compose File Path** `compose.yaml`.
4. Enable **Sync Files** (the build needs `Dockerfile`, `server.js` and `public/`);
   optionally enable **Redeploy After Sync**.
5. **Add Sync**, open the project and choose **Build & Deploy**.
6. Open `http://<arcane-host>:3000` (allow the port in the firewall). Set `PORT`
   in the project environment to change the host port.

### Without Docker

Requires Node.js 22 or newer. Traceroute needs `tracepath` installed.

```sh
node server.js                                            # http://localhost:3000
PORT=8080 DOH_ENDPOINT=https://example.net/dns-query node server.js
```
