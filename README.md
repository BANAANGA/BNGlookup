# BNGlookup

A lightweight, self-hosted DNS lookup web interface for querying DNS records and
reverse DNS (PTR) records for IPv4 and IPv6 addresses.

## Features

- Query common DNS records: A, AAAA, ANY, CAA, CNAME, HTTPS, MX, NS, PTR, SOA,
  SRV, SSHFP, SVCB, TLSA, and TXT.
- Query other record types by name or numeric DNS type code.
- Look up PTR records from IPv4 or IPv6 addresses.
- Display PTR hostnames for IP addresses returned in DNS results and for
  resolved nameserver addresses.
- View public domain registration details from RDAP (the modern WHOIS service),
  including registrar, registration dates, status, and published contacts.
- Compare nameservers from registration data with live DNS NS answers, including
  available IP addresses and TTLs.
- View DNS response status and answer, authority, and additional records.
- Run as a small Docker container, with no application dependencies to install.
- Configure the DNS-over-HTTPS (DoH) JSON provider; Cloudflare is the default.

## Screenshot

![BNGlookup DNS lookup interface](assets/dns-lookup.png)

## Installation with Docker Compose

### Requirements

- Docker Engine
- Docker Compose v2 (`docker compose`)

### Build and start

From the repository directory, build the image and start the service:

```sh
docker compose up --build -d
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

To use a different host port, set `PORT` when starting Compose. For example,
this maps host port 8080 to the app's container port 3000:

```sh
PORT=8080 docker compose up --build -d
```

View the application logs or stop the service with:

```sh
docker compose logs -f
docker compose down
```

### Configure the DNS provider

Queries use Cloudflare's DNS-over-HTTPS JSON endpoint by default. To select a
different compatible endpoint, set `DOH_ENDPOINT` when starting the container:

```sh
DOH_ENDPOINT=https://cloudflare-dns.com/dns-query docker compose up --build -d
```

The DNS provider receives the names and record types you query.

## Deploy with Arcane

Arcane can deploy this repository as a Compose project. Since the Compose file
builds the image from the repository (`build: .`), sync the project files as
well as the Compose file:

1. In Arcane, go to **Customization → Git Repositories** and add
   `https://github.com/BANAANGA/BNGlookup.git`. Configure repository
   authentication if your Arcane setup requires it.
2. Open **Projects** and select **From Git Repo** from the dropdown next to
   **Create Project**.
3. Choose **Pull**, give the project a name, keep **Target Type** set to
   **Project**, and choose **Create a new project**.
4. Select the repository and the `main` branch. Set **Compose File Path** to
   `compose.yaml`.
5. Enable **Sync Files** so Arcane also copies `Dockerfile`, `server.js`, and
   the `public/` assets needed by the image build. Optionally enable
   **Redeploy After Sync** to rebuild and restart the app after repository
   updates.
6. Click **Add Sync**, open the project, and choose **Build & Deploy** to build
   the image and start the service.
7. Open `http://<arcane-host>:3000` in your browser. If Arcane runs on another
   host, make sure its firewall allows inbound traffic on port 3000.

The Compose file publishes port 3000 by default. To use a different host port,
set `PORT` in the project's environment configuration (for example, `PORT=8080`)
and redeploy. To change the DNS provider, set `DOH_ENDPOINT` in the same
environment configuration.

## Run without Docker

Requires Node.js 22 or newer. Clone or download the repository, change to its
directory, and start the server:

```sh
node server.js
```

The interface is available at [http://localhost:3000](http://localhost:3000).
Set `PORT` to change the listening port, or `DOH_ENDPOINT` to select another
DNS-over-HTTPS JSON provider:

```sh
PORT=8080 DOH_ENDPOINT=https://cloudflare-dns.com/dns-query node server.js
```

## DNS record notes

Select **Custom…** to enter another record type by name (such as `NAPTR`) or
numeric type code. `ANY` queries do not necessarily return every record; DNS
servers commonly limit their responses. The available records depend on the
queried domain and provider.

Choose **Domain details** to view publicly available registration information
and compare registered nameservers with the domain's live DNS NS records.
Registration data is retrieved from RDAP using `rdap.org`, which redirects to
the responsible registry. The domain name is sent to the RDAP service;
contact details may be redacted or unavailable.
