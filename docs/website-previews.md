# Website previews

Shows a screenshot of a site inside the results, taken safely on the server, so you can see a suspicious site without opening it.

| | |
| --- | --- |
| **Where** | [Web check](web-check.md), [Magic scan](magic-scan.md), [Reputation](reputation.md) and [Lookalike domains](lookalike-domains.md) results |
| **Default access** | Logged-in users |

![Website previews](images/website-preview.jpg)

## What it does

A picture of the site's first screen appears in the results: the final page in
Web check, the homepage in Magic scan, the site in Reputation, and thumbnails of
registered lookalikes. Click a preview to see it at full size.

## How it works

1. A headless Chromium browser in the container opens the page at 1280 × 800.
2. The screenshot is saved as a JPEG and cached for one hour.

Because previews are often taken of suspicious sites, the browser is locked down:

| Protection | Effect |
| --- | --- |
| Scripts disabled | Malicious JavaScript does not run. Sites that need scripts may look bare. |
| Filtering proxy | All browser traffic goes through a proxy in the app that only connects to public addresses on ports 80 and 443, so a page cannot reach your network. |
| QUIC and WebRTC off | These could otherwise bypass the proxy. |
| Limits | Two browsers at a time, a short queue, 150 previews per user per hour. |

## Good to know

- An administrator can enable scripts with `SCREENSHOT_JAVASCRIPT=true` (renders
  more sites, but runs their code on the server) or turn previews off with `SCREENSHOTS=false`.
- A site that blocks automated browsers shows *Preview unavailable*.

---

[← Back to the wiki](README.md)
