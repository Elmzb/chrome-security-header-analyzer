# Security Audit Dashboard 🛡️

A Chrome extension (Manifest V3) that turns any website into a plain-English
**security audit** — and quietly **shields** you while you browse.

It reads the **real** data your browser received (never a second, made-up
request), grades it, and explains what each finding means and how to fix it.
It also **auto-rejects cookie-consent banners** so you're not tracked by default.

> **Two views:** click the toolbar icon for a quick popup with the overall
> grade; hit **"Open full audit ↗"** for the full-page dashboard.

---

## What it does

### 🔍 Audit
| Area | What's checked |
| --- | --- |
| **Security headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP — each graded, with fixes and "Learn more" links |
| **CSP, directive by directive** | Every directive (`script-src`, `object-src`, `frame-ancestors`, …) graded on its own; flags `unsafe-inline`/`unsafe-eval`/broad sources and recommends missing directives |
| **Cookies** | Flags cookies missing **Secure**, **HttpOnly**, or a safe **SameSite** — cookie *values* are never read or shown |
| **Connection / TLS** | HTTPS vs HTTP, protocol version, server IP, HSTS status (honest that Chrome doesn't expose cert/cipher to extensions) |
| **Tech stack** | Detects CMS / framework / analytics / server from fingerprint headers *and* page markers (WordPress, Shopify, Next.js, Cloudflare, GTM, …) |

Everything rolls up into a single weighted **A–F grade**
(**Headers 50% · Transport 20% · Cookies 30%**), with a per-dimension breakdown
so you see *why*. Export the whole report as **HTML**, **JSON**, or copy it as text.

### 🛡️ Shield
- **Auto-reject cookie banners** — recognises 14 major consent platforms
  (OneTrust, Cookiebot, Didomi, Quantcast, Usercentrics, Sourcepoint, …) plus a
  multilingual generic fallback. Runs in every frame, pierces shadow DOM, and
  clicks "Reject all / Only necessary" for you. A green **✓** badge shows when it
  fires. Toggle it off anytime in the popup.

---

## How it works

```
┌──────────┐  page loads   ┌──────────────────┐  saves per tab   ┌───────────────┐
│ website  │ ────────────▶ │   background.js   │ ───────────────▶ │ session store │
└────┬─────┘ (main frame)  │ (service worker)  │  (in-memory RAM) └───────┬───────┘
     │                     └──────────────────┘                          │ reads
     │ content scripts run inside the page:                      ┌────────▼────────┐
     │  • consent.js  → auto-rejects the cookie banner           │ popup / dashboard│
     │  • tech.js     → detects the tech stack from the DOM      │  grade + render  │
     └───────────────────────────────────────────────────────── │  (analysis.js)   │
                                                                 └─────────────────┘
```

- **`background.js`** watches each page's main response, saving only the
  security + fingerprint headers (and server IP/protocol) for that tab into
  `chrome.storage.session` — in-memory, wiped when Chrome closes, never on disk.
- **`analysis.js`** is the shared "engine": pure grading logic with **no DOM**,
  so it's unit-testable. Both the popup and dashboard import it, so their
  grades always agree.
- **`popup.js` / `dashboard.js`** just read the saved data and draw it.
- **`consent.js` / `tech.js`** are content scripts that run inside pages; they
  report back to the background worker via messages.

No second network request is ever made — the audit reflects exactly what your
browser really loaded (including logged-in pages and redirects).

---

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Metadata, permissions, content-script registration, icons |
| `background.js` | Service worker: records real headers / connection info per tab; receives consent + tech reports |
| `analysis.js` | Shared engine: grading, scoring, and report builders (no DOM) |
| `popup.html/.css/.js` | The compact popup (quick grade + shield toggle) |
| `dashboard.html/.css/.js` | The full-page audit dashboard |
| `consent-rules.js` | Knowledge base of consent platforms + reject-label matcher |
| `consent.js` | Content script: the cookie-banner auto-rejecter engine |
| `tech.js` | Content script: tech-stack detection from the page's DOM |
| `icons/` | Toolbar/store icons (16, 32, 48, 128 px) |
| `dev-server.py` / `dev-reload.js` | Optional live-reload helpers for development |

---

## Permissions & privacy

- `webRequest` + `host_permissions: <all_urls>` — to observe the response
  headers of the pages you load. The extension only ever **reads** headers; it
  never modifies requests or responses.
- `cookies` — to read cookie **flags** (Secure/HttpOnly/SameSite). Cookie
  **values are never read or shown**.
- `storage` — keeps captured data in private, in-memory session storage.
- **Content scripts** (`consent.js`, `tech.js`) run inside pages to reject
  consent banners and read public page markers. They read no personal data, no
  page content, and no cookie values, and send nothing off your machine.

Nothing the extension collects ever leaves your computer.

---

## Install (developer mode)

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select this folder.
4. Pin the icon, open any `http`/`https` site, reload it once, and click the icon.

> First-run tip: pages open *before* you installed the extension have no captured
> data yet — the popup offers a **Reload page & analyze** button.

---

## Live reload while developing (optional)

So you don't have to keep clicking reload on `chrome://extensions`:

```
python3 dev-server.py
```

Then just edit and save — the extension reloads itself within a second.
**Before publishing**, delete `dev-reload.js` and `dev-server.py`.

---

## License

MIT — see `LICENSE`.
