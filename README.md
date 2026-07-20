# Security Header Analyzer

A Chrome extension (Manifest V3) that shows you the **real** HTTP security
headers your browser received for the page you're on, grades them, and explains
in plain English what each one protects against — and how to fix the weak ones.

Unlike tools that re-request the page, this extension reads the headers your
browser *actually got*, so the report matches what you really loaded (including
logged-in pages and redirects).

## What it checks

| Header | Protects against | Graded on |
| --- | --- | --- |
| Content-Security-Policy (CSP) | Cross-site scripting (XSS) | `unsafe-inline` / `unsafe-eval` / broad sources, with credit for nonces, hashes, and `strict-dynamic` |
| Strict-Transport-Security (HSTS) | HTTPS downgrade / eavesdropping | `max-age` length, `includeSubDomains`, `preload` |
| X-Frame-Options | Clickjacking | `DENY` / `SAMEORIGIN`; flags deprecated `ALLOW-FROM` |
| X-Content-Type-Options | MIME-type sniffing | must be exactly `nosniff` |
| Referrer-Policy | Leaking sensitive URLs | flags leaky policies like `unsafe-url` |
| Permissions-Policy | Misuse of camera, mic, location, etc. | presence |
| Cross-Origin-Opener-Policy (COOP) | Cross-window snooping | flags `unsafe-none` |
| Cross-Origin-Embedder-Policy (COEP) | Un-isolated embedding | flags `unsafe-none` |
| Cross-Origin-Resource-Policy (CORP) | Cross-site resource leaks | notes overly-open `cross-origin` |

Each result gets a color-coded badge — **PRESENT** (green), **OK** (green, e.g.
protection provided by another header), **WEAK** (yellow), or **MISSING** (red) —
plus the header's real value, specific notes, and a "Learn more" link. At the top
you get an overall **A–F letter grade** and a summary, and a **Copy report**
button for sharing the results as text.

Smart touches:

- If CSP sets `frame-ancestors`, X-Frame-Options is marked **OK** (already covered).
- `unsafe-inline` isn't flagged when a nonce/hash or `strict-dynamic` neutralizes it.
- Multiple copies of the same header are detected and noted.

## How it works

```
┌────────────┐   page loads    ┌──────────────────┐   saves headers   ┌───────────────┐
│  website   │ ──────────────▶ │  background.js    │ ────────────────▶ │ session store │
└────────────┘  (main frame)   │ (service worker)  │   per tab, in RAM └───────┬───────┘
                               └──────────────────┘                            │ reads
                                                                       ┌────────▼───────┐
                                                        you click icon │   popup.js     │
                                                                       │ grades + draws │
                                                                       └────────────────┘
```

`background.js` quietly watches each page's main response and saves only the
security-related headers for that tab into `chrome.storage.session` (in-memory;
wiped when you close Chrome, never written to disk). When you click the icon,
`popup.js` reads what was saved, grades it, and draws the report. No second
network request is ever made.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Extension metadata, permissions, icons |
| `background.js` | Service worker: records the real response headers per tab |
| `popup.html` | The popup window's structure |
| `popup.css` | Styling (light + dark mode) |
| `popup.js` | Logic: reads saved headers, grades them, renders the report |
| `icons/` | Toolbar/store icons (16, 32, 48, 128 px) |

## Permissions

- `webRequest` + `host_permissions: <all_urls>` — needed to observe the response
  headers of the pages you load. Chrome shows this as "read your browsing history"
  and "read and change your data on all websites." The extension only ever *reads*
  headers; it never changes requests or responses, and never sends anything
  anywhere.
- `storage` — to keep the captured headers in private, in-memory session storage.

The extension has **no content scripts** and makes **no network requests of its
own**. It only reads response headers locally, on your machine.

## Install (developer mode)

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select this folder.
4. Pin the icon, open any `http`/`https` site, and click it.

> First run tip: pages already open before you installed the extension have no
> captured headers yet. The popup will offer a **Reload page & analyze** button —
> click it and the report appears automatically. (The same applies to pages
> restored from the browser's back/forward cache.)

## Live reload while developing (optional)

So you don't have to keep clicking "reload" on `chrome://extensions` every time
you edit a file, there's a tiny built-in auto-reloader.

1. In a terminal, from this folder, start the watcher:
   ```
   python3 dev-server.py
   ```
   (Only Python 3 is needed — no installs. Stop it with Ctrl+C. Use a different
   port with `PORT=6000 python3 dev-server.py`.)
2. Load/reload the extension once in Chrome.
3. Now just **edit and save**. The extension reloads itself automatically:
   - Edits to `popup.*` show up when you next open the popup (no reload needed).
   - Edits to `background.js`/`manifest.json` trigger a full extension reload
     within about a second.

How it works: `dev-server.py` serves a token that changes when any source file
is saved; `dev-reload.js` (loaded by the service worker) watches that token and
calls `chrome.runtime.reload()` on a change. It uses no extra permissions.

There's also a manual fallback: press **Alt+Shift+R** (Option+Shift+R on macOS)
to reload the extension any time, even without the watcher running.

**Before publishing**, delete `dev-reload.js` and `dev-server.py` (and, if you
like, the `commands` block in `manifest.json`). The service worker loads
`dev-reload.js` inside a `try/catch`, so its absence is a harmless no-op.

## License

MIT — see `LICENSE`.
