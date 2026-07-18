# Security Header Analyzer

A simple Chrome extension (Manifest V3) that inspects the security-related HTTP
response headers of whatever website you're currently on, and explains in plain
English what each one protects against.

## What it checks

| Header | Protects against |
| --- | --- |
| Content-Security-Policy (CSP) | Cross-site scripting (XSS) — also graded for weak values |
| Strict-Transport-Security (HSTS) | HTTPS downgrade / eavesdropping |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME-type sniffing |
| Referrer-Policy | Leaking sensitive URLs |
| Permissions-Policy | Unwanted use of camera, mic, location, etc. |

Each result shows a color-coded badge — **PRESENT** (green), **WEAK** (yellow),
or **MISSING** (red) — the header's actual value, and a short explanation.
The CSP check additionally flags loose policies (`unsafe-inline`, `unsafe-eval`,
or a `*` wildcard source).

## How to install (developer mode)

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select this folder.
4. Pin the icon, then click it on any `http`/`https` site.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | Extension metadata and permissions |
| `popup.html` | The popup window's structure |
| `popup.css` | Styling for the popup |
| `popup.js` | Logic: reads the site's headers and renders the results |

## How it works

Clicking the toolbar icon opens `popup.html`, which loads `popup.css` and
`popup.js`. The script reads the active tab's URL, fetches that URL (permitted by
the extension's host permissions) to read its response headers, evaluates each
header, and draws a result card for each one.

## Permissions

- `activeTab` — read the URL of the tab you're currently viewing.
- `host_permissions: <all_urls>` — fetch the current site so its response
  headers can be read (ordinary web pages aren't allowed to read another site's
  headers; host permissions grant the extension that access).

The extension has no background worker and no content scripts — it does nothing
until you click the icon, and only ever looks at the one tab you point it at.
