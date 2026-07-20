// background.js — the extension's background "service worker".
//
// Its ONE job: quietly watch each page your browser loads and remember the
// security-relevant response headers the server actually sent for that page.
// The popup later reads what we saved here, so it can show you the REAL headers
// your browser received — never a second, made-up request.
//
// Nothing here ever leaves your computer. What we save lives in
// `chrome.storage.session`, which is in-memory only: it is wiped when you close
// the browser and is never written to disk.

// Optional live-reload helper for development. If dev-reload.js is present, it
// auto-reloads the extension whenever you save a file. In production this file
// is simply deleted, and the try/catch below turns this into a harmless no-op.
try {
  importScripts("dev-reload.js");
} catch (e) {
  // dev-reload.js not present — running as a normal, production extension.
}

// The header names we care about, all lowercase (header names are
// case-insensitive, so we compare in lowercase everywhere). We deliberately
// store ONLY these — not cookies or anything else — to keep things private and
// small. If popup.js starts checking a new header, add its name here too.
const RELEVANT_HEADERS = new Set([
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
]);

// We store one record per tab, under a key like "headers:42".
function storageKey(tabId) {
  return `headers:${tabId}`;
}

// Connection details (server IP + protocol) live under a separate key,
// like "conn:42". Kept separate from headers so the two capture paths never
// overwrite each other.
function connKey(tabId) {
  return `conn:${tabId}`;
}

// What the consent auto-rejecter did on a tab lives under "consent:42".
function consentKey(tabId) {
  return `consent:${tabId}`;
}

// ---------------------------------------------------------------------------
// Listen for the top-level page of every tab finishing its response headers.
// ---------------------------------------------------------------------------
// - "onHeadersReceived" fires the moment the server's headers arrive, before
//   the page body is processed.
// - types: ["main_frame"] means ONLY the main page in the tab — not images,
//   scripts, ads, or embedded iframes. That's exactly the page you're looking
//   at, which is what we want to grade.
// - On a redirect (e.g. http -> https), this fires for each hop; the final
//   landing page fires last and overwrites the earlier ones, so we always end
//   up with the headers of the page you actually see.
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // details.tabId is -1 for requests not tied to a tab (e.g. the browser
    // itself). We can't show those in a tab's popup, so skip them.
    if (details.tabId < 0) return;

    // Keep only the security headers we understand. Everything else is dropped
    // on the floor and never stored.
    const headers = (details.responseHeaders || [])
      .filter((h) => RELEVANT_HEADERS.has(h.name.toLowerCase()))
      .map((h) => ({ name: h.name, value: h.value || "" }));

    const record = {
      url: details.url, // the final URL these headers belong to
      statusCode: details.statusCode, // e.g. 200, 301, 404
      fromCache: !!details.fromCache, // was it served from the browser cache?
      headers, // the filtered list above
      capturedAt: Date.now(), // when we saw it
    };

    // Save it. If the worker gets shut down between now and when you open the
    // popup, session storage keeps the record safe until then.
    chrome.storage.session.set({ [storageKey(details.tabId)]: record });
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  // Ask Chrome to actually include the response headers (and any "extra" ones
  // some sites use) in what it hands us.
  ["responseHeaders", "extraHeaders"]
);

// ---------------------------------------------------------------------------
// Also record the CONNECTION details for the top-level page.
// ---------------------------------------------------------------------------
// "onResponseStarted" fires once the response begins, and — unlike
// onHeadersReceived — it tells us:
//   - details.ip:         the server's IP address the request actually hit
//   - details.statusLine: e.g. "HTTP/1.1 200 OK", which reveals the protocol
// Chrome does NOT expose TLS certificate or cipher details to extensions at
// all, so those simply aren't available here — the dashboard says as much.
chrome.webRequest.onResponseStarted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    chrome.storage.session.set({
      [connKey(details.tabId)]: {
        url: details.url,
        ip: details.ip || null, // absent when served from cache
        statusLine: details.statusLine || "",
        fromCache: !!details.fromCache,
        capturedAt: Date.now(),
      },
    });
    // A fresh page load starts with a clean slate: clear last page's consent
    // record and the ✓ badge. The content script will re-set them if it acts.
    chrome.storage.session.remove(consentKey(details.tabId));
    chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

// ---------------------------------------------------------------------------
// Hear from the consent auto-rejecter (consent.js) when it rejects a banner.
// ---------------------------------------------------------------------------
// The content script can't write to chrome.storage.session (that's reserved for
// trusted contexts), so it sends us a message instead. We record what happened
// for the popup and light up a green ✓ badge on the toolbar icon.
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.type !== "consentHandled" || !sender.tab) return;
  const tabId = sender.tab.id;
  chrome.storage.session.set({
    [consentKey(tabId)]: { cmp: msg.cmp || "generic", url: sender.url || "", at: Date.now() },
  });
  chrome.action.setBadgeText({ tabId, text: "✓" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
});

// ---------------------------------------------------------------------------
// Tidy up: when a tab is closed, throw away anything we saved for it.
// ---------------------------------------------------------------------------
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([storageKey(tabId), connKey(tabId), consentKey(tabId)]);
});

// ---------------------------------------------------------------------------
// Developer convenience: reload the whole extension with one keyboard shortcut.
// ---------------------------------------------------------------------------
// While building the extension, you normally have to click the little reload
// icon on chrome://extensions every time the code changes. Instead, press the
// shortcut (Alt+Shift+R by default) and Chrome reloads the extension for you.
//
// This is a dev helper. It's harmless to leave in — reloading an extension does
// nothing bad — but you can remove this block and the "commands" section of
// manifest.json before publishing if you'd rather not ship it.
//
// Note: reloading the extension re-arms this header listener for FUTURE page
// loads. Pages already open still need a normal page refresh to be re-measured
// (the popup's "Reload page & analyze" button does exactly that).
if (chrome.commands && chrome.commands.onCommand) {
  chrome.commands.onCommand.addListener((command) => {
    if (command === "reload-extension") chrome.runtime.reload();
  });
}
