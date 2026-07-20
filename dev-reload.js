// dev-reload.js — DEVELOPMENT ONLY. Safe to delete before publishing.
//
// Loaded by background.js (via importScripts, wrapped in try/catch). It watches
// a tiny local dev server for file changes and reloads the whole extension the
// moment you save — so you never have to touch chrome://extensions.
//
// How it works:
//   • dev-server.py serves a "token" that changes whenever any extension file
//     is edited (it's just the newest file-modified time).
//   • We fetch that token about once a second. The first value we see is our
//     baseline; if it ever differs, a file changed, so we reload.
//   • This top-level code runs every time the service worker wakes up (Chrome
//     re-runs the worker script on each wake), so normal dev activity — loading
//     a page, opening the popup — automatically restarts the watcher.
//
// If dev-server.py isn't running, the fetch just fails quietly and we retry.

const DEV_SERVER_URL = "http://127.0.0.1:5599/version";
let devReloadBaseline = null;

async function devReloadPoll() {
  try {
    const response = await fetch(DEV_SERVER_URL, { cache: "no-store" });
    const token = (await response.text()).trim();

    if (devReloadBaseline === null) {
      // First successful read: remember it and start watching for changes.
      devReloadBaseline = token;
      console.log("[dev-reload] connected — watching for file changes");
    } else if (token !== devReloadBaseline) {
      console.log("[dev-reload] change detected → reloading extension");
      chrome.runtime.reload();
      return; // stop; a fresh worker will take over after the reload
    }
    // All good — check again shortly.
    setTimeout(devReloadPoll, 1000);
  } catch (e) {
    // Server not running yet (or just stopped). Back off and keep trying so it
    // reconnects automatically once you start dev-server.py.
    setTimeout(devReloadPoll, 3000);
  }
}

devReloadPoll();
