// popup.js — the small popup you get when you click the toolbar icon.
//
// It:
//   1. Finds the tab you're looking at.
//   2. Reads the real headers the background worker saved for that tab.
//   3. Uses the shared analysis engine (analysis.js) to grade them.
//   4. Draws a compact report, an overall letter grade, and buttons to copy
//      the report or open the FULL-PAGE dashboard.
//
// All the grading rules now live in analysis.js so the popup and the dashboard
// stay perfectly in sync. This file is only about drawing to the screen.
//
// It never makes its own network request — it only reads what your browser
// already received, so what you see is exactly what the site actually sent.

"use strict";

import {
  storageKey,
  indexHeaders,
  analyze,
  scoreOf,
  sortForDisplay,
  BADGE_TEXT,
  buildReport,
} from "./analysis.js";

// ===========================================================================
// DRAWING THE UI
// ===========================================================================

const els = {
  overview: document.getElementById("overview"),
  grade: document.getElementById("grade"),
  site: document.getElementById("site"),
  meta: document.getElementById("meta"),
  results: document.getElementById("results"),
  status: document.getElementById("status"),
  actions: document.getElementById("actions"),
  copy: document.getElementById("copy"),
  open: document.getElementById("open"),
  autoReject: document.getElementById("autoReject"),
  consentStatus: document.getElementById("consentStatus"),
};

// ===========================================================================
// SHIELD: auto-reject cookie banners (the toggle + per-page status)
// ===========================================================================
async function setupConsentUI(tabId) {
  // Reflect the saved on/off setting (stored in storage.local so the content
  // script can read it too). Default ON.
  const { autoReject = true } = await chrome.storage.local.get({ autoReject: true });
  els.autoReject.checked = autoReject;
  els.autoReject.onchange = () => {
    chrome.storage.local.set({ autoReject: els.autoReject.checked });
  };

  // Show what the auto-rejecter did on this page, if anything.
  const key = `consent:${tabId}`;
  const showStatus = (record) => {
    if (record && record.cmp) {
      const via = record.cmp === "generic" ? "" : ` (${record.cmp})`;
      els.consentStatus.textContent = `✓ Cookie banner auto-rejected${via}.`;
      els.consentStatus.hidden = false;
    } else {
      els.consentStatus.hidden = true;
    }
  };
  const data = await chrome.storage.session.get(key);
  showStatus(data[key]);
  // Update live if the banner is handled while the popup is open.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes[key]) showStatus(changes[key].newValue);
  });
}

// Build one result card. Everything user-controlled is set with textContent,
// so a hostile site can never inject code into the popup.
function drawRow(result) {
  const { def, status, values, notes } = result;

  const li = document.createElement("li");
  li.className = "result";

  const head = document.createElement("div");
  head.className = "result-head";

  const badge = document.createElement("span");
  badge.className = "badge " + status;
  badge.textContent = BADGE_TEXT[status];

  const name = document.createElement("span");
  name.className = "result-name";
  name.textContent = def.label;

  head.appendChild(badge);
  head.appendChild(name);
  li.appendChild(head);

  const desc = document.createElement("p");
  desc.className = "result-desc";
  desc.textContent = def.desc;
  li.appendChild(desc);

  if (values.length > 0) {
    const valueEl = document.createElement("p");
    valueEl.className = "result-value";
    valueEl.textContent = values.join("\n");
    li.appendChild(valueEl);
  }

  if (notes.length > 0) {
    const list = document.createElement("ul");
    list.className = "notes";
    for (const note of notes) {
      const item = document.createElement("li");
      item.className = "note " + note.type;
      item.textContent = note.text;
      list.appendChild(item);
    }
    li.appendChild(list);
  }

  if (def.learn) {
    const link = document.createElement("a");
    link.className = "learn-more";
    link.href = def.learn;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "Learn more ↗";
    li.appendChild(link);
  }

  return li;
}

// Remove everything currently in an element.
function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

// ===========================================================================
// THE THREE THINGS THE POPUP CAN SHOW
// ===========================================================================

// 1) A full report for a page we have data for.
function renderReport(record, currentUrl, tabId) {
  const headerMap = indexHeaders(record.headers);
  const results = analyze(headerMap);
  const score = scoreOf(results);
  const presentCount = results.filter(
    (r) => r.status === "present" || r.status === "covered"
  ).length;

  // Overall grade circle.
  els.grade.textContent = score.letter;
  els.grade.className = "grade grade-" + score.letter.toLowerCase();

  // Which page these headers belong to.
  els.site.textContent = record.url;

  // A one-line summary.
  const parts = [`HTTP ${record.statusCode}`];
  if (record.fromCache) parts.push("from cache");
  parts.push(`${presentCount} of ${results.length} headers in place`);
  parts.push(`grade ${score.letter} (${score.pct}%)`);
  els.meta.textContent = parts.join(" · ");
  els.overview.hidden = false;

  // If the tab's address no longer matches (e.g. a single-page app changed the
  // URL without reloading), tell the user which page we actually measured.
  if (currentUrl && !sameOrigin(currentUrl, record.url)) {
    els.status.textContent = "Note: the tab has since navigated. These are the headers from the page shown above.";
  } else {
    els.status.textContent = "";
  }

  // The cards, problems first.
  clear(els.results);
  for (const result of sortForDisplay(results)) {
    els.results.appendChild(drawRow(result));
  }

  // Wire up the Copy button.
  els.copy.hidden = false;
  els.copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(buildReport(record.url, results, score));
      els.copy.textContent = "Copied!";
      setTimeout(() => (els.copy.textContent = "Copy report"), 1500);
    } catch (e) {
      els.copy.textContent = "Copy failed";
    }
  };

  // Wire up the "Open full audit" button. It opens dashboard.html in a new tab
  // and tells it (via the URL) which tab's saved headers to load.
  els.open.hidden = false;
  els.open.onclick = () => {
    const dashUrl =
      chrome.runtime.getURL("dashboard.html") + `?tabId=${encodeURIComponent(tabId)}`;
    chrome.tabs.create({ url: dashUrl });
  };

  els.actions.hidden = true;
}

// 2) We have no saved headers for this tab (page loaded before the extension
//    was watching, or came from the back/forward cache). Offer to reload.
function renderNoData(tabId) {
  els.overview.hidden = true;
  els.copy.hidden = true;
  els.open.hidden = true;
  clear(els.results);
  els.status.textContent =
    "No header data for this page yet. This happens when the page loaded before the extension was ready (for example, right after installing it). Reload the page to analyze it.";

  clear(els.actions);
  const button = document.createElement("button");
  button.className = "primary-btn";
  button.type = "button";
  button.textContent = "Reload page & analyze";
  button.onclick = () => {
    button.disabled = true;
    button.textContent = "Reloading…";
    chrome.tabs.reload(tabId);
    // When the reload finishes, the background worker saves fresh headers and
    // our storage listener (below) redraws automatically.
  };
  els.actions.appendChild(button);
  els.actions.hidden = false;
}

// 3) A page we can't analyze at all (chrome:// pages, the extensions gallery,
//    blank tabs, local files, etc.).
function renderUnsupported(url) {
  els.overview.hidden = true;
  els.copy.hidden = true;
  els.open.hidden = true;
  els.actions.hidden = true;
  clear(els.results);
  els.site.textContent = url || "No active tab";
  els.status.textContent =
    "This page can't be analyzed. Open a normal website (http or https) and try again.";
}

// Do two URLs share the same scheme + host + port?
function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

// ===========================================================================
// STARTUP
// ===========================================================================
async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    renderUnsupported("");
    return;
  }

  const tabId = tab.id;
  const url = tab.url || "";

  // The shield toggle works on any page, so set it up regardless.
  setupConsentUI(tabId);

  // We can only analyze real web pages.
  if (!/^https?:/i.test(url)) {
    renderUnsupported(url);
    return;
  }

  // Draw whatever we have saved for this tab right now...
  await load(tabId, url);

  // ...and redraw if fresh headers arrive while the popup is open (e.g. after
  // the user clicks Reload).
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes[storageKey(tabId)]) {
      load(tabId, url);
    }
  });
}

async function load(tabId, currentUrl) {
  const key = storageKey(tabId);
  const data = await chrome.storage.session.get(key);
  const record = data[key];
  if (record && record.headers) {
    renderReport(record, currentUrl, tabId);
  } else {
    renderNoData(tabId);
  }
}

init();
