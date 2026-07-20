// dashboard.js — the brain of the full-page audit.
//
// The popup opens this page in a new tab with a URL like
//   dashboard.html?tabId=42
// so this script knows WHICH tab to audit. It then reads that tab's saved
// headers from session storage (the same data the popup uses) and renders a
// full-page report using the shared analysis engine.
//
// Right now it shows one section — Security Headers. In the next steps we'll
// append more sections here (Cookies, CSP directives, TLS, Tech stack) without
// touching the parts below.

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

const els = {
  hero: document.getElementById("hero"),
  grade: document.getElementById("grade"),
  site: document.getElementById("site"),
  meta: document.getElementById("meta"),
  sections: document.getElementById("sections"),
  status: document.getElementById("status"),
  copy: document.getElementById("copy"),
};

// Remove everything currently inside an element.
function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

// ---------------------------------------------------------------------------
// Small building blocks
// ---------------------------------------------------------------------------

// Create a titled <section> card and return { section, body } so callers can
// fill the body with whatever they like. Every audit area uses this, so they
// all look consistent.
function makeSection(title, subtitle) {
  const section = document.createElement("section");
  section.className = "section";

  const h = document.createElement("h2");
  h.className = "section-title";
  h.textContent = title;
  section.appendChild(h);

  if (subtitle) {
    const p = document.createElement("p");
    p.className = "section-subtitle";
    p.textContent = subtitle;
    section.appendChild(p);
  }

  const body = document.createElement("div");
  section.appendChild(body);
  els.sections.appendChild(section);
  return { section, body };
}

// Build one header result card. Same shape as the popup's, but this is the
// dashboard's own copy because the two pages lay cards out differently.
// Everything user-controlled is set with textContent, so a hostile site's
// header value can never inject markup or code into the page.
function headerCard(result) {
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
    const value = document.createElement("p");
    value.className = "result-value";
    value.textContent = values.join("\n");
    li.appendChild(value);
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

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function renderHeadersSection(results) {
  const { body } = makeSection(
    "Security Headers",
    "The HTTP response headers your browser actually received, graded and sorted worst-first."
  );
  const list = document.createElement("ul");
  list.className = "cards";
  for (const result of sortForDisplay(results)) {
    list.appendChild(headerCard(result));
  }
  body.appendChild(list);
}

// ---------------------------------------------------------------------------
// The whole report
// ---------------------------------------------------------------------------

function renderReport(record) {
  const headerMap = indexHeaders(record.headers);
  const results = analyze(headerMap);
  const score = scoreOf(results);
  const presentCount = results.filter(
    (r) => r.status === "present" || r.status === "covered"
  ).length;

  // Hero: overall grade + which page + summary line.
  els.grade.textContent = score.letter;
  els.grade.className = "grade grade-" + score.letter.toLowerCase();
  els.site.textContent = record.url;

  const parts = [`HTTP ${record.statusCode}`];
  if (record.fromCache) parts.push("from cache");
  parts.push(`${presentCount} of ${results.length} headers in place`);
  parts.push(`grade ${score.letter} (${score.pct}%)`);
  els.meta.textContent = parts.join(" · ");
  els.hero.hidden = false;
  els.status.textContent = "";

  // Sections.
  clear(els.sections);
  renderHeadersSection(results);

  // Copy button.
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
}

function renderNoData() {
  els.hero.hidden = true;
  els.copy.hidden = true;
  clear(els.sections);
  els.status.textContent =
    "No saved audit data for that tab. Open the page you want to audit, click the extension icon, then use “Open full audit” from the popup.";
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function init() {
  // Read the tabId the popup passed in the URL, e.g. dashboard.html?tabId=42.
  const params = new URLSearchParams(location.search);
  const tabId = params.get("tabId");
  if (!tabId) {
    renderNoData();
    return;
  }

  const key = storageKey(tabId);
  const data = await chrome.storage.session.get(key);
  const record = data[key];
  if (record && record.headers) {
    renderReport(record);
  } else {
    renderNoData();
  }

  // If the audited tab reloads while this dashboard is open, refresh the report
  // automatically with the new headers.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes[key] && changes[key].newValue) {
      renderReport(changes[key].newValue);
    }
  });
}

init();
