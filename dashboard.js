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
  connKey,
  indexHeaders,
  analyze,
  scoreOf,
  sortForDisplay,
  BADGE_TEXT,
  buildReport,
  analyzeCookies,
  analyzeCsp,
  analyzeTls,
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

// Draw the connection / transport-security facts as a simple key–value list.
function renderTlsSection(record, conn) {
  const headerMap = indexHeaders(record.headers);
  const hstsValues = headerMap.get("strict-transport-security") || [];
  const { items } = analyzeTls(record.url, conn, hstsValues);

  const { body } = makeSection(
    "Connection & Transport Security",
    "How this page was delivered. Certificate and cipher details aren't shown — Chrome doesn't expose them to extensions."
  );

  const list = document.createElement("ul");
  list.className = "kv";
  for (const item of items) {
    const row = document.createElement("li");
    row.className = "kv-row";

    const label = document.createElement("span");
    label.className = "kv-label";
    label.textContent = item.label;

    const value = document.createElement("span");
    value.className = "kv-value " + item.level;
    value.textContent = item.value;

    row.appendChild(label);
    row.appendChild(value);
    list.appendChild(row);
  }
  body.appendChild(list);
}

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

// Build one cookie card. Like a header card, but for a single cookie. We show
// its name and domain ONLY — never its value, which could be a session token.
function cookieCard(result) {
  const li = document.createElement("li");
  li.className = "result";

  const head = document.createElement("div");
  head.className = "result-head";

  const badge = document.createElement("span");
  // Reuse the same badge colors: green for a healthy cookie, yellow for weak.
  badge.className = "badge " + (result.status === "weak" ? "weak" : "present");
  badge.textContent = result.status === "weak" ? "WEAK" : "OK";

  const name = document.createElement("span");
  name.className = "result-name";
  name.textContent = result.name;

  head.appendChild(badge);
  head.appendChild(name);
  li.appendChild(head);

  const domain = document.createElement("p");
  domain.className = "result-desc";
  domain.textContent = "Domain: " + result.domain;
  li.appendChild(domain);

  if (result.notes.length) {
    const list = document.createElement("ul");
    list.className = "notes";
    for (const note of result.notes) {
      const item = document.createElement("li");
      item.className = "note " + note.type;
      item.textContent = note.text;
      list.appendChild(item);
    }
    li.appendChild(list);
  }

  return li;
}

// Fetch the page's cookies (via the chrome.cookies API), grade them, and draw
// a Cookies section. This is async because reading cookies is a browser call.
async function renderCookiesSection(url) {
  const pageIsHttps = /^https:/i.test(url);

  let cookies;
  try {
    // getAll({ url }) returns exactly the cookies that apply to this page.
    cookies = await chrome.cookies.getAll({ url });
  } catch (e) {
    const { body } = makeSection("Cookies", "Couldn't read cookies for this page.");
    const p = document.createElement("p");
    p.className = "result-desc";
    p.textContent = String((e && e.message) || e);
    body.appendChild(p);
    return;
  }

  const { results, summary } = analyzeCookies(cookies, pageIsHttps);

  // Build a summary line for the section subtitle.
  const bits = [`${summary.total} cookie${summary.total === 1 ? "" : "s"}`];
  if (summary.missingSecure) bits.push(`${summary.missingSecure} missing Secure`);
  if (summary.missingHttpOnly) bits.push(`${summary.missingHttpOnly} missing HttpOnly`);
  bits.push("values are never read or shown");

  const { body } = makeSection("Cookies", bits.join(" · ") + ".");

  if (summary.total === 0) {
    const p = document.createElement("p");
    p.className = "result-desc";
    p.textContent = "No cookies are set for this page.";
    body.appendChild(p);
    return;
  }

  const list = document.createElement("ul");
  list.className = "cards";
  // Weak cookies first so problems are easy to spot.
  const sorted = [...results].sort(
    (a, b) => (a.status === "weak" ? 0 : 1) - (b.status === "weak" ? 0 : 1)
  );
  for (const result of sorted) list.appendChild(cookieCard(result));
  body.appendChild(list);
}

// Build one CSP directive card: the directive name, what it controls, its
// current sources, and per-directive notes.
function cspDirectiveCard(d) {
  const li = document.createElement("li");
  li.className = "result";

  const head = document.createElement("div");
  head.className = "result-head";

  const badge = document.createElement("span");
  const cls = d.status === "weak" ? "weak" : d.status === "missing" ? "missing" : "present";
  badge.className = "badge " + cls;
  badge.textContent = d.status === "weak" ? "WEAK" : d.status === "missing" ? "MISSING" : "OK";

  const name = document.createElement("span");
  name.className = "result-name";
  name.textContent = d.name;

  head.appendChild(badge);
  head.appendChild(name);
  li.appendChild(head);

  if (d.info) {
    const info = document.createElement("p");
    info.className = "result-desc";
    info.textContent = d.info;
    li.appendChild(info);
  }

  // Show the directive's current sources (its value), if any.
  if (d.sources.length) {
    const value = document.createElement("p");
    value.className = "result-value";
    value.textContent = d.sources.join(" ");
    li.appendChild(value);
  }

  if (d.notes.length) {
    const notes = document.createElement("ul");
    notes.className = "notes";
    for (const note of d.notes) {
      const item = document.createElement("li");
      item.className = "note " + note.type;
      item.textContent = note.text;
      notes.appendChild(item);
    }
    li.appendChild(notes);
  }

  return li;
}

// Draw the directive-by-directive CSP breakdown. Only shown when a CSP exists —
// if there's no CSP, the Security Headers section already flags it as missing.
function renderCspSection(cspValues) {
  const { present, directives } = analyzeCsp(cspValues);
  if (!present) return;

  const weak = directives.filter((d) => d.status === "weak").length;
  const missing = directives.filter((d) => d.status === "missing").length;
  const bits = [`${directives.length} directives`];
  if (weak) bits.push(`${weak} weak`);
  if (missing) bits.push(`${missing} recommended but missing`);

  const { body } = makeSection(
    "Content-Security-Policy — directive by directive",
    bits.join(" · ") + ". Each rule is graded on its own, problems first."
  );
  const list = document.createElement("ul");
  list.className = "cards";
  for (const d of directives) list.appendChild(cspDirectiveCard(d));
  body.appendChild(list);
}

// ---------------------------------------------------------------------------
// The whole report
// ---------------------------------------------------------------------------

function renderReport(record, conn) {
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

  // Sections. Transport security first (how the page arrived), then the
  // headers, then the CSP breakdown.
  clear(els.sections);
  renderTlsSection(record, conn);
  renderHeadersSection(results);
  renderCspSection(headerMap.get("content-security-policy") || []);

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

// Draw the whole report: the synchronous sections first (transport, headers,
// CSP), then cookies (needs an async browser call, so it pops in a moment
// later, appended at the bottom).
async function renderAll(record, conn) {
  renderReport(record, conn); // clears #sections, draws hero + TLS + headers + CSP
  await renderCookiesSection(record.url); // appends the Cookies section
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
  const ckey = connKey(tabId);
  const data = await chrome.storage.session.get([key, ckey]);
  const record = data[key];
  if (record && record.headers) {
    await renderAll(record, data[ckey]);
  } else {
    renderNoData();
  }

  // If the audited tab reloads while this dashboard is open, refresh the report
  // automatically with the new headers, connection info, and cookies.
  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== "session") return;
    if (changes[key] && changes[key].newValue) {
      // Re-read the latest connection record so it stays in sync.
      const latest = await chrome.storage.session.get(ckey);
      renderAll(changes[key].newValue, latest[ckey]);
    }
  });
}

init();
