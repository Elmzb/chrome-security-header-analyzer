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
  techKey,
  indexHeaders,
  analyze,
  scoreOf,
  sortForDisplay,
  BADGE_TEXT,
  analyzeCookies,
  analyzeCsp,
  analyzeTls,
  detectTechFromHeaders,
  mergeTech,
  transportScore,
  overallGrade,
  reportToText,
  reportToJson,
  reportToHtml,
} from "./analysis.js";

const els = {
  hero: document.getElementById("hero"),
  grade: document.getElementById("grade"),
  site: document.getElementById("site"),
  meta: document.getElementById("meta"),
  subgrades: document.getElementById("subgrades"),
  sections: document.getElementById("sections"),
  status: document.getElementById("status"),
  copy: document.getElementById("copy"),
  downloadHtml: document.getElementById("downloadHtml"),
  downloadJson: document.getElementById("downloadJson"),
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
  return items;
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

// Read the page's cookies once (via the chrome.cookies API). Returns the graded
// analysis, or null if we couldn't read them. Done up front so the overall
// grade and the export can use it too.
async function loadCookieAnalysis(url) {
  try {
    const cookies = await chrome.cookies.getAll({ url });
    return analyzeCookies(cookies, /^https:/i.test(url));
  } catch (e) {
    return null;
  }
}

// Draw the Cookies section from an already-loaded analysis (sync).
function renderCookiesSection(cookieAnalysis) {
  if (!cookieAnalysis) {
    makeSection("Cookies", "Couldn't read cookies for this page.");
    return;
  }
  const { results, summary } = cookieAnalysis;

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

// Read the DOM-detected tech (reported by tech.js) from storage.
async function loadDomTech(tabId) {
  try {
    const data = await chrome.storage.session.get(techKey(tabId));
    const rec = data[techKey(tabId)];
    if (rec && Array.isArray(rec.tech)) return rec.tech;
  } catch (e) {}
  return [];
}

// Draw a Technology section from header tech + already-loaded DOM tech (sync).
// Returns the merged list so the export can include it.
function renderTechSection(headerMap, domTech) {
  const all = mergeTech(detectTechFromHeaders(headerMap), domTech);
  const { body } = makeSection(
    "Technology",
    all.length
      ? `${all.length} detected from response headers and page markers.`
      : "Nothing recognised from headers or page markers (the site may hide these)."
  );

  if (!all.length) return all;

  const list = document.createElement("ul");
  list.className = "cards";
  for (const tech of all) {
    const li = document.createElement("li");
    li.className = "result";

    const head = document.createElement("div");
    head.className = "result-head";
    const name = document.createElement("span");
    name.className = "result-name";
    name.textContent = tech.name;
    head.appendChild(name);
    li.appendChild(head);

    const desc = document.createElement("p");
    desc.className = "result-desc";
    desc.textContent = `${tech.category} · detected via ${tech.evidence}`;
    li.appendChild(desc);

    list.appendChild(li);
  }
  body.appendChild(list);
  return all;
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
  const analysis = analyzeCsp(cspValues);
  if (!analysis.present) return analysis;

  const { directives } = analysis;
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
  return analysis;
}

// ---------------------------------------------------------------------------
// The whole report
// ---------------------------------------------------------------------------

// Draw everything, using data that's ALL been loaded up front (cookies + tech),
// so the combined grade and the export are complete and consistent.
function renderReport(record, conn, cookieAnalysis, domTech) {
  const headerMap = indexHeaders(record.headers);
  const results = analyze(headerMap);
  const headerScore = scoreOf(results);
  const hstsValues = headerMap.get("strict-transport-security") || [];

  // --- The combined overall grade (Headers + Transport + Cookies) -----------
  const cookiePct = cookieAnalysis ? cookieAnalysis.summary.pct : 100;
  const overall = overallGrade({
    headerPct: headerScore.pct,
    transportPct: transportScore(record.url, hstsValues),
    cookiePct,
  });

  // Hero: the big combined grade + which page + a one-line summary.
  els.grade.textContent = overall.letter;
  els.grade.className = "grade grade-" + overall.letter.toLowerCase();
  els.site.textContent = record.url;

  const metaBits = [`HTTP ${record.statusCode}`];
  if (record.fromCache) metaBits.push("from cache");
  metaBits.push(`overall ${overall.letter} (${overall.pct}%)`);
  els.meta.textContent = metaBits.join(" · ");

  // Per-dimension breakdown chips, so you see WHY the grade is what it is.
  clear(els.subgrades);
  for (const p of overall.parts) {
    const pill = document.createElement("span");
    pill.className = "subgrade grade-" + p.letter.toLowerCase();
    pill.textContent = `${p.label}: ${p.letter} (${p.pct}%)`;
    els.subgrades.appendChild(pill);
  }
  els.hero.hidden = false;
  els.status.textContent = "";

  // --- Sections (all synchronous now) ---------------------------------------
  clear(els.sections);
  const transport = renderTlsSection(record, conn);
  const tech = renderTechSection(headerMap, domTech) || [];
  renderHeadersSection(results);
  const csp = renderCspSection(headerMap.get("content-security-policy") || []);
  renderCookiesSection(cookieAnalysis);

  // --- Assemble the exportable report data ----------------------------------
  const reportData = {
    generatedAt: new Date().toLocaleString(),
    url: record.url,
    statusCode: record.statusCode,
    overall,
    transport,
    tech,
    headers: results.map((r) => ({
      label: r.def.label, status: r.status, values: r.values, notes: r.notes,
    })),
    csp: csp && csp.present ? { present: true, directives: csp.directives } : { present: false },
    cookies: cookieAnalysis || { summary: { total: 0, missingSecure: 0, missingHttpOnly: 0 }, results: [] },
  };
  wireExportButtons(reportData);
}

// Hook up Copy / Download HTML / Download JSON to the current report data.
function wireExportButtons(data) {
  const host = safeHost(data.url);

  els.copy.hidden = false;
  els.copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(reportToText(data));
      flash(els.copy, "Copied!", "Copy report");
    } catch (e) {
      flash(els.copy, "Copy failed", "Copy report");
    }
  };

  els.downloadHtml.hidden = false;
  els.downloadHtml.onclick = () =>
    downloadFile(`security-audit-${host}.html`, reportToHtml(data), "text/html");

  els.downloadJson.hidden = false;
  els.downloadJson.onclick = () =>
    downloadFile(`security-audit-${host}.json`, reportToJson(data), "application/json");
}

// Trigger a file download from a string, entirely in-browser.
function downloadFile(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeHost(url) {
  try { return new URL(url).hostname || "site"; } catch { return "site"; }
}

function flash(btn, temp, back) {
  btn.textContent = temp;
  setTimeout(() => (btn.textContent = back), 1500);
}

// Load the async pieces (cookies + DOM tech) up front, then render everything.
async function renderAll(record, conn, tabId) {
  const [cookieAnalysis, domTech] = await Promise.all([
    loadCookieAnalysis(record.url),
    loadDomTech(tabId),
  ]);
  renderReport(record, conn, cookieAnalysis, domTech);
}

function renderNoData() {
  els.hero.hidden = true;
  els.copy.hidden = true;
  els.downloadHtml.hidden = true;
  els.downloadJson.hidden = true;
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
  const tkey = techKey(tabId);
  const data = await chrome.storage.session.get([key, ckey]);
  let record = data[key];
  let conn = data[ckey];
  if (record && record.headers) {
    await renderAll(record, conn, tabId);
  } else {
    renderNoData();
  }

  // If the audited tab reloads (new headers) or the tech-detector reports in
  // after we drew, refresh the report so everything stays in sync.
  chrome.storage.onChanged.addListener(async (changes, area) => {
    if (area !== "session") return;
    if (changes[key] && changes[key].newValue) {
      record = changes[key].newValue;
      const latest = await chrome.storage.session.get(ckey);
      conn = latest[ckey];
      renderAll(record, conn, tabId);
    } else if (changes[tkey] && record) {
      renderAll(record, conn, tabId); // tech arrived after first render
    }
  });
}

init();
