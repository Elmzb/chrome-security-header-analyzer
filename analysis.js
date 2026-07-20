// analysis.js — the shared "analysis engine".
//
// This file contains ONLY logic: no DOM, no HTML, nothing that draws to a
// screen. It takes raw headers and turns them into graded results, notes, and
// an overall score. Both the small popup (popup.js) and the new full-page
// dashboard (dashboard.js) import from here, so the grading rules live in ONE
// place and can never drift apart between the two views.
//
// It's written as an ES module (note the `export` keywords). Any page that
// wants to use it loads its script with <script type="module"> and imports the
// pieces it needs.

// The session-storage keys the background worker uses. Must match background.js.
export const storageKey = (tabId) => `headers:${tabId}`;
export const connKey = (tabId) => `conn:${tabId}`;
export const techKey = (tabId) => `tech:${tabId}`;

// ===========================================================================
// CSP PARSING + GRADING
// ===========================================================================

// Turn a Content-Security-Policy string into a lookup of
// { "script-src": ["'self'", "https://x"], "object-src": ["'none'"], ... }.
// A CSP is a list of directives separated by ";", each being a name followed
// by its allowed sources.
export function parseCsp(value) {
  const map = {};
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens.shift();
    if (!(name in map)) map[name] = tokens; // first occurrence wins
  }
  return map;
}

// Grade a Content-Security-Policy. Returns { level: "ok" | "weak", notes: [] }.
// This is the most involved check because a CSP can exist yet still be loose.
export function gradeCsp(values) {
  const map = parseCsp(values.join("; ").toLowerCase());
  const notes = [];
  let weak = false;

  // Scripts are the dangerous part, so we focus on script-src. If it isn't set,
  // the browser falls back to default-src.
  const script = map["script-src"] || map["default-src"] || null;

  const hasNonceOrHash = (sources) =>
    !!sources && sources.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
  const strictDynamic = !!script && script.includes("'strict-dynamic'");

  if (!script) {
    notes.push({
      type: "bad",
      text: "No script-src or default-src is set, so scripts could load from anywhere.",
    });
    weak = true;
  } else {
    // With 'strict-dynamic' (or nonces/hashes), modern browsers IGNORE
    // 'unsafe-inline' and host wildcards — so we only flag those when there's
    // no such modern mechanism in place. This avoids false alarms.
    if (!strictDynamic) {
      if (script.includes("'unsafe-inline'") && !hasNonceOrHash(script)) {
        notes.push({
          type: "bad",
          text: "Allows 'unsafe-inline' scripts — the main thing CSP is meant to block.",
        });
        weak = true;
      }
      const broad = script.find(
        (s) => s === "*" || s === "http:" || s === "https:" || s === "data:"
      );
      if (broad) {
        notes.push({
          type: "bad",
          text: `Allows a very broad script source ("${broad}") — scripts can load from almost anywhere.`,
        });
        weak = true;
      }
    }
    // 'unsafe-eval' is dangerous regardless of strict-dynamic.
    if (script.includes("'unsafe-eval'")) {
      notes.push({
        type: "bad",
        text: "Allows 'unsafe-eval' — code can be run from plain text strings.",
      });
      weak = true;
    }
    // Praise a genuinely modern setup, but only if nothing above was wrong.
    if ((strictDynamic || hasNonceOrHash(script)) && !weak) {
      notes.push({
        type: "good",
        text: "Uses nonces/hashes or strict-dynamic — a strong, modern setup.",
      });
    }
  }

  // Two common hardening tips (these are suggestions, not failures).
  const objectSrc = map["object-src"] || map["default-src"];
  if (!(objectSrc && objectSrc.includes("'none'"))) {
    notes.push({
      type: "tip",
      text: "Consider \"object-src 'none'\" to block legacy plugin content.",
    });
  }
  if (!map["base-uri"]) {
    notes.push({
      type: "tip",
      text: "Consider \"base-uri 'none'\" so an injected <base> tag can't hijack links.",
    });
  }

  return { level: weak ? "weak" : "ok", notes };
}

// ===========================================================================
// CSP — DIRECTIVE BY DIRECTIVE
// ===========================================================================
// gradeCsp (above) gives the WHOLE policy one pass/fail, used for the header
// card and the score. analyzeCsp goes deeper: it grades each directive on its
// own so the dashboard can show exactly which rule is strong or weak — and it
// points out important directives the site forgot to set.

// A one-line, plain-English description of what each directive controls.
export const CSP_DIRECTIVE_INFO = {
  "default-src": "The fallback rule for any resource type you didn't set explicitly.",
  "script-src": "Which scripts the page may run — the single most important CSP rule.",
  "object-src": "Legacy plugin content (<object>/<embed>). Best set to 'none'.",
  "base-uri": "Restricts <base href>, so an injected tag can't re-point the page's relative links.",
  "frame-ancestors": "Who may embed this page in a frame — clickjacking protection.",
  "style-src": "Which stylesheets and inline styles may apply.",
  "img-src": "Where images may load from.",
  "connect-src": "Where fetch(), XHR, and WebSocket connections may go.",
  "font-src": "Where web fonts may load from.",
  "form-action": "Where forms on this page are allowed to submit.",
  "frame-src": "Which pages may be loaded into frames on this page.",
  "upgrade-insecure-requests": "Automatically upgrades insecure http subresource requests to https.",
};

// The directives important enough that we recommend adding them if missing.
const CSP_RECOMMENDED = ["script-src", "object-src", "base-uri", "frame-ancestors"];

// A source list is "broad" if it effectively allows content from anywhere.
function hasBroadSource(sources) {
  return sources.some((s) => ["*", "http:", "https:", "data:", "blob:"].includes(s));
}
function hasNonceOrHash(sources) {
  return sources.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
}

// The strong checks used for script-src (and default-src acting as its fallback).
function gradeScriptSources(sources) {
  const notes = [];
  let status = "present";
  const strictDynamic = sources.includes("'strict-dynamic'");
  const nonceHash = hasNonceOrHash(sources);

  if (!strictDynamic) {
    if (sources.includes("'unsafe-inline'") && !nonceHash) {
      notes.push({ type: "bad", text: "'unsafe-inline' lets inline scripts run — the main thing CSP is meant to block." });
      status = "weak";
    }
    if (hasBroadSource(sources)) {
      notes.push({ type: "bad", text: "A broad source here lets scripts load from almost anywhere." });
      status = "weak";
    }
  }
  if (sources.includes("'unsafe-eval'")) {
    notes.push({ type: "bad", text: "'unsafe-eval' allows running code from plain text strings." });
    status = "weak";
  }
  if ((strictDynamic || nonceHash) && status !== "weak") {
    notes.push({ type: "good", text: "Uses nonces/hashes or strict-dynamic — a strong, modern setup." });
  }
  return { status, notes };
}

// Grade a single directive that the site actually set.
function gradeOneDirective(name, sources) {
  const info = CSP_DIRECTIVE_INFO[name] || "";

  if (name === "script-src") {
    const g = gradeScriptSources(sources);
    return { name, sources, status: g.status, notes: g.notes, info };
  }
  if (name === "default-src") {
    const g = gradeScriptSources(sources);
    g.notes.unshift({ type: "tip", text: "Also the fallback for any resource type without its own rule." });
    return { name, sources, status: g.status, notes: g.notes, info };
  }
  if (name === "object-src") {
    const ok = sources.includes("'none'");
    return {
      name, sources, status: ok ? "present" : "weak",
      notes: [ok
        ? { type: "good", text: "'none' blocks legacy plugin content." }
        : { type: "bad", text: "Set this to 'none' to block <object>/<embed> plugin content." }],
      info,
    };
  }
  if (name === "base-uri") {
    const restrictive = sources.includes("'none'") || sources.includes("'self'");
    return {
      name, sources, status: restrictive ? "present" : "weak",
      notes: [restrictive
        ? { type: "good", text: "Restricts <base>, so an injected tag can't re-point relative links." }
        : { type: "tip", text: "Prefer 'none' or 'self' here." }],
      info,
    };
  }
  if (name === "frame-ancestors") {
    const broad = sources.includes("*");
    return {
      name, sources, status: broad ? "weak" : "present",
      notes: [broad
        ? { type: "bad", text: "'*' lets any site frame this page — a clickjacking risk." }
        : { type: "good", text: "Limits who can embed this page (clickjacking protection)." }],
      info,
    };
  }
  if (name === "upgrade-insecure-requests") {
    return { name, sources, status: "present", notes: [{ type: "good", text: "Upgrades insecure http subresources to https." }], info };
  }

  // Any other directive: informational. Flag a broad wildcard as a light tip.
  const notes = [];
  if (hasBroadSource(sources)) {
    notes.push({ type: "tip", text: "Uses a broad source — fine for public assets, tighten if it can hold sensitive data." });
  }
  return { name, sources, status: "present", notes, info };
}

// A suggestion string for a recommended directive the site is missing.
function cspRecommendText(name) {
  switch (name) {
    case "script-src": return "No script-src or default-src — scripts could load from anywhere. Add one.";
    case "object-src": return "Add \"object-src 'none'\" to block legacy plugin content.";
    case "base-uri": return "Add \"base-uri 'none'\" so an injected <base> tag can't hijack links.";
    case "frame-ancestors": return "Add frame-ancestors to control who can frame this page (clickjacking).";
    default: return "Consider adding this directive.";
  }
}

// Break a CSP into per-directive results (weak/missing first). Returns
// { present:false } when there's no CSP at all (the header card already flags that).
export function analyzeCsp(cspValues) {
  if (!cspValues || !cspValues.length) return { present: false, directives: [] };

  const map = parseCsp(cspValues.join("; ").toLowerCase());
  const directives = [];
  const seen = new Set();

  // Grade each directive the site actually set.
  for (const name of Object.keys(map)) {
    seen.add(name);
    directives.push(gradeOneDirective(name, map[name]));
  }

  // Recommend important directives that are missing.
  for (const name of CSP_RECOMMENDED) {
    if (seen.has(name)) continue;
    // script-src is covered if default-src is present (it's the fallback).
    if (name === "script-src" && map["default-src"]) continue;
    directives.push({
      name,
      sources: [],
      status: "missing",
      notes: [{ type: "tip", text: cspRecommendText(name) }],
      info: CSP_DIRECTIVE_INFO[name] || "",
    });
  }

  // Problems first: weak, then missing, then the healthy ones.
  const rank = { weak: 0, missing: 1, present: 2 };
  directives.sort((a, b) => rank[a.status] - rank[b.status]);
  return { present: true, directives };
}

// ===========================================================================
// THE HEADERS WE CHECK
// ===========================================================================
// Each entry has:
//   - name:    exact header name to look for (lowercase).
//   - label:   friendly title.
//   - desc:    a plain-English explanation of what it protects against.
//   - weight:  how much it counts toward the overall grade (more = important).
//   - learn:   a link to Mozilla's docs for people who want more detail.
//   - evaluate (optional): inspects the VALUE and returns { level, notes }.
//   - coveredBy (optional): if the header is MISSING, decides whether another
//     header already provides the same protection.
const MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/";

export const HEADERS = [
  {
    name: "content-security-policy",
    label: "Content-Security-Policy (CSP)",
    desc: "Controls what scripts, styles, and other content the page may load. The strongest defense against cross-site scripting (XSS), where an attacker sneaks malicious code into a page.",
    weight: 3,
    learn: MDN + "Content-Security-Policy",
    evaluate: gradeCsp,
  },
  {
    name: "strict-transport-security",
    label: "Strict-Transport-Security (HSTS)",
    desc: "Tells the browser to always use secure HTTPS for this site, blocking attackers who try to downgrade you to unencrypted HTTP to spy on the connection.",
    weight: 2,
    learn: MDN + "Strict-Transport-Security",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase();
      const match = v.match(/max-age\s*=\s*(\d+)/);
      const maxAge = match ? parseInt(match[1], 10) : 0;
      const notes = [];
      let weak = false;
      if (!match || maxAge === 0) {
        notes.push({ type: "bad", text: "max-age is 0 or missing — HSTS is effectively turned off." });
        weak = true;
      } else if (maxAge < 15768000) {
        notes.push({ type: "bad", text: `max-age is short (${maxAge}s). Aim for at least 6 months (15768000).` });
        weak = true;
      }
      if (!v.includes("includesubdomains")) {
        notes.push({ type: "tip", text: "Add includeSubDomains to protect subdomains too." });
      }
      if (v.includes("preload")) {
        notes.push({ type: "good", text: "preload is set — eligible for the browser's built-in HSTS list." });
      }
      return { level: weak ? "weak" : "ok", notes };
    },
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    desc: "Stops other websites from embedding this page inside a hidden frame. Defends against 'clickjacking', where you're tricked into clicking something you can't see.",
    weight: 1.5,
    learn: MDN + "X-Frame-Options",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase();
      if (v.includes("allow-from")) {
        return { level: "weak", notes: [{ type: "bad", text: "ALLOW-FROM is deprecated and ignored by modern browsers — use CSP frame-ancestors instead." }] };
      }
      if (!/(deny|sameorigin)/.test(v)) {
        return { level: "weak", notes: [{ type: "bad", text: `Unexpected value "${v}". Use DENY or SAMEORIGIN.` }] };
      }
      return { level: "ok", notes: [] };
    },
    // If CSP already sets frame-ancestors, it does this job (and does it better).
    coveredBy: (ctx) => ctx.csp && "frame-ancestors" in ctx.csp,
    coverageNote: "Covered by the CSP frame-ancestors directive, which handles clickjacking protection.",
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    desc: "Forces the browser to trust the declared file type instead of guessing. Prevents a file from being treated as something more dangerous than intended (MIME sniffing).",
    weight: 1.5,
    learn: MDN + "X-Content-Type-Options",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase().trim();
      if (v !== "nosniff") {
        return { level: "weak", notes: [{ type: "bad", text: `The value should be exactly "nosniff" (found "${v}").` }] };
      }
      return { level: "ok", notes: [] };
    },
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    desc: "Limits how much of the current address is shared when you follow a link to another site, so sensitive URLs don't leak.",
    weight: 1,
    learn: MDN + "Referrer-Policy",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase();
      if (v.includes("unsafe-url") || v.includes("no-referrer-when-downgrade")) {
        return { level: "weak", notes: [{ type: "bad", text: `"${v}" can leak full URLs to other sites. Prefer strict-origin-when-cross-origin or no-referrer.` }] };
      }
      return { level: "ok", notes: [] };
    },
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    desc: "Controls which browser features (camera, microphone, location, and so on) the page and anything it embeds may use, limiting what a compromised script can reach.",
    weight: 1,
    learn: MDN + "Permissions-Policy",
  },
  {
    name: "cross-origin-opener-policy",
    label: "Cross-Origin-Opener-Policy (COOP)",
    desc: "Separates this page from other windows or tabs it opens or was opened by, so they can't peek into each other. Helps block a class of cross-window snooping attacks.",
    weight: 1,
    learn: MDN + "Cross-Origin-Opener-Policy",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase();
      if (v.includes("unsafe-none")) {
        return { level: "weak", notes: [{ type: "bad", text: "unsafe-none gives no isolation (same as not setting it). Use same-origin." }] };
      }
      return { level: "ok", notes: [] };
    },
  },
  {
    name: "cross-origin-embedder-policy",
    label: "Cross-Origin-Embedder-Policy (COEP)",
    desc: "Requires everything the page loads to explicitly allow being embedded. Works together with COOP to fully isolate the page for extra-sensitive features.",
    weight: 0.5,
    learn: MDN + "Cross-Origin-Embedder-Policy",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase();
      if (v.includes("unsafe-none")) {
        return { level: "weak", notes: [{ type: "bad", text: "unsafe-none gives no protection. Use require-corp or credentialless." }] };
      }
      return { level: "ok", notes: [] };
    },
  },
  {
    name: "cross-origin-resource-policy",
    label: "Cross-Origin-Resource-Policy (CORP)",
    desc: "Controls which other sites are allowed to load this site's resources (images, scripts, data), reducing certain cross-site information-leak attacks.",
    weight: 0.5,
    learn: MDN + "Cross-Origin-Resource-Policy",
    evaluate: (values) => {
      const v = values.join(", ").toLowerCase();
      if (v.includes("cross-origin")) {
        return { level: "ok", notes: [{ type: "tip", text: "cross-origin lets any site load this resource — fine for public assets/CDNs, but not for private data." }] };
      }
      return { level: "ok", notes: [] };
    },
  },
];

// ===========================================================================
// GRADING A WHOLE PAGE
// ===========================================================================

// Turn the saved header list into a Map of lowercaseName -> [values...].
export function indexHeaders(headers) {
  const map = new Map();
  for (const h of headers) {
    const key = h.name.toLowerCase();
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(h.value);
  }
  return map;
}

// Decide the status ("present" | "weak" | "missing" | "covered") and notes for
// every header, given the page's headers.
export function analyze(headerMap) {
  // Pre-parse the CSP once so headers like X-Frame-Options can check it.
  const cspValues = headerMap.get("content-security-policy") || [];
  const cspParsed = cspValues.length ? parseCsp(cspValues.join("; ").toLowerCase()) : null;
  const ctx = { csp: cspParsed };

  return HEADERS.map((def) => {
    const values = headerMap.get(def.name) || [];
    let status;
    let notes = [];

    if (values.length > 0) {
      if (def.evaluate) {
        const result = def.evaluate(values);
        status = result.level === "weak" ? "weak" : "present";
        notes = result.notes || [];
      } else {
        status = "present";
      }
    } else if (def.coveredBy && def.coveredBy(ctx)) {
      status = "covered";
      notes = [{ type: "good", text: def.coverageNote }];
    } else {
      status = "missing";
    }

    if (values.length > 1) {
      notes = notes.concat({ type: "tip", text: `The site sent this header ${values.length} times.` });
    }

    return { def, status, values, notes };
  });
}

// Turn results into a 0–100 score and a letter grade. Present = full marks,
// weak = partial, missing = none — each scaled by the header's importance.
export function scoreOf(results) {
  let got = 0;
  let max = 0;
  for (const r of results) {
    max += r.def.weight;
    if (r.status === "present" || r.status === "covered") got += r.def.weight;
    else if (r.status === "weak") got += r.def.weight * 0.4;
  }
  const pct = max ? Math.round((got / max) * 100) : 0;
  return { pct, letter: letterFor(pct) };
}

// Map a 0–100 percentage to an A–F letter. Exported so other sections
// (cookies, TLS, etc.) can grade themselves on the same scale later.
export function letterFor(pct) {
  if (pct >= 90) return "A";
  if (pct >= 80) return "B";
  if (pct >= 70) return "C";
  if (pct >= 60) return "D";
  return "F";
}

// ===========================================================================
// COOKIE SECURITY
// ===========================================================================
// chrome.cookies (called from the dashboard) hands us each cookie's flags.
// This file only GRADES them — it never fetches or shows a cookie's value.
// We check the three flags that matter:
//   - Secure:   only send over HTTPS, so it can't be sniffed on the network.
//   - HttpOnly: hidden from JavaScript, so an XSS bug can't read it.
//   - SameSite: not sent on cross-site requests, which blunts CSRF.

// chrome.cookies reports the SameSite flag as one of these strings.
const SAMESITE_LABEL = {
  no_restriction: "None",
  lax: "Lax",
  strict: "Strict",
  unspecified: "not set",
};

// Grade a single cookie object (as returned by chrome.cookies).
// pageIsHttps lets us avoid flagging a missing Secure flag on an http:// page,
// where Secure wouldn't do anything anyway.
export function gradeCookie(cookie, pageIsHttps = true) {
  const notes = [];
  let weak = false;

  if (!cookie.secure) {
    notes.push({
      type: pageIsHttps ? "bad" : "tip",
      text: "Missing Secure — the cookie can travel over unencrypted HTTP, where it can be intercepted.",
    });
    if (pageIsHttps) weak = true;
  }

  if (!cookie.httpOnly) {
    notes.push({
      type: "bad",
      text: "Missing HttpOnly — JavaScript can read this cookie, so a cross-site scripting bug could steal it.",
    });
    weak = true;
  }

  const ss = cookie.sameSite || "unspecified";
  if (ss === "no_restriction") {
    notes.push({
      type: "bad",
      text: "SameSite=None — sent on cross-site requests, which enables CSRF unless that's genuinely required.",
    });
    weak = true;
  } else if (ss === "unspecified") {
    notes.push({
      type: "tip",
      text: "SameSite not set — browsers default to Lax, but setting it explicitly is clearer and safer.",
    });
  } else {
    notes.push({
      type: "good",
      text: `SameSite=${SAMESITE_LABEL[ss]} — limits cross-site sending.`,
    });
  }

  return {
    name: cookie.name,
    domain: cookie.domain,
    status: weak ? "weak" : "present",
    notes,
  };
}

// Grade a whole list of cookies and produce a short summary.
export function analyzeCookies(cookies, pageIsHttps = true) {
  const results = cookies.map((c) => gradeCookie(c, pageIsHttps));
  const summary = {
    total: cookies.length,
    missingSecure: cookies.filter((c) => !c.secure).length,
    missingHttpOnly: cookies.filter((c) => !c.httpOnly).length,
    weak: results.filter((r) => r.status === "weak").length,
  };
  // A simple 0–100 score: the share of cookies with no serious problems.
  summary.pct = summary.total
    ? Math.round(((summary.total - summary.weak) / summary.total) * 100)
    : 100;
  summary.letter = letterFor(summary.pct);
  return { results, summary };
}

// ===========================================================================
// HTTPS / TRANSPORT SECURITY
// ===========================================================================
// Turn the URL, the connection record (ip + statusLine from onResponseStarted),
// and the HSTS header into a list of plain-English facts. Each item has a
// level: "good" | "bad" | "tip" | "info" that the dashboard colors.
//
// LIMITATION: Chrome does not expose the TLS certificate, its expiry, or the
// cipher suite to extensions — so unlike a server-side scanner, we can't show
// those. We only report what the browser makes available.
export function analyzeTls(url, conn, hstsValues) {
  const isHttps = /^https:/i.test(url);
  const items = [];

  // 1) Is the connection encrypted at all? This is the big one.
  items.push({
    label: "Connection",
    value: isHttps ? "HTTPS — encrypted" : "HTTP — NOT encrypted",
    level: isHttps ? "good" : "bad",
  });
  if (!isHttps) {
    items.push({
      label: "Warning",
      value: "Loaded over plain HTTP — anyone on the network can read or modify this page.",
      level: "bad",
    });
  }

  // 2) HTTP protocol version, pulled from the status line ("HTTP/1.1 200 OK").
  if (conn && conn.statusLine) {
    const proto = (conn.statusLine.match(/^(HTTP\/[\d.]+)/i) || [])[1];
    if (proto) items.push({ label: "Protocol", value: proto, level: "info" });
  }

  // 3) Server IP (absent when the page came from the browser cache).
  if (conn && conn.ip) {
    items.push({ label: "Server IP", value: conn.ip, level: "info" });
  } else if (conn && conn.fromCache) {
    items.push({ label: "Server IP", value: "Not available (served from cache)", level: "info" });
  }

  // 4) HSTS — is the browser told to always use HTTPS for this site?
  const hsts = hstsValues && hstsValues.length ? hstsValues.join(", ").toLowerCase() : "";
  if (hsts) {
    const m = hsts.match(/max-age\s*=\s*(\d+)/);
    const maxAge = m ? parseInt(m[1], 10) : 0;
    const extras = [];
    if (hsts.includes("includesubdomains")) extras.push("includeSubDomains");
    if (hsts.includes("preload")) extras.push("preload");
    const strong = maxAge >= 15768000; // 6 months
    items.push({
      label: "HSTS",
      value:
        `Enabled — max-age=${maxAge}` +
        (extras.length ? ", " + extras.join(", ") : "") +
        (strong ? "" : " (short; aim for ≥ 6 months)"),
      level: strong ? "good" : "tip",
    });
  } else {
    items.push({
      label: "HSTS",
      value: isHttps
        ? "Not set — the browser isn't told to stick to HTTPS on future visits."
        : "Not applicable over HTTP.",
      level: isHttps ? "tip" : "info",
    });
  }

  // 5) Be explicit about what we can't see.
  items.push({
    label: "Certificate / cipher",
    value: "Not available — Chrome doesn't expose TLS certificate or cipher details to extensions.",
    level: "info",
  });

  return { isHttps, items };
}

// ===========================================================================
// TECH-STACK DETECTION (from response headers)
// ===========================================================================
// Some response headers quietly reveal what a site is built with. This maps
// those "fingerprint" headers to technologies. The page's DOM markers are
// detected separately (in tech.js) and merged in by mergeTech() below.
const TECH_HEADER_RULES = [
  { header: "server", match: /nginx/i, name: "nginx", category: "Web server" },
  { header: "server", match: /apache/i, name: "Apache", category: "Web server" },
  { header: "server", match: /microsoft-iis/i, name: "IIS", category: "Web server" },
  { header: "server", match: /litespeed/i, name: "LiteSpeed", category: "Web server" },
  { header: "server", match: /cloudflare/i, name: "Cloudflare", category: "CDN" },
  { header: "x-powered-by", match: /php/i, name: "PHP", category: "Language" },
  { header: "x-powered-by", match: /asp\.net/i, name: "ASP.NET", category: "Framework" },
  { header: "x-powered-by", match: /express/i, name: "Express", category: "Framework" },
  { header: "x-powered-by", match: /next\.js/i, name: "Next.js", category: "Framework" },
  { header: "x-powered-by", match: /wordpress|w3 total cache/i, name: "WordPress", category: "CMS" },
  { header: "x-aspnet-version", match: /.+/, name: "ASP.NET", category: "Framework" },
  { header: "x-generator", match: /drupal/i, name: "Drupal", category: "CMS" },
  { header: "x-drupal-cache", match: /.+/, name: "Drupal", category: "CMS" },
  { header: "x-shopify-stage", match: /.+/, name: "Shopify", category: "E-commerce" },
  { header: "cf-ray", match: /.+/, name: "Cloudflare", category: "CDN" },
  { header: "x-served-by", match: /cache|fastly/i, name: "Fastly", category: "CDN" },
  { header: "x-vercel-id", match: /.+/, name: "Vercel", category: "Hosting" },
  { header: "via", match: /varnish/i, name: "Varnish", category: "Cache" },
];

export function detectTechFromHeaders(headerMap) {
  const found = [];
  for (const rule of TECH_HEADER_RULES) {
    const values = headerMap.get(rule.header);
    if (values && rule.match.test(values.join(", "))) {
      found.push({ name: rule.name, category: rule.category, evidence: `${rule.header} header` });
    }
  }
  return found;
}

// Merge header-derived and DOM-derived tech lists, removing duplicates by name
// (case-insensitive). The first mention of a name wins its category/evidence.
export function mergeTech(...lists) {
  const byName = new Map();
  for (const list of lists) {
    for (const item of list || []) {
      const key = item.name.toLowerCase();
      if (!byName.has(key)) byName.set(key, item);
    }
  }
  return [...byName.values()].sort((a, b) =>
    a.category === b.category
      ? a.name.localeCompare(b.name)
      : a.category.localeCompare(b.category)
  );
}

// ===========================================================================
// SHARED DISPLAY HELPERS (still no DOM — just data about how to display)
// ===========================================================================

// Order results so problems float to the top: missing, then weak, then the
// ones that are fine. Within a group, more important headers come first.
const STATUS_RANK = { missing: 0, weak: 1, covered: 2, present: 3 };

export function sortForDisplay(results) {
  return [...results].sort((a, b) => {
    const byStatus = STATUS_RANK[a.status] - STATUS_RANK[b.status];
    return byStatus !== 0 ? byStatus : b.def.weight - a.def.weight;
  });
}

export const BADGE_TEXT = { present: "PRESENT", covered: "OK", weak: "WEAK", missing: "MISSING" };

// Assemble a plain-text version of the header report (used by the Copy button).
export function buildReport(url, results, score) {
  const lines = [
    "Security Header Report",
    url,
    `Overall grade: ${score.letter} (${score.pct}%)`,
    "",
  ];
  for (const r of results) {
    lines.push(`[${BADGE_TEXT[r.status]}] ${r.def.label}`);
    if (r.values.length) lines.push("    " + r.values.join(" | "));
    for (const n of r.notes) lines.push("    - " + n.text);
  }
  return lines.join("\n");
}
