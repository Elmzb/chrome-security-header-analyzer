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

// The session-storage key the background worker uses to save a tab's headers.
// Must match the format in background.js.
export const storageKey = (tabId) => `headers:${tabId}`;

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
