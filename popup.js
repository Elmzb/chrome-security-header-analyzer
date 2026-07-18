// popup.js
// This script runs every time you open the popup. Its job is:
//   1. Figure out which website you're currently on.
//   2. Ask that website for its HTTP response headers.
//   3. Check whether each important security header is present.
//   4. Draw a result row for each header, with a plain-English explanation.

// ---------------------------------------------------------------------------
// STEP 0: Describe the headers we care about.
// ---------------------------------------------------------------------------
// This is a plain list. Each entry has:
//   - name:  the exact header name to look for (case does not matter to us).
//   - label: a friendly title to show the user.
//   - desc:  a short, non-technical explanation of what it protects against.
//   - grade: (optional) a function that inspects the header's VALUE and decides
//            whether it's weak. Most headers are simply present-or-missing, so
//            they don't need one — only CSP does, because a CSP can technically
//            exist while still being loosely configured.
// Adding or removing a header later is as easy as editing this list.
const HEADERS = [
  {
    name: "content-security-policy",
    label: "Content-Security-Policy (CSP)",
    desc: "Controls what scripts, styles, and other content the page is allowed to load. Helps block cross-site scripting (XSS), where an attacker sneaks malicious code into a page.",
    grade: gradeCsp, // defined below; flags loose policies as "weak".
  },
  {
    name: "strict-transport-security",
    label: "Strict-Transport-Security (HSTS)",
    desc: "Tells the browser to always use secure HTTPS for this site. Protects against attackers who try to downgrade your connection to unencrypted HTTP to spy on it.",
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    desc: "Stops other websites from embedding this page inside a hidden frame. Defends against 'clickjacking', where you're tricked into clicking something you can't see.",
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    desc: "Forces the browser to trust the declared file type instead of guessing. Prevents a file from being treated as something more dangerous than intended (MIME sniffing).",
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    desc: "Limits how much of the current address is shared when you click a link to another site. Protects your privacy by not leaking sensitive URLs.",
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    desc: "Controls which browser features (camera, microphone, location, etc.) the page and anything it embeds are allowed to use. Reduces what a compromised or malicious script can access.",
  },
];

// ---------------------------------------------------------------------------
// CSP grading: is a Content-Security-Policy present but weak?
// ---------------------------------------------------------------------------
// A CSP is a set of rules like "script-src 'self'". Some values weaken it so
// much that the protection is largely undone. This function scans the policy
// text for those common weak spots and returns a list of human-readable
// reasons. An empty list means "no weaknesses found".
function gradeCsp(value) {
  const v = value.toLowerCase();
  const reasons = [];

  // 'unsafe-inline' re-allows inline <script> tags — the exact thing CSP is
  // meant to block. Its presence largely defeats XSS protection.
  if (v.includes("'unsafe-inline'")) {
    reasons.push("allows 'unsafe-inline' (inline scripts/styles can run)");
  }

  // 'unsafe-eval' re-enables eval() and similar, a common attack vector.
  if (v.includes("'unsafe-eval'")) {
    reasons.push("allows 'unsafe-eval' (dynamic code execution)");
  }

  // A bare "*" wildcard as a source lets content load from ANY site.
  if (/(^|[\s;])(default-src|script-src)[^;]*\*/.test(v)) {
    reasons.push("uses a '*' wildcard source (content can load from anywhere)");
  }

  return reasons;
}

// Grab the page elements we'll be updating. We looked these up by their id.
const siteEl = document.getElementById("site");
const resultsEl = document.getElementById("results");
const statusEl = document.getElementById("status");

// ---------------------------------------------------------------------------
// STEP 1: Find the active tab, then kick everything off.
// ---------------------------------------------------------------------------
// chrome.tabs.query is the browser telling us about open tabs. We ask only
// for the one that is active in the current window — that's the site you're
// looking at right now.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  const url = tab && tab.url ? tab.url : "";

  // We can only inspect normal web pages. Chrome's own pages (chrome://...),
  // the extensions gallery, and blank tabs can't be fetched, so we bail early
  // with a friendly message instead of showing a confusing error.
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    siteEl.textContent = url || "No active tab";
    statusEl.textContent =
      "This page can't be analyzed. Open a normal website (http or https) and try again.";
    return;
  }

  siteEl.textContent = url;
  analyze(url);
});

// ---------------------------------------------------------------------------
// STEP 2: Fetch the site's headers and check each one.
// ---------------------------------------------------------------------------
async function analyze(url) {
  try {
    // We request the page ourselves. Because the manifest grants
    // host_permissions for all URLs, the browser lets us read the full set
    // of response headers (something ordinary web pages are not allowed to do).
    //
    // - method "GET": a normal request. Most reliable across servers.
    // - redirect "follow": if the site redirects (e.g. http -> https),
    //   follow it so we check the page you actually end up on.
    // - cache "no-store": don't use a saved copy; get the real, live headers.
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      cache: "no-store",
    });

    // response.headers is a lookup table of everything the server sent back.
    // For each header we care about, figure out three things:
    //   - status: "missing", "present", or "weak"
    //   - value:  what the server actually set it to (null if missing)
    //   - note:   why it was graded weak (only for weak CSPs)
    let presentCount = 0;

    for (const header of HEADERS) {
      // .get() returns the header's value, or null if it wasn't sent. Casing
      // doesn't matter, which is why our names above are all lowercase.
      const value = response.headers.get(header.name);

      let status = "missing";
      let note = "";

      if (value !== null) {
        presentCount++;
        status = "present";

        // If this header has a grading function (only CSP does), run it.
        // Any reasons it returns mean the header is present but weak.
        if (header.grade) {
          const reasons = header.grade(value);
          if (reasons.length > 0) {
            status = "weak";
            note = "Weak because it " + reasons.join("; ") + ".";
          }
        }
      }

      drawRow(header, status, value, note);
    }

    // A one-line summary at the bottom.
    statusEl.textContent = `${presentCount} of ${HEADERS.length} security headers present.`;
  } catch (error) {
    // Network errors, sites that block extension requests, etc. land here.
    statusEl.textContent =
      "Couldn't read this site's headers (the site may block extra requests). Error: " +
      error.message;
  }
}

// ---------------------------------------------------------------------------
// STEP 3: Build one result card and add it to the popup.
// ---------------------------------------------------------------------------
// This function creates the little bordered box for a single header. It takes:
//   - header: the entry from the HEADERS list (for its label and description).
//   - status: "present" (green), "weak" (yellow), or "missing" (red).
//   - value:  the header's actual value, or null if it's missing.
//   - note:   an optional extra line, e.g. why a CSP was graded weak.
function drawRow(header, status, value, note) {
  // The wording shown on the badge for each status.
  const badgeText = {
    present: "PRESENT",
    weak: "WEAK",
    missing: "MISSING",
  };

  // The outer card.
  const li = document.createElement("li");
  li.className = "result";

  // The top line: badge + header name.
  const head = document.createElement("div");
  head.className = "result-head";

  // The badge's CSS class (present/weak/missing) matches the status directly,
  // so the color follows automatically from popup.css.
  const badge = document.createElement("span");
  badge.className = "badge " + status;
  badge.textContent = badgeText[status];

  const name = document.createElement("span");
  name.textContent = header.label;

  head.appendChild(badge);
  head.appendChild(name);
  li.appendChild(head);

  // The plain-English explanation of what the header protects against.
  const desc = document.createElement("p");
  desc.className = "result-desc";
  desc.textContent = header.desc;
  li.appendChild(desc);

  // If the header was actually sent, show its real value in a monospace box.
  if (value !== null) {
    const valueEl = document.createElement("p");
    valueEl.className = "result-value";
    valueEl.textContent = value;
    li.appendChild(valueEl);
  }

  // If we graded it weak, explain why, right below the value.
  if (note) {
    const noteEl = document.createElement("p");
    noteEl.className = "result-note";
    noteEl.textContent = note;
    li.appendChild(noteEl);
  }

  // Drop the finished card into the results list.
  resultsEl.appendChild(li);
}
