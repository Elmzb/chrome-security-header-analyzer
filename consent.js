// consent.js — the cookie-consent auto-rejecter ENGINE.
//
// This is a content script: it runs INSIDE web pages (not in the popup). It's
// declared in the manifest with all_frames:true, so a separate copy runs in the
// main page AND in every iframe — important because some consent banners
// (e.g. Sourcepoint) render inside an iframe.
//
// What it does: when a page loads, it hunts for a cookie-consent banner and
// clicks its "Reject all / Only necessary" button for you. It tries the known
// consent platforms first (from consent-rules.js), then a multilingual generic
// fallback. It watches for banners that appear a moment after load, digs
// through shadow DOM, and stops once it has acted (or after 15 seconds).

(function () {
  "use strict";

  var MAX_CLICKS = 2;        // a few sites stack two banners; allow a couple.
  var LIFETIME_MS = 15000;   // give up hunting after 15s to save CPU.
  var stopAt = Date.now() + LIFETIME_MS;
  var clicks = 0;
  var clickedEls = new WeakSet(); // never click the same element twice.

  // Content scripts may read chrome.storage.local (unlike session). Respect the
  // user's on/off setting; default ON.
  try {
    chrome.storage.local.get({ autoReject: true }, function (cfg) {
      if (chrome.runtime.lastError) { start(); return; }
      if (cfg.autoReject) start();
    });
  } catch (e) {
    start(); // storage unavailable for some reason — default to running.
  }

  // ----- DOM helpers --------------------------------------------------------

  // Collect the document AND every OPEN shadow root, recursively. Many modern
  // banners live inside a shadow DOM, which a normal querySelector can't see.
  function allRoots() {
    var roots = [document];
    var i = 0;
    while (i < roots.length) {
      var hosts = roots[i].querySelectorAll("*");
      for (var j = 0; j < hosts.length; j++) {
        if (hosts[j].shadowRoot) roots.push(hosts[j].shadowRoot);
      }
      i++;
    }
    return roots;
  }

  function isVisible(el) {
    if (!el) return false;
    var rects = el.getClientRects();
    if (!rects || rects.length === 0) return false;
    var style = getComputedStyle(el);
    return style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0";
  }

  function clickEl(el, cmpName) {
    if (!el || clickedEls.has(el) || !isVisible(el)) return false;
    clickedEls.add(el);
    try { el.click(); } catch (e) { return false; }
    clicks++;
    report(cmpName);
    return true;
  }

  // ----- Matching -----------------------------------------------------------

  // Try the known consent platforms first — the most reliable path.
  function tryKnown(roots) {
    for (var r = 0; r < roots.length; r++) {
      for (var c = 0; c < CONSENT_CMPS.length; c++) {
        var selectors = CONSENT_CMPS[c].reject;
        for (var s = 0; s < selectors.length; s++) {
          var el = null;
          try { el = roots[r].querySelector(selectors[s]); } catch (e) {}
          if (el && clickEl(el, CONSENT_CMPS[c].name)) return true;
        }
      }
    }
    return false;
  }

  // Generic fallback: scan clickable elements and click the first whose visible
  // label clearly means "reject".
  function tryGeneric(roots) {
    for (var r = 0; r < roots.length; r++) {
      var candidates = roots[r].querySelectorAll(
        'button, a[role="button"], [role="button"], input[type="button"], input[type="submit"], a'
      );
      for (var i = 0; i < candidates.length; i++) {
        var el = candidates[i];
        var label = el.getAttribute("aria-label") || el.value || el.textContent || "";
        if (consentIsRejectLabel(label) && clickEl(el, "generic")) return true;
      }
    }
    return false;
  }

  function sweep() {
    if (clicks >= MAX_CLICKS || Date.now() > stopAt) { stop(); return; }
    var roots = allRoots();
    if (tryKnown(roots)) return; // prefer a known CMP if present
    tryGeneric(roots);
  }

  // ----- Lifecycle ----------------------------------------------------------
  // Banners often appear a moment after load, so we (a) watch DOM changes and
  // (b) poll, for up to LIFETIME_MS. Sweeps from mutations are throttled so busy
  // pages don't cause a storm of scans.
  var observer = null, poll = null, pending = false;

  function scheduleSweep() {
    if (pending) return;
    pending = true;
    setTimeout(function () { pending = false; sweep(); }, 250);
  }

  function start() {
    sweep();
    try {
      observer = new MutationObserver(scheduleSweep);
      observer.observe(document.documentElement || document, { childList: true, subtree: true });
    } catch (e) {}
    poll = setInterval(sweep, 700);
    setTimeout(stop, LIFETIME_MS);
  }

  function stop() {
    if (observer) { observer.disconnect(); observer = null; }
    if (poll) { clearInterval(poll); poll = null; }
  }

  // Tell the background worker we handled a banner (it sets the ✓ badge and
  // records it for the popup). The empty callback swallows the harmless
  // "no receiver" error if the worker is briefly asleep.
  function report(cmpName) {
    try {
      chrome.runtime.sendMessage({ type: "consentHandled", cmp: cmpName }, function () {
        void chrome.runtime.lastError;
      });
    } catch (e) {}
  }
})();
