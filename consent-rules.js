// consent-rules.js — the knowledge base for the cookie-consent auto-rejecter.
//
// This is loaded as a content script BEFORE consent.js, so it simply defines a
// few globals that consent.js reads. Content scripts are classic scripts (not
// ES modules), so there are no imports here — just plain `var` globals.
//
// Keeping the *rules* separate from the *engine* means you can add support for
// a new consent platform by editing only this file.

// ---------------------------------------------------------------------------
// 1) KNOWN CONSENT PLATFORMS (CMPs)
// ---------------------------------------------------------------------------
// A "CMP" is the cookie-consent system a site uses. Each has a recognizable
// "Reject all / Only necessary" button. For every CMP we list CSS selectors for
// that button; the engine clicks the first visible one it finds. (Selectors
// that live inside a shadow DOM are found by the engine's shadow-piercing
// search, so they work here too.)
var CONSENT_CMPS = [
  { name: "OneTrust",     reject: ["#onetrust-reject-all-handler", ".ot-pc-refuse-all-handler"] },
  { name: "Cookiebot",    reject: ["#CybotCookiebotDialogBodyButtonDecline", "#CybotCookiebotDialogBodyLevelButtonLevelOptinDeclineAll"] },
  { name: "Didomi",       reject: ["#didomi-notice-disagree-button", "button.didomi-continue-without-agreeing"] },
  { name: "Quantcast",    reject: [".qc-cmp2-summary-buttons button[mode=\"secondary\"]"] },
  { name: "Usercentrics", reject: ["button[data-testid=\"uc-deny-all-button\"]", "#uc-btn-deny-banner"] },
  { name: "Sourcepoint",  reject: ["button.sp_choice_type_REJECT_ALL", "button[title=\"Reject All\"]", "button[aria-label=\"Reject All\"]"] },
  { name: "Osano",        reject: [".osano-cm-denyAll", ".osano-cm-button--type_denyAll"] },
  { name: "CookieYes",    reject: [".cky-btn-reject"] },
  { name: "Complianz",    reject: [".cmplz-deny", ".cc-deny"] },
  { name: "Termly",       reject: ["[data-tid=\"banner-decline\"]"] },
  { name: "Klaro",        reject: [".cm-btn-decline", ".cn-decline"] },
  { name: "Borlabs",      reject: ["a.brlbs-btn-refuse-all", "._brlbs-refuse-all"] },
  { name: "CookieNotice", reject: ["#cn-refuse-cookie"] },
  { name: "MooveGDPR",    reject: [".moove-gdpr-infobar-reject-btn"] },
];

// ---------------------------------------------------------------------------
// 2) GENERIC FALLBACK (multilingual)
// ---------------------------------------------------------------------------
// When none of the known CMP selectors match, the engine looks at the text of
// every clickable element and clicks the first one that clearly means "reject".
// Anchored to the START of the label (with a word boundary) so "Reject all
// cookies" matches, but a paragraph merely containing the word "reject" doesn't.
var CONSENT_REJECT_TEXT =
  /^\W*(reject all|reject non[- ]?essential|reject|decline all|decline|refuse all|refuse|deny all|deny|disagree|do not (?:accept|consent)|don'?t (?:accept|consent)|only necessary|necessary only|essentials? only|continue without accepting|alle ablehnen|ablehnen|nur (?:erforderliche|notwendige)|tout refuser|refuser|continuer sans accepter|rechazar(?: todo)?|solo (?:las )?necesarias|rifiuta(?: tutto)?|alles weigeren|weigeren|afwijzen)\b/i;

// A safety guard: never treat a clear "accept/agree" button as a reject.
var CONSENT_ACCEPT_TEXT =
  /^\W*(accept all|accept|agree|allow all|allow|got it|ok(?:ay)?|alle akzeptieren|akzeptieren|zustimmen|aceptar|tout accepter|accepter|j'accepte)\b/i;

// Pure helper (no DOM) so it can be unit-tested on its own: does this button
// label mean "reject"? Ignores very long strings (those are paragraphs, not
// buttons) and anything that looks like an accept button.
function consentIsRejectLabel(text) {
  var t = (text || "").replace(/\s+/g, " ").trim();
  if (!t || t.length > 40) return false;
  if (CONSENT_ACCEPT_TEXT.test(t)) return false;
  return CONSENT_REJECT_TEXT.test(t);
}
