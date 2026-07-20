// tech.js — detects the site's tech stack from the page's DOM.
//
// A content script (runs inside the page, at document_idle so the DOM is ready).
// It reads only PUBLIC page markers — the <meta generator> tag, the URLs of the
// <script>/<link> resources the page loads, and a few tell-tale element ids —
// then reports the technologies it recognizes to the background worker (which
// stores them for the dashboard). It reads no personal data and no page cookies.

(function () {
  "use strict";

  // Declarative signatures. Each entry can match on any of:
  //   - generator: regex tested against the <meta name="generator"> content
  //   - url:       regex tested against all script/link resource URLs
  //   - selector:  a CSS selector whose presence proves the tech
  //   - attr:      an attribute whose presence anywhere proves the tech
  var SIGNATURES = [
    { name: "WordPress",  category: "CMS",             generator: /wordpress/i, url: /\/wp-(content|includes)\// },
    { name: "Drupal",     category: "CMS",             generator: /drupal/i,    url: /\/sites\/(default|all)\/(files|modules|themes)\// },
    { name: "Joomla",     category: "CMS",             generator: /joomla/i },
    { name: "Ghost",      category: "CMS",             generator: /ghost/i },
    { name: "Shopify",    category: "E-commerce",      url: /cdn\.shopify\.com/ },
    { name: "Wix",        category: "Website builder", generator: /wix\.com/i,  url: /static\.parastorage\.com/ },
    { name: "Squarespace",category: "Website builder", url: /static1\.squarespace\.com/ },
    { name: "Webflow",    category: "Website builder", generator: /webflow/i },
    { name: "Next.js",    category: "Framework",       selector: "#__next",     url: /\/_next\// },
    { name: "Nuxt.js",    category: "Framework",       selector: "#__nuxt",     url: /\/_nuxt\// },
    { name: "Gatsby",     category: "Framework",       selector: "#___gatsby" },
    { name: "Angular",    category: "Framework",       attr: "ng-version" },
    { name: "jQuery",     category: "JS library",      url: /jquery[-.\/]/ },
    { name: "Bootstrap",  category: "UI framework",    url: /bootstrap(\.min)?\.(css|js)/ },
    { name: "Google Tag Manager", category: "Analytics", url: /googletagmanager\.com/ },
    { name: "Google Analytics",   category: "Analytics", url: /google-analytics\.com|gtag\/js/ },
    { name: "Facebook Pixel",     category: "Analytics", url: /connect\.facebook\.net/ },
    { name: "Hotjar",             category: "Analytics", url: /static\.hotjar\.com/ },
  ];

  // Gather the public signals once.
  var generatorMeta = document.querySelector('meta[name="generator"]');
  var generator = generatorMeta ? generatorMeta.getAttribute("content") || "" : "";

  var urls = [];
  document.querySelectorAll("script[src], link[href]").forEach(function (el) {
    urls.push(el.getAttribute("src") || el.getAttribute("href") || "");
  });
  var urlBlob = urls.join(" ");

  // Match each signature; record the first kind of evidence that proves it.
  var detected = [];
  for (var i = 0; i < SIGNATURES.length; i++) {
    var sig = SIGNATURES[i];
    var evidence = "";
    if (sig.generator && sig.generator.test(generator)) evidence = "meta generator";
    else if (sig.url && sig.url.test(urlBlob)) evidence = "resource URL";
    else if (sig.selector && document.querySelector(sig.selector)) evidence = "page marker";
    else if (sig.attr && document.querySelector("[" + sig.attr + "]")) evidence = "page marker";
    if (evidence) detected.push({ name: sig.name, category: sig.category, evidence: evidence });
  }

  // Report to the background worker (which stores it for the dashboard). The
  // empty callback swallows the harmless "no receiver" error if it's asleep.
  if (detected.length) {
    try {
      chrome.runtime.sendMessage({ type: "techDetected", tech: detected }, function () {
        void chrome.runtime.lastError;
      });
    } catch (e) {}
  }
})();
