// ─────────────────────────────────────────────
//  detector.js  –  Anti-Phishing Risk Engine
//  Improved with Sneaky 2FA / AiTM detection
// ─────────────────────────────────────────────

function getHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); }
  catch { return ""; }
}

function isTrustedHost(hostname) {
  const trustedDomains = [
    "microsoft.com", "login.microsoftonline.com", "microsoftonline.com",
    "office.com", "live.com", "outlook.com",
    "google.com", "accounts.google.com", "gmail.com",
    "okta.com", "apple.com", "appleid.apple.com",
    "github.com", "linkedin.com", "facebook.com"
  ];
  return trustedDomains.some(d => hostname === d || hostname.endsWith("." + d));
}

// ── Sneaky 2FA: email can be passed as plain text OR base64 in the URL ──
function emailPrefilledFromUrl() {
  try {
    const url = new URL(window.location.href);
    const raw = `${url.search} ${url.hash}`;
    const emailInput = document.querySelector(
      "input[type='email'], input[name*='email'], input[id*='email'], input[name*='login'], input[name*='username']"
    );
    if (!emailInput) return false;
    const val = (emailInput.value || "").toLowerCase().trim();
    if (!val) return false;

    // Plain-text match
    if (raw.toLowerCase().includes(val)) return true;

    // Base64-encoded match (Sneaky 2FA specific technique)
    try {
      const decoded = atob(raw.replace(/[^A-Za-z0-9+/=]/g, "")).toLowerCase();
      if (decoded.includes(val)) return true;
    } catch { /* not valid base64 */ }

    // Check individual query params for base64 email
    for (const [, v] of url.searchParams) {
      try {
        const decoded = atob(v).toLowerCase();
        if (decoded.includes("@") && decoded.includes(val)) return true;
      } catch { /* not base64 */ }
    }
  } catch { /* bad URL */ }
  return false;
}

// ── Microsoft login_hint / username_hint param (AiTM kits copy this) ──
function hasLoginHintParam() {
  try {
    const url = new URL(window.location.href);
    return url.searchParams.has("login_hint") ||
           url.searchParams.has("username") ||
           url.searchParams.has("email") ||
           url.searchParams.has("user");
  } catch { return false; }
}

function looksRandomPath(pathname) {
  if (!pathname) return false;
  const segments = pathname.split("/").filter(Boolean);
  return segments.some(seg => {
    if (seg.length < 20) return false;
    const alnumRatio = (seg.match(/[a-zA-Z0-9]/g) || []).length / seg.length;
    return alnumRatio > 0.85;
  });
}

function hasCaptchaOrTurnstile() {
  const html = document.documentElement.innerHTML.toLowerCase();
  return Boolean(
    html.includes("turnstile") ||
    html.includes("cf-turnstile") ||
    html.includes("g-recaptcha") ||
    html.includes("recaptcha") ||
    document.querySelector('iframe[src*="captcha"], iframe[src*="turnstile"], iframe[src*="challenges.cloudflare"]')
  );
}

// ── Sneaky 2FA: Turnstile appears BEFORE the login form ──
function hasTurnstileBeforeLogin() {
  const turnstile = document.querySelector(
    '[class*="turnstile"], [id*="turnstile"], .cf-turnstile, iframe[src*="challenges.cloudflare"]'
  );
  const loginForm = document.querySelector("form input[type='password']");
  if (!turnstile || loginForm) return false; // Turnstile before password form = very suspicious
  return true;
}

function hasLoginForm() {
  return Boolean(document.querySelector("form input[type='password']"));
}

function hasPasswordField() {
  return Boolean(document.querySelector("input[type='password']"));
}

function hasHiddenIframe() {
  return Array.from(document.querySelectorAll("iframe")).some(frame => {
    const style = window.getComputedStyle(frame);
    return style.display === "none" ||
           style.visibility === "hidden" ||
           parseInt(frame.width) === 0 ||
           parseInt(frame.height) === 0 ||
           parseInt(style.width) === 0 ||
           parseInt(style.height) === 0;
  });
}

function getBrandSignals() {
  const text = (document.body?.innerText || "").toLowerCase();
  const title = document.title.toLowerCase();
  const combined = text + " " + title;
  const brands = [
    "microsoft", "office 365", "office365", "microsoft 365",
    "outlook", "teams", "onedrive", "sharepoint",
    "google", "gmail", "google workspace",
    "okta", "apple", "icloud"
  ];
  return brands.filter(b => combined.includes(b));
}

// ── Brand name in <title> but domain is untrusted ──
function brandInTitleNotTrusted(hostname) {
  if (isTrustedHost(hostname)) return false;
  const title = document.title.toLowerCase();
  const brands = ["microsoft", "office", "outlook", "teams", "google", "okta", "apple"];
  return brands.some(b => title.includes(b));
}

function suspiciousKeywords() {
  const text = (document.body?.innerText || "").toLowerCase();
  const keywords = ["verify your identity", "verify", "validate", "session expired",
                    "confirm your password", "security check", "mfa", "two-factor",
                    "two factor", "authentication required", "sign in to continue"];
  return keywords.filter(k => text.includes(k));
}

function punycodeOrLookalike(hostname) {
  return hostname.includes("xn--");
}

// ── Typosquatting check: domains that look like known brands ──
function isTyposquatting(hostname) {
  const typoPatterns = [
    /micros[0o]ft/i, /mircosoft/i, /microsofft/i, /microsooft/i,
    /m1crosoft/i, /micr0soft/i,
    /0utlook/i, /outl00k/i, /0utl00k/i,
    /g[0o]{2}gle/i, /g00gle/i, /googl3/i,
    /0kta/i, /0kt4/i,
    /app1e/i, /appl3/i,
    /1inkedin/i, /linkedln/i
  ];
  return typoPatterns.some(p => p.test(hostname));
}

// ── Suspicious TLDs common in phishing campaigns ──
function hasSuspiciousTLD(hostname) {
  const suspiciousTLDs = [
    ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".ga", ".cf",
    ".pw", ".rest", ".icu", ".monster", ".cyou", ".bar", ".sbs", ".bond"
  ];
  return suspiciousTLDs.some(tld => hostname.endsWith(tld));
}

// ── Too many subdomains (e.g., login.secure.verify.microsoft.com.evil.com) ──
function hasTooManySubdomains(hostname) {
  return hostname.split(".").length >= 5;
}

// ── Domain impersonation: brand name appears IN the domain but isn't the brand ──
function brandInDomainNotTrusted(hostname) {
  if (isTrustedHost(hostname)) return false;
  const brands = ["microsoft", "outlook", "office", "office365", "google", "okta", "apple", "icloud"];
  return brands.some(b => hostname.includes(b));
}

// ── HTTPS check – login pages should always be HTTPS ──
function isNotHttps() {
  return window.location.protocol !== "https:";
}

// ── Form action points to a suspicious/external URL ──
function hasSuspiciousFormAction() {
  const forms = Array.from(document.querySelectorAll("form"));
  return forms.some(form => {
    const action = form.action || "";
    if (!action || action === "" || action.startsWith(window.location.origin)) return false;
    try {
      const actionHost = new URL(action).hostname;
      const pageHost = new URL(window.location.href).hostname;
      return actionHost !== pageHost;
    } catch { return false; }
  });
}

// ── Multiple redirects before landing here (common in AiTM chains) ──
function hasMultipleRedirects() {
  try {
    const entries = performance.getEntriesByType("navigation");
    if (entries.length > 0) {
      return entries[0].redirectCount >= 2;
    }
  } catch { /* not supported */ }
  return false;
}

// ── Resources loaded from Microsoft domains on a non-Microsoft page ──
// Phishing kits often hotlink MS CSS/fonts to look convincing
function loadsMicrosoftResources(hostname) {
  if (isTrustedHost(hostname)) return false;
  const html = document.documentElement.innerHTML;
  return html.includes("logincdn.msftauth.net") ||
         html.includes("aadcdn.msftauth.net") ||
         html.includes("aadcdn.msauth.net") ||
         html.includes("msftauthimages.net") ||
         html.includes("secure.aadcdn.microsoftonline-p.com");
}

// ── Sneaky 2FA: suspicious auth-like path patterns ──
// Sekoia observed paths like /auth/, /verify, /validate, /index on compromised sites
function hasSuspiciousAuthPath(pathname, hostname) {
  if (isTrustedHost(hostname)) return false;
  const lower = pathname.toLowerCase();

  // Exact or trailing match on known kit endpoint names
  const suspiciousPaths = ["/verify", "/validate", "/auth", "/index", "/login", "/signin", "/secure"];
  const exactMatch = suspiciousPaths.some(p =>
    lower === p || lower === p + "/" || lower.startsWith(p + "/") || lower.startsWith(p + "?")
  );
  if (exactMatch) return true;

  // Compromised WordPress site pattern: wp path + auth-like subdirectory
  if (lower.includes("/wp-") && suspiciousPaths.some(p => lower.includes(p))) return true;

  return false;
}

// ── Very long URL path (150+ chars) = per-victim unique token ──
// Sekoia specifically called out ~150-char random paths in Sneaky 2FA
function hasVeryLongPath(pathname) {
  return pathname.length > 100;
}

// ── href.li redirect detection ──
// Sneaky 2FA uses href.li to redirect bots/scanners to innocent pages (e.g. Wikipedia)
// If document.referrer comes from href.li, the real victim was redirected through it
function cameViaHrefLi() {
  return document.referrer.includes("href.li") ||
         window.location.href.includes("href.li");
}

// ── Page obfuscation signals ──
// Sneaky 2FA obfuscates pages with: base64 images, broken-up HTML text, junk content
function hasObfuscationSignals() {
  const html = document.documentElement.innerHTML;

  // Large inline base64 blobs (>500 chars of base64 in src= attributes)
  const base64ImgMatches = html.match(/src="data:image\/[^;]+;base64,[A-Za-z0-9+/=]{500,}"/g);
  if (base64ImgMatches && base64ImgMatches.length > 3) return true;

  // Excessively long single-line script content (obfuscated JS)
  const scripts = Array.from(document.querySelectorAll("script:not([src])"));
  const hasObfuscatedScript = scripts.some(s => {
    const src = s.textContent || "";
    // Obfuscated JS often has very long strings of hex/base64 encoded content
    return src.length > 5000 && (
      src.includes("\\x") ||
      /[A-Za-z0-9+/=]{200,}/.test(src)
    );
  });
  if (hasObfuscatedScript) return true;

  // Excessive hidden elements (junk HTML to confuse scanners)
  const hiddenEls = document.querySelectorAll(
    '[style*="display:none"], [style*="display: none"], [style*="visibility:hidden"]'
  );
  if (hiddenEls.length > 10) return true;

  return false;
}

// ── Main scoring function ──
function calculateRisk() {
  const hostname = getHostname(window.location.href);
  const trusted = isTrustedHost(hostname);
  const brands = getBrandSignals();
  const suspiciousWords = suspiciousKeywords();

  let risk = 0;
  const reasons = [];

  // ── Base signals ──────────────────────────────────────────
  if (hasPasswordField()) {
    risk += 20;
    reasons.push("Password field detected");
  }
  if (hasLoginForm()) {
    risk += 10;
    reasons.push("Login form detected");
  }

  // ── Brand impersonation ───────────────────────────────────
  if (brands.length > 0 && !trusted) {
    risk += 30;
    reasons.push(`Brand impersonation on untrusted host: ${brands.slice(0, 3).join(", ")}`);
  }
  if (brandInTitleNotTrusted(hostname)) {
    risk += 20;
    reasons.push("Trusted brand name in page title on untrusted domain");
  }
  if (brandInDomainNotTrusted(hostname)) {
    risk += 25;
    reasons.push("Trusted brand name embedded in domain (not the real brand)");
  }

  // ── Sneaky 2FA / AiTM specific ────────────────────────────
  if (hasTurnstileBeforeLogin()) {
    risk += 25;
    reasons.push("Cloudflare Turnstile challenge before login form (Sneaky 2FA pattern)");
  } else if (hasCaptchaOrTurnstile()) {
    risk += 15;
    reasons.push("CAPTCHA/Turnstile present before login");
  }
  if (emailPrefilledFromUrl()) {
    risk += 20;
    reasons.push("Email pre-filled from URL (plain text or base64 — AiTM phishing technique)");
  }
  if (hasLoginHintParam()) {
    risk += 15;
    reasons.push("Login hint / email passed as URL parameter (common in phishing links)");
  }
  if (loadsMicrosoftResources(hostname)) {
    risk += 30;
    reasons.push("Page loads Microsoft CDN resources on non-Microsoft domain (kit hotlinking)");
  }

  // ── URL/domain signals ────────────────────────────────────
  if (looksRandomPath(window.location.pathname)) {
    risk += 10;
    reasons.push("Random-looking URL path (unique token per victim)");
  }
  if (hasVeryLongPath(window.location.pathname)) {
    risk += 15;
    reasons.push("Unusually long URL path (100+ chars — per-victim tracking token, Sneaky 2FA pattern)");
  }
  if (hasSuspiciousAuthPath(window.location.pathname, hostname)) {
    risk += 20;
    reasons.push("Suspicious auth-like URL path (/verify, /validate, /auth) on non-trusted domain");
  }
  if (punycodeOrLookalike(hostname)) {
    risk += 20;
    reasons.push("Punycode/lookalike hostname detected");
  }
  if (isTyposquatting(hostname)) {
    risk += 30;
    reasons.push("Hostname resembles a known brand (typosquatting)");
  }
  if (hasSuspiciousTLD(hostname)) {
    risk += 15;
    reasons.push("Suspicious top-level domain commonly used in phishing");
  }
  if (hasTooManySubdomains(hostname)) {
    risk += 15;
    reasons.push("Unusually many subdomains (domain impersonation technique)");
  }
  if (isNotHttps()) {
    risk += 25;
    reasons.push("Login page served over HTTP, not HTTPS");
  }
  if (cameViaHrefLi()) {
    risk += 25;
    reasons.push("Page accessed via href.li redirect (Sneaky 2FA uses this to hide phishing URLs from scanners)");
  }

  // ── Page structure signals ────────────────────────────────
  if (hasHiddenIframe()) {
    risk += 10;
    reasons.push("Hidden iframe detected");
  }
  if (hasSuspiciousFormAction()) {
    risk += 20;
    reasons.push("Login form submits to a different domain");
  }
  if (hasMultipleRedirects()) {
    risk += 10;
    reasons.push("Page reached through multiple redirects");
  }
  if (hasObfuscationSignals()) {
    risk += 20;
    reasons.push("Page contains obfuscation (large base64 blobs, encoded JS, or excessive hidden elements)");
  }
  if (suspiciousWords.length >= 2) {
    risk += 10;
    reasons.push(`Suspicious text cues: ${suspiciousWords.slice(0, 3).join(", ")}`);
  }

  return {
    url: window.location.href,
    hostname,
    trusted,
    risk: Math.min(risk, 100),
    reasons
  };
}
