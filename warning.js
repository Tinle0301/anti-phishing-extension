// ─────────────────────────────────────────────
//  warning.js  –  Warning Page Logic
// ─────────────────────────────────────────────

const params = new URLSearchParams(window.location.search);
const originalUrl = params.get("url") || "";
const hostname    = params.get("hostname") || "";
const risk        = parseInt(params.get("risk") || "0", 10);
const reasons     = JSON.parse(params.get("reasons") || "[]");

// ── Populate risk score ──
document.getElementById("riskScore").textContent = risk;

// ── Colour-coded badge and meter ──
const badge = document.getElementById("riskBadge");
const fill  = document.getElementById("meterFill");

fill.style.width = `${Math.min(risk, 100)}%`;

if (risk >= 75) {
  badge.textContent = "CRITICAL RISK";
  badge.classList.add("badge-critical");
  fill.classList.add("fill-critical");
} else if (risk >= 50) {
  badge.textContent = "HIGH RISK";
  badge.classList.add("badge-high");
  fill.classList.add("fill-high");
} else {
  badge.textContent = "MEDIUM RISK";
  badge.classList.add("badge-medium");
  fill.classList.add("fill-medium");
}

// ── Blocked URL ──
const urlEl = document.getElementById("blockedUrl");
urlEl.textContent = originalUrl.length > 80
  ? originalUrl.slice(0, 80) + "…"
  : originalUrl;
urlEl.title = originalUrl;

// ── Reasons list ──
const list = document.getElementById("reasonsList");
reasons.forEach(reason => {
  const li = document.createElement("li");
  li.textContent = reason;
  list.appendChild(li);
});

// ── Show AiTM box if relevant signals detected ──
const aitmSignals = [
  "aitm", "sneaky", "turnstile", "base64", "hotlinking",
  "pre-filled", "prefilled", "login hint", "microsoft cdn",
  "href.li", "relay", "autograb"
];
const aitmMatch = reasons.some(r =>
  aitmSignals.some(s => r.toLowerCase().includes(s))
);
if (aitmMatch) {
  document.getElementById("aitmBox").style.display = "block";
  // Also show MFA education when AiTM is detected
  document.getElementById("mfaBox").style.display = "block";
}

// ── Go Back button ──
document.getElementById("btnGoBack").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "GO_BACK" });
});

// ── Trust this site button ──
document.getElementById("btnTrust").addEventListener("click", () => {
  const confirmed = window.confirm(
    `Are you sure you want to trust "${hostname}"?\n\nOnly do this if you are absolutely certain this is a legitimate site.`
  );
  if (confirmed) {
    chrome.runtime.sendMessage({
      type: "TRUST_SITE",
      hostname: hostname,
      originalUrl: originalUrl
    });
  }
});
