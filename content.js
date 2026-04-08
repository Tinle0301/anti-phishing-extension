// ─────────────────────────────────────────────
//  content.js  –  Detection trigger & DOM watcher
// ─────────────────────────────────────────────

const DEBOUNCE_MS = 600;
let debounceTimer = null;
let lastRisk = 0;
let alreadyWarned = false;

function runAnalysis() {
  // Don't re-warn if we already triggered for this page
  if (alreadyWarned) return;

  const result = calculateRisk();

  // Only send if risk increased meaningfully (avoids spam on minor DOM changes)
  if (result.risk >= 50 && result.risk > lastRisk) {
    lastRisk = result.risk;
    chrome.runtime.sendMessage({
      type: "PHISHING_ANALYSIS_RESULT",
      payload: result
    }, (response) => {
      if (response && response.redirecting) {
        alreadyWarned = true;
      }
    });
  }
}

// Initial analysis at document_idle
runAnalysis();

// ── MutationObserver: re-run when the DOM changes ──
// Important for React/SPA login pages (e.g. Microsoft's login flow) that
// render forms dynamically and for Sneaky 2FA pages that inject fields late.
const observer = new MutationObserver(() => {
  if (alreadyWarned) {
    observer.disconnect();
    return;
  }
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(runAnalysis, DEBOUNCE_MS);
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: false  // attributes off to reduce noise
});

// ── Stop watching once the page is fully stable ──
window.addEventListener("load", () => {
  // Give the page 3 seconds to finish any JS rendering, then do a final check
  setTimeout(() => {
    runAnalysis();
    observer.disconnect();
  }, 3000);
});
