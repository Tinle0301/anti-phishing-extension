// ─────────────────────────────────────────────
//  background.js  –  Service Worker
// ─────────────────────────────────────────────

const WHITELIST_KEY = "trustedSites";

// Load the user's whitelisted sites from storage
async function getWhitelist() {
  return new Promise(resolve => {
    chrome.storage.local.get([WHITELIST_KEY], result => {
      resolve(result[WHITELIST_KEY] || []);
    });
  });
}

async function addToWhitelist(hostname) {
  const list = await getWhitelist();
  if (!list.includes(hostname)) {
    list.push(hostname);
    chrome.storage.local.set({ [WHITELIST_KEY]: list });
  }
}

function isWhitelisted(hostname, whitelist) {
  return whitelist.some(h => hostname === h || hostname.endsWith("." + h));
}

// ── Main message handler ──────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // ── Phishing analysis result from content script ──
  if (message.type === "PHISHING_ANALYSIS_RESULT") {
    const result = message.payload;

    if (result.risk < 50 || !sender.tab?.id) {
      sendResponse({ redirecting: false });
      return true;
    }

    // Check whitelist before warning
    getWhitelist().then(whitelist => {
      if (isWhitelisted(result.hostname, whitelist)) {
        sendResponse({ redirecting: false });
        return;
      }

      const warningUrl =
        chrome.runtime.getURL("warning.html") +
        `?url=${encodeURIComponent(result.url)}` +
        `&risk=${encodeURIComponent(result.risk)}` +
        `&hostname=${encodeURIComponent(result.hostname)}` +
        `&reasons=${encodeURIComponent(JSON.stringify(result.reasons))}`;

      chrome.tabs.update(sender.tab.id, { url: warningUrl });
      sendResponse({ redirecting: true });
    });

    return true; // keep message channel open for async response
  }

  // ── User chose "Trust this site" on the warning page ──
  if (message.type === "TRUST_SITE") {
    addToWhitelist(message.hostname);
    if (message.originalUrl && sender.tab?.id) {
      chrome.tabs.update(sender.tab.id, { url: message.originalUrl });
    }
    sendResponse({ ok: true });
    return true;
  }

  // ── User chose "Go back" on the warning page ──
  if (message.type === "GO_BACK") {
    if (sender.tab?.id) {
      chrome.tabs.goBack(sender.tab.id, () => {
        // If no history, navigate to new tab
        if (chrome.runtime.lastError) {
          chrome.tabs.update(sender.tab.id, { url: "chrome://newtab/" });
        }
      });
    }
    sendResponse({ ok: true });
    return true;
  }
});
