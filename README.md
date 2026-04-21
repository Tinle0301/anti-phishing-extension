# Anti-Phishing Login Detector

> **Companion repo — Attack Simulator:** [Tinle0301/aitmproj](https://github.com/Tinle0301/aitmproj) — contains the AiTM proxy and target app used to demonstrate the attacks this extension defends against.

A Chrome extension that detects suspicious login pages, with specific rules targeting **AiTM (Adversary-in-the-Middle) phishing kits** like **Sneaky 2FA**.

## How It Works

The extension runs a risk scoring engine on every page you visit. If a page scores 50 or above, it redirects you to a warning page before you can enter your credentials.

## Detection Signals

### Brand Impersonation
- Detects trusted brand names (Microsoft, Google, Okta, Apple) on untrusted domains
- Flags brand names embedded in the page `<title>` on non-brand domains
- Flags brand names embedded in the domain itself (e.g., `microsoft-login.xyz`)

### Sneaky 2FA / AiTM-Specific Signals
- **Base64-encoded email in URL** — Sneaky 2FA passes the victim's email as a base64 parameter to pre-fill the phishing form
- **Cloudflare Turnstile before login** — Sneaky 2FA uses Turnstile as an anti-bot gate before showing the credential form
- **Microsoft CDN hotlinking** — phishing kits load Microsoft's own CSS/fonts to look authentic
- **Login hint URL parameters** — `login_hint`, `username`, `email` passed in the URL (AiTM kits replicate this from real OAuth flows)

### URL & Domain Signals
- Random-looking URL paths (per-victim unique tokens)
- Punycode / lookalike hostnames
- Typosquatting (e.g., `micros0ft.com`, `0utlook.com`)
- Suspicious TLDs (`.xyz`, `.top`, `.tk`, `.gq`, etc.)
- Excessive subdomains (5+ levels)
- Login page served over HTTP

### Page Structure Signals
- Password fields and login forms
- Email pre-filled from URL query string or hash
- Login form posting to a different domain
- Hidden iframes
- Page reached through multiple redirects
- Suspicious text cues (verify, validate, session expired, MFA required, etc.)

## Risk Levels

| Score | Level    | Action               |
|-------|----------|----------------------|
| < 50  | Safe     | No action            |
| 50–74 | High     | Warning page shown   |
| 75+   | Critical | Warning page shown   |

## Warning Page Features

- Visual risk meter with colour coding
- List of specific reasons the page was flagged
- AiTM pattern notice when Sneaky 2FA-style techniques are detected
- **Go Back (Safe)** — returns to previous page
- **I trust this site** — whitelists the domain and continues (with confirmation dialog)

## Load in Chrome

1. Open `chrome://extensions/`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `anti-phishing-extension` folder

## Notes

- Test only on pages you control or a test environment replicating phishing behaviour.
- The whitelist is stored in `chrome.storage.local` and persists across browser sessions.
- The extension does not send any data externally — all analysis is done locally.
