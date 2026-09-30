# URL & Message Scanner

A Manifest V3 browser extension for checking URLs and messages for scam and phishing patterns. It works offline by default and supports optional Safe Browsing and VirusTotal checks.

## Features
- Popup scanner for a URL or a full message
- Local heuristic checks for risky URLs and scam messages
- Optional online threat checks via Google Safe Browsing and VirusTotal
- Context menu scanning for links and selected text
- Hover badge protection for links
- Best-effort message scanning buttons for common webmail and chat layouts
- Region-aware scam packs (global and India)
- Warning interstitial before opening a high-risk link
- Toolbar badge that shows a risk level for the current page using local heuristics only

## File structure
- manifest.json
- background.js
- content.js
- content.css
- popup.html
- popup.js
- popup.css
- options.html
- options.js
- lib/rules.js
- lib/scoring.js
- lib/intel.js
- lib/packs/global.js
- lib/packs/india.js
- icons/
- onboarding.html
- onboarding.js
- warning.html
- warning.js
- test.html

## Install steps
1. Download or clone this repository.
2. Open `chrome://extensions` in Chrome/Edge/Brave.
3. Turn on Developer mode.
4. Click `Load unpacked`.
5. Select this project folder.

## Why each permission is needed
- `contextMenus`: adds the right-click “Scan this link” and “Scan selected text” actions.
- `storage`: saves settings, selected region, warning toggle, and cached threat intel results.
- `activeTab`: allows the popup to scan the current active tab without broad permissions.
- `scripting`: lets the extension inject lightweight logic and page overlays where necessary.
- `notifications`: shows a desktop notification if a context-menu overlay cannot be injected.
- `host_permissions` for `safebrowsing.googleapis.com` and `www.virustotal.com`: required only for optional online lookups, not for general browsing.
- `content_scripts` with `<all_urls>`: required so the extension can detect links and add hover badges across pages. It does no network calls itself.

## Online checks
Online checks are disabled by default. To enable them:
1. Open the extension options page.
2. Turn on “Enable online threat check”.
3. Add your own Google Safe Browsing API key and/or VirusTotal API key.
4. Use “Test key” to confirm connectivity.
5. If a key fails, the extension keeps the local heuristic results and shows a clear warning.

This is intentionally safe by default and does not leak your private text to analytics or telemetry.

## Region packs
- Global: catches generic scam language and brand impersonation.
- India: adds patterns for KYC/account-blocked scams, UPI collection tricks, courier fraud, fake government impersonation, Telegram/job scams, loan-app harassment, and more.

## Warning interstitial
When the warning interstitial setting is enabled, the extension opens a warning page before navigating to a high-risk URL. The user can:
- Go back
- Proceed anyway

This is a user override and never silently blocks navigation.

## Hover protection
When enabled, hovering over links shows a tiny badge based on local heuristics only. This happens instantly without any network request. It also lightly outlines risky links and checks whether a visible link text appears to mismatch the destination.

## Privacy and security
- No analytics, no telemetry, no remote configuration.
- No `eval`, no inline scripts, no remote code.
- Content scripts avoid reading page text except when the user explicitly triggers a scan or selection.
- The extension uses `textContent` and DOM APIs instead of unsafe HTML injection with user-supplied content.
- It never fetches or follows the scanned URL itself.

## Firefox note
To port to Firefox:
- Change the manifest `browser_specific_settings` to include a Firefox ID if desired.
- Replace the background service worker format with a background script because Firefox historically uses non-module service workers less consistently.
- Check for API differences in `chrome.tabs.update` and `chrome.notifications` behavior.

## Manual QA checklist
1. Load the extension in Chrome/Edge/Brave.
2. Open the popup and scan a known safe link, such as `https://www.google.com/`.
3. Scan a suspicious URL such as `https://secure-login-updates-verify-account.co/verify`.
4. Paste a scam message, such as “Your SBI account is blocked. Verify your OTP now.”
5. Right-click a suspicious link and select “Scan this link”.
6. Highlight text in a page and select “Scan selected text”.
7. Open the `test.html` page and verify hover badges appear on risky links.
8. Toggle the warning interstitial in settings, then navigate to a suspicious URL to confirm the warning page opens.
9. Confirm the toolbar badge updates for risky vs safe pages.
10. Verify the extension does not trigger any network check when hover protection is active.

## Test page
Open `test.html` in a browser tab to test hover badge behavior on safe and suspicious example links.

## Disclaimer
This extension’s results are heuristic and informational only. They are not a guarantee of safety and should not be treated as legal, financial, or security advice.
