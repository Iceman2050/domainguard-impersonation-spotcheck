# Permissions — justification for every manifest permission

DomainGuard — Impersonation Spot-Check v1.0.0. Every permission below is the
minimum required for the feature it powers. No host permissions, no broad
URL access.

## `activeTab`
**Why:** Lets the popup read the URL of the tab you clicked the extension on,
so it can spot-check the site you are actually viewing. Access is granted only
for the active tab, only when you invoke the extension — the extension cannot
see any other tab, your history, or background tabs.
**Without it:** the extension could not know which site to check.

## `storage`
**Why:** Stores your allowlist ("don't warn me for this domain again") and your
Deep Check preference locally on your device via `chrome.storage.local`.
**Without it:** your trusted-domain choices would reset every browser restart.

## `scripting`
**Why:** Injects the bundled `banner.js` warning banner into the current page
when you tap "Show warning on this page". The injected file is bundled with the
extension — no remote code, ever.
**Without it:** no on-page warning banner.

## Deliberately NOT requested
- **No host permissions** (`<all_urls>` etc.): the extension never observes
  pages passively. v1 is a user-initiated spot-check — you click, it checks.
  This is the core privacy differentiator.
- **No `tabs` / history permission:** we never read your browsing history.
- **No `webRequest` / `declarativeNetRequest`:** we never see or modify traffic.
- **No `cookies`:** we never touch cookies.
- **No remote code:** `content_security_policy.extension_pages` pins
  `script-src 'self'`. All logic is bundled.
