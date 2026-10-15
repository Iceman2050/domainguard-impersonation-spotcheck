# DomainGuard — Impersonation Spot-Check (Chrome extension, MV3)

Free browser extension from Ingenious AI. Click the icon on any site to
spot-check its domain for lookalike impersonation tricks — homoglyphs,
punycode, typosquats, hyphen-stuffed fakes, suspicious TLDs, subdomain
spoofing. All checks run **on your device**; nothing is sent anywhere.

## Files
- `manifest.json` — MV3, permissions: `activeTab`, `storage`, `scripting` only.
- `heuristics.js` — pure local detection engine (shared, node-testable).
- `brands.json` — curated commonly-impersonated brand list (local only).
- `popup.html` / `popup.css` / `popup.js` — spot-check UI, allowlist, Deep Check toggle (inert stub).
- `banner.js` — dismissible on-page warning banner (bundled, injected via `chrome.scripting`).
- `icons/` — shield icons (PNG for the manifest + SVG sources).
- `PERMISSIONS.md` / `PRIVACY.md` / `DEEP-CHECK.md` — review-facing docs.
- `STORE-SUBMISSION.md` — Aldo's one-tap submission steps.

## Load unpacked (dev)
1. Open `chrome://extensions`, enable Developer mode.
2. "Load unpacked" → select this folder.
3. Click the toolbar icon on any site to spot-check it.

## Design decisions (deviations from the original spec, all deliberate)
- **User-initiated, not passive:** the spec imagined badge states on every page
  load; that requires `<all_urls>` host permission. v1 ships `activeTab` only —
  you click, it checks. This is the privacy differentiator and the reason the
  Web Store "permissions justification" should pass cleanly.
- **Deep Check is an honest stub:** toggle + consent UI exist, but no network
  call is possible without a host permission that is deliberately excluded.
  See DEEP-CHECK.md for the v1.1 wiring plan.

## Safety invariants (do not regress)
- No `eval`, no `new Function`, no remote code, no analytics, no tracking.
- `content_security_policy.extension_pages`: `script-src 'self'`.
- Only two external URLs exist in the whole codebase, both Ingenious AI:
  `https://domain-guard-08k7.onrender.com` and
  `https://ingeniousai-security-checks.netlify.app/domain-check.html`.
