# Privacy — DomainGuard Impersonation Spot-Check

**Short version: the extension collects nothing and sends nothing.**

## What runs where
Every check happens **on your device**. The extension compares the current
site's domain against impersonation patterns (lookalike characters, punycode,
typosquats, hyphen-stuffed fakes, suspicious top-level domains, subdomain
spoofing) using code bundled with the extension. No page you visit is reported
anywhere.

## What is stored
- Your **allowlist**: domains you marked "don't warn me again".
It lives in `chrome.storage.local` — on your device only. Uninstalling the
extension deletes it.

## What leaves your device
**Nothing.** The extension makes zero network calls — there is no server
component in v1.0.0.

## What we never do
- No analytics, no tracking pixels, no telemetry of any kind.
- No account, no sign-in, no identifiers.
- No access to browsing history, cookies, or page content.
- No remote code: all logic is bundled and `script-src` is pinned to `'self'`.

## Contact
Ingenious AI — https://domain-guard-08k7.onrender.com
