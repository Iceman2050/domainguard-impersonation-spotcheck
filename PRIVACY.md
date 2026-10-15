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
- Your **Deep Check preference** (off by default).
Both live in `chrome.storage.local` — on your device only. Uninstalling the
extension deletes them.

## What leaves your device
**Nothing** — unless you explicitly turn on Deep Check (off by default, with a
separate consent confirmation). Deep Check would send **only the domain name**
(e.g. `example.com`) to DomainGuard for a deeper lookup — never the full URL,
never page content. In v1.0.0 the Deep Check path is inert (it requires a
manifest host permission that is deliberately not included; see DEEP-CHECK.md).

## What we never do
- No analytics, no tracking pixels, no telemetry of any kind.
- No account, no sign-in, no identifiers.
- No access to browsing history, cookies, or page content.
- No remote code: all logic is bundled and `script-src` is pinned to `'self'`.

## Contact
Ingenious AI — https://domain-guard-08k7.onrender.com
