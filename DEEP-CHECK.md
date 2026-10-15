# Deep Check — optional cloud lookup (STUB in v1.0.0)

## Design
Deep Check is an **opt-in, consent-gated** enhancement: instead of only local
heuristics, the extension may ask the DomainGuard API about a domain. The
contract is strict:

- Sent: **the registrable domain only** (e.g. `example.com`).
- Never sent: the full URL, path, query string, page title, page content,
  cookies, or any identifier.
- Default: **OFF**. Turning it on requires an explicit in-popup confirmation
  that states exactly what is sent.
- Revoking: switching it off stops all network calls immediately.

## Why it is a stub in v1.0.0
A cross-origin `fetch()` from an extension page requires a matching
`host_permissions` entry in the manifest. That entry is **deliberately not
included** in v1.0.0, because:

1. The v1 privacy story is "nothing ever leaves your device" — a host
   permission would weaken the listing and the review narrative.
2. The DomainGuard API endpoint for this lookup is not built yet.

So in v1.0.0 the toggle exists in the popup UI, explains what Deep Check
*would* do, asks for consent, then honestly reports that it is not wired yet
and stays off. No silent network calls are possible: without the host
permission, `fetch()` to the API origin throws.

## Wiring it later (v1.1+)
1. Build the server endpoint: `POST /api/lookalike-check` accepting
   `{ "domain": "example.com" }`, returning `{ verdict, signals[] }`.
2. Add to manifest.json:
   `"host_permissions": ["https://domain-guard-08k7.onrender.com/*"]`
3. Implement `deepCheckDomain(domain)` in popup.js:
   `fetch('https://domain-guard-08k7.onrender.com/api/lookalike-check',
   { method: 'POST', headers: { 'Content-Type': 'application/json' },
   body: JSON.stringify({ domain }) })`
4. Update PRIVACY.md + PERMISSIONS.md + store listing to disclose the new
   permission and exactly what is transmitted.

The stub function location is marked `DEEP-CHECK STUB` in popup.js.
