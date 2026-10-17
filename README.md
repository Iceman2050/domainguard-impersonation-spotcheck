# domainguard-impersonation-spotcheck

**`paypaI.com` (capital i) vs `paypal.com` — your eyes can't reliably tell, and phishers know it.**

Homoglyphs, punycode, typosquats, hyphen-stuffed fakes: lookalike domains are the oldest phishing trick and still the most effective. This MV3 browser extension spot-checks any site you're on — entirely on-device, nothing sent anywhere.

## 30-second quickstart
```
chrome://extensions → Developer mode → Load unpacked → select this folder → click the toolbar icon on any site.
```

## Example output
```
paypaI.com -> MODERATE
[
 {
  "id": "typosquat",
  "text": "This domain is one character off \"paypal\" — a typosquatting pattern."
 }
]
google.com -> LOW
[]
```

User-initiated by design: `activeTab` permission only, no `<all_urls>`. See PERMISSIONS.md / PRIVACY.md / DEEP-CHECK.md for the review docs.

## Tests

The heuristics engine (`heuristics.js`) is pure functions — no DOM, no `chrome.*`, no network — so it runs under plain node:

```bash
node tests/test_heuristics.js
# 26/26 tests passed (exits 1 on the first failure)
```

Covers: confusable domains flagged (Cyrillic-а `paypal`, single-script lookalikes), suspicious TLDs flagged, typosquats and leet-substitutions (`paypaI.com`, `g00gle.com`), punycode, subdomain spoofing, keyword-stuffed brand slugs; and clean domains (`paypal.com`, `google.com`, hyphenated recipe blogs) NOT flagged. Registrable-domain extraction for two-part suffixes (`co.uk`, `com.au`) and levenshtein sanity included.

## What it does NOT do
Heuristic detection against a curated brand list — novel brands and targeted spear-phish domains may not match. It's a spot-check aid, not a phishing verdict.

## Built by Ingenious AI

This project is part of the **Ingenious AI** platform suite — defensive security tooling for the AI era. Our platforms are currently in early access (full launch Nov 1) — request access to any of them on WhatsApp:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
