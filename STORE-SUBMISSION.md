# Chrome Web Store submission — one-tap steps for Aldo

The extension is built, tested, and review-ready. Submitting needs YOUR Chrome
Web Store developer account — I can't create accounts.

## Step 1 — Developer account (one time, ~5 min)
1. Go to https://chrome.google.com/webstore/devconsole
2. Sign in with your Google account.
3. Pay the **one-time $5 developer registration fee** (Google's fee, not ours —
   flagging per your no-spend rule: this is the only cost; the listing itself is free).
4. Accept the developer agreement.

## Step 2 — Zip the extension
```bash
cd ~/workspace/extension/domainguard-lookalike
zip -r ../domainguard-lookalike-v1.0.0.zip . -x '*.DS_Store'
```

## Step 3 — New item
1. Developer Dashboard → **New Item** → upload the zip.
2. Fill the listing (copy-paste ready):
   - **Name:** DomainGuard — Impersonation Spot-Check
   - **Summary:** Know when a lookalike domain is wearing a trusted brand's face.
   - **Description:** Free browser extension from Ingenious AI. Click the icon on any site to spot-check its domain for lookalike impersonation tricks — mixed-script characters, punycode, typosquats, hyphen-stuffed fakes, suspicious domains. Shows a plain-language warning before you type credentials. All checks run on your device; nothing is sent anywhere. No account, no tracking.
   - **Category:** Productivity
   - **Language:** English
3. **Privacy tab:** paste the contents of `PRIVACY.md`. Data usage answers:
   - Does it collect user data? **No.**
   - Single purpose: "Spot-check the current site's domain for impersonation patterns, on-device."
   - Permissions justification: paste `PERMISSIONS.md`.
4. Upload screenshots: take 2–3 (popup on a test lookalike page + the warning banner). 1280×800 recommended.

## Step 4 — Submit for review
- Click **Submit for Review**. Typical review time: **a few hours to ~3 business days** for a minimal-permission extension with no host permissions.
- You get an email when it's live. Reply in chat when it publishes and I'll announce it across the traffic channels.

## After publish
- The listing links the DomainGuard platform — every install is a daily reminder of the product.
- v1.1 ideas (queued, not built): Deep Check wiring (see DEEP-CHECK.md), Firefox port, protected-brand editor UI.

## Honest limitations (already in the listing + in-extension "Why am I seeing this?")
- Catches common impersonation shapes, not targeted spear-phishing on clean domains.
- Can't verify who really owns a domain — similarity signals only.
- New phishing domains appear faster than any static list.
