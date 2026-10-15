/* DomainGuard — Impersonation Spot-Check: local heuristics engine.
 * Pure functions only: no DOM, no chrome.* APIs, no network.
 * Safe to load in popup, content script, or node tests. */

'use strict';

/* Unicode confusables: Latin chars -> lookalike code points attackers use. */
const CONFUSABLES = {
  a: ['\u0430', '\u0251'],          // Cyrillic а, Latin alpha
  b: ['\u042c', '\u0431'],          // Cyrillic soft sign lookalikes
  c: ['\u0441', '\u03f2'],          // Cyrillic с, lunate sigma
  d: ['\u0501'],
  e: ['\u0435', '\u025b'],          // Cyrillic е
  g: ['\u0261'],
  h: ['\u04bb'],
  i: ['\u0456', '\u0131', '\u03b9'], // Cyrillic і, dotless ı, Greek iota
  j: ['\u0458'],
  k: ['\u03ba'],                    // Greek kappa
  l: ['\u04cf', '1', '\u0399'],     // Cyrillic palochka, Greek iota
  m: ['\u043c'],                    // Cyrillic м
  n: ['\u043f', '\u03b7'],          // Cyrillic п, Greek eta
  o: ['\u043e', '\u03bf', '0'],     // Cyrillic о, Greek omicron
  p: ['\u0440', '\u03c1'],          // Cyrillic р, Greek rho
  q: ['\u051b'],
  r: ['\u0433'],
  s: ['\u0455'],
  t: ['\u0442', '\u03c4'],          // Cyrillic т, Greek tau
  u: ['\u03c5'],                    // Greek upsilon
  v: ['\u03bd', '\u0475'],          // Greek nu
  w: ['\u051d'],
  x: ['\u0445', '\u03c7'],          // Cyrillic х, Greek chi
  y: ['\u0443', '\u03b3'],          // Cyrillic у, Greek gamma
  z: ['\u0290'],
  0: ['o', '\u043e', '\u03bf'],
  1: ['l', '\u0456', '\u04cf'],
  5: ['\u0455'],
  6: ['\u0431']
};

const CONFUSABLE_SET = new Set();
for (const k of Object.keys(CONFUSABLES)) {
  for (const c of CONFUSABLES[k]) {
    // Only non-ASCII lookalikes count: plain ASCII letters/digits are not
    // attacker confusables (e.g. the letter "l" must not flag paypal.com).
    if (c.codePointAt(0) > 127) CONFUSABLE_SET.add(c);
  }
}

/* TLDs disproportionately abused in phishing (public threat-report consensus). */
const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'click', 'link', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq',
  'buzz', 'cam', 'date', 'faith', 'loan', 'men', 'party', 'racing', 'review',
  'science', 'stream', 'trade', 'win', 'download', 'lol', 'sbs', 'quest',
  'dad', 'prof', 'rest', 'country', 'kim', 'cricket', 'work', 'bid'
]);

/* Common two-label public suffixes so registrable-domain extraction is sane. */
const TWO_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'com.br', 'com.mx', 'com.ar', 'com.co',
  'co.jp', 'co.kr', 'co.in', 'co.nz', 'co.za', 'co.il', 'com.sg', 'com.hk',
  'com.tr', 'com.tw', 'co.th', 'com.ph', 'com.my', 'com.vn', 'co.id'
]);

function getRegistrableDomain(hostname) {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.has(lastTwo) && parts.length > 2) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array(n + 1);
  let cur = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    const t = prev; prev = cur; cur = t;
  }
  return prev[n];
}

function scriptOf(ch) {
  const cp = ch.codePointAt(0);
  if (cp >= 0x0400 && cp <= 0x04FF) return 'cyrillic';
  if ((cp >= 0x0370 && cp <= 0x03FF) || (cp >= 0x1F00 && cp <= 0x1FFF)) return 'greek';
  if ((cp >= 0x0041 && cp <= 0x005A) || (cp >= 0x0061 && cp <= 0x007A) || (cp >= 0x0030 && cp <= 0x0039)) return 'latin';
  return 'other';
}

/* Common leet-speak substitutions attackers use to dodge naive brand matching. */
const LEET = { '0': 'o', '1': 'l', '5': 's', '3': 'e', '7': 't', '@': 'a', '$': 's', '!': 'i' };
function deleet(s) {
  return s.split('').map(c => LEET[c] || c).join('');
}

/* Analyze one registrable domain. Returns {score, verdict, signals[], brand}. */
function analyzeDomain(hostname, brands) {
  const signals = [];
  const domain = getRegistrableDomain(hostname);
  const labels = domain.split('.');
  const tld = labels[labels.length - 1];
  const sld = labels.length >= 2 ? labels[labels.length - 2] : domain;
  let score = 0;
  let brand = null;

  // 1. Punycode — internationalized label hiding non-Latin chars.
  if (labels.some(l => l.startsWith('xn--'))) {
    score += 3;
    signals.push({ id: 'punycode', text: 'This domain uses punycode (xn--) — a common way to hide non-Latin characters that look like Latin ones.' });
  }

  // 2. Mixed-script label — Latin mixed with Cyrillic/Greek in one label.
  for (const label of labels) {
    const scripts = new Set();
    for (const ch of label) {
      const s = scriptOf(ch);
      if (s !== 'other') scripts.add(s);
    }
    if (scripts.has('latin') && (scripts.has('cyrillic') || scripts.has('greek'))) {
      score += 3;
      signals.push({ id: 'mixed-script', text: 'A part of this domain mixes Latin letters with Cyrillic or Greek letters — a classic impersonation trick (e.g. "pаypal" with a Cyrillic а).' });
      break;
    }
  }

  // 3. Confusable characters present (single-script but suspicious lookalikes).
  let confusableFound = false;
  for (const ch of sld) {
    if (CONFUSABLE_SET.has(ch)) { confusableFound = true; break; }
  }
  if (confusableFound && !signals.some(s => s.id === 'mixed-script')) {
    score += 2;
    signals.push({ id: 'confusable', text: 'This domain contains characters that are visually identical to common Latin letters but come from another alphabet.' });
  }

  // 4. Brand similarity — typosquat (edit distance) or keyword stuffing.
  // Brand comparison runs on a leet-normalized copy so g00gle -> google.
  const sldAlpha = sld.replace(/[^a-z0-9]/g, '');
  const sldNorm = deleet(sldAlpha);
  for (const b of brands) {
    const d = levenshtein(sldNorm, b);
    if (d === 0 && sldAlpha !== b && b.length >= 3) {
      // Exact brand name reached only via leet substitution: g00gle.com.
      score += 3;
      brand = b;
      signals.push({ id: 'typosquat', text: 'This domain spells "' + b + '" using lookalike characters (e.g. 0 for o) — a typosquatting pattern.' });
      break;
    }
    if (d > 0 && d <= 1 && sldAlpha.length >= 3) {
      score += 3;
      brand = b;
      signals.push({ id: 'typosquat', text: 'This domain is one character off "' + b + '" — a typosquatting pattern.' });
      break;
    }
    if (d === 2 && sldAlpha.length >= 5 && !brand) {
      score += 2;
      brand = b;
      signals.push({ id: 'typosquat2', text: 'This domain is two characters off "' + b + '" — close enough to fool a quick glance.' });
    }
  }
  if (!brand) {
    for (const b of brands) {
      if (sldNorm.length > b.length + 2 && sldNorm.includes(b)) {
        const extra = sldNorm.replace(b, '');
        // Trigger words (login/secure/verify...) wrapped around the brand.
        // (hyphen test runs on the raw label: sldNorm has hyphens stripped.)
        if (/^(login|secure|verify|account|update|support|service|help|signin|auth)/.test(extra) || /(login|secure|verify|account|update|support|service|help|signin|auth)$/.test(extra)) {
          score += 2;
          brand = b;
          signals.push({ id: 'keyword-stuff', text: 'This domain wraps the brand name "' + b + '" with words like "secure" or "login" — legitimate companies rarely do this.' });
          break;
        }
      }
    }
  }

  // 4b. Hyphenated brand slug (amazon-deals, apple-verify): weak on its own,
  // meaningful with other signals. Kept at +1 so recipe blogs stay LOW.
  if (!brand) {
    for (const b of brands) {
      if (sld.includes('-') && sldNorm.includes(b) && sldNorm.length > b.length + 2) {
        score += 1;
        brand = b;
        signals.push({ id: 'hyphen-brand', text: 'This domain is a hyphenated phrase built around the brand name "' + b + '" — a shape often used by copycat sites.' });
        break;
      }
    }
  }
  // 5. Hyphen-stuffed label (2+ hyphens in one label, or leading/trailing).
  if (labels.some(l => (l.match(/-/g) || []).length >= 2 || (l.startsWith('-') || l.endsWith('-')))) {
    score += 1;
    signals.push({ id: 'hyphens', text: 'A part of this domain is stuffed with hyphens (e.g. "secure-login-verify") — a pattern common in fake sites.' });
  }

  // 6. Suspicious TLD, especially paired with a brand keyword.
  if (SUSPICIOUS_TLDS.has(tld)) {
    const brandHit = brands.some(b => sldNorm.includes(b));
    score += brandHit ? 2 : 1;
    signals.push({ id: 'suspicious-tld', text: 'This site uses a top-level domain (.' + tld + ') that is disproportionately used by phishing sites.' + (brandHit ? ' Combined with a brand-like name, that is a strong warning sign.' : '') });
  }

  // 7. Subdomain spoofing — brand keyword in subdomain, different registrable domain.
  const full = hostname.toLowerCase();
  if (brand) {
    const idx = full.indexOf(brand);
    if (idx > 0 && !full.startsWith(domain)) {
      score += 3;
      signals.push({ id: 'subdomain-spoof', text: 'The brand name "' + brand + '" appears in the subdomain, but the real domain is "' + domain + '" — the part before the first single slash after the domain is what matters, not the subdomain.' });
    }
  } else {
    for (const b of brands) {
      if (full.includes(b + '.') && !full.startsWith(domain) && full.indexOf(b) < full.indexOf(domain)) {
        score += 3;
        brand = b;
        signals.push({ id: 'subdomain-spoof', text: 'The brand name "' + b + '" appears in the subdomain, but the real domain is "' + domain + '".' });
        break;
      }
    }
  }

  let verdict = 'LOW';
  if (score >= 5) verdict = 'HIGH';
  else if (score >= 3) verdict = 'MODERATE';

  return { domain, score, verdict, signals, brand };
}

/* Export for node tests; harmless in browser. */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeDomain, getRegistrableDomain, levenshtein, CONFUSABLES, SUSPICIOUS_TLDS };
}
