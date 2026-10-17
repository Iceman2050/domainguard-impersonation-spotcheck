/* DomainGuard heuristics engine — node fixture tests.
 *
 * Run: node tests/test_heuristics.js
 * Exits 0 when every test passes, 1 on the first failure.
 * Stdlib only (node:assert). No DOM, no network.
 */
'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');

const H = require(path.join(__dirname, '..', 'heuristics.js'));
const BRANDS = require(path.join(__dirname, '..', 'brands.json')).brands;

function signalIds(result) {
  return result.signals.map(s => s.id);
}

// Cyrillic "а" (U+0430) lookalike of Latin "a".
const PAYPAL_CYRILLIC_A = 'p\u0430ypal.com';
// Fully non-Latin lookalike of "amzon" (Cyrillic а м, ʐ U+0290, о, п U+043F).
const ALL_CYRILLIC_AMZON = '\u0430\u043c\u0290\u043e\u043f.com';

const tests = [];

function t(name, fn) { tests.push([name, fn]); }

/* -- levenshtein -------------------------------------------------------- */
t('levenshtein: identical strings are 0', () => {
  assert.equal(H.levenshtein('paypal', 'paypal'), 0);
});
t('levenshtein: classic kitten/sitting is 3', () => {
  assert.equal(H.levenshtein('kitten', 'sitting'), 3);
});
t('levenshtein: empty string cases', () => {
  assert.equal(H.levenshtein('', 'abc'), 3);
  assert.equal(H.levenshtein('abc', ''), 3);
  assert.equal(H.levenshtein('', ''), 0);
});
t('levenshtein: single substitution is 1', () => {
  assert.equal(H.levenshtein('paypa1', 'paypal'), 1);
});
t('levenshtein: leet pair g00gle/google is 2', () => {
  assert.equal(H.levenshtein('g00gle', 'google'), 2);
});

/* -- getRegistrableDomain ----------------------------------------------- */
t('registrable domain: subdomains stripped', () => {
  assert.equal(H.getRegistrableDomain('www.paypal.com'), 'paypal.com');
  assert.equal(H.getRegistrableDomain('a.b.c.example.net'), 'example.net');
});
t('registrable domain: two-part suffixes (co.uk, com.au)', () => {
  assert.equal(H.getRegistrableDomain('www.example.co.uk'), 'example.co.uk');
  assert.equal(H.getRegistrableDomain('sub.example.com.au'), 'example.com.au');
  assert.equal(H.getRegistrableDomain('example.co.uk'), 'example.co.uk');
});
t('registrable domain: case and trailing dot normalized', () => {
  assert.equal(H.getRegistrableDomain('WWW.GOOGLE.COM'), 'google.com');
  assert.equal(H.getRegistrableDomain('example.com.'), 'example.com');
});

/* -- constants sanity ---------------------------------------------------- */
t('CONFUSABLES: Cyrillic а listed as lookalike of a', () => {
  assert.ok(H.CONFUSABLES.a.includes('а'));
});
t('SUSPICIOUS_TLDS: phishing TLDs in, common TLDs out', () => {
  for (const tld of ['zip', 'tk', 'xyz', 'top', 'click']) {
    assert.ok(H.SUSPICIOUS_TLDS.has(tld), tld + ' should be suspicious');
  }
  for (const tld of ['com', 'org', 'net', 'io', 'uk']) {
    assert.ok(!H.SUSPICIOUS_TLDS.has(tld), tld + ' should be clean');
  }
});

/* -- clean domains are NOT flagged --------------------------------------- */
t('clean: paypal.com is LOW with no signals', () => {
  const r = H.analyzeDomain('paypal.com', BRANDS);
  assert.equal(r.verdict, 'LOW');
  assert.deepEqual(r.signals, []);
});
t('clean: google.com is LOW with no signals', () => {
  const r = H.analyzeDomain('google.com', BRANDS);
  assert.equal(r.verdict, 'LOW');
  assert.deepEqual(r.signals, []);
});
t('clean: exact brand on its own domain is not a typosquat', () => {
  const r = H.analyzeDomain('www.github.com', BRANDS);
  assert.equal(r.verdict, 'LOW');
  assert.deepEqual(r.signals, []);
});
t('clean: hyphenated recipe blog stays LOW (weak signals only)', () => {
  const r = H.analyzeDomain('grandmas-recipe-blog.com', BRANDS);
  assert.equal(r.verdict, 'LOW');
});

/* -- confusables ---------------------------------------------------------- */
t('confusable: Cyrillic-а paypal flags mixed-script + typosquat, HIGH', () => {
  const r = H.analyzeDomain(PAYPAL_CYRILLIC_A, BRANDS);
  const ids = signalIds(r);
  assert.ok(ids.includes('mixed-script'), 'mixed-script signal, got ' + ids);
  assert.ok(ids.includes('typosquat'), 'typosquat signal, got ' + ids);
  assert.equal(r.brand, 'paypal');
  assert.equal(r.verdict, 'HIGH');
});
t('confusable: single-script lookalike label fires confusable signal', () => {
  const r = H.analyzeDomain(ALL_CYRILLIC_AMZON, BRANDS);
  const ids = signalIds(r);
  assert.ok(ids.includes('confusable'), 'confusable signal, got ' + ids);
  assert.ok(!ids.includes('mixed-script'), 'must not be mixed-script');
});
t('confusable: plain ASCII lookalike letters do NOT count (paypal.com)', () => {
  // Guard for the CONFUSABLE_SET ASCII exclusion: the letter "l" in
  // paypal.com must never be treated as an attacker confusable.
  const r = H.analyzeDomain('paypal.com', BRANDS);
  assert.ok(!signalIds(r).includes('confusable'));
});

/* -- punycode / typosquat / leet ----------------------------------------- */
t('punycode label flags MODERATE', () => {
  const r = H.analyzeDomain('xn--pypal-4ve.com', BRANDS);
  assert.ok(signalIds(r).includes('punycode'));
  assert.equal(r.verdict, 'MODERATE');
});
t('typosquat: paypaI.com (capital i) flags MODERATE like the README', () => {
  const r = H.analyzeDomain('paypaI.com', BRANDS);
  assert.ok(signalIds(r).includes('typosquat'));
  assert.equal(r.brand, 'paypal');
  assert.equal(r.verdict, 'MODERATE');
});
t('leet typosquat: g00gle.com normalizes to google, MODERATE', () => {
  const r = H.analyzeDomain('g00gle.com', BRANDS);
  assert.ok(signalIds(r).includes('typosquat'));
  assert.equal(r.brand, 'google');
  assert.equal(r.verdict, 'MODERATE');
});

/* -- suspicious TLDs ------------------------------------------------------- */
t('suspicious TLD: paypal.zip raises the signal', () => {
  const r = H.analyzeDomain('paypal.zip', BRANDS);
  assert.ok(signalIds(r).includes('suspicious-tld'));
});
t('suspicious TLD + brand keyword stuffing: HIGH', () => {
  const r = H.analyzeDomain('paypal-secure-login.xyz', BRANDS);
  const ids = signalIds(r);
  assert.ok(ids.includes('keyword-stuff'), 'keyword-stuff, got ' + ids);
  assert.ok(ids.includes('suspicious-tld'), 'suspicious-tld, got ' + ids);
  assert.equal(r.brand, 'paypal');
  assert.equal(r.verdict, 'HIGH'); // +2 keyword-stuff, +1 hyphens, +2 susp-tld w/ brand
});
t('suspicious TLD without brand stays LOW but is still signaled', () => {
  const r = H.analyzeDomain('example.zip', BRANDS);
  assert.ok(signalIds(r).includes('suspicious-tld'));
  assert.equal(r.verdict, 'LOW');
});

/* -- hyphenated brand slugs are weak alone -------------------------------- */
t('hyphen-brand: apple-deals.com is LOW (weak signal, not a verdict)', () => {
  const r = H.analyzeDomain('apple-deals.com', BRANDS);
  assert.ok(signalIds(r).includes('hyphen-brand'));
  assert.equal(r.brand, 'apple');
  assert.equal(r.verdict, 'LOW');
});

/* -- subdomain spoofing ---------------------------------------------------- */
t('subdomain spoof: brand in subdomain flags MODERATE', () => {
  const r = H.analyzeDomain('paypal.secure-login.example.com', BRANDS);
  assert.ok(signalIds(r).includes('subdomain-spoof'));
  assert.equal(r.brand, 'paypal');
  assert.equal(r.verdict, 'MODERATE');
});

/* -- result shape ---------------------------------------------------------- */
t('analyzeDomain returns the documented result shape', () => {
  const r = H.analyzeDomain('example.com', BRANDS);
  assert.ok(typeof r.domain === 'string');
  assert.ok(typeof r.score === 'number');
  assert.ok(['LOW', 'MODERATE', 'HIGH'].includes(r.verdict));
  assert.ok(Array.isArray(r.signals));
  for (const s of r.signals) {
    assert.ok(typeof s.id === 'string' && typeof s.text === 'string');
  }
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    fn();
    console.log('ok   ' + name);
  } catch (e) {
    failed += 1;
    console.log('FAIL ' + name);
    console.log('     ' + String(e && e.message || e).split('\n')[0]);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} tests passed`);
process.exit(failed ? 1 : 0);
