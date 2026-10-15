/* DomainGuard popup — user-initiated spot check.
 * activeTab grants this popup access to the current tab's URL when opened.
 * All analysis is local (heuristics.js). No network calls. */

'use strict';

const LINKS = {
  platform: 'https://domain-guard-08k7.onrender.com',
  hubCheck: 'https://ingeniousai-security-checks.netlify.app/domain-check.html'
};

const VERDICT_COPY = {
  LOW: { label: 'LOOKS CLEAN', cls: 'low', summary: 'No impersonation patterns detected on this domain.' },
  MODERATE: { label: 'SUSPICIOUS', cls: 'moderate', summary: 'This domain shows patterns commonly used by impersonation sites. Verify before entering credentials.' },
  HIGH: { label: 'LIKELY IMPERSONATION', cls: 'high', summary: 'This domain strongly resembles a known impersonation pattern. Do not enter passwords or payment details.' }
};

async function getBrands() {
  const url = chrome.runtime.getURL('brands.json');
  const res = await fetch(url);
  const data = await res.json();
  return data.brands;
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function hostnameOf(tab) {
  try {
    const u = new URL(tab.url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.hostname;
  } catch (e) { return null; }
}

async function loadStore() {
  const d = await chrome.storage.local.get({ allowlist: [] });
  return { allowlist: d.allowlist || [] };
}

async function render() {
  const tab = await getActiveTab();
  const host = tab ? hostnameOf(tab) : null;
  const store = await loadStore();
  const brands = await getBrands();

  const badge = document.getElementById('verdict-badge');
  const domainLine = document.getElementById('domain-line');
  const summary = document.getElementById('verdict-summary');
  const signalList = document.getElementById('signal-list');
  const allowNote = document.getElementById('allowlisted-note');
  const btnBanner = document.getElementById('btn-banner');
  const btnAllow = document.getElementById('btn-allow');
  const btnUnallow = document.getElementById('btn-unallow');

  signalList.textContent = '';
  allowNote.classList.add('hidden');
  btnBanner.classList.add('hidden');

  if (!host) {
    badge.className = 'badge moderate';
    badge.textContent = 'NO PAGE';
    domainLine.textContent = '';
    summary.textContent = 'Open a website first, then click the extension to spot-check it.';
    btnAllow.classList.add('hidden');
    renderAllowlist(store.allowlist);
    return;
  }

  const result = analyzeDomain(host, brands);
  const allowlisted = store.allowlist.includes(result.domain);
  const shown = allowlisted ? 'LOW' : result.verdict;
  const copy = VERDICT_COPY[shown];

  badge.className = 'badge ' + copy.cls;
  badge.textContent = allowlisted ? 'TRUSTED BY YOU' : copy.label;
  domainLine.textContent = result.domain;
  summary.textContent = allowlisted
    ? 'You marked this domain as trusted, so no warning is shown.'
    : copy.summary;

  if (allowlisted) {
    allowNote.classList.remove('hidden');
    allowNote.textContent = 'Underlying check found ' + result.signals.length + ' signal(s); suppressed by your allowlist.';
    btnAllow.classList.add('hidden');
    btnUnallow.classList.remove('hidden');
  } else {
    for (const s of result.signals) {
      const li = document.createElement('li');
      li.textContent = s.text;
      signalList.appendChild(li);
    }
    btnAllow.classList.remove('hidden');
    btnUnallow.classList.add('hidden');
    if (result.verdict !== 'LOW') btnBanner.classList.remove('hidden');
  }

  btnAllow.onclick = async () => {
    const s = await loadStore();
    if (!s.allowlist.includes(result.domain)) s.allowlist.push(result.domain);
    await chrome.storage.local.set({ allowlist: s.allowlist });
    render();
  };
  btnUnallow.onclick = async () => {
    const s = await loadStore();
    await chrome.storage.local.set({ allowlist: s.allowlist.filter(d => d !== result.domain) });
    render();
  };
  btnBanner.onclick = async () => {
    const t = await getActiveTab();
    if (!t || !t.id) return;
    await chrome.scripting.executeScript({
      target: { tabId: t.id },
      files: ['banner.js']
    });
    await chrome.scripting.executeScript({
      target: { tabId: t.id },
      func: (payload) => { window.__dgShowBanner(payload); },
      args: [{ domain: result.domain, verdict: result.verdict, brand: result.brand, signals: result.signals.map(s => s.text) }]
    });
    window.close();
  };

  renderAllowlist(store.allowlist);
}

function renderAllowlist(list) {
  const ul = document.getElementById('allowlist');
  const empty = document.getElementById('allowlist-empty');
  ul.textContent = '';
  empty.classList.toggle('hidden', list.length > 0);
  for (const d of list) {
    const li = document.createElement('li');
    const span = document.createElement('span');
    span.textContent = d;
    const btn = document.createElement('button');
    btn.className = 'ghost';
    btn.textContent = 'Remove';
    btn.onclick = async () => {
      const s = await loadStore();
      await chrome.storage.local.set({ allowlist: s.allowlist.filter(x => x !== d) });
      render();
    };
    li.appendChild(span);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

document.getElementById('link-why').addEventListener('click', (e) => {
  e.preventDefault();
  document.getElementById('why-modal').classList.remove('hidden');
});
document.getElementById('btn-why-close').addEventListener('click', () => {
  document.getElementById('why-modal').classList.add('hidden');
});

document.addEventListener('DOMContentLoaded', render);
