/* DomainGuard warning banner — injected into the page via
 * chrome.scripting.executeScript (bundled file, no remote code).
 * Dismissible, non-blocking, never breaks page layout. */

'use strict';

(function () {
  if (window.__dgBannerInstalled) return;
  window.__dgBannerInstalled = true;

  window.__dgShowBanner = function (payload) {
    if (document.getElementById('dg-impersonation-banner')) return;

    const style = document.createElement('style');
    style.textContent = [
      '#dg-impersonation-banner{position:fixed;top:0;left:0;right:0;z-index:2147483647;',
      'font-family:-apple-system,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.4;',
      'padding:12px 48px 12px 16px;box-sizing:border-box;}',
      '#dg-impersonation-banner.dg-high{background:#3f0d0d;color:#fecaca;border-bottom:2px solid #7f1d1d;}',
      '#dg-impersonation-banner.dg-moderate{background:#3a2a05;color:#fde68a;border-bottom:2px solid #92600a;}',
      '#dg-impersonation-banner strong{font-weight:700;}',
      '#dg-impersonation-banner .dg-domain{font-family:monospace;}',
      '#dg-impersonation-banner .dg-why{margin-top:6px;font-size:12px;opacity:.9;}',
      '#dg-impersonation-banner .dg-close{position:absolute;top:8px;right:12px;background:none;border:0;',
      'color:inherit;font-size:20px;cursor:pointer;padding:4px 8px;}',
      '#dg-impersonation-banner .dg-actions{margin-top:8px;}',
      '#dg-impersonation-banner .dg-actions a{color:inherit;text-decoration:underline;margin-right:16px;font-size:12px;}'
    ].join('');
    document.documentElement.appendChild(style);

    const banner = document.createElement('div');
    banner.id = 'dg-impersonation-banner';
    banner.setAttribute('role', 'alert');
    banner.className = payload.verdict === 'HIGH' ? 'dg-high' : 'dg-moderate';

    const title = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = payload.verdict === 'HIGH'
      ? 'Warning: this site looks like an impersonation attempt.'
      : 'Caution: this site shows impersonation warning signs.';
    title.appendChild(strong);
    title.appendChild(document.createTextNode(' '));
    const dom = document.createElement('span');
    dom.className = 'dg-domain';
    dom.textContent = payload.domain;
    title.appendChild(dom);
    if (payload.brand) {
      title.appendChild(document.createTextNode(' It resembles "' + payload.brand + '". Verify before entering credentials.'));
    } else {
      title.appendChild(document.createTextNode(' Verify before entering credentials.'));
    }
    banner.appendChild(title);

    if (payload.signals && payload.signals.length) {
      const why = document.createElement('div');
      why.className = 'dg-why';
      why.textContent = 'Why: ' + payload.signals[0];
      banner.appendChild(why);
    }

    const actions = document.createElement('div');
    actions.className = 'dg-actions';
    const report = document.createElement('a');
    report.href = 'https://domain-guard-08k7.onrender.com/report?domain=' + encodeURIComponent(payload.domain);
    report.target = '_blank';
    report.rel = 'noopener';
    report.textContent = 'Report this domain';
    actions.appendChild(report);
    const learn = document.createElement('a');
    learn.href = 'https://ingeniousai-security-checks.netlify.app/domain-check.html';
    learn.target = '_blank';
    learn.rel = 'noopener';
    learn.textContent = 'How spot-checks work';
    actions.appendChild(learn);
    banner.appendChild(actions);

    const close = document.createElement('button');
    close.className = 'dg-close';
    close.setAttribute('aria-label', 'Dismiss warning');
    close.textContent = '×';
    close.addEventListener('click', function () { banner.remove(); });
    banner.appendChild(close);

    document.body.insertBefore(banner, document.body.firstChild);
  };
})();
