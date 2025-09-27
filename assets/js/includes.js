(function () {
  async function injectIncludes() {
    // Find all elements like: <div data-include="/partials/header.html"></div>
    const targets = document.querySelectorAll('[data-include]');
    for (const el of targets) {
      const url = el.getAttribute('data-include');
      try {
        const res = await fetch(url, { credentials: 'same-origin' });
        if (!res.ok) throw new Error(`Fetch failed for ${url}: ${res.status}`);
        const html = await res.text();
        el.outerHTML = html; // replace placeholder with fetched markup
      } catch (err) {
        console.error('Include error:', err);
      }
    }
  }

  function initHeaderBehavior() {
    const hamburger = document.querySelector('.hamburger');
    const nav = document.getElementById('primary-nav');
    if (hamburger && nav) {
      hamburger.addEventListener('click', () => {
        const open = nav.classList.toggle('open');
        hamburger.setAttribute('aria-expanded', String(open));
      });
    }

    // Highlight the active link by URL path
    const here = location.pathname.replace(/\/index\.html?$/i, '/');
    document.querySelectorAll('.menu a[href]').forEach(a => {
      const href = a.getAttribute('href');
      // simple startsWith match so /security.html highlights inside section anchors
      if (!href || href.startsWith('#') || href.startsWith('tel:')) return;
      const normalized = href.replace(/\/index\.html?$/i, '/');
      if (here === normalized || (here !== '/' && normalized.startsWith(here))) {
        a.classList.add('is-active');
      }
    });
  }

  // Wait until footer is injected, then set the year
  function setFooterYearWhenReady(){
    const trySet = () => {
      const y = document.getElementById('year');
      if (y) { 
        y.textContent = new Date().getFullYear(); 
        return true; 
      }
      return false;
    };
    if (trySet()) return;
    const mo = new MutationObserver(() => { if (trySet()) mo.disconnect(); });
    mo.observe(document.documentElement, { childList: true, subtree: true });
  }

  // Optional: one-place site title. On each page put: <title data-page="Home"></title>
  function initTitle() {
    const siteName = 'System Alternatives — IT & Cybersecurity';
    const t = document.querySelector('title[data-page]');
    if (t) {
      const page = t.getAttribute('data-page');
      document.title = page ? `${page} | ${siteName}` : siteName;
    }
  }

  // Run:
  document.addEventListener('DOMContentLoaded', async () => {
    await injectIncludes();        // inject header/footer
    setFooterYearWhenReady();
    initHeaderBehavior();          // re-bind events after injection
    initTitle();                   // optional single-source title pattern
  });
})();
