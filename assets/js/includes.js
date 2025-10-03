/* System Alternatives – shared includes + header/footer + subnav + reveals */
(function () {
  /* ---------- 1) Inject partials (header/footer) ---------- */
  async function injectIncludes() {
    const targets = document.querySelectorAll('[data-include]');
    for (const holder of targets) {
      const url = holder.getAttribute('data-include');
      try {
        const res = await fetch(url, { credentials: 'same-origin' });
        if (!res.ok) throw new Error(`Fetch failed for ${url}: ${res.status}`);
        const html = await res.text();
        holder.outerHTML = html;            // replace placeholder
      } catch (err) {
        console.error('Include error:', err);
      }
    }
  }

  /* ---------- 2) Footer year helper ---------- */
  function setFooterYear() {
    const y = document.getElementById('year');
    if (y) y.textContent = new Date().getFullYear();
  }

  /* ---------- utilities ---------- */
  const rafThrottle = (fn) => {
    let ticking = false;
    return (...args) => {
      if (!ticking) {
        ticking = true;
        requestAnimationFrame(() => {
          ticking = false;
          fn(...args);
        });
      }
    };
  };

  function getStickyHeaderHeight() {
    // Base fallback
    let h = 72;
    const rootStyles = getComputedStyle(document.documentElement);
    const varVal = rootStyles.getPropertyValue('--sticky-header').trim();
    const fromVar = parseInt(varVal, 10);
    if (!Number.isNaN(fromVar) && fromVar > 0) h = fromVar;

    const header = document.querySelector('header.nav');
    if (header) h = Math.max(h, header.offsetHeight || 0);
    return h;
  }

  /* ---------- 3) Header / mobile menu behavior ---------- */
  function initHeader() {
    const header = document.querySelector('header.nav');
    if (!header) return;

    const hamburger = header.querySelector('.hamburger');
    const nav = header.querySelector('#primary-nav');
    if (!hamburger || !nav) return;

    const mqMobile = window.matchMedia('(max-width: 900px)');

    const setOpen = (open) => {
      header.classList.toggle('nav--open', open);
      hamburger.setAttribute('aria-expanded', String(open));
      document.documentElement.classList.toggle('body--nav-open', open);
    };

    if (hamburger._saBound) hamburger.removeEventListener('click', hamburger._saBound);
    hamburger._saBound = () => setOpen(!header.classList.contains('nav--open'));
    hamburger.addEventListener('click', hamburger._saBound);

    mqMobile.addEventListener('change', () => setOpen(false));

    nav.addEventListener('click', (e) => {
      if (!mqMobile.matches) return;
      const a = e.target.closest('a[href]');
      if (!a) return;
      const isHash = a.getAttribute('href').startsWith('#');
      if (!isHash) setOpen(false);
    });
  }

  /* ---------- 4) In-page subnavs (MS + Cybersecurity) ---------- */
  function initInPageSubnav() {
    document.querySelectorAll('.subnav').forEach((subnav) => {
      const scroller = subnav.querySelector('.container');
      if (!scroller) return;

      const links = Array.from(scroller.querySelectorAll('a[href^="#"]'));
      if (!links.length) return;

      const map = new Map();
      links.forEach((a) => {
        const id = decodeURIComponent(a.hash.slice(1));
        const sec = document.getElementById(id);
        if (sec) map.set(id, { link: a, section: sec });
      });
      if (!map.size) return;

      // Horizontal wheel scroll
      const onWheel = (e) => {
        const canScrollX = scroller.scrollWidth > scroller.clientWidth;
        if (!canScrollX) return;
        if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
          e.preventDefault();
          scroller.scrollLeft += e.deltaY;
        }
      };
      scroller.addEventListener('wheel', onWheel, { passive: false });

      // Keep active chip visible
      function ensureChipVisible(link, behavior = 'smooth') {
        const left = link.offsetLeft;
        const right = left + link.offsetWidth;
        const viewLeft = scroller.scrollLeft;
        const viewRight = viewLeft + scroller.clientWidth;

        if (left < viewLeft || right > viewRight) {
          const targetLeft = Math.max(
            0,
            left - (scroller.clientWidth - link.offsetWidth) / 2
          );
          scroller.scrollTo({ left: targetLeft, behavior });
        }
      }

      function setActiveLink(link) {
        if (!link) return;
        links.forEach((l) => l.classList.toggle('is-active', l === link));
        ensureChipVisible(link);
      }

      // Smooth-scroll with sticky-header offset
      function scrollToSection(id) {
        const entry = map.get(id);
        if (!entry) return;

        const extra = 8; // breathing room
        const offset = getStickyHeaderHeight() + (subnav.offsetHeight || 0) + extra;
        const y = entry.section.getBoundingClientRect().top + window.scrollY - offset;

        window.scrollTo({ top: y, behavior: 'smooth' });
        setActiveLink(entry.link);
        history.replaceState(null, '', '#' + id);
      }

      links.forEach((a) => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const id = decodeURIComponent(a.hash.slice(1));
          scrollToSection(id);
        });
      });

      // Scroll spy
      const onScroll = rafThrottle(() => {
        const extra = 10;
        const offset = window.scrollY + getStickyHeaderHeight() + (subnav.offsetHeight || 0) + extra;

        let currentLink = null;
        for (const { section, link } of map.values()) {
          if (section.offsetTop <= offset) currentLink = link;
        }
        setActiveLink(currentLink || links[0]);
      });
      window.addEventListener('scroll', onScroll, { passive: true });
      window.addEventListener('resize', onScroll);

      // Hash support
      function handleHash() {
        const id = decodeURIComponent(location.hash.replace('#', ''));
        if (id && map.has(id)) {
          setTimeout(() => scrollToSection(id), 0);
        } else {
          onScroll();
        }
      }
      window.addEventListener('hashchange', handleHash);

      requestAnimationFrame(() => {
        onScroll();
        if (location.hash) handleHash();
      });
    });
  }

  /* ---------- 5) Section reveal (site-wide) ---------- */
  function initSectionReveal() {
    // Add .reveal to all main sections except ones that already have it
    const sections = Array.from(document.querySelectorAll('main > section'));
    sections.forEach(sec => sec.classList.add('reveal'));

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduceMotion) {
      sections.forEach(sec => sec.classList.add('is-visible'));
      return;
    }

    const io = new IntersectionObserver((entries, obs) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });

    sections.forEach(sec => io.observe(sec));
  }

  /* ---------- 6) Page title helper (optional) ---------- */
  function initTitle() {
    const siteName = 'System Alternatives — IT & Cybersecurity';
    const t = document.querySelector('title[data-page]');
    if (t) {
      const page = t.getAttribute('data-page');
      document.title = page ? `${page} | ${siteName}` : siteName;
    }
  }

  /* ---------- 7) Boot ---------- */
  document.addEventListener('DOMContentLoaded', async () => {
    await injectIncludes();
    setFooterYear();
    initHeader();
    initInPageSubnav();
    initSectionReveal();   // NEW: ensures Cybersecurity (and others) always fade in
    initTitle();
  });
})();
