/* ================================
   Jobseekers.ph - Main JavaScript
   ================================ */

// Navbar scroll effect
const navbar = document.getElementById('navbar');
if (navbar) {
  const onScroll = () => {
    navbar.classList.toggle('scrolled', window.scrollY > 20);
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

// Mobile menu
const navToggle = document.getElementById('navToggle');
const mobileMenu = document.getElementById('mobileMenu');

if (navToggle && mobileMenu) {
  navToggle.addEventListener('click', (e) => {
    e.stopPropagation();
    mobileMenu.classList.toggle('open');
  });

  document.addEventListener('click', (e) => {
    if (!mobileMenu.contains(e.target) && !navToggle.contains(e.target)) {
      mobileMenu.classList.remove('open');
    }
  });

  document.querySelectorAll('.mobile-menu a').forEach(link => {
    link.addEventListener('click', () => mobileMenu.classList.remove('open'));
  });
}

// Set active nav link
const currentPage = window.location.pathname.split('/').pop() || 'index.html';
document.querySelectorAll('.navbar-nav a, .mobile-menu a').forEach(link => {
  const href = link.getAttribute('href');
  if (href === currentPage || (currentPage === '' && href === 'index.html')) {
    link.classList.add('active');
  }
});

// Highlight the "More" dropdown when one of its pages is open
document.querySelectorAll('.nav-dropdown').forEach(dd => {
  if (dd.querySelector('.nav-dropdown-menu a.active')) dd.querySelector('button').classList.add('active');
});

// Small toast used by feature pages: showToast('Saved!')
function showToast(message) {
  let toast = document.querySelector('.feature-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'feature-toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('show'), 2600);
}

/* ---------- Language toggle: English / Taglish ----------
   Common UI labels are translated from the dictionary below.
   Any element can also carry its own translation: <h2 data-tl="...">  */
const TAGLISH = {
  'Home': 'Home',
  'Find VAs': 'Maghanap ng VA',
  'Browse Jobs': 'Maghanap ng Trabaho',
  'How It Works': 'Paano Gumagana',
  'Pricing': 'Presyo',
  'About': 'Tungkol Sa Amin',
  'Contact': 'Makipag-ugnayan',
  'Login': 'Mag-login',
  'Post a Job': 'Mag-post ng Trabaho',
  'More': 'Iba Pa',
  'AI Match': 'AI Match',
  'VA Academy': 'VA Academy',
  'Community': 'Komunidad',
  'Work Tools': 'Work Tools',
  'Contracts & Taxes': 'Kontrata at Buwis',
  'Setup Check': 'Setup Check',
  'Apply Now': 'Mag-apply Na',
  'View Profile': 'Tingnan ang Profile',
  'Search': 'Hanapin',
  'Filter': 'I-filter',
  'Clear': 'I-clear',
  'Create Free Profile': 'Gumawa ng Libreng Profile',
  'Send Message': 'Mag-message',
  'Hire Me': 'I-hire Ako',
  'Start Paid Trial': 'Simulan ang Paid Trial',
  'Save Profile': 'I-save ang Profile',
  'Enroll Free': 'Mag-enroll nang Libre',
  'Continue': 'Ituloy',
  'Start Test': 'Simulan ang Test',
  'Find My Matches': 'Hanapin ang Match Ko',
  'Start New Topic': 'Magsimula ng Topic',
};

let currentLang = 'en';
try { currentLang = localStorage.getItem('jsph-lang') || 'en'; } catch (e) {}
const originalText = new WeakMap();

function translateTextNodes(root, toTaglish) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(node => {
    if (!originalText.has(node)) originalText.set(node, node.nodeValue);
    const original = originalText.get(node);
    const key = original.trim();
    if (!key || !(key in TAGLISH)) return;
    node.nodeValue = toTaglish ? original.replace(key, TAGLISH[key]) : original;
  });
}

function applyLanguage(lang) {
  const toTaglish = lang === 'tl';
  document.documentElement.lang = toTaglish ? 'fil' : 'en';
  document.querySelectorAll('.navbar, .mobile-menu, .btn, .sidebar-title button, .nav-dropdown').forEach(el => translateTextNodes(el, toTaglish));
  document.querySelectorAll('[data-tl]').forEach(el => {
    if (!el.dataset.en) el.dataset.en = el.innerHTML;
    el.innerHTML = toTaglish ? el.dataset.tl : el.dataset.en;
  });
  document.querySelectorAll('.lang-toggle').forEach(btn => {
    btn.querySelector('[data-lang="en"]').classList.toggle('on', !toTaglish);
    btn.querySelector('[data-lang="tl"]').classList.toggle('on', toTaglish);
  });
}

function buildLangToggle() {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'lang-toggle';
  btn.title = 'Switch language / Palitan ang wika';
  btn.innerHTML = '<i class="fas fa-language"></i><span data-lang="en">EN</span>/<span data-lang="tl">TL</span>';
  btn.addEventListener('click', () => {
    currentLang = currentLang === 'en' ? 'tl' : 'en';
    try { localStorage.setItem('jsph-lang', currentLang); } catch (e) {}
    applyLanguage(currentLang);
  });
  return btn;
}

const navActions = document.querySelector('.navbar-actions');
if (navActions) navActions.prepend(buildLangToggle());
const mobileActions = document.querySelector('.mobile-menu .mobile-actions');
if (mobileActions) mobileActions.before(buildLangToggle());
const dashTopbarRight = document.querySelector('.dash-topbar-right');
if (dashTopbarRight) dashTopbarRight.prepend(buildLangToggle());
applyLanguage(currentLang);

// How It Works tabs
function initTabs(tabSelector, panelSelector) {
  const tabs = document.querySelectorAll(tabSelector);
  if (!tabs.length) return;

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const target = tab.dataset.target;
      document.querySelectorAll(panelSelector).forEach(p => p.classList.remove('active'));
      const panel = document.getElementById(target);
      if (panel) panel.classList.add('active');
    });
  });
}

initTabs('.how-tab', '.tab-panel');

// Auth tabs
initTabs('.auth-tab', '.auth-panel');

// Role selector
document.querySelectorAll('.role-card').forEach(card => {
  card.addEventListener('click', () => {
    document.querySelectorAll('.role-card').forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
  });
});

// Intersection Observer for scroll animations
const scrollObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      scrollObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.on-scroll').forEach(el => scrollObserver.observe(el));

// Counter animation
function animateCount(el) {
  const target = parseInt(el.dataset.target, 10);
  const suffix = el.dataset.suffix || '+';
  const duration = 2000;
  const startTime = performance.now();

  const tick = (now) => {
    const elapsed = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - elapsed, 3);
    const current = Math.floor(eased * target);
    el.textContent = current.toLocaleString() + suffix;
    if (elapsed < 1) requestAnimationFrame(tick);
  };

  requestAnimationFrame(tick);
}

const counterObserver = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      animateCount(entry.target);
      counterObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.5 });

document.querySelectorAll('.counter').forEach(el => counterObserver.observe(el));

// Tag input
document.querySelectorAll('.tag-input-wrap').forEach(wrap => {
  const input = wrap.querySelector('input');
  if (!input) return;

  input.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
      e.preventDefault();
      addTag(wrap, input.value.trim().replace(/,$/, ''));
      input.value = '';
    }
    if (e.key === 'Backspace' && !input.value) {
      const tags = wrap.querySelectorAll('.input-tag');
      if (tags.length) tags[tags.length - 1].remove();
    }
  });
});

function addTag(wrap, text) {
  const tag = document.createElement('span');
  tag.className = 'input-tag';
  tag.innerHTML = `${text}<button type="button" aria-label="Remove">×</button>`;
  tag.querySelector('button').addEventListener('click', () => tag.remove());
  wrap.insertBefore(tag, wrap.querySelector('input'));
}

// Smooth anchor scrolling
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', (e) => {
    const id = anchor.getAttribute('href');
    if (id === '#') return; // placeholder links
    const target = document.querySelector(id);
    if (target) {
      e.preventDefault();
      const offset = 80;
      const top = target.getBoundingClientRect().top + window.scrollY - offset;
      window.scrollTo({ top, behavior: 'smooth' });
    }
  });
});

// Rating stars display (read-only)
document.querySelectorAll('.star-rating-interactive').forEach(wrap => {
  const stars = wrap.querySelectorAll('i');
  const input = wrap.previousElementSibling;

  stars.forEach((star, i) => {
    star.addEventListener('mouseover', () => {
      stars.forEach((s, j) => s.classList.toggle('active', j <= i));
    });
    star.addEventListener('click', () => {
      if (input) input.value = i + 1;
      stars.forEach((s, j) => s.dataset.selected = j <= i ? 'true' : 'false');
    });
  });

  wrap.addEventListener('mouseleave', () => {
    stars.forEach(s => s.classList.toggle('active', s.dataset.selected === 'true'));
  });
});

// Form validation helper
function validateForm(formEl) {
  let valid = true;
  formEl.querySelectorAll('[required]').forEach(field => {
    const invalid = !field.value.trim();
    field.style.borderColor = invalid ? 'var(--danger)' : '';
    if (invalid) valid = false;
  });
  return valid;
}

// Attach to any form with data-validate
document.querySelectorAll('form[data-validate]').forEach(form => {
  form.addEventListener('submit', (e) => {
    if (!validateForm(form)) {
      e.preventDefault();
      const firstInvalid = form.querySelector('[required]:placeholder-shown, [required][value=""]');
      if (firstInvalid) firstInvalid.focus();
    }
  });
});

// Show/hide password toggle
document.querySelectorAll('.pw-toggle').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = btn.previousElementSibling || btn.parentElement.querySelector('input');
    if (!input) return;
    const isText = input.type === 'text';
    input.type = isText ? 'password' : 'text';
    btn.querySelector('i').className = isText ? 'fas fa-eye' : 'fas fa-eye-slash';
  });
});

// Filter range display
document.querySelectorAll('.range-display').forEach(display => {
  const input = display.previousElementSibling;
  if (!input) return;
  const suffix = display.dataset.suffix || '';
  display.textContent = input.value + suffix;
  input.addEventListener('input', () => { display.textContent = input.value + suffix; });
});

// Mobile filter toggle
document.querySelectorAll('.mobile-filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const sidebar = btn.nextElementSibling?.querySelector('.sidebar-collapsible')
      || btn.parentElement.querySelector('.sidebar-collapsible');
    if (!sidebar) return;
    const open = sidebar.classList.toggle('open');
    btn.innerHTML = open
      ? '<i class="fas fa-times"></i> Hide Filters'
      : '<i class="fas fa-sliders-h"></i> Show Filters';
  });
});

// Sticky sidebar
const stickySidebar = document.querySelector('.sticky-sidebar');
if (stickySidebar) {
  const top = stickySidebar.getBoundingClientRect().top + window.scrollY;
  window.addEventListener('scroll', () => {
    stickySidebar.style.top = window.scrollY > top - 90 ? '90px' : '';
  }, { passive: true });
}
