/* ================================
   Jobseekers.ph - Dashboard shell
   Renders the sidebar and top bar for VA, client and admin pages:
   <aside class="dash-sidebar" id="dashSidebar" data-role="client" data-active="hires"></aside>
   <header class="dash-topbar" id="dashTopbar"></header>
   Load before main.js so the language toggle lands in the new top bar.
   ================================ */

const DASH_ROLES = {
  va: {
    user: { name: 'Maria Santos', role: 'Virtual Assistant', img: 47, short: 'Maria' },
    nav: [
      ['Main'],
      ['overview', 'dashboard-va', 'fa-th-large', 'Overview'],
      ['applications', 'my-applications', 'fa-file-alt', 'My Applications', 'apps'],
      ['jobs', 'browse-jobs', 'fa-search', 'Browse Jobs'],
      ['messages', 'messages', 'fa-comments', 'Messages', 'msgs'],
      ['My Account'],
      ['profile', 'edit-profile', 'fa-user-circle', 'My Profile'],
      ['earnings', 'work-tools', 'fa-wallet', 'Earnings &amp; Invoices'],
      ['Grow &amp; Tools'],
      ['tools', 'work-tools', 'fa-stopwatch', 'Work Tools'],
      ['academy', 'academy', 'fa-graduation-cap', 'VA Academy'],
      ['setup', 'setup-check', 'fa-bolt', 'Setup Check'],
      ['compliance', 'compliance', 'fa-file-signature', 'Contracts &amp; Taxes'],
      ['community', 'community', 'fa-users', 'Community'],
    ],
  },
  client: {
    user: { name: 'James Carter', role: 'Client · Carter Digital', img: 33, short: 'James' },
    nav: [
      ['Hiring'],
      ['overview', 'dashboard-client', 'fa-th-large', 'Overview'],
      ['applicants', 'applicants', 'fa-user-friends', 'Jobs &amp; Applicants', 'applicants'],
      ['messages', 'messages?as=client', 'fa-comments', 'Messages', 'msgs'],
      ['post', 'post-job', 'fa-plus-circle', 'Post a Job'],
      ['match', 'ai-match', 'fa-magic', 'AI Match'],
      ['Team'],
      ['hires', 'dashboard-client#hires', 'fa-user-check', 'Hires &amp; Trials'],
      ['invoices', 'dashboard-client#invoices', 'fa-file-invoice-dollar', 'Invoices', 'invoices'],
      ['guarantee', 'dashboard-client#guarantee', 'fa-sync-alt', 'Replacement Guarantee'],
      ['compliance', 'compliance', 'fa-file-signature', 'Contracts &amp; NDAs'],
    ],
  },
  admin: {
    user: { name: 'Trust &amp; Safety', role: 'Admin', img: 65, short: 'Admin' },
    nav: [
      ['Moderation'],
      ['overview', 'admin', 'fa-th-large', 'Overview'],
      ['flagged', 'admin#flagged', 'fa-flag', 'Flagged Posts', 'flagged'],
      ['verify', 'admin#verify', 'fa-id-card', 'Verifications', 'verify'],
      ['disputes', 'admin#disputes', 'fa-balance-scale', 'Disputes', 'disputes'],
      ['Site'],
      ['site', 'index', 'fa-globe', 'View Website'],
      ['jobs', 'browse-jobs', 'fa-briefcase', 'Live Job Board'],
    ],
  },
};

// Badge counts come from the shared Store (js/app-data.js) when the page loads it
function dashBadges(roleKey) {
  if (typeof Store === 'undefined') return {};
  const unread = threads => threads.reduce((n, t) => n + (t.unread || 0), 0);
  if (roleKey === 'client') {
    const c = Store.get('jsph-client', seedClient);
    return {
      msgs: unread(Store.get('jsph-threads-client', () => seedThreads('client'))),
      applicants: c.applicants.filter(a => a.status === 'new').length,
      invoices: c.invoices.filter(i => i.status === 'due').length,
    };
  }
  if (roleKey === 'admin') {
    const a = Store.get('jsph-admin', seedAdmin);
    return {
      flagged: a.flagged.filter(x => x.status === 'open').length,
      verify: a.verifications.filter(x => x.status === 'pending').length,
      disputes: a.disputes.filter(x => x.status === 'open').length,
    };
  }
  return {
    msgs: unread(Store.get('jsph-threads-va', () => seedThreads('va'))),
    apps: Store.get('jsph-applications', seedApplications).filter(a => ['submitted', 'viewed', 'interview', 'trial', 'trialing'].includes(a.status)).length,
  };
}

// Re-renders just the nav (keeps the top bar and its language toggle); pages call it after changing state
function renderDashNav() {
  const sidebar = document.getElementById('dashSidebar');
  const nav = sidebar && sidebar.querySelector('.dash-nav');
  if (!nav) return;
  const roleKey = sidebar.dataset.role;
  const role = DASH_ROLES[roleKey] || DASH_ROLES.va;
  const active = sidebar.dataset.active;
  const badges = dashBadges(roleKey);
  nav.innerHTML = `
      ${role.nav.map(([key, href, icon, label, badge]) => href === undefined
        ? `<div class="dash-nav-section">${key}</div>`
        : `<a href="${href}" class="dash-nav-item${key === active ? ' active' : ''}"><i class="fas ${icon}"></i> ${label}${badge && badges[badge] ? ` <span class="dash-nav-badge">${badges[badge]}</span>` : ''}</a>`).join('')}
      <div class="dash-nav-divider"></div>
      ${roleKey === 'admin' ? '' : '<a href="#" class="dash-nav-item"><i class="fas fa-cog"></i> Settings</a>'}
      <a href="auth" class="dash-nav-item" style="color:rgba(239,68,68,0.7);"><i class="fas fa-sign-out-alt"></i> Log Out</a>`;
  nav.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
    sidebar.classList.remove('open');
    const overlay = document.getElementById('dashOverlay');
    if (overlay) overlay.classList.remove('visible');
  }));
}

function renderDashShell() {
  const sidebar = document.getElementById('dashSidebar');
  if (!sidebar) return;
  const role = DASH_ROLES[sidebar.dataset.role] || DASH_ROLES.va;
  const u = role.user;

  sidebar.innerHTML = `
    <a href="index" class="dash-brand">
      <div class="dash-brand-icon"><i class="fas fa-briefcase"></i></div>
      <span class="dash-brand-name">Jobseekers<span>.ph</span></span>
    </a>
    <div class="dash-user-card">
      <img src="https://i.pravatar.cc/150?img=${u.img}" alt="" class="dash-user-avatar" />
      <div><div class="dash-user-name">${u.name}</div><div class="dash-user-role">${u.role}</div></div>
      <div class="dash-online-dot" title="Online"></div>
    </div>
    <nav class="dash-nav"></nav>`;
  renderDashNav();

  const topbar = document.getElementById('dashTopbar');
  if (topbar) {
    topbar.innerHTML = `
      <button class="dash-topbar-toggle" id="sidebarToggle" aria-label="Menu"><i class="fas fa-bars"></i></button>
      <div class="dash-search-wrap">
        <i class="fas fa-search" style="color:var(--text-light); font-size:0.8125rem; flex-shrink:0;"></i>
        <input type="text" placeholder="${sidebar.dataset.role === 'client' ? 'Search VAs, applicants…' : sidebar.dataset.role === 'admin' ? 'Search users, posts, disputes…' : 'Search jobs, companies…'}" />
      </div>
      <div class="dash-topbar-right">
        <button class="dash-icon-btn" title="Notifications"><i class="fas fa-bell"></i><span class="notif-dot"></span></button>
        <button class="dash-avatar-btn">
          <img src="https://i.pravatar.cc/150?img=${u.img}" alt="" />
          <span>${u.short}</span>
          <i class="fas fa-chevron-down" style="font-size:0.625rem; color:var(--text-light);"></i>
        </button>
      </div>`;
  }

  const overlay = document.getElementById('dashOverlay');
  const toggle = document.getElementById('sidebarToggle');
  const close = () => { sidebar.classList.remove('open'); overlay && overlay.classList.remove('visible'); };
  if (toggle) toggle.addEventListener('click', () => {
    if (sidebar.classList.contains('open')) return close();
    sidebar.classList.add('open');
    overlay && overlay.classList.add('visible');
  });
  if (overlay) overlay.addEventListener('click', close);
}

renderDashShell();
