(() => {
    const body = document.body;
    const sidebar = document.getElementById('appSidebar');
    const toggle = document.getElementById('sidebarToggle');
    const scrim = document.getElementById('sidebarScrim');

    if (!sidebar || !toggle || !scrim) return;

    const setSidebarOpen = open => {
        body.classList.toggle('sidebar-open', open);
        toggle.setAttribute('aria-expanded', String(open));
        toggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
        scrim.setAttribute('aria-hidden', String(!open));
    };

    const closeSidebar = () => setSidebarOpen(false);
    toggle.addEventListener('click', () => setSidebarOpen(!body.classList.contains('sidebar-open')));
    scrim.addEventListener('click', closeSidebar);
    sidebar.querySelectorAll('a').forEach(link => link.addEventListener('click', closeSidebar));

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && body.classList.contains('sidebar-open')) {
            closeSidebar();
            toggle.focus();
        }
    });

    const syncDashboardSection = () => {
        const section = location.hash === '#query-log' || location.hash === '#cluster-nodes'
            ? location.hash.slice(1)
            : 'dashboard';
        sidebar.querySelectorAll('[data-sidebar-view]').forEach(link => {
            const active = link.dataset.sidebarView === section;
            link.classList.toggle('is-active', active);
            if (active) link.setAttribute('aria-current', 'page');
            else link.removeAttribute('aria-current');
        });
    };

    if (body.classList.contains('dashboard-page')) {
        syncDashboardSection();
        window.addEventListener('hashchange', syncDashboardSection);
    }
})();
