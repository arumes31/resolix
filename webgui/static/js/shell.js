(() => {
    const body = document.body;
    const sidebar = document.getElementById('appSidebar');
    const toggle = document.getElementById('sidebarToggle');
    const scrim = document.getElementById('sidebarScrim');

    if (!sidebar || !toggle || !scrim) return;

    const drawerLayout = window.matchMedia('(max-width: 900px)');
    const focusableSelector = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

    const setSidebarOpen = (open, moveFocus = true) => {
        const drawerOpen = drawerLayout.matches && open;
        body.classList.toggle('sidebar-open', drawerOpen);
        toggle.setAttribute('aria-expanded', String(drawerOpen));
        toggle.setAttribute('aria-label', drawerOpen ? 'Close navigation' : 'Open navigation');
        scrim.setAttribute('aria-hidden', String(!drawerOpen));

        const drawerClosed = drawerLayout.matches && !drawerOpen;
        sidebar.inert = drawerClosed;
        if (drawerClosed && sidebar.contains(document.activeElement)) {
            toggle.focus();
        } else if (drawerOpen && moveFocus) {
            const focusTarget = sidebar.querySelector(focusableSelector) || sidebar;
            if (focusTarget === sidebar) sidebar.setAttribute('tabindex', '-1');
            focusTarget.focus();
        }
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

    const handleLayoutChange = () => setSidebarOpen(false, false);
    if (typeof drawerLayout.addEventListener === 'function') {
        drawerLayout.addEventListener('change', handleLayoutChange);
    } else {
        drawerLayout.addListener(handleLayoutChange);
    }
    setSidebarOpen(false, false);

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
