(() => {
    const body = document.body;
    const sidebar = document.getElementById('appSidebar');
    const toggle = document.getElementById('sidebarToggle');
    const scrim = document.getElementById('sidebarScrim');

    const liveRegion = document.createElement('div');
    liveRegion.id = 'globalLiveRegion';
    liveRegion.className = 'sr-only';
    liveRegion.setAttribute('role', 'status');
    liveRegion.setAttribute('aria-live', 'polite');
    liveRegion.setAttribute('aria-atomic', 'true');
    body.appendChild(liveRegion);
    window.resolixAnnounce = (message) => {
        liveRegion.textContent = '';
        window.setTimeout(() => { liveRegion.textContent = String(message || ''); }, 20);
    };

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

    const page = body.dataset.page || 'dashboard';
    sidebar.querySelectorAll('.app-nav-link[href]').forEach(link => {
        const href = (link.getAttribute('href') || '').replace(/^\.\//, '').replace(/\/$/, '');
        const targetPage = href === '' || href === '.' ? 'dashboard' : href.split('/').pop();
        const active = targetPage === page;
        link.classList.toggle('is-active', active);
        if (active) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
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

    document.addEventListener('keydown', event => {
        const dialog = document.querySelector('[role="dialog"][aria-hidden="false"]');
        if (event.key === 'Tab' && dialog) {
            const focusable = Array.from(dialog.querySelectorAll(focusableSelector)).filter(element => !element.inert);
            if (focusable.length > 0) {
                const first = focusable[0];
                const last = focusable[focusable.length - 1];
                if (event.shiftKey && document.activeElement === first) {
                    event.preventDefault();
                    last.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            }
        }

        const target = event.target;
        const isEditing = target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement || target?.isContentEditable;
        if (!isEditing && event.key === '/') {
            const search = document.getElementById('searchInput') || document.getElementById('simDomain');
            if (search) {
                event.preventDefault();
                search.focus();
            }
        }
        if (!isEditing && event.key.toLowerCase() === 'r' && !event.ctrlKey && !event.metaKey && !event.altKey) {
            const refresh = document.getElementById('refreshNodesBtn') || document.getElementById('refreshConfigBtn');
            if (refresh) {
                event.preventDefault();
                refresh.click();
                window.resolixAnnounce('Refresh requested');
            } else if (typeof window.resolixRefreshPage === 'function') {
                event.preventDefault();
                window.resolixRefreshPage();
                window.resolixAnnounce('Refresh requested');
            }
        }
    });
})();
