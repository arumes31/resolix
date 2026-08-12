async function decommissionNode(button) {
	const identity = button.dataset.nodeId;
	const name = button.dataset.nodeName || identity;
    if (button.dataset.confirmed !== 'true') {
        button.dataset.confirmed = 'true';
        button.classList.add('is-confirming');
        button.textContent = 'Confirm removal';
        button.setAttribute('aria-label', `Confirm decommissioning ${name}`);
        announce(`Press confirm removal to decommission ${name}`);
        setTimeout(() => {
            if (!button.isConnected || button.disabled) return;
            button.dataset.confirmed = 'false';
            button.classList.remove('is-confirming');
            button.textContent = 'Decommission';
            button.setAttribute('aria-label', `Decommission ${name}`);
        }, 6000);
        return;
    }
    button.disabled = true;
    try {
		await apiJSON(`/api/nodes?id=${encodeURIComponent(identity)}`, { method: 'DELETE' });
        announce(`${name} decommissioned`);
        await fetchNodeStatus();
    } catch (error) {
        button.disabled = false;
        button.dataset.confirmed = 'false';
        button.classList.remove('is-confirming');
        button.textContent = 'Decommission';
        showSettingsNotice(error.message, true);
    }
}

async function applyQueryAction(button) {
    const domain = button.dataset.domain;
    const action = button.dataset.action;
    button.disabled = true;
    try {
        const data = await apiJSON(`/api/querylog/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain })
        });
        const nextAction = action === 'block' ? 'unblock' : 'block';
        updateQueryActionState(domain, nextAction);
        showUndoNotice(`${domain}: ${String(data.action || action).replaceAll('_', ' ')}`, async () => {
            await apiJSON(`/api/querylog/${nextAction}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });
            updateQueryActionState(domain, action);
            showSettingsNotice(`${domain}: change undone`);
            announce(`Undid query rule change for ${domain}`);
        });
        announce(`${domain} ${action === 'block' ? 'blocked' : 'unblocked'}`);
    } finally {
        button.disabled = false;
    }
}

document.getElementById('freezeBtn')?.addEventListener('click', function () {
    isFrozen = !isFrozen;
    this.classList.toggle('freeze-active', isFrozen);
    this.textContent = isFrozen ? '▶️' : '⏸️';
    this.setAttribute('aria-pressed', String(isFrozen));
    this.setAttribute('aria-label', isFrozen ? 'Resume live query log' : 'Freeze live query log');
    if (!isFrozen && frozenEvents.length > 0) {
        frozenEvents.forEach(event => mergeEvent(event, false));
        frozenEvents = [];
        renderEvents();
    }
});

document.getElementById('clearViewBtn')?.addEventListener('click', function () {
    clearView();
});

document.getElementById('simulateBtn')?.addEventListener('click', simulateQuery);
document.getElementById('modalCloseBtn')?.addEventListener('click', function () {
    closeClientModal();
});
document.getElementById('clientModal')?.addEventListener('click', function (event) {
    if (event.target === this) closeClientModal();
});
document.addEventListener('keydown', event => {
    const modal = document.getElementById('clientModal');
    const drawer = document.getElementById('queryDetailDrawer');
    if (modal?.classList.contains('open')) {
        if (event.key === 'Escape') closeClientModal();
        trapDialogFocus(modal, event);
        return;
    }
    if (drawer?.classList.contains('open')) {
        if (event.key === 'Escape') closeQueryDetail();
        trapDialogFocus(drawer, event);
        return;
    }
    const editing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
    if (!editing && event.key === '/') {
        event.preventDefault();
        document.getElementById('searchInput')?.focus();
        return;
    }
    if (!editing && event.key.toLowerCase() === 'r') {
        event.preventDefault();
        if (activePage === 'dashboard') void fetchStats();
        if (activePage === 'querylog') void fetchEvents();
        if (activePage === 'cluster') void Promise.all([fetchNodeStatus(), fetchStorageStatus()]);
        return;
    }
    if (!editing && navigationPrefix) {
        const routes = { d: './', q: 'querylog', c: 'cluster', s: 'config' };
        navigationPrefix = false;
        if (routes[event.key.toLowerCase()]) location.href = routes[event.key.toLowerCase()];
        return;
    }
    if (!editing && event.key.toLowerCase() === 'g') {
        navigationPrefix = true;
        setTimeout(() => { navigationPrefix = false; }, 1200);
    }
});

document.getElementById('refreshNodesBtn')?.addEventListener('click', () => { void Promise.all([fetchNodeStatus(), fetchStorageStatus()]); });
document.getElementById('queryDetailClose')?.addEventListener('click', closeQueryDetail);
document.getElementById('queryDrawerScrim')?.addEventListener('click', closeQueryDetail);
document.getElementById('queryUndoBtn')?.addEventListener('click', () => { void runUndoNotice(); });

window.resolixRefreshPage = () => {
    if (activePage === 'dashboard') return fetchStats();
    if (activePage === 'querylog') return fetchEvents();
    if (activePage === 'cluster') return Promise.all([fetchNodeStatus(), fetchStorageStatus()]);
    return Promise.resolve();
};

function updateVisibility() {
    isTabVisible = document.visibilityState === 'visible';
    if (statsInterval) clearInterval(statsInterval);
    if (nodeStatusInterval) clearInterval(nodeStatusInterval);
    statsInterval = null;
    nodeStatusInterval = null;

    if (!isTabVisible) {
        if (activePage === 'querylog') {
            stopStream();
            setStreamStatus(false);
        }
        return;
    }

    if (activePage === 'dashboard') {
        statsInterval = setInterval(() => { void fetchStats(); }, 10000);
        void fetchStats();
    } else if (activePage === 'querylog') {
        statsInterval = setInterval(() => { void fetchEvents(); }, 10000);
        void fetchEvents();
        startStream();
    } else if (activePage === 'cluster') {
        nodeStatusInterval = setInterval(() => { void Promise.all([fetchNodeStatus(), fetchStorageStatus()]); }, 30000);
        void Promise.all([fetchNodeStatus(), fetchStorageStatus()]);
    }
}

function updateQueryActionState(domain, nextAction) {
    document.querySelectorAll('.query-action-btn').forEach(candidate => {
        if (candidate.dataset.domain !== domain) return;
        candidate.dataset.action = nextAction;
        candidate.textContent = nextAction === 'unblock' ? 'Allow' : 'Block';
        candidate.classList.toggle('is-unblock', nextAction === 'unblock');
    });
    allEvents.forEach(event => {
        if (event.domain === domain) event.user_rule_action = nextAction;
    });
}

function showUndoNotice(message, undo) {
    const toast = document.getElementById('queryUndoToast');
    const messageElement = document.getElementById('queryUndoMessage');
    if (!toast || !messageElement) return;
    if (undoTimer) clearTimeout(undoTimer);
    pendingUndo = undo;
    messageElement.textContent = message;
    toast.classList.add('open');
    toast.setAttribute('aria-hidden', 'false');
    toast.inert = document.getElementById('queryDetailDrawer')?.classList.contains('open') ?? false;
    undoTimer = setTimeout(hideUndoNotice, 8000);
}

function hideUndoNotice() {
    const toast = document.getElementById('queryUndoToast');
    if (undoTimer) clearTimeout(undoTimer);
    undoTimer = null;
    pendingUndo = null;
    toast?.classList.remove('open');
    toast?.setAttribute('aria-hidden', 'true');
    if (toast) toast.inert = true;
}

async function runUndoNotice() {
    const undo = pendingUndo;
    if (!undo) return;
    const button = document.getElementById('queryUndoBtn');
    if (button) button.disabled = true;
    pendingUndo = null;
    try {
        await undo();
        hideUndoNotice();
    } catch (error) {
        showSettingsNotice(error.message, true);
    } finally {
        if (button) button.disabled = false;
    }
}

function decisionSteps(event) {
    const steps = ['Request accepted'];
    if (event.matched_rule) steps.push(`Rule matched: ${event.matched_rule}`);
    if (event.block_reason) steps.push(`Policy decision: ${event.block_reason}`);
    if (event.cache_status) steps.push(`Cache: ${event.cache_status}`);
    else if (String(event.upstream || '').includes('Cache')) steps.push(`Cache: ${event.upstream}`);
    if (event.upstream && !String(event.upstream).includes('Cache')) steps.push(`Resolver: ${event.upstream}`);
    steps.push(event.blocked ? 'Response blocked' : `Response returned${event.rcode != null ? ` (RCODE ${event.rcode})` : ''}`);
    return steps;
}

function openQueryDetail(event) {
    const drawer = document.getElementById('queryDetailDrawer');
    const body = document.getElementById('queryDetailBody');
    if (!drawer || !body) return;
    lastQueryDetailFocus = document.activeElement;
    const timestamp = event.unix_time ? new Date(event.unix_time * 1000).toLocaleString() : '—';
    const responseCode = event.response_code ?? event.rcode ?? '—';
    const fields = [
        ['Time', timestamp, false], ['Domain', event.domain, true], ['Type', event.type, false],
        ['Decision', event.blocked ? 'Blocked' : 'Allowed', false], ['Client', event.client_ip, true],
        ['Client alias', event.alias || '—', false], ['Node', event.node || 'local', true],
        ['Upstream', event.upstream || '—', Boolean(event.upstream)],
        ['Latency', event.latencyFormatted || (event.latency_ms != null ? `${Number(event.latency_ms).toFixed(1)}ms` : '—'), false],
        ['Response', responseCode, false], ['Cache state', event.cache_status || '—', false],
        ['Cache TTL', event.cache_ttl != null ? `${event.cache_ttl}s` : '—', false],
        ['Negative SOA', event.negative_soa || '—', Boolean(event.negative_soa)],
        ['Matched rule', event.matched_rule || '—', Boolean(event.matched_rule)], ['Block reason', event.block_reason || '—', false]
    ];
    body.innerHTML = `<dl class="query-detail-grid">${fields.map(([label, value, copyable]) => `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}${copyable ? copyControl(value, label.toLowerCase()) : ''}</dd></div>`).join('')}</dl><ol class="decision-path" aria-label="Decision path">${decisionSteps(event).map(step => `<li>${escapeHtml(step)}</li>`).join('')}</ol>`;
    drawer.inert = false;
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    const scrim = document.getElementById('queryDrawerScrim');
    scrim?.classList.add('open');
    scrim?.setAttribute('aria-hidden', 'false');
    document.body.classList.add('query-drawer-open');
    const toast = document.getElementById('queryUndoToast');
    if (toast) toast.inert = true;
    document.getElementById('queryDetailClose')?.focus();
}

function closeQueryDetail() {
    const drawer = document.getElementById('queryDetailDrawer');
    if (!drawer?.classList.contains('open')) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    drawer.inert = true;
    const scrim = document.getElementById('queryDrawerScrim');
    scrim?.classList.remove('open');
    scrim?.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('query-drawer-open');
    const toast = document.getElementById('queryUndoToast');
    if (toast?.classList.contains('open')) toast.inert = false;
    if (lastQueryDetailFocus?.isConnected) lastQueryDetailFocus.focus();
}

function trapDialogFocus(dialog, event) {
    if (event.key !== 'Tab') return;
    const focusable = [...dialog.querySelectorAll('button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')]
        .filter(element => element.offsetParent !== null);
    if (focusable.length === 0) return;
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

async function copyQueryValue(button) {
    const value = button.dataset.copy || '';
    if (navigator.clipboard?.writeText && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
    } else {
        const fallback = document.createElement('textarea');
        fallback.value = value;
        fallback.setAttribute('readonly', '');
        fallback.className = 'clipboard-fallback';
        document.body.append(fallback);
        fallback.select();
        const copied = document.execCommand('copy');
        fallback.remove();
        if (!copied) throw new Error('Clipboard access is unavailable');
    }
    const original = button.textContent;
    button.textContent = '✓';
    button.classList.add('copied');
    setTimeout(() => {
        button.textContent = original;
        button.classList.remove('copied');
    }, 1200);
    announce(`${button.getAttribute('aria-label') || 'Value'} copied`);
}

function initializeQueryLog() {
    if (activePage !== 'querylog') return;
    restoreQueryFilters();
    renderQueryTableHead();
    renderColumnChooser();
    renderQuerySkeleton();

    document.getElementById('queryScroll').addEventListener('scroll', scheduleQueryRender, { passive: true });
    ['searchInput', 'queryTypeFilter', 'queryStatusFilter'].forEach(id => {
        document.getElementById(id).addEventListener(id === 'searchInput' ? 'input' : 'change', () => {
            document.getElementById('queryScroll').scrollTop = 0;
            persistQueryFilters();
            scheduleQueryRender();
        });
    });
    document.getElementById('queryFilterChips').addEventListener('click', event => {
        const chip = event.target.closest('[data-filter-key]');
        if (!chip) return;
        const controls = { q: 'searchInput', type: 'queryTypeFilter', status: 'queryStatusFilter' };
        document.getElementById(controls[chip.dataset.filterKey]).value = '';
        persistQueryFilters();
        scheduleQueryRender();
    });
    document.getElementById('columnChooserList').addEventListener('change', event => {
        const choice = event.target.closest('[data-column]');
        if (!choice || event.target.type !== 'checkbox') return;
        const key = choice.dataset.column;
        queryColumns.hidden = event.target.checked ? queryColumns.hidden.filter(item => item !== key) : [...new Set([...queryColumns.hidden, key])];
        if (queryColumns.hidden.length === defaultQueryColumns.length) queryColumns.hidden = queryColumns.hidden.filter(item => item !== key);
        saveQueryColumns();
        renderQueryTableHead();
        renderColumnChooser();
        scheduleQueryRender();
    });
    document.getElementById('columnChooserList').addEventListener('click', event => {
        const button = event.target.closest('[data-move]');
        const choice = event.target.closest('[data-column]');
        if (!button || !choice) return;
        const index = queryColumns.order.indexOf(choice.dataset.column);
        const target = button.dataset.move === 'up' ? index - 1 : index + 1;
        if (target < 0 || target >= queryColumns.order.length) return;
        [queryColumns.order[index], queryColumns.order[target]] = [queryColumns.order[target], queryColumns.order[index]];
        saveQueryColumns();
        renderQueryTableHead();
        renderColumnChooser();
        scheduleQueryRender();
    });
}

document.addEventListener('visibilitychange', updateVisibility);

// Event delegation for test-domain-btn (XSS-safe: domain from data attribute)
document.addEventListener('click', function (e) {
    const decommission = e.target.closest('.node-decommission-btn');
    if (decommission) {
        e.stopPropagation();
        void decommissionNode(decommission);
        return;
    }
    const copyButton = e.target.closest('[data-copy]');
    if (copyButton) {
        e.stopPropagation();
        copyQueryValue(copyButton).catch(error => showSettingsNotice(error.message, true));
        return;
    }
    const queryAction = e.target.closest('.query-action-btn');
    if (queryAction) {
        e.stopPropagation();
        applyQueryAction(queryAction).catch(error => showSettingsNotice(error.message, true));
        return;
    }
    const btn = e.target.closest('.test-domain-btn');
    if (btn) {
        e.stopPropagation();
        prefillSimulator(btn.dataset.domain);
    }
    const clientCell = e.target.closest('.client-cell');
    if (clientCell) {
        e.stopPropagation();
        showClientStats(clientCell.dataset.clientIp);
        return;
    }
    const row = e.target.closest('#eventTable tr[data-event-id]');
    if (row) {
        const event = allEvents.find(item => String(item.id) === row.dataset.eventId);
        if (event) openQueryDetail(event);
    }
});

document.getElementById('eventTable')?.addEventListener('keydown', event => {
    if (!['Enter', ' '].includes(event.key)) return;
    const row = event.target.closest('tr[data-event-id]');
    if (!row) return;
    event.preventDefault();
    const item = allEvents.find(candidate => String(candidate.id) === row.dataset.eventId);
    if (item) openQueryDetail(item);
});

initializeQueryLog();
updateVisibility(); // Initial set
if (activePage === 'querylog') {
    setInterval(() => {
        if (isTabVisible && !isFrozen) refreshEventTimes();
    }, 30000);
}

