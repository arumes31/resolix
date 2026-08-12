function clearView() {
    allEvents = [];
    eventsByID.clear();
    isViewCleared = true;
    const tableBody = document.getElementById('eventTable');
    tableBody.innerHTML = '';
    const banner = document.getElementById('viewClearedBanner');
    if (banner) {
        banner.classList.remove('is-hidden');
        banner.textContent = 'View cleared — new events will appear as they arrive';
    }
    const clearBtn = document.getElementById('clearViewBtn');
    if (clearBtn) clearBtn.classList.add('active');
}

async function simulateQuery() {
    const domain = document.getElementById('simDomain').value;
    const resBox = document.getElementById('simulatorResult');
    resBox.classList.add('visible');
    resBox.textContent = 'Querying...';
    const button = document.getElementById('simulateBtn');
    button.disabled = true;
    try {
        const response = await fetch(apiPath(`/api/simulate?domain=${encodeURIComponent(domain)}`));
        if (!response.ok) throw new Error(`Simulation failed (${response.status})`);
        const data = await response.json();
        if (data.status === 'success') {
            resBox.innerHTML = `<strong>Results:</strong> ${data.ips.map(escapeHtml).join(', ')}`;
        } else {
            resBox.innerHTML = `<span class="sim-error">Error: ${escapeHtml(data.error)}</span>`;
        }
    } catch (e) { resBox.textContent = 'Error: ' + e.message; }
    finally { button.disabled = false; }
}

function queryDecisionMatches(event, status) {
    if (!status) return true;
    if (status === 'blocked') return Boolean(event.blocked);
    if (status === 'cached') return String(event.cache_status || event.upstream || '').toLowerCase().includes('cache');
    const responseCode = String(event.response_code ?? event.rcode ?? '').toUpperCase();
    if (status === 'failed') return responseCode === '2' || responseCode === 'SERVFAIL' || String(event.status || '').toLowerCase() === 'failed';
    return !event.blocked && responseCode !== '2' && responseCode !== 'SERVFAIL';
}

function fetchStorageStatus() {
    return coalesceRequest('storage-status', async () => {
        const response = await fetch(apiPath('/api/storage/status'));
        if (!response.ok) throw new Error(`Storage status failed (${response.status})`);
        const data = await response.json();
        const archive = data.archive || {};
        document.getElementById('storageDatabaseSize').textContent = formatBytes(data.database_bytes);
        document.getElementById('storageWALSize').textContent = formatBytes(data.wal_bytes);
        document.getElementById('storageQueueDepth').textContent = formatNumber(archive.pending || 0);
        document.getElementById('storageQueueCapacity').textContent = `${formatNumber(archive.pending || 0)} / ${formatNumber(archive.capacity || 0)} queued · ${formatBytes(archive.pending_bytes)}`;
        document.getElementById('storageDroppedEvents').textContent = formatNumber(archive.dropped || 0);
        document.getElementById('storageCheckpointAge').textContent = data.checkpoint_age_seconds >= 0
            ? `Checkpoint ${Math.round(data.checkpoint_age_seconds)}s ago`
            : 'Checkpoint not reported';
        document.getElementById('storageVacuumState').textContent = data.vacuum_recommended
            ? 'Maintenance-window migration recommended'
            : `Incremental vacuum · ${data.auto_vacuum_mode || 'unknown'}`;
    }).catch(error => {
        console.error(error);
        ['storageDatabaseSize', 'storageWALSize', 'storageQueueDepth', 'storageDroppedEvents'].forEach(id => {
            const element = document.getElementById(id);
            if (element) element.textContent = 'Unavailable';
        });
    });
}

function applyQueryFilters() {
    const searchTerm = (document.getElementById('searchInput')?.value || '').trim().toLowerCase();
    const type = document.getElementById('queryTypeFilter')?.value || '';
    const status = document.getElementById('queryStatusFilter')?.value || '';
    const parts = searchTerm.split(/\s+/).filter(Boolean);

    filteredEvents = allEvents.filter(event => {
        if (type && event.type !== type) return false;
        if (!queryDecisionMatches(event, status)) return false;
        return parts.every(part => {
            if (part.startsWith('node:')) return part.length > 5 && (event.node || 'local').toLowerCase().includes(part.slice(5));
            if (part.startsWith('type:')) return part.length > 5 && String(event.type || '').toLowerCase().includes(part.slice(5));
            if (part.startsWith('client:')) return part.length > 7 && String(event.client_ip || '').toLowerCase().includes(part.slice(7));
            if (part.startsWith('alias:')) return part.length > 6 && String(event.alias || '').toLowerCase().includes(part.slice(6));
            return [event.domain, event.client_ip, event.alias, event.node, event.upstream, event.block_reason]
                .some(value => String(value || '').toLowerCase().includes(part));
        });
    });
}

function scheduleQueryRender() {
    if (activePage !== 'querylog' || queryRenderFrame) return;
    queryRenderFrame = requestAnimationFrame(() => {
        queryRenderFrame = null;
        renderEvents();
    });
}

function renderEvents() {
    const tableBody = document.getElementById('eventTable');
    const scroll = document.getElementById('queryScroll');
    if (!tableBody || !scroll) return;
    const focusedRow = document.activeElement?.closest?.('#eventTable tr[data-event-id]');
    const focusedEventID = focusedRow?.dataset.eventId;
    const focusedControls = focusedRow ? [...focusedRow.querySelectorAll('button, [tabindex]')] : [];
    const focusedControlIndex = focusedControls.indexOf(document.activeElement);
    applyQueryFilters();
    const resultCount = document.getElementById('queryResultCount');
    if (resultCount) resultCount.innerHTML = `<i class="metric-dot green"></i>${filteredEvents.length.toLocaleString()} shown · newest first`;

    const viewportHeight = scroll.clientHeight || 640;
    const start = Math.max(0, Math.floor(scroll.scrollTop / queryRowHeight) - queryOverscan);
    const visibleCount = Math.ceil(viewportHeight / queryRowHeight) + queryOverscan * 2;
    const end = Math.min(filteredEvents.length, start + visibleCount);
    const columns = visibleQueryColumns();
    const topHeight = start * queryRowHeight;
    const bottomHeight = Math.max(0, (filteredEvents.length - end) * queryRowHeight);
    const rows = filteredEvents.slice(start, end).map((event, offset) =>
        `<tr id="row-${escapeHtml(event.id)}" data-event-id="${escapeHtml(event.id)}" aria-rowindex="${start + offset + 2}" tabindex="0">${createRowHtml(event)}</tr>`
    ).join('');
    const topSpacer = topHeight > 0 ? `<tr class="virtual-spacer" aria-hidden="true" height="${topHeight}"><td colspan="${columns.length}" height="${topHeight}"></td></tr>` : '';
    const bottomSpacer = bottomHeight > 0 ? `<tr class="virtual-spacer" aria-hidden="true" height="${bottomHeight}"><td colspan="${columns.length}" height="${bottomHeight}"></td></tr>` : '';
    const empty = filteredEvents.length === 0 ? `<tr class="empty-query-row"><td colspan="${columns.length}">${allEvents.length ? 'No queries match these filters.' : 'Waiting for DNS queries…'}</td></tr>` : '';
    tableBody.innerHTML = topSpacer + rows + bottomSpacer + empty;
    tableBody.closest('table')?.setAttribute('aria-rowcount', String(filteredEvents.length + 1));
    if (focusedEventID) {
        const replacementRow = [...tableBody.querySelectorAll('tr[data-event-id]')]
            .find(row => row.dataset.eventId === focusedEventID);
        if (replacementRow) {
            const replacementControls = [...replacementRow.querySelectorAll('button, [tabindex]')];
            const focusTarget = focusedControlIndex >= 0 ? replacementControls[focusedControlIndex] : replacementRow;
            focusTarget?.focus({ preventScroll: true });
        }
    }
}

function renderQueryTableHead() {
    const head = document.getElementById('queryTableHead');
    if (!head) return;
    head.innerHTML = visibleQueryColumns().map(key => `<th id="query-column-${key}" data-col="${key}" scope="col">${queryColumnLabels[key]}</th>`).join('');
}

function renderColumnChooser() {
    const list = document.getElementById('columnChooserList');
    if (!list) return;
    list.innerHTML = queryColumns.order.map((key, index) => {
        const checked = !queryColumns.hidden.includes(key) ? ' checked' : '';
        return `<div class="column-choice" data-column="${key}"><label><input type="checkbox"${checked}>${queryColumnLabels[key]}</label><span><button type="button" data-move="up" aria-label="Move ${queryColumnLabels[key]} left"${index === 0 ? ' disabled' : ''}>←</button><button type="button" data-move="down" aria-label="Move ${queryColumnLabels[key]} right"${index === queryColumns.order.length - 1 ? ' disabled' : ''}>→</button></span></div>`;
    }).join('');
}

function persistQueryFilters() {
    const state = {
        q: document.getElementById('searchInput')?.value || '',
        type: document.getElementById('queryTypeFilter')?.value || '',
        status: document.getElementById('queryStatusFilter')?.value || ''
    };
    localStorage.setItem('resolix.queryFilters', JSON.stringify(state));
    const url = new URL(location.href);
    Object.entries(state).forEach(([key, value]) => value ? url.searchParams.set(key, value) : url.searchParams.delete(key));
    history.replaceState(null, '', url);
    renderFilterChips(state);
}

function renderFilterChips(state) {
    const container = document.getElementById('queryFilterChips');
    if (!container) return;
    const labels = { q: 'Search', type: 'Type', status: 'Decision' };
    const chips = Object.entries(state).filter(([, value]) => value).map(([key, value]) =>
        `<button type="button" class="filter-chip" data-filter-key="${key}" aria-label="Remove ${labels[key]} filter">${labels[key]}: ${escapeHtml(value)} <span aria-hidden="true">×</span></button>`
    );
    container.innerHTML = chips.length ? chips.join('') : '<span class="filter-empty">No active filters</span>';
}

function restoreQueryFilters() {
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem('resolix.queryFilters') || '{}'); } catch (_) { saved = {}; }
    const params = new URLSearchParams(location.search);
    const state = {
        q: params.get('q') ?? saved.q ?? '',
        type: params.get('type') ?? saved.type ?? '',
        status: params.get('status') ?? saved.status ?? ''
    };
    const search = document.getElementById('searchInput');
    const type = document.getElementById('queryTypeFilter');
    const status = document.getElementById('queryStatusFilter');
    if (search) search.value = state.q;
    if (type && Array.from(type.options).some(option => option.value === state.type)) type.value = state.type;
    if (status && Array.from(status.options).some(option => option.value === state.status)) status.value = state.status;
    renderFilterChips(state);
}

function renderQuerySkeleton() {
    const tableBody = document.getElementById('eventTable');
    if (!tableBody) return;
    const columns = visibleQueryColumns().length;
    tableBody.innerHTML = Array.from({ length: 8 }, () => `<tr class="skeleton-row" aria-hidden="true"><td colspan="${columns}"><span class="skeleton-bar"></span></td></tr>`).join('');
}

function refreshEventTimes() {
    document.querySelectorAll('#eventTable .timestamp[data-unix-time]').forEach(cell => {
        const relative = cell.querySelector('.timestamp-relative');
        const unixTime = Number(cell.dataset.unixTime);
        if (relative && Number.isFinite(unixTime)) relative.textContent = getRelativeTime(unixTime);
    });
}

