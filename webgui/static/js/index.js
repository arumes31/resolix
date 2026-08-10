function escapeHtml(unsafe) {
    if (unsafe == null) return '';
    return String(unsafe)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
    }
    if (num >= 1000) {
        return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
    }
    return num;
}

function getRelativeTime(timestamp) {
    const diff = Math.floor(Date.now() / 1000 - timestamp);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
}

function applyDynamicStyles(root) {
    root.querySelectorAll('[data-height]').forEach((element) => {
        element.style.height = `${Math.max(0, Math.min(100, Number(element.dataset.height)))}%`;
    });
    root.querySelectorAll('[data-width]').forEach((element) => {
        element.style.width = `${Math.max(0, Math.min(100, Number(element.dataset.width)))}%`;
    });
}

// Base URL prefix for API requests (empty for root deployments)
const apiBase = (document.body.dataset.baseUrl || '/').replace(/\/$/, '');
const configReadOnly = document.body.dataset.mode === 'agent';

function apiPath(path) {
    return apiBase + path;
}

const inFlightRequests = new Map();
const renderedHTML = new WeakMap();

function coalesceRequest(key, task) {
    const existing = inFlightRequests.get(key);
    if (existing) return existing;

    const request = Promise.resolve().then(task).finally(() => {
        if (inFlightRequests.get(key) === request) inFlightRequests.delete(key);
    });
    inFlightRequests.set(key, request);
    return request;
}

function replaceHTMLIfChanged(element, html) {
    if (renderedHTML.get(element) === html) return false;
    element.innerHTML = html;
    renderedHTML.set(element, html);
    return true;
}

let allEvents = [];
let rpmHistory = Array(20).fill(0);
let lastEventTimestamp = 0;
let lastEventID = '';
let isTabVisible = true;
let isFrozen = false;
let isViewCleared = false;
let statsInterval = null;
let nodeStatusInterval = null;
let knownServices = [];
let configuredClients = [];
let editingClient = null;
let frozenEvents = [];
let lastModalFocus = null;
let streamConnected = false;
let pollingHealthy = true;
const loadedSettings = new Set();

function renderSystemStatus() {
    const status = document.getElementById('systemStatus');
    status.classList.toggle('offline', !streamConnected || !pollingHealthy);
    if (!pollingHealthy) {
        status.textContent = '● System Offline';
    } else if (!streamConnected) {
        status.textContent = '● Live stream reconnecting';
    } else {
        status.textContent = '● Live stream connected';
    }
}

function setStreamStatus(connected) {
    streamConnected = connected;
    renderSystemStatus();
}

function setPollingStatus(healthy) {
    pollingHealthy = healthy;
    renderSystemStatus();
}

function mergeEvent(newEvent, updateDOM = true) {
    const index = allEvents.findIndex(e => e.id === newEvent.id);
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const isFiltered = searchTerm.length > 0;
    if (index !== -1) {
        allEvents[index] = newEvent;
        if (updateDOM && !isFiltered && isTabVisible) updateRowInDom(newEvent);
    } else {
        allEvents.unshift(newEvent);
        if (allEvents.length > 1000) allEvents.pop();
        if (updateDOM && !isFiltered && isTabVisible) prependRowToDom(newEvent);
    }
    if (isFiltered && updateDOM && isTabVisible) {
        if (window.renderTimeout) clearTimeout(window.renderTimeout);
        window.renderTimeout = setTimeout(renderEvents, 100);
    }
}

// Stream handler
function startStream() {
    const eventSource = new EventSource(apiPath('/api/stream'));
    eventSource.onopen = () => setStreamStatus(true);
    eventSource.onmessage = (event) => {
        try {
            const newEvent = JSON.parse(event.data);

            if (event.lastEventId) lastEventID = event.lastEventId;
            if (isFrozen) {
                const index = frozenEvents.findIndex(item => item.id === newEvent.id);
                if (index === -1) frozenEvents.push(newEvent); else frozenEvents[index] = newEvent;
                if (frozenEvents.length > 1000) frozenEvents.shift();
                return;
            }

            // Dismiss view-cleared banner when new events arrive
            if (isViewCleared) {
                isViewCleared = false;
                const banner = document.getElementById('viewClearedBanner');
                if (banner) banner.classList.add('is-hidden');
                const clearBtn = document.getElementById('clearViewBtn');
                if (clearBtn) clearBtn.classList.remove('active');
            }

            mergeEvent(newEvent);
        } catch (e) {
            console.error("Failed to parse SSE event:", e, event.data);
        }
    };
    eventSource.onerror = () => {
        setStreamStatus(false);
        console.error("SSE connection lost. Reconnecting...");
    };
}

function createRowHtml(e) {
    const hasLatency = e.latency_ms !== null && e.latency_ms !== undefined;
    let latencyClass = hasLatency ? 'latency-low' : 'latency-neutral';
    if (hasLatency && e.latency_ms > 50) latencyClass = 'latency-mid';
    if (hasLatency && e.latency_ms > 150) latencyClass = 'latency-high';

    const latencyText = e.latencyFormatted || (hasLatency ? e.latency_ms.toFixed(1) + 'ms' : '-');
    const timeStr = new Date(e.unix_time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    const relTime = getRelativeTime(e.unix_time);
    const action = e.user_rule_action || (e.blocked ? 'unblock' : 'block');
    const actionLabel = action === 'unblock' ? 'Unblock' : 'Block';

    return `
        <td class="timestamp" data-unix-time="${escapeHtml(e.unix_time)}"><div class="timestamp-primary">${escapeHtml(timeStr)}</div><div class="timestamp-relative">${escapeHtml(relTime)}</div></td>
        <td><span class="badge node-badge">${escapeHtml(e.node || 'local')}</span></td>
        <td><span class="badge badge-type">${escapeHtml(e.type)}</span></td>
        <td class="domain cell-with-copy">${escapeHtml(e.domain)}<button type="button" class="test-domain-btn" title="Test in simulator" aria-label="Test ${escapeHtml(e.domain)} in simulator" data-domain="${escapeHtml(e.domain)}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></button></td>
        <td class="client-cell" data-client-ip="${escapeHtml(e.client_ip)}" title="Click for details">
            <span class="badge badge-ip">${escapeHtml(e.client_ip)}</span>
            ${e.alias ? `<span class="alias-tag">${escapeHtml(e.alias)}</span>` : ''}
        </td>
        <td>${e.upstream ? `<span class="upstream-badge">${escapeHtml(e.upstream)}</span>` : '-'}</td>
        <td class="latency-cell ${latencyClass}">${escapeHtml(latencyText)}</td>
        <td>${configReadOnly ? '<span class="settings-list-meta">Controller managed</span>' : `<button type="button" class="query-action-btn ${action === 'unblock' ? 'is-unblock' : ''}" aria-label="${actionLabel} ${escapeHtml(e.domain)}" data-domain="${escapeHtml(e.domain)}" data-action="${action}">${actionLabel}</button>`}</td>
    `;
}

function prependRowToDom(e) {
    const tableBody = document.getElementById('eventTable');
    const row = document.createElement('tr');
    row.id = `row-${e.id}`;
    row.innerHTML = createRowHtml(e);
    tableBody.prepend(row);

    // Limit DOM size
    if (tableBody.children.length > 100) {
        tableBody.removeChild(tableBody.lastChild);
    }
}

function updateRowInDom(e) {
    const row = document.getElementById(`row-${e.id}`);
    if (row) {
        row.innerHTML = createRowHtml(e);
    }
}

async function fetchAll() {
    await Promise.allSettled([fetchEvents(), fetchStats(), fetchNodeStatus()]);
}

function fetchEvents() {
    return coalesceRequest('events', async () => {
        try {
        const cursorQuery = lastEventID ? `?cursor=${encodeURIComponent(lastEventID)}&limit=1000` : '?limit=1000';
        const response = await fetch(apiPath('/api/events' + cursorQuery));
        if (!response.ok) throw new Error(`Events API failed (${response.status})`);
        const newEvents = await response.json();
        const nextCursor = response.headers.get('X-Next-Cursor');
        if (nextCursor) lastEventID = nextCursor;

        if (newEvents.length > 0) {
            if (allEvents.length === 0) {
                allEvents = newEvents.slice(0, 1000).reverse();
            } else {
                newEvents.forEach(event => mergeEvent(event, false));
            }
            renderEvents();
        }

        setPollingStatus(true);
    } catch (e) {
        console.error(e);
        setPollingStatus(false);
        }
    });
}

function fetchStats() {
    return coalesceRequest('stats', async () => {
        try {
        const response = await fetch(apiPath('/api/stats'));
        if (!response.ok) throw new Error(`Stats API failed (${response.status})`);
        const stats = await response.json();
        renderTopList('topDomains', stats.top_domains);
        renderTopList('topClients', stats.top_clients);

        // Update counters
        document.getElementById('rpm_val').textContent = formatNumber(stats.rpm) + ' RPM';
        document.getElementById('rph_val').textContent = formatNumber(stats.rph);
        document.getElementById('rpd_val').textContent = formatNumber(stats.rpd);
        document.getElementById('total_val').textContent = formatNumber(stats.total);
        document.getElementById('cache_ratio').textContent = (stats.cache_hit_ratio || 0).toFixed(1) + '%';

        // Update health list with sparklines (Per Node)
        const healthEl = document.getElementById('upstreamHealth');
        if (stats.node_health) {
            const healthHTML = Object.entries(stats.node_health).map(([node, upstreams]) => {
                const nodeHtml = Object.entries(upstreams).map(([ip, lat]) => {
                    const hist = (stats.node_health_hist && stats.node_health_hist[node]) ? stats.node_health_hist[node][ip] || [] : [];
                    const maxLat = Math.max(...hist.filter(l => l > 0), 1);
                    const sparkline = `<div class="sparkline">${hist.map(l => {
                        const h = l === -1 ? 100 : (l / maxLat) * 100;
                        return `<div class="spark-bar ${l === -1 ? 'fail' : ''}" data-height="${h}"></div>`;
                    }).join('')}</div>`;

                    return `
                        <div class="health-row">
                            <div class="health-label">
                                <span class="health-ip">${escapeHtml(ip)}</span>
                                ${sparkline}
                            </div>
                            <span class="top-count health-status ${lat === -1 ? 'down' : 'up'}">${lat === -1 ? 'DOWN' : lat.toFixed(1) + 'ms'}</span>
                        </div>
                    `;
                }).join('');

                return `
                    <li class="health-node">
                        <div class="health-node-title">Node: ${escapeHtml(node)}</div>
                        ${nodeHtml}
                    </li>
                `;
            }).join('');
            if (replaceHTMLIfChanged(healthEl, healthHTML)) applyDynamicStyles(healthEl);
        }

        // Update type breakdown bars
        const typeEl = document.getElementById('typeBreakdown');
        if (stats.type_counts) {
            const total = Object.values(stats.type_counts).reduce((a, b) => a + b, 0);
            if (total === 0) {
                replaceHTMLIfChanged(typeEl, '<div class="empty-small">No data</div>');
            } else {
                const sortedTypes = Object.entries(stats.type_counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
                const typeHTML = sortedTypes.map(([type, count]) => {
                    const pct = (count / total) * 100;
                    return `
                        <div class="type-item">
                            <div class="type-row">
                                <span>${escapeHtml(type)}</span>
                                <span class="type-meta">${count} (${pct.toFixed(1)}%)</span>
                            </div>
                            <div class="type-track">
                                <div class="type-bar" data-width="${pct}"></div>
                            </div>
                        </div>
                    `;
                }).join('');
                if (replaceHTMLIfChanged(typeEl, typeHTML)) applyDynamicStyles(typeEl);
            }
        }

        // Update heatmap
        const heatmapEl = document.getElementById('trafficHeatmap');
        if (stats.heatmap) {
            const sortedHours = Object.entries(stats.heatmap).sort();
            const maxCount = Math.max(...sortedHours.map(h => h[1]), 1);
            const heatmapHTML = sortedHours.map(([hour, count]) => {
                const level = count === 0 ? 0 : Math.max(1, Math.ceil((count / maxCount) * 10));
                return `<div class="heatmap-box heatmap-level-${level}" title="${escapeHtml(hour)}: ${count} queries">${escapeHtml(hour.split(':')[0])}</div>`;
            }).join('');
            replaceHTMLIfChanged(heatmapEl, heatmapHTML);
        }

        // Update node list
        const nodeStats = document.getElementById('nodeStats');
        if (stats.nodes) {
            const nodeHTML = Object.entries(stats.nodes).map(([name, s]) => `
                <li class="top-item">
                    <span>${escapeHtml(name)}</span>
                    <span><span class="top-count">${formatNumber(s.rpm)}</span> <span class="top-count node-rph">${formatNumber(s.rph)}</span></span>
                </li>
            `).join('');
            replaceHTMLIfChanged(nodeStats, nodeHTML);
        } else {
            replaceHTMLIfChanged(nodeStats, '');
        }

        // Update chart locally
        rpmHistory.push(stats.rpm);
        rpmHistory.shift();
        renderMiniChart();
        } catch (e) { console.error(e); }
    });
}
function fetchNodeStatus() {
    return coalesceRequest('nodes', async () => {
        try {
        const response = await fetch(apiPath('/api/nodes'));
        if (!response.ok) return;
        const data = await response.json();
        const nodes = data.nodes || [];
        const container = document.getElementById('nodeCards');
        if (!container) return;
        if (!nodes || nodes.length === 0) {
            replaceHTMLIfChanged(container, '<p class="empty-state">No agent nodes connected</p>');
            return;
        }
        const nodeCardsHTML = nodes.map(node => {
            const statusClass = node.online ? 'online' : 'offline';
            const statusText = node.online ? 'Online' : 'Offline';
            const lastSeen = node.last_seen ? getRelativeTime(new Date(node.last_seen).getTime() / 1000) : 'Never';
            const memInfo = node.memory_mb != null ? node.memory_mb.toFixed(1) + ' MB' : '-';
            const dbInfo = node.db_size_mb != null ? node.db_size_mb.toFixed(1) + ' MB' : '-';
            return '<div class="node-card">' +
                '<div class="node-card-header">' +
                '<span class="node-name">' + escapeHtml(node.name) + '</span>' +
                '<span class="node-online-indicator ' + statusClass + '">' +
                '<span class="node-online-dot ' + statusClass + '"></span>' +
                statusText +
                '</span>' +
                '</div>' +
                '<div class="node-details">' +
                '<div class="node-detail-row"><span class="node-detail-label">Version</span><span class="node-detail-value">' + escapeHtml(node.version || '-') + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Go</span><span class="node-detail-value">' + escapeHtml(node.go_version || '-') + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Build</span><span class="node-detail-value">' + escapeHtml(node.build_info || '-') + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Last Seen</span><span class="node-detail-value">' + lastSeen + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Memory</span><span class="node-detail-value">' + memInfo + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Goroutines</span><span class="node-detail-value">' + escapeHtml(String(node.goroutines ?? '-')) + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">DB Size</span><span class="node-detail-value">' + dbInfo + '</span></div>' +
                '</div>' +
                (node.version ? '<div class="node-version">' + escapeHtml(node.version) + '</div>' : '') +
                '</div>';
        }).join('');
        replaceHTMLIfChanged(container, nodeCardsHTML);
        } catch (e) {
        // Silently fail - node status is non-critical
        }
    });
}



// Item 98: Pre-fill DNS Lookup Simulator from table
function prefillSimulator(domain) {
    const simInput = document.getElementById('simDomain');
    simInput.value = domain;
    simInput.focus();
    simInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// Item 99: Clear Dashboard View
function clearView() {
    allEvents = [];
    isViewCleared = true;
    const tableBody = document.getElementById('eventTable');
    tableBody.innerHTML = '';
    const banner = document.getElementById('viewClearedBanner');
    if (banner) banner.classList.remove('is-hidden');
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

function renderEvents() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const tableBody = document.getElementById('eventTable');

    if (searchTerm === "") {
        const filtered = allEvents.slice(0, 100);
        tableBody.innerHTML = filtered.map(e => `<tr id="row-${e.id}">${createRowHtml(e)}</tr>`).join('');
        return;
    }

    // Advanced Search Parsing
    const parts = searchTerm.split(' ').filter(p => p.trim() !== '');
    const filtered = allEvents.filter(e => {
        return parts.every(p => {
            if (p.startsWith('node:')) return p.length > 5 && (e.node || 'local').toLowerCase().includes(p.substring(5));
            if (p.startsWith('type:')) return p.length > 5 && e.type.toLowerCase().includes(p.substring(5));
            if (p.startsWith('client:')) return p.length > 7 && e.client_ip.toLowerCase().includes(p.substring(7));
            if (p.startsWith('alias:')) return p.length > 6 && (e.alias || '').toLowerCase().includes(p.substring(6));
            return e.domain.toLowerCase().includes(p) ||
                e.client_ip.toLowerCase().includes(p) ||
                (e.alias || '').toLowerCase().includes(p) ||
                (e.node || 'local').toLowerCase().includes(p);
        });
    }).slice(0, 100);

    tableBody.innerHTML = filtered.map(e => `<tr id="row-${e.id}">${createRowHtml(e)}</tr>`).join('');
}

function refreshEventTimes() {
    document.querySelectorAll('#eventTable .timestamp[data-unix-time]').forEach(cell => {
        const relative = cell.querySelector('.timestamp-relative');
        const unixTime = Number(cell.dataset.unixTime);
        if (relative && Number.isFinite(unixTime)) relative.textContent = getRelativeTime(unixTime);
    });
}

function renderTopList(id, list) {
    const el = document.getElementById(id);
    const html = (list || []).map(item => {
        let trendIcon = '';
        if (item.trend === 'up') trendIcon = '<span class="trend-up">↑</span>';
        if (item.trend === 'down') trendIcon = '<span class="trend-down">↓</span>';
        if (item.trend === 'stable') trendIcon = '<span class="trend-stable">-</span>';

        const aliasTag = item.alias ? `<span class="alias-tag">${escapeHtml(item.alias)}</span>` : '';

        return `
            <li class="top-item">
                <span class="truncate-label">
                    ${escapeHtml(item.key)} ${trendIcon} ${aliasTag}
                </span>
                <span class="top-count">${formatNumber(item.count)}</span>
            </li>
        `;
    }).join('');
    replaceHTMLIfChanged(el, html);
}

function updateMainStats() {
    // Stats are now pulled from /api/stats for better accuracy
    // This function is kept for any immediate local UI feedback if needed
}

function renderMiniChart() {
    const chart = document.getElementById('miniChart');
    const max = Math.max(...rpmHistory, 1);
    chart.innerHTML = rpmHistory.map(h => {
        const height = (h / max) * 100;
        return `<div class="chart-bar" data-height="${height}"></div>`;
    }).join('');
    applyDynamicStyles(chart);
}

async function showClientStats(ip) {
    const modal = document.getElementById('clientModal');
    document.getElementById('modalTitle').textContent = `Stats for ${ip}`;
    lastModalFocus = document.activeElement;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
    document.getElementById('modalCloseBtn').focus();

    try {
        const response = await fetch(apiPath(`/api/client_stats?ip=${encodeURIComponent(ip)}`));
        if (!response.ok) throw new Error(`Client stats failed (${response.status})`);
        const data = await response.json();

        document.getElementById('modalRPM').textContent = data.rpm;
        document.getElementById('modalRPH').textContent = data.rph;

        const charts = document.getElementById('modalCharts');
        const max = Math.max(...data.rpm_history, 1);
        charts.innerHTML = data.rpm_history.map(h => {
            const height = (h / max) * 100;
            return `<div class="modal-chart-bar" data-height="${height}"></div>`;
        }).join('');
        applyDynamicStyles(charts);
    } catch (e) { console.error(e); }
}

function closeClientModal() {
    const modal = document.getElementById('clientModal');
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    if (lastModalFocus && typeof lastModalFocus.focus === 'function') lastModalFocus.focus();
}

async function withFormBusy(form, action) {
    const controls = Array.from(form.querySelectorAll('button, input, select, textarea'));
    const disabledStates = controls.map(control => control.disabled);
    controls.forEach(control => { control.disabled = true; });
    form.setAttribute('aria-busy', 'true');
    try {
        return await action();
    } finally {
        controls.forEach((control, index) => { control.disabled = disabledStates[index]; });
        form.removeAttribute('aria-busy');
        if (form.id === 'clientForm') setClientPolicyState();
    }
}

async function apiJSON(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        const csrfToken = document.body.dataset.csrfToken;
        options.headers = { ...options.headers, 'X-CSRF-Token': csrfToken };
    }
    const response = await fetch(apiPath(path), options);
    const contentType = response.headers.get('Content-Type') || '';
    const payload = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok) {
        const message = typeof payload === 'string' ? payload.trim() : payload.message || payload.error;
        throw new Error(message || `Request failed (${response.status})`);
    }
    return payload;
}

function showSettingsNotice(message, isError = false) {
    const notice = document.getElementById('settingsNotice');
    notice.textContent = message;
    notice.classList.toggle('error', isError);
    notice.classList.remove('is-hidden');
    window.clearTimeout(showSettingsNotice.timer);
    showSettingsNotice.timer = window.setTimeout(() => notice.classList.add('is-hidden'), 5000);
}

function splitSettingList(value) {
    return value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
}

function emptySettings(message) {
    return `<div class="empty-settings">${escapeHtml(message)}</div>`;
}

async function loadFilterSettings() {
    const data = await apiJSON('/api/filtering/status');
    const state = document.getElementById('filterState');
    state.textContent = data.enabled ? 'Protection active' : 'Protection paused';
    state.classList.toggle('online', Boolean(data.enabled));
    state.classList.toggle('paused', !data.enabled);
    document.getElementById('filterBlockedTotal').textContent = formatNumber(data.filter_blocked_total || 0);
    document.getElementById('filterAllowedTotal').textContent = formatNumber(data.filter_allowed_total || 0);
    document.getElementById('filterSourceTotal').textContent = formatNumber((data.sources || []).length);
    const sourceList = document.getElementById('filterSources');
    sourceList.innerHTML = (data.sources || []).map(source => {
        const updated = source.last_update && !source.last_update.startsWith('0001-')
            ? new Date(source.last_update).toLocaleString()
            : 'Not updated yet';
        const detail = source.last_error
            ? `<span class="error-text">${escapeHtml(source.last_error)}</span>`
            : `${formatNumber(source.rule_count || 0)} block · ${formatNumber(source.allow_rule_count || 0)} allow · ${escapeHtml(updated)}`;
        return `<div class="settings-list-row">
            <div class="settings-list-main">
                <div class="settings-list-title">${escapeHtml(source.name)}</div>
                <div class="settings-list-meta">${escapeHtml(source.kind)}${source.allow_only ? ' · allow only' : ''} · ${detail}</div>
            </div>
        </div>`;
    }).join('') || emptySettings('No filter sources configured');
}

async function setFilterPause(minutes) {
    await apiJSON('/api/filtering/pause', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ minutes })
    });
    showSettingsNotice(minutes > 0 ? `Protection paused for ${minutes} minutes` : 'Protection resumed');
    await loadFilterSettings();
}

function rewriteValueState() {
    const type = document.getElementById('rewriteType').value;
    const label = document.getElementById('rewriteValueLabel');
    const input = document.getElementById('rewriteValue');
    const noValue = ['NXDOMAIN', 'REFUSED', 'NOERROR'].includes(type);
    label.hidden = noValue;
    input.required = !noValue;
    const placeholders = {
        A: '192.0.2.10', AAAA: '2001:db8::10', CNAME: 'target.internal', PTR: 'host.internal',
        MX: '10 mail.internal', TXT: 'verification text', SRV: '10 5 443 target.internal'
    };
    input.placeholder = placeholders[type] || '';
    if (noValue) input.value = '';
}

async function loadRewrites() {
    const data = await apiJSON('/api/rewrites');
    const rewrites = data.rewrites || [];
    document.getElementById('rewriteCount').textContent = `${rewrites.length} ${rewrites.length === 1 ? 'rule' : 'rules'}`;
    document.getElementById('rewriteList').innerHTML = rewrites.map(rewrite => `
        <div class="settings-list-row">
            <div class="settings-list-main">
                <div class="settings-list-title">${escapeHtml(rewrite.domain)}</div>
                <div class="settings-list-meta">${escapeHtml(rewrite.type)}${rewrite.value ? ` → ${escapeHtml(rewrite.value)}` : ''}</div>
            </div>
            <div class="row-actions"><button type="button" class="mini-action danger rewrite-delete-btn" data-id="${escapeHtml(rewrite.id)}">Delete</button></div>
        </div>`).join('') || emptySettings('No DNS rewrites configured');
}

async function addRewrite(event) {
    event.preventDefault();
    await withFormBusy(event.target, async () => {
        const domain = document.getElementById('rewriteDomain').value.trim();
        const type = document.getElementById('rewriteType').value;
        const value = document.getElementById('rewriteValue').value.trim();
        await apiJSON('/api/rewrites', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, type, value })
        });
        event.target.reset();
        rewriteValueState();
        showSettingsNotice(`Rewrite added for ${domain}`);
        await loadRewrites();
    });
}

async function deleteRewrite(id) {
    await apiJSON(`/api/rewrites?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
    showSettingsNotice('Rewrite deleted');
    await loadRewrites();
}

function renderClientServicePicker(selected = []) {
    const selectedSet = new Set(selected);
    document.getElementById('clientServicePicker').innerHTML = knownServices.map(service => `
        <label class="service-option"><input type="checkbox" value="${escapeHtml(service.id)}" ${selectedSet.has(service.id) ? 'checked' : ''}> ${escapeHtml(service.id)}</label>
    `).join('') || '<span class="settings-list-meta">Service catalog unavailable</span>';
}

function setClientPolicyState() {
    const inherit = document.getElementById('clientUseGlobal').checked;
    const fields = document.getElementById('clientPolicyFields');
    fields.classList.toggle('is-muted', inherit);
    fields.querySelectorAll('input').forEach(input => { input.disabled = inherit; });
}

function resetClientForm() {
    const form = document.getElementById('clientForm');
    form.reset();
    editingClient = null;
    document.getElementById('clientName').readOnly = false;
    document.getElementById('clientUseGlobal').checked = true;
    document.getElementById('clientFiltering').checked = true;
    document.getElementById('clientSaveBtn').textContent = 'Add client';
    document.getElementById('clientCancelBtn').classList.add('is-hidden');
    renderClientServicePicker();
    setClientPolicyState();
}

function editClient(name) {
    const client = configuredClients.find(item => item.name === name);
    if (!client) return;
    editingClient = client;
    document.getElementById('clientName').value = client.name;
    document.getElementById('clientName').readOnly = true;
    document.getElementById('clientIDs').value = (client.ids || []).join(', ');
    document.getElementById('clientUseGlobal').checked = Boolean(client.use_global_settings);
    document.getElementById('clientFiltering').checked = Boolean(client.filtering_enabled);
    document.getElementById('clientSafeSearch').checked = Boolean(client.safe_search_enabled);
    document.getElementById('clientSafeEngines').value = (client.safe_search_engines || []).join(', ');
    document.getElementById('clientUpstreams').value = (client.upstreams || []).join(', ');
    document.getElementById('clientExcludeLog').checked = Boolean(client.exclude_from_log);
    document.getElementById('clientExcludeStats').checked = Boolean(client.exclude_from_stats);
    renderClientServicePicker(client.blocked_services || []);
    setClientPolicyState();
    document.getElementById('clientSaveBtn').textContent = 'Save client';
    document.getElementById('clientCancelBtn').classList.remove('is-hidden');
    document.getElementById('clientForm').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

async function loadClients() {
    const data = await apiJSON('/api/clients');
    configuredClients = data.clients || [];
    document.getElementById('clientCount').textContent = `${configuredClients.length} ${configuredClients.length === 1 ? 'client' : 'clients'}`;
    document.getElementById('clientList').innerHTML = configuredClients.map(client => {
        const mode = client.use_global_settings ? 'Global policy' : 'Custom policy';
        const services = (client.blocked_services || []).length ? ` · ${(client.blocked_services || []).join(', ')}` : '';
        return `<div class="settings-list-row">
            <div class="settings-list-main">
                <div class="settings-list-title">${escapeHtml(client.name)}</div>
                <div class="settings-list-meta">${escapeHtml((client.ids || []).join(', '))} · ${mode}${escapeHtml(services)}</div>
            </div>
            <div class="row-actions">
                <button type="button" class="mini-action client-edit-btn" data-name="${escapeHtml(client.name)}">Edit</button>
                <button type="button" class="mini-action danger client-delete-btn" data-name="${escapeHtml(client.name)}">Delete</button>
            </div>
        </div>`;
    }).join('') || emptySettings('No client policies configured');
}

async function saveClient(event) {
    event.preventDefault();
    await withFormBusy(event.target, async () => {
        const inherit = document.getElementById('clientUseGlobal').checked;
        const selectedServices = Array.from(document.querySelectorAll('#clientServicePicker input:checked')).map(input => input.value);
        const client = {
            ...(editingClient || {}),
            name: document.getElementById('clientName').value.trim(),
            ids: splitSettingList(document.getElementById('clientIDs').value),
            use_global_settings: inherit,
            filtering_enabled: inherit || document.getElementById('clientFiltering').checked,
            safe_search_enabled: !inherit && document.getElementById('clientSafeSearch').checked,
            safe_search_engines: inherit ? [] : splitSettingList(document.getElementById('clientSafeEngines').value),
            blocked_services: inherit ? [] : selectedServices,
            upstreams: splitSettingList(document.getElementById('clientUpstreams').value),
            exclude_from_log: document.getElementById('clientExcludeLog').checked,
            exclude_from_stats: document.getElementById('clientExcludeStats').checked
        };
        await apiJSON('/api/clients', {
            method: editingClient ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(client)
        });
        showSettingsNotice(editingClient ? `Client ${client.name} updated` : `Client ${client.name} added`);
        resetClientForm();
        await loadClients();
    });
}

async function deleteClient(name) {
    await apiJSON(`/api/clients?name=${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (editingClient && editingClient.name === name) resetClientForm();
    showSettingsNotice(`Client ${name} deleted`);
    await loadClients();
}

async function loadServices() {
    const data = await apiJSON('/api/services');
    knownServices = data.services || [];
    document.getElementById('serviceCatalog').innerHTML = knownServices.map(service => `
        <div class="service-card ${service.enabled ? 'enabled' : ''}">
            <div class="service-card-name">${escapeHtml(service.id)}</div>
            <div class="service-card-meta">${service.enabled ? 'Globally blocked' : 'Available'} · ${formatNumber(service.hits || 0)} hits</div>
        </div>`).join('') || emptySettings('Service catalog unavailable');
    renderClientServicePicker(editingClient ? editingClient.blocked_services || [] : []);
    setClientPolicyState();
}

function activeSettingsPanel() {
    return document.querySelector('.settings-tab.active')?.dataset.settingsTab || 'filters';
}

async function loadSettings(panelName = activeSettingsPanel()) {
    const loaders = {
        filters: loadFilterSettings,
        rewrites: loadRewrites,
        clients: async () => {
            if (!loadedSettings.has('services')) await loadSettings('services');
            await loadClients();
        },
        services: loadServices
    };
    const loader = loaders[panelName];
    if (!loader) return;
    await coalesceRequest(`settings:${panelName}`, loader);
    loadedSettings.add(panelName);
}

async function clearDNSCache() {
    const data = await apiJSON('/api/cache/clear', { method: 'POST' });
    showSettingsNotice(`DNS cache cleared (${data.cleared || 0} entries removed)`);
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
        document.querySelectorAll('.query-action-btn').forEach(candidate => {
            if (candidate.dataset.domain === domain) {
                candidate.dataset.action = nextAction;
                candidate.textContent = nextAction === 'unblock' ? 'Unblock' : 'Block';
                candidate.classList.toggle('is-unblock', nextAction === 'unblock');
            }
        });
        allEvents.forEach(event => {
            if (event.domain === domain) event.user_rule_action = nextAction;
        });
        showSettingsNotice(`${domain}: ${data.action.replaceAll('_', ' ')}`);
    } finally {
        button.disabled = false;
    }
}

document.getElementById('freezeBtn').addEventListener('click', function () {
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

document.getElementById('compactToggle').addEventListener('click', function () {
    const active = document.body.classList.toggle('compact');
    this.setAttribute('aria-pressed', String(active));
});

document.getElementById('clearViewBtn').addEventListener('click', function () {
    clearView();
});

document.getElementById('simulateBtn').addEventListener('click', simulateQuery);
document.getElementById('modalCloseBtn').addEventListener('click', function () {
    closeClientModal();
});
document.getElementById('clientModal').addEventListener('click', function (event) {
    if (event.target === this) closeClientModal();
});
document.addEventListener('keydown', event => {
    const modal = document.getElementById('clientModal');
    if (event.key === 'Escape' && modal.classList.contains('open')) closeClientModal();
});

document.getElementById('searchInput').addEventListener('input', renderEvents);

function updateVisibility() {
    isTabVisible = document.visibilityState === 'visible';
    if (statsInterval) clearInterval(statsInterval);
    if (nodeStatusInterval) clearInterval(nodeStatusInterval);

    const rate = isTabVisible ? 10000 : 60000;
    statsInterval = setInterval(() => { void fetchStats(); }, rate);
    nodeStatusInterval = setInterval(() => { void fetchNodeStatus(); }, 30000);

    if (isTabVisible) {
        fetchAll(); // Catch up immediately
    }
}

document.addEventListener('visibilitychange', updateVisibility);

// Event delegation for test-domain-btn (XSS-safe: domain from data attribute)
document.addEventListener('click', function (e) {
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
    if (clientCell) showClientStats(clientCell.dataset.clientIp);
});

startStream();
updateVisibility(); // Initial set
setInterval(() => {
    if (isTabVisible && !isFrozen) refreshEventTimes();
}, 30000);
