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

function percentStep(value) {
    return Math.round(Math.max(0, Math.min(100, Number(value))) / 5) * 5;
}

// Base URL prefix for API requests (empty for root deployments)
const apiBase = (document.body.dataset.baseUrl || '/').replace(/\/$/, '');
const configReadOnly = document.body.dataset.mode === 'agent';
const activePage = document.body.dataset.page || 'dashboard';

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
const eventsByID = new Map();
let rpmHistory = Array(20).fill(0);
let lastEventTimestamp = 0;
let lastEventID = '';
let isTabVisible = true;
let isFrozen = false;
let isViewCleared = false;
let statsInterval = null;
let nodeStatusInterval = null;
let configuredClients = [];
let editingClient = null;
let frozenEvents = [];
let lastModalFocus = null;
let streamConnected = false;
let streamSource = null;
let streamRetryCount = 0;
let streamReconnectSeconds = 0;
let streamReconnectTimer = null;
let pollingHealthy = true;
const loadedSettings = new Set();
const queryRowHeight = 43;
const queryOverscan = 10;
let filteredEvents = [];
let queryRenderFrame = null;
let lastQueryDetailFocus = null;
let pendingUndo = null;
let undoTimer = null;
let navigationPrefix = false;

const defaultQueryColumns = ['time', 'node', 'type', 'domain', 'client', 'upstream', 'latency', 'action'];
const queryColumnLabels = {
    time: 'Time', node: 'Node', type: 'Type', domain: 'Domain', client: 'Client',
    upstream: 'Upstream', latency: 'Latency', action: 'Action'
};
let queryColumns = loadQueryColumns();

function loadQueryColumns() {
    try {
        const saved = JSON.parse(localStorage.getItem('resolix.queryColumns') || 'null');
        const order = Array.isArray(saved?.order) ? saved.order.filter(key => defaultQueryColumns.includes(key)) : [];
        const completeOrder = [...order, ...defaultQueryColumns.filter(key => !order.includes(key))];
        const hidden = Array.isArray(saved?.hidden) ? saved.hidden.filter(key => defaultQueryColumns.includes(key)) : [];
        return { order: completeOrder, hidden };
    } catch (_) {
        return { order: [...defaultQueryColumns], hidden: [] };
    }
}

function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (value < 1024) return `${value} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let size = value / 1024;
    let unit = units[0];
    for (let index = 1; index < units.length && size >= 1024; index++) {
        size /= 1024;
        unit = units[index];
    }
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${unit}`;
}

function saveQueryColumns() {
    localStorage.setItem('resolix.queryColumns', JSON.stringify(queryColumns));
}

function announce(message) {
    if (typeof window.resolixAnnounce === 'function') window.resolixAnnounce(message);
}

function renderSystemStatus() {
    const status = document.getElementById('systemStatus');
    if (!status) return;
    const streamUnavailable = activePage === 'querylog' && !streamConnected;
    status.classList.toggle('offline', streamUnavailable || !pollingHealthy);
    if (!pollingHealthy) {
        status.textContent = '● System Offline';
    } else if (streamUnavailable) {
        const countdown = streamReconnectSeconds > 0 ? ` in ${streamReconnectSeconds}s` : '';
        const attempt = streamRetryCount > 0 ? ` · retry ${streamRetryCount}` : '';
        status.textContent = `● Live stream reconnecting${countdown}${attempt}`;
    } else if (activePage === 'querylog') {
        status.textContent = '● Live stream connected';
    } else {
        status.textContent = '● System online';
    }
}

function setStreamStatus(connected) {
    const changed = streamConnected !== connected;
    streamConnected = connected;
    renderSystemStatus();
    if (changed) announce(connected ? 'Live query stream connected' : 'Live query stream disconnected');
}

function setPollingStatus(healthy) {
    pollingHealthy = healthy;
    renderSystemStatus();
}

function mergeEvent(newEvent, updateDOM = true) {
    const eventKey = String(newEvent.id);
    const existing = eventsByID.get(eventKey);
    if (existing) {
        Object.assign(existing, newEvent);
    } else {
        const scroll = document.getElementById('queryScroll');
        const preserveViewport = scroll && scroll.scrollTop > queryRowHeight;
        allEvents.unshift(newEvent);
        eventsByID.set(eventKey, newEvent);
        if (allEvents.length > 1000) {
            const removed = allEvents.pop();
            if (removed) eventsByID.delete(String(removed.id));
        }
        if (preserveViewport) scroll.scrollTop += queryRowHeight;
    }
    if (updateDOM && isTabVisible) scheduleQueryRender();
}

function stopStream() {
    if (streamSource) {
        streamSource.close();
        streamSource = null;
    }
    if (streamReconnectTimer) {
        clearInterval(streamReconnectTimer);
        streamReconnectTimer = null;
    }
}

function scheduleStreamReconnect() {
    stopStream();
    if (!isTabVisible || activePage !== 'querylog') return;
    streamRetryCount++;
    streamReconnectSeconds = Math.min(30, Math.max(1, 2 ** Math.min(streamRetryCount - 1, 5)));
    setStreamStatus(false);
    streamReconnectTimer = setInterval(() => {
        streamReconnectSeconds--;
        renderSystemStatus();
        if (streamReconnectSeconds <= 0) {
            clearInterval(streamReconnectTimer);
            streamReconnectTimer = null;
            startStream();
        }
    }, 1000);
}

// Stream handler. Hidden tabs close the connection and resume with a bounded,
// visible retry loop so inactive dashboards consume no streaming work.
function startStream() {
    if (!isTabVisible || activePage !== 'querylog' || streamSource) return;
    streamSource = new EventSource(apiPath('/api/stream'));
    streamSource.onopen = () => {
        streamRetryCount = 0;
        streamReconnectSeconds = 0;
        setStreamStatus(true);
    };
    streamSource.onmessage = (event) => {
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
    streamSource.onerror = () => {
        setStreamStatus(false);
        console.error('SSE connection lost. Reconnecting...');
        scheduleStreamReconnect();
    };
}

function copyControl(value, label) {
    if (!value) return '';
    return `<button type="button" class="copy-btn" data-copy="${escapeHtml(value)}" aria-label="Copy ${escapeHtml(label)}" title="Copy ${escapeHtml(label)}">⧉</button>`;
}

function visibleQueryColumns() {
    const visible = queryColumns.order.filter(key => !queryColumns.hidden.includes(key));
    return visible.length > 0 ? visible : ['domain'];
}

function createRowHtml(e) {
    const hasLatency = e.latency_ms !== null && e.latency_ms !== undefined;
    let latencyClass = hasLatency ? 'latency-low' : 'latency-neutral';
    if (hasLatency && e.latency_ms > 50) latencyClass = 'latency-mid';
    if (hasLatency && e.latency_ms > 150) latencyClass = 'latency-high';

    const latencyText = e.latencyFormatted || (hasLatency ? Number(e.latency_ms).toFixed(1) + 'ms' : '-');
    const timeStr = new Date(e.unix_time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    const relTime = getRelativeTime(e.unix_time);
    const action = e.user_rule_action || (e.blocked ? 'unblock' : 'block');
    const actionLabel = action === 'unblock' ? 'Allow' : 'Block';
    const node = e.node || 'local';
    const cells = {
        time: `<td data-col="time" class="timestamp" data-unix-time="${escapeHtml(e.unix_time)}"><div class="timestamp-primary">${escapeHtml(timeStr)}</div><div class="timestamp-relative">${escapeHtml(relTime)}</div></td>`,
        node: `<td data-col="node" class="cell-with-copy"><span class="badge node-badge">${escapeHtml(node)}</span>${copyControl(node, 'node')}</td>`,
        type: `<td data-col="type"><span class="badge badge-type">${escapeHtml(e.type)}</span></td>`,
        domain: `<td data-col="domain" class="domain cell-with-copy"><span>${escapeHtml(e.domain)}</span>${copyControl(e.domain, 'domain')}<button type="button" class="test-domain-btn" title="Test in simulator" aria-label="Test ${escapeHtml(e.domain)} in simulator" data-domain="${escapeHtml(e.domain)}">⌕</button></td>`,
        client: `<td data-col="client" class="client-cell cell-with-copy" data-client-ip="${escapeHtml(e.client_ip)}" title="Open client details"><span class="badge badge-ip">${escapeHtml(e.client_ip)}</span>${e.alias ? `<span class="alias-tag">${escapeHtml(e.alias)}</span>` : ''}${copyControl(e.client_ip, 'client')}</td>`,
        upstream: `<td data-col="upstream" class="cell-with-copy">${e.upstream ? `<span class="upstream-badge">${escapeHtml(e.upstream)}</span>${copyControl(e.upstream, 'upstream')}` : '-'}</td>`,
        latency: `<td data-col="latency" class="latency-cell ${latencyClass}">${escapeHtml(latencyText)}</td>`,
        action: `<td data-col="action">${configReadOnly ? '<span class="settings-list-meta">Controller managed</span>' : `<button type="button" class="query-action-btn ${action === 'unblock' ? 'is-unblock' : ''}" aria-label="${actionLabel} ${escapeHtml(e.domain)}" data-domain="${escapeHtml(e.domain)}" data-action="${action}">${actionLabel}</button>`}</td>`
    };
    return visibleQueryColumns().map(key => cells[key]).join('');
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
                eventsByID.clear();
                allEvents.forEach(event => eventsByID.set(String(event.id), event));
            } else {
                newEvents.forEach(event => mergeEvent(event, false));
            }
        }
        renderEvents();

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
                        return `<div class="spark-bar height-pct-${percentStep(h)} ${l === -1 ? 'fail' : ''}"></div>`;
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
            replaceHTMLIfChanged(healthEl, healthHTML);
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
                                <div class="type-bar width-pct-${percentStep(pct)}"></div>
                            </div>
                        </div>
                    `;
                }).join('');
                replaceHTMLIfChanged(typeEl, typeHTML);
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
        document.querySelectorAll('.skeleton-card').forEach(card => card.classList.remove('skeleton-card'));
        setPollingStatus(true);
        } catch (e) {
            console.error(e);
            setPollingStatus(false);
        }
    });
}
function fetchNodeStatus() {
    return coalesceRequest('nodes', async () => {
        try {
        const response = await fetch(apiPath('/api/nodes'));
        if (!response.ok) throw new Error(`Nodes API failed (${response.status})`);
        const data = await response.json();
        setPollingStatus(true);
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
			const dbInfo = node.db_size_mb != null ? node.db_size_mb.toFixed(1) + ' MB' : '-';
            const appliedRevision = String(node.config_revision || '').slice(0, 12) || '-';
            const desiredRevision = String(node.desired_config_revision || '').slice(0, 12) || '-';
            const backlog = `${formatNumber(node.forwarder_backlog_depth || 0)} events · ${formatBytes(node.forwarder_backlog_bytes || 0)}`;
            const endpointErrors = Object.entries(node.forwarder_endpoint_errors || {});
            const warning = node.duplicate_name_warning
                ? '<div class="node-warning">Duplicate node name reported from a different address</div>'
                : (!node.config_schema_compatible && node.config_schema_version
                    ? '<div class="node-warning">Configuration schema is incompatible with the controller</div>'
                    : '');
            const errorDetail = node.config_apply_error
                ? `<div class="node-warning">Apply failed: ${escapeHtml(node.config_apply_error)}</div>`
                : '';
            const endpointDetail = endpointErrors.length
                ? `<details class="node-endpoint-errors"><summary>${endpointErrors.length} endpoint error${endpointErrors.length === 1 ? '' : 's'}</summary>${endpointErrors.map(([endpoint, error]) => `<div><strong>${escapeHtml(endpoint)}</strong><span>${escapeHtml(error)}</span></div>`).join('')}</details>`
                : '';
            const decommission = !node.online && !configReadOnly
				? `<button type="button" class="mini-action danger node-decommission-btn" data-node-id="${escapeHtml(node.id || node.name)}" data-node-name="${escapeHtml(node.name)}">Decommission</button>`
                : '';
            return `<div class="node-card">
                <div class="node-card-header"><span class="node-name">${escapeHtml(node.name)}</span><span class="node-online-indicator ${statusClass}"><span class="node-online-dot ${statusClass}"></span>${statusText}</span></div>
                ${warning}${errorDetail}
                <div class="node-details">
					<div class="node-detail-row"><span class="node-detail-label">Version</span><span class="node-detail-value">${escapeHtml(node.version || '-')}</span></div>
					<div class="node-detail-row"><span class="node-detail-label">Go version</span><span class="node-detail-value">${escapeHtml(node.go_version || '-')}</span></div>
					<div class="node-detail-row"><span class="node-detail-label">Database</span><span class="node-detail-value">${escapeHtml(dbInfo)}</span></div>
                    <div class="node-detail-row"><span class="node-detail-label">Last seen</span><span class="node-detail-value">${escapeHtml(lastSeen)}</span></div>
                    <div class="node-detail-row"><span class="node-detail-label">Applied / desired</span><span class="node-detail-value">${escapeHtml(appliedRevision)} / ${escapeHtml(desiredRevision)}</span></div>
                    <div class="node-detail-row"><span class="node-detail-label">Apply / clock skew</span><span class="node-detail-value">${formatNumber(node.config_apply_duration_ms || 0)}ms · ${formatNumber(node.clock_skew_ms || 0)}ms</span></div>
                    <div class="node-detail-row"><span class="node-detail-label">Forward backlog</span><span class="node-detail-value">${escapeHtml(backlog)}</span></div>
                    <div class="node-detail-row"><span class="node-detail-label">Backlog age</span><span class="node-detail-value">${Number(node.forwarder_backlog_oldest_seconds || 0).toFixed(1)}s</span></div>
                </div>
                ${endpointDetail}
                <div class="node-card-actions">${decommission}</div>
            </div>`;
        }).join('');
        replaceHTMLIfChanged(container, nodeCardsHTML);
        } catch (e) {
            console.error(e);
            setPollingStatus(false);
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
    eventsByID.clear();
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
    const rows = filteredEvents.slice(start, end).map(event =>
        `<tr id="row-${escapeHtml(event.id)}" data-event-id="${escapeHtml(event.id)}" tabindex="0">${createRowHtml(event)}</tr>`
    ).join('');
    const topSpacer = topHeight > 0 ? `<tr class="virtual-spacer" aria-hidden="true" height="${topHeight}"><td colspan="${columns.length}" height="${topHeight}"></td></tr>` : '';
    const bottomSpacer = bottomHeight > 0 ? `<tr class="virtual-spacer" aria-hidden="true" height="${bottomHeight}"><td colspan="${columns.length}" height="${bottomHeight}"></td></tr>` : '';
    const empty = filteredEvents.length === 0 ? `<tr class="empty-query-row"><td colspan="${columns.length}">${allEvents.length ? 'No queries match these filters.' : 'Waiting for DNS queries…'}</td></tr>` : '';
    tableBody.innerHTML = topSpacer + rows + bottomSpacer + empty;
    tableBody.closest('table')?.setAttribute('aria-rowcount', String(filteredEvents.length));
}

function renderQueryTableHead() {
    const head = document.getElementById('queryTableHead');
    if (!head) return;
    head.innerHTML = visibleQueryColumns().map(key => `<th data-col="${key}">${queryColumnLabels[key]}</th>`).join('');
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
        return `<div class="chart-bar height-pct-${percentStep(height)}"></div>`;
    }).join('');
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
            return `<div class="modal-chart-bar height-pct-${percentStep(height)}"></div>`;
        }).join('');
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
    if (!notice) {
        announce(message);
        if (isError) console.error(message);
        return;
    }
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
		return `<div class="settings-list-row">
            <div class="settings-list-main">
                <div class="settings-list-title">${escapeHtml(client.name)}</div>
				<div class="settings-list-meta">${escapeHtml((client.ids || []).join(', '))} · ${mode}</div>
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
		const client = {
            ...(editingClient || {}),
            name: document.getElementById('clientName').value.trim(),
            ids: splitSettingList(document.getElementById('clientIDs').value),
            use_global_settings: inherit,
            filtering_enabled: inherit || document.getElementById('clientFiltering').checked,
            safe_search_enabled: !inherit && document.getElementById('clientSafeSearch').checked,
            safe_search_engines: inherit ? [] : splitSettingList(document.getElementById('clientSafeEngines').value),
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

function activeSettingsPanel() {
    return document.querySelector('.settings-tab.active')?.dataset.settingsTab || 'filters';
}

async function loadSettings(panelName = activeSettingsPanel()) {
	const loaders = {
		filters: loadFilterSettings,
		rewrites: loadRewrites,
		clients: loadClients
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
    undoTimer = setTimeout(hideUndoNotice, 8000);
}

function hideUndoNotice() {
    const toast = document.getElementById('queryUndoToast');
    if (undoTimer) clearTimeout(undoTimer);
    undoTimer = null;
    pendingUndo = null;
    toast?.classList.remove('open');
    toast?.setAttribute('aria-hidden', 'true');
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
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    const scrim = document.getElementById('queryDrawerScrim');
    scrim?.classList.add('open');
    scrim?.setAttribute('aria-hidden', 'false');
    document.body.classList.add('query-drawer-open');
    document.getElementById('queryDetailClose')?.focus();
}

function closeQueryDetail() {
    const drawer = document.getElementById('queryDetailDrawer');
    if (!drawer?.classList.contains('open')) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    const scrim = document.getElementById('queryDrawerScrim');
    scrim?.classList.remove('open');
    scrim?.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('query-drawer-open');
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
