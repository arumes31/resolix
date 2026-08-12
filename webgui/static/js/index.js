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
        time: `<td data-col="time" headers="query-column-time" class="timestamp" data-unix-time="${escapeHtml(e.unix_time)}"><div class="timestamp-primary">${escapeHtml(timeStr)}</div><div class="timestamp-relative">${escapeHtml(relTime)}</div></td>`,
        node: `<td data-col="node" headers="query-column-node" class="cell-with-copy"><span class="badge node-badge">${escapeHtml(node)}</span>${copyControl(node, 'node')}</td>`,
        type: `<td data-col="type" headers="query-column-type"><span class="badge badge-type">${escapeHtml(e.type)}</span></td>`,
        domain: `<td data-col="domain" headers="query-column-domain" class="domain cell-with-copy"><span>${escapeHtml(e.domain)}</span>${copyControl(e.domain, 'domain')}<button type="button" class="test-domain-btn" title="Test in simulator" aria-label="Test ${escapeHtml(e.domain)} in simulator" data-domain="${escapeHtml(e.domain)}">⌕</button></td>`,
        client: `<td data-col="client" headers="query-column-client" class="client-cell cell-with-copy" data-client-ip="${escapeHtml(e.client_ip)}" title="Open client details"><span class="badge badge-ip">${escapeHtml(e.client_ip)}</span>${e.alias ? `<span class="alias-tag">${escapeHtml(e.alias)}</span>` : ''}${copyControl(e.client_ip, 'client')}</td>`,
        upstream: `<td data-col="upstream" headers="query-column-upstream" class="cell-with-copy">${e.upstream ? `<span class="upstream-badge">${escapeHtml(e.upstream)}</span>${copyControl(e.upstream, 'upstream')}` : '-'}</td>`,
        latency: `<td data-col="latency" headers="query-column-latency" class="latency-cell ${latencyClass}">${escapeHtml(latencyText)}</td>`,
        action: `<td data-col="action" headers="query-column-action">${configReadOnly ? '<span class="settings-list-meta">Controller managed</span>' : `<button type="button" class="query-action-btn ${action === 'unblock' ? 'is-unblock' : ''}" aria-label="${actionLabel} ${escapeHtml(e.domain)}" data-domain="${escapeHtml(e.domain)}" data-action="${action}">${actionLabel}</button>`}</td>`
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
