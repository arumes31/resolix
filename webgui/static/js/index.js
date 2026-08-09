function escapeHtml(unsafe) {
    if (unsafe == null) return '';
    const el = document.createElement('div');
    el.textContent = unsafe;
    return el.innerHTML;
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

function apiPath(path) {
    return apiBase + path;
}

let allEvents = [];
let rpmHistory = Array(20).fill(0);
let lastEventTimestamp = 0;
let isTabVisible = true;
let isFrozen = false;
let isViewCleared = false;
let statsInterval = null;
let nodeStatusInterval = null;

// Stream handler
function startStream() {
    const eventSource = new EventSource(apiPath('/api/stream'));
    eventSource.onmessage = (event) => {
        try {
            const newEvent = JSON.parse(event.data);

            if (isFrozen) return;

            // Dismiss view-cleared banner when new events arrive
            if (isViewCleared) {
                isViewCleared = false;
                const banner = document.getElementById('viewClearedBanner');
                if (banner) banner.classList.add('is-hidden');
                const clearBtn = document.getElementById('clearViewBtn');
                if (clearBtn) clearBtn.classList.remove('active');
            }

            const index = allEvents.findIndex(e => e.id === newEvent.id);
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const isFiltered = searchTerm.length > 0;

            if (index !== -1) {
                allEvents[index] = newEvent;
                if (!isFiltered && isTabVisible) updateRowInDom(newEvent);
            } else {
                allEvents.unshift(newEvent);
                if (allEvents.length > 1000) allEvents.pop();
                if (!isFiltered && isTabVisible) prependRowToDom(newEvent);
            }

            if (isFiltered && isTabVisible) {
                // Throttle filter re-render
                if (window.renderTimeout) clearTimeout(window.renderTimeout);
                window.renderTimeout = setTimeout(renderEvents, 100);
            }
        } catch (e) {
            console.error("Failed to parse SSE event:", e, event.data);
        }
    };
    eventSource.onerror = () => {
        console.error("SSE connection lost. Reconnecting...");
    };
}

function createRowHtml(e) {
    let latencyClass = 'latency-low';
    if (e.latency_ms > 50) latencyClass = 'latency-mid';
    if (e.latency_ms > 150) latencyClass = 'latency-high';

    const latencyText = e.LatencyFormatted || (e.latency_ms !== null && e.latency_ms !== undefined ? e.latency_ms.toFixed(1) + 'ms' : '-');
    const timeStr = new Date(e.unix_time * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    const relTime = getRelativeTime(e.unix_time);

    return `
        <td class="timestamp"><div class="timestamp-primary">${escapeHtml(timeStr)}</div><div class="timestamp-relative">${escapeHtml(relTime)}</div></td>
        <td><span class="badge node-badge">${escapeHtml(e.node || 'local')}</span></td>
        <td><span class="badge badge-type">${escapeHtml(e.type)}</span></td>
        <td class="domain cell-with-copy">${escapeHtml(e.domain)}<button class="test-domain-btn" title="Test in simulator" data-domain="${escapeHtml(e.domain)}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></button></td>
        <td class="client-cell" data-client-ip="${escapeHtml(e.client_ip)}" title="Click for details">
            <span class="badge badge-ip">${escapeHtml(e.client_ip)}</span>
            ${e.alias ? `<span class="alias-tag">${escapeHtml(e.alias)}</span>` : ''}
        </td>
        <td>${e.upstream ? `<span class="upstream-badge">${escapeHtml(e.upstream)}</span>` : '-'}</td>
        <td class="latency-cell ${latencyClass}">${escapeHtml(latencyText)}</td>
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
    await Promise.all([fetchEvents(), fetchStats(), fetchNodeStatus()]);
}

async function fetchEvents() {
    try {
        const response = await fetch(apiPath('/api/events'));
        if (!response.ok) throw new Error('API down');
        const newEvents = await response.json();

        if (newEvents.length > 0) {
            allEvents = newEvents.slice(0, 1000);
            renderEvents();
        }

        document.getElementById('systemStatus').classList.remove('offline');
        document.getElementById('systemStatus').textContent = '● System Online';
    } catch (e) {
        console.error(e);
        document.getElementById('systemStatus').classList.add('offline');
        document.getElementById('systemStatus').textContent = '● System Offline';
    }
}

async function fetchStats() {
    try {
        const response = await fetch(apiPath('/api/stats'));
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
            healthEl.innerHTML = Object.entries(stats.node_health).map(([node, upstreams]) => {
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
            applyDynamicStyles(healthEl);
        }

        // Update type breakdown bars
        const typeEl = document.getElementById('typeBreakdown');
        if (stats.type_counts) {
            const total = Object.values(stats.type_counts).reduce((a, b) => a + b, 0);
            if (total === 0) {
                typeEl.innerHTML = '<div class="empty-small">No data</div>';
            } else {
                const sortedTypes = Object.entries(stats.type_counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
                typeEl.innerHTML = sortedTypes.map(([type, count]) => {
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
                applyDynamicStyles(typeEl);
            }
        }

        // Update heatmap
        const heatmapEl = document.getElementById('trafficHeatmap');
        if (stats.heatmap) {
            const sortedHours = Object.entries(stats.heatmap).sort();
            const maxCount = Math.max(...sortedHours.map(h => h[1]), 1);
            heatmapEl.innerHTML = sortedHours.map(([hour, count]) => {
                const level = count === 0 ? 0 : Math.max(1, Math.ceil((count / maxCount) * 10));
                return `<div class="heatmap-box heatmap-level-${level}" title="${escapeHtml(hour)}: ${count} queries">${escapeHtml(hour.split(':')[0])}</div>`;
            }).join('');
        }

        // Update node list
        const nodeStats = document.getElementById('nodeStats');
        if (stats.nodes) {
            nodeStats.innerHTML = Object.entries(stats.nodes).map(([name, s]) => `
                <li class="top-item">
                    <span>${escapeHtml(name)}</span>
                    <span><span class="top-count">${formatNumber(s.rpm)}</span> <span class="top-count node-rph">${formatNumber(s.rph)}</span></span>
                </li>
            `).join('');
        } else {
            nodeStats.innerHTML = '';
        }

        // Update chart locally
        rpmHistory.push(stats.rpm);
        rpmHistory.shift();
        renderMiniChart();
    } catch (e) { console.error(e); }
}
async function fetchNodeStatus() {
    try {
        const response = await fetch(apiPath('/api/nodes'));
        if (!response.ok) return;
        const nodes = await response.json();
        const container = document.getElementById('nodeCards');
        if (!container) return;
        if (!nodes || nodes.length === 0) {
            container.innerHTML = '<p class="empty-state">No slave nodes connected</p>';
            return;
        }
        container.innerHTML = nodes.map(node => {
            const statusClass = node.Online ? 'online' : 'offline';
            const statusText = node.Online ? 'Online' : 'Offline';
            const lastSeen = node.LastSeen ? new Date(node.LastSeen).toLocaleTimeString() : 'Never';
            const memInfo = node.MemoryMB ? node.MemoryMB.toFixed(1) + ' MB' : '-';
            const dbInfo = node.DBSizeMB ? node.DBSizeMB.toFixed(1) + ' MB' : '-';
            return '<div class="node-card">' +
                '<div class="node-card-header">' +
                '<span class="node-name">' + escapeHtml(node.Name) + '</span>' +
                '<span class="node-online-indicator ' + statusClass + '">' +
                '<span class="node-online-dot ' + statusClass + '"></span>' +
                statusText +
                '</span>' +
                '</div>' +
                '<div class="node-details">' +
                '<div class="node-detail-row"><span class="node-detail-label">Version</span><span class="node-detail-value">' + escapeHtml(node.Version || '-') + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Last Seen</span><span class="node-detail-value">' + lastSeen + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Memory</span><span class="node-detail-value">' + memInfo + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">Goroutines</span><span class="node-detail-value">' + (node.Goroutines || '-') + '</span></div>' +
                '<div class="node-detail-row"><span class="node-detail-label">DB Size</span><span class="node-detail-value">' + dbInfo + '</span></div>' +
                '</div>' +
                (node.Version ? '<div class="node-version">v' + escapeHtml(node.Version) + '</div>' : '') +
                '</div>';
        }).join('');
    } catch (e) {
        // Silently fail - node status is non-critical
    }
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
    try {
        const response = await fetch(apiPath(`/api/simulate?domain=${encodeURIComponent(domain)}`));
        const data = await response.json();
        if (data.status === 'success') {
            resBox.innerHTML = `<strong>Results:</strong> ${data.ips.map(escapeHtml).join(', ')}`;
        } else {
            resBox.innerHTML = `<span class="sim-error">Error: ${escapeHtml(data.error)}</span>`;
        }
    } catch (e) { resBox.textContent = 'Error: ' + e.message; }
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

function renderTopList(id, list) {
    const el = document.getElementById(id);
    el.innerHTML = list.map(item => {
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
    modal.classList.add('open');

    try {
        const response = await fetch(apiPath(`/api/client_stats?ip=${encodeURIComponent(ip)}`));
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

document.getElementById('freezeBtn').addEventListener('click', function () {
    isFrozen = !isFrozen;
    this.classList.toggle('freeze-active', isFrozen);
    this.textContent = isFrozen ? '▶️' : '⏸️';
});

document.getElementById('compactToggle').addEventListener('click', function () {
    document.body.classList.toggle('compact');
});

document.getElementById('clearViewBtn').addEventListener('click', function () {
    clearView();
});

document.getElementById('simulateBtn').addEventListener('click', simulateQuery);
document.getElementById('modalCloseBtn').addEventListener('click', function () {
    document.getElementById('clientModal').classList.remove('open');
});
document.getElementById('clientModal').addEventListener('click', function (event) {
    if (event.target === this) this.classList.remove('open');
});

document.getElementById('searchInput').addEventListener('input', renderEvents);

function updateVisibility() {
    isTabVisible = document.visibilityState === 'visible';
    if (statsInterval) clearInterval(statsInterval);
    if (nodeStatusInterval) clearInterval(nodeStatusInterval);

    const rate = isTabVisible ? 5000 : 60000;
    statsInterval = setInterval(fetchStats, rate);
    nodeStatusInterval = setInterval(fetchNodeStatus, 30000);

    if (isTabVisible) {
        fetchAll(); // Catch up immediately
    }
}

document.addEventListener('visibilitychange', updateVisibility);

// Event delegation for test-domain-btn (XSS-safe: domain from data attribute)
document.addEventListener('click', function (e) {
    const btn = e.target.closest('.test-domain-btn');
    if (btn) {
        e.stopPropagation();
        prefillSimulator(btn.dataset.domain);
    }
    const clientCell = e.target.closest('.client-cell');
    if (clientCell) showClientStats(clientCell.dataset.clientIp);
});

updateVisibility(); // Initial set
startStream();
