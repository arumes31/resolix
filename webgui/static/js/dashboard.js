const dashboardRanges = new Set(['15m', '1h', '6h', '24h', '7d', '30d']);
let dashboardGeneratedAt = 0;

function selectedDashboardRange() {
    return document.getElementById('dashboardRange')?.value || '24h';
}

function fetchStats() {
    const range = selectedDashboardRange();
    return coalesceRequest(`stats:${range}`, async () => {
        try {
            const response = await fetch(apiPath(`/api/dashboard/v1/stats?range=${encodeURIComponent(range)}`));
            if (!response.ok) throw new Error(`Dashboard API failed (${response.status})`);
            const stats = await response.json();
            if (stats.schema_version !== 1) throw new Error(`Unsupported dashboard schema ${stats.schema_version}`);
            renderDashboardStats(stats);
            document.querySelectorAll('.skeleton-card').forEach(card => card.classList.remove('skeleton-card'));
            setPollingStatus(true);
        } catch (error) {
            console.error(error);
            refreshDashboardFreshness(true);
            setPollingStatus(false);
        }
    });
}

function renderDashboardStats(stats) {
    const summary = stats.summary || {};
    const range = stats.range || {};
    const breakdowns = stats.breakdowns || {};
    document.getElementById('windowQueries').textContent = formatNumber(summary.queries || 0);
    document.getElementById('averageRPM').textContent = `${Number(summary.queries_per_minute || 0).toFixed(1)} RPM`;
    document.getElementById('blockedRatio').textContent = `${Number(summary.blocked_ratio || 0).toFixed(1)}%`;
    document.getElementById('blockedCount').textContent = formatNumber(summary.blocked || 0);
    document.getElementById('errorRatio').textContent = `${Number(summary.error_ratio || 0).toFixed(1)}%`;
    document.getElementById('errorCount').textContent = formatNumber(summary.errors || 0);
    document.getElementById('cacheRatio').textContent = `${Number(summary.cache_hit_ratio || 0).toFixed(1)}%`;
    document.getElementById('cacheHitCount').textContent = formatNumber(summary.cache_hits || 0);
    document.getElementById('bandwidthSaved').textContent = formatBytes(summary.bandwidth_saved_bytes || 0);
    document.getElementById('windowLabel').textContent = range.label || 'Selected window';
    document.getElementById('trafficBucketLabel').textContent = formatBucketDuration(range.bucket_seconds || 0);

    renderTopList('topDomains', breakdowns.top_domains);
    renderTopList('topClients', breakdowns.top_clients);
    renderTopList('topBlockedDomains', breakdowns.top_blocked_domains);
    renderTrafficSeries(stats.series || [], range);
    renderOutcomeSeries(stats.series || []);
    renderNodeComparison(stats.series || [], breakdowns.node_totals || {});
    renderTypeBreakdown(breakdowns.type_counts || {});
    renderTrafficHeatmap(stats.series || [], range.bucket_seconds || 0);
    renderUpstreamHealth(stats.upstream_health || {}, stats.upstream_health_history || {});
    renderFilteringStatus(stats.filtering || {});
    renderDashboardDegraded(stats);

    dashboardGeneratedAt = Date.parse(stats.generated_at || '') || Date.now();
    refreshDashboardFreshness(false);
}

function renderTrafficSeries(series, range) {
    const chart = document.getElementById('trafficSeries');
    const maxQueries = Math.max(...series.map(point => point.queries || 0), 1);
    const html = series.map(point => {
        const height = percentStep((point.queries / maxQueries) * 100);
        const label = formatBucketTime(point.start, range.bucket_seconds);
        return `<span class="timeline-column" title="${escapeHtml(label)}: ${formatNumber(point.queries)} queries"><i class="timeline-bar height-pct-${height}"></i></span>`;
    }).join('');
    replaceHTMLIfChanged(chart, html || '<span class="empty-small">No traffic in this window</span>');
    chart.setAttribute('aria-label', `Query volume for ${range.label || 'the selected window'}`);
    document.getElementById('trafficStartLabel').textContent = series.length ? formatBucketTime(series[0].start, range.bucket_seconds) : '—';
    document.getElementById('trafficEndLabel').textContent = series.length ? formatBucketTime(series[series.length - 1].start, range.bucket_seconds) : 'Now';
}

function renderOutcomeSeries(series) {
    const chart = document.getElementById('outcomeSeries');
    const maxQueries = Math.max(...series.map(point => point.queries || 0), 1);
    const html = series.map(point => {
        const title = `Answered ${point.forwarded || 0}, cached ${point.cached || 0}, blocked ${point.blocked || 0}, failed ${point.errors || 0}`;
        const segment = (kind, count) => `<i class="outcome-segment ${kind} height-pct-${percentStep((count / maxQueries) * 100)}"></i>`;
        return `<span class="timeline-column outcome-column" title="${title}">${segment('forwarded', point.forwarded || 0)}${segment('cached', point.cached || 0)}${segment('blocked', point.blocked || 0)}${segment('errors', point.errors || 0)}</span>`;
    }).join('');
    replaceHTMLIfChanged(chart, html || '<span class="empty-small">No outcomes in this window</span>');
}

function renderNodeComparison(series, totals) {
    const container = document.getElementById('nodeComparison');
    const nodes = Object.entries(totals).sort((a, b) => b[1] - a[1]);
    if (nodes.length === 0) {
        replaceHTMLIfChanged(container, '<div class="empty-small">No node traffic</div>');
        return;
    }
    const maxTotal = Math.max(...nodes.map(([, total]) => total), 1);
    const html = nodes.slice(0, 8).map(([node, total]) => {
        const samples = series.map(point => point.nodes?.[node] || 0);
        const sampleMax = Math.max(...samples, 1);
        const sparkline = samples.map(value => `<i class="node-spark-bar height-pct-${percentStep((value / sampleMax) * 100)}"></i>`).join('');
        return `<div class="node-comparison-row"><div class="node-comparison-title"><span>${escapeHtml(node)}</span><strong>${formatNumber(total)}</strong></div><div class="node-share-track"><i class="node-share-fill width-pct-${percentStep((total / maxTotal) * 100)}"></i></div><div class="node-series" aria-label="${escapeHtml(node)} traffic trend">${sparkline}</div></div>`;
    }).join('');
    replaceHTMLIfChanged(container, html);
}

function renderTypeBreakdown(typeCounts) {
    const element = document.getElementById('typeBreakdown');
    const total = Object.values(typeCounts).reduce((sum, value) => sum + value, 0);
    if (total === 0) {
        replaceHTMLIfChanged(element, '<div class="empty-small">No data</div>');
        return;
    }
    const html = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([type, count]) => {
        const percentage = (count / total) * 100;
        return `<div class="type-item"><div class="type-row"><span>${escapeHtml(type || 'Unknown')}</span><span class="type-meta">${formatNumber(count)} (${percentage.toFixed(1)}%)</span></div><div class="type-track"><div class="type-bar width-pct-${percentStep(percentage)}"></div></div></div>`;
    }).join('');
    replaceHTMLIfChanged(element, html);
}

function renderTrafficHeatmap(series, bucketSeconds) {
    const element = document.getElementById('trafficHeatmap');
    const maxQueries = Math.max(...series.map(point => point.queries || 0), 1);
    const html = series.map(point => {
        const level = point.queries === 0 ? 0 : Math.max(1, Math.ceil((point.queries / maxQueries) * 10));
        const label = formatBucketTime(point.start, bucketSeconds);
        return `<div class="heatmap-box heatmap-level-${level}" title="${escapeHtml(label)}: ${formatNumber(point.queries)} queries">${escapeHtml(shortBucketLabel(point.start, bucketSeconds))}</div>`;
    }).join('');
    replaceHTMLIfChanged(element, html || '<div class="empty-small">No data</div>');
}

function renderUpstreamHealth(health, history) {
    const element = document.getElementById('upstreamHealth');
    const nodes = Object.entries(health);
    if (nodes.length === 0) {
        replaceHTMLIfChanged(element, '<li class="top-item"><span>No health samples</span></li>');
        return;
    }
    const html = nodes.map(([node, upstreams]) => {
        const rows = Object.entries(upstreams).map(([upstream, latency]) => {
            const samples = history[node]?.[upstream] || [];
            const maxLatency = Math.max(...samples.filter(value => value > 0), 1);
            const sparkline = samples.map(value => {
                const height = value === -1 ? 100 : (value / maxLatency) * 100;
                return `<i class="spark-bar height-pct-${percentStep(height)} ${value === -1 ? 'fail' : ''}"></i>`;
            }).join('');
            const isDown = latency === -1;
            return `<div class="health-row"><div class="health-label"><span class="health-ip">${escapeHtml(upstream)}</span><div class="sparkline">${sparkline}</div></div><span class="top-count health-status ${isDown ? 'down' : 'up'}">${isDown ? 'DOWN' : Number(latency).toFixed(1) + 'ms'}</span></div>`;
        }).join('');
        return `<li class="health-node"><div class="health-node-title">Node: ${escapeHtml(node)}</div>${rows}</li>`;
    }).join('');
    replaceHTMLIfChanged(element, html);
}

function renderFilteringStatus(filtering) {
    const state = filtering.state || 'unconfigured';
    const stateLabels = { active: 'Protection active', paused: 'Protection paused', degraded: 'Sources degraded', unconfigured: 'No filter engine' };
    document.getElementById('filteringState').textContent = stateLabels[state] || 'Filter status unknown';
    document.getElementById('filteringDetail').textContent = filtering.configured ? `${formatNumber(filtering.blocked_total || 0)} blocked · ${formatNumber(filtering.allowed_total || 0)} exceptions` : 'DNS traffic is not using configured filter sources';
    document.getElementById('filterBlockRules').textContent = formatNumber(filtering.block_rules || 0);
    document.getElementById('filterAllowRules').textContent = formatNumber(filtering.allow_rules || 0);
    document.getElementById('filterHealthySources').textContent = `${filtering.healthy_sources || 0} / ${filtering.source_count || 0}`;
    document.getElementById('filterLastUpdated').textContent = filtering.last_updated ? `Rules updated ${getRelativeTime(Date.parse(filtering.last_updated) / 1000)}` : 'No filter update reported';
    const beacon = document.getElementById('filteringBeacon');
    beacon.className = `filtering-beacon is-${state}`;
    const chip = document.getElementById('filteringChip');
    chip.className = `section-chip ${state === 'active' ? 'healthy' : 'alert-chip'}`;
    chip.textContent = state;
}

function renderDashboardDegraded(stats) {
    const banner = document.getElementById('dashboardDegraded');
    const messages = [];
    const labels = { events: 'Historical event aggregation is incomplete.', filtering_paused: 'Filtering protection is paused.', filter_sources: 'One or more filter sources failed to update.' };
    (stats.errors || []).forEach(error => messages.push(labels[error] || `Data source ${error} is unavailable.`));
    if (stats.range?.retention_limited) {
        messages.push(`The selected window exceeds ${formatDuration(stats.range.available_seconds)} retention; showing available data.`);
    }
    banner.hidden = messages.length === 0;
    banner.classList.toggle('is-info', !stats.degraded && stats.range?.retention_limited);
    document.getElementById('dashboardDegradedMessage').textContent = messages.join(' ');
}

function formatBucketDuration(seconds) {
    if (seconds >= 86400) return `${seconds / 86400}d buckets`;
    if (seconds >= 3600) return `${seconds / 3600}h buckets`;
    return `${Math.max(1, seconds / 60)}m buckets`;
}

function formatDuration(seconds) {
    if (seconds >= 86400) return `${Math.round(seconds / 86400)}d`;
    if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`;
    return `${Math.round(seconds / 60)}m`;
}

function formatBucketTime(timestamp, bucketSeconds) {
    const date = new Date(timestamp * 1000);
    if (bucketSeconds >= 86400) return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    if (bucketSeconds >= 21600) return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' });
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function shortBucketLabel(timestamp, bucketSeconds) {
    const date = new Date(timestamp * 1000);
    if (bucketSeconds >= 86400) return date.toLocaleDateString([], { day: '2-digit' });
    if (bucketSeconds >= 21600) return date.toLocaleDateString([], { weekday: 'short' }).slice(0, 2);
    return date.toLocaleTimeString([], { hour: '2-digit', hour12: false });
}

function refreshDashboardFreshness(failed) {
    const element = document.getElementById('dashboardFreshness');
    if (!element) return;
    if (!dashboardGeneratedAt) {
        element.textContent = failed ? 'Update failed' : 'Waiting for data';
        element.classList.toggle('is-stale', failed);
        return;
    }
    const ageSeconds = Math.max(0, Math.floor((Date.now() - dashboardGeneratedAt) / 1000));
    element.textContent = failed ? `Update failed · last good ${ageSeconds}s ago` : `Updated ${ageSeconds}s ago`;
    element.classList.toggle('is-stale', failed || ageSeconds > 30);
}

const dashboardRangeElement = document.getElementById('dashboardRange');
if (dashboardRangeElement) {
    const savedRange = localStorage.getItem('resolix.dashboardRange');
    if (dashboardRanges.has(savedRange)) dashboardRangeElement.value = savedRange;
    dashboardRangeElement.addEventListener('change', () => {
        localStorage.setItem('resolix.dashboardRange', dashboardRangeElement.value);
        void fetchStats();
    });
    setInterval(() => refreshDashboardFreshness(false), 5000);
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
