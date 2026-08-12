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

