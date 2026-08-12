async function loadUpstreams() {
    const data = await apiJSON('/api/upstream-settings');
    const upstreams = data.upstreams || [];
	state.upstreamDetails = data.details || [];
	state.upstreamRuntime = data.runtime || [];
    document.getElementById('upstreamList').value = upstreams.join('\n');
    document.getElementById('bootstrapList').value = (data.bootstrap_servers || []).join('\n');
    document.getElementById('upstreamCount').textContent = `${upstreams.length} ${upstreams.length === 1 ? 'server' : 'servers'}`;
	renderUpstreamRuntime(data.bootstrap_status || []);
	markFormClean(document.getElementById('upstreamForm'));
}

function summarizeDiffValue(value) {
	if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`;
	if (value && typeof value === 'object') {
		const count = Object.keys(value).length;
		return `${count} entr${count === 1 ? 'y' : 'ies'}`;
	}
	return String(value ?? 'empty');
}

async function confirmConfigChange(patch, action) {
	state.snapshot = await apiJSON('/api/config/snapshot');
	const candidate = JSON.parse(JSON.stringify(state.snapshot));
	Object.assign(candidate, patch, { revision: '' });
	const preview = await apiJSON('/api/config/diff', {
		method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(candidate)
	});
	if (!preview.changed) {
		notice('No configuration changes to save');
		return false;
	}
	const changes = (preview.changes || []).map(change =>
		`• ${change.field}: ${summarizeDiffValue(change.before)} → ${summarizeDiffValue(change.after)}`
	).join('\n');
	return window.confirm(`${action}\n\n${changes}\n\nCurrent ${String(preview.current_revision).slice(0, 12)} → desired ${String(preview.desired_revision).slice(0, 12)}`);
}

function renderUpstreamRuntime(bootstrapStatus) {
	const runtimeBySpec = new Map(state.upstreamRuntime.map(item => [item.spec, item]));
	const rows = state.upstreamDetails.map(detail => {
		const runtime = runtimeBySpec.get(detail.spec) || {};
		const health = runtime.healthy === false ? `Failure · ${runtime.last_failure || 'health check failed'}` : 'Ready';
		const latency = runtime.successes ? `p50 ${Number(runtime.p50_ms || 0).toFixed(1)} · p95 ${Number(runtime.p95_ms || 0).toFixed(1)} · p99 ${Number(runtime.p99_ms || 0).toFixed(1)} ms` : 'No latency samples';
		const connection = detail.scheme === 'https' ? `Connections: ${runtime.connections_reused || 0} reused / ${runtime.connections_fresh || 0} fresh` : '';
		const circuit = runtime.circuit_open_until && !runtime.circuit_open_until.startsWith('0001-') ? `Circuit open until ${new Date(runtime.circuit_open_until).toLocaleString()}` : 'Circuit closed';
		const streaks = `${runtime.consecutive_successes || 0} success / ${runtime.consecutive_failures || 0} failure streak`;
		const tls = runtime.tls_issuer ? `TLS issuer ${runtime.tls_issuer}${runtime.tls_expires_at && !runtime.tls_expires_at.startsWith('0001-') ? ` · expires ${new Date(runtime.tls_expires_at).toLocaleString()}` : ''}` : '';
		const protocol = { udp: 'UDP', tcp: 'TCP', tls: 'DoT', https: 'DoH' }[detail.scheme] || String(detail.scheme || 'DNS').toUpperCase();
		return `<div class="settings-list-row"><div class="settings-list-main"><div class="settings-list-title upstream-title-line"><span>${escapeHtml(detail.spec)}</span><span class="upstream-protocol-badge" data-protocol="${escapeHtml(detail.scheme)}">${escapeHtml(protocol)}</span></div><div class="settings-list-meta">${escapeHtml(detail.normalized_spec)} · ${escapeHtml(health)} · timeout ${escapeHtml(detail.timeout_ms)} ms · weight ${escapeHtml(runtime.weight || detail.weight)}${runtime.resolved_endpoint ? ` · endpoint ${escapeHtml(runtime.resolved_endpoint)}` : ''}</div><div class="settings-list-meta">${escapeHtml(latency)} · ${escapeHtml(streaks)} · ${escapeHtml(circuit)}${connection ? ` · ${escapeHtml(connection)}` : ''}${tls ? ` · ${escapeHtml(tls)}` : ''}</div></div><div class="row-actions"><button type="button" class="mini-action upstream-test" data-spec="${escapeHtml(detail.spec)}">Test</button></div></div>`;
	});
	if (bootstrapStatus.length) {
		rows.push(...bootstrapStatus.map(entry => `<div class="settings-list-row"><div class="settings-list-main"><div class="settings-list-title upstream-title-line"><span>Bootstrap cache · ${escapeHtml(entry.hostname)}</span><span class="upstream-protocol-badge" data-protocol="bootstrap">Bootstrap</span></div><div class="settings-list-meta">${escapeHtml((entry.addresses || []).join(', '))} · ${entry.stale ? 'stale' : `expires ${new Date(entry.expires_at).toLocaleString()}`}</div></div></div>`));
	}
	document.getElementById('upstreamRuntime').innerHTML = rows.join('') || emptyState('No upstream runtime observations yet');
}

function structuredUpstreamSpec() {
	const scheme = document.getElementById('upstreamScheme').value;
	const rawHost = document.getElementById('upstreamHost').value.trim();
	if (!rawHost) throw new Error('Resolver host is required');
	const host = rawHost.includes(':') && !rawHost.startsWith('[') ? `[${rawHost}]` : rawHost;
	const port = document.getElementById('upstreamPort').value.trim();
	const path = scheme === 'https' ? (document.getElementById('upstreamPath').value.trim() || '/dns-query') : '';
	const params = new URLSearchParams();
	const timeout = document.getElementById('upstreamTimeout').value.trim();
	const weight = Number(document.getElementById('upstreamWeight').value) || 1;
	if (timeout) params.set('timeout', timeout);
	if (weight !== 1) params.set('weight', String(weight));
	return `${scheme}://${host}${port ? `:${port}` : ''}${path}${params.size ? `?${params}` : ''}`;
}

function addStructuredUpstream() {
	const spec = structuredUpstreamSpec();
	const list = document.getElementById('upstreamList');
	const current = list.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
	current.push(spec);
	list.value = current.join('\n');
	refreshFormDirty(document.getElementById('upstreamForm'));
	notice('Resolver added to the draft list');
}

async function testUpstream(spec) {
	const bootstrapServers = document.getElementById('bootstrapList').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
	const report = await apiJSON('/api/upstreams/test', {
		method: 'POST', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ spec, bootstrap_servers: bootstrapServers })
	});
	const timing = Object.entries(report.timings_ms || {}).map(([phase, value]) => `${phase} ${Number(value).toFixed(1)} ms`).join(' · ');
	const tls = report.tls_issuer ? `TLS ${report.tls_server_name} · ${report.tls_issuer} · expires ${new Date(report.tls_expires_at).toLocaleDateString()}` : '';
	const bootstrap = (report.bootstrap_cache || []).map(item => `${item.hostname} → ${(item.addresses || []).join(', ')}${item.stale ? ' (stale)' : ''}`).join(' · ');
	document.getElementById('upstreamTestResult').innerHTML = [
		['Result', report.healthy ? 'Healthy' : `${report.failure?.phase || 'probe'} · ${report.failure?.message || 'failed'}`],
		['Endpoint', report.resolved_endpoint || 'Not resolved'],
		['Phases', timing || 'No timing data'],
		['Transport', [tls, report.http_status ? `HTTP ${report.http_status}` : '', report.content_type, report.dns_message_id ? `DNS ID ${report.dns_message_id}` : '', report.connection_reused ? 'reused connection' : 'fresh connection'].filter(Boolean).join(' · ') || report.normalized_spec],
		['Bootstrap', bootstrap || 'Literal endpoint / no bootstrap lookup']
	].map(([key, value]) => `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
	return report;
}

async function testAllUpstreams() {
	const specs = document.getElementById('upstreamList').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
	if (!specs.length) throw new Error('At least one upstream resolver is required');
	for (const spec of specs) {
		const report = await testUpstream(spec);
		if (!report.healthy) throw new Error(`${spec}: ${report.failure?.message || 'probe failed'}`);
	}
	notice(`All ${specs.length} upstream resolvers passed`);
}

async function saveUpstreams(event) {
    event.preventDefault();
    const upstreams = document.getElementById('upstreamList').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    const bootstrapServers = document.getElementById('bootstrapList').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    if (!upstreams.length) throw new Error('At least one upstream resolver is required');
	if (!await confirmConfigChange({ upstreams, bootstrap_servers: bootstrapServers }, 'Save upstream resolver changes?')) return;
	await apiJSON('/api/upstream-settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ upstreams, bootstrap_servers: bootstrapServers })
	});
	markFormClean(event.target);
    notice('Upstream and bootstrap resolvers saved and activated');
    await Promise.all([loadUpstreams(), loadStatus()]);
}

async function loadRoutes() {
    const data = await apiJSON('/api/dns/routes');
    state.routes = data.routes || {};
    const entries = Object.entries(state.routes).sort(([left], [right]) => left.localeCompare(right));
    document.getElementById('routeCount').textContent = `${entries.length} ${entries.length === 1 ? 'route' : 'routes'}`;
    document.getElementById('routeList').innerHTML = entries.map(([pattern, resolver]) => {
		const overlaps = routeOverlaps(pattern, entries.map(([candidate]) => candidate));
		return `
        <div class="settings-list-row"><div class="settings-list-main">
            <div class="settings-list-title">${escapeHtml(pattern)}</div>
            <div class="settings-list-meta">${escapeHtml(resolver)}${overlaps.length ? ` · overlaps ${escapeHtml(overlaps.join(', '))}; most-specific match wins` : ''}</div>
        </div><div class="row-actions controller-edit"><button type="button" class="mini-action danger route-delete" data-pattern="${escapeHtml(pattern)}">Delete</button></div></div>`
    }).join('') || emptyState('No domain-specific routes configured');
    setEditable(state.editable);
}

async function persistRoutes(routes) {
	if (!await confirmConfigChange({ routes }, 'Save DNS route changes?')) return false;
    await apiJSON('/api/dns/routes', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(routes)
    });
    await Promise.all([loadRoutes(), loadStatus()]);
	return true;
}

async function saveRoute(event) {
    event.preventDefault();
    const pattern = document.getElementById('routePattern').value.trim();
    const resolver = document.getElementById('routeUpstream').value.trim();
	if (!await persistRoutes({ ...state.routes, [pattern]: resolver })) return;
	event.target.reset(); markFormClean(event.target); notice(`DNS route saved for ${pattern}`);
}

async function deleteRoute(pattern) {
    const routes = { ...state.routes }; delete routes[pattern];
	if (await persistRoutes(routes)) notice('DNS route deleted');
}
