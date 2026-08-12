const apiBase = (document.body.dataset.baseUrl || '/').replace(/\/$/, '');
const state = {
    editable: false,
    mode: '',
    revision: '',
	snapshot: null,
	routes: {},
	subscriptions: [],
	subscriptionSources: new Map(),
	selectedSubscriptions: new Set(),
	filterUpdateInterval: 86400,
	upstreamDetails: [],
	upstreamRuntime: [],
	rewrites: [],
	clients: [],
	dnsSettings: null,
    editingRewrite: null,
    pendingRewriteDelete: null,
    rewriteDeleteTrigger: null,
    editingClient: null
};
const tailscaleRewriteCIDRs = ['100.64.0.0/10', 'fd7a:115c:a1e0::/48'];

function apiPath(path) { return apiBase + path; }
function escapeHtml(value) {
    return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
function splitList(value) { return value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean); }
function emptyState(message) { return `<div class="empty-settings">${escapeHtml(message)}</div>`; }

async function apiJSON(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        options.headers = { ...options.headers, 'X-CSRF-Token': document.body.dataset.csrfToken || '' };
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

function notice(message, error = false) {
    const element = document.getElementById('settingsNotice');
    element.textContent = message;
    element.classList.toggle('error', error);
    element.classList.remove('is-hidden');
    clearTimeout(notice.timer);
    notice.timer = setTimeout(() => element.classList.add('is-hidden'), 5000);
}

function setEditable(editable) {
    state.editable = editable;
    document.querySelectorAll('.controller-edit input, .controller-edit select, .controller-edit textarea, .controller-edit button, button.controller-edit')
        .forEach(control => { control.disabled = !editable; });
    document.body.classList.toggle('read-only-config', !editable);
    rewriteScopeState();
	updateDNSBlockingFields();
}

function formatRuntimeKey(key) {
    return key.split('_').map(word => word.toUpperCase()).join(' ');
}

function runtimeValue(value) {
    if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled';
    if (value === '' || value === null || value === undefined) return 'Not configured';
    return String(value);
}

function cacheRuntimeValues(cache) {
    if (!cache) return {};
    const hits = Number(cache.hits || 0);
    const misses = Number(cache.misses || 0);
    const lookups = hits + misses;
    const hitRate = lookups > 0 ? `${(hits * 100 / lookups).toFixed(1)}%` : 'No lookups';
    const qtypes = Object.entries(cache.by_qtype || {}).sort(([left], [right]) => left.localeCompare(right))
        .map(([qtype, stats]) => `${qtype}: ${stats.hits || 0} hit / ${stats.misses || 0} miss`)
        .join(' · ');
    return {
        cache_usage: `${cache.entries || 0} / ${cache.capacity || 0} (${(Number(cache.utilization || 0) * 100).toFixed(1)}%)`,
        cache_hit_rate: `${hitRate} (${hits} hit / ${misses} miss)`,
        cache_negative_entries: cache.negative_entries || 0,
        cache_in_flight: cache.in_flight || 0,
        cache_evictions: cache.evictions || 0,
        cache_expirations: cache.expirations || 0,
        cache_qtype_activity: qtypes || 'No lookups'
    };
}

function updateDNSBlockingFields() {
	const mode = document.getElementById('dnsBlockingMode');
	if (!mode) return;
	const custom = mode.value === 'custom_ip';
	['dnsBlockIPv4', 'dnsBlockIPv6'].forEach(id => {
		const control = document.getElementById(id);
		control.disabled = !state.editable || !custom;
	});
}

function renderDNSSettings(settings) {
	const form = document.getElementById('dnsSettingsForm');
	if (!form || form.dataset.dirty === 'true') return;
	state.dnsSettings = settings;
	document.getElementById('dnsUpstreamMode').value = settings.upstream_mode || 'load_balance';
	document.getElementById('dnsFallbacks').value = (settings.fallback_dns || []).join('\n');
	document.getElementById('dnsECSSubnet').value = settings.ecs_client_subnet || '';
	document.getElementById('dnsBlockingMode').value = settings.blocking_mode || 'nxdomain';
	document.getElementById('dnsBlockIPv4').value = settings.block_custom_ipv4 || '0.0.0.0';
	document.getElementById('dnsBlockIPv6').value = settings.block_custom_ipv6 || '::';
	document.getElementById('dnsBlockedTTL').value = settings.blocked_response_ttl ?? 60;
	document.getElementById('dnsDisableAAAA').checked = Boolean(settings.aaaa_disabled);
	document.getElementById('dnsRefuseANY').checked = Boolean(settings.refuse_any);
	document.getElementById('dnsDNSSEC').checked = Boolean(settings.dnssec);
	document.getElementById('dnsPrivatePTR').checked = Boolean(settings.private_ptr);
	document.getElementById('dnsPrivatePTRUpstreams').value = (settings.private_ptr_upstreams || []).join('\n');
	document.getElementById('dnsResolveClientHostnames').checked = Boolean(settings.resolve_client_hostnames);
	const safeSearch = new Set(settings.safe_search || []);
	document.querySelectorAll('.dns-safe-search').forEach(control => { control.checked = safeSearch.has(control.value); });
	document.getElementById('dnsBogusNXDOMAIN').value = (settings.bogus_nxdomain || []).join('\n');
	document.getElementById('dnsRateLimit').value = settings.rate_limit_qps ?? 0;
	document.getElementById('dnsInternalRateLimit').value = settings.internal_rate_limit_qps ?? 0;
	document.getElementById('dnsRateLimitEDE').checked = Boolean(settings.rate_limit_ede);
	document.getElementById('dnsRateLimitIPv4Prefix').value = settings.rate_limit_ipv4_prefix ?? 32;
	document.getElementById('dnsRateLimitIPv6Prefix').value = settings.rate_limit_ipv6_prefix ?? 128;
	document.getElementById('dnsRateLimitAllowlist').value = (settings.rate_limit_allowlist || []).join('\n');
	document.getElementById('dnsAllowedClients').value = (settings.allowed_clients || []).join('\n');
	document.getElementById('dnsDisallowedClients').value = (settings.disallowed_clients || []).join('\n');
	document.getElementById('dnsCacheSize').value = settings.cache_size ?? 25000;
	document.getElementById('dnsCacheMinTTL').value = settings.cache_min_ttl ?? 60;
	document.getElementById('dnsCacheMaxTTL').value = settings.cache_max_ttl ?? 600;
	document.getElementById('dnsCacheOptimistic').checked = Boolean(settings.cache_optimistic);
	document.getElementById('dnsCachePrefetch').checked = Boolean(settings.cache_prefetch);
	document.getElementById('dnsCachePrefetchWindow').value = settings.cache_prefetch_window_ms ?? 30000;
	document.getElementById('dnsCachePrefetchHits').value = settings.cache_prefetch_hits ?? 3;
	document.getElementById('dnsCacheSERVFAIL').value = settings.cache_servfail_ttl_ms ?? 0;
	updateDNSBlockingFields();
	markFormClean(form);
}

function integerValue(id) {
	return Number.parseInt(document.getElementById(id).value, 10);
}

function collectDNSSettings() {
	return {
		upstream_mode: document.getElementById('dnsUpstreamMode').value,
		fallback_dns: splitList(document.getElementById('dnsFallbacks').value),
		ecs_client_subnet: document.getElementById('dnsECSSubnet').value.trim(),
		blocking_mode: document.getElementById('dnsBlockingMode').value,
		block_custom_ipv4: document.getElementById('dnsBlockIPv4').value.trim(),
		block_custom_ipv6: document.getElementById('dnsBlockIPv6').value.trim(),
		blocked_response_ttl: integerValue('dnsBlockedTTL'),
		safe_search: [...document.querySelectorAll('.dns-safe-search:checked')].map(control => control.value),
		bogus_nxdomain: splitList(document.getElementById('dnsBogusNXDOMAIN').value),
		aaaa_disabled: document.getElementById('dnsDisableAAAA').checked,
		refuse_any: document.getElementById('dnsRefuseANY').checked,
		dnssec: document.getElementById('dnsDNSSEC').checked,
		private_ptr: document.getElementById('dnsPrivatePTR').checked,
		private_ptr_upstreams: splitList(document.getElementById('dnsPrivatePTRUpstreams').value),
		resolve_client_hostnames: document.getElementById('dnsResolveClientHostnames').checked,
		allowed_clients: splitList(document.getElementById('dnsAllowedClients').value),
		disallowed_clients: splitList(document.getElementById('dnsDisallowedClients').value),
		rate_limit_qps: integerValue('dnsRateLimit'),
		internal_rate_limit_qps: integerValue('dnsInternalRateLimit'),
		rate_limit_ede: document.getElementById('dnsRateLimitEDE').checked,
		rate_limit_ipv4_prefix: integerValue('dnsRateLimitIPv4Prefix'),
		rate_limit_ipv6_prefix: integerValue('dnsRateLimitIPv6Prefix'),
		rate_limit_allowlist: splitList(document.getElementById('dnsRateLimitAllowlist').value),
		cache_size: integerValue('dnsCacheSize'),
		cache_min_ttl: integerValue('dnsCacheMinTTL'),
		cache_max_ttl: integerValue('dnsCacheMaxTTL'),
		cache_optimistic: document.getElementById('dnsCacheOptimistic').checked,
		cache_prefetch: document.getElementById('dnsCachePrefetch').checked,
		cache_prefetch_window_ms: integerValue('dnsCachePrefetchWindow'),
		cache_prefetch_hits: integerValue('dnsCachePrefetchHits'),
		cache_servfail_ttl_ms: integerValue('dnsCacheSERVFAIL')
	};
}

async function saveDNSSettings(event) {
	event.preventDefault();
	const settings = collectDNSSettings();
	if (!await confirmConfigChange({ dns_settings: settings }, 'Apply this DNS policy to all synchronized nodes?')) return;
	const saved = await apiJSON('/api/config/dns-settings', {
		method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(settings)
	});
	state.dnsSettings = saved;
	markFormClean(event.target);
	notice('DNS policy applied and queued for agent synchronization');
	await loadStatus();
}

async function loadStatus() {
    const data = await apiJSON('/api/config/status');
    state.mode = data.mode;
    state.revision = data.revision || '';
    setEditable(Boolean(data.editable));
    const statePill = document.getElementById('authorityState');
    statePill.textContent = data.editable ? 'Controller' : 'Read only';
    statePill.classList.toggle('online', Boolean(data.editable));
    statePill.classList.toggle('paused', !data.editable);
    document.getElementById('authorityTitle').textContent = data.editable
        ? 'Changes apply here and replicate to agent nodes'
        : 'This agent mirrors configuration from the controller node';
    document.getElementById('configRevision').textContent = `revision ${String(data.revision || '—').slice(0, 12)}`;
    document.getElementById('clusterMode').textContent = data.mode;
    document.getElementById('clusterSummary').innerHTML = [
        ['Role', data.mode],
        ['Authority', data.editable ? 'Controller-owned' : 'Mirrored / read only'],
        ['Revision', data.revision || 'Not available'],
		['Snapshot contents', 'Upstreams, DNS policy, routes, blocklists, allowlists, rules, rewrites, clients']
    ].map(([key, value]) => `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
    const runtime = { ...(data.runtime || {}), ...cacheRuntimeValues(data.cache) };
    document.getElementById('runtimeSettings').innerHTML = Object.entries(runtime).map(([key, value]) =>
        `<div class="runtime-item"><span>${escapeHtml(formatRuntimeKey(key))}</span><strong>${escapeHtml(runtimeValue(value))}</strong></div>`
    ).join('');
	renderDNSSettings(data.dns_settings || {});
}

async function loadCluster() {
    await loadStatus();
    let nodes = [];
    if (state.mode === 'controller') {
        const data = await apiJSON('/api/nodes');
        nodes = data.nodes || [];
    }
    const summary = [
        ['Role', state.mode],
        ['Authority', state.editable ? 'Controller-owned' : 'Mirrored / read only'],
        ['Local revision', state.revision || 'Not available'],
		['Snapshot contents', 'Upstreams, DNS policy, routes, blocklists, allowlists, rules, rewrites, clients']
    ];
    nodes.forEach(node => {
		const revision = node.config_revision
			? `${node.config_revision.slice(0, 12)}${node.config_revision === state.revision ? ' · current' : ' · pending/drifted'}`
			: 'No configuration revision reported';
		const details = [
			revision,
			`DB ${Number(node.db_size_mb || 0).toFixed(1)} MiB`,
			`${Number(node.forwarder_backlog_depth || 0)} queued · ${Number(node.forwarder_backlog_oldest_seconds || 0).toFixed(1)}s oldest`
		];
		if (node.last_config_sync_error) details.push(`Sync error: ${node.last_config_sync_error}`);
		summary.push([node.name || 'Unnamed node', details.join(' · '), node.id || node.name]);
	});
    document.getElementById('clusterSummary').innerHTML = summary.map(([key, value, nodeID]) =>
        `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong>${nodeID && state.editable ? `<button type="button" class="mini-action sync-node" data-node="${escapeHtml(nodeID)}">Sync now</button>` : ''}</div>`
    ).join('');
}

async function requestConfigSync(node = '') {
	await apiJSON(`/api/config/sync-now${node ? `?node=${encodeURIComponent(node)}` : ''}`, { method: 'POST' });
	notice(node ? 'Agent synchronization scheduled' : 'Synchronization scheduled for all agents');
}

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
		return `<div class="settings-list-row"><div class="settings-list-main"><div class="settings-list-title">${escapeHtml(detail.spec)}</div><div class="settings-list-meta">${escapeHtml(detail.normalized_spec)} · ${escapeHtml(health)} · timeout ${escapeHtml(detail.timeout_ms)} ms · weight ${escapeHtml(runtime.weight || detail.weight)}${runtime.resolved_endpoint ? ` · endpoint ${escapeHtml(runtime.resolved_endpoint)}` : ''}</div><div class="settings-list-meta">${escapeHtml(latency)} · ${escapeHtml(streaks)} · ${escapeHtml(circuit)}${connection ? ` · ${escapeHtml(connection)}` : ''}${tls ? ` · ${escapeHtml(tls)}` : ''}</div></div><div class="row-actions"><button type="button" class="mini-action upstream-test" data-spec="${escapeHtml(detail.spec)}">Test</button></div></div>`;
	});
	if (bootstrapStatus.length) {
		rows.push(...bootstrapStatus.map(entry => `<div class="settings-list-row"><div class="settings-list-main"><div class="settings-list-title">Bootstrap cache · ${escapeHtml(entry.hostname)}</div><div class="settings-list-meta">${escapeHtml((entry.addresses || []).join(', '))} · ${entry.stale ? 'stale' : `expires ${new Date(entry.expires_at).toLocaleString()}`}</div></div></div>`));
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

async function loadSubscriptions() {
    const [data, filterStatus] = await Promise.all([
        apiJSON('/api/config/subscriptions'),
        apiJSON('/api/filtering/status')
    ]);
    state.subscriptions = data.subscriptions || [];
    state.subscriptionSources = new Map((filterStatus.sources || []).map(source => [source.id, source]));
	state.filterUpdateInterval = Number(filterStatus.update_interval_seconds) || 86400;
	state.selectedSubscriptions = new Set([...state.selectedSubscriptions].filter(id => state.subscriptions.some(item => item.id === id)));
    renderSubscriptionPanel(false);
	renderSubscriptionPanel(true);
	renderOverrideReport(filterStatus.allowlist_overrides || []);
	setEditable(state.editable);
}

function routeOverlaps(pattern, patterns) {
	const suffix = pattern.replace(/^\*\./, '').toLocaleLowerCase();
	return patterns.filter(candidate => {
		if (candidate === pattern) return false;
		const candidateSuffix = candidate.replace(/^\*\./, '').toLocaleLowerCase();
		return suffix === candidateSuffix || suffix.endsWith(`.${candidateSuffix}`) || candidateSuffix.endsWith(`.${suffix}`);
	});
}

function renderOverrideReport(overrides) {
	document.getElementById('allowlistOverrideReport').innerHTML = overrides.length ? [
		['Active overrides', `${overrides.length} exact allow rules currently suppress a block match`],
		['Examples', overrides.slice(0, 5).map(item => `${item.domain}: ${item.allow_rule} overrides ${item.block_rule}`).join(' · ')]
	].map(([key, value]) => `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('') : '';
}

async function testRoute(event) {
	event.preventDefault();
	const domain = document.getElementById('routeTestDomain').value.trim();
	const data = await apiJSON(`/api/dns/routes/test?domain=${encodeURIComponent(domain)}`);
	const selected = data.selected;
	const precedence = (data.precedence || []).map(item => `${item.exact ? 'exact' : 'wildcard'} ${item.pattern} → ${item.upstream}`).join(' · ');
	document.getElementById('routeTestResult').innerHTML = [
		['Selected route', selected ? `${selected.pattern} → ${selected.upstream}` : 'Global upstream pool'],
		['Precedence', precedence || 'No matching dedicated route']
	].map(([key, value]) => `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
}

function subscriptionPrefix(allowOnly) {
    return allowOnly ? 'allowlist' : 'blocklist';
}

function validSourceDate(value) {
    return value && !value.startsWith('0001-') ? new Date(value) : null;
}

function formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function sourceIsStale(source) {
    const successful = validSourceDate(source?.last_update);
	const staleAfter = Math.max(state.filterUpdateInterval * 1.5, 3600) * 1000;
	return Boolean(successful && Date.now() - successful.getTime() > staleAfter);
}

function subscriptionStatus(item, source, allowOnly) {
    if (!item.enabled) return { label: 'Disabled', rank: 3, stale: false };
    if (!source) return { label: 'Awaiting first update', rank: 2, stale: false };
    const stale = sourceIsStale(source);
    if (source.last_error) return { label: `${stale ? 'Stale · ' : ''}Error · ${source.last_error}`, rank: stale ? 0 : 1, stale };
    const count = allowOnly ? source.allow_rule_count || 0 : source.rule_count || 0;
	return { label: `${stale ? 'Stale success · ' : ''}${count} ${count === 1 ? 'domain' : 'domains'}`, rank: stale ? 1 : 4, stale };
}

function subscriptionDetail(source) {
    if (!source) return [];
    const details = [];
    const checked = validSourceDate(source.last_checked);
    const successful = validSourceDate(source.last_update);
    details.push(`Checked: ${checked ? checked.toLocaleString() : 'never'}`);
    details.push(`Successful: ${successful ? successful.toLocaleString() : 'never'}`);
    if (source.rule_count_delta) details.push(`Rule change: ${source.rule_count_delta > 0 ? '+' : ''}${source.rule_count_delta}`);
    if (source.ignored_count) details.push(`${source.ignored_count} ignored: ${source.ignored_reason || 'non-DNS lines'}`);
    if (source.truncated) details.push(source.truncated_reason || 'Truncated at the active-rule safety limit');
    if (source.downloaded_bytes) details.push(`Download: ${formatBytes(source.downloaded_bytes)}`);
    if (source.final_hostname) details.push(`Final host: ${source.final_hostname}${source.redirect_count ? ` (${source.redirect_count} redirects)` : ''}`);
	if (source.final_url && source.final_url !== source.name) details.push(`Final URL: ${source.final_url}`);
    if (source.checksum) details.push(`SHA-256: ${source.checksum.slice(0, 12)}…`);
	if (source.rollback_count) details.push(`${source.rollback_count} rollback ${source.rollback_count === 1 ? 'version' : 'versions'}`);
    return details;
}

function subscriptionSortValue(item, source, allowOnly, sort) {
    if (sort === 'status') return subscriptionStatus(item, source, allowOnly).rank;
    if (sort === 'size') return -(Number(source?.downloaded_bytes) || 0);
    if (sort === 'updated') return -(validSourceDate(source?.last_update)?.getTime() || 0);
    return (item.name || item.url).toLocaleLowerCase();
}

function renderSubscriptionPanel(allowOnly) {
    const prefix = subscriptionPrefix(allowOnly);
    const allItems = state.subscriptions.filter(item => Boolean(item.allow_only) === allowOnly);
    const search = document.getElementById(`${prefix}Search`)?.value.trim().toLocaleLowerCase() || '';
    const sort = document.getElementById(`${prefix}Sort`)?.value || 'name';
    const items = allItems.filter(item => !search || `${item.name || ''} ${item.url}`.toLocaleLowerCase().includes(search));
    items.sort((left, right) => {
        const leftValue = subscriptionSortValue(left, state.subscriptionSources.get(left.id), allowOnly, sort);
        const rightValue = subscriptionSortValue(right, state.subscriptionSources.get(right.id), allowOnly, sort);
        return typeof leftValue === 'number' ? leftValue - rightValue : leftValue.localeCompare(rightValue);
    });
    document.getElementById(`${prefix}Count`).textContent = `${allItems.length} ${allItems.length === 1 ? 'list' : 'lists'}`;
    document.getElementById(`${prefix}List`).innerHTML = items.map(item => {
        const source = state.subscriptionSources.get(item.id);
        const sourceState = subscriptionStatus(item, source, allowOnly);
        const details = subscriptionDetail(source);
        return `
        <div class="settings-list-row subscription-row ${item.enabled ? '' : 'is-muted'} ${sourceState.stale ? 'is-stale' : ''}">
			<label class="subscription-toggle-label"><input type="checkbox" class="subscription-select" data-id="${escapeHtml(item.id)}" ${state.selectedSubscriptions.has(item.id) ? 'checked' : ''}> Select</label>
            <div class="settings-list-main">
                <div class="settings-list-title">${escapeHtml(item.name || item.url)}</div>
                <div class="settings-list-meta subscription-status">${escapeHtml(sourceState.label)} · ${escapeHtml(item.url)}${item.refresh_at_utc ? ` · daily ${escapeHtml(item.refresh_at_utc)} UTC` : ''}</div>
                ${details.length ? `<div class="settings-list-meta subscription-details">${details.map(escapeHtml).join(' · ')}</div>` : ''}
            </div>
            <div class="row-actions controller-edit">
                <label class="subscription-toggle-label"><input type="checkbox" class="subscription-toggle" data-id="${escapeHtml(item.id)}" ${item.enabled ? 'checked' : ''}> Enabled</label>
                <button type="button" class="mini-action subscription-refresh" data-id="${escapeHtml(item.id)}" ${item.enabled ? '' : 'disabled'}>Refresh</button>
				<button type="button" class="mini-action subscription-clone" data-id="${escapeHtml(item.id)}">Clone</button>
				${source?.rollback_count ? `<button type="button" class="mini-action subscription-rollback" data-id="${escapeHtml(item.id)}">Rollback</button>` : ''}
                <button type="button" class="mini-action subscription-edit" data-id="${escapeHtml(item.id)}">Edit</button>
                <button type="button" class="mini-action danger subscription-delete" data-id="${escapeHtml(item.id)}">Delete</button>
            </div>
        </div>`;
    }).join('') || emptyState(search ? `No DNS ${prefix}s match the search` : `No DNS ${prefix}s configured`);
}

function resetSubscriptionForm(allowOnly) {
    const prefix = subscriptionPrefix(allowOnly);
    document.getElementById(`${prefix}Form`).reset();
    document.getElementById(`${prefix}ID`).value = '';
    document.getElementById(`${prefix}Enabled`).checked = true;
    document.getElementById(`${prefix}AllowPrivate`).checked = false;
    document.getElementById(`${prefix}Timeout`).value = '30';
    document.getElementById(`${prefix}RedirectLimit`).value = '5';
	document.getElementById(`${prefix}RefreshAt`).value = '';
    showDuplicateURLWarning(allowOnly);
    document.getElementById(`${prefix}SaveBtn`).textContent = `Add ${prefix}`;
	document.getElementById(`${prefix}CancelBtn`).classList.add('is-hidden');
	markFormClean(document.getElementById(`${prefix}Form`));
}

function editSubscription(id) {
    const item = state.subscriptions.find(subscription => subscription.id === id);
    if (!item) return;
    const prefix = subscriptionPrefix(Boolean(item.allow_only));
    document.getElementById(`${prefix}ID`).value = item.id;
    document.getElementById(`${prefix}Name`).value = item.name || '';
    document.getElementById(`${prefix}URL`).value = item.url;
    document.getElementById(`${prefix}Enabled`).checked = Boolean(item.enabled);
    document.getElementById(`${prefix}AllowPrivate`).checked = Boolean(item.allow_private);
    document.getElementById(`${prefix}Timeout`).value = item.timeout_seconds || 30;
    document.getElementById(`${prefix}RedirectLimit`).value = item.redirect_limit || 5;
	document.getElementById(`${prefix}RefreshAt`).value = item.refresh_at_utc || '';
    document.getElementById(`${prefix}SaveBtn`).textContent = `Save ${prefix}`;
    document.getElementById(`${prefix}CancelBtn`).classList.remove('is-hidden');
    showDuplicateURLWarning(Boolean(item.allow_only));
	markFormClean(document.getElementById(`${prefix}Form`));
}

function cloneSubscription(id) {
	const item = state.subscriptions.find(subscription => subscription.id === id);
	if (!item) return;
	editSubscription(id);
	const prefix = subscriptionPrefix(Boolean(item.allow_only));
	document.getElementById(`${prefix}ID`).value = '';
	document.getElementById(`${prefix}Name`).value = `${item.name || 'DNS list'} copy`;
	document.getElementById(`${prefix}SaveBtn`).textContent = `Add ${prefix}`;
	refreshFormDirty(document.getElementById(`${prefix}Form`));
	showDuplicateURLWarning(Boolean(item.allow_only));
	document.getElementById(`${prefix}URL`).focus();
}

function normalizeSubscriptionURL(value) {
	try {
		const parsed = new URL(value);
		parsed.protocol = parsed.protocol.toLowerCase();
		if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return '';
        parsed.hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
        if ((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443')) parsed.port = '';
        parsed.hash = '';
        return parsed.toString();
    } catch { return ''; }
}

function duplicateSubscriptionFor(allowOnly) {
    const prefix = subscriptionPrefix(allowOnly);
    const id = document.getElementById(`${prefix}ID`).value;
    const normalized = normalizeSubscriptionURL(document.getElementById(`${prefix}URL`).value.trim());
    if (!normalized) return null;
    return state.subscriptions.find(item => item.id !== id && normalizeSubscriptionURL(item.url) === normalized) || null;
}

function showDuplicateURLWarning(allowOnly) {
    const prefix = subscriptionPrefix(allowOnly);
    const warning = document.getElementById(`${prefix}URLWarning`);
    const duplicate = duplicateSubscriptionFor(allowOnly);
    warning.hidden = !duplicate;
    warning.textContent = duplicate ? `This URL is already used by “${duplicate.name || duplicate.url}”.` : '';
    return duplicate;
}

async function persistSubscriptions(items) {
	if (!await confirmConfigChange({ subscriptions: items }, 'Save DNS list changes?')) return false;
    const data = await apiJSON('/api/config/subscriptions', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subscriptions: items })
    });
    state.subscriptions = data.subscriptions || [];
    await Promise.all([loadSubscriptions(), loadStatus()]);
	return true;
}

async function saveSubscription(event, allowOnly) {
    event.preventDefault();
	const prefix = subscriptionPrefix(allowOnly);
	const id = document.getElementById(`${prefix}ID`).value;
	if (showDuplicateURLWarning(allowOnly)) throw new Error('A subscription with this URL already exists');
	const item = {
		...(id ? state.subscriptions.find(existing => existing.id === id) : {}),
		id,
        name: document.getElementById(`${prefix}Name`).value.trim(),
        url: document.getElementById(`${prefix}URL`).value.trim(),
        allow_only: allowOnly,
        enabled: document.getElementById(`${prefix}Enabled`).checked,
        allow_private: document.getElementById(`${prefix}AllowPrivate`).checked,
        timeout_seconds: Number(document.getElementById(`${prefix}Timeout`).value),
        redirect_limit: Number(document.getElementById(`${prefix}RedirectLimit`).value),
		refresh_at_utc: document.getElementById(`${prefix}RefreshAt`).value
    };
    const items = id ? state.subscriptions.map(existing => existing.id === id ? item : existing) : [...state.subscriptions, item];
	if (!await persistSubscriptions(items)) return;
	markFormClean(event.target);
    resetSubscriptionForm(allowOnly);
    notice(id ? `${allowOnly ? 'Allowlist' : 'Blocklist'} updated` : `${allowOnly ? 'Allowlist' : 'Blocklist'} added`);
}

async function toggleSubscription(id, enabled) {
    const items = state.subscriptions.map(item => item.id === id ? { ...item, enabled } : item);
	if (!await persistSubscriptions(items)) return;
    notice(`DNS list ${enabled ? 'enabled' : 'disabled'}`);
}

async function deleteSubscription(id) {
	if (await persistSubscriptions(state.subscriptions.filter(item => item.id !== id))) notice('DNS list deleted');
}

async function rollbackSubscription(id) {
	await apiJSON('/api/filtering/rollback', {
		method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id })
	});
	notice('Previous successful DNS list version restored');
	await loadSubscriptions();
}

async function bulkSubscriptionAction(prefix, action) {
	const allowOnly = prefix === 'allowlist';
	const ids = [...state.selectedSubscriptions].filter(id => state.subscriptions.some(item => item.id === id && Boolean(item.allow_only) === allowOnly));
	if (!ids.length) throw new Error(`Select at least one ${prefix}`);
	if (action === 'delete' && !window.confirm(`Delete ${ids.length} selected DNS lists?`)) return;
	await apiJSON('/api/config/subscriptions/bulk', {
		method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, ids })
	});
	ids.forEach(id => state.selectedSubscriptions.delete(id));
	await Promise.all([loadSubscriptions(), loadStatus()]);
	notice(`${ids.length} DNS ${ids.length === 1 ? 'list' : 'lists'} ${action === 'refresh' ? 'scheduled for refresh' : action === 'delete' ? 'deleted' : `${action}d`}`);
}

async function exportSubscriptions() {
	const payload = await apiJSON('/api/config/subscriptions/export');
	const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
	const link = document.createElement('a');
	link.href = URL.createObjectURL(blob);
	link.download = `resolix-subscriptions-${new Date().toISOString().slice(0, 10)}.json`;
	link.click();
	URL.revokeObjectURL(link.href);
}

async function importSubscriptions(file) {
	const parsed = JSON.parse(await file.text());
	if (parsed?.version !== 1 || !Array.isArray(parsed.subscriptions)) throw new Error('Import must be a version 1 subscription document');
	if (!window.confirm(`Replace all subscriptions with ${parsed.subscriptions.length} imported entries?`)) return;
	await apiJSON('/api/config/subscriptions/import', {
		method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsed)
	});
	await Promise.all([loadSubscriptions(), loadStatus()]);
	notice(`${parsed.subscriptions.length} subscriptions imported`);
}

async function requestSubscriptionUpdate(id = '') {
    await apiJSON(`/api/filtering/update${id ? `?id=${encodeURIComponent(id)}` : ''}`, { method: 'POST' });
    notice(id ? 'DNS list update check started' : 'All DNS list update checks started');
    setTimeout(() => loadSubscriptions().catch(error => notice(error.message, true)), 1500);
}

async function loadRules() {
    const data = await apiJSON('/api/config/user-rules');
    document.getElementById('userRules').value = data.rules || '';
    const count = (data.rules || '').split(/\r?\n/).filter(line => line.trim() && !line.trim().startsWith('!') && !line.trim().startsWith('#')).length;
    document.getElementById('ruleCount').textContent = `${count} ${count === 1 ? 'rule' : 'rules'}`;
	markFormClean(document.getElementById('userRulesForm'));
	document.getElementById('ruleDiagnostics').innerHTML = '';
}

function renderRuleDiagnostics(data) {
	const diagnostics = data.diagnostics || [];
	document.getElementById('ruleDiagnostics').innerHTML = diagnostics.length ? diagnostics.map(item => `
		<div class="settings-list-row ${item.severity === 'error' ? 'has-error' : ''}">
			<div class="settings-list-main"><div class="settings-list-title">Line ${escapeHtml(item.line)} · ${escapeHtml(item.severity)}</div><div class="settings-list-meta">${escapeHtml(item.message)}</div></div>
		</div>`).join('') : emptyState(`${data.accepted || 0} active DNS rules validated without diagnostics`);
	return diagnostics.every(item => item.severity !== 'error');
}

async function validateRules() {
	const data = await apiJSON('/api/filtering/validate', {
		method: 'POST', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ rules: document.getElementById('userRules').value })
	});
	const valid = renderRuleDiagnostics(data);
	notice(valid ? `${data.accepted || 0} DNS rules are valid` : 'Custom rules contain invalid syntax', !valid);
	return valid;
}

async function saveRules(event) {
    event.preventDefault();
	if (!await validateRules()) return;
	const rules = document.getElementById('userRules').value;
	if (!await confirmConfigChange({ user_rules: rules }, 'Save custom filter rule changes?')) return;
	await apiJSON('/api/config/user-rules', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ rules })
	});
	markFormClean(event.target);
    notice('Custom filter rules saved and activated');
    await Promise.all([loadRules(), loadStatus()]);
}

async function testFilterDomain(event) {
	event.preventDefault();
	const domain = document.getElementById('filterTestDomain').value.trim();
	const client = document.getElementById('filterTestClient').value.trim();
	const queryType = document.getElementById('filterTestType').value;
	const parameters = new URLSearchParams({ domain, type: queryType });
	if (client) parameters.set('client', client);
	const data = await apiJSON(`/api/filtering/test?${parameters}`);
	const diagnostic = data.diagnostic || {};
	const resultElement = document.getElementById('filterTestResult');
	const clientPolicy = diagnostic.client_name
		? `${diagnostic.client_name}${diagnostic.client_ip ? ` · ${diagnostic.client_ip}` : ''}`
		: diagnostic.client_identifier || 'Global defaults';
	const details = [
		['Question', `${diagnostic.domain || domain} · ${diagnostic.query_type || queryType}`],
		['Client policy', clientPolicy],
		['Matched rule', diagnostic.matched_rule || 'None'],
		['Source', diagnostic.source || 'None']
	];
	resultElement.dataset.decision = diagnostic.decision || 'forwarded';
	resultElement.innerHTML = `
		<div class="filter-diagnostic-summary">
			<span class="filter-decision-mark" aria-hidden="true"></span>
			<div><span class="filter-diagnostic-kicker">Effective decision</span><strong>${escapeHtml(diagnostic.title || 'Policy evaluated')}</strong><p>${escapeHtml(diagnostic.detail || '')}</p></div>
		</div>
		<div class="runtime-grid">${details.map(([key, value]) => `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div>`;
	resultElement.classList.remove('is-hidden');
}

function rewriteValueState() {
    const type = document.getElementById('rewriteType').value;
    const noValue = ['NXDOMAIN', 'REFUSED', 'NOERROR'].includes(type);
    document.getElementById('rewriteValueLabel').hidden = noValue;
    document.getElementById('rewriteValue').required = !noValue;
}

function rewriteScopeState() {
    const tailscaleOnly = document.getElementById('rewriteTailscaleOnly').checked;
    const customCIDRs = document.getElementById('rewriteSourceCIDRs');
    customCIDRs.disabled = !state.editable || tailscaleOnly;
    customCIDRs.closest('label').classList.toggle('is-muted', tailscaleOnly);
}

function rewriteScopeLabel(sourceCIDRs = []) {
    if (sourceCIDRs.length === 0) return 'All clients';
    return isTailscaleRewriteScope(sourceCIDRs) ? 'Tailscale only' : sourceCIDRs.join(', ');
}

function isTailscaleRewriteScope(sourceCIDRs = []) {
    const sorted = [...sourceCIDRs].sort();
    return sorted.length === tailscaleRewriteCIDRs.length &&
        tailscaleRewriteCIDRs.every((cidr, index) => sorted[index] === cidr);
}

function findRewrite(id) {
    return state.rewrites.find(item => item.id === id);
}

function resetRewriteForm() {
	const form = document.getElementById('rewriteForm');
	form.reset();
    state.editingRewrite = null;
    document.getElementById('rewriteSaveBtn').textContent = 'Add rewrite';
    document.getElementById('rewriteCancelBtn').classList.add('is-hidden');
    rewriteValueState();
	rewriteScopeState();
	markFormClean(form);
}

function populateRewriteForm(item, editing) {
    resetRewriteForm();
    state.editingRewrite = editing ? item.id : null;
    document.getElementById('rewriteDomain').value = item.domain || '';
    document.getElementById('rewriteType').value = item.type || 'A';
    document.getElementById('rewriteValue').value = item.value || '';

    const sourceCIDRs = item.source_cidrs || [];
    const tailscaleOnly = isTailscaleRewriteScope(sourceCIDRs);
    document.getElementById('rewriteTailscaleOnly').checked = tailscaleOnly;
    document.getElementById('rewriteSourceCIDRs').value = tailscaleOnly ? '' : sourceCIDRs.join(', ');
    document.getElementById('rewriteSaveBtn').textContent = editing ? 'Save changes' : 'Add cloned rewrite';
    document.getElementById('rewriteCancelBtn').classList.remove('is-hidden');
    rewriteValueState();
    rewriteScopeState();

    const form = document.getElementById('rewriteForm');
	if (editing) markFormClean(form);
	else refreshFormDirty(form);
    form.scrollIntoView({ behavior: 'smooth', block: 'center' });
    document.getElementById('rewriteDomain').focus({ preventScroll: true });
    notice(editing ? `Editing rewrite for ${item.domain}` : `Cloned ${item.domain}; review and add the new rewrite`);
}

function editRewrite(id) {
    const item = findRewrite(id);
    if (!item) {
        notice('Rewrite no longer exists; refresh and try again', true);
        return;
    }
    populateRewriteForm(item, true);
}

function cloneRewrite(id) {
    const item = findRewrite(id);
    if (!item) {
        notice('Rewrite no longer exists; refresh and try again', true);
        return;
    }
    populateRewriteForm(item, false);
}

async function loadRewrites() {
    const data = await apiJSON('/api/rewrites');
    const items = data.rewrites || [];
    state.rewrites = items;
    if (state.editingRewrite && !findRewrite(state.editingRewrite)) resetRewriteForm();
    document.getElementById('rewriteCount').textContent = `${items.length} ${items.length === 1 ? 'rule' : 'rules'}`;
    document.getElementById('rewriteList').innerHTML = items.map(item => `
        <div class="settings-list-row"><div class="settings-list-main">
            <div class="settings-list-title">${escapeHtml(item.domain)}</div>
            <div class="settings-list-meta">${escapeHtml(item.type)}${item.value ? ` → ${escapeHtml(item.value)}` : ''}</div>
            <div class="settings-list-meta">Sources: ${escapeHtml(rewriteScopeLabel(item.source_cidrs || []))}</div>
        </div><div class="row-actions controller-edit">
            <button type="button" class="mini-action rewrite-edit" data-id="${escapeHtml(item.id)}">Edit</button>
            <button type="button" class="mini-action rewrite-clone" data-id="${escapeHtml(item.id)}">Clone</button>
            <button type="button" class="mini-action danger rewrite-delete" data-id="${escapeHtml(item.id)}">Delete</button>
        </div></div>`
    ).join('') || emptyState('No DNS rewrites configured');
    setEditable(state.editable);
}

async function saveRewrite(event) {
    event.preventDefault();
    const domain = document.getElementById('rewriteDomain').value.trim();
    const sourceCIDRs = document.getElementById('rewriteTailscaleOnly').checked
        ? tailscaleRewriteCIDRs
        : splitList(document.getElementById('rewriteSourceCIDRs').value);
    const editingID = state.editingRewrite;
	const draft = {
		...(editingID ? state.rewrites.find(item => item.id === editingID) : {}),
		id: editingID || 'new-rewrite-preview', domain,
		type: document.getElementById('rewriteType').value,
		value: document.getElementById('rewriteValue').value.trim(), source_cidrs: sourceCIDRs
	};
	const rewrites = editingID
		? state.rewrites.map(item => item.id === editingID ? draft : item)
		: [...state.rewrites, draft];
	if (!await confirmConfigChange({ rewrites }, editingID ? 'Save DNS rewrite changes?' : 'Add this DNS rewrite?')) return;
    const path = editingID ? `/api/rewrites?id=${encodeURIComponent(editingID)}` : '/api/rewrites';
    await apiJSON(path, {
        method: editingID ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
            domain, type: document.getElementById('rewriteType').value,
            value: document.getElementById('rewriteValue').value.trim(), source_cidrs: sourceCIDRs
        })
    });
    resetRewriteForm();
    notice(editingID ? `Rewrite updated for ${domain}` : `Rewrite added for ${domain}`);
    await Promise.all([loadRewrites(), loadStatus()]);
}

async function deleteRewrite(id) {
	if (!await confirmConfigChange({ rewrites: state.rewrites.filter(item => item.id !== id) }, 'Delete this DNS rewrite?')) return false;
    await apiJSON(`/api/rewrites?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (state.editingRewrite === id) resetRewriteForm();
    notice('Rewrite deleted');
    await Promise.all([loadRewrites(), loadStatus()]);
	return true;
}

function openRewriteDeleteDialog(id, trigger) {
    const item = findRewrite(id);
    if (!item) {
        notice('Rewrite no longer exists; refresh and try again', true);
        return;
    }
    state.pendingRewriteDelete = id;
    state.rewriteDeleteTrigger = trigger;
    document.getElementById('rewriteDeleteMessage').textContent =
        `Delete ${item.type} rewrite for “${item.domain}”? It will be removed from every synchronized node.`;
    document.getElementById('rewriteDeleteDialog').showModal();
    document.getElementById('rewriteDeleteConfirmBtn').focus();
}

function closeRewriteDeleteDialog(restoreFocus = true) {
    const dialog = document.getElementById('rewriteDeleteDialog');
    const trigger = state.rewriteDeleteTrigger;
    state.pendingRewriteDelete = null;
    state.rewriteDeleteTrigger = null;
    if (dialog.open) dialog.close();
    if (restoreFocus && trigger && trigger.isConnected) trigger.focus();
}

async function confirmRewriteDelete() {
    const id = state.pendingRewriteDelete;
    if (!id) return;
    const button = document.getElementById('rewriteDeleteConfirmBtn');
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Deleting…';
    try {
		const deleted = await deleteRewrite(id);
		if (deleted && state.pendingRewriteDelete === id) closeRewriteDeleteDialog(false);
    } finally {
        button.disabled = false;
        button.textContent = originalText;
    }
}

function setClientPolicyState() {
    const inherit = document.getElementById('clientUseGlobal').checked;
    const fields = document.getElementById('clientPolicyFields');
    fields.classList.toggle('is-muted', inherit);
    fields.querySelectorAll('input').forEach(input => { input.disabled = inherit || !state.editable; });
}

function resetClientForm() {
	const form = document.getElementById('clientForm');
	form.reset(); state.editingClient = null;
    document.getElementById('clientName').readOnly = false;
    document.getElementById('clientUseGlobal').checked = true;
    document.getElementById('clientFiltering').checked = true;
    document.getElementById('clientSaveBtn').textContent = 'Add client';
	document.getElementById('clientCancelBtn').classList.add('is-hidden');
	setClientPolicyState();
	markFormClean(form);
}

function editClient(name) {
    const client = state.clients.find(item => item.name === name);
    if (!client) return;
    state.editingClient = client;
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
	markFormClean(document.getElementById('clientForm'));
}

async function loadClients() {
    const data = await apiJSON('/api/clients'); state.clients = data.clients || [];
    document.getElementById('clientCount').textContent = `${state.clients.length} ${state.clients.length === 1 ? 'client' : 'clients'}`;
    document.getElementById('clientList').innerHTML = state.clients.map(client => `
        <div class="settings-list-row"><div class="settings-list-main">
            <div class="settings-list-title">${escapeHtml(client.name)}</div>
            <div class="settings-list-meta">${escapeHtml((client.ids || []).join(', '))} · ${client.use_global_settings ? 'Global policy' : 'Custom policy'}</div>
        </div><div class="row-actions controller-edit">
            <button type="button" class="mini-action client-edit" data-name="${escapeHtml(client.name)}">Edit</button>
            <button type="button" class="mini-action danger client-delete" data-name="${escapeHtml(client.name)}">Delete</button>
        </div></div>`).join('') || emptyState('No client policies configured');
    setEditable(state.editable);
}

async function saveClient(event) {
    event.preventDefault();
    const inherit = document.getElementById('clientUseGlobal').checked;
    const client = {
        ...(state.editingClient || {}), name: document.getElementById('clientName').value.trim(),
        ids: splitList(document.getElementById('clientIDs').value), use_global_settings: inherit,
        filtering_enabled: inherit || document.getElementById('clientFiltering').checked,
        safe_search_enabled: !inherit && document.getElementById('clientSafeSearch').checked,
        safe_search_engines: inherit ? [] : splitList(document.getElementById('clientSafeEngines').value),
		upstreams: splitList(document.getElementById('clientUpstreams').value),
        exclude_from_log: document.getElementById('clientExcludeLog').checked,
        exclude_from_stats: document.getElementById('clientExcludeStats').checked
    };
	const clients = state.editingClient
		? state.clients.map(item => item.name === client.name ? client : item)
		: [...state.clients, client];
	if (!await confirmConfigChange({ clients }, state.editingClient ? 'Save client policy changes?' : 'Add this client policy?')) return;
	await apiJSON('/api/clients', { method: state.editingClient ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(client) });
	markFormClean(event.target);
    notice(state.editingClient ? 'Client policy updated' : 'Client policy added'); resetClientForm();
    await Promise.all([loadClients(), loadStatus()]);
}

async function deleteClient(name) {
	if (!await confirmConfigChange({ clients: state.clients.filter(item => item.name !== name) }, 'Delete this client policy?')) return;
    await apiJSON(`/api/clients?name=${encodeURIComponent(name)}`, { method: 'DELETE' });
    notice('Client policy deleted'); await Promise.all([loadClients(), loadStatus()]);
}

function formFingerprint(form) {
	if (!form) return '';
	return JSON.stringify([...form.elements].flatMap(control => {
		const key = control.id || control.name;
		if (!key || ['button', 'submit', 'reset', 'file'].includes(control.type)) return [];
		if (control.type === 'checkbox' || control.type === 'radio') return [[key, control.checked]];
		return [[key, control.value]];
	}));
}

function markFormClean(form) {
	if (!form) return;
	form.dataset.cleanFingerprint = formFingerprint(form);
	form.dataset.dirty = 'false';
}

function refreshFormDirty(form) {
	if (!form) return;
	form.dataset.dirty = String(formFingerprint(form) !== (form.dataset.cleanFingerprint || ''));
}

function hasUnsavedChanges(panel = null) {
	const scope = panel || document;
	return Boolean(scope.querySelector('form[data-dirty="true"]'));
}

function confirmDiscardChanges(panel) {
	if (!panel || !hasUnsavedChanges(panel)) return true;
	const title = panel.querySelector('h2')?.textContent?.trim() || 'this panel';
	return window.confirm(`Discard unsaved changes in ${title}?`);
}

const loaders = {
	upstreams: loadUpstreams, routes: loadRoutes, blocklists: loadSubscriptions, allowlists: loadSubscriptions, rules: loadRules,
	rewrites: loadRewrites, clients: loadClients, runtime: loadStatus, cluster: loadCluster
};

async function activatePanel(name, updateHash = true) {
	let loader = loaders.upstreams;
	const validName = Object.hasOwn(loaders, name) && typeof loaders[name] === 'function';
	if (validName) loader = loaders[name];
	else name = 'upstreams';
	const currentPanel = document.querySelector('.settings-panel.active');
	if (currentPanel?.dataset.panel !== name && !confirmDiscardChanges(currentPanel)) return false;
	if (currentPanel?.dataset.panel === name && updateHash) return true;
    document.querySelectorAll('.settings-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.settingsTab === name));
    document.querySelectorAll('.settings-panel').forEach(panel => {
        const active = panel.dataset.panel === name; panel.classList.toggle('active', active); panel.hidden = !active;
    });
	if (updateHash) history.pushState({ panel: name }, '', `#${name}`);
	else if (!validName) history.replaceState({ panel: name }, '', `#${name}`);
	try { await loader(); } catch (error) { notice(error.message, true); }
	return true;
}

document.querySelectorAll('.settings-tab').forEach(tab => tab.addEventListener('click', () => activatePanel(tab.dataset.settingsTab)));
document.getElementById('upstreamForm').addEventListener('submit', event => saveUpstreams(event).catch(error => notice(error.message, true)));
document.getElementById('addStructuredUpstreamBtn').addEventListener('click', () => {
	try { addStructuredUpstream(); } catch (error) { notice(error.message, true); }
});
document.getElementById('testStructuredUpstreamBtn').addEventListener('click', () => {
	try { testUpstream(structuredUpstreamSpec()).catch(error => notice(error.message, true)); } catch (error) { notice(error.message, true); }
});
document.getElementById('testAllUpstreamsBtn').addEventListener('click', () => testAllUpstreams().catch(error => notice(error.message, true)));
document.getElementById('upstreamRuntime').addEventListener('click', event => {
	const button = event.target.closest('.upstream-test');
	if (button) testUpstream(button.dataset.spec).catch(error => notice(error.message, true));
});
document.getElementById('routeForm').addEventListener('submit', event => saveRoute(event).catch(error => notice(error.message, true)));
document.getElementById('routeTestForm').addEventListener('submit', event => testRoute(event).catch(error => notice(error.message, true)));
document.getElementById('blocklistForm').addEventListener('submit', event => saveSubscription(event, false).catch(error => notice(error.message, true)));
document.getElementById('blocklistCancelBtn').addEventListener('click', () => resetSubscriptionForm(false));
document.getElementById('allowlistForm').addEventListener('submit', event => saveSubscription(event, true).catch(error => notice(error.message, true)));
document.getElementById('allowlistCancelBtn').addEventListener('click', () => resetSubscriptionForm(true));
document.getElementById('userRulesForm').addEventListener('submit', event => saveRules(event).catch(error => notice(error.message, true)));
document.getElementById('validateRulesBtn').addEventListener('click', () => validateRules().catch(error => notice(error.message, true)));
document.getElementById('filterTestForm').addEventListener('submit', event => testFilterDomain(event).catch(error => notice(error.message, true)));
document.getElementById('rewriteType').addEventListener('change', rewriteValueState);
document.getElementById('rewriteTailscaleOnly').addEventListener('change', rewriteScopeState);
document.getElementById('rewriteForm').addEventListener('submit', event => saveRewrite(event).catch(error => notice(error.message, true)));
document.getElementById('rewriteCancelBtn').addEventListener('click', resetRewriteForm);
document.getElementById('clientForm').addEventListener('submit', event => saveClient(event).catch(error => notice(error.message, true)));
document.getElementById('clientCancelBtn').addEventListener('click', resetClientForm);
document.getElementById('clientUseGlobal').addEventListener('change', setClientPolicyState);
document.getElementById('dnsSettingsForm').addEventListener('submit', event => saveDNSSettings(event).catch(error => notice(error.message, true)));
document.getElementById('dnsBlockingMode').addEventListener('change', updateDNSBlockingFields);
['blocklistList', 'allowlistList'].forEach(id => document.getElementById(id).addEventListener('click', event => {
	const edit = event.target.closest('.subscription-edit'); const remove = event.target.closest('.subscription-delete');
	const refresh = event.target.closest('.subscription-refresh');
	const clone = event.target.closest('.subscription-clone');
	const rollback = event.target.closest('.subscription-rollback');
	if (edit) editSubscription(edit.dataset.id);
	if (remove) deleteSubscription(remove.dataset.id).catch(error => notice(error.message, true));
	if (refresh) requestSubscriptionUpdate(refresh.dataset.id).catch(error => notice(error.message, true));
	if (clone) cloneSubscription(clone.dataset.id);
	if (rollback) rollbackSubscription(rollback.dataset.id).catch(error => notice(error.message, true));
}));
['blocklistList', 'allowlistList'].forEach(id => document.getElementById(id).addEventListener('change', event => {
	const toggle = event.target.closest('.subscription-toggle');
	const selection = event.target.closest('.subscription-select');
	if (toggle) toggleSubscription(toggle.dataset.id, toggle.checked).catch(error => {
		toggle.checked = !toggle.checked;
		notice(error.message, true);
	});
	if (selection) {
		if (selection.checked) state.selectedSubscriptions.add(selection.dataset.id);
		else state.selectedSubscriptions.delete(selection.dataset.id);
	}
}));
['blocklist', 'allowlist'].forEach(prefix => {
	document.getElementById(`${prefix}URL`).addEventListener('input', () => showDuplicateURLWarning(prefix === 'allowlist'));
	document.getElementById(`${prefix}Search`).addEventListener('input', () => renderSubscriptionPanel(prefix === 'allowlist'));
	document.getElementById(`${prefix}Sort`).addEventListener('change', () => renderSubscriptionPanel(prefix === 'allowlist'));
});
document.getElementById('routeList').addEventListener('click', event => {
    const button = event.target.closest('.route-delete');
    if (button) deleteRoute(button.dataset.pattern).catch(error => notice(error.message, true));
});
document.getElementById('rewriteList').addEventListener('click', event => {
    const edit = event.target.closest('.rewrite-edit');
    const clone = event.target.closest('.rewrite-clone');
    const remove = event.target.closest('.rewrite-delete');
    if (edit) editRewrite(edit.dataset.id);
    if (clone) cloneRewrite(clone.dataset.id);
    if (remove) openRewriteDeleteDialog(remove.dataset.id, remove);
});
document.getElementById('rewriteDeleteCancelBtn').addEventListener('click', () => closeRewriteDeleteDialog());
document.getElementById('rewriteDeleteConfirmBtn').addEventListener('click', () => confirmRewriteDelete().catch(error => notice(error.message, true)));
document.getElementById('rewriteDeleteDialog').addEventListener('cancel', event => {
    event.preventDefault();
    closeRewriteDeleteDialog();
});
document.getElementById('rewriteDeleteDialog').addEventListener('click', event => {
    if (event.target === event.currentTarget) closeRewriteDeleteDialog();
});
document.getElementById('clientList').addEventListener('click', event => {
    const edit = event.target.closest('.client-edit'); const remove = event.target.closest('.client-delete');
    if (edit) editClient(edit.dataset.name);
    if (remove) deleteClient(remove.dataset.name).catch(error => notice(error.message, true));
});
document.getElementById('clearCacheBtn').addEventListener('click', () => apiJSON('/api/cache/clear', { method: 'POST' }).then(() => notice('DNS cache cleared')).catch(error => notice(error.message, true)));
document.getElementById('pause5Btn').addEventListener('click', () => apiJSON('/api/filtering/pause', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"minutes":5}' }).then(() => notice('Filtering paused for 5 minutes')).catch(error => notice(error.message, true)));
document.getElementById('resumeBtn').addEventListener('click', () => apiJSON('/api/filtering/pause', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"minutes":0}' }).then(() => notice('Filtering resumed')).catch(error => notice(error.message, true)));
document.getElementById('refreshBlocklistsBtn').addEventListener('click', () => requestSubscriptionUpdate().catch(error => notice(error.message, true)));
document.getElementById('refreshAllowlistsBtn').addEventListener('click', () => requestSubscriptionUpdate().catch(error => notice(error.message, true)));
document.getElementById('syncAllNodesBtn').addEventListener('click', () => requestConfigSync().catch(error => notice(error.message, true)));
document.getElementById('clusterSummary').addEventListener('click', event => {
	const button = event.target.closest('.sync-node');
	if (button) requestConfigSync(button.dataset.node).catch(error => notice(error.message, true));
});
document.querySelectorAll('.subscription-bulk').forEach(button => button.addEventListener('click', () =>
	bulkSubscriptionAction(button.dataset.prefix, button.dataset.action).catch(error => notice(error.message, true))));
document.getElementById('exportSubscriptionsBtn').addEventListener('click', () => exportSubscriptions().catch(error => notice(error.message, true)));
document.getElementById('importSubscriptionsBtn').addEventListener('click', () => document.getElementById('importSubscriptionsFile').click());
document.getElementById('importSubscriptionsFile').addEventListener('change', event => {
	const [file] = event.target.files;
	if (file) importSubscriptions(file).catch(error => notice(error.message, true));
	event.target.value = '';
});
document.getElementById('refreshSettingsBtn').addEventListener('click', () => Promise.all([loadStatus(), activatePanel((location.hash || '#upstreams').slice(1), false)]).then(() => notice('Configuration refreshed')).catch(error => notice(error.message, true)));

document.querySelectorAll('.settings-panel form.controller-edit').forEach(form => {
	markFormClean(form);
	form.addEventListener('input', () => refreshFormDirty(form));
	form.addEventListener('change', () => refreshFormDirty(form));
});
window.addEventListener('beforeunload', event => {
	if (!hasUnsavedChanges()) return;
	event.preventDefault();
	event.returnValue = '';
});
function activatePanelFromLocation() {
	const requested = (location.hash || '#upstreams').slice(1);
	const target = Object.hasOwn(loaders, requested) && typeof loaders[requested] === 'function' ? requested : 'upstreams';
	if (document.querySelector('.settings-panel.active')?.dataset.panel === target) return;
	activatePanel(requested, false).catch(error => notice(error.message, true));
}
window.addEventListener('popstate', activatePanelFromLocation);
window.addEventListener('hashchange', activatePanelFromLocation);

resetRewriteForm(); resetSubscriptionForm(false); resetSubscriptionForm(true); resetClientForm();
loadStatus().then(() => activatePanel((location.hash || '#upstreams').slice(1), false)).catch(error => notice(error.message, true));
