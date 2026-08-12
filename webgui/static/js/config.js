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

function integerValue(id, fallback) {
	const value = document.getElementById(id).value.trim();
	if (value === '') return fallback;
	const parsed = Number(value);
	return Number.isInteger(parsed) ? parsed : fallback;
}

function collectDNSSettings() {
	return {
		upstream_mode: document.getElementById('dnsUpstreamMode').value,
		fallback_dns: splitList(document.getElementById('dnsFallbacks').value),
		ecs_client_subnet: document.getElementById('dnsECSSubnet').value.trim(),
		blocking_mode: document.getElementById('dnsBlockingMode').value,
		block_custom_ipv4: document.getElementById('dnsBlockIPv4').value.trim(),
		block_custom_ipv6: document.getElementById('dnsBlockIPv6').value.trim(),
		blocked_response_ttl: integerValue('dnsBlockedTTL', 60),
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
		rate_limit_qps: integerValue('dnsRateLimit', 0),
		internal_rate_limit_qps: integerValue('dnsInternalRateLimit', 0),
		rate_limit_ede: document.getElementById('dnsRateLimitEDE').checked,
		rate_limit_ipv4_prefix: integerValue('dnsRateLimitIPv4Prefix', 32),
		rate_limit_ipv6_prefix: integerValue('dnsRateLimitIPv6Prefix', 128),
		rate_limit_allowlist: splitList(document.getElementById('dnsRateLimitAllowlist').value),
		cache_size: integerValue('dnsCacheSize', 25000),
		cache_min_ttl: integerValue('dnsCacheMinTTL', 60),
		cache_max_ttl: integerValue('dnsCacheMaxTTL', 600),
		cache_optimistic: document.getElementById('dnsCacheOptimistic').checked,
		cache_prefetch: document.getElementById('dnsCachePrefetch').checked,
		cache_prefetch_window_ms: integerValue('dnsCachePrefetchWindow', 30000),
		cache_prefetch_hits: integerValue('dnsCachePrefetchHits', 3),
		cache_servfail_ttl_ms: integerValue('dnsCacheSERVFAIL', 0)
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
