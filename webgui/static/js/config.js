const apiBase = (document.body.dataset.baseUrl || '/').replace(/\/$/, '');
const state = {
    editable: false,
    mode: '',
    revision: '',
	routes: {},
	subscriptions: [],
	rewrites: [],
	clients: [],
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
}

function formatRuntimeKey(key) {
    return key.split('_').map(word => word.toUpperCase()).join(' ');
}

function runtimeValue(value) {
    if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled';
    if (value === '' || value === null || value === undefined) return 'Not configured';
    return String(value);
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
        ['Snapshot contents', 'Upstreams, bootstrap resolvers, routes, blocklists, allowlists, rules, rewrites, clients']
    ].map(([key, value]) => `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
    document.getElementById('runtimeSettings').innerHTML = Object.entries(data.runtime || {}).map(([key, value]) =>
        `<div class="runtime-item"><span>${escapeHtml(formatRuntimeKey(key))}</span><strong>${escapeHtml(runtimeValue(value))}</strong></div>`
    ).join('');
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
        ['Snapshot contents', 'Upstreams, bootstrap resolvers, routes, blocklists, allowlists, rules, rewrites, clients']
    ];
    nodes.forEach(node => summary.push([
        node.name || 'Unnamed node',
        node.config_revision
            ? `${node.config_revision.slice(0, 12)}${node.config_revision === state.revision ? ' · current' : ' · pending/drifted'}`
            : 'No configuration revision reported'
    ]));
    document.getElementById('clusterSummary').innerHTML = summary.map(([key, value]) =>
        `<div class="runtime-item"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`
    ).join('');
}

async function loadUpstreams() {
    const data = await apiJSON('/api/upstream-settings');
    const upstreams = data.upstreams || [];
    document.getElementById('upstreamList').value = upstreams.join('\n');
    document.getElementById('bootstrapList').value = (data.bootstrap_servers || []).join('\n');
    document.getElementById('upstreamCount').textContent = `${upstreams.length} ${upstreams.length === 1 ? 'server' : 'servers'}`;
}

async function saveUpstreams(event) {
    event.preventDefault();
    const upstreams = document.getElementById('upstreamList').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    const bootstrapServers = document.getElementById('bootstrapList').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
    if (!upstreams.length) throw new Error('At least one upstream resolver is required');
    await apiJSON('/api/upstream-settings', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ upstreams, bootstrap_servers: bootstrapServers })
    });
    notice('Upstream and bootstrap resolvers saved and activated');
    await Promise.all([loadUpstreams(), loadStatus()]);
}

async function loadRoutes() {
    const data = await apiJSON('/api/dns/routes');
    state.routes = data.routes || {};
    const entries = Object.entries(state.routes).sort(([left], [right]) => left.localeCompare(right));
    document.getElementById('routeCount').textContent = `${entries.length} ${entries.length === 1 ? 'route' : 'routes'}`;
    document.getElementById('routeList').innerHTML = entries.map(([pattern, resolver]) => `
        <div class="settings-list-row"><div class="settings-list-main">
            <div class="settings-list-title">${escapeHtml(pattern)}</div>
            <div class="settings-list-meta">${escapeHtml(resolver)}</div>
        </div><div class="row-actions controller-edit"><button type="button" class="mini-action danger route-delete" data-pattern="${escapeHtml(pattern)}">Delete</button></div></div>`
    ).join('') || emptyState('No domain-specific routes configured');
    setEditable(state.editable);
}

async function persistRoutes(routes) {
    await apiJSON('/api/dns/routes', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(routes)
    });
    await Promise.all([loadRoutes(), loadStatus()]);
}

async function saveRoute(event) {
    event.preventDefault();
    const pattern = document.getElementById('routePattern').value.trim();
    const resolver = document.getElementById('routeUpstream').value.trim();
    await persistRoutes({ ...state.routes, [pattern]: resolver });
    event.target.reset(); notice(`DNS route saved for ${pattern}`);
}

async function deleteRoute(pattern) {
    const routes = { ...state.routes }; delete routes[pattern];
    await persistRoutes(routes); notice('DNS route deleted');
}

async function loadSubscriptions() {
    const [data, filterStatus] = await Promise.all([
        apiJSON('/api/config/subscriptions'),
        apiJSON('/api/filtering/status')
    ]);
    state.subscriptions = data.subscriptions || [];
    const sourceByID = new Map((filterStatus.sources || []).map(source => [source.id, source]));
    renderSubscriptionPanel(false, sourceByID);
    renderSubscriptionPanel(true, sourceByID);
    setEditable(state.editable);
}

function subscriptionPrefix(allowOnly) {
    return allowOnly ? 'allowlist' : 'blocklist';
}

function subscriptionStatus(source, allowOnly) {
    if (!source) return 'Awaiting first update';
    if (source.last_error) return `Error · ${source.last_error}`;
    const count = allowOnly ? source.allow_rule_count || 0 : source.rule_count || 0;
    const label = `${count} ${count === 1 ? 'domain' : 'domains'}`;
    if (!source.last_update || source.last_update.startsWith('0001-')) return label;
    return `${label} · updated ${new Date(source.last_update).toLocaleString()}`;
}

function renderSubscriptionPanel(allowOnly, sourceByID) {
    const prefix = subscriptionPrefix(allowOnly);
    const items = state.subscriptions.filter(item => Boolean(item.allow_only) === allowOnly);
    document.getElementById(`${prefix}Count`).textContent = `${items.length} ${items.length === 1 ? 'list' : 'lists'}`;
    document.getElementById(`${prefix}List`).innerHTML = items.map(item => {
        const source = sourceByID.get(item.id);
        const sourceState = subscriptionStatus(source, allowOnly);
        return `
        <div class="settings-list-row ${item.enabled ? '' : 'is-muted'}">
            <div class="settings-list-main">
                <div class="settings-list-title">${escapeHtml(item.name || item.url)}</div>
                <div class="settings-list-meta">${item.enabled ? 'Enabled' : 'Disabled'} · ${escapeHtml(sourceState)} · ${escapeHtml(item.url)}</div>
            </div>
            <div class="row-actions controller-edit">
                <button type="button" class="mini-action subscription-edit" data-id="${escapeHtml(item.id)}">Edit</button>
                <button type="button" class="mini-action danger subscription-delete" data-id="${escapeHtml(item.id)}">Delete</button>
            </div>
        </div>`;
    }).join('') || emptyState(`No DNS ${prefix}s configured`);
}

function resetSubscriptionForm(allowOnly) {
    const prefix = subscriptionPrefix(allowOnly);
    document.getElementById(`${prefix}Form`).reset();
    document.getElementById(`${prefix}ID`).value = '';
    document.getElementById(`${prefix}Enabled`).checked = true;
    document.getElementById(`${prefix}SaveBtn`).textContent = `Add ${prefix}`;
    document.getElementById(`${prefix}CancelBtn`).classList.add('is-hidden');
}

function editSubscription(id) {
    const item = state.subscriptions.find(subscription => subscription.id === id);
    if (!item) return;
    const prefix = subscriptionPrefix(Boolean(item.allow_only));
    document.getElementById(`${prefix}ID`).value = item.id;
    document.getElementById(`${prefix}Name`).value = item.name || '';
    document.getElementById(`${prefix}URL`).value = item.url;
    document.getElementById(`${prefix}Enabled`).checked = Boolean(item.enabled);
    document.getElementById(`${prefix}SaveBtn`).textContent = `Save ${prefix}`;
    document.getElementById(`${prefix}CancelBtn`).classList.remove('is-hidden');
}

async function persistSubscriptions(items) {
    const data = await apiJSON('/api/config/subscriptions', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subscriptions: items })
    });
    state.subscriptions = data.subscriptions || [];
    await Promise.all([loadSubscriptions(), loadStatus()]);
}

async function saveSubscription(event, allowOnly) {
    event.preventDefault();
    const prefix = subscriptionPrefix(allowOnly);
    const id = document.getElementById(`${prefix}ID`).value;
    const item = {
        id,
        name: document.getElementById(`${prefix}Name`).value.trim(),
        url: document.getElementById(`${prefix}URL`).value.trim(),
        allow_only: allowOnly,
        enabled: document.getElementById(`${prefix}Enabled`).checked
    };
    const items = id ? state.subscriptions.map(existing => existing.id === id ? item : existing) : [...state.subscriptions, item];
    await persistSubscriptions(items);
    resetSubscriptionForm(allowOnly);
    notice(id ? `${allowOnly ? 'Allowlist' : 'Blocklist'} updated` : `${allowOnly ? 'Allowlist' : 'Blocklist'} added`);
}

async function deleteSubscription(id) {
    await persistSubscriptions(state.subscriptions.filter(item => item.id !== id));
    notice('DNS list deleted');
}

async function requestSubscriptionUpdate() {
    await apiJSON('/api/filtering/update', { method: 'POST' });
    notice('DNS list update check started');
    setTimeout(() => loadSubscriptions().catch(error => notice(error.message, true)), 1500);
}

async function loadRules() {
    const data = await apiJSON('/api/config/user-rules');
    document.getElementById('userRules').value = data.rules || '';
    const count = (data.rules || '').split(/\r?\n/).filter(line => line.trim() && !line.trim().startsWith('!') && !line.trim().startsWith('#')).length;
    document.getElementById('ruleCount').textContent = `${count} ${count === 1 ? 'rule' : 'rules'}`;
}

async function saveRules(event) {
    event.preventDefault();
    await apiJSON('/api/config/user-rules', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: document.getElementById('userRules').value })
    });
    notice('Custom filter rules saved and activated');
    await Promise.all([loadRules(), loadStatus()]);
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
    document.getElementById('rewriteForm').reset();
    state.editingRewrite = null;
    document.getElementById('rewriteSaveBtn').textContent = 'Add rewrite';
    document.getElementById('rewriteCancelBtn').classList.add('is-hidden');
    rewriteValueState();
    rewriteScopeState();
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
    await apiJSON(`/api/rewrites?id=${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (state.editingRewrite === id) resetRewriteForm();
    notice('Rewrite deleted');
    await Promise.all([loadRewrites(), loadStatus()]);
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
        await deleteRewrite(id);
        if (state.pendingRewriteDelete === id) closeRewriteDeleteDialog(false);
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
    document.getElementById('clientForm').reset(); state.editingClient = null;
    document.getElementById('clientName').readOnly = false;
    document.getElementById('clientUseGlobal').checked = true;
    document.getElementById('clientFiltering').checked = true;
    document.getElementById('clientSaveBtn').textContent = 'Add client';
    document.getElementById('clientCancelBtn').classList.add('is-hidden');
	setClientPolicyState();
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
    await apiJSON('/api/clients', { method: state.editingClient ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(client) });
    notice(state.editingClient ? 'Client policy updated' : 'Client policy added'); resetClientForm();
    await Promise.all([loadClients(), loadStatus()]);
}

async function deleteClient(name) {
    await apiJSON(`/api/clients?name=${encodeURIComponent(name)}`, { method: 'DELETE' });
    notice('Client policy deleted'); await Promise.all([loadClients(), loadStatus()]);
}

const loaders = {
	upstreams: loadUpstreams, routes: loadRoutes, blocklists: loadSubscriptions, allowlists: loadSubscriptions, rules: loadRules,
	rewrites: loadRewrites, clients: loadClients, runtime: loadStatus, cluster: loadCluster
};

async function activatePanel(name, updateHash = true) {
    let loader = loaders.upstreams;
    if (Object.hasOwn(loaders, name) && typeof loaders[name] === 'function') loader = loaders[name];
    else name = 'upstreams';
    document.querySelectorAll('.settings-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.settingsTab === name));
    document.querySelectorAll('.settings-panel').forEach(panel => {
        const active = panel.dataset.panel === name; panel.classList.toggle('active', active); panel.hidden = !active;
    });
    if (updateHash) history.replaceState(null, '', `#${name}`);
    try { await loader(); } catch (error) { notice(error.message, true); }
}

document.querySelectorAll('.settings-tab').forEach(tab => tab.addEventListener('click', () => activatePanel(tab.dataset.settingsTab)));
document.getElementById('upstreamForm').addEventListener('submit', event => saveUpstreams(event).catch(error => notice(error.message, true)));
document.getElementById('routeForm').addEventListener('submit', event => saveRoute(event).catch(error => notice(error.message, true)));
document.getElementById('blocklistForm').addEventListener('submit', event => saveSubscription(event, false).catch(error => notice(error.message, true)));
document.getElementById('blocklistCancelBtn').addEventListener('click', () => resetSubscriptionForm(false));
document.getElementById('allowlistForm').addEventListener('submit', event => saveSubscription(event, true).catch(error => notice(error.message, true)));
document.getElementById('allowlistCancelBtn').addEventListener('click', () => resetSubscriptionForm(true));
document.getElementById('userRulesForm').addEventListener('submit', event => saveRules(event).catch(error => notice(error.message, true)));
document.getElementById('rewriteType').addEventListener('change', rewriteValueState);
document.getElementById('rewriteTailscaleOnly').addEventListener('change', rewriteScopeState);
document.getElementById('rewriteForm').addEventListener('submit', event => saveRewrite(event).catch(error => notice(error.message, true)));
document.getElementById('rewriteCancelBtn').addEventListener('click', resetRewriteForm);
document.getElementById('clientForm').addEventListener('submit', event => saveClient(event).catch(error => notice(error.message, true)));
document.getElementById('clientCancelBtn').addEventListener('click', resetClientForm);
document.getElementById('clientUseGlobal').addEventListener('change', setClientPolicyState);
['blocklistList', 'allowlistList'].forEach(id => document.getElementById(id).addEventListener('click', event => {
    const edit = event.target.closest('.subscription-edit'); const remove = event.target.closest('.subscription-delete');
    if (edit) editSubscription(edit.dataset.id);
    if (remove) deleteSubscription(remove.dataset.id).catch(error => notice(error.message, true));
}));
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
document.getElementById('refreshSettingsBtn').addEventListener('click', () => Promise.all([loadStatus(), activatePanel((location.hash || '#upstreams').slice(1), false)]).then(() => notice('Configuration refreshed')).catch(error => notice(error.message, true)));

resetRewriteForm(); resetSubscriptionForm(false); resetSubscriptionForm(true); resetClientForm();
loadStatus().then(() => activatePanel((location.hash || '#upstreams').slice(1), false)).catch(error => notice(error.message, true));
