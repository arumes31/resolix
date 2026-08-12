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

