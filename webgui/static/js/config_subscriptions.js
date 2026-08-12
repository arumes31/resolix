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
	if (!await persistSubscriptions(items)) {
		renderSubscriptionPanel(false);
		renderSubscriptionPanel(true);
		return;
	}
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
	const objectURL = URL.createObjectURL(blob);
	link.href = objectURL;
	link.download = `resolix-subscriptions-${new Date().toISOString().slice(0, 10)}.json`;
	link.click();
	setTimeout(() => URL.revokeObjectURL(objectURL), 0);
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

