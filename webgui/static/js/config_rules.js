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

