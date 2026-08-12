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

function captureFormState(form) {
	return [...form.elements].flatMap(control => {
		const key = control.id || control.name;
		if (!key || ['button', 'submit', 'reset', 'file'].includes(control.type)) return [];
		return [{ key, checked: Boolean(control.checked), value: control.value }];
	});
}

function updateConfigDirtyUI() {
	document.querySelectorAll('.settings-tab').forEach(tab => {
		const panel = document.querySelector(`.settings-panel[data-panel="${tab.dataset.settingsTab}"]`);
		const dirtyCount = panel ? panel.querySelectorAll('form[data-dirty="true"]').length : 0;
		if (!tab.dataset.baseLabel) tab.dataset.baseLabel = tab.textContent.trim();
		tab.dataset.dirtyCount = String(dirtyCount);
		tab.setAttribute('aria-label', dirtyCount ? `${tab.dataset.baseLabel}, unsaved changes` : tab.dataset.baseLabel);
	});

	const bar = document.getElementById('configEditBar');
	if (!bar) return;
	const panel = document.querySelector('.settings-panel.active');
	const form = panel?.querySelector('form.controller-edit[data-dirty="true"]');
	bar.hidden = !form;
	bar.dataset.formId = form?.id || '';
	if (form) document.getElementById('configEditSection').textContent = panel.querySelector('h2')?.textContent?.trim() || 'Configuration changes';
}

function markFormClean(form) {
	if (!form) return;
	configFormSnapshots.set(form, captureFormState(form));
	form.dataset.cleanFingerprint = formFingerprint(form);
	form.dataset.dirty = 'false';
	updateConfigDirtyUI();
}

function refreshFormDirty(form) {
	if (!form) return;
	form.dataset.dirty = String(formFingerprint(form) !== (form.dataset.cleanFingerprint || ''));
	updateConfigDirtyUI();
}

function restoreCleanForm(form, showNotice = true) {
	const snapshot = configFormSnapshots.get(form);
	if (!snapshot) return;
	const controls = new Map([...form.elements].map(control => [control.id || control.name, control]));
	snapshot.forEach(item => {
		const control = controls.get(item.key);
		if (!control) return;
		if (control.type === 'checkbox' || control.type === 'radio') control.checked = item.checked;
		else control.value = item.value;
	});
	if (form.id === 'clientForm') setClientPolicyState();
	if (form.id === 'rewriteForm') { rewriteValueState(); rewriteScopeState(); }
	if (form.id === 'dnsSettingsForm') updateDNSBlockingFields();
	markFormClean(form);
	if (showNotice) notice('Unsaved configuration changes reverted');
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
