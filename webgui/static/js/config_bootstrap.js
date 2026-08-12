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
	if (currentPanel?.dataset.panel !== name && hasUnsavedChanges(currentPanel)) {
		if (!confirmDiscardChanges(currentPanel)) return false;
		currentPanel.querySelectorAll('form[data-dirty="true"]').forEach(form => restoreCleanForm(form, false));
	}
	if (currentPanel?.dataset.panel === name && updateHash) return true;
    document.querySelectorAll('.settings-tab').forEach(tab => tab.classList.toggle('active', tab.dataset.settingsTab === name));
    document.querySelectorAll('.settings-panel').forEach(panel => {
        const active = panel.dataset.panel === name; panel.classList.toggle('active', active); panel.hidden = !active;
    });
	if (updateHash) history.pushState({ panel: name }, '', `#${name}`);
	else if (!validName) history.replaceState({ panel: name }, '', `#${name}`);
	try { await loader(); } catch (error) { notice(error.message, true); }
	updateConfigDirtyUI();
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
document.getElementById('configSaveBtn')?.addEventListener('click', () => {
	const form = document.getElementById(document.getElementById('configEditBar').dataset.formId);
	if (form) form.requestSubmit();
});
document.getElementById('configRevertBtn')?.addEventListener('click', () => {
	const form = document.getElementById(document.getElementById('configEditBar').dataset.formId);
	if (form) restoreCleanForm(form);
});

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
