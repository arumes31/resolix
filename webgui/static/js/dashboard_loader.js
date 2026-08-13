(function initializeDashboardLoader(root, factory) {
    const helpers = factory();
    root.ResolixDashboardLoader = helpers;
    if (typeof module === 'object' && module.exports) module.exports = helpers;
}(typeof globalThis !== 'undefined' ? globalThis : this, function createDashboardLoaderHelpers() {
    'use strict';

    function create(options) {
        if (!options || typeof options.fetchRange !== 'function' || typeof options.render !== 'function') {
            throw new TypeError('Dashboard loader requires fetchRange and render callbacks');
        }

        const cache = new Map();
        let generation = 0;
        let activeRequest = null;

        function load(range) {
            const key = String(range || '').trim();
            if (activeRequest?.range === key) return activeRequest.promise;

            const requestGeneration = ++generation;
            activeRequest?.controller.abort();
            const controller = new AbortController();
            const cached = cache.get(key);
            if (cached) options.render(cached, { range: key, source: 'cache' });
            options.setLoading?.({ loading: true, range: key, hasCachedData: Boolean(cached) });

            const promise = Promise.resolve()
                .then(() => options.fetchRange(key, controller.signal))
                .then(data => {
                    if (requestGeneration !== generation) return undefined;
                    cache.set(key, data);
                    options.render(data, { range: key, source: 'network' });
                    options.setLoading?.({ loading: false, range: key, hasCachedData: Boolean(cached) });
                    options.onSuccess?.(data, { range: key });
                    return data;
                })
                .catch(error => {
                    if (requestGeneration !== generation || error?.name === 'AbortError') return undefined;
                    options.setLoading?.({ loading: false, range: key, hasCachedData: Boolean(cached) });
                    options.onError?.(error, { range: key, hasCachedData: Boolean(cached) });
                    return undefined;
                })
                .finally(() => {
                    if (activeRequest?.generation === requestGeneration) activeRequest = null;
                });

            activeRequest = { controller, generation: requestGeneration, promise, range: key };
            return promise;
        }

        return { load };
    }

    function createView(options = {}) {
        let loadingTimer = null;

        function rangeLabel(range) {
            const rangeSelect = document.getElementById('dashboardRange');
            const option = Array.from(rangeSelect?.options || []).find(candidate => candidate.value === range);
            return option?.textContent?.trim() || range;
        }

        function elements() {
            return {
                content: document.getElementById('dashboardContent'),
                message: document.getElementById('dashboardLoadingMessage'),
                retry: document.getElementById('dashboardRetry'),
                status: document.getElementById('dashboardLoadingStatus')
            };
        }

        function setLoading(state) {
            const { content, message, retry, status } = elements();
            if (!content || !status || !message || !retry) return;

            clearTimeout(loadingTimer);
            loadingTimer = null;
            content.setAttribute('aria-busy', String(Boolean(state.loading)));
            if (!state.loading) {
                content.classList.remove('is-dashboard-loading', 'is-dashboard-initial-loading');
                status.hidden = true;
                status.classList.remove('is-error');
                retry.hidden = true;
                return;
            }

            status.classList.remove('is-error');
            status.hidden = true;
            retry.hidden = true;
            const initialLoad = !options.getCurrentStats?.() && !state.hasCachedData;
            content.classList.toggle('is-dashboard-initial-loading', initialLoad);
            loadingTimer = setTimeout(() => {
                content.classList.add('is-dashboard-loading');
                message.textContent = `${initialLoad ? 'Loading' : 'Updating'} ${rangeLabel(state.range)}…`;
                status.hidden = false;
            }, 150);
        }

        function showError(detail) {
            const { message, retry, status } = elements();
            if (!status || !message || !retry) return;
            const retained = options.getCurrentStats?.()?.range?.label;
            const requested = rangeLabel(detail.range);
            message.textContent = retained
                ? `Could not load ${requested} · still showing ${retained}`
                : `Could not load ${requested}`;
            status.classList.add('is-error');
            status.hidden = false;
            retry.hidden = false;
            options.announce?.('Dashboard update failed');
        }

        return { setLoading, showError };
    }

    return { create, createView };
}));
