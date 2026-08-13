const test = require('node:test');
const assert = require('node:assert/strict');

const { create } = require('../static/js/dashboard_loader.js');

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, reject, resolve };
}

test('coalesces repeated requests for the active range', async () => {
    const pending = deferred();
    let fetches = 0;
    const loader = create({
        fetchRange: () => { fetches++; return pending.promise; },
        render: () => {}
    });

    const first = loader.load('1h');
    const second = loader.load('1h');
    assert.equal(first, second);
    await Promise.resolve();
    assert.equal(fetches, 1);
    pending.resolve({ range: '1h' });
    await first;
});

test('aborts an obsolete range and ignores its late response', async () => {
    const requests = [];
    const rendered = [];
    const loader = create({
        fetchRange: (range, signal) => {
            const request = deferred();
            requests.push({ range, request, signal });
            return request.promise;
        },
        render: (data, detail) => rendered.push({ data, detail })
    });

    const oldLoad = loader.load('30d');
    await Promise.resolve();
    const currentLoad = loader.load('1h');
    await Promise.resolve();
    assert.equal(requests[0].signal.aborted, true);

    requests[0].request.resolve({ marker: 'obsolete' });
    requests[1].request.resolve({ marker: 'current' });
    await Promise.all([oldLoad, currentLoad]);
    assert.deepEqual(rendered.map(entry => entry.data.marker), ['current']);
});

test('renders a cached range immediately while revalidating it', async () => {
    const requests = [];
    const rendered = [];
    const loading = [];
    const loader = create({
        fetchRange: () => {
            const request = deferred();
            requests.push(request);
            return request.promise;
        },
        render: (data, detail) => rendered.push({ data, detail }),
        setLoading: state => loading.push(state)
    });

    const initial = loader.load('6h');
    await Promise.resolve();
    requests[0].resolve({ marker: 'initial' });
    await initial;

    const refresh = loader.load('6h');
    assert.equal(rendered.at(-1).data.marker, 'initial');
    assert.equal(rendered.at(-1).detail.source, 'cache');
    assert.equal(loading.at(-1).loading, true);
    assert.equal(loading.at(-1).hasCachedData, true);
    await Promise.resolve();
    requests[1].resolve({ marker: 'fresh' });
    await refresh;
    assert.equal(rendered.at(-1).data.marker, 'fresh');
    assert.equal(rendered.at(-1).detail.source, 'network');
});

test('reports active request failures without replacing cached data', async () => {
    const errors = [];
    const rendered = [];
    const loader = create({
        fetchRange: () => Promise.reject(new Error('offline')),
        render: data => rendered.push(data),
        onError: error => errors.push(error.message)
    });

    await loader.load('24h');
    assert.deepEqual(rendered, []);
    assert.deepEqual(errors, ['offline']);
});
