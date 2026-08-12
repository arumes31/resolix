const test = require('node:test');
const assert = require('node:assert/strict');

const {
    axisLabelIndexes,
    intensityLevel,
    layoutForRange,
    percentileCeiling,
    queryValue,
    seriesState
} = require('../static/js/traffic_intensity.js');

test('distinguishes missing values from valid zero traffic', () => {
    assert.equal(queryValue({}), null);
    assert.equal(queryValue({ queries: null }), null);
    assert.equal(queryValue({ queries: 0 }), 0);
    assert.equal(intensityLevel(null, 1), null);
    assert.equal(intensityLevel(0, 1), 0);
});

test('uses the 95th percentile and square-root scaling to resist spikes', () => {
    const series = Array.from({ length: 19 }, (_, index) => ({ queries: index + 1 }));
    series.push({ queries: 10000 });

    const ceiling = percentileCeiling(series);
    assert.equal(ceiling, 19);
    assert.equal(intensityLevel(1, ceiling), 3);
    assert.equal(intensityLevel(19, ceiling), 10);
    assert.equal(intensityLevel(10000, ceiling), 10);
});

test('handles empty and all-zero series safely', () => {
    assert.equal(percentileCeiling([]), 1);
    assert.equal(percentileCeiling([{ queries: 0 }, { queries: 0 }]), 1);
    assert.equal(seriesState([]), 'empty');
    assert.equal(seriesState([{}, { queries: null }]), 'missing');
    assert.equal(seriesState([{ queries: 0 }, { queries: 0 }]), 'zero');
    assert.equal(seriesState([{ queries: 0 }, { queries: 4 }]), 'traffic');
});

test('selects a limited set of axis labels including both edges', () => {
    assert.deepEqual(axisLabelIndexes(0, 3), []);
    assert.deepEqual(axisLabelIndexes(3, 4), [0, 1, 2]);
    assert.deepEqual(axisLabelIndexes(15, 3), [0, 7, 14]);
    assert.deepEqual(axisLabelIndexes(24, 4), [0, 8, 15, 23]);
});

test('adapts layout to the available long-range bucket resolution', () => {
    assert.equal(layoutForRange('15m', 60, 15), 'strip');
    assert.equal(layoutForRange('1h', 300, 12), 'strip');
    assert.equal(layoutForRange('24h', 3600, 24), 'strip');
    assert.equal(layoutForRange('7d', 21600, 28), 'week');
    assert.equal(layoutForRange('30d', 86400, 30), 'calendar');
    assert.equal(layoutForRange('7d', 86400, 7), 'strip');
});
