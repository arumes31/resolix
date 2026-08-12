(function initializeTrafficIntensity(root, factory) {
    const helpers = factory();
    root.ResolixTrafficIntensity = helpers;
    if (typeof module === 'object' && module.exports) module.exports = helpers;
}(typeof globalThis !== 'undefined' ? globalThis : this, function createTrafficIntensityHelpers() {
    'use strict';

    function queryValue(point) {
        if (!point || !Object.prototype.hasOwnProperty.call(point, 'queries')) return null;
        if (point.queries === null || point.queries === '') return null;
        const value = Number(point.queries);
        return Number.isFinite(value) && value >= 0 ? value : null;
    }

    function percentileCeiling(series) {
        // A percentile ceiling prevents one exceptional bucket from flattening the rest.
        const values = (series || [])
            .map(queryValue)
            .filter(value => value !== null && value > 0)
            .sort((a, b) => a - b);
        const p95Index = Math.max(0, Math.ceil(values.length * 0.95) - 1);
        return values[p95Index] || 1;
    }

    function intensityLevel(value, ceiling) {
        if (value === null || !Number.isFinite(Number(value)) || Number(value) < 0) return null;
        if (Number(value) === 0) return 0;
        const safeCeiling = Math.max(1, Number(ceiling) || 1);
        // Square-root scaling preserves visible differences among lower-volume buckets.
        return Math.max(1, Math.min(10, Math.ceil(Math.sqrt(Number(value) / safeCeiling) * 10)));
    }

    function seriesState(series) {
        if (!Array.isArray(series) || series.length === 0) return 'empty';
        const values = series.map(queryValue);
        if (values.every(value => value === null)) return 'missing';
        if (values.some(value => value > 0)) return 'traffic';
        return 'zero';
    }

    function axisLabelIndexes(length, maximumLabels) {
        const total = Math.max(0, Math.floor(Number(length) || 0));
        const limit = Math.max(1, Math.floor(Number(maximumLabels) || 1));
        if (total === 0) return [];
        if (total <= limit) return Array.from({ length: total }, (_, index) => index);
        if (limit === 1) return [0];

        const indexes = [];
        for (let index = 0; index < limit; index++) {
            indexes.push(Math.round(index * (total - 1) / (limit - 1)));
        }
        return [...new Set(indexes)];
    }

    function layoutForRange(rangeKey, bucketSeconds, pointCount) {
        const seconds = Number(bucketSeconds) || 0;
        const count = Number(pointCount) || 0;
        if (rangeKey === '7d' && seconds > 0 && seconds <= 21600 && count >= 14) return 'week';
        if (rangeKey === '30d' && seconds >= 86400 && count >= 14) return 'calendar';
        return 'strip';
    }

    return Object.freeze({
        axisLabelIndexes,
        intensityLevel,
        layoutForRange,
        percentileCeiling,
        queryValue,
        seriesState
    });
}));
