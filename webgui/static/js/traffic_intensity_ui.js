(function initializeTrafficIntensityUI(root, factory) {
    root.ResolixTrafficIntensityUI = factory(root);
}(typeof globalThis !== 'undefined' ? globalThis : this, function createTrafficIntensityUI(root) {
    'use strict';

    function create(options) {
        const {
            announce,
            escapeHtml,
            formatBucketDuration,
            formatBucketTime,
            formatNumber,
            replaceHTMLIfChanged
        } = options;
        const {
            axisLabelIndexes,
            intensityLevel,
            layoutForRange,
            percentileCeiling,
            queryValue,
            seriesState
        } = root.ResolixTrafficIntensity;
        const document = root.document;
        const element = document.getElementById('trafficHeatmap');
        let activeSeries = [];
        let activeBucketSeconds = 0;

        function numericField(point, field) {
            if (!point || !Object.prototype.hasOwnProperty.call(point, field)) return null;
            if (point[field] === null || point[field] === '') return null;
            const value = Number(point[field]);
            return Number.isFinite(value) && value >= 0 ? value : null;
        }

        function interval(point) {
            const start = Number(point?.start);
            if (!Number.isFinite(start)) return 'Unknown interval';
            const end = start + Math.max(1, Number(activeBucketSeconds) || 1);
            return `${formatBucketTime(start, activeBucketSeconds)}–${formatBucketTime(end, activeBucketSeconds)}`;
        }

        function details(point) {
            const parts = [interval(point)];
            const queries = queryValue(point);
            if (queries === null) {
                parts.push('data unavailable');
                return parts.join(' · ');
            }
            parts.push(`${formatNumber(queries)} queries`);
            const blocked = numericField(point, 'blocked');
            const errors = numericField(point, 'errors');
            if (blocked !== null) parts.push(`${formatNumber(blocked)} blocked`);
            if (errors !== null) parts.push(`${formatNumber(errors)} failed`);
            return parts.join(' · ');
        }

        function renderButton(point, index, ceiling) {
            const queries = queryValue(point);
            const level = intensityLevel(queries, ceiling);
            const stateClass = level === null ? 'is-missing' : `heatmap-level-${level}`;
            return `<button type="button" class="traffic-intensity-cell ${stateClass}" data-intensity-index="${index}" aria-label="${escapeHtml(details(point))}"></button>`;
        }

        function renderWeek(ceiling) {
            const groups = [];
            const slots = new Map();
            activeSeries.forEach((point, index) => {
                const date = new Date(Number(point.start) * 1000);
                const dayKey = `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
                const slotKey = date.getHours() * 60 + date.getMinutes();
                if (!slots.has(slotKey)) {
                    slots.set(slotKey, date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
                }
                let group = groups[groups.length - 1];
                if (!group || group.key !== dayKey) {
                    group = {
                        key: dayKey,
                        label: date.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }),
                        points: new Map()
                    };
                    groups.push(group);
                }
                group.points.set(slotKey, { point, index });
            });

            const orderedSlots = [...slots.entries()].sort((a, b) => a[0] - b[0]);
            const timeAxis = orderedSlots.map(([, label]) => `<span>${escapeHtml(label)}</span>`).join('');
            const rows = groups.map(group => {
                const cells = orderedSlots.map(([slotKey]) => {
                    const item = group.points.get(slotKey);
                    return item
                        ? renderButton(item.point, item.index, ceiling)
                        : '<span class="traffic-intensity-cell is-missing is-gap" aria-hidden="true"></span>';
                }).join('');
                return `<div class="traffic-intensity-week-row"><span class="traffic-intensity-day">${escapeHtml(group.label)}</span><div class="traffic-intensity-week-cells">${cells}</div></div>`;
            }).join('');
            return `<div class="traffic-intensity-week"><div class="traffic-intensity-week-row traffic-intensity-week-times"><span></span><div>${timeAxis}</div></div>${rows}</div>`;
        }

        function renderCalendar(ceiling) {
            const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
                .map(day => `<span>${day}</span>`).join('');
            const firstStart = Number(activeSeries[0]?.start);
            const leadingGaps = Number.isFinite(firstStart) ? new Date(firstStart * 1000).getDay() : 0;
            const gaps = Array.from({ length: leadingGaps }, () => '<span class="traffic-intensity-cell is-missing is-gap" aria-hidden="true"></span>').join('');
            const cells = activeSeries.map((point, index) => renderButton(point, index, ceiling)).join('');
            return `<div class="traffic-intensity-calendar"><div class="traffic-intensity-weekdays" aria-hidden="true">${weekdays}</div><div class="traffic-intensity-calendar-grid">${gaps}${cells}</div></div>`;
        }

        function renderTrafficIntensityAxis(rangeKey) {
            const axis = document.getElementById('trafficIntensityAxis');
            const maximumLabels = ({ '15m': 3, '1h': 3, '6h': 4, '24h': 4, '7d': 4, '30d': 5 })[rangeKey] || 4;
            const indexes = axisLabelIndexes(activeSeries.length, maximumLabels);
            axis.hidden = indexes.length === 0;
            axis.className = `traffic-intensity-axis axis-count-${indexes.length}`;
            replaceHTMLIfChanged(axis, indexes.map(index => {
                const timestamp = Number(activeSeries[index]?.start);
                return `<span>${Number.isFinite(timestamp) ? escapeHtml(formatBucketTime(timestamp, activeBucketSeconds)) : 'Unavailable'}</span>`;
            }).join(''));
        }

        function peak() {
            return activeSeries.reduce((currentPeak, point) => {
                const queries = queryValue(point);
                if (queries === null || queries <= 0 || (currentPeak && queries <= currentPeak.queries)) return currentPeak;
                return { point, queries };
            }, null);
        }

        function resetInspector() {
            const inspector = document.getElementById('trafficIntensityInspect');
            if (!inspector) return;
            inspector.textContent = 'Focus or select a bucket to inspect traffic.';
            document.querySelectorAll('.traffic-intensity-cell.is-inspected').forEach(cell => cell.classList.remove('is-inspected'));
        }

        function inspect(button, shouldAnnounce = false) {
            const point = activeSeries[Number(button?.dataset.intensityIndex)];
            if (!point) return;
            const inspectionDetails = details(point);
            document.getElementById('trafficIntensityInspect').textContent = inspectionDetails;
            document.querySelectorAll('.traffic-intensity-cell').forEach(cell => cell.classList.toggle('is-inspected', cell === button));
            if (shouldAnnounce) announce(inspectionDetails);
        }

        function render(nextSeries, bucketSeconds, rangeKey) {
            activeSeries = Array.isArray(nextSeries) ? nextSeries : [];
            activeBucketSeconds = Number(bucketSeconds) || 0;
            const card = element.closest('.traffic-intensity-card');
            const peakElement = document.getElementById('trafficIntensityPeak');
            const inspector = document.getElementById('trafficIntensityInspect');
            const state = seriesState(activeSeries);
            document.getElementById('trafficIntensityScale').textContent = `${formatBucketDuration(activeBucketSeconds)} · relative scale`;
            card.dataset.state = state;

            if (state === 'empty') {
                card.dataset.layout = 'empty';
                peakElement.textContent = 'No data';
                inspector.textContent = 'No traffic data is available for this window.';
                replaceHTMLIfChanged(element, '<div class="traffic-intensity-empty">No traffic data is available for this window.</div>');
                const axis = document.getElementById('trafficIntensityAxis');
                axis.hidden = true;
                replaceHTMLIfChanged(axis, '');
                return;
            }

            const ceiling = percentileCeiling(activeSeries);
            const layout = layoutForRange(rangeKey, activeBucketSeconds, activeSeries.length);
            const peakBucket = peak();
            const hasUsableData = state !== 'missing';
            card.dataset.layout = layout;
            peakElement.textContent = peakBucket
                ? `Peak ${formatBucketTime(peakBucket.point.start, activeBucketSeconds)} · ${formatNumber(peakBucket.queries)} queries`
                : (hasUsableData ? 'No traffic in window' : 'No usable buckets');
            inspector.textContent = hasUsableData
                ? 'Focus or select a bucket to inspect traffic.'
                : 'Bucket data is unavailable for this window.';

            let html;
            if (layout === 'week') {
                html = renderWeek(ceiling);
            } else if (layout === 'calendar') {
                html = renderCalendar(ceiling);
            } else {
                html = `<div class="traffic-intensity-strip">${activeSeries.map((point, index) => renderButton(point, index, ceiling)).join('')}</div>`;
            }
            replaceHTMLIfChanged(element, html);
            renderTrafficIntensityAxis(rangeKey);
        }

        if (element) {
            element.addEventListener('mouseover', event => {
                const button = event.target.closest('[data-intensity-index]');
                if (button) inspect(button);
            });
            element.addEventListener('focusin', event => {
                const button = event.target.closest('[data-intensity-index]');
                if (button) inspect(button);
            });
            element.addEventListener('click', event => {
                const button = event.target.closest('[data-intensity-index]');
                if (button) inspect(button, true);
            });
            element.addEventListener('keydown', event => {
                if (event.key !== 'Enter' && event.key !== ' ') return;
                const button = event.target.closest('[data-intensity-index]');
                if (button) inspect(button);
            });
            element.addEventListener('mouseleave', () => {
                if (!element.contains(document.activeElement)) resetInspector();
            });
            element.addEventListener('focusout', event => {
                if (!element.contains(event.relatedTarget)) resetInspector();
            });
        }

        return Object.freeze({ render });
    }

    return Object.freeze({ create });
}));
