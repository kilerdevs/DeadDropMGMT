/* Pin → "Country, State" label via the proxied Nominatim reverse endpoint.
 *
 * Static file (CSP: script-src 'self' covers it, no nonce needed). Resolves
 * { current, label }: label is '' when the place is unknown, and current is
 * false when a newer pin move superseded this request — only paint when
 * current is true. Callers show a generic placed/draft text for '' and must
 * NEVER fall back to raw coordinates (lat/lng are hidden from owner-facing
 * surfaces by policy).
 *
 * Two client-side savings on top of the server's per-account label cache:
 * coordinates are rounded to 0.01° before sending (a "country, state" label
 * needs ~1 km, and rounding keeps exact drops out of access logs), repeated
 * asks for the same cell answer from an in-memory cache, and a new move
 * aborts the previous request instead of letting slow responses pile up.
 */
var ddmgmtPinSeq = 0;
var ddmgmtPinCache = {};
var ddmgmtPinAbort = null;
function ddmgmtPinLabel(lat, lng) {
    var mine = ++ddmgmtPinSeq;
    var key = (Math.round(lat * 100) / 100).toFixed(2) + ',' + (Math.round(lng * 100) / 100).toFixed(2);
    if (Object.prototype.hasOwnProperty.call(ddmgmtPinCache, key)) {
        return Promise.resolve({ current: mine === ddmgmtPinSeq, label: ddmgmtPinCache[key] });
    }
    if (ddmgmtPinAbort) {
        try { ddmgmtPinAbort.abort(); } catch (e) { /* superseded — ignore */ }
    }
    var ctrl = ('AbortController' in window) ? new AbortController() : null;
    ddmgmtPinAbort = ctrl;
    return fetch('/admin/geocode_proxy.php?reverse=1&lat=' + encodeURIComponent(key.split(',')[0]) + '&lon=' + encodeURIComponent(key.split(',')[1]),
        { credentials: 'same-origin', signal: ctrl ? ctrl.signal : undefined })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
            var label = '';
            if (d) {
                var parts = [];
                if (d.country) parts.push(d.country);
                if (d.state) parts.push(d.state);
                label = parts.join(', ');
            }
            ddmgmtPinCache[key] = label;
            return { current: mine === ddmgmtPinSeq, label: label };
        })
        .catch(function (e) {
            if (e && e.name === 'AbortError') {
                return { current: false, label: '' };
            }
            return { current: mine === ddmgmtPinSeq, label: '' };
        });
}
