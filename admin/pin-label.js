/* Pin → "Country, State" label via the proxied Nominatim reverse endpoint.
 *
 * Static file (CSP: script-src 'self' covers it, no nonce needed). Resolves
 * { current, label }: label is '' when the place is unknown, and current is
 * false when a newer pin move superseded this request — only paint when
 * current is true. Callers show a generic placed/draft text for '' and must
 * NEVER fall back to raw coordinates (lat/lng are hidden from owner-facing
 * surfaces by policy).
 */
var ddmgmtPinSeq = 0;
function ddmgmtPinLabel(lat, lng) {
    var mine = ++ddmgmtPinSeq;
    return fetch('/admin/geocode_proxy.php?reverse=1&lat=' + encodeURIComponent(lat) + '&lon=' + encodeURIComponent(lng), { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
            var label = '';
            if (d) {
                var parts = [];
                if (d.country) parts.push(d.country);
                if (d.state) parts.push(d.state);
                label = parts.join(', ');
            }
            return { current: mine === ddmgmtPinSeq, label: label };
        })
        .catch(function () { return { current: mine === ddmgmtPinSeq, label: '' }; });
}
