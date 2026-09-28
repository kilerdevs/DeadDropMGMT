/* Shared map attribution (plain TEXT, not MapLibre's control).
 *
 * Static file (CSP: script-src 'self' covers it, no nonce needed). Used by
 * reveal-map.js (public) and maplibre-picker.js (admin) — one copy instead
 * of two. MapLibre's own control runs source/archive attribution strings
 * through DOM.sanitize(), which CVE-2026-85061 (GHSA-jrc7-96c5-q579, fixed
 * only in the ESM-only 6.x line) can bypass, and zone archives carry
 * upstream metadata. The credit comes from our own style JSON and is set
 * via textContent.
 */
function ddmgmtMapAttribution(box, style) {
    var seen = {};
    var parts = [];
    Object.keys((style && style.sources) || {}).forEach(function (k) {
        var a = style.sources[k] && style.sources[k].attribution;
        if (typeof a === 'string' && a !== '' && !seen[a]) { seen[a] = true; parts.push(a); }
    });
    if (parts.length === 0) return;
    var el = document.createElement('div');
    el.className = 'map-attrib';
    el.textContent = parts.join(' · ');
    box.appendChild(el);
}
