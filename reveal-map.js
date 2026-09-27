/* Public reveal map (self-hosted provider): vendored MapLibre GL JS rendering
 * the covering ready zones from same-origin PMTiles files — zero third-party
 * contact on the recipient path. Static file (CSP: script-src 'self' covers
 * it, no nonce needed). Configured exclusively through data-* attributes on
 * #reveal-map (server-inlined style JSON, pin coordinates):
 *
 *   data-lat / data-lng / data-style
 *
 * Read-only: a marker pins the drop, the recipient may pan/zoom. Anything
 * missing or malformed (no libraries, no style, no sources) renders nothing —
 * the server falls back to the OSM embed in those cases before this runs.
 */
(function () {
    var box = document.getElementById('reveal-map');
    if (!box || typeof maplibregl === 'undefined' || typeof pmtiles === 'undefined') return;

    var lat = parseFloat(box.dataset.lat);
    var lng = parseFloat(box.dataset.lng);
    if (!isFinite(lat) || !isFinite(lng)) return;

    var style = null;
    try {
        style = JSON.parse(box.dataset.style || 'null');
    } catch (e) {
        return;
    }
    if (!style || !style.sources || Object.keys(style.sources).length === 0) return;

    var protocol = new pmtiles.Protocol();
    maplibregl.addProtocol('pmtiles', protocol.tile);

    // Attribution as plain TEXT instead of MapLibre's control: that control runs
    // source/archive attribution strings through DOM.sanitize(), which
    // CVE-2026-85061 (GHSA-jrc7-96c5-q579, fixed only in the ESM-only 6.x line)
    // can bypass, and zone archives carry upstream metadata. The credit comes from
    // our own style JSON and is set via textContent.
    function addTextAttribution(box, style) {
        var seen = {};
        var parts = [];
        Object.keys(style.sources || {}).forEach(function (k) {
            var a = style.sources[k] && style.sources[k].attribution;
            if (typeof a === 'string' && a !== '' && !seen[a]) { seen[a] = true; parts.push(a); }
        });
        if (parts.length === 0) return;
        var el = document.createElement('div');
        el.className = 'map-attrib';
        el.textContent = parts.join(' · ');
        box.appendChild(el);
    }

    var map = new maplibregl.Map({
        container: box,
        style: style,
        center: [lng, lat],
        zoom: 14,
        attributionControl: false, // see addTextAttribution
    });
    new maplibregl.Marker().setLngLat([lng, lat]).addTo(map);
    addTextAttribution(box, style);
})();
