/* Public reveal map (self-hosted provider): vendored MapLibre GL JS rendering
 * the covering ready zones from same-origin PMTiles files — zero third-party
 * contact on the recipient path. Static file (CSP: script-src 'self' covers
 * it, no nonce needed). Configured exclusively through data-* attributes on
 * #reveal-map (server-inlined style JSON, pin coordinates, versioned
 * library URLs):
 *
 *   data-lat / data-lng / data-style / data-lib / data-pmtiles
 *
 * The 1 MB of map libraries loads only when the map scrolls near the
 * viewport (or on tap) — recipients who never look at the map never parse
 * it. Read-only: a marker pins the drop, the recipient may pan/zoom.
 * Anything missing or malformed (no libraries, no style, no sources)
 * renders nothing — the server falls back to the OSM embed in those cases
 * before this runs.
 */
(function () {
    var box = document.getElementById('reveal-map');
    if (!box) return;

    function libsReady() {
        return typeof maplibregl !== 'undefined' && typeof pmtiles !== 'undefined';
    }

    function boot() {
        if (!libsReady()) return;
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

        // Shared credit line (map-attrib.js) — plain text, never MapLibre's
        // control (CVE-2026-85061 via DOM.sanitize()).
        var map = new maplibregl.Map({
            container: box,
            style: style,
            center: [lng, lat],
            zoom: 14,
            attributionControl: false,
        });
        new maplibregl.Marker().setLngLat([lng, lat]).addTo(map);
        if (typeof ddmgmtMapAttribution === 'function') ddmgmtMapAttribution(box, style);
    }

    if (libsReady()) {
        boot();
        return;
    }
    var lib = box.dataset.lib;
    var pt = box.dataset.pmtiles;
    if (!lib || !pt) return;

    var started = false;
    function load(src, done) {
        var s = document.createElement('script');
        s.src = src;
        s.onload = done;
        s.onerror = function () { started = false; };
        document.head.appendChild(s);
    }
    function start() {
        if (started) return;
        started = true;
        load(lib, function () { load(pt, boot); });
    }
    if ('IntersectionObserver' in window) {
        var io = new IntersectionObserver(function (entries) {
            var near = entries.some(function (e) { return e.isIntersecting; });
            if (near) {
                io.disconnect();
                start();
            }
        }, { rootMargin: '200px' });
        io.observe(box);
    }
    box.addEventListener('click', start, { once: true });
})();
