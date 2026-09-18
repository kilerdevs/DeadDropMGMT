/* Self-hosted map picker (MapLibre GL JS + same-origin PMTiles zones).
 *
 * Static file (CSP: script-src 'self' covers it, no nonce needed). Configured
 * exclusively through data-* attributes on #map-picker, so admin pages carry
 * no inline map code:
 *
 *   data-init-lat / data-init-lng / data-init-zoom / data-has-pin ("1"/"0")
 *   data-geolocate ("1" = center on browser location when available)
 *   data-i18n-pin / data-i18n-locating / data-i18n-placed
 *   data-i18n-not-found / data-i18n-error
 *   data-i18n-load-error / data-i18n-no-zones
 *
 * Requires /admin/pin-label.js first: the pin readout shows the
 * reverse-geocoded place ("Country, State"), never raw coordinates.
 *
 * Pin changes are published as a bubbling 'map-pin' CustomEvent on the
 * container (edit.php autosave listens); initial rendering never fires it.
 * The style comes from /tiles/style.php (admin-gated, server-side zone list).
 */
(function () {
    var box = document.getElementById('map-picker');
    if (!box || typeof maplibregl === 'undefined' || typeof pmtiles === 'undefined') return;

    var latInput   = document.getElementById('lat');
    var lngInput   = document.getElementById('lng');
    var coordsDisp = document.getElementById('coords-display');
    if (!latInput || !lngInput || !coordsDisp) return;

    function num(name, fallback) {
        var v = parseFloat(box.dataset[name]);
        return isFinite(v) ? v : fallback;
    }

    var initLat  = num('initLat', 52.2297);
    var initLng  = num('initLng', 21.0122);
    var initZoom = num('initZoom', 12);
    var hasPin   = box.dataset.hasPin === '1';

    var map = null;
    var marker = null;

    function setPin(lat, lng, silent) {
        latInput.value = lat.toFixed(7);
        lngInput.value = lng.toFixed(7);
        coordsDisp.textContent = box.dataset.i18nLocating || '…';
        if (typeof ddmgmtPinLabel === 'function') {
            ddmgmtPinLabel(lat, lng).then(function (res) {
                if (res.current) coordsDisp.textContent = res.label || box.dataset.i18nPlaced || '';
            });
        }
        if (marker) {
            marker.setLngLat([lng, lat]);
        } else {
            marker = new maplibregl.Marker({ draggable: true })
                .setLngLat([lng, lat])
                .addTo(map);
            marker.on('dragend', function () {
                var p = marker.getLngLat();
                setPin(p.lat, p.lng, false);
            });
        }
        if (!silent) {
            box.dispatchEvent(new CustomEvent('map-pin', { bubbles: true }));
        }
    }

    var protocol = new pmtiles.Protocol();
    maplibregl.addProtocol('pmtiles', protocol.tile);

    fetch('/tiles/style.php', { credentials: 'same-origin' })
        .then(function (r) {
            if (!r.ok) throw new Error('style ' + r.status);
            return r.json();
        })
        .then(function (style) {
            map = new maplibregl.Map({
                container: box,
                style: style,
                center: [initLng, initLat],
                zoom: initZoom,
                attributionControl: { compact: true },
            });
            if (Object.keys(style.sources || {}).length === 0) {
                var overlay = document.createElement('div');
                overlay.className = 'map-empty-overlay';
                overlay.textContent = box.dataset.i18nNoZones;
                box.appendChild(overlay);
            }
            if (hasPin) setPin(initLat, initLng, true);
            map.on('click', function (e) { setPin(e.lngLat.lat, e.lngLat.lng, false); });
            if (box.dataset.geolocate === '1' && navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(function (pos) {
                    map.setCenter([pos.coords.longitude, pos.coords.latitude]);
                    map.setZoom(14);
                });
            }
        })
        .catch(function () {
            coordsDisp.textContent = box.dataset.i18nLoadError;
        });

    var addrBtn = document.getElementById('addr-btn');
    var addrSearch = document.getElementById('addr-search');
    if (addrBtn && addrSearch) {
        addrBtn.addEventListener('click', function () {
            var q = addrSearch.value.trim();
            if (!q || !map) return;
            var label = addrBtn.textContent;
            addrBtn.textContent = '…';
            addrBtn.disabled = true;
            fetch('/admin/geocode_proxy.php?q=' + encodeURIComponent(q), { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d.length) {
                        var lat = parseFloat(d[0].lat), lng = parseFloat(d[0].lon);
                        map.setCenter([lng, lat]);
                        map.setZoom(17);
                        setPin(lat, lng, false);
                    } else {
                        coordsDisp.textContent = box.dataset.i18nNotFound;
                    }
                })
                .catch(function () {
                    coordsDisp.textContent = box.dataset.i18nError;
                })
                .then(function () {
                    addrBtn.textContent = label;
                    addrBtn.disabled = false;
                });
        });
        addrSearch.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); addrBtn.click(); }
        });
    }
})();
