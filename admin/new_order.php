<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

start_secure_session();
require_admin();
$csp_nonce = set_security_headers(true);

$flash    = $_SESSION['flash']    ?? '';
$flash_ok = $_SESSION['flash_ok'] ?? false;
unset($_SESSION['flash'], $_SESSION['flash_ok']);

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.new_order.title') ?></title>
<link rel="stylesheet" href="/admin/vendor/leaflet/leaflet.css">
<link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = 'new_order'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
    <?php require __DIR__ . '/osm_monit.php'; ?>
        <div class="page-heading"><?= t('admin.new_order.title') ?></div>

        <?php if ($flash): ?>
        <div class="flash <?= $flash_ok ? 'ok' : '' ?>"><?= htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <div class="form-panel centered-panel">
            <form method="POST" action="/admin/create.php"
                  enctype="multipart/form-data" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="lat" id="lat" value="">
                <input type="hidden" name="lng" id="lng" value="">

                <div class="form-group">
                    <label for="location">
                        <?= t('admin.new_order.location_label') ?>
                        <span class="hint"><?= t('admin.new_order.location_hint') ?></span>
                    </label>
                    <textarea id="location" name="location" rows="2"
                              placeholder="<?= htmlspecialchars(t('admin.new_order.location_placeholder'), ENT_QUOTES, 'UTF-8') ?>"></textarea>
                </div>

                <div class="form-group map-section">
                    <div class="field-label">
                        <?= t('admin.new_order.pin_label') ?>
                        <span class="hint"><?= t('admin.new_order.pin_hint') ?></span>
                    </div>
                    <div class="map-search-row">
                        <input type="text" id="addr-search"
                               placeholder="<?= htmlspecialchars(t('admin.new_order.addr_search_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="off">
                        <button type="button" class="btn btn-sm" id="addr-btn"><?= t('admin.new_order.search_button') ?></button>
                    </div>
                    <div id="map-picker"></div>
                    <div class="map-coords" id="coords-display"><?= t('admin.new_order.no_pin') ?></div>
                    <div class="map-hint"><?= t('admin.new_order.drag_hint') ?></div>
                </div>

                <div class="form-group">
                    <label for="instructions">
                        <?= t('admin.new_order.instructions_label') ?>
                        <span class="hint"><?= t('admin.new_order.instructions_hint') ?></span>
                    </label>
                    <textarea id="instructions" name="instructions" rows="4"
                              placeholder="<?= htmlspecialchars(t('admin.new_order.instructions_placeholder'), ENT_QUOTES, 'UTF-8') ?>"></textarea>
                </div>

                <div class="form-group">
                    <label for="pickup_password">
                        <?= t('public.index.pw_label') ?>
                        <span class="hint"><?= t('admin.new_order.pw_hint') ?></span>
                    </label>
                    <input type="password" id="pickup_password" name="pickup_password"
                           autocomplete="new-password" placeholder="<?= htmlspecialchars(t('admin.new_order.pw_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
                </div>

                <div class="form-group">
                    <label for="photos">
                        <?= t('public.index.reveal.photos') ?>
                        <span class="hint">JPEG / PNG / WebP / GIF · <?= t('admin.new_order.photos_hint', ['mb' => (int)get_setting('max_photo_mb', '12')]) ?></span>
                    </label>
                    <input type="file" id="photos" name="photos[]" multiple
                           accept="image/jpeg,image/png,image/webp,image/gif">
                </div>

                <div class="form-group">
                    <label for="notes">
                        <?= t('public.index.reveal.notes') ?>
                        <span class="hint"><?= t('admin.new_order.notes_hint') ?></span>
                    </label>
                    <textarea id="notes" name="notes" rows="2" placeholder="<?= htmlspecialchars(t('admin.new_order.notes_placeholder'), ENT_QUOTES, 'UTF-8') ?>"></textarea>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn"><?= t('admin.new_order.submit_button') ?></button>
                </div>
            </form>
        </div>
    </main>
</div>

<script src="/admin/vendor/leaflet/leaflet.js"></script>
<script src="/admin/admin.js"></script>
<script nonce="<?= htmlspecialchars($csp_nonce, ENT_QUOTES, 'UTF-8') ?>">
(function () {
    // Fix self-hosted Leaflet marker icon paths
    delete L.Icon.Default.prototype._getIconUrl;
    L.Icon.Default.mergeOptions({
        iconUrl:       '/admin/vendor/leaflet/images/marker-icon.png',
        iconRetinaUrl: '/admin/vendor/leaflet/images/marker-icon-2x.png',
        shadowUrl:     '/admin/vendor/leaflet/images/marker-shadow.png',
    });

    var map = L.map('map-picker', { zoomControl: true }).setView([52.2297, 21.0122], 12);
    L.tileLayer('/admin/tile_proxy.php?z={z}&x={x}&y={y}', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 19
    }).addTo(map);

    var latInput   = document.getElementById('lat');
    var lngInput   = document.getElementById('lng');
    var coordsDisp = document.getElementById('coords-display');
    var marker     = null;

    function setPin(lat, lng) {
        latInput.value = lat.toFixed(7);
        lngInput.value = lng.toFixed(7);
        coordsDisp.textContent = <?= json_encode(t('admin.new_order.pin_prefix')) ?> + lat.toFixed(6) + ', ' + lng.toFixed(6);
        coordsDisp.className = 'map-pin-ok';
        if (marker) {
            marker.setLatLng([lat, lng]);
        } else {
            marker = L.marker([lat, lng], { draggable: true }).addTo(map);
            marker.on('dragend', function (e) {
                var p = e.target.getLatLng();
                setPin(p.lat, p.lng);
            });
        }
    }

    map.on('click', function (e) { setPin(e.latlng.lat, e.latlng.lng); });

    document.getElementById('addr-btn').addEventListener('click', async function () {
        var q = document.getElementById('addr-search').value.trim();
        if (!q) return;
        this.textContent = '…';
        this.disabled = true;
        try {
            var r = await fetch('/admin/geocode_proxy.php?q=' + encodeURIComponent(q));
            var d = await r.json();
            if (d.length) {
                var lat = parseFloat(d[0].lat), lng = parseFloat(d[0].lon);
                map.setView([lat, lng], 17);
                setPin(lat, lng);
            } else {
                coordsDisp.textContent = <?= json_encode(t('admin.new_order.geocode_not_found')) ?>;
            }
        } catch (err) {
            coordsDisp.textContent = <?= json_encode(t('admin.new_order.geocode_error')) ?>;
        } finally {
            this.textContent = <?= json_encode(t('admin.new_order.search_button')) ?>;
            this.disabled = false;
        }
    });

    document.getElementById('addr-search').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); document.getElementById('addr-btn').click(); }
    });

    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (pos) {
            map.setView([pos.coords.latitude, pos.coords.longitude], 14);
        });
    }
})();
</script>
</body>
</html>
