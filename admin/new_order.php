<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

start_secure_session();
require_admin();
$csp_nonce = set_security_headers(true);

$flash    = $_SESSION['flash']    ?? '';
$flash_ok = $_SESSION['flash_ok'] ?? false;
unset($_SESSION['flash'], $_SESSION['flash_ok']);

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Nowe zamówienie</title>
<meta name="dd-ttl" content="<?= (int)order_ttl_hours() ?>"><link rel="stylesheet" href="/admin/vendor/leaflet/leaflet.css">
<link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = 'new_order'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading">Nowe zamówienie</div>

        <?php if ($flash): ?>
        <div class="flash <?= $flash_ok ? 'ok' : '' ?>"><?= htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <div class="form-panel">
            <form method="POST" action="/admin/create.php"
                  enctype="multipart/form-data" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="lat" id="lat" value="">
                <input type="hidden" name="lng" id="lng" value="">

                <div class="form-group">
                    <label for="location">
                        Opis lokalizacji
                        <span class="hint">szyfrowane po stronie serwera</span>
                    </label>
                    <textarea id="location" name="location" rows="2"
                              placeholder="np. Pod ławką przy wschodnim wejściu do Parku Rynek"></textarea>
                </div>

                <div class="form-group map-section">
                    <div class="field-label">
                        Pinezka na mapie
                        <span class="hint">opcjonalne — kliknij mapę lub wyszukaj adres</span>
                    </div>
                    <div class="map-search-row">
                        <input type="text" id="addr-search"
                               placeholder="Szukaj adresu lub miejsca..." autocomplete="off">
                        <button type="button" class="btn btn-sm" id="addr-btn">Szukaj</button>
                    </div>
                    <div id="map-picker"></div>
                    <div class="map-coords" id="coords-display">Brak pinezki — kliknij mapę, aby ją ustawić.</div>
                    <div class="map-hint">Możesz przeciągnąć pinezkę po jej umieszczeniu.</div>
                </div>

                <div class="form-group">
                    <label for="instructions">
                        Instrukcje odbioru
                        <span class="hint">opcjonalne — szyfrowane</span>
                    </label>
                    <textarea id="instructions" name="instructions" rows="4"
                              placeholder="Krok 1: Wejdź od strony północnej&#10;Krok 2: Idź 20m do fontanny&#10;Krok 3: Sprawdź pod ławką"></textarea>
                </div>

                <div class="form-group">
                    <label for="pickup_password">
                        Hasło odbioru
                        <span class="hint">zostaw puste — zostanie wygenerowane automatycznie</span>
                    </label>
                    <input type="password" id="pickup_password" name="pickup_password"
                           autocomplete="new-password" placeholder="Pozostaw puste dla auto-generacji">
                </div>

                <div class="form-group">
                    <label for="photos">
                        Zdjęcia referencyjne
                        <span class="hint">JPEG / PNG / WebP / GIF · maks. <?= (int)get_setting('max_photo_mb', '12') ?> MB</span>
                    </label>
                    <input type="file" id="photos" name="photos[]" multiple
                           accept="image/jpeg,image/png,image/webp,image/gif">
                </div>

                <div class="form-group">
                    <label for="notes">
                        Notatki
                        <span class="hint">widoczne dla klienta</span>
                    </label>
                    <textarea id="notes" name="notes" rows="2" placeholder="Opcjonalne"></textarea>
                </div>

                <div class="form-actions">
                    <button type="submit" class="btn">Utwórz zamówienie</button>
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
        coordsDisp.textContent = 'Pinezka: ' + lat.toFixed(6) + ', ' + lng.toFixed(6);
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
                coordsDisp.textContent = 'Nie znaleziono lokalizacji.';
            }
        } catch (err) {
            coordsDisp.textContent = 'Błąd wyszukiwania.';
        } finally {
            this.textContent = 'Szukaj';
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
