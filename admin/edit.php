<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

start_secure_session();
require_admin();
$csp_nonce = set_security_headers(true);

$id = (int)($_GET['id'] ?? $_POST['id'] ?? 0);
if ($id <= 0) {
    header('Location: /admin/orders.php');
    exit;
}

// ── Fetch order ───────────────────────────────────────────────────────────────
function fetch_order(int $id) {
    try {
        $db   = get_db();
        $stmt = $db->prepare('SELECT * FROM orders WHERE id = ? LIMIT 1');
        $stmt->execute([$id]);
        return $stmt->fetch();
    } catch (Exception $e) {
        log_err('Edit fetch: ' . $e->getMessage());
        return false;
    }
}

$order = fetch_order($id);
if (!$order) {
    $_SESSION['flash']    = t('admin.orders.flash.not_found');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

// Couriers may only edit their own orders — the same central check every
// other mutating endpoint uses.
if (!courier_owns_order($id)) {
    $_SESSION['flash']    = t('admin.orders.flash.no_access');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

$error   = '';
$success = '';

// ── Handle POST ───────────────────────────────────────────────────────────────
$is_ajax = ($_SERVER['HTTP_X_AJAX'] ?? '') === '1';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.common.invalid_csrf');
    } else {
        $new_status       = in_array($_POST['status'] ?? '', ['preparing', 'delivered'], true)
                            ? $_POST['status'] : $order['status'];
        $new_notes        = trim($_POST['notes']        ?? '');
        $new_location     = trim($_POST['location']     ?? '');
        $new_instructions = trim($_POST['instructions'] ?? '');
        $new_password     = (string)($_POST['new_password'] ?? '');
        $lat_raw          = $_POST['lat'] ?? '';
        $lng_raw          = $_POST['lng'] ?? '';

        // State machine: preparing -> delivered only. A delivered order can
        // never regress to preparing (the recipient may already have seen it);
        // the UI no longer offers it and the server refuses it outright.
        if ($order['status'] === 'delivered' && $new_status === 'preparing') {
            $error = t('admin.edit.error.invalid_transition');
        }

        // Decode current location data for coordinate fallback
        if ($error === '') {
            $cur = decrypt_location_data($order['location_encrypted'], $order['location_iv'])
                ?: ['text' => '', 'lat' => null, 'lng' => null, 'instructions' => ''];
        } else {
            $cur = ['text' => '', 'lat' => null, 'lng' => null, 'instructions' => ''];
        }

        $final_text  = $new_location;
        $final_instr = $new_instructions;

        $final_lat = $cur['lat'];
        $final_lng = $cur['lng'];
        if ($lat_raw !== '' && $lng_raw !== '' && is_numeric($lat_raw) && is_numeric($lng_raw)) {
            $nlat = round((float)$lat_raw, 7);
            $nlng = round((float)$lng_raw, 7);
            if ($nlat >= -90 && $nlat <= 90 && $nlng >= -180 && $nlng <= 180) {
                $final_lat = $nlat;
                $final_lng = $nlng;
            }
        }

        // Password — hash-only: keep current hash if not changing, otherwise
        // replace it. The old recoverable AES copy is purged on every save.
        if ($new_password !== '') {
            if (strlen($new_password) < 8) {
                $error = t('admin.edit.error.pw_too_short');
            } else {
                $pw_hash = hash_password($new_password);
            }
        } else {
            $pw_hash = $order['pickup_password_hash'];
        }

        if ($error === '') {
            try {
                $enc = encrypt_location_data([
                    'text'         => $final_text,
                    'lat'          => $final_lat,
                    'lng'          => $final_lng,
                    'instructions' => $final_instr,
                ]);

                // delivered_at/expires_at are set by the SAME conditional
                // update that flips the status — no read-decide-write window.
                if ($order['status'] === 'preparing' && $new_status === 'delivered') {
                    get_db()->prepare(
                        'UPDATE orders SET
                            status                = "delivered",
                            delivered_at          = NOW(),
                            expires_at            = DATE_ADD(NOW(), INTERVAL ? HOUR),
                            notes                 = ?,
                            location_encrypted    = ?,
                            location_iv           = ?,
                            pickup_password_hash  = ?,
                            pickup_password_enc   = NULL,
                            pickup_password_iv    = NULL
                         WHERE id = ? AND status = "preparing"'
                    )->execute([
                        order_ttl_hours(),
                        $new_notes !== '' ? $new_notes : null,
                        $enc['ciphertext'],
                        $enc['iv'],
                        $pw_hash,
                        $id,
                    ]);
                } else {
                    get_db()->prepare(
                        'UPDATE orders SET
                            notes                 = ?,
                            location_encrypted    = ?,
                            location_iv           = ?,
                            pickup_password_hash  = ?,
                            pickup_password_enc   = NULL,
                            pickup_password_iv    = NULL
                         WHERE id = ? AND status = ?'
                    )->execute([
                        $new_notes !== '' ? $new_notes : null,
                        $enc['ciphertext'],
                        $enc['iv'],
                        $pw_hash,
                        $id,
                        $order['status'],
                    ]);
                }

                // Handle new photo uploads
                if (!empty($_FILES['photos']['name'][0])) {
                    $db    = get_db();
                    $files = $_FILES['photos'];
                    $count = count($files['name']);
                    for ($i = 0; $i < $count; $i++) {
                        $entry = [
                            'name'     => $files['name'][$i],
                            'type'     => $files['type'][$i],
                            'tmp_name' => $files['tmp_name'][$i],
                            'error'    => $files['error'][$i],
                            'size'     => $files['size'][$i],
                        ];
                        $rel = save_uploaded_photo($entry, $id, max_photo_bytes());
                        if ($rel !== false) {
                            $db->prepare(
                                'INSERT INTO order_photos (order_id, filename) VALUES (?, ?)'
                            )->execute([$id, $rel]);
                        }
                    }
                }

                audit('order_edit', $id, $order['order_token'], "status={$new_status}");
                $order   = fetch_order($id);
                $success = t('admin.edit.success.saved');
            } catch (Exception $e) {
                log_err('Edit update: ' . $e->getMessage());
                $error = t('admin.edit.error.save_failed');
            }
        }
    }

    if ($is_ajax) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => empty($error), 'msg' => $error ?: $success]);
        exit;
    }
}

// ── Decrypt current data ──────────────────────────────────────────────────────
$loc = decrypt_location_data($order['location_encrypted'], $order['location_iv'])
    ?: ['text' => t('admin.edit.decrypt_error'), 'lat' => null, 'lng' => null, 'instructions' => ''];

// Pickup passwords are hash-only: nothing is decrypted for display. The
// credential was shown once at creation and can be replaced, not recovered.
$pw_display = null;

// Load photos
try {
    $photos_stmt = get_db()->prepare(
        'SELECT id, filename, caption FROM order_photos WHERE order_id = ? ORDER BY sort_order, id'
    );
    $photos_stmt->execute([$id]);
    $photos = $photos_stmt->fetchAll();
} catch (Exception $e) {
    $photos = [];
}

$csrf      = generate_csrf();
$has_pin   = is_numeric($loc['lat']) && is_numeric($loc['lng']);
$init_lat  = $has_pin ? (float)$loc['lat'] : 52.2297;
$init_lng  = $has_pin ? (float)$loc['lng'] : 21.0122;
$init_zoom = $has_pin ? 17 : 12;
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.edit.title_prefix') ?> <?= htmlspecialchars($order['order_token'], ENT_QUOTES, 'UTF-8') ?></title><link rel="stylesheet" href="/admin/vendor/leaflet/leaflet.css">
<link rel="stylesheet" href="/admin/style.css">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
</head>
<body>
<div class="shell">

    <?php $_active = 'edit'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
    <?php require __DIR__ . '/osm_monit.php'; ?>
        <div class="page-heading">
            <?= t('admin.edit.title_prefix') ?> — <span class="token"><?= htmlspecialchars($order['order_token'], ENT_QUOTES, 'UTF-8') ?></span>
        </div>

        <?php if ($error):   ?><div class="flash"><?= htmlspecialchars($error,   ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <?php if ($success): ?><div class="flash ok"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

        <!-- ── Quick delivered action ────────────────────────────────────── -->
        <?php if ($order['status'] === 'preparing'): ?>
        <form method="POST" action="/admin/mark_delivered.php" class="form-deliver">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="id" value="<?= htmlspecialchars((string)$id, ENT_QUOTES, 'UTF-8') ?>">
            <button type="submit" class="btn btn-deliver">
                ✓ <?= t('admin.edit.mark_delivered_button') ?>
            </button>
        </form>
        <?php else: ?>
        <div class="flash ok flash-delivered">
            <?= t('public.status.delivered') ?> — <?= htmlspecialchars($order['delivered_at'] ?? '', ENT_QUOTES, 'UTF-8') ?>
        </div>
        <?php endif; ?>

        <div class="form-panel centered-panel">

            <!-- ── Main edit form ──────────────────────────────────────────── -->
            <form method="POST" action="/admin/edit.php?id=<?= htmlspecialchars((string)$id, ENT_QUOTES, 'UTF-8') ?>"
                  enctype="multipart/form-data" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="id"  value="<?= htmlspecialchars((string)$id, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="lat" id="lat" value="<?= $has_pin ? htmlspecialchars((string)$loc['lat'], ENT_QUOTES, 'UTF-8') : '' ?>">
                <input type="hidden" name="lng" id="lng" value="<?= $has_pin ? htmlspecialchars((string)$loc['lng'], ENT_QUOTES, 'UTF-8') : '' ?>">

                <!-- Status -->
                <div class="form-group">
                    <label for="status"><?= t('admin.orders.th.status') ?></label>
                    <select id="status" name="status">
                        <?php if ($order['status'] === 'preparing'): ?>
                        <option value="preparing" selected><?= t('admin.edit.status.preparing_option') ?></option>
                        <option value="delivered"><?= t('admin.edit.status.delivered_option') ?></option>
                        <?php else: ?>
                        <!-- delivered is terminal: no regression option offered -->
                        <option value="delivered" selected><?= t('admin.edit.status.delivered_option') ?></option>
                        <?php endif; ?>
                    </select>
                </div>

                <!-- Current pickup password -->
                <div class="form-group">
                    <div class="field-label"><?= t('public.index.pw_label') ?></div>
                    <div class="location-note"><?= t('admin.edit.pw_hashed_note') ?></div>
                </div>

                <!-- New password -->
                <div class="form-group">
                    <label for="new_password">
                        <?= t('admin.edit.new_pw_label') ?>
                        <span class="hint"><?= t('admin.edit.new_pw_hint') ?></span>
                    </label>
                    <input type="text" id="new_password" name="new_password"
                           autocomplete="off" placeholder="<?= htmlspecialchars(t('admin.edit.new_pw_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
                </div>

                <!-- Location text -->
                <div class="form-group">
                    <label for="location">
                        <?= t('admin.new_order.location_label') ?>
                        <span class="hint"><?= t('admin.edit.location_hint') ?></span>
                    </label>
                    <textarea id="location" name="location" rows="2"><?= htmlspecialchars($loc['text'], ENT_QUOTES, 'UTF-8') ?></textarea>
                </div>

                <!-- Map picker -->
                <div class="form-group map-section">
                    <div class="field-label">
                        <?= t('admin.new_order.pin_label') ?>
                        <span class="hint"><?= t('admin.edit.pin_hint') ?></span>
                    </div>
                    <div class="map-search-row">
                        <input type="text" id="addr-search"
                               placeholder="<?= htmlspecialchars(t('admin.new_order.addr_search_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="off">
                        <button type="button" class="btn btn-sm" id="addr-btn"><?= t('admin.new_order.search_button') ?></button>
                    </div>
                    <div id="map-picker"></div>
                    <div class="map-coords" id="coords-display">
                        <?= $has_pin
                            ? t('admin.edit.current_pin', ['lat' => number_format((float)$loc['lat'], 6), 'lng' => number_format((float)$loc['lng'], 6)])
                            : t('admin.new_order.no_pin') // nosemgrep: params are number_format() strings, t() escapes them
                            ?>
                    </div>
                </div>

                <!-- Instructions -->
                <div class="form-group">
                    <label for="instructions">
                        <?= t('admin.new_order.instructions_label') ?>
                        <span class="hint"><?= t('admin.edit.location_hint') ?></span>
                    </label>
                    <textarea id="instructions" name="instructions" rows="4"><?= htmlspecialchars($loc['instructions'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
                </div>

                <!-- Notes -->
                <div class="form-group">
                    <label for="notes"><?= t('public.index.reveal.notes') ?> <span class="hint"><?= t('admin.new_order.notes_hint') ?></span></label>
                    <textarea id="notes" name="notes" rows="2"
                              placeholder="<?= htmlspecialchars(t('admin.edit.notes_placeholder'), ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($order['notes'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
                </div>

                <!-- Existing photos -->
                <?php if (!empty($photos)): ?>
                <div class="form-group">
                    <div class="field-label">
                        <?= t('admin.edit.photos_count_label', ['n' => count($photos)]) ?>
                        <?php if (count($photos) > 3): ?>
                        <span class="hint"><?= t('admin.edit.photos_click_hint') ?></span>
                        <?php endif; ?>
                    </div>
                    <div class="photo-grid">
                        <?php foreach ($photos as $i => $ph): ?>
                        <div class="photo-thumb <?= $i >= 3 ? 'photo-thumb--hidden' : '' ?>">
                            <a class="gallery-link"
                               href="/uploads/<?= htmlspecialchars($ph['filename'], ENT_QUOTES, 'UTF-8') ?>"
                               data-caption="<?= htmlspecialchars($ph['caption'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                               data-photo-id="<?= (int)$ph['id'] ?>"
                               data-order-id="<?= htmlspecialchars((string)$id, ENT_QUOTES, 'UTF-8') ?>">
                                <img src="/uploads/<?= htmlspecialchars($ph['filename'], ENT_QUOTES, 'UTF-8') ?>"
                                     alt="<?= htmlspecialchars($ph['caption'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                                     loading="lazy">
                            </a>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Add photos -->
                <div class="form-group">
                    <label for="photos">
                        <?= t('admin.edit.add_photos_label') ?>
                        <span class="hint">JPEG / PNG / WebP / GIF · <?= t('admin.new_order.photos_hint', ['mb' => number_format((float)get_setting('max_photo_mb', '2'), 1)]) ?></span>
                    </label>
                    <input type="file" id="photos" name="photos[]" multiple
                           accept="image/jpeg,image/png,image/webp,image/gif">
                </div>

                <!-- Metadata -->
                <div class="form-group">
                    <div class="field-label"><?= t('admin.edit.metadata_label') ?></div>
                    <div class="meta">
                        <?= t('admin.edit.created_label') ?> <?= htmlspecialchars($order['created_at'], ENT_QUOTES, 'UTF-8') ?><br>
                        <?= t('admin.edit.delivered_label') ?> <?= $order['delivered_at'] ? htmlspecialchars($order['delivered_at'], ENT_QUOTES, 'UTF-8') : '—' ?><br>
                        <?php if ($order['status'] === 'preparing'): ?>
                        <?= t('admin.edit.expires_after_delivery') ?>
                        <?php else:
                            $exp_ts  = !empty($order['expires_at']) ? (int)strtotime($order['expires_at']) : 0;
                            $exp_rem = $exp_ts > 0 ? $exp_ts - time() : 0;
                            $exp_cls = $exp_rem <= 0 ? 'urgent' : ($exp_rem < 3600 ? 'urgent' : ($exp_rem < 21600 ? 'warning' : ''));
                        ?>
                        <?= t('admin.edit.expires_label') ?> <?= $exp_ts > 0 ? htmlspecialchars($order['expires_at'], ENT_QUOTES, 'UTF-8') : '—' ?>
                        <?php if ($exp_ts > 0): ?>
                        (<span class="expiry-timer <?= $exp_cls ?>"
                               data-expires="<?= htmlspecialchars((string)$exp_ts, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars(format_countdown($exp_rem), ENT_QUOTES, 'UTF-8') ?></span>)
                        <?php endif; endif; ?>
                    </div>
                </div>

                <?php if ($order['status'] === 'delivered'): ?>
                <!-- Extend expiry -->
                <div class="form-group">
                    <div class="field-label"><?= t('admin.edit.extend_label') ?></div>
                    <div class="extend-row">
                    <?php foreach (extend_hours_options() as $h): ?>
                    <button type="button" class="btn btn-sm"
                            onclick="(function(){
                                var f = document.createElement('form');
                                f.method = 'POST';
                                f.action = '/admin/extend.php';
                                f.innerHTML = '<input name=csrf_token value=\'<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>\'>' +
                                              '<input name=id value=\'<?= (int)$id // nosemgrep: cast to int, JS-string context ?>\'>' +
                                              '<input name=hours value=\'<?= (int)$h ?>\'>' +
                                              '<input name=ref value=edit>';
                                document.body.appendChild(f);
                                f.submit();
                            })()">+<?= (int)$h ?>h</button>
                    <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>

                <div class="form-actions">
                    <button type="submit" class="btn"><?= t('admin.edit.save_button') ?></button>
                    <a class="btn-cancel" href="/admin/orders.php"><?= t('common.cancel') ?></a>
                </div>

                <div class="edit-extra-actions">
                    <button class="action-btn"
                            data-copy
                            data-token="<?= htmlspecialchars($order['order_token'], ENT_QUOTES, 'UTF-8') ?>">
                        <?= t('admin.edit.copy_data_button') ?>
                    </button>
                </div>

            </form><!-- END main edit form -->

            <!-- ── Delete form — OUTSIDE the edit form ─────────────────────── -->
            <div class="edit-extra-actions">
                <form class="inline-form" method="POST" action="/admin/orders.php"
                      data-confirm="<?= htmlspecialchars(t('admin.edit.delete_confirm', ['token' => $order['order_token']]), ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" value="<?= htmlspecialchars((string)$id, ENT_QUOTES, 'UTF-8') ?>">
                    <button class="action-btn action-btn--danger"><?= t('admin.edit.delete_button') ?></button>
                </form>
            </div>

        </div><!-- .form-panel -->
    </main>
</div>

<script src="/admin/vendor/leaflet/leaflet.js"></script>
<script src="/admin/admin.js"></script>
<script nonce="<?= htmlspecialchars($csp_nonce, ENT_QUOTES, 'UTF-8') ?>">
(function () {
    // ── Auto-save ─────────────────────────────────────────────────────────────
    var csrf      = document.querySelector('meta[name="csrf-token"]').content;
    var editForm  = document.querySelector('form[action*="edit.php"]');
    var saveTimer = null;
    var saving    = false;
    var mapReady  = false;

    var popup = document.createElement('div');
    popup.className = 'save-popup';
    document.body.appendChild(popup);
    var popupTimer = null;

    function showPopup(msg, isError) {
        popup.textContent = msg;
        popup.className = 'save-popup' + (isError ? ' error' : '') + ' visible';
        clearTimeout(popupTimer);
        popupTimer = setTimeout(function () { popup.classList.remove('visible'); }, isError ? 3000 : 1400);
    }

    function saveNow() {
        if (saving || !editForm) return;
        saving = true;
        var fd = new FormData(editForm);
        fetch(editForm.action || window.location.href, {
            method: 'POST',
            headers: { 'X-Ajax': '1' },
            body: fd,
        })
        .then(function (r) { return r.json(); })
        .then(function (d) {
            saving = false;
            if (d.ok) {
                showPopup(<?= json_encode('✓ ' . t('admin.edit.js.saved')) ?>, false);
                setTimeout(function () { location.reload(); }, 600);
            } else {
                showPopup(d.msg || <?= json_encode(t('admin.edit.js.save_error')) ?>, true);
            }
        })
        .catch(function () { saving = false; showPopup(<?= json_encode(t('admin.edit.js.connection_error')) ?>, true); });
    }

    function scheduleSave(ms) {
        clearTimeout(saveTimer);
        saveTimer = setTimeout(saveNow, ms || 3000);
    }

    if (editForm) {
        editForm.querySelectorAll('textarea, input[type="text"], input[type="password"]').forEach(function (el) {
            el.addEventListener('input', function () { scheduleSave(3000); });
        });
        editForm.querySelectorAll('select').forEach(function (el) {
            el.addEventListener('change', function () { clearTimeout(saveTimer); saveNow(); });
        });
        editForm.querySelectorAll('input[type="file"]').forEach(function (el) {
            el.addEventListener('change', function () { clearTimeout(saveTimer); saveNow(); });
        });
        editForm.addEventListener('submit', function (e) {
            e.preventDefault();
            clearTimeout(saveTimer);
            saveNow();
        });
    }

    document.addEventListener('submit', function (e) {
        if (e.target !== editForm) {
            clearTimeout(saveTimer);
        }
    });

    // ── Leaflet map ───────────────────────────────────────────────────────────
    delete L.Icon.Default.prototype._getIconUrl;
    L.Icon.Default.mergeOptions({
        iconUrl:       '/admin/vendor/leaflet/images/marker-icon.png',
        iconRetinaUrl: '/admin/vendor/leaflet/images/marker-icon-2x.png',
        shadowUrl:     '/admin/vendor/leaflet/images/marker-shadow.png',
    });

    // json_encode emits JS literals (null/number/bool) — the correct and
    // complete encoding for this context; HTML escaping would corrupt it.
    const initLat  = <?= json_encode($init_lat) // nosemgrep: JSON-in-script context ?>;
    const initLng  = <?= json_encode($init_lng) // nosemgrep: JSON-in-script context ?>;
    const initZoom = <?= json_encode($init_zoom) ?>;
    const hasPin   = <?= json_encode($has_pin) // nosemgrep: JSON-in-script context ?>;

    const map = L.map('map-picker').setView([initLat, initLng], initZoom);
    L.tileLayer('/admin/tile_proxy.php?z={z}&x={x}&y={y}', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 19
    }).addTo(map);

    const latInput   = document.getElementById('lat');
    const lngInput   = document.getElementById('lng');
    const coordsDisp = document.getElementById('coords-display');
    let marker = null;

    function setPin(lat, lng) {
        latInput.value = lat.toFixed(7);
        lngInput.value = lng.toFixed(7);
        coordsDisp.textContent = <?= json_encode(t('admin.new_order.pin_prefix')) ?> + lat.toFixed(6) + ', ' + lng.toFixed(6);
        if (mapReady) scheduleSave(500);
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

    if (hasPin) { setPin(initLat, initLng); }
    mapReady = true;
    map.on('click', function (e) { setPin(e.latlng.lat, e.latlng.lng); });

    document.getElementById('addr-btn').addEventListener('click', async function () {
        const q = document.getElementById('addr-search').value.trim();
        if (!q) return;
        this.textContent = '…';
        this.disabled = true;
        try {
            const r = await fetch('/admin/geocode_proxy.php?q=' + encodeURIComponent(q));
            const d = await r.json();
            if (d.length) {
                const lat = parseFloat(d[0].lat), lng = parseFloat(d[0].lon);
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

    // ── Photo gallery / lightbox ──────────────────────────────────────────────
    var links = Array.from(document.querySelectorAll('.gallery-link'));
    if (links.length) {
        var alb = document.createElement('div');
        alb.id = 'admin-lb';
        alb.innerHTML =
            '<div class="alb-backdrop"></div>' +
            '<button class="alb-close" aria-label="<?= htmlspecialchars(t('public.gallery.close'), ENT_QUOTES, 'UTF-8') ?>">&times;</button>' +
            '<button class="alb-prev" aria-label="<?= htmlspecialchars(t('public.gallery.prev'), ENT_QUOTES, 'UTF-8') ?>">&#8249;</button>' +
            '<div class="alb-stage">' +
                '<img class="alb-img" src="" alt="">' +
                '<div class="alb-caption"></div>' +
                '<div class="alb-counter"></div>' +
                '<form class="alb-delete-form" method="POST" action="/admin/photo_delete.php" data-confirm="<?= htmlspecialchars(t('admin.edit.gallery.delete_confirm'), ENT_QUOTES, 'UTF-8') ?>">' +
                    '<input type="hidden" name="csrf_token" value="">' +
                    '<input type="hidden" name="photo_id" value="">' +
                    '<input type="hidden" name="order_id" value="">' +
                    '<button type="submit" class="alb-delete-btn"><?= htmlspecialchars(t('admin.edit.gallery.delete_button'), ENT_QUOTES, 'UTF-8') ?></button>' +
                '</form>' +
            '</div>' +
            '<button class="alb-next" aria-label="<?= htmlspecialchars(t('public.gallery.next'), ENT_QUOTES, 'UTF-8') ?>">&#8250;</button>';
        document.body.appendChild(alb);

        var albImg     = alb.querySelector('.alb-img');
        var albCaption = alb.querySelector('.alb-caption');
        var albCounter = alb.querySelector('.alb-counter');
        var albPrev    = alb.querySelector('.alb-prev');
        var albNext    = alb.querySelector('.alb-next');
        var albCur     = 0;
        var albDelForm = alb.querySelector('.alb-delete-form');

        function albShow(i) {
            albCur = (i + links.length) % links.length;
            var a  = links[albCur];
            albImg.src = a.href;
            albImg.alt = a.dataset.caption || '';
            albCaption.textContent = a.dataset.caption || '';
            albCounter.textContent = (albCur + 1) + ' / ' + links.length;
            albPrev.style.display = links.length > 1 ? '' : 'none';
            albNext.style.display = links.length > 1 ? '' : 'none';
            albDelForm.querySelector('[name="csrf_token"]').value =
                (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
            albDelForm.querySelector('[name="photo_id"]').value = a.dataset.photoId || '';
            albDelForm.querySelector('[name="order_id"]').value = a.dataset.orderId || '';
            alb.classList.add('active');
            document.body.style.overflow = 'hidden';
        }
        function albHide() {
            alb.classList.remove('active');
            albImg.src = '';
            document.body.style.overflow = '';
        }

        links.forEach(function (a, i) {
            a.addEventListener('click', function (e) { e.preventDefault(); albShow(i); });
        });

        alb.querySelector('.alb-backdrop').addEventListener('click', albHide);
        alb.querySelector('.alb-close').addEventListener('click', albHide);
        albPrev.addEventListener('click', function (e) { e.stopPropagation(); albShow(albCur - 1); });
        albNext.addEventListener('click', function (e) { e.stopPropagation(); albShow(albCur + 1); });

        document.addEventListener('keydown', function (e) {
            if (!alb.classList.contains('active')) return;
            if (e.key === 'Escape')     { albHide(); }
            if (e.key === 'ArrowLeft')  { albShow(albCur - 1); }
            if (e.key === 'ArrowRight') { albShow(albCur + 1); }
        });

        var touchX0 = 0;
        alb.addEventListener('touchstart', function (e) { touchX0 = e.touches[0].clientX; }, { passive: true });
        alb.addEventListener('touchend',   function (e) {
            var dx = touchX0 - e.changedTouches[0].clientX;
            if (Math.abs(dx) > 50) albShow(albCur + (dx > 0 ? 1 : -1));
        }, { passive: true });
    }
})();
</script>
</body>
</html>