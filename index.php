<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/analytics.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/cleanup.php';
require_once __DIR__ . '/includes/i18n.php';

$csp_nonce = set_security_headers(false);
start_secure_session();
run_cleanup_if_due();

$allow_status_lookup = get_setting('allow_status_lookup', '1') === '1';

// ── State ─────────────────────────────────────────────────────────────────────
$error             = '';
$order_status      = '';
$loc_data          = null;
$order_notes       = '';
$order_expires_ts  = 0;
$photos            = [];
$show_pw_step      = false;
$prefill_token     = '';
$correct_preparing = false;
$blocked           = false;
$cooldown_secs     = 0;
$current_token     = '';

// ── PRG: restore reveal state from session after redirect ─────────────────────
// The payload is AES-sealed inside the session — the session store never
// holds the decrypted location, only ciphertext like the database.
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !empty($_SESSION['reveal'])) {
    $rv = $_SESSION['reveal'];
    unset($_SESSION['reveal']);
    if ((time() - ($rv['ts'] ?? 0)) < 300 && ($rv['type'] ?? '') === 'delivered') {
        $dec = open_payload($rv['sealed'] ?? []);
        if ($dec !== false) {
            $loc_data         = $dec;
            $order_notes      = $rv['notes'];
            $order_expires_ts = $rv['expires'];
            $photos           = $rv['photos'];
            $current_token    = $rv['token'];
        }
    } elseif ((time() - ($rv['ts'] ?? 0)) < 300 && ($rv['type'] ?? '') === 'preparing') {
        $correct_preparing = true;
    }
    unset($rv);
}

// ── GET ?token= pre-fill: auto-show password step ─────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $loc_data === null && !$correct_preparing) {
    $get_token = trim($_GET['token'] ?? '');
    if (strlen($get_token) === 16 && ctype_alnum($get_token)) {
        try {
            $db_g  = get_db();
            $st_g  = $db_g->prepare('SELECT id, status FROM orders WHERE order_token = ? LIMIT 1');
            $st_g->execute([$get_token]);
            $ord_g = $st_g->fetch();
            if ($ord_g) {
                $prefill_token = $get_token;
                if ($allow_status_lookup) {
                    log_event('lookup', (int)$ord_g['id'], $get_token);
                    $order_status = $ord_g['status'];
                    $show_pw_step = true;
                }
                // if status lookup is disabled, just pre-fill the token field
            }
        } catch (Exception $e) {
            // silently ignore — form shows empty
        }
    }
}

// ── Handle POST ───────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Enforce whichever budget trips first: the IP's or this session cookie's.
    $rl  = rl_status('public');
    $bkt = bucket_status('public', rl_max());

    if ($rl['blocked'] || $bkt['blocked']) {
        $blocked       = true;
        $cooldown_secs = max($rl['remaining'], bucket_remaining('public'));
    } else {
        $raw_token = trim($_POST['order_token'] ?? '');
        $password  = (string)($_POST['pickup_password'] ?? '');

        if (strlen($raw_token) !== 16 || !ctype_alnum($raw_token)) {
            $error = t('public.index.error.not_found');
        } else {
            try {
                $db   = get_db();
                $stmt = $db->prepare('SELECT * FROM orders WHERE order_token = ? LIMIT 1');
                $stmt->execute([$raw_token]);
                $order = $stmt->fetch();

                if (!$order) {
                    log_event('lookup', null, $raw_token);
                    $error = t('public.index.error.not_found');
                } elseif ($password === '' && !$allow_status_lookup) {
                    $error = t('public.index.error.password_required');
                } elseif ($password === '') {
                    log_event('lookup', (int)$order['id'], $raw_token);
                    $order_status  = $order['status'];
                    $prefill_token = $raw_token;
                    $show_pw_step  = true;
                } else {
                    if (verify_password($password, $order['pickup_password_hash'])) {
                        bucket_clear('public');
                        if ($order['status'] === 'preparing') {
                            log_event('unlock_success', (int)$order['id'], $raw_token);
                            $_SESSION['reveal'] = ['type' => 'preparing', 'ts' => time()];
                            header('Location: /');
                            exit;
                        } else {
                            $dec = decrypt_location_data($order['location_encrypted'], $order['location_iv']);
                            if ($dec === false) {
                                log_err('Decryption failed for ' . $raw_token);
                                $error = t('public.index.error.server_decrypt');
                            } else {
                                log_event('unlock_success', (int)$order['id'], $raw_token);
                                $ps = $db->prepare(
                                    'SELECT filename, caption FROM order_photos
                                     WHERE order_id = ? ORDER BY sort_order, id'
                                );
                                $ps->execute([$order['id']]);
                                $_SESSION['reveal'] = [
                                    'type'    => 'delivered',
                                    'sealed'  => seal_payload($dec),
                                    'notes'   => trim($order['notes'] ?? ''),
                                    'expires' => $order['expires_at'] ? (int)strtotime($order['expires_at']) : 0,
                                    'photos'  => $ps->fetchAll(),
                                    'token'   => $raw_token,
                                    'ts'      => time(),
                                ];
                                header('Location: /');
                                exit;
                            }
                        }
                    } else {
                        rl_increment('public');
                        bucket_fail('public');
                        log_event('unlock_fail', (int)$order['id'], $raw_token);
                        $error = t('public.index.error.invalid_credentials');
                    }
                }
            } catch (Exception $e) {
                log_err('Lookup error: ' . $e->getMessage());
                $error = t('public.index.error.service_unavailable');
            }
        }
    }
}

$cd_mins  = $blocked ? (int)floor($cooldown_secs / 60) : 0;
$cd_secs  = $blocked ? ($cooldown_secs % 60) : 0;

// Map iframe + links
$map_src   = '';
$gm_link   = '';
$apple_link = '';
if ($loc_data && is_numeric($loc_data['lat']) && is_numeric($loc_data['lng'])) {
    $lat = (float)$loc_data['lat'];
    $lng = (float)$loc_data['lng'];
    $mg  = 0.008;
    $map_src    = sprintf(
        'https://www.openstreetmap.org/export/embed.html?bbox=%.7f,%.7f,%.7f,%.7f&layer=mapnik&marker=%.7f,%.7f',
        $lng - $mg, $lat - $mg, $lng + $mg, $lat + $mg, $lat, $lng
    );
    $gm_link    = sprintf('https://www.google.com/maps/search/?api=1&query=%.7f%%2C%.7f', $lat, $lng);
    $apple_link = sprintf('https://maps.apple.com/?ll=%.7f,%.7f&q=%s&t=m', $lat, $lng, rawurlencode(t('public.index.reveal.location')));
}
$csrf_public = generate_csrf();
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= t('public.index.title') ?></title><link rel="stylesheet" href="/style.css">
<?php if ($blocked && $cooldown_secs <= 60): ?>
<meta http-equiv="refresh" content="<?= $cooldown_secs + 2 ?>">
<?php endif; ?>
</head>
<body>
<main>
    <div class="wordmark">DEAD DROP // <?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?></div>
    <h1><?= t('public.index.title') ?></h1>

<?php if ($blocked): ?>
    <div class="cooldown">
        <div class="cooldown-heading"><?= t('public.index.cooldown_heading') ?></div>
        <div class="cooldown-timer"><?= $cd_mins ?>m <?= str_pad((string)$cd_secs, 2, '0', STR_PAD_LEFT) ?>s</div>
        <div class="cooldown-sub"><?= t('public.index.cooldown_sub') ?></div>
    </div>

<?php else: ?>

    <?php if ($error): ?>
    <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>

    <?php if ($correct_preparing): ?>
    <!-- ── Correct password but not yet delivered ─────────────────────── -->
    <div class="status-card">
        <div class="status-label"><?= t('public.index.status_label') ?></div>
        <div class="status-badge"><?= t('public.status.preparing') ?></div>
        <div class="not-ready-note"><?= t('public.index.not_ready_note') ?></div>
    </div>

    <?php elseif ($loc_data !== null): ?>
    <!-- ── Delivered + correct password — full reveal ─────────────────── -->
    <div class="status-card">
        <div class="status-label"><?= t('public.index.status_label') ?></div>
        <div class="status-badge delivered"><?= t('public.status.delivered') ?></div>

        <?php if ($order_expires_ts > 0): ?>
        <div>
            <div class="expiry-banner">
                <span class="expiry-label"><?= t('public.index.expiry_label') ?></span>
                <span class="expiry-timer"
                      id="expiry-countdown"
                      data-expires="<?= $order_expires_ts ?>">
                    <?= htmlspecialchars(format_countdown($order_expires_ts - time()), ENT_QUOTES, 'UTF-8') ?>
                </span>
            </div>
        </div>
        <?php endif; ?>

        <div class="location-reveal">

            <?php if ($loc_data['text'] !== ''): ?>
            <div class="reveal-section">
                <div class="reveal-key"><?= t('public.index.reveal.location') ?></div>
                <div class="reveal-value"><?= htmlspecialchars($loc_data['text'], ENT_QUOTES, 'UTF-8') ?></div>
            </div>
            <?php endif; ?>

            <?php if ($map_src !== ''): ?>
            <div class="reveal-section">
                <div class="reveal-key"><?= t('public.index.reveal.map') ?></div>
                <iframe class="map-frame"
                        src="<?= htmlspecialchars($map_src, ENT_QUOTES, 'UTF-8') ?>"
                        loading="lazy"
                        title="<?= htmlspecialchars(t('public.index.map_title'), ENT_QUOTES, 'UTF-8') ?>"
                        sandbox="allow-scripts allow-same-origin"></iframe>
                <div class="map-actions">
                    <a class="map-link"
                       href="<?= htmlspecialchars($gm_link, ENT_QUOTES, 'UTF-8') ?>"
                       target="_blank" rel="noopener noreferrer">Google Maps ↗</a>
                    <a class="map-link"
                       href="<?= htmlspecialchars($apple_link, ENT_QUOTES, 'UTF-8') ?>"
                       target="_blank" rel="noopener noreferrer">Apple Maps ↗</a>
                </div>
            </div>
            <?php endif; ?>

            <?php if (!empty($loc_data['instructions'])): ?>
            <div class="reveal-section">
                <div class="reveal-key"><?= t('public.index.reveal.instructions') ?></div>
                <div class="instructions-text"><?= nl2br(htmlspecialchars($loc_data['instructions'], ENT_QUOTES, 'UTF-8')) ?></div>
            </div>
            <?php endif; ?>

            <?php if ($order_notes !== ''): ?>
            <div class="reveal-section">
                <div class="reveal-key"><?= t('public.index.reveal.notes') ?></div>
                <div class="instructions-text"><?= nl2br(htmlspecialchars($order_notes, ENT_QUOTES, 'UTF-8')) ?></div>
            </div>
            <?php endif; ?>

            <?php if (!empty($photos)): ?>
            <div class="reveal-section">
                <div class="reveal-key"><?= t('public.index.reveal.photos') ?></div>
                <div class="photos-grid">
                    <?php foreach ($photos as $ph): ?>
                    <div class="photo-item">
                        <img src="/uploads/<?= htmlspecialchars($ph['filename'], ENT_QUOTES, 'UTF-8') ?>"
                             alt="<?= htmlspecialchars($ph['caption'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                             loading="lazy">
                        <?php if (!empty($ph['caption'])): ?>
                        <div class="photo-caption"><?= htmlspecialchars($ph['caption'], ENT_QUOTES, 'UTF-8') ?></div>
                        <?php endif; ?>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

            <div class="once-note"><?= t('public.index.once_note') ?></div>
        </div>
    </div>

    <!-- ── Odebrałem ───────────────────────────────────────────────────── -->
    <hr class="divider">
    <form method="POST" action="/receive.php" autocomplete="off">
        <input type="hidden" name="csrf_token"
               value="<?= htmlspecialchars($csrf_public, ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" name="order_token"
               value="<?= htmlspecialchars($current_token, ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" name="step" value="1">
        <button type="submit" class="btn btn-receive"><?= t('public.index.receive_button') ?></button>
    </form>

    <?php elseif ($show_pw_step): ?>
    <!-- ── Status shown, prompt for password ─────────────────────────── -->
    <div class="status-card">
        <div class="status-label"><?= t('public.index.status_label') ?></div>
        <div class="status-badge <?= $order_status === 'delivered' ? 'delivered' : '' ?>">
            <?= $order_status === 'delivered' ? t('public.status.delivered') : t('public.status.preparing') ?>
        </div>
    </div>
    <hr class="divider">
    <div class="unlock-heading"><?= t('public.index.unlock_heading') ?></div>
    <form method="POST" action="" autocomplete="off">
        <input type="hidden" name="order_token"
               value="<?= htmlspecialchars($prefill_token, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-group">
            <label for="pickup_password"><?= t('public.index.pw_label') ?></label>
            <input type="password" id="pickup_password" name="pickup_password"
                   autofocus autocomplete="off">
        </div>
        <button type="submit" class="btn"><?= t('public.index.unlock_button') ?></button>
    </form>

    <?php else: ?>
    <!-- ── Initial form ──────────────────────────────────────────────── -->
    <form method="POST" action="" autocomplete="off">
        <div class="form-group">
            <label for="order_token"><?= t('public.index.token_label') ?></label>
            <input type="text" id="order_token" name="order_token"
                   maxlength="16" placeholder="XXXXXXXXXXXXXXXX"
                   value="<?= htmlspecialchars($prefill_token ?: ($_POST['order_token'] ?? ''), ENT_QUOTES, 'UTF-8') ?>"
                   autocomplete="off" spellcheck="false">
        </div>
        <div class="form-group">
            <label for="pickup_password">
                <?= t('public.index.pw_label') ?>
                <?php if ($allow_status_lookup): ?>
                <span class="optional"><?= t('public.index.pw_optional_hint') ?></span>
                <?php endif; ?>
            </label>
            <input type="password" id="pickup_password" name="pickup_password"
                   autocomplete="off" <?= !$allow_status_lookup ? 'required' : '' ?>>
        </div>
        <button type="submit" class="btn"><?= t('public.index.search_button') ?></button>
    </form>
    <?php endif; ?>

    <p class="form-footnote">
        <?= t('public.index.footnote', ['hours' => (int)order_ttl_hours()]) ?>
    </p>

<?php endif; ?>

    <div class="trust-bar" aria-label="<?= htmlspecialchars(t('public.trust.aria_label'), ENT_QUOTES, 'UTF-8') ?>">
        <span class="trust-lock" aria-hidden="true"></span>
        <span class="trust-text"><?= t('public.trust.secure') ?></span>
        <span class="trust-sep">·</span>
        <span class="trust-text"><?= t('public.trust.auto_delete') ?></span>
        <span class="trust-sep">·</span>
        <span class="trust-text"><?= t('public.trust.no_tracking') ?></span>
    </div>
    <?php if (compliance_note_enabled()): ?><div class="compliance-note"><?= t('common.compliance_note') ?></div><?php endif; ?>
</main>
<?php if ($order_expires_ts > 0 || !empty($photos)): ?>
<script nonce="<?= htmlspecialchars($csp_nonce, ENT_QUOTES, 'UTF-8') ?>">
window.I18N = <?= json_encode([
    'order_expired' => t('public.index.order_expired'),
    'gallery_close' => t('public.gallery.close'),
    'gallery_prev'  => t('public.gallery.prev'),
    'gallery_next'  => t('public.gallery.next'),
]) ?>;
</script>
<script src="/public.js"></script>
<?php endif; ?>
<?php if (!empty($photos)): ?>
<script src="/gallery.js"></script>
<?php endif; ?>
</body>
</html>
