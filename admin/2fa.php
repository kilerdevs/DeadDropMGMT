<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

start_secure_session();
// The enrollment page itself: a courier pending TOTP setup must reach it,
// so it carries the same 2fa-exempt flag dispatched routes declare.
$GLOBALS['DDMGMT_ROUTE_2FA_EXEMPT'] = true;
require_admin();
$csp_nonce = set_security_headers(true);

$uid = current_user_id();

try {
    $stmt = get_db()->prepare('SELECT totp_enabled, totp_secret_enc, totp_secret_iv FROM users WHERE id = ? LIMIT 1');
    $stmt->execute([$uid]);
    $row = $stmt->fetch() ?: ['totp_enabled' => 0, 'totp_secret_enc' => null, 'totp_secret_iv' => null];
} catch (Exception $e) {
    log_err('2FA load: ' . $e->getMessage());
    $row = ['totp_enabled' => 0, 'totp_secret_enc' => null, 'totp_secret_iv' => null];
}
$enabled = !empty($row['totp_enabled']);

$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.common.invalid_csrf');
    } else {
        $action = $_POST['action'] ?? '';
        $code   = trim(post_string('code'));
        $rl     = rl_status('admin_2fa_setup');

        if ($rl['blocked']) {
            $error = t('admin.verify2fa.error.rate_limited', ['min' => (int)ceil($rl['remaining'] / 60)]);
        } elseif ($action === 'enable' && !$enabled) {
            // The pending secret crosses the QR render via the session sealed
            // (TOTP subkey), never plaintext — a session-file reader learns
            // nothing. A bare string is still honored so enrollments started
            // before the seal deploy complete instead of bricking.
            $pending_raw = $_SESSION['pending_totp_secret'] ?? '';
            if (is_array($pending_raw)) {
                $pending = decrypt_secret(
                    (string)($pending_raw['ciphertext'] ?? ''),
                    (string)($pending_raw['iv'] ?? '')
                );
                if ($pending === false) {
                    $pending = '';
                }
            } else {
                $pending = (string)$pending_raw;
            }
            if ($pending === '' || !totp_verify($pending, $code)) {
                rl_increment('admin_2fa_setup');
                $error = t('admin.2fa.error.invalid_code');
            } else {
                $enc = encrypt_secret($pending);
                get_db()->prepare(
                    'UPDATE users SET totp_enabled = 1, totp_secret_enc = ?, totp_secret_iv = ?, totp_last_counter = NULL WHERE id = ?'
                )->execute([$enc['ciphertext'], $enc['iv'], $uid]);
                unset($_SESSION['pending_totp_secret']);
                $_SESSION['totp_enabled'] = true;
                audit('2fa_enable');
                $enabled = true;
                $success = t('admin.2fa.success.enabled');
            }
        } elseif ($action === 'disable' && $enabled && !is_owner()) {
            // 2FA is mandatory for couriers — only the owner may self-disable.
            $error = t('admin.2fa.mandatory_notice');
        } elseif ($action === 'disable' && $enabled) {
            $secret = ($row['totp_secret_enc'] && $row['totp_secret_iv'])
                ? decrypt_secret($row['totp_secret_enc'], $row['totp_secret_iv'])
                : false;
            if ($secret === false || !totp_verify($secret, $code)) {
                rl_increment('admin_2fa_setup');
                $error = t('admin.2fa.error.invalid_code');
            } else {
                get_db()->prepare(
                    'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_secret_iv = NULL, totp_last_counter = NULL WHERE id = ?'
                )->execute([$uid]);
                $_SESSION['totp_enabled'] = false;
                audit('2fa_disable');
                $enabled = false;
                $success = t('admin.2fa.success.disabled');
            }
        }
    }
}

// Generate (or reuse) a pending secret for enrollment — sealed at rest.
$pending_secret = '';
$qr_uri         = '';
if (!$enabled) {
    $pending_secret = '';
    $pending_raw = $_SESSION['pending_totp_secret'] ?? '';
    if (is_array($pending_raw)) {
        $dec = decrypt_secret(
            (string)($pending_raw['ciphertext'] ?? ''),
            (string)($pending_raw['iv'] ?? '')
        );
        if (is_string($dec)) {
            $pending_secret = $dec;
        }
    } elseif (is_string($pending_raw)) {
        $pending_secret = $pending_raw;
    }
    if ($pending_secret === '') {
        $pending_secret = totp_generate_secret();
        $_SESSION['pending_totp_secret'] = encrypt_secret($pending_secret);
    }
    $qr_uri = totp_uri($pending_secret, current_user_name(), site_name());
}
$secret_display = $pending_secret !== '' ? trim(chunk_split($pending_secret, 4, ' ')) : '';

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.2fa.page_title') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = '2fa'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <?php $totp_banner_show_link = false; require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading"><?= t('admin.2fa.h1') ?></div>

        <?php if ($error):   ?><div class="flash"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="flash ok"><?= $success ?></div><?php endif; ?>
        <!-- $error/$success are t()-built (HTML-safe); raw echo (see orders.php). -->

        <div class="form-panel totp-panel">
        <?php if ($enabled && is_owner()): ?>
            <div class="settings-warning">
                <?= t('admin.2fa.enabled_notice', ['username' => current_user_name()]) ?>
            </div>
            <form method="POST" action="/admin/2fa.php" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="disable">
                <div class="form-group">
                    <label for="code"><?= t('admin.2fa.code_from_app_label') ?></label>
                    <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}"
                           maxlength="6" placeholder="000000" autocomplete="one-time-code" autofocus>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn btn-danger"><?= t('admin.2fa.disable_button') ?></button>
                </div>
            </form>
        <?php elseif ($enabled): ?>
            <div class="settings-warning">
                <?= t('admin.2fa.courier_mandatory_notice', ['username' => current_user_name()]) ?>
            </div>
        <?php else: ?>
            <?php if (!is_owner() && ($_GET['required'] ?? '') === '1'): ?>
            <div class="settings-warning">
                <?= t('admin.2fa.required_banner') ?>
            </div>
            <?php endif; ?>
            <div class="settings-warning">
                <?= t('admin.2fa.scan_instructions') ?>
                <?= t('admin.2fa.no_app_prompt') ?>
                <a href="https://github.com/kilerdevs/DeadDropMGMT/blob/master/TOTP-APPS.md" target="_blank" rel="noopener"><?= t('admin.2fa.no_app_link_text') ?></a>.
            </div>
            <details class="why-totp">
                <summary><?= t('admin.2fa.why_summary') ?></summary>
                <?php if (is_owner()): ?>
                <p><?= t('admin.2fa.why_owner') ?></p>
                <?php else: ?>
                <p><?= t('admin.2fa.why_courier') ?></p>
                <?php endif; ?>
            </details>
            <div class="totp-enroll">
                <div class="qr-box"><div id="qr-code"></div></div>
                <div class="totp-enroll-secret">
                    <div class="field-label"><?= t('admin.2fa.secret_label') ?></div>
                    <div class="location-display location-display-pw" id="totp-secret"><?= htmlspecialchars($secret_display, ENT_QUOTES, 'UTF-8') ?></div>
                    <div class="location-note">
                        <?= t('admin.2fa.manual_entry_note', [
                            'site'     => site_name(),
                            'username' => current_user_name(),
                        ]) ?>
                    </div>
                </div>
                <button type="button" class="action-btn" id="copy-secret"><?= t('admin.2fa.copy_secret_button') ?></button>
            </div>
            <form method="POST" action="/admin/2fa.php" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="enable">
                <div class="form-group">
                    <label for="code"><?= t('admin.2fa.code_from_app_label') ?></label>
                    <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}"
                           maxlength="6" placeholder="000000" autocomplete="one-time-code">
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn"><?= t('admin.2fa.enable_button') ?></button>
                </div>
            </form>
        <?php endif; ?>
        </div>
    </main>
</div>

<script src="/admin/admin.js"></script>
<?php if (!$enabled): ?>
<script src="/admin/vendor/qrcode/qrcode.js"></script>
<script nonce="<?= htmlspecialchars($csp_nonce, ENT_QUOTES, 'UTF-8') ?>">
new QRCode(document.getElementById('qr-code'), {
    text:         <?= json_encode($qr_uri, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>,
    width:        200,
    height:       200,
    colorDark:    '#000000',
    colorLight:   '#ffffff',
    correctLevel: QRCode.CorrectLevel.M
});

document.getElementById('copy-secret').addEventListener('click', function () {
    var raw = document.getElementById('totp-secret').textContent.replace(/\s+/g, '');
    navigator.clipboard.writeText(raw).then(function () {
        var btn = document.getElementById('copy-secret');
        var old = btn.textContent;
        btn.textContent = <?= json_encode(t('admin.2fa.copied'), JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
        setTimeout(function () { btn.textContent = old; }, 1500);
    });
});
</script>
<?php endif; ?>
</body>
</html>
