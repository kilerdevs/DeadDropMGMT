<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/totp.php';
require_once dirname(__DIR__) . '/includes/audit.php';

start_secure_session();
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
        $error = 'Nieprawidłowy token CSRF.';
    } else {
        $action = $_POST['action'] ?? '';
        $code   = trim($_POST['code'] ?? '');
        $rl     = rl_status('admin_2fa_setup');

        if ($rl['blocked']) {
            $error = 'Zbyt wiele prób — odczekaj ' . (int)ceil($rl['remaining'] / 60) . ' min.';
        } elseif ($action === 'enable' && !$enabled) {
            $pending = $_SESSION['pending_totp_secret'] ?? '';
            if ($pending === '' || !totp_verify($pending, $code)) {
                rl_increment('admin_2fa_setup');
                $error = 'Nieprawidłowy kod. Spróbuj ponownie.';
            } else {
                $enc = encrypt_location($pending);
                get_db()->prepare(
                    'UPDATE users SET totp_enabled = 1, totp_secret_enc = ?, totp_secret_iv = ? WHERE id = ?'
                )->execute([$enc['ciphertext'], $enc['iv'], $uid]);
                unset($_SESSION['pending_totp_secret']);
                $_SESSION['totp_enabled'] = true;
                audit('2fa_enable');
                $enabled = true;
                $success = 'Weryfikacja dwuetapowa włączona.';
            }
        } elseif ($action === 'disable' && $enabled && !is_owner()) {
            // 2FA is mandatory for couriers — only the owner may self-disable.
            $error = 'Weryfikacja dwuetapowa jest wymagana dla kont kurierskich.';
        } elseif ($action === 'disable' && $enabled) {
            $secret = ($row['totp_secret_enc'] && $row['totp_secret_iv'])
                ? decrypt_location($row['totp_secret_enc'], $row['totp_secret_iv'])
                : false;
            if ($secret === false || !totp_verify($secret, $code)) {
                rl_increment('admin_2fa_setup');
                $error = 'Nieprawidłowy kod. Spróbuj ponownie.';
            } else {
                get_db()->prepare(
                    'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_secret_iv = NULL WHERE id = ?'
                )->execute([$uid]);
                $_SESSION['totp_enabled'] = false;
                audit('2fa_disable');
                $enabled = false;
                $success = 'Weryfikacja dwuetapowa wyłączona.';
            }
        }
    }
}

// Generate (or reuse) a pending secret for enrollment
$pending_secret = '';
$qr_uri         = '';
if (!$enabled) {
    $pending_secret = $_SESSION['pending_totp_secret'] ?? '';
    if ($pending_secret === '') {
        $pending_secret = totp_generate_secret();
        $_SESSION['pending_totp_secret'] = $pending_secret;
    }
    $qr_uri = totp_uri($pending_secret, current_user_name(), site_name());
}
$secret_display = $pending_secret !== '' ? trim(chunk_split($pending_secret, 4, ' ')) : '';

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Weryfikacja dwuetapowa</title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = '2fa'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading">Weryfikacja dwuetapowa (2FA)</div>

        <?php if ($error):   ?><div class="flash"><?= htmlspecialchars($error,   ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <?php if ($success): ?><div class="flash ok"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

        <div class="form-panel">
        <?php if ($enabled && is_owner()): ?>
            <div class="settings-warning">
                2FA jest włączone dla konta <strong><?= htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8') ?></strong>.
                Aby je wyłączyć, podaj bieżący kod z aplikacji uwierzytelniającej TOTP.
            </div>
            <form method="POST" action="/admin/2fa.php" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="disable">
                <div class="form-group">
                    <label for="code">Kod z aplikacji</label>
                    <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}"
                           maxlength="6" placeholder="000000" autocomplete="one-time-code" autofocus>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn btn-danger">Wyłącz 2FA</button>
                </div>
            </form>
        <?php elseif ($enabled): ?>
            <div class="settings-warning">
                2FA jest włączone dla konta <strong><?= htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8') ?></strong>
                i <strong>wymagane dla kont kurierskich</strong> — nie można go samodzielnie wyłączyć.
                W razie utraty dostępu poproś właściciela o reset w sekcji Użytkownicy.
            </div>
        <?php else: ?>
            <?php if (!is_owner() && ($_GET['required'] ?? '') === '1'): ?>
            <div class="settings-warning">
                <strong>Weryfikacja dwuetapowa jest wymagana dla kont kurierskich.</strong>
                Skonfiguruj ją poniżej, aby uzyskać dostęp do panelu.
            </div>
            <?php endif; ?>
            <div class="settings-warning">
                Zeskanuj poniższy kod w dowolnej aplikacji uwierzytelniającej zgodnej z TOTP — albo dodaj konto
                ręcznie, wpisując poniższy sekret. Następnie potwierdź bieżącym kodem, aby włączyć 2FA.
                Nie masz takiej aplikacji? Zobacz
                <a href="https://github.com/kilerdevs/DeadDropMGMT/blob/master/TOTP-APPS.md" target="_blank" rel="noopener">polecane aplikacje open source</a>.
            </div>
            <details class="why-totp">
                <summary>Dlaczego to ważne?</summary>
                <?php if (is_owner()): ?>
                <p>
                    Konto właściciela ma pełny dostęp do wszystkich zamówień, lokalizacji, użytkowników i ustawień
                    systemu — to najcenniejszy cel w razie wycieku hasła. 2FA nie jest wymagane dla właściciela,
                    ale jest zdecydowanie zalecane: nawet silne, unikalne hasło może wyciec, a 2FA to dodatkowa
                    bariera, którą atakujący musiałby pokonać.
                </p>
                <?php else: ?>
                <p>
                    Kurierzy pracują w terenie — często na współdzielonych urządzeniach lub sieciach publicznych,
                    gdzie ryzyko przechwycenia hasła jest wyższe. 2FA chroni konto nawet jeśli hasło wycieknie,
                    dlatego jest obowiązkowe dla kont kurierskich.
                </p>
                <?php endif; ?>
            </details>
            <div class="form-group">
                <div class="qr-box"><div id="qr-code"></div></div>
            </div>
            <div class="form-group">
                <div class="field-label">Sekret</div>
                <div class="location-display location-display-pw" id="totp-secret"><?= htmlspecialchars($secret_display, ENT_QUOTES, 'UTF-8') ?></div>
                <div class="location-note">
                    Dodawanie ręczne — Wydawca: <?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?>
                    · Konto: <?= htmlspecialchars(current_user_name(), ENT_QUOTES, 'UTF-8') ?> · SHA1 · 6 cyfr · 30s
                </div>
            </div>
            <div class="form-group">
                <button type="button" class="action-btn" id="copy-secret">Kopiuj sekret</button>
            </div>
            <form method="POST" action="/admin/2fa.php" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="action" value="enable">
                <div class="form-group">
                    <label for="code">Kod z aplikacji</label>
                    <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}"
                           maxlength="6" placeholder="000000" autocomplete="one-time-code">
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn">Włącz 2FA</button>
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
    text:         <?= json_encode($qr_uri) ?>,
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
        btn.textContent = 'Skopiowano ✓';
        setTimeout(function () { btn.textContent = old; }, 1500);
    });
});
</script>
<?php endif; ?>
</body>
</html>
