<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/totp.php';
require_once dirname(__DIR__) . '/includes/settings.php';

set_security_headers(false);
start_secure_session();

$pending_uid = (int)($_SESSION['pending_2fa_user_id'] ?? 0);
$pending_ts  = (int)($_SESSION['pending_2fa_time']    ?? 0);

// Pending state expires after 5 minutes — back to the login form.
if ($pending_uid <= 0 || (time() - $pending_ts) > 300) {
    unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_time']);
    header('Location: /admin/index.php');
    exit;
}

$csrf  = generate_csrf();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Nieprawidłowy token CSRF.';
    } else {
        $rl = rl_status('admin_2fa');
        if ($rl['blocked']) {
            $error = 'Zbyt wiele prób — odczekaj ' . (int)ceil($rl['remaining'] / 60) . ' min.';
        } else {
            try {
                $stmt = get_db()->prepare(
                    'SELECT id, role, username, totp_secret_enc, totp_secret_iv, totp_enabled
                     FROM users WHERE id = ? LIMIT 1'
                );
                $stmt->execute([$pending_uid]);
                $user = $stmt->fetch();
            } catch (Exception $e) {
                $user = false;
            }

            $secret = ($user && $user['totp_enabled'] && $user['totp_secret_enc'] && $user['totp_secret_iv'])
                ? decrypt_location($user['totp_secret_enc'], $user['totp_secret_iv'])
                : false;

            $code = trim($_POST['code'] ?? '');
            if ($user && $secret !== false && totp_verify($secret, $code)) {
                admin_finish_login((int)$user['id'], $user['role'], $user['username']);
                header('Location: /admin/orders.php');
                exit;
            }
            rl_increment('admin_2fa');
            usleep(random_int(50000, 150000));
            $error = 'Nieprawidłowy kod.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Kod 2FA</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="/admin/style.css">
</head>
<body class="login-page">
<div class="login-wrap">
    <div class="wordmark">DEAD DROP // ADMIN</div>
    <h1>Kod z aplikacji 2FA</h1>
    <?php if ($error): ?>
    <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <?php endif; ?>
    <form method="POST" action="/admin/verify_2fa.php" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-group">
            <label for="code">Kod (6 cyfr)</label>
            <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}"
                   maxlength="6" autocomplete="one-time-code" autofocus>
        </div>
        <button type="submit" class="btn">Zweryfikuj</button>
    </form>
    <a href="/admin/logout.php" class="btn-cancel-link">Anuluj i wyloguj</a>
</div>
</body>
</html>
