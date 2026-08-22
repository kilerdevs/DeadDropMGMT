<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

set_security_headers(false);
start_secure_session();

// Already logged in → go straight to orders
if (is_admin_logged_in()) {
    header('Location: /admin/orders.php');
    exit;
}

// Password verified, 2FA code still pending → resume there
if (!empty($_SESSION['pending_2fa_user_id']) && (time() - (int)($_SESSION['pending_2fa_time'] ?? 0)) <= 300) {
    header('Location: /admin/verify_2fa.php');
    exit;
}

$csrf = generate_csrf();
$lerr = htmlspecialchars($_SESSION['login_error'] ?? '', ENT_QUOTES, 'UTF-8');
if (isset($_GET['timeout'])) {
    $lerr = 'Sesja wygasła. Zaloguj się ponownie.';
}
unset($_SESSION['login_error']);
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Logowanie</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="/admin/style.css">
</head>
<body class="login-page">
<div class="login-wrap">
    <div class="wordmark">DEAD DROP // <?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?> — ADMIN</div>
    <h1>Logowanie</h1>
    <?php if ($lerr): ?>
    <div class="alert"><?= $lerr ?></div>
    <?php endif; ?>
    <form method="POST" action="/admin/login.php" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-group">
            <label for="username">Nazwa użytkownika</label>
            <input type="text" id="username" name="username"
                   autocomplete="username" autofocus spellcheck="false">
        </div>
        <div class="form-group">
            <label for="password">Hasło</label>
            <input type="password" id="password" name="password" autocomplete="current-password">
        </div>
        <button type="submit" class="btn">Zaloguj się</button>
    </form>
</div>
</body>
</html>
