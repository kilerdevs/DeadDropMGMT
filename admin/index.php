<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

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

$csrf  = generate_csrf();
$nonce = set_security_headers(false);
$lerr  = htmlspecialchars($_SESSION['login_error'] ?? '', ENT_QUOTES, 'UTF-8');
if (isset($_GET['timeout'])) {
    $lerr = htmlspecialchars(t('admin.login.error.session_expired'), ENT_QUOTES, 'UTF-8');
}
unset($_SESSION['login_error']);
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.login.title') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body class="login-page">
<div class="login-wrap">
    <div class="wordmark">DEAD DROP // <?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?> — ADMIN</div>
    <h1><?= t('admin.login.title') ?></h1>
    <?php if ($lerr): ?>
    <div class="alert"><?= $lerr ?></div>
    <?php endif; ?>
    <form method="POST" action="/admin/login.php" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-group">
            <label for="username"><?= t('admin.login.username_label') ?></label>
            <input type="text" id="username" name="username"
                   autocomplete="username" autofocus spellcheck="false">
        </div>
        <div class="login-hint" id="first-time-hint" hidden><?= t('admin.login.hint.first_time') ?></div>
        <div class="form-group" id="pw-group">
            <label for="password"><?= t('admin.login.password_label') ?></label>
            <input type="password" id="password" name="password" autocomplete="current-password">
        </div>
        <button type="submit" class="btn"><?= t('admin.login.submit_button') ?></button>
    </form>
</div>
<script nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
(function () {
    var u    = document.getElementById('username');
    var grp  = document.getElementById('pw-group');
    var pw   = document.getElementById('password');
    var hint = document.getElementById('first-time-hint');
    if (!u || !grp || !pw || !hint) return;

    var csrf  = <?= json_encode($csrf) ?>;
    var timer = null;

    function showPw() {
        grp.style.display = '';
        hint.hidden = true;
    }
    function hidePw() {
        if (grp.style.display !== 'none') {
            grp.style.display = 'none';
            pw.value = ''; // never submit a stale autofilled value
        }
        hint.hidden = false;
    }

    function check() {
        var name = u.value.trim();
        if (name === '') { showPw(); return; }
        fetch('/admin/check_setup.php?username=' + encodeURIComponent(name), {
            headers: { 'X-CSRF-Token': csrf }
        }).then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
            // Ignore stale responses (user kept typing) — a newer request is in flight.
            if (!d || u.value.trim() !== name) return;
            d.needs_setup ? hidePw() : showPw();
        }).catch(function () { /* fail open: password field stays visible */ });
    }

    u.addEventListener('input', function () {
        clearTimeout(timer);
        timer = setTimeout(check, 250);
    });
    u.addEventListener('blur', check);
})();
</script>
</body>
</html>
