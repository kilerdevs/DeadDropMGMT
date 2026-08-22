<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';
set_security_headers(false);
start_secure_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/index.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['login_error'] = 'Nieprawidłowe żądanie. Spróbuj ponownie.';
    header('Location: /admin/index.php');
    exit;
}

// ── Rate limit failed attempts (IP-based, configurable in Ustawienia) ────────
require_once dirname(__DIR__) . '/includes/settings.php';
$rl = rl_status('admin_login');
if ($rl['blocked']) {
    $_SESSION['login_error'] = 'Zbyt wiele nieudanych prób. Odczekaj ' . (int)ceil($rl['remaining'] / 60) . ' min.';
    header('Location: /admin/index.php');
    exit;
}

$username = trim($_POST['username'] ?? '');
$password = (string)($_POST['password'] ?? '');

switch (admin_login($username, $password)) {
    case 'ok':
        rl_reset('admin_login');
        header('Location: /admin/orders.php');
        exit;
    case 'need_2fa':
        rl_reset('admin_login');
        header('Location: /admin/verify_2fa.php');
        exit;
}

usleep(random_int(50000, 150000));

rl_increment('admin_login');
$_SESSION['login_error'] = 'Nieprawidłowe dane logowania.';
header('Location: /admin/index.php');
exit;
