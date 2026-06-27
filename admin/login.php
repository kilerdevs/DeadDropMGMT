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

// ── Rate limit failed attempts (session-based, 5 attempts / 15 min) ──────────
$_lf_cnt  = (int)($_SESSION['lf_count'] ?? 0);
$_lf_time = (int)($_SESSION['lf_time']  ?? 0);
if ($_lf_cnt > 0 && (time() - $_lf_time) >= 900) {
    $_lf_cnt = 0;
    unset($_SESSION['lf_count'], $_SESSION['lf_time']);
}
if ($_lf_cnt >= 5) {
    $remaining = max(1, (int)ceil((900 - (time() - $_lf_time)) / 60));
    $_SESSION['login_error'] = 'Zbyt wiele nieudanych prób. Odczekaj ' . $remaining . ' min.';
    header('Location: /admin/index.php');
    exit;
}

$username = trim($_POST['username'] ?? '');
$password = (string)($_POST['password'] ?? '');

if (admin_login($username, $password)) {
    unset($_SESSION['lf_count'], $_SESSION['lf_time']);
    header('Location: /admin/orders.php');
    exit;
}

usleep(random_int(50000, 150000));

$_lf_cnt++;
$_SESSION['lf_count'] = $_lf_cnt;
if (!isset($_SESSION['lf_time'])) {
    $_SESSION['lf_time'] = time();
}
$_SESSION['login_error'] = 'Nieprawidłowe dane logowania.';
header('Location: /admin/index.php');
exit;
