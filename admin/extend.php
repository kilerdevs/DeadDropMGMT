<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

set_security_headers(true);
start_secure_session();
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/orders.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['flash']    = 'Nieprawidłowy token CSRF.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

$id    = (int)($_POST['id']    ?? 0);
$hours = (int)($_POST['hours'] ?? 0);

if ($id <= 0 || $hours <= 0 || $hours > 720) {
    $_SESSION['flash']    = 'Nieprawidłowe dane.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

if (!courier_owns_order($id)) {
    $_SESSION['flash']    = 'Brak dostępu do tego zamówienia.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

try {
    $db = get_db();
    // Extend from current expiry (or NOW() if already expired), whichever is later
    $db->prepare(
        'UPDATE orders
         SET expires_at = DATE_ADD(GREATEST(COALESCE(expires_at, NOW()), NOW()), INTERVAL ? HOUR)
         WHERE id = ?'
    )->execute([$hours, $id]);

    $_SESSION['flash']    = "Termin przedłużony o {$hours}h.";
    $_SESSION['flash_ok'] = true;
} catch (Exception $e) {
    log_err('Extend error: ' . $e->getMessage());
    $_SESSION['flash']    = 'Nie udało się przedłużyć terminu.';
    $_SESSION['flash_ok'] = false;
}

$ref = $_POST['ref'] ?? 'orders';
header('Location: /admin/' . ($ref === 'edit' ? 'edit.php?id=' . $id : 'orders.php'));
exit;
