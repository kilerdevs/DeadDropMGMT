<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';

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

$id = (int)($_POST['id'] ?? 0);
if ($id <= 0) {
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
    $db   = get_db();
    $ttl_hours = order_ttl_hours();
    $stmt = $db->prepare(
        'UPDATE orders
         SET status = "delivered", delivered_at = NOW(),
             expires_at = DATE_ADD(NOW(), INTERVAL ? HOUR)
         WHERE id = ? AND status = "preparing"'
    );
    $stmt->execute([$ttl_hours, $id]);

    if ($stmt->rowCount() > 0) {
        audit('order_deliver', $id);
    }
    $_SESSION['flash']    = $stmt->rowCount() > 0 ? 'Status zmieniony na: dostarczone.' : 'Zamówienie już oznaczone jako dostarczone.';
    $_SESSION['flash_ok'] = true;
} catch (Exception $e) {
    log_err('Mark delivered error: ' . $e->getMessage());
    $_SESSION['flash']    = 'Nie udało się zmienić statusu.';
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
