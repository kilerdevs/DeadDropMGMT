<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';

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
    $db     = get_db();
    $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
    $photos->execute([$id]);
    foreach ($photos->fetchAll() as $ph) {
        secure_unlink(dirname(__DIR__) . '/uploads/' . $ph['filename']);
    }

    // Wipe sensitive columns before row removal
    $db->prepare(
        'UPDATE orders SET
            location_encrypted = "", location_iv = "",
            pickup_password_hash = "", pickup_password_enc = NULL, pickup_password_iv = NULL,
            notes = NULL
         WHERE id = ?'
    )->execute([$id]);

    $stmt = $db->prepare('DELETE FROM orders WHERE id = ?');
    $stmt->execute([$id]);

    $_SESSION['flash']    = $stmt->rowCount() > 0 ? 'Zamówienie usunięte.' : 'Zamówienie nie istnieje.';
    $_SESSION['flash_ok'] = $stmt->rowCount() > 0;
} catch (Exception $e) {
    log_err('Delete error: ' . $e->getMessage());
    $_SESSION['flash']    = 'Nie udało się usunąć zamówienia.';
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
