<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

set_security_headers(true);
start_secure_session();
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/orders.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['flash']    = t('admin.common.invalid_csrf');
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
    $_SESSION['flash']    = t('admin.orders.flash.no_access');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

try {
    $db  = get_db();
    $tok = $db->prepare('SELECT order_token FROM orders WHERE id = ? LIMIT 1');
    $tok->execute([$id]);
    $order_token = $tok->fetchColumn() ?: null;

    $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
    $photos->execute([$id]);
    foreach ($photos->fetchAll() as $ph) {
        overwrite_and_unlink(dirname(__DIR__) . '/uploads/' . $ph['filename']);
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

    if ($stmt->rowCount() > 0) {
        audit('order_delete', $id, $order_token);
    }
    $_SESSION['flash']    = $stmt->rowCount() > 0 ? t('admin.orders.flash.deleted') : t('admin.orders.flash.not_found');
    $_SESSION['flash_ok'] = $stmt->rowCount() > 0;
} catch (Exception $e) {
    log_err('Delete error: ' . $e->getMessage());
    $_SESSION['flash']    = t('admin.orders.flash.delete_failed');
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
