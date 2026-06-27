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
    $_SESSION['flash']    = 'Invalid CSRF token.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

$photo_id = (int)($_POST['photo_id'] ?? 0);
$order_id = (int)($_POST['order_id'] ?? 0);

if ($photo_id <= 0 || $order_id <= 0) {
    header('Location: /admin/edit.php?id=' . $order_id);
    exit;
}

if (!courier_owns_order($order_id)) {
    header('Location: /admin/orders.php');
    exit;
}

try {
    $db   = get_db();
    // Verify ownership — only delete if photo belongs to the claimed order
    $stmt = $db->prepare('SELECT filename FROM order_photos WHERE id = ? AND order_id = ? LIMIT 1');
    $stmt->execute([$photo_id, $order_id]);
    $photo = $stmt->fetch();

    if ($photo && preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $photo['filename'])) {
        secure_unlink(dirname(__DIR__) . '/uploads/' . $photo['filename']);
        $db->prepare('DELETE FROM order_photos WHERE id = ?')->execute([$photo_id]);
    }
} catch (Exception $e) {
    log_err('Photo delete error: ' . $e->getMessage());
}

header('Location: /admin/edit.php?id=' . $order_id);
exit;
