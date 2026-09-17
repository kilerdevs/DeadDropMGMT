<?php
declare(strict_types=1);

// Handler for the photo_delete dispatch route. Runs INSIDE the dispatcher
// envelope (security headers, session, admin auth, POST, CSRF, order
// ownership) — direct requests are refused.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'photo_delete') {
    http_response_code(404);
    exit;
}

$photo_id = (int)($_POST['photo_id'] ?? 0);
$order_id = (int)($_POST['order_id'] ?? 0);

if ($photo_id <= 0 || $order_id <= 0) {
    header('Location: /admin/edit.php?id=' . $order_id);
    exit;
}

try {
    $db   = get_db();
    // Verify ownership — only delete if photo belongs to the claimed order
    $stmt = $db->prepare('SELECT filename FROM order_photos WHERE id = ? AND order_id = ? LIMIT 1');
    $stmt->execute([$photo_id, $order_id]);
    $photo = $stmt->fetch();

    if ($photo && preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $photo['filename'])) {
        overwrite_and_unlink(dirname(__DIR__, 2) . '/uploads/' . $photo['filename']);
        $db->prepare('DELETE FROM order_photos WHERE id = ?')->execute([$photo_id]);
        audit('photo_delete', $order_id);
    }
} catch (Exception $e) {
    log_err('Photo delete error: ' . $e->getMessage());
}

header('Location: /admin/edit.php?id=' . $order_id);
exit;
