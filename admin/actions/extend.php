<?php
declare(strict_types=1);

// Handler for the extend dispatch route. Runs INSIDE the dispatcher envelope
// (security headers, session, admin auth, POST, CSRF, order ownership) —
// direct requests are refused.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'extend') {
    http_response_code(404);
    exit;
}

$id    = (int)($_POST['id']    ?? 0);
$hours = (int)($_POST['hours'] ?? 0);

if ($id <= 0 || $hours <= 0 || $hours > 720) {
    $_SESSION['flash']    = t('admin.orders.flash.invalid_data');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/orders.php');
    exit;
}

try {
    $db = get_db();
    // Extend from current expiry (or NOW() if already expired), whichever is later.
    // Delivered-only: arming expiry on a preparing order (normally immortal)
    // would schedule it for silent auto-deletion before it was ever delivered.
    $stmt = $db->prepare(
        'UPDATE orders
         SET expires_at = DATE_ADD(GREATEST(COALESCE(expires_at, NOW()), NOW()), INTERVAL ? HOUR)
         WHERE id = ? AND status = "delivered"'
    );
    $stmt->execute([$hours, $id]);
    if ($stmt->rowCount() === 0) {
        $_SESSION['flash']    = t('admin.orders.flash.not_found');
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/orders.php');
        exit;
    }

    audit('order_extend', $id, null, "+{$hours}h");
    $_SESSION['flash']    = t('admin.orders.flash.extended', ['hours' => (string)$hours]);
    $_SESSION['flash_ok'] = true;
} catch (Exception $e) {
    log_err('Extend error: ' . $e->getMessage());
    $_SESSION['flash']    = t('admin.orders.flash.extend_failed');
    $_SESSION['flash_ok'] = false;
}

$ref = $_POST['ref'] ?? 'orders';
header('Location: /admin/' . ($ref === 'edit' ? 'edit.php?id=' . $id : 'orders.php'));
exit;
