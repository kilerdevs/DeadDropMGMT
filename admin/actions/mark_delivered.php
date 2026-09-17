<?php
declare(strict_types=1);

// Handler for the mark_delivered dispatch route. Runs INSIDE the dispatcher
// envelope (security headers, session, admin auth, POST, CSRF, order
// ownership) — direct requests are refused.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'mark_delivered') {
    http_response_code(404);
    exit;
}

$id = (int)($_POST['id'] ?? 0);
if ($id <= 0) {
    header('Location: /admin/orders.php');
    exit;
}

// Atomic preparing → delivered transition: affected rows decide, so a
// double-submit or a race with another admin is a harmless no-op.
if (order_deliver_atomic($id, order_ttl_hours())) {
    audit('order_deliver', $id);
    $_SESSION['flash']    = t('admin.orders.flash.marked_delivered');
    $_SESSION['flash_ok'] = true;
} else {
    $_SESSION['flash']    = t('admin.orders.flash.already_delivered');
    $_SESSION['flash_ok'] = true;
}

header('Location: /admin/orders.php');
exit;
