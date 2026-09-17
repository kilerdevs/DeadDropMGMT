<?php
declare(strict_types=1);

// Handler for the order_remove dispatch route. Runs INSIDE the dispatcher
// envelope (security headers, session, admin auth, POST, CSRF, order
// ownership) — direct requests are refused.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'order_remove') {
    http_response_code(404);
    exit;
}

$id = (int)($_POST['id'] ?? 0);
if ($id <= 0) {
    header('Location: /admin/orders.php');
    exit;
}

// Atomic delete under a row lock: token + photo list are captured in the
// same transaction that removes the row; files are swept only after commit.
$res = order_delete_atomic($id);
if ($res !== null) {
    audit('order_remove', $id, $res['token']);
    $_SESSION['flash']    = t('admin.orders.flash.deleted');
    $_SESSION['flash_ok'] = true;
} else {
    $_SESSION['flash']    = t('admin.orders.flash.not_found');
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
