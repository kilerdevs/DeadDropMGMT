<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/order_state.php';
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

// Central authorization check for every courier/admin mutation.
if (!courier_owns_order($id)) {
    $_SESSION['flash']    = t('admin.orders.flash.no_access');
    $_SESSION['flash_ok'] = false;
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
