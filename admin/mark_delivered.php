<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
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
