<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

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
    // Single source of truth for deletion: row lock + conditional delete in
    // one transaction, event rows removed, filenames pattern-checked before
    // unlink (a hand-rolled copy here once unlinked DB filenames blindly and
    // skipped order_events entirely).
    $res = order_delete_atomic($id);

    if ($res !== null) {
        audit('order_delete', $id, $res['token']);
    }
    $_SESSION['flash']    = $res !== null ? t('admin.orders.flash.deleted') : t('admin.orders.flash.not_found');
    $_SESSION['flash_ok'] = $res !== null;
} catch (Exception $e) {
    log_err('Delete error: ' . $e->getMessage());
    $_SESSION['flash']    = t('admin.orders.flash.delete_failed');
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
