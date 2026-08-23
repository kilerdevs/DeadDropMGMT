<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
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

$id    = (int)($_POST['id']    ?? 0);
$hours = (int)($_POST['hours'] ?? 0);

if ($id <= 0 || $hours <= 0 || $hours > 720) {
    $_SESSION['flash']    = t('admin.orders.flash.invalid_data');
    $_SESSION['flash_ok'] = false;
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
    $db = get_db();
    // Extend from current expiry (or NOW() if already expired), whichever is later
    $db->prepare(
        'UPDATE orders
         SET expires_at = DATE_ADD(GREATEST(COALESCE(expires_at, NOW()), NOW()), INTERVAL ? HOUR)
         WHERE id = ?'
    )->execute([$hours, $id]);

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
