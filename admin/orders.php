<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

start_secure_session();
require_admin();
$csp_nonce = set_security_headers(true);

// ── Inline delete handler ─────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete') {
    if (verify_csrf($_POST['csrf_token'] ?? '')) {
        $del_id = (int)($_POST['id'] ?? 0);
        if ($del_id > 0 && courier_owns_order($del_id)) {
            // Same atomic delete-under-lock core as order_close.
            $res = order_delete_atomic($del_id);
            if ($res !== null) {
                audit('order_delete', $del_id, $res['token']);
                $_SESSION['flash']    = t('admin.orders.flash.deleted');
                $_SESSION['flash_ok'] = true;
            } else {
                $_SESSION['flash']    = t('admin.orders.flash.not_found');
                $_SESSION['flash_ok'] = false;
            }
        } else {
            $_SESSION['flash']    = t('admin.orders.flash.no_access');
            $_SESSION['flash_ok'] = false;
        }
    } else {
        $_SESSION['flash']    = t('admin.common.invalid_csrf');
        $_SESSION['flash_ok'] = false;
    }
    header('Location: /admin/orders.php');
    exit;
}

[$flash, $flash_ok] = flash_take();

// ── Courier filter (owner only) ───────────────────────────────────────────────
$filter_courier = is_owner() ? (int)($_GET['courier'] ?? 0) : 0;

// Paginated like audit_log.php: preparing orders never expire, so the list
// only grows — and every row costs an AES-GCM decrypt. 50 per page keeps
// the unbounded GROUP BY + decrypt-all off the request path.
$page     = max(1, (int)($_GET['page'] ?? 1));
$per_page = 50;

try {
    $db = get_db();

    // Couriers listed for the filter dropdown (owner only)
    $couriers = is_owner()
        ? $db->query('SELECT id, username FROM users WHERE role = "courier" ORDER BY username')->fetchAll()
        : [];

    // Build WHERE clause based on role and filter
    if (is_courier()) {
        $where_sql  = 'WHERE o.created_by = ?';
        $where_args = [current_user_id()];
    } elseif ($filter_courier > 0) {
        $where_sql  = 'WHERE o.created_by = ?';
        $where_args = [$filter_courier];
    } else {
        $where_sql  = '';
        $where_args = [];
    }

    $cntStmt = $db->prepare("SELECT COUNT(*) FROM orders o {$where_sql}");
    $cntStmt->execute($where_args);
    $total = (int)$cntStmt->fetchColumn();
    $pages = max(1, (int)ceil($total / $per_page));
    // Clamp BEFORE the data query: an out-of-range ?page= must render the
    // last valid page, not a permanently empty one.
    $page   = min($page, $pages);
    $offset = ($page - 1) * $per_page;

    $stmt = $db->prepare(
        "SELECT o.id, o.token_hmac, o.token_enc, o.token_iv, o.status, o.created_at, o.delivered_at, o.expires_at,
                o.created_by,
                u.username AS courier_name,
                COUNT(p.id) AS photo_count
         FROM orders o
         LEFT JOIN users u ON u.id = o.created_by
         LEFT JOIN order_photos p ON p.order_id = o.id
         {$where_sql}
         GROUP BY o.id
         ORDER BY o.created_at DESC, o.id DESC LIMIT ? OFFSET ?"
    );
    foreach ($where_args as $i => $arg) {
        $stmt->bindValue($i + 1, $arg, PDO::PARAM_INT);
    }
    $stmt->bindValue(count($where_args) + 1, $per_page, PDO::PARAM_INT);
    $stmt->bindValue(count($where_args) + 2, $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();
    // The token is stored encrypted (ADR-019); open it for display here so the
    // template below stays a plain read of $o['order_token'].
    foreach ($rows as &$row) {
        $row['order_token'] = token_label(order_token_plain($row), $row['token_hmac']);
    }
    unset($row);

    // Pickup passwords are hash-only since the recovery copy was removed:
    // they exist once at creation and are otherwise replaced, not displayed.
    $orders = $rows;
} catch (Throwable $e) {
    log_err('Admin fetch: ' . $e->getMessage());
    $orders   = [];
    $couriers = [];
    $total    = 0;
    $pages    = 1;
    $flash    = t('admin.orders.flash.load_failed');
    $flash_ok = false;
}

$csrf   = generate_csrf();
$_active = 'orders';
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.orders.title') ?></title>
<link rel="stylesheet" href="/admin/style.css?v=<?= admin_css_ver() ?>">
</head>
<body>
<div class="shell">

    <?php require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading"><?= t('admin.orders.title') ?></div>

        <?php if ($flash): ?>
        <!-- Flash is always t()-built (HTML-safe: static text + escaped params) —
             echo raw. htmlspecialchars() here would double-escape every value
             t() already escaped (e.g. a generated password containing &). -->
        <div class="flash <?= $flash_ok ? 'ok' : '' ?>"><?= $flash ?></div>
        <?php endif; ?>

        <?php if (is_owner() && !empty($couriers)): ?>
        <!-- ── Courier filter ─────────────────────────────────────────── -->
        <div class="courier-filter">
            <a class="filter-btn <?= $filter_courier === 0 ? 'active' : '' ?>" href="/admin/orders.php"><?= t('admin.orders.filter_all') ?></a>
            <?php foreach ($couriers as $c): ?>
            <a class="filter-btn <?= $filter_courier === (int)$c['id'] ? 'active' : '' ?>"
               href="/admin/orders.php?courier=<?= (int)$c['id'] ?>">
                <?= htmlspecialchars($c['username'], ENT_QUOTES, 'UTF-8') ?>
            </a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <div class="section-label">
            <?php if (is_courier()): ?>
            <?= t('admin.orders.section.mine', ['n' => $total]) ?>
            <?php elseif ($filter_courier > 0): ?>
            <?= t('admin.orders.section.courier', ['n' => $total]) ?>
            <?php else: ?>
            <?= t('admin.orders.section.all', ['n' => $total]) ?>
            <?php endif; ?>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th><?= t('admin.orders.th.token') ?></th>
                        <th><?= t('admin.orders.th.status') ?></th>
                        <?php if (is_owner()): ?><th><?= t('admin.orders.th.courier') ?></th><?php endif; ?>
                        <th><?= t('admin.orders.th.photos') ?></th>
                        <th><?= t('admin.orders.th.expires') ?></th>
                        <th><?= t('admin.orders.th.delivered') ?></th>
                        <th><?= t('admin.orders.th.actions') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($orders)): ?>
                    <tr class="empty-row"><td colspan="<?= is_owner() ? 7 : 6 ?>"><?= t('admin.orders.empty') ?></td></tr>
                <?php else: foreach ($orders as $o): ?>
                    <tr>
                        <td><span class="token"><?= htmlspecialchars($o['order_token'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td>
                            <span class="badge <?= $o['status'] === 'delivered' ? 'delivered' : '' ?>">
                                <?= $o['status'] === 'delivered' ? t('public.status.delivered') : t('public.status.preparing') ?>
                            </span>
                        </td>
                        <?php if (is_owner()): ?>
                        <td>
                            <?php if ($o['courier_name']): ?>
                            <span class="courier-tag"><?= htmlspecialchars($o['courier_name'], ENT_QUOTES, 'UTF-8') ?></span>
                            <?php else: ?>
                            <span class="td-muted">—</span>
                            <?php endif; ?>
                        </td>
                        <?php endif; ?>
                        <td class="td-muted"><?= (int)$o['photo_count'] ?></td>
                        <td>
                            <?php if ($o['status'] === 'preparing'): ?>
                            <span class="td-muted">—</span>
                            <?php else:
                                $exp_ts  = $o['expires_at'] ? (int)strtotime($o['expires_at']) : 0;
                                $exp_rem = $exp_ts > 0 ? $exp_ts - time() : 0;
                                $exp_cls = $exp_rem <= 0 ? 'urgent' : ($exp_rem < 3600 ? 'urgent' : ($exp_rem < 21600 ? 'warning' : ''));
                            ?>
                            <span class="expiry-timer <?= $exp_cls ?>"
                                  <?= $exp_ts > 0 ? 'data-expires="'.$exp_ts.'"' : '' ?>>
                                <?= $exp_ts > 0 ? htmlspecialchars(format_countdown($exp_rem), ENT_QUOTES, 'UTF-8') : '—' ?>
                            </span>
                            <?php endif; ?>
                        </td>
                        <td class="meta td-muted">
                            <?= $o['delivered_at'] ? htmlspecialchars($o['delivered_at'], ENT_QUOTES, 'UTF-8') : '—' ?>
                        </td>
                        <td>
                            <div class="order-actions">
                                <a class="action-btn" href="/admin/edit.php?id=<?= (int)$o['id'] ?>"><?= t('admin.orders.edit_button') ?></a>

                                <button class="action-btn"
                                        data-copy
                                        data-token="<?= htmlspecialchars($o['order_token'], ENT_QUOTES, 'UTF-8') ?>">
                                    <?= t('admin.orders.copy_button') ?>
                                </button>

                                <?php if ($o['status'] === 'preparing'): ?>
                                <form class="inline-form" method="POST" action="/admin/mark_delivered.php">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="id" value="<?= (int)$o['id'] ?>">
                                    <button class="action-btn action-btn--deliver"><?= t('admin.orders.deliver_button') ?></button>
                                </form>
                                <?php endif; ?>

                                <form class="inline-form" method="POST" action="/admin/orders.php"
                                      data-confirm="<?= htmlspecialchars(t('admin.orders.delete_confirm', ['token' => $o['order_token']]), ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="id" value="<?= (int)$o['id'] ?>">
                                    <button class="action-btn action-btn--danger"><?= t('admin.orders.delete_button') ?></button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($pages > 1): ?>
        <div class="log-toolbar">
            <span class="td-muted"><?= htmlspecialchars(t('admin.audit.page_summary', ['page' => $page, 'pages' => $pages, 'total' => number_format($total)]), ENT_QUOTES, 'UTF-8') ?></span>
            <div class="log-toolbar-actions">
                <?php
                // Raw & here: the whole URL is escaped below (an &amp; entity
                // would double-encode). Both values are ints by construction.
                $page_qs = $filter_courier > 0 ? '?courier=' . $filter_courier . '&page=' : '?page=';
                if ($page > 1): ?><a class="action-btn" href="<?= htmlspecialchars($page_qs . ($page - 1), ENT_QUOTES, 'UTF-8') ?>">&larr; <?= t('admin.analytics.prev_page') ?></a><?php endif; ?>
                <?php if ($page < $pages): ?><a class="action-btn" href="<?= htmlspecialchars($page_qs . ($page + 1), ENT_QUOTES, 'UTF-8') ?>"><?= t('admin.analytics.next_page') ?> &rarr;</a><?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
    </main>
</div>
<script src="/admin/admin.js?v=<?= asset_ver('/admin/admin.js') ?>"></script>
</body>
</html>
