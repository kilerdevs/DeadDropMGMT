<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';

start_secure_session();
require_admin();
$csp_nonce = set_security_headers(true);

// ── Inline delete handler ─────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete') {
    if (verify_csrf($_POST['csrf_token'] ?? '')) {
        $del_id = (int)($_POST['id'] ?? 0);
        if ($del_id > 0 && courier_owns_order($del_id)) {
            try {
                $del_db = get_db();
                $tq = $del_db->prepare('SELECT order_token FROM orders WHERE id = ? LIMIT 1');
                $tq->execute([$del_id]);
                $del_token = $tq->fetchColumn() ?: null;

                $pq = $del_db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
                $pq->execute([$del_id]);
                foreach ($pq->fetchAll() as $ph) {
                    secure_unlink(dirname(__DIR__) . '/uploads/' . $ph['filename']);
                }
                $dq = $del_db->prepare('DELETE FROM orders WHERE id = ?');
                $dq->execute([$del_id]);
                $affected = $dq->rowCount();
                if ($affected > 0) {
                    audit('order_delete', $del_id, $del_token);
                }
                $_SESSION['flash']    = $affected > 0 ? 'Zamówienie usunięte.' : 'Zamówienie nie istnieje.';
                $_SESSION['flash_ok'] = $affected > 0;
            } catch (Throwable $e) {
                log_err('Order delete: ' . $e->getMessage());
                $_SESSION['flash']    = 'Nie udało się usunąć zamówienia.';
                $_SESSION['flash_ok'] = false;
            }
        } else {
            $_SESSION['flash']    = 'Brak dostępu do tego zamówienia.';
            $_SESSION['flash_ok'] = false;
        }
    } else {
        $_SESSION['flash']    = 'Nieprawidłowy token CSRF.';
        $_SESSION['flash_ok'] = false;
    }
    header('Location: /admin/orders.php');
    exit;
}

$flash    = $_SESSION['flash']    ?? '';
$flash_ok = $_SESSION['flash_ok'] ?? false;
unset($_SESSION['flash'], $_SESSION['flash_ok']);

// ── Courier filter (owner only) ───────────────────────────────────────────────
$filter_courier = is_owner() ? (int)($_GET['courier'] ?? 0) : 0;

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

    $stmt = $db->prepare(
        "SELECT o.id, o.order_token, o.status, o.created_at, o.delivered_at, o.expires_at,
                o.pickup_password_enc, o.pickup_password_iv,
                o.created_by,
                u.username AS courier_name,
                COUNT(p.id) AS photo_count
         FROM orders o
         LEFT JOIN users u ON u.id = o.created_by
         LEFT JOIN order_photos p ON p.order_id = o.id
         {$where_sql}
         GROUP BY o.id
         ORDER BY o.created_at DESC"
    );
    $stmt->execute($where_args);
    $rows = $stmt->fetchAll();

    $orders = [];
    foreach ($rows as $o) {
        $pw = null;
        if (!empty($o['pickup_password_enc']) && !empty($o['pickup_password_iv'])) {
            $dec = decrypt_location($o['pickup_password_enc'], $o['pickup_password_iv']);
            $pw  = ($dec !== false) ? $dec : null;
        }
        $o['pw_plain'] = $pw;
        $orders[]      = $o;
    }
} catch (Throwable $e) {
    log_err('Admin fetch: ' . $e->getMessage());
    $orders   = [];
    $couriers = [];
    $flash    = 'Nie udało się załadować zamówień.';
    $flash_ok = false;
}

$csrf   = generate_csrf();
$_active = 'orders';
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Zamówienia</title>
<meta name="dd-ttl" content="<?= (int)order_ttl_hours() ?>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading">Zamówienia</div>

        <?php if ($flash): ?>
        <div class="flash <?= $flash_ok ? 'ok' : '' ?>"><?= htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <?php if (is_owner() && !empty($couriers)): ?>
        <!-- ── Courier filter ─────────────────────────────────────────── -->
        <div class="courier-filter">
            <a class="filter-btn <?= $filter_courier === 0 ? 'active' : '' ?>" href="/admin/orders.php">Wszystkie</a>
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
            Moje zamówienia (<?= count($orders) ?>)
            <?php elseif ($filter_courier > 0): ?>
            Zamówienia kuriera (<?= count($orders) ?>)
            <?php else: ?>
            Wszystkie zamówienia (<?= count($orders) ?>)
            <?php endif; ?>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Token</th>
                        <th>Status</th>
                        <?php if (is_owner()): ?><th>Kurier</th><?php endif; ?>
                        <th>Zdjęcia</th>
                        <th>Wygasa za</th>
                        <th>Dostarczone</th>
                        <th>Akcje</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($orders)): ?>
                    <tr class="empty-row"><td colspan="<?= is_owner() ? 7 : 6 ?>">BRAK ZAMÓWIEŃ</td></tr>
                <?php else: foreach ($orders as $o): ?>
                    <tr>
                        <td><span class="token"><?= htmlspecialchars($o['order_token'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td>
                            <span class="badge <?= $o['status'] === 'delivered' ? 'delivered' : '' ?>">
                                <?= $o['status'] === 'delivered' ? 'DOSTARCZONE' : 'W PRZYGOTOWANIU' ?>
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
                                <a class="action-btn" href="/admin/edit.php?id=<?= (int)$o['id'] ?>">Edytuj</a>

                                <button class="action-btn"
                                        data-copy
                                        data-token="<?= htmlspecialchars($o['order_token'], ENT_QUOTES, 'UTF-8') ?>"
                                        data-code="<?= htmlspecialchars($o['pw_plain'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                                    Kopiuj
                                </button>

                                <?php if ($o['status'] === 'preparing'): ?>
                                <form class="inline-form" method="POST" action="/admin/mark_delivered.php">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="id" value="<?= (int)$o['id'] ?>">
                                    <button class="action-btn action-btn--deliver">Dostarczone ✓</button>
                                </form>
                                <?php endif; ?>

                                <form class="inline-form" method="POST" action="/admin/orders.php"
                                      data-confirm="Usunąć zamówienie <?= htmlspecialchars($o['order_token'], ENT_QUOTES, 'UTF-8') ?>?">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="id" value="<?= (int)$o['id'] ?>">
                                    <button class="action-btn action-btn--danger">Usuń</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
<script src="/admin/admin.js"></script>
</body>
</html>
