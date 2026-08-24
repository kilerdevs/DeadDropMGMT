<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

$page     = max(1, (int)($_GET['page'] ?? 1));
$per_page = 100;
$offset   = ($page - 1) * $per_page;

try {
    $db    = get_db();
    $total = (int)$db->query('SELECT COUNT(*) FROM audit_log')->fetchColumn();
    $stmt  = $db->prepare(
        'SELECT username, action, order_id, order_token, detail, ip_address, created_at
         FROM audit_log ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?'
    );
    $stmt->bindValue(1, $per_page, PDO::PARAM_INT);
    $stmt->bindValue(2, $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();
} catch (Exception $e) {
    log_err('Audit log page: ' . $e->getMessage());
    $rows  = [];
    $total = 0;
}
$pages = max(1, (int)ceil($total / $per_page));
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.sidebar.audit_log') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = 'audit'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading"><?= t('admin.audit.heading') ?></div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr><th><?= t('admin.analytics.th.time') ?></th><th><?= t('admin.audit.th.user') ?></th><th><?= t('admin.audit.th.action') ?></th><th><?= t('admin.audit.th.order') ?></th><th><?= t('admin.audit.th.details') ?></th><th><?= t('admin.audit.th.ip') ?></th></tr>
                </thead>
                <tbody>
                <?php if (empty($rows)): ?>
                    <tr class="empty-row"><td colspan="6"><?= t('admin.audit.no_entries') ?></td></tr>
                <?php else: foreach ($rows as $r): ?>
                    <tr>
                        <td class="meta td-muted"><?= htmlspecialchars($r['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= htmlspecialchars($r['username'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><span class="token"><?= htmlspecialchars($r['action'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td class="td-muted"><?= htmlspecialchars($r['order_token'] ?? ($r['order_id'] !== null ? '#' . $r['order_id'] : '—'), ENT_QUOTES, 'UTF-8') ?></td>
                        <td class="td-muted"><?= htmlspecialchars($r['detail'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td class="meta td-muted"><?= htmlspecialchars($r['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                    </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($pages > 1): ?>
        <div class="log-toolbar">
            <span class="td-muted"><?= t('admin.audit.page_summary', ['page' => $page, 'pages' => $pages, 'total' => number_format($total)]) // nosemgrep: int params, escaped inside t() ?></span>
            <div class="log-toolbar-actions">
                <?php if ($page > 1): ?><a class="action-btn" href="?page=<?= htmlspecialchars((string)($page - 1), ENT_QUOTES, 'UTF-8') ?>">&larr; <?= t('admin.analytics.prev_page') ?></a><?php endif; ?>
                <?php if ($page < $pages): ?><a class="action-btn" href="?page=<?= htmlspecialchars((string)($page + 1), ENT_QUOTES, 'UTF-8') ?>"><?= t('admin.analytics.next_page') ?> &rarr;</a><?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
    </main>
</div>
<script src="/admin/admin.js"></script>
</body>
</html>
