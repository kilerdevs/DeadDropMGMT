<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/analytics.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

// ── Period filter ─────────────────────────────────────────────────────────────
$period = $_GET['period'] ?? '7d';
if (!in_array($period, ['24h', '7d', '30d', 'all'], true)) $period = '7d';

if ($period === '24h') {
    $date_cond = "AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)";
} elseif ($period === '7d') {
    $date_cond = "AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
} elseif ($period === '30d') {
    $date_cond = "AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
} else {
    $date_cond = "";
}
$date_cond_e = str_replace('created_at', 'e.created_at', $date_cond);

// ── Pagination ────────────────────────────────────────────────────────────────
$page     = max(1, (int)($_GET['page'] ?? 1));
$per_page = 50;
$offset   = ($page - 1) * $per_page;

// ── UA parser ─────────────────────────────────────────────────────────────────
function parse_browser(string $ua): string {
    if ($ua === '') return '—';
    $mobile = (bool)preg_match('/Mobile|Android|iPhone|iPad/i', $ua);
    if     (strpos($ua, 'Firefox/') !== false)                                   $b = 'Firefox';
    elseif (strpos($ua, 'Edg/') !== false)                                       $b = 'Edge';
    elseif (strpos($ua, 'Chrome/') !== false)                                    $b = 'Chrome';
    elseif (strpos($ua, 'Safari/') !== false && strpos($ua, 'Chrome') === false) $b = 'Safari';
    elseif (strpos($ua, 'curl/') !== false)                                      $b = 'curl';
    elseif (preg_match('/bot|spider|crawl/i', $ua))                              $b = 'Bot';
    else                                                                         $b = t('admin.analytics.browser.other');
    return $b . ' · ' . ($mobile ? t('admin.analytics.browser.mobile') : t('admin.analytics.browser.desktop'));
}

// ── Queries ───────────────────────────────────────────────────────────────────
try {
    $db = get_db();

    // Summary counts
    $summary = $db->query(
        "SELECT event_type, COUNT(*) AS cnt FROM order_events
         WHERE event_type NOT LIKE 'admin_%' $date_cond
         GROUP BY event_type"
    )->fetchAll();
    $counts = [];
    foreach ($summary as $r) { $counts[$r['event_type']] = (int)$r['cnt']; }

    // Unique visitor IPs
    $unique_ips = (int)$db->query(
        "SELECT COUNT(DISTINCT ip_address) FROM order_events
         WHERE event_type NOT LIKE 'admin_%' $date_cond"
    )->fetchColumn();

    // Daily breakdown (fixed 14 days regardless of period filter)
    $daily = $db->query(
        "SELECT DATE(created_at) AS dzien,
                SUM(event_type = 'lookup')         AS wyszukania,
                SUM(event_type = 'unlock_success') AS odblokowania,
                SUM(event_type = 'unlock_fail')    AS bledy,
                SUM(event_type = 'received')       AS odbiory
         FROM order_events
         WHERE event_type NOT LIKE 'admin_%'
           AND created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
         GROUP BY DATE(created_at)
         ORDER BY dzien DESC"
    )->fetchAll();

    // Per-order activity
    $per_order = $db->query(
        "SELECT e.order_token,
                SUM(e.event_type = 'lookup')         AS wyszukania,
                SUM(e.event_type = 'unlock_success') AS odblokowania,
                SUM(e.event_type = 'unlock_fail')    AS bledy,
                MAX(e.created_at)                    AS ostatnia_aktywnosc,
                o.status
         FROM order_events e
         LEFT JOIN orders o ON o.order_token = e.order_token
         WHERE e.event_type NOT LIKE 'admin_%'
           AND e.order_token IS NOT NULL
           $date_cond_e
         GROUP BY e.order_token
         ORDER BY ostatnia_aktywnosc DESC
         LIMIT 25"
    )->fetchAll();

    // Suspicious IPs (failed unlocks)
    $hot_ips = $db->query(
        "SELECT ip_address, COUNT(*) AS cnt, MAX(created_at) AS ostatnia
         FROM order_events
         WHERE event_type = 'unlock_fail' $date_cond
         GROUP BY ip_address
         ORDER BY cnt DESC LIMIT 15"
    )->fetchAll();

    // Successful unlock IPs
    $unlock_ips = $db->query(
        "SELECT ip_address, COUNT(*) AS cnt, MAX(created_at) AS ostatnia
         FROM order_events
         WHERE event_type = 'unlock_success' $date_cond
         GROUP BY ip_address ORDER BY cnt DESC LIMIT 15"
    )->fetchAll();

    // Total event count for pagination
    $total_events = (int)$db->query(
        "SELECT COUNT(*) FROM order_events
         WHERE event_type NOT LIKE 'admin_%' $date_cond"
    )->fetchColumn();
    $total_pages = max(1, (int)ceil($total_events / $per_page));
    $page = min($page, $total_pages);

    // Recent events (paginated)
    $recent = $db->query(
        "SELECT e.event_type, e.order_token, e.ip_address, e.user_agent, e.created_at
         FROM order_events e
         WHERE e.event_type NOT LIKE 'admin_%' $date_cond_e
         ORDER BY e.created_at DESC
         LIMIT " . (int)$per_page . " OFFSET " . (int)$offset
    )->fetchAll();

} catch (Exception $e) {
    log_err('Analytics: ' . $e->getMessage());
    $recent = []; $hot_ips = []; $unlock_ips = []; $counts = [];
    $unique_ips = 0; $daily = []; $per_order = [];
    $total_events = 0; $total_pages = 1;
}

$labels = [
    'lookup'         => t('admin.analytics.event.lookup'),
    'unlock_success' => t('admin.analytics.event.unlock_success'),
    'unlock_fail'    => t('admin.analytics.event.unlock_fail'),
    'received'       => t('admin.analytics.event.received'),
];

function period_url(string $p, int $page = 1): string {
    $q = http_build_query(['period' => $p, 'page' => $page]);
    return '/admin/analytics.php?' . $q;
}

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.analytics.title') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = 'analytics'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading"><?= t('admin.analytics.title') ?></div>

        <?php if (!analytics_enabled()): ?>
        <div class="flash">
            <?= t('admin.analytics.disabled_notice') ?>
            <a href="/admin/settings.php" class="flash-link"><?= t('admin.analytics.enable_link') ?></a>
        </div>
        <?php endif; ?>

        <!-- ── Period filter ─────────────────────────────────────────────── -->
        <div class="period-filter">
            <a class="period-btn <?= $period === '24h'  ? 'active' : '' ?>" href="<?= period_url('24h')  ?>"><?= t('admin.analytics.period.24h') ?></a>
            <a class="period-btn <?= $period === '7d'   ? 'active' : '' ?>" href="<?= period_url('7d')   ?>"><?= t('admin.analytics.period.7d') ?></a>
            <a class="period-btn <?= $period === '30d'  ? 'active' : '' ?>" href="<?= period_url('30d')  ?>"><?= t('admin.analytics.period.30d') ?></a>
            <a class="period-btn <?= $period === 'all'  ? 'active' : '' ?>" href="<?= period_url('all')  ?>"><?= t('admin.analytics.period.all') ?></a>
        </div>

        <!-- ── Summary cards ─────────────────────────────────────────────── -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['lookup'] ?? 0) ?></div>
                <div class="stat-label"><?= t('admin.analytics.stat.lookups') ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['unlock_success'] ?? 0) ?></div>
                <div class="stat-label"><?= t('admin.analytics.stat.unlocks') ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['unlock_fail'] ?? 0) ?></div>
                <div class="stat-label"><?= t('admin.analytics.stat.failed_pw') ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['received'] ?? 0) ?></div>
                <div class="stat-label"><?= t('admin.analytics.stat.confirmations') ?></div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($unique_ips) ?></div>
                <div class="stat-label"><?= t('admin.analytics.stat.unique_ips') ?></div>
            </div>
        </div>

        <!-- ── Daily breakdown ───────────────────────────────────────────── -->
        <?php if (!empty($daily)): ?>
        <div class="divider"></div>
        <div class="section-label"><?= t('admin.analytics.daily_section') ?></div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th><?= t('admin.analytics.th.day') ?></th>
                        <th><?= t('admin.analytics.th.lookups') ?></th>
                        <th><?= t('admin.analytics.th.unlocks') ?></th>
                        <th><?= t('admin.analytics.stat.failed_pw') ?></th>
                        <th><?= t('admin.analytics.th.confirmations') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($daily as $d): ?>
                <tr>
                    <td class="token"><?= htmlspecialchars($d['dzien'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="td-muted"><?= (int)$d['wyszukania'] ?></td>
                    <td class="td-muted"><?= (int)$d['odblokowania'] ?></td>
                    <td class="<?= (int)$d['bledy'] > 0 ? 'text-danger' : 'td-muted' ?>"><?= (int)$d['bledy'] ?></td>
                    <td class="td-muted"><?= (int)$d['odbiory'] ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- ── Per-order activity ────────────────────────────────────────── -->
        <?php if (!empty($per_order)): ?>
        <div class="divider"></div>
        <div class="section-label"><?= t('admin.analytics.per_order_section') ?></div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th><?= t('admin.orders.th.token') ?></th>
                        <th><?= t('admin.orders.th.status') ?></th>
                        <th><?= t('admin.analytics.th.lookups') ?></th>
                        <th><?= t('admin.analytics.th.unlocks') ?></th>
                        <th><?= t('admin.analytics.th.errors') ?></th>
                        <th><?= t('admin.analytics.th.last_activity') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($per_order as $o): ?>
                <tr>
                    <td><span class="token"><?= htmlspecialchars($o['order_token'] ?? '—', ENT_QUOTES, 'UTF-8') ?></span></td>
                    <td>
                        <?php if ($o['status'] === null): ?>
                        <span class="td-muted"><?= t('admin.analytics.deleted') ?></span>
                        <?php else: ?>
                        <span class="badge <?= $o['status'] === 'delivered' ? 'delivered' : '' ?>">
                            <?= $o['status'] === 'delivered' ? t('admin.analytics.status.delivered_lc') : t('admin.analytics.status.preparing_lc') ?>
                        </span>
                        <?php endif; ?>
                    </td>
                    <td class="td-muted"><?= (int)$o['wyszukania'] ?></td>
                    <td class="td-muted"><?= (int)$o['odblokowania'] ?></td>
                    <td class="<?= (int)$o['bledy'] > 0 ? 'text-danger' : 'td-muted' ?>"><?= (int)$o['bledy'] ?></td>
                    <td class="meta td-muted"><?= htmlspecialchars($o['ostatnia_aktywnosc'], ENT_QUOTES, 'UTF-8') ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- ── Suspicious IPs ───────────────────────────────────────────── -->
        <?php if (!empty($hot_ips)): ?>
        <div class="divider"></div>
        <div class="section-label"><?= t('admin.analytics.hot_ips_section') ?></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th><?= t('admin.analytics.th.ip') ?></th><th><?= t('admin.analytics.th.error_count') ?></th><th><?= t('admin.analytics.th.last_attempt') ?></th></tr></thead>
                <tbody>
                <?php foreach ($hot_ips as $r): ?>
                <tr>
                    <td class="token"><?= htmlspecialchars($r['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="text-danger"><?= (int)$r['cnt'] ?></td>
                    <td class="meta td-muted"><?= htmlspecialchars($r['ostatnia'], ENT_QUOTES, 'UTF-8') ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- ── Successful unlock IPs ─────────────────────────────────────── -->
        <?php if (!empty($unlock_ips)): ?>
        <div class="section-label"><?= t('admin.analytics.unlock_ips_section') ?></div>
        <div class="table-wrap">
            <table>
                <thead><tr><th><?= t('admin.analytics.th.ip') ?></th><th><?= t('admin.analytics.th.unlocks') ?></th><th><?= t('admin.analytics.th.last') ?></th></tr></thead>
                <tbody>
                <?php foreach ($unlock_ips as $r): ?>
                <tr>
                    <td class="token"><?= htmlspecialchars($r['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="td-muted"><?= (int)$r['cnt'] ?></td>
                    <td class="meta td-muted"><?= htmlspecialchars($r['ostatnia'], ENT_QUOTES, 'UTF-8') ?></td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- ── Recent events (paginated) ────────────────────────────────── -->
        <div class="divider"></div>
        <div class="section-label">
            <?= t('admin.analytics.recent_section') ?>
            <span class="td-muted"><?= htmlspecialchars(t('admin.analytics.recent_meta', ['total' => number_format($total_events), 'page' => $page, 'pages' => $total_pages]), ENT_QUOTES, 'UTF-8') ?></span>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th><?= t('admin.analytics.th.time') ?></th>
                        <th><?= t('admin.analytics.th.event') ?></th>
                        <th><?= t('admin.orders.th.token') ?></th>
                        <th><?= t('admin.analytics.th.ip') ?></th>
                        <th><?= t('admin.analytics.th.browser') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($recent)): ?>
                    <tr class="empty-row"><td colspan="5"><?= t('admin.analytics.no_events') ?></td></tr>
                <?php else: foreach ($recent as $ev): ?>
                <tr>
                    <td class="meta td-muted"><?= htmlspecialchars($ev['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td>
                        <span class="badge <?= $ev['event_type'] === 'unlock_success' || $ev['event_type'] === 'received' ? 'delivered' : ($ev['event_type'] === 'unlock_fail' ? 'badge-danger' : '') ?>">
                            <?= htmlspecialchars($labels[$ev['event_type']] ?? $ev['event_type'], ENT_QUOTES, 'UTF-8') ?>
                        </span>
                    </td>
                    <td class="token td-muted"><?= htmlspecialchars($ev['order_token'] ?? '—', ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="token"><?= htmlspecialchars($ev['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="meta td-muted ua-cell"><?= htmlspecialchars(parse_browser($ev['user_agent'] ?? ''), ENT_QUOTES, 'UTF-8') ?></td>
                </tr>
                <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>

        <!-- ── Pagination ────────────────────────────────────────────────── -->
        <?php if ($total_pages > 1): ?>
        <div class="pagination">
            <?php if ($page > 1): ?>
            <a class="page-btn" href="<?= htmlspecialchars(period_url($period, $page - 1), ENT_QUOTES, 'UTF-8') ?>">&#8592; <?= t('admin.analytics.prev_page') ?></a>
            <?php endif; ?>
            <span class="page-info"><?= htmlspecialchars(t('admin.analytics.page_info', ['page' => $page, 'pages' => $total_pages]), ENT_QUOTES, 'UTF-8') ?></span>
            <?php if ($page < $total_pages): ?>
            <a class="page-btn" href="<?= htmlspecialchars(period_url($period, $page + 1), ENT_QUOTES, 'UTF-8') ?>"><?= t('admin.analytics.next_page') ?> &#8594;</a>
            <?php endif; ?>
        </div>
        <?php endif; ?>

    </main>
</div>
<script src="/admin/admin.js"></script>
</body>
</html>
