<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/analytics.php';
require_once dirname(__DIR__) . '/includes/settings.php';

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
    else                                                                         $b = 'Inny';
    return $b . ' · ' . ($mobile ? 'Mobilny' : 'Desktop');
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
    'lookup'         => 'Wyszukanie tokenu',
    'unlock_success' => 'Udane odblokowanie',
    'unlock_fail'    => 'Błędne hasło',
    'received'       => 'Potwierdzenie odbioru',
];

function period_url(string $p, int $page = 1): string {
    $q = http_build_query(['period' => $p, 'page' => $page]);
    return '/admin/analytics.php?' . $q;
}

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Analityka</title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php $_active = 'analytics'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading">Analityka</div>

        <?php if (!analytics_enabled()): ?>
        <div class="flash">
            Zbieranie danych analitycznych jest wyłączone. Nowe zdarzenia nie są rejestrowane.
            Dane zebrane przed wyłączeniem są nadal widoczne poniżej.
            <a href="/admin/settings.php" class="flash-link">Włącz w ustawieniach &#8594;</a>
        </div>
        <?php endif; ?>

        <!-- ── Period filter ─────────────────────────────────────────────── -->
        <div class="period-filter">
            <a class="period-btn <?= $period === '24h'  ? 'active' : '' ?>" href="<?= period_url('24h')  ?>">Ostatnie 24h</a>
            <a class="period-btn <?= $period === '7d'   ? 'active' : '' ?>" href="<?= period_url('7d')   ?>">Ostatnie 7 dni</a>
            <a class="period-btn <?= $period === '30d'  ? 'active' : '' ?>" href="<?= period_url('30d')  ?>">Ostatnie 30 dni</a>
            <a class="period-btn <?= $period === 'all'  ? 'active' : '' ?>" href="<?= period_url('all')  ?>">Wszystko</a>
        </div>

        <!-- ── Summary cards ─────────────────────────────────────────────── -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['lookup'] ?? 0) ?></div>
                <div class="stat-label">Wyszukania tokenów</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['unlock_success'] ?? 0) ?></div>
                <div class="stat-label">Udane odblokowania</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['unlock_fail'] ?? 0) ?></div>
                <div class="stat-label">Błędne hasła</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($counts['received'] ?? 0) ?></div>
                <div class="stat-label">Potwierdzenia odbioru</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><?= number_format($unique_ips) ?></div>
                <div class="stat-label">Unikalne adresy IP</div>
            </div>
        </div>

        <!-- ── Daily breakdown ───────────────────────────────────────────── -->
        <?php if (!empty($daily)): ?>
        <div class="divider"></div>
        <div class="section-label">Aktywność dzienna — ostatnie 14 dni</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Dzień</th>
                        <th>Wyszukania</th>
                        <th>Odblokowania</th>
                        <th>Błędne hasła</th>
                        <th>Odbiory</th>
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
        <div class="section-label">Aktywność według zamówień</div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Token</th>
                        <th>Status</th>
                        <th>Wyszukania</th>
                        <th>Odblokowania</th>
                        <th>Błędy</th>
                        <th>Ostatnia aktywność</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($per_order as $o): ?>
                <tr>
                    <td><span class="token"><?= htmlspecialchars($o['order_token'] ?? '—', ENT_QUOTES, 'UTF-8') ?></span></td>
                    <td>
                        <?php if ($o['status'] === null): ?>
                        <span class="td-muted">usunięte</span>
                        <?php else: ?>
                        <span class="badge <?= $o['status'] === 'delivered' ? 'delivered' : '' ?>">
                            <?= $o['status'] === 'delivered' ? 'dostarczone' : 'w przygotowaniu' ?>
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
        <div class="section-label">Podejrzane adresy IP — wielokrotne błędne hasła</div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Adres IP</th><th>Liczba błędów</th><th>Ostatnia próba</th></tr></thead>
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
        <div class="section-label">Adresy IP — udane odblokowania</div>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Adres IP</th><th>Odblokowania</th><th>Ostatnie</th></tr></thead>
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
            Ostatnie zdarzenia
            <span class="td-muted"><?= number_format($total_events) ?> łącznie · strona <?= $page ?> z <?= $total_pages ?></span>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Czas</th>
                        <th>Zdarzenie</th>
                        <th>Token</th>
                        <th>Adres IP</th>
                        <th>Przeglądarka / urządzenie</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($recent)): ?>
                    <tr class="empty-row"><td colspan="5">BRAK ZDARZEŃ</td></tr>
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
            <a class="page-btn" href="<?= period_url($period, $page - 1) ?>">&#8592; Poprzednia</a>
            <?php endif; ?>
            <span class="page-info">Strona <?= $page ?> / <?= $total_pages ?></span>
            <?php if ($page < $total_pages): ?>
            <a class="page-btn" href="<?= period_url($period, $page + 1) ?>">Następna &#8594;</a>
            <?php endif; ?>
        </div>
        <?php endif; ?>

    </main>
</div>
<script src="/admin/admin.js"></script>
</body>
</html>
