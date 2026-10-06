<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

// Owner diagnostics: seven read-only sections aggregated live by
// includes/diagnostics.php (counts, sizes, heartbeats — never secrets, never
// writes). Collection releases the session lock first (the uploads disk walk
// and log tail must not queue every other owner request behind this page),
// panic.php idiom. ?format=json serves the same payload machine-readable for
// external monitoring; a GET that exfiltrates needs its CSRF token checked
// (verify_csrf_readonly: checked, never rotated).
start_secure_session();
$csp_nonce = set_security_headers(true);
require_owner();

$csrf = generate_csrf();
if (($_GET['format'] ?? '') === 'json') {
    if (!verify_csrf_readonly($_GET['csrf_token'] ?? null)) {
        http_response_code(403);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'invalid_csrf']);
        exit;
    }
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(diagnostics_collect());
    exit;
}
session_write_close();
$diag = diagnostics_collect();
$_active = 'diagnostics';

/** Fail-soft section: degraded source renders one row, never a blank page. */
function _diag_section(array $sec): bool {
    return ($sec['ok'] ?? false) === true;
}
function _diag_age(?int $ts): string {
    if ($ts === null || $ts <= 0) {
        return t('admin.diag.never');
    }
    return htmlspecialchars(diagnostics_age($ts), ENT_QUOTES, 'UTF-8');
}
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.diag.title') ?></title><link rel="stylesheet" href="/admin/style.css?v=<?= admin_css_ver() ?>">
</head>
<body>
<div class="shell">

    <?php require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading"><?= t('admin.diag.title') ?></div>
        <p class="td-muted"><?= t('admin.diag.lead') ?></p>
        <p class="td-muted"><a href="/admin/diagnostics.php?format=json&amp;csrf_token=<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>"><?= t('admin.diag.json_link') ?></a></p>

        <h2><?= t('admin.diag.sec_system') ?></h2>
        <?php $s = $diag['system']; ?>
        <?php if (!_diag_section($s)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><tbody>
            <tr><th>PHP</th><td><?= htmlspecialchars((string)($s['php'] ?? '?'), ENT_QUOTES, 'UTF-8') ?> (<?= htmlspecialchars((string)($s['sapi'] ?? '?'), ENT_QUOTES, 'UTF-8') ?>, <?= htmlspecialchars((string)($s['memory_limit'] ?? '?'), ENT_QUOTES, 'UTF-8') ?>)</td></tr>
            <tr><th>DB</th><td><?= htmlspecialchars((string)($s['db_version'] ?? '?'), ENT_QUOTES, 'UTF-8') ?> — <?= htmlspecialchars(diagnostics_bytes(isset($s['db_size']) ? (int)$s['db_size'] : null), ENT_QUOTES, 'UTF-8') ?></td></tr>
            <?php foreach (($s['disks'] ?? []) as $label => $d): ?>
            <tr><th><?= htmlspecialchars(t('admin.diag.disk_label', ['label' => (string)$label]), ENT_QUOTES, 'UTF-8') ?></th><td><?= htmlspecialchars(diagnostics_bytes(isset($d['free']) ? (int)$d['free'] : null), ENT_QUOTES, 'UTF-8') ?> <?= t('admin.diag.free_of') ?> <?= htmlspecialchars(diagnostics_bytes(isset($d['total']) ? (int)$d['total'] : null), ENT_QUOTES, 'UTF-8') ?></td></tr>
            <?php endforeach; ?>
        </tbody></table>
        <?php endif; ?>

        <h2><?= t('admin.diag.sec_jobs') ?></h2>
        <?php $j = $diag['jobs']; ?>
        <?php if (!_diag_section($j)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><tbody>
            <?php foreach (($j['heartbeats'] ?? []) as $b): ?>
            <tr><th><?= htmlspecialchars((string)($b['label'] ?? '?'), ENT_QUOTES, 'UTF-8') ?></th><td><?= _diag_age(isset($b['at']) ? (int)$b['at'] : null) ?><?php if (($b['stale'] ?? false) === true): ?> — <strong><?= t('admin.diag.stale') ?></strong><?php endif; ?></td></tr>
            <?php endforeach; ?>
            <tr><th><?= t('admin.diag.worker_lock') ?></th><td><?php $wl = $j['maps_worker_lock'] ?? null; ?><?= is_array($wl) ? htmlspecialchars((string)($wl['by'] ?? '?'), ENT_QUOTES, 'UTF-8') . ', ' . _diag_age((int)($wl['at'] ?? 0)) : t('admin.diag.empty') ?></td></tr>
        </tbody></table>
        <?php endif; ?>

        <h2><?= t('admin.diag.sec_logs') ?></h2>
        <?php $l = $diag['logs']; ?>
        <?php if (!_diag_section($l)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><tbody>
            <?php foreach (($l['files'] ?? []) as $label => $f): ?>
            <tr><th><?= htmlspecialchars((string)$label, ENT_QUOTES, 'UTF-8') ?></th><td><?= htmlspecialchars(diagnostics_bytes(isset($f['size']) ? (int)$f['size'] : null), ENT_QUOTES, 'UTF-8') ?> — <?= _diag_age(isset($f['mtime']) ? (int)$f['mtime'] : null) ?></td></tr>
            <?php endforeach; ?>
            <tr><th><?= t('admin.diag.checkpoint') ?></th><td><?php $cp = $l['checkpoint'] ?? null; ?><?= is_array($cp) ? 'seq ' . (int)($cp['tip_seq'] ?? 0) . ', ' . _diag_age(isset($cp['at']) ? (int)$cp['at'] : null) : t('admin.diag.empty') ?></td></tr>
        </tbody></table>
        <p class="td-muted"><a href="/admin/settings.php"><?= t('admin.diag.verify_link') ?></a></p>
        <?php endif; ?>

        <h2><?= t('admin.diag.sec_traffic') ?></h2>
        <?php $tr = $diag['traffic']; ?>
        <?php if (!_diag_section($tr)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><tbody>
            <?php foreach (($tr['events_24h_by_type'] ?? []) as $type => $n): ?>
            <tr><th><?= htmlspecialchars((string)$type, ENT_QUOTES, 'UTF-8') ?></th><td><?= (int)$n ?> / 24h</td></tr>
            <?php endforeach; ?>
            <?php foreach (($tr['log_levels'] ?? []) as $lv => $n): ?>
            <tr><th>log.<?= htmlspecialchars((string)$lv, ENT_QUOTES, 'UTF-8') ?></th><td><?= (int)$n ?> <?= t('admin.diag.of_sampled', ['n' => (int)($tr['log_sampled_lines'] ?? 0)]) ?></td></tr>
            <?php endforeach; ?>
        </tbody></table>
        <?php endif; ?>

        <h2><?= t('admin.diag.sec_security') ?></h2>
        <?php $sec = $diag['security']; ?>
        <?php if (!_diag_section($sec)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><thead><tr><th>IP</th><th><?= t('admin.diag.scope') ?></th><th><?= t('admin.diag.count') ?></th></tr></thead><tbody>
            <?php foreach (($sec['top_blocked'] ?? []) as $b): ?>
            <tr><td><?= htmlspecialchars((string)($b['ip'] ?? '?'), ENT_QUOTES, 'UTF-8') ?></td><td><?= htmlspecialchars((string)($b['scope'] ?? '?'), ENT_QUOTES, 'UTF-8') ?></td><td><?= (int)($b['count'] ?? 0) ?></td></tr>
            <?php endforeach; ?>
            <?php if (empty($sec['top_blocked'])): ?><tr><td colspan="3"><?= t('admin.diag.empty') ?></td></tr><?php endif; ?>
        </tbody></table>
        <?php endif; ?>

        <h2><?= t('admin.diag.sec_data') ?></h2>
        <?php $d = $diag['data']; ?>
        <?php if (!_diag_section($d)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><tbody>
            <?php foreach (($d['orders_by_status'] ?? []) as $st => $n): ?>
            <tr><th>orders.<?= htmlspecialchars((string)$st, ENT_QUOTES, 'UTF-8') ?></th><td><?= (int)$n ?></td></tr>
            <?php endforeach; ?>
            <tr><th><?= t('admin.diag.photos') ?></th><td><?= (int)($d['photos'] ?? 0) ?> (<?= htmlspecialchars(diagnostics_bytes(isset($d['uploads']['bytes']) ? (int)$d['uploads']['bytes'] : null), ENT_QUOTES, 'UTF-8') ?>)</td></tr>
            <?php foreach (($d['zones'] ?? []) as $z): ?>
            <tr><th><?= htmlspecialchars((string)($z['name'] ?? '?'), ENT_QUOTES, 'UTF-8') ?></th><td><?= htmlspecialchars((string)($z['status'] ?? '?'), ENT_QUOTES, 'UTF-8') ?><?= $z['pct'] !== null ? ' — ' . (float)$z['pct'] . '%' : '' ?></td></tr>
            <?php endforeach; ?>
        </tbody></table>
        <?php endif; ?>

        <h2><?= t('admin.diag.sec_backups') ?></h2>
        <?php $bb = $diag['backups']; ?>
        <?php if (!_diag_section($bb)): ?><p class="td-muted"><?= t('admin.diag.unavailable') ?></p>
        <?php else: ?>
        <table class="data-table"><tbody>
            <tr><th><?= t('admin.diag.backup_count') ?></th><td><?= (int)($bb['count'] ?? 0) ?></td></tr>
            <tr><th><?= t('admin.diag.backup_latest') ?></th><td><?php $bl = $bb['latest'] ?? null; ?><?= is_array($bl) ? htmlspecialchars((string)$bl['name'], ENT_QUOTES, 'UTF-8') . ' — ' . _diag_age((int)$bl['mtime']) : t('admin.diag.empty') ?></td></tr>
        </tbody></table>
        <?php endif; ?>
    </main>
</div>
</body>
</html>
