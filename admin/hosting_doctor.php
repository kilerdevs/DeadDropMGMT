<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

// Hosting doctor: every host capability from capability_definitions() with
// its state on THIS host and the exact fallback when one is missing — the
// answer to "what does my panel host lack, and what still works".
// Owner-only, unconditionally: unlike setup_check (which has a pre-owner
// public installer mode), there is no state of the app where host internals
// — versions, paths, privilege censuses — are stranger-safe. require_owner()
// before any probe output is rendered, and the page takes no input at all
// (read-only: no POST, no CSRF surface, nothing to inject array-shaped input
// into — ArrayInputTest sweeps it like every other endpoint).
start_secure_session();
$csp_nonce = set_security_headers(true);
require_owner();

$root = dirname(__DIR__);
// Writability the app itself depends on (nearest existing ancestor decides,
// same rule as host_dir_writable — data/ and tiles/ do not exist until first
// use, so a missing dir is not a failure).
$dirs = [];
foreach (['logs' => '/logs', 'uploads' => '/uploads', 'cache' => '/cache',
          'data' => '/data', 'tiles' => '/tiles'] as $label => $rel) {
    $dirs[$label . '/'] = host_dir_writable($root . $rel);
}
// The privilege census never dies with the page: setup_db_probe() connects
// without get_db()'s 503, and a dead database simply leaves grants unknown
// (which reads as restricted — the safe direction).
$grants = null;
try {
    $probe = setup_db_probe();
    $grants = $probe['connected'] ? $probe['grants'] : null;
} catch (Throwable) {
    $grants = null;
}
$sp = session_effective_path();
$env = capabilities_live_env([
    'grants' => $grants,
    'dirs' => $dirs,
    'session_path' => $sp,
    'session_writable' => is_dir($sp) && is_writable($sp),
    'server_sw' => (string)($_SERVER['SERVER_SOFTWARE'] ?? ''),
    'htaccess_ok' => is_file($root . '/.htaccess'),
]);
// Doctor words for the registry states (badge classes reuse the setup-check
// st-* set): ok works, limited works differently (the fallback beside it is
// active), unavailable is off with a fallback, blocked stops the install.
$docWord = ['ok' => t('admin.setupcheck.st_ok'), 'limited' => t('admin.setupcheck.st_info'),
            'unavailable' => t('admin.setupcheck.st_warn'), 'blocked' => t('admin.setupcheck.st_fail')];
$docBadge = ['ok' => 'ok', 'limited' => 'info', 'unavailable' => 'warn', 'blocked' => 'fail'];
$rows = [];
foreach (capabilities_evaluate($env) as $r) {
    if ($r['state'] === 'ok') {
        $rows[] = ['id' => $r['id'], 'label' => $r['label'], 'status' => 'ok', 'detail' => ''];
        continue;
    }
    if ($r['state'] === 'limited') {
        $st = 'limited';
    } else {
        $st = $r['required'] ? 'blocked' : 'unavailable';
    }
    $params = [];
    if ($r['id'] === 'zip' && $r['note'] !== '') {
        $params = ['bin' => $r['note']];
    } elseif ($r['id'] === 'dirs') {
        $params = ['dirs' => $r['note']];
    } elseif ($r['id'] === 'php') {
        $params = ['v' => PHP_VERSION];
    }
    $rows[] = ['id' => $r['id'], 'label' => $r['label'], 'status' => $st, 'detail' => t($r['fallback'], $params)];
}
$_active = 'hosting_doctor';
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.doctor.title') ?></title><link rel="stylesheet" href="/admin/style.css?v=<?= admin_css_ver() ?>">
</head>
<body>
<div class="shell">

    <?php require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading"><?= t('admin.doctor.title') ?></div>
        <p class="td-muted"><?= t('admin.doctor.lead') ?></p>

        <div class="table-wrap">
            <table>
                <tbody>
                <?php foreach ($rows as $r): ?>
                    <tr>
                        <td><span class="badge st-<?= htmlspecialchars($docBadge[$r['status']], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($docWord[$r['status']], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td><span class="token"><?= htmlspecialchars($r['label'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td class="td-muted"><?= htmlspecialchars($r['detail'], ENT_QUOTES, 'UTF-8') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <p class="td-muted"><a href="/admin/setup_check.php"><?= htmlspecialchars(t('admin.setupcheck.title'), ENT_QUOTES, 'UTF-8') ?></a></p>
    </main>
</div>
<script src="/admin/admin.js?v=<?= asset_ver('/admin/admin.js') ?>"></script>
</body>
</html>
