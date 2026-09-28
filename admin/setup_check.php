<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

// Setup check: first-run and restricted-host diagnostics with a schema
// installer. A setup page that 503s on a bad DB_NAME cannot diagnose a bad
// DB_NAME, so the database is probed WITHOUT get_db()'s death — and the
// page gates itself on what the probe finds: while an owner row exists this
// is an owner-only page (standard require_owner); before that it is the
// installer (public diagnostics, schema apply behind CSRF plus the optional
// DDMGMT_SETUP_TOKEN, the same claim model as admin/bootstrap.php).
start_secure_session();
$csp_nonce = set_security_headers(true);

$probe = setup_db_probe();
if ($probe['owner_exists']) {
    require_owner();
}
// Unknowable owner status (database down, users table unreadable): this may
// well be an installed app, so strangers get one generic row — never the raw
// PDO error (host, user), versions or paths. The detail goes to the error log.
$limited = !$probe['owner_exists'] && !($probe['owner_known'] ?? false) && !is_owner();
if ($limited && !$probe['connected']) {
    error_log('DeadDropMGMT setup check: database unreachable: ' . $probe['error']);
}
$setupMode = !$probe['owner_exists'];
$setupTokenSet = _secret('DDMGMT_SETUP_TOKEN', '') !== '';

// ── POST: apply schema ──────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $limited) {
    http_response_code(403);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $flash = t('admin.common.invalid_request');
    $flashOk = false;
    $hit = rl_hit('setup_apply', 10);
    // Chicken-and-egg: the limiter lives IN the schema this installer
    // creates, so with tables missing it answers blocked (fail-closed) and
    // would brick the install. Bypass it only then — CSRF plus the optional
    // setup token still gate the action, the same claim model as bootstrap.
    $noLimiter = $probe['connected'] && count(array_diff(SETUP_TABLES, $probe['tables'])) > 0;
    if ($noLimiter) {
        error_log('DeadDropMGMT: setup schema apply without rate limiter (tables missing yet).');
    }
    if ($hit['blocked'] && !$noLimiter) {
        $flash = t('admin.login.error.rate_limited', ['min' => (int)ceil($hit['remaining'] / 60)]);
    } elseif (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $flash = t('admin.common.invalid_csrf');
    } elseif (($_POST['action'] ?? '') === 'apply_schema') {
        $allowed = is_owner();
        if (!$allowed && $setupMode) {
            $want = _secret('DDMGMT_SETUP_TOKEN', '');
            $allowed = $want === '' || hash_equals($want, trim((string)($_POST['setup_token'] ?? '')));
            if (!$allowed) {
                $flash = t('admin.setupcheck.token_needed');
            }
        }
        if ($allowed && !$probe['connected']) {
            $flash = t('admin.setupcheck.db_down', ['error' => $probe['error']]);
        } elseif ($allowed) {
            $sql = @file_get_contents(dirname(__DIR__) . '/setup.sql');
            if (!is_string($sql) || $sql === '') {
                $flash = t('admin.setupcheck.apply_failed', ['error' => 'setup.sql unreadable']);
            } else {
                $res = schema_apply($probe['pdo'], schema_statements($sql));
                if ($res['error'] === '') {
                    $flash = t('admin.setupcheck.applied', ['n' => (string)$res['applied']]);
                    $flashOk = true;
                    audit('schema_apply', null, null, 'applied=' . $res['applied']);
                    $probe = setup_db_probe(); // refresh rows below the flash
                } else {
                    $flash = t('admin.setupcheck.apply_failed', ['error' => $res['error']]);
                }
            }
        }
    }
    $_SESSION['flash'] = $flash;
    $_SESSION['flash_ok'] = $flashOk;
    header('Location: /admin/setup_check.php');
    exit;
}

// ── Read flash (set by PRG above) ───────────────────────────────────────────
$error = '';
$success = '';
[$flashMsg, $flashOk] = flash_take();
if ($flashMsg !== '') {
    if ($flashOk) {
        $success = $flashMsg;
    } else {
        $error = $flashMsg;
    }
}

$rows = $limited
    ? [setup_row('db', 'database', 'fail', t('admin.setupcheck.db_down_public'))]
    : array_merge(
        setup_runtime_checks(),
        setup_db_rows($probe),
        setup_storage_checks()
    );
$csrf = generate_csrf();
$stWord = ['ok' => t('admin.setupcheck.st_ok'), 'warn' => t('admin.setupcheck.st_warn'),
           'fail' => t('admin.setupcheck.st_fail'), 'info' => t('admin.setupcheck.st_info')];
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.setupcheck.title') ?></title><link rel="stylesheet" href="/admin/style.css?v=<?= admin_css_ver() ?>">
</head>
<body>
<div class="shell">

    <?php if (!$setupMode): ?>
    <?php $_active = 'setup_check'; require __DIR__ . '/sidebar.php'; ?>
    <?php endif; ?>

    <main class="main">
    <?php if (!$setupMode): ?>
    <?php require __DIR__ . '/totp_banner.php'; ?>
    <?php endif; ?>
        <div class="page-heading"><?= t('admin.setupcheck.title') ?></div>
        <p class="td-muted"><?= t('admin.setupcheck.lead') ?></p>

        <?php if ($error !== ''): ?>
        <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>
        <?php if ($success !== ''): ?>
        <div class="flash ok"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <div class="table-wrap">
            <table>
                <tbody>
                <?php foreach ($rows as $r): ?>
                    <tr>
                        <td><span class="badge st-<?= htmlspecialchars($r['status'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($stWord[$r['status']] ?? $r['status'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td><span class="token"><?= htmlspecialchars($r['label'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td class="td-muted"><?= htmlspecialchars($r['detail'], ENT_QUOTES, 'UTF-8') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php if (!$limited && $probe['connected'] && (is_owner() || $setupMode)): ?>
        <form method="POST" action="/admin/setup_check.php" class="log-toolbar">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="action" value="apply_schema">
            <?php if ($setupMode && $setupTokenSet): ?>
            <input type="password" name="setup_token" autocomplete="off" placeholder="setup_token">
            <?php endif; ?>
            <button type="submit" class="action-btn"><?= t('admin.setupcheck.apply') ?></button>
        </form>
        <?php endif; ?>
    </main>
</div>
<script src="/admin/admin.js?v=<?= asset_ver('/admin/admin.js') ?>"></script>
</body>
</html>
