<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

$step    = (int)($_POST['step'] ?? 0);
$done    = false;
$counts  = [];
$error   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $step === 3) {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.common.invalid_csrf');
        $step  = 0;
    } else {
        try {
            $db = get_db();
            $counts['orders'] = (int)$db->query('SELECT COUNT(*) FROM orders')->fetchColumn();
            $counts['photos'] = (int)$db->query('SELECT COUNT(*) FROM order_photos')->fetchColumn();
            $counts['events'] = (int)$db->query('SELECT COUNT(*) FROM order_events')->fetchColumn();

            $all_photos = $db->query('SELECT filename FROM order_photos')->fetchAll();
            $files_deleted = 0;
            foreach ($all_photos as $ph) {
                $path = dirname(__DIR__) . '/uploads/' . $ph['filename'];
                if (is_file($path)) {
                    secure_unlink($path);
                    $files_deleted++;
                }
            }
            foreach (glob(dirname(__DIR__) . '/uploads/*', GLOB_ONLYDIR) as $dir) {
                foreach (glob($dir . '/*') ?: [] as $f) { secure_unlink($f); }
                @rmdir($dir);
            }

            audit('panic_wipe', null, null, "orders={$counts['orders']} photos={$counts['photos']}");

            $db->exec('SET FOREIGN_KEY_CHECKS = 0');
            $db->exec('TRUNCATE TABLE order_photos');
            $db->exec('TRUNCATE TABLE order_events');
            $db->exec('TRUNCATE TABLE orders');
            $db->exec('SET FOREIGN_KEY_CHECKS = 1');

            // Wipe error log
            if (is_file(ERROR_LOG_PATH)) {
                file_put_contents(ERROR_LOG_PATH, '');
            }

            $counts['files'] = $files_deleted;
            $done = true;
            admin_logout();
        } catch (Exception $e) {
            log_err('PANIC: ' . $e->getMessage());
            $error = t('admin.panic.error.server', ['msg' => $e->getMessage()]);
            $step  = 2;
        }
    }
}

if ($step === 2 && !$done) {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) { $step = 0; }
    else {
        try {
            $db = get_db();
            $counts['orders'] = (int)$db->query('SELECT COUNT(*) FROM orders')->fetchColumn();
            $counts['photos'] = (int)$db->query('SELECT COUNT(*) FROM order_photos')->fetchColumn();
            $counts['events'] = (int)$db->query('SELECT COUNT(*) FROM order_events')->fetchColumn();
        } catch (Exception $e) { $counts = []; }
    }
}

if ($step === 1 && !verify_csrf($_POST['csrf_token'] ?? '')) { $step = 0; }

$csrf = generate_csrf();
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.sidebar.panic') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body>
<div class="shell">

    <?php if (!$done): ?>
    <?php $_active = 'panic'; require __DIR__ . '/sidebar.php'; ?>
    <?php endif; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>

    <?php if ($done): ?>
    <!-- ── Done ─────────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <div class="panic-step"><?= t('admin.panic.done.step_label') ?></div>
        <div class="panic-heading"><?= t('admin.panic.done.heading') ?></div>
        <div class="panic-report">
            <div class="panic-report-row"><?= t('admin.orders.title') ?><strong><?= $counts['orders'] ?></strong></div>
            <div class="panic-report-row"><?= t('admin.panic.report.photos_db') ?><strong><?= $counts['photos'] ?></strong></div>
            <div class="panic-report-row"><?= t('admin.panic.report.files') ?><strong><?= $counts['files'] ?></strong></div>
            <div class="panic-report-row"><?= t('admin.panic.report.logs') ?><strong><?= $counts['events'] ?></strong></div>
        </div>
        <div class="panic-body"><?= t('admin.panic.done.body') ?></div>
        <a href="/admin/index.php" class="btn btn-neutral"><?= t('admin.panic.relogin_button') ?></a>
    </div>

    <?php elseif ($step === 2): ?>
    <!-- ── Step 3/3 ──────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <?php if ($error): ?><div class="flash"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <div class="panic-step"><?= t('admin.panic.step3.label') ?></div>
        <div class="panic-heading"><?= t('admin.panic.step3.heading') ?></div>
        <?php if (!empty($counts)): ?>
        <div class="panic-counts">
            <div class="panic-counts-row"><?= t('admin.orders.title') ?><span><?= $counts['orders'] ?></span></div>
            <div class="panic-counts-row"><?= t('admin.panic.counts.photos_label') ?><span><?= $counts['photos'] ?></span></div>
            <div class="panic-counts-row"><?= t('admin.panic.counts.events') ?><span><?= $counts['events'] ?></span></div>
        </div>
        <?php endif; ?>
        <div class="panic-body">
            <?= t('admin.panic.step3.warning') ?>
        </div>
        <form method="POST" action="/admin/panic.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="step" value="3">
            <div class="form-actions">
                <button type="submit" class="btn btn-panic">&#9888; <?= t('admin.panic.delete_now_button') ?></button>
                <a href="/admin/index.php" class="btn-cancel"><?= t('common.cancel') ?></a>
            </div>
        </form>
    </div>

    <?php elseif ($step === 1): ?>
    <!-- ── Step 2/3 ──────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <div class="panic-step"><?= t('admin.panic.step2.label') ?></div>
        <div class="panic-heading"><?= t('admin.panic.step2.heading') ?></div>
        <div class="panic-body">
            <?= t('admin.panic.step2.body') ?>
        </div>
        <form method="POST" action="/admin/panic.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="step" value="2">
            <div class="form-actions">
                <button type="submit" class="btn btn-panic"><?= t('admin.panic.step2.continue_button') ?></button>
                <a href="/admin/index.php" class="btn-cancel"><?= t('common.cancel') ?></a>
            </div>
        </form>
    </div>

    <?php else: ?>
    <!-- ── Step 1/3 ──────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <div class="panic-step"><?= t('admin.panic.step1.label') ?></div>
        <div class="panic-heading"><?= t('admin.sidebar.panic') ?></div>
        <div class="panic-body">
            <?= t('admin.panic.step1.body') ?>
        </div>
        <form method="POST" action="/admin/panic.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="step" value="1">
            <div class="form-actions">
                <button type="submit" class="btn btn-panic">&#9888; <?= t('admin.panic.step1.activate_button') ?></button>
                <a href="/admin/index.php" class="btn-cancel"><?= t('common.cancel') ?></a>
            </div>
        </form>
    </div>
    <?php endif; ?>

    </main>
</div>
<script src="/admin/admin.js"></script>
</body>
</html>
