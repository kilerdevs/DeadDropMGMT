<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

$step    = (int)($_POST['step'] ?? 0);
$done    = false;
$counts  = [];
$error   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $step === 3) {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = 'Nieprawidłowy token CSRF.';
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
            $error = 'Błąd: ' . $e->getMessage();
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
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Tryb awaryjny</title><link rel="stylesheet" href="/admin/style.css">
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
        <div class="panic-step">Operacja zakończona</div>
        <div class="panic-heading">Wszystko usunięte</div>
        <div class="panic-report">
            <div class="panic-report-row">Zamówienia<strong><?= $counts['orders'] ?></strong></div>
            <div class="panic-report-row">Zdjęcia (DB)<strong><?= $counts['photos'] ?></strong></div>
            <div class="panic-report-row">Pliki<strong><?= $counts['files'] ?></strong></div>
            <div class="panic-report-row">Logi<strong><?= $counts['events'] ?></strong></div>
        </div>
        <div class="panic-body">Baza danych wyczyszczona. Sesja admina została zakończona.</div>
        <a href="/admin/index.php" class="btn btn-neutral">Zaloguj się ponownie</a>
    </div>

    <?php elseif ($step === 2): ?>
    <!-- ── Step 3/3 ──────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <?php if ($error): ?><div class="flash"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <div class="panic-step">Krok 3 z 3 — ostatnie ostrzeżenie</div>
        <div class="panic-heading">Nieodwracalne usunięcie</div>
        <?php if (!empty($counts)): ?>
        <div class="panic-counts">
            <div class="panic-counts-row">Zamówienia<span><?= $counts['orders'] ?></span></div>
            <div class="panic-counts-row">Zdjęcia<span><?= $counts['photos'] ?></span></div>
            <div class="panic-counts-row">Logi zdarzeń<span><?= $counts['events'] ?></span></div>
        </div>
        <?php endif; ?>
        <div class="panic-body">
            <strong>Tej operacji nie można cofnąć.</strong><br>
            Wszystkie powyższe rekordy oraz pliki zostaną trwale zniszczone.
        </div>
        <form method="POST" action="/admin/panic.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="step" value="3">
            <div class="form-actions">
                <button type="submit" class="btn btn-panic">&#9888; Usuń wszystko teraz</button>
                <a href="/admin/index.php" class="btn-cancel">Anuluj</a>
            </div>
        </form>
    </div>

    <?php elseif ($step === 1): ?>
    <!-- ── Step 2/3 ──────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <div class="panic-step">Krok 2 z 3</div>
        <div class="panic-heading">Potwierdzenie awaryjne</div>
        <div class="panic-body">
            Zamierzasz usunąć <strong>wszystkie zamówienia</strong>, zdjęcia, logi i dane operacyjne.<br><br>
            Tej operacji <strong>nie można cofnąć</strong>.
        </div>
        <form method="POST" action="/admin/panic.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="step" value="2">
            <div class="form-actions">
                <button type="submit" class="btn btn-panic">Rozumiem — kontynuuj (2/3)</button>
                <a href="/admin/index.php" class="btn-cancel">Anuluj</a>
            </div>
        </form>
    </div>

    <?php else: ?>
    <!-- ── Step 1/3 ──────────────────────────────────────────────────────── -->
    <div class="panic-wrap">
        <div class="panic-step">Krok 1 z 3</div>
        <div class="panic-heading">Tryb awaryjny</div>
        <div class="panic-body">
            Ten tryb trwale usuwa <strong>całą zawartość bazy danych</strong> — wszystkie zamówienia, lokalizacje, zdjęcia, instrukcje i logi.<br><br>
            Użyj wyłącznie w sytuacji zagrożenia. Wymaga trzech potwierdzeń.
        </div>
        <form method="POST" action="/admin/panic.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="step" value="1">
            <div class="form-actions">
                <button type="submit" class="btn btn-panic">&#9888; Aktywuj tryb awaryjny (1/3)</button>
                <a href="/admin/index.php" class="btn-cancel">Anuluj</a>
            </div>
        </form>
    </div>
    <?php endif; ?>

    </main>
</div>
<script src="/admin/admin.js"></script>
</body>
</html>
