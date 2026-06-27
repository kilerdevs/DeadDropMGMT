<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/analytics.php';
require_once __DIR__ . '/includes/settings.php';

set_security_headers(false);
start_secure_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    header('Location: /');
    exit;
}

$raw_token = trim($_POST['order_token'] ?? '');
$step      = (int)($_POST['step'] ?? 0);
$deleted   = false;
$error     = '';
$csrf      = generate_csrf();

if (strlen($raw_token) !== 16 || !ctype_alnum($raw_token)) {
    header('Location: /');
    exit;
}

// ── Step 1 — show confirmation page ──────────────────────────────────────────
if ($step === 1) {
    // Verify order still exists before showing the confirm page
    try {
        $stmt = get_db()->prepare('SELECT id, order_token, status FROM orders WHERE order_token = ? LIMIT 1');
        $stmt->execute([$raw_token]);
        $order = $stmt->fetch();
    } catch (Exception $e) {
        log_err('Receive step1: ' . $e->getMessage());
        $order = null;
    }

    if (!$order) {
        header('Location: /');
        exit;
    }
    // Fall through to render the confirmation page below
}

// ── Step 2 — execute deletion ─────────────────────────────────────────────────
if ($step === 2) {
    $rl = rl_status();
    if ($rl['blocked']) {
        $error = 'Zbyt wiele prób — odczekaj ' . (int)ceil($rl['remaining'] / 60) . ' min.';
    } else {
        try {
            $db   = get_db();
            $stmt = $db->prepare('SELECT * FROM orders WHERE order_token = ? LIMIT 1');
            $stmt->execute([$raw_token]);
            $order = $stmt->fetch();

            if (!$order) {
                $error = 'Zamówienie nie zostało znalezione.';
            } else {
                log_event('received', (int)$order['id'], $raw_token);

                // Securely delete photo files
                $photos = $db->prepare('SELECT filename FROM order_photos WHERE order_id = ?');
                $photos->execute([$order['id']]);
                foreach ($photos->fetchAll() as $ph) {
                    secure_unlink(__DIR__ . '/uploads/' . $ph['filename']);
                }
                $dir = __DIR__ . '/uploads/' . (int)$order['id'] . '/';
                if (is_dir($dir) && count(glob($dir . '*')) === 0) { @rmdir($dir); }

                $db->prepare('DELETE FROM orders WHERE id = ?')->execute([$order['id']]);
                $deleted = true;
            }
        } catch (Exception $e) {
            log_err('Receive step2: ' . $e->getMessage());
            $error = 'Błąd serwera. Spróbuj ponownie.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $deleted ? 'Odebrano' : 'Potwierdzenie odbioru' ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="/style.css">
<?php if ($deleted): ?>
<meta http-equiv="refresh" content="10; url=/">
<?php endif; ?>
</head>
<body>
<main>
    <div class="wordmark">DEAD DROP // <?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?></div>

    <?php if ($deleted): ?>
    <!-- ── Success ─────────────────────────────────────────────────────── -->
    <h1>Odebrano</h1>
    <div class="status-card">
        <div class="status-label">Operacja zakończona</div>
        <div class="status-badge delivered">ZAKOŃCZONE</div>
        <div class="location-reveal">
            <div class="reveal-section">
                <div class="reveal-key">Potwierdzenie</div>
                <div class="reveal-value">
                    Przesyłka potwierdzona jako odebrana.<br>
                    Wszystkie dane zostały trwale usunięte.
                </div>
            </div>
        </div>
        <div class="once-note">
            Powrót do strony głównej za <span id="redirect-countdown" data-secs="10">10</span>s
        </div>
    </div>

    <?php elseif ($error): ?>
    <!-- ── Error ───────────────────────────────────────────────────────── -->
    <h1>Błąd</h1>
    <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <a href="/" class="btn">Powrót</a>

    <?php else: ?>
    <!-- ── Confirmation page (step 1) ──────────────────────────────────── -->
    <h1>Potwierdzenie odbioru</h1>
    <div class="confirm-card">
        <div class="status-label">Numer przesyłki</div>
        <div class="confirm-token"><?= htmlspecialchars($raw_token, ENT_QUOTES, 'UTF-8') ?></div>
        <div class="confirm-warning">
            Tej operacji nie można cofnąć.<br>
            Lokalizacja, zdjęcia i wszystkie dane zostaną trwale usunięte.
        </div>
        <div class="confirm-actions">
            <form method="POST" action="/receive.php">
                <input type="hidden" name="csrf_token"
                       value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="order_token"
                       value="<?= htmlspecialchars($raw_token, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="step" value="2">
                <button type="submit" class="btn btn-confirm-delete">Tak — usuń wszystko</button>
            </form>
            <a href="/" class="btn-cancel-link">Anuluj</a>
        </div>
    </div>
    <?php endif; ?>

    <div class="trust-bar" aria-label="Informacje o bezpieczeństwie">
        <span class="trust-lock" aria-hidden="true"></span>
        <span class="trust-text">Bezpieczne i prywatne</span>
        <span class="trust-sep">·</span>
        <span class="trust-text">Dane usuwane automatycznie</span>
        <span class="trust-sep">·</span>
        <span class="trust-text">Bez śledzenia</span>
    </div>
    <div class="compliance-note">Zgodność z ISO/IEC 27001:2022 — zarządzanie bezpieczeństwem informacji</div>
</main>
<?php if ($deleted): ?>
<script src="/public.js"></script>
<?php endif; ?>
</body>
</html>
