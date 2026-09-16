<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/crypto.php';
require_once __DIR__ . '/includes/analytics.php';
require_once __DIR__ . '/includes/settings.php';
require_once __DIR__ . '/includes/order_state.php';
require_once __DIR__ . '/includes/i18n.php';

$csp_nonce = set_security_headers(false);
start_secure_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /');
    exit;
}

// Token enumeration is limited on every public surface, not just the
// destructive one: the confirmation probe burns budget like anything else.
// rl_hit is one atomic state transition — spend + verdict — so concurrent
// requests can never both slip through on a stale count. It runs BEFORE the
// CSRF check deliberately: a flood of forged requests must drain its own
// budget (self-throttling), and an already-blocked visitor gets the cooldown
// card instead of being waved to a redirect that leaks nothing anyway.
$rl = rl_hit('public');
$error = $rl['blocked']
    ? t('public.receive.rate_limited', ['min' => (int)ceil($rl['remaining'] / 60)])
    : '';

if ($error === '' && !verify_csrf($_POST['csrf_token'] ?? '')) {
    header('Location: /');
    exit;
}

$raw_token = trim($_POST['order_token'] ?? '');
$step      = (int)($_POST['step'] ?? 0);
$deleted   = false;
$csrf      = generate_csrf();

if (strlen($raw_token) !== 16 || !ctype_alnum($raw_token)) {
    header('Location: /');
    exit;
}

// A receipt capability is armed ONLY inside index.php after a verified
// pickup-password unlock, sealed with the same AES key as reveal payloads,
// bound to the unlocked token, and single-use. Possession of the order token
// alone therefore reaches the password gate — never the destructive step.
const RECEIPT_MAX_AGE = 600; // seconds a confirmed receipt stays confirmable

function receipt_capability_valid(?array $cap, string $token): bool {
    if (!is_array($cap) || (time() - ($cap['ts'] ?? 0)) >= RECEIPT_MAX_AGE) {
        return false;
    }
    $dec = open_payload($cap['sealed'] ?? []);
    return is_array($dec) && ($dec['token'] ?? '') === $token;
}

// ── Step 1 — show confirmation page ──────────────────────────────────────────
// A token alone proves nothing: only a DELIVERED order may be received, so
// anything else (preparing, already received/deleted, unknown) is bounced
// with the same redirect — no existence or state oracle.
if ($step === 1 && $error === '') {
    try {
        $stmt = get_db()->prepare(
            "SELECT id FROM orders WHERE order_token = ? AND status = 'delivered' LIMIT 1"
        );
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

// ── Step 2 — execute receipt (blocked budget already set $error above) ───────
// Two independent secrets must line up before anything is destroyed: a valid
// CSRF token AND a fresh post-unlock receipt capability for THIS token. The
// capability is consumed on presentation — win or lose — so it can never be
// replayed, and a tampered/stale/foreign one fails closed to an error page.
if ($step === 2 && $error === '') {
    $cap = $_SESSION['receipt'] ?? null;
    unset($_SESSION['receipt']); // single-use: consume before deciding

    if (!receipt_capability_valid($cap, $raw_token)) {
        $error = t('public.receive.error.locked');
    } else {
        try {
            $deleted = order_receive_atomic($raw_token);
            if (!$deleted) {
                $error = t('public.receive.error.invalid_state');
            } else {
                log_event('received', null, $raw_token);
            }
        } catch (Exception $e) {
            log_err('Receive step2: ' . $e->getMessage());
            $error = t('public.receive.error.server');
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $deleted ? t('public.receive.title.done') : t('public.receive.title.confirm') ?></title><link rel="stylesheet" href="/style.css">
<?php if ($deleted): ?>
<meta http-equiv="refresh" content="10; url=/">
<?php endif; ?>
</head>
<body>
<main>
    <div class="wordmark">DEAD DROP // <?= htmlspecialchars(site_name(), ENT_QUOTES, 'UTF-8') ?></div>

    <?php if ($deleted): ?>
    <!-- ── Success ─────────────────────────────────────────────────────── -->
    <h1><?= t('public.receive.title.done') ?></h1>
    <div class="status-card">
        <div class="status-label"><?= t('public.receive.status_label.done') ?></div>
        <div class="status-badge delivered"><?= t('public.receive.status.done') ?></div>
        <div class="location-reveal">
            <div class="reveal-section">
                <div class="reveal-key"><?= t('public.receive.confirmation_label') ?></div>
                <div class="reveal-value"><?= t('public.receive.confirmation_text') ?></div>
            </div>
        </div>
        <div class="once-note"><?= t('public.receive.redirect_note') ?></div>
    </div>

    <?php elseif ($error): ?>
    <!-- ── Error ───────────────────────────────────────────────────────── -->
    <h1><?= t('public.receive.title.error') ?></h1>
    <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
    <a href="/" class="btn"><?= t('common.back') ?></a>

    <?php else: ?>
    <!-- ── Confirmation page (step 1) ──────────────────────────────────── -->
    <h1><?= t('public.receive.title.confirm') ?></h1>
    <div class="confirm-card">
        <div class="status-label"><?= t('public.index.token_label') ?></div>
        <div class="confirm-token"><?= htmlspecialchars($raw_token, ENT_QUOTES, 'UTF-8') ?></div>
        <div class="confirm-warning"><?= t('public.receive.warning') ?></div>
        <div class="confirm-actions">
            <form method="POST" action="/receive.php">
                <input type="hidden" name="csrf_token"
                       value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="order_token"
                       value="<?= htmlspecialchars($raw_token, ENT_QUOTES, 'UTF-8') ?>">
                <input type="hidden" name="step" value="2">
                <button type="submit" class="btn btn-confirm-delete"><?= t('public.receive.confirm_delete_button') ?></button>
            </form>
            <a href="/" class="btn-cancel-link"><?= t('common.cancel') ?></a>
        </div>
    </div>
    <?php endif; ?>

    <div class="trust-bar" aria-label="<?= htmlspecialchars(t('public.trust.aria_label'), ENT_QUOTES, 'UTF-8') ?>">
        <span class="trust-lock" aria-hidden="true"></span>
        <span class="trust-text"><?= t('public.trust.secure') ?></span>
        <span class="trust-sep">·</span>
        <span class="trust-text"><?= t('public.trust.auto_delete') ?></span>
        <span class="trust-sep">·</span>
        <span class="trust-text"><?= t('public.trust.no_tracking') ?></span>
    </div>
    <?php if (compliance_note_enabled()): ?><div class="compliance-note"><?= t('common.compliance_note') ?></div><?php endif; ?>
</main>
<?php if ($deleted): ?>
<script src="/public.js"></script>
<?php endif; ?>
</body>
</html>
