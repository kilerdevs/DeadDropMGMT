<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

set_security_headers(false);
start_secure_session();

$pending_uid = (int)($_SESSION['pending_2fa_user_id'] ?? 0);
$pending_ts  = (int)($_SESSION['pending_2fa_time']    ?? 0);

// Pending state expires after 5 minutes — back to the login form.
if ($pending_uid <= 0 || (time() - $pending_ts) > 300) {
    unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_time']);
    header('Location: /admin/index.php');
    exit;
}

$csrf  = generate_csrf();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.verify2fa.error.csrf');
    } else {
        // verify_csrf() rotates on success, invalidating the token captured
        // at the top: a wrong-code re-render below must embed the fresh
        // value, or the next attempt dies with "Invalid CSRF token".
        $csrf = generate_csrf();
        $rl = rl_status('admin_2fa');
        // Per-ACCOUNT budget next to the per-IP one: a stolen password plus
        // rotating addresses must not buy unlimited six-digit guesses.
        $acctKey = 'u:' . $pending_uid;
        $acctRl = rl_status('admin_2fa_acct', $acctKey);
        if ($acctRl['blocked']) {
            $rl = $acctRl;
        }
        if ($rl['blocked']) {
            $error = t('admin.verify2fa.error.rate_limited', ['min' => (int)ceil($rl['remaining'] / 60)]);
        } else {
            try {
                $stmt = get_db()->prepare(
                    'SELECT id, role, username, totp_secret_enc, totp_secret_iv, totp_enabled, lang
                     FROM users WHERE id = ? LIMIT 1'
                );
                $stmt->execute([$pending_uid]);
                $user = $stmt->fetch();
            } catch (Exception $e) {
                $user = false;
            }

            $secret = ($user && $user['totp_enabled'] && $user['totp_secret_enc'] && $user['totp_secret_iv'])
                ? decrypt_secret($user['totp_secret_enc'], $user['totp_secret_iv'])
                : false;

            $code = trim(post_string('code'));
            // Replay resistance: a code is good for its FIRST presentation
            // only. A replayed-but-valid code takes the exact same path as
            // a wrong one below (same message, same limiter spend) — success
            // vs replay must not be distinguishable.
            $counter = ($user && $secret !== false) ? totp_verify_counter($secret, $code) : null;
            $claimed = $counter !== null && $user && totp_claim_counter((int)$user['id'], $counter);
            if ($user && $claimed) {
                rl_reset('admin_2fa_acct', $acctKey); // a valid code proves the real owner is here
                admin_finish_login((int)$user['id'], $user['role'], $user['username'], true, $user['lang'] ?? 'en');
                header('Location: /admin/orders.php');
                exit;
            }
            if (!$user || $secret === false) {
                // No real secret to verify against — burn one full TOTP
                // verification anyway so failure timing does not leak
                // whether the account exists or its secret decrypts.
                totp_verify(DUMMY_TOTP_SECRET, $code);
            }
            $hit = rl_hit('admin_2fa');
            rl_hit('admin_2fa_acct', null, null, $acctKey);
            if ($hit['blocked']) {
                $error = t('admin.verify2fa.error.rate_limited', ['min' => (int)ceil($hit['remaining'] / 60)]);
            } else {
                // Guessing visibility mirrors the password step: the audit
                // row carries the targeted account, never the tried code.
                audit('2fa_failed', $pending_uid, null, (string)($user['username'] ?? 'unknown'));
                $error = t('admin.verify2fa.error.invalid_code');
            }
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
<title>Admin — <?= t('admin.verify2fa.title') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body class="login-page">
<div class="login-wrap">
    <div class="wordmark">DEAD DROP // ADMIN</div>
    <h1><?= t('admin.verify2fa.h1') ?></h1>
    <?php if ($error): ?>
    <!-- $error is t()-built (HTML-safe); raw echo (see admin/orders.php). -->
    <div class="alert"><?= $error ?></div>
    <?php endif; ?>
    <form method="POST" action="/admin/verify_2fa.php" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-group">
            <label for="code"><?= t('admin.verify2fa.code_label') ?></label>
            <input type="text" id="code" name="code" inputmode="numeric" pattern="[0-9]{6}"
                   maxlength="6" placeholder="000000" autocomplete="one-time-code" autofocus>
        </div>
        <div class="form-actions">
            <button type="submit" class="btn"><?= t('admin.verify2fa.verify_button') ?></button>
            <!-- Logout is POST-only (CSRF): formaction re-targets this form's
                 POST (with its CSRF token) at logout.php — no nested form. -->
            <button type="submit" formaction="/admin/logout.php" class="btn-cancel"><?= t('admin.verify2fa.cancel_button') ?></button>
        </div>
    </form>
</div>
</body>
</html>
