<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

set_security_headers(false);
start_secure_session();

$pending_uid = (int)($_SESSION['pending_setup_user_id'] ?? 0);
$pending_ts  = (int)($_SESSION['pending_setup_time']   ?? 0);

// Pending state expires after 5 minutes — back to the login form.
if ($pending_uid <= 0 || (time() - $pending_ts) > 300) {
    unset($_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time'], $_SESSION['enrollment_flash']);
    header('Location: /admin/index.php');
    exit;
}

$csrf  = generate_csrf();
$error = '';
// One-time: the enrollment secret issued at account creation (owner bootstrap
// or courier creation). Shown here because this is the only screen the
// creator is guaranteed to see before the secret's context scrolls away.
// Deliberately NOT consumed on render: a failed attempt (too short,
// mismatch, bad CSRF) must re-show the code — this screen holds the only
// copy the creator will ever see. Consumed on the terminal paths below.
// Sealed at rest (see bootstrap.php); a bare string is still honored so a
// setup started before the seal deploy completes instead of bricking.
$flash_raw = $_SESSION['enrollment_flash'] ?? '';
if (is_array($flash_raw)) {
    // A setup begun on the previous build sealed this under the TOTP subkey;
    // honor it once so an upgrade mid-enrollment cannot destroy the only copy.
    $flash_dec = decrypt_flash(
        (string)($flash_raw['ciphertext'] ?? ''),
        (string)($flash_raw['iv'] ?? '')
    );
    if ($flash_dec === false) {
        $flash_dec = decrypt_secret(
            (string)($flash_raw['ciphertext'] ?? ''),
            (string)($flash_raw['iv'] ?? '')
        );
    }
    $enrollment_note = is_string($flash_dec) ? $flash_dec : '';
} else {
    $enrollment_note = (string)$flash_raw;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.setup.error.csrf');
    } else {
        // verify_csrf() rotates on success, invalidating the token captured
        // at the top: an error re-render below must embed the fresh value,
        // or the next submit dies with "Invalid CSRF token".
        $csrf = generate_csrf();
        $pw1 = post_string('password');
        $pw2 = post_string('password2');

        if (strlen($pw1) < 8) {
            $error = t('admin.setup.error.min8');
        } elseif (!password_length_ok($pw1)) {
            $error = t('admin.common.password_too_long');
        } elseif ($pw1 !== $pw2) {
            $error = t('admin.setup.error.mismatch');
        } else {
            try {
                $db   = get_db();
                // Guard: only claim an account that is still passwordless —
                // if someone completed setup meanwhile, refuse to overwrite.
                // Claiming also burns the enrollment secret (single use).
                $stmt = $db->prepare(
                    "UPDATE users SET password_hash = ?, enrollment_hash = NULL, enrollment_expires = NULL
                     WHERE id = ? AND (password_hash = '' OR password_hash IS NULL)"
                );
                $stmt->execute([password_hash($pw1, PASSWORD_BCRYPT, ['cost' => 12]), $pending_uid]);

                if ($stmt->rowCount() === 0) {
                    unset($_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time'], $_SESSION['enrollment_flash']);
                    $_SESSION['login_error'] = t('admin.setup.error.claimed');
                    header('Location: /admin/index.php');
                    exit;
                } else {
                    // Re-read the row so the rest of the login continues from truth.
                    $q = $db->prepare(
                        'SELECT id, role, username, totp_enabled, lang FROM users WHERE id = ? LIMIT 1'
                    );
                    $q->execute([$pending_uid]);
                    $user = $q->fetch();

                    audit('password_set', null, null, 'user_id=' . $pending_uid);

                    if ($user && !empty($user['totp_enabled'])) {
                        session_regenerate_id(true);
                        $_SESSION['pending_2fa_user_id'] = (int)$user['id'];
                        $_SESSION['pending_2fa_time']    = time();
                        unset($_SESSION['csrf_token'], $_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time'], $_SESSION['enrollment_flash']);
                        header('Location: /admin/verify_2fa.php');
                        exit;
                    }

                    admin_finish_login(
                        (int)($user['id'] ?? $pending_uid),
                        (string)($user['role'] ?? 'courier'),
                        (string)($user['username'] ?? ''),
                        false,
                        (string)($user['lang'] ?? 'en')
                    );
                    // Password set: the enrollment secret is burned server-side
                    // above, so its displayed copy is consumed here too.
                    unset($_SESSION['enrollment_flash']);
                    header('Location: /admin/orders.php');
                    exit;
                }
            } catch (Exception $e) {
                log_err('Setup password: ' . $e->getMessage());
                $error = t('admin.setup.error.save_failed');
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
<title>Admin — <?= t('admin.setup.title') ?></title><link rel="stylesheet" href="/admin/style.css">
</head>
<body class="login-page">
<div class="login-wrap">
    <div class="wordmark">DEAD DROP // ADMIN</div>
    <h1><?= t('admin.setup.h1') ?></h1>
    <?php if ($error): ?>
    <!-- t()-built: already HTML-safe, echo raw (see orders.php). -->
    <div class="alert"><?= $error ?></div>
    <?php endif; ?>
    <?php if ($enrollment_note !== ''): ?>
    <!-- Informational, not an error: amber .notice, never the red .alert. -->
    <div class="notice"><?= $enrollment_note ?></div>
    <?php endif; ?>
    <p class="setup-explain"><?= t('admin.setup.explain') ?></p>
    <form method="POST" action="/admin/setup_password.php" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-group">
            <label for="password"><?= t('admin.setup.password_label') ?></label>
            <input type="password" id="password" name="password" autocomplete="new-password" autofocus>
        </div>
        <div class="form-group">
            <label for="password2"><?= t('admin.setup.password2_label') ?></label>
            <input type="password" id="password2" name="password2" autocomplete="new-password">
        </div>
        <button type="submit" class="btn"><?= t('admin.setup.submit_button') ?></button>
    </form>
</div>
</body>
</html>
