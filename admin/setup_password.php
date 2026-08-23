<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

set_security_headers(false);
start_secure_session();

$pending_uid = (int)($_SESSION['pending_setup_user_id'] ?? 0);
$pending_ts  = (int)($_SESSION['pending_setup_time']   ?? 0);

// Pending state expires after 5 minutes — back to the login form.
if ($pending_uid <= 0 || (time() - $pending_ts) > 300) {
    unset($_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time']);
    header('Location: /admin/index.php');
    exit;
}

$csrf  = generate_csrf();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $error = t('admin.setup.error.csrf');
    } else {
        $pw1 = (string)($_POST['password']  ?? '');
        $pw2 = (string)($_POST['password2'] ?? '');

        if (strlen($pw1) < 8) {
            $error = t('admin.setup.error.min8');
        } elseif ($pw1 !== $pw2) {
            $error = t('admin.setup.error.mismatch');
        } else {
            try {
                $db   = get_db();
                // Guard: only claim an account that is still passwordless —
                // if someone completed setup meanwhile, refuse to overwrite.
                $stmt = $db->prepare(
                    "UPDATE users SET password_hash = ? WHERE id = ? AND (password_hash = '' OR password_hash IS NULL)"
                );
                $stmt->execute([password_hash($pw1, PASSWORD_BCRYPT, ['cost' => 12]), $pending_uid]);

                if ($stmt->rowCount() === 0) {
                    unset($_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time']);
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
                        unset($_SESSION['csrf_token'], $_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time']);
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
    <div class="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
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
