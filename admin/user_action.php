<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';

set_security_headers(true);
start_secure_session();
require_owner();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/users.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['flash']    = 'Nieprawidłowy token CSRF.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/users.php');
    exit;
}

$action = $_POST['action'] ?? '';

// ── Create courier ────────────────────────────────────────────────────────────
if ($action === 'create_courier') {
    $username = trim($_POST['username'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if ($username === '' || strlen($username) < 3 || strlen($username) > 64) {
        $_SESSION['flash']    = 'Nazwa użytkownika musi mieć 3–64 znaki.';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }
    if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $username)) {
        $_SESSION['flash']    = 'Nazwa użytkownika może zawierać tylko litery, cyfry, _, - i .';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }
    if (strlen($password) < 8) {
        $_SESSION['flash']    = 'Hasło musi mieć co najmniej 8 znaków.';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }

    try {
        get_db()->prepare(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, "courier")'
        )->execute([$username, password_hash($password, PASSWORD_BCRYPT, ['cost' => 12])]);
        audit('courier_create', null, null, $username);
        $_SESSION['flash']    = "Konto kuriera {$username} zostało utworzone.";
        $_SESSION['flash_ok'] = true;
    } catch (Exception $e) {
        $msg = str_contains($e->getMessage(), 'Duplicate') ? 'Ta nazwa użytkownika jest już zajęta.' : 'Błąd tworzenia konta.';
        log_err('Create courier: ' . $e->getMessage());
        $_SESSION['flash']    = $msg;
        $_SESSION['flash_ok'] = false;
    }
    header('Location: /admin/users.php');
    exit;
}

// ── Delete courier ────────────────────────────────────────────────────────────
if ($action === 'delete_courier') {
    $uid = (int)($_POST['user_id'] ?? 0);

    if ($uid <= 0 || $uid === current_user_id()) {
        $_SESSION['flash']    = 'Nieprawidłowe żądanie.';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }

    try {
        $db   = get_db();
        $user = $db->prepare('SELECT role, username FROM users WHERE id = ? LIMIT 1');
        $user->execute([$uid]);
        $row  = $user->fetch();

        if (!$row || $row['role'] !== 'courier') {
            $_SESSION['flash']    = 'Konto nie istnieje lub nie jest kontem kuriera.';
            $_SESSION['flash_ok'] = false;
            header('Location: /admin/users.php');
            exit;
        }

        $db->prepare('DELETE FROM users WHERE id = ?')->execute([$uid]);
        audit('courier_delete', null, null, $row['username']);
        $_SESSION['flash']    = "Konto kuriera {$row['username']} zostało usunięte.";
        $_SESSION['flash_ok'] = true;
    } catch (Exception $e) {
        log_err('Delete courier: ' . $e->getMessage());
        $_SESSION['flash']    = 'Błąd podczas usuwania konta.';
        $_SESSION['flash_ok'] = false;
    }
    header('Location: /admin/users.php');
    exit;
}

// ── Change password ───────────────────────────────────────────────────────────
if ($action === 'change_password') {
    $uid      = (int)($_POST['user_id']      ?? 0);
    $password = (string)($_POST['new_password'] ?? '');

    if ($uid <= 0) {
        $_SESSION['flash']    = 'Nieprawidłowe żądanie.';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }
    if (strlen($password) < 8) {
        $_SESSION['flash']    = 'Nowe hasło musi mieć co najmniej 8 znaków.';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }

    try {
        $db   = get_db();
        $stmt = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([
            password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
            $uid,
        ]);
        audit('password_change', null, null, "user_id={$uid}");
        $_SESSION['flash']    = 'Hasło zostało zmienione.';
        $_SESSION['flash_ok'] = true;
    } catch (Exception $e) {
        log_err('Change password: ' . $e->getMessage());
        $_SESSION['flash']    = 'Błąd zmiany hasła.';
        $_SESSION['flash_ok'] = false;
    }
    header('Location: /admin/users.php');
    exit;
}

// ── Reset 2FA — owner recovery path for a locked-out account ─────────────────
if ($action === 'reset_2fa') {
    $uid = (int)($_POST['user_id'] ?? 0);
    if ($uid <= 0) {
        $_SESSION['flash']    = 'Nieprawidłowe żądanie.';
        $_SESSION['flash_ok'] = false;
        header('Location: /admin/users.php');
        exit;
    }
    try {
        get_db()->prepare(
            'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_secret_iv = NULL WHERE id = ?'
        )->execute([$uid]);
        audit('2fa_reset', null, null, "user_id={$uid}");
        $_SESSION['flash']    = 'Weryfikacja dwuetapowa została wyłączona dla tego konta.';
        $_SESSION['flash_ok'] = true;
    } catch (Exception $e) {
        log_err('Reset 2FA: ' . $e->getMessage());
        $_SESSION['flash']    = 'Błąd resetowania 2FA.';
        $_SESSION['flash_ok'] = false;
    }
    header('Location: /admin/users.php');
    exit;
}

header('Location: /admin/users.php');
exit;