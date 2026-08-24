<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';

// Tells the login form whether a username belongs to an account that is
// still awaiting first-login password setup. CSRF-checked, read-only.
set_security_headers(false);
start_secure_session();

header('Content-Type: application/json; charset=utf-8');

$needs = false;
if (verify_csrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
    $username = trim((string)($_GET['username'] ?? ''));
    if ($username !== '' && strlen($username) <= 64) {
        try {
            $stmt = get_db()->prepare(
                "SELECT 1 FROM users WHERE username = ? AND (password_hash = '' OR password_hash IS NULL) LIMIT 1"
            );
            $stmt->execute([$username]);
            $needs = (bool)$stmt->fetch();
        } catch (Exception $e) {
            $needs = false;
        }
    }
}

echo json_encode(['needs_setup' => $needs], JSON_UNESCAPED_UNICODE);
