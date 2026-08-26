<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';

// Tells the login form whether a username belongs to an account that is
// still awaiting first-login password setup. CSRF-checked, read-only.
//
// The login page fires this on every keystroke, so it gets its own generous
// budget (30 / 15 min) instead of sharing the admin_login one — an attacker
// burning THIS scope must not lock the owner out of logging in, and vice
// versa. Enumeration resistance note: the response distinguishes only
// "awaiting setup" from "everything else"; the limiter caps how fast that
// one bit can be polled per IP.
set_security_headers(false);
start_secure_session();

header('Content-Type: application/json; charset=utf-8');

$needs = false;
$limited = false;
try {
    // Read-only probe: no state changes, so the CSRF token is verified but
    // not consumed — per-keystroke calls keep working from one page render.
    if (!verify_csrf($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '', rotate: false)) {
        $limited = true; // indistinguishable slow-down for bad requests
    } else {
        $hit = rl_hit('admin_setup', 30);
        $limited = $hit['blocked'];
    }
} catch (Throwable) {
    // Fail closed: limiter trouble means no enumeration oracle today.
    $limited = true;
}
http_response_code($limited ? 429 : 200);

if (!$limited) {
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
