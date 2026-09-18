<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

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
// Poll endpoint: open the session WITHOUT emitting cookies. The login form
// polls this on every keystroke, so a poll is routinely IN FLIGHT across
// login's session_regenerate_id(true): it lands with a dead session id, and
// a normal strict-mode start would mint a fresh EMPTY session whose
// Set-Cookie clobbers the brand-new auth cookie — an instant post-login
// logout for fast typists. Reads (the readonly CSRF check below) still
// work; nothing here writes session state, so no cookie ever needs sending.
$pollSid = (string)($_COOKIE[SESSION_NAME] ?? '');
if ($pollSid !== '' && preg_match('/^[a-zA-Z0-9,-]{22,256}$/', $pollSid) === 1) {
    session_name(SESSION_NAME);
    session_id($pollSid);
}
ini_set('session.use_cookies', '0');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
ini_set('session.use_strict_mode', '1');
session_start();

header('Content-Type: application/json; charset=utf-8');

$needs = false;
$limited = false;
try {
    // Read-only probe: no state changes, so the CSRF token is verified but
    // not consumed — per-keystroke calls keep working from one page render.
    if (!verify_csrf_readonly($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
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
