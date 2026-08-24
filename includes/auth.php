<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

// ── Session ───────────────────────────────────────────────────────────────────

function start_secure_session(): void {
    if (session_status() !== PHP_SESSION_NONE) return;
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => request_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_name(SESSION_NAME);
    session_start();
}

// ── Identity helpers ──────────────────────────────────────────────────────────

function is_admin_logged_in(): bool {
    return !empty($_SESSION['user_id']) && !empty($_SESSION['user_role']);
}

function is_owner(): bool {
    return ($_SESSION['user_role'] ?? '') === 'owner';
}

function is_courier(): bool {
    return ($_SESSION['user_role'] ?? '') === 'courier';
}

function current_user_id(): int {
    return (int)($_SESSION['user_id'] ?? 0);
}

function current_user_name(): string {
    return $_SESSION['user_name'] ?? '';
}

// ── Access guards ─────────────────────────────────────────────────────────────

function require_admin(): void {
    start_secure_session();
    if (!is_admin_logged_in()) {
        header('Location: /admin/index.php');
        exit;
    }
    require_once dirname(__DIR__) . '/includes/settings.php';
    $timeout = admin_session_seconds();
    if ($timeout > 0 && isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > $timeout) {
        admin_logout();
        header('Location: /admin/index.php?timeout=1');
        exit;
    }

    // 2FA is mandatory for couriers (optional for the owner). Gate every
    // page but the enrollment page itself, logout, and self-service
    // preference endpoints that touch nothing but the caller's own row.
    if (is_courier() && empty($_SESSION['totp_enabled'])) {
        $script = basename($_SERVER['SCRIPT_NAME'] ?? '');
        if (!in_array($script, ['2fa.php', 'logout.php', 'set_lang.php'], true)) {
            header('Location: /admin/2fa.php?required=1');
            exit;
        }
    }
}

function require_owner(): void {
    require_admin();
    if (!is_owner()) {
        header('Location: /admin/orders.php');
        exit;
    }
}

// ── Ownership check for courier actions ───────────────────────────────────────
// Fetches created_by for an order and returns false if the courier doesn't own it.

function courier_owns_order(int $order_id): bool {
    if (is_owner()) return true;
    try {
        $stmt = get_db()->prepare('SELECT created_by FROM orders WHERE id = ? LIMIT 1');
        $stmt->execute([$order_id]);
        $row = $stmt->fetch();
        return $row && (int)$row['created_by'] === current_user_id();
    } catch (Exception $e) {
        return false;
    }
}

// ── Login / logout ────────────────────────────────────────────────────────────

// Completes login: sets the full session and clears any pending-2FA state.
function admin_finish_login(int $user_id, string $role, string $username, bool $totp_enabled = false, string $lang = 'en'): void {
    session_regenerate_id(true);
    $_SESSION['user_id']      = $user_id;
    $_SESSION['user_role']    = $role;
    $_SESSION['user_name']    = $username;
    $_SESSION['totp_enabled'] = $totp_enabled;
    $_SESSION['user_lang']    = $lang;
    $_SESSION['login_time']   = time();
    unset($_SESSION['csrf_token'], $_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_time'],
          $_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time']);
}

// Returns 'ok' (fully logged in), 'need_2fa' (password ok, TOTP code required
// next), 'need_setup' (account exists but has no password yet — first login;
// the pending-setup session state is armed), or 'fail' (bad credentials).
function admin_login(string $username, string $password): string {
    require_once dirname(__DIR__) . '/includes/db.php';
    try {
        $stmt = get_db()->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $user = $stmt->fetch();
    } catch (Exception $e) {
        // users table may not exist yet — fall back to config-based owner
        if (defined('ADMIN_USERNAME') && defined('ADMIN_PASSWORD_HASH') &&
            hash_equals(ADMIN_USERNAME, $username) &&
            password_verify($password, ADMIN_PASSWORD_HASH)) {
            admin_finish_login(0, 'owner', $username);
            return 'ok';
        }
        return 'fail';
    }

    if (!$user) {
        // Burn the same bcrypt cost a real account would: unknown username
        // and wrong password become indistinguishable by timing. No sleeps —
        // the hash itself IS the constant-time answer.
        password_verify($password, DUMMY_AUTH_HASH);
        return 'fail';
    }

    $hash = (string)$user['password_hash'];

    // Accounts awaiting first login carry no password: the enrollment secret
    // issued at account creation is the claim credential — knowing only the
    // username must never reach the setup step. Anything else just fails.
    if ($hash === '') {
        $enrollment = trim((string)($_POST['enrollment'] ?? ''));
        if ($password !== '' || $enrollment === '' || !enrollment_secret_valid((int)$user['id'], $enrollment)) {
            return 'fail';
        }
        session_regenerate_id(true);
        $_SESSION['pending_setup_user_id'] = (int)$user['id'];
        $_SESSION['pending_setup_time']    = time();
        unset($_SESSION['csrf_token']);
        return 'need_setup';
    }

    if (!password_verify($password, $hash)) {
        return 'fail';
    }

    if (!empty($user['totp_enabled'])) {
        session_regenerate_id(true);
        $_SESSION['pending_2fa_user_id'] = (int)$user['id'];
        $_SESSION['pending_2fa_time']    = time();
        unset($_SESSION['csrf_token']);
        return 'need_2fa';
    }

    admin_finish_login((int)$user['id'], $user['role'], $user['username'], false, $user['lang'] ?? 'en');
    return 'ok';
}

function admin_logout(): void {
    start_secure_session();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

function generate_csrf(): string {
    start_secure_session();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(string $token): bool {
    start_secure_session();
    if (empty($_SESSION['csrf_token'])) return false;
    return hash_equals($_SESSION['csrf_token'], $token);
}

// ── Security headers ──────────────────────────────────────────────────────────

function set_security_headers(bool $admin = false): string {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 0');

    // Never let the browser cache or bfcache-restore a rendered page — these
    // carry decrypted locations, passwords, or TOTP secrets. Applies to every
    // page (public reveal included), so nothing lingers after logout or
    // navigating away.
    header('Cache-Control: no-store, no-cache, must-revalidate, private');
    header('Pragma: no-cache');

    if (request_is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    if ($admin) {
        header('Referrer-Policy: strict-origin');
        $nonce = base64_encode(random_bytes(18));
        header('Permissions-Policy: geolocation=(self), camera=(), microphone=()');
        header(
            "Content-Security-Policy: default-src 'self'; " .
            "style-src 'self'; " .
            "font-src 'self'; " .
            "script-src 'self' 'nonce-{$nonce}'; " .
            "img-src 'self' data: blob:; " .
            "connect-src 'self';"
        );
        return $nonce;
    }

    header('Referrer-Policy: no-referrer');
    $nonce = base64_encode(random_bytes(18));
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    header(
        "Content-Security-Policy: default-src 'self'; " .
        "style-src 'self'; " .
        "font-src 'self'; " .
        "script-src 'self' 'nonce-{$nonce}'; " .
        "img-src 'self'; " .
        "frame-src https://www.openstreetmap.org;"
    );
    return $nonce;
}

// ── Rate limiting (IP-based, DB-backed, togglable via settings) ───────────────
// scope separates independent budgets (e.g. 'public' pickup guessing vs
// 'admin_login' vs 'admin_2fa') so abuse on one surface doesn't lock out another.

function rl_enabled(): bool {
    require_once dirname(__DIR__) . '/includes/settings.php';
    return get_setting('rate_limit_enabled', '1') === '1';
}

function rl_status(string $scope = 'public'): array {
    if (!rl_enabled()) {
        return ['blocked' => false, 'remaining' => 0, 'count' => 0];
    }
    require_once dirname(__DIR__) . '/includes/settings.php';
    $max    = rl_max();
    $window = rl_window_seconds();
    try {
        $stmt = get_db()->prepare('SELECT count, window_start FROM rate_limits WHERE ip_address = ? AND scope = ? LIMIT 1');
        $stmt->execute([get_client_ip(), $scope]);
        $row = $stmt->fetch();
    } catch (Exception $e) {
        // Fail CLOSED: this limiter guards pickup-password guessing and admin
        // login. If the counter is unreadable the caller must treat the
        // request as blocked (temporary outage), never as unblocked traffic.
        log_err('Rate limit status failed (fail closed): ' . $e->getMessage());
        return ['blocked' => true, 'remaining' => $window, 'count' => 0];
    }
    if (!$row || (time() - strtotime($row['window_start'])) >= $window) {
        return ['blocked' => false, 'remaining' => $window, 'count' => 0];
    }
    return [
        'blocked'   => (int)$row['count'] >= $max,
        'remaining' => max(0, $window - (time() - strtotime($row['window_start']))),
        'count'     => (int)$row['count'],
    ];
}

// Spend one attempt from the IP budget AND decide, atomically. The whole
// read-decide-write runs inside one transaction on a row lock (SELECT ...
// FOR UPDATE): concurrent requests from the same IP are serialized, so no
// increment can be lost and two simultaneous visitors can never both see
// "one attempt left". The returned 'blocked' verdict comes from the
// post-increment count of that single state transition.
function rl_hit(string $scope = 'public'): array {
    if (!rl_enabled()) {
        return ['blocked' => false, 'remaining' => 0, 'count' => 0];
    }
    require_once dirname(__DIR__) . '/includes/settings.php';
    $ip     = get_client_ip();
    $max    = rl_max();
    $window = rl_window_seconds();
    $db     = get_db();
    try {
        $db->beginTransaction();
        $stmt = $db->prepare(
            'SELECT count, window_start FROM rate_limits WHERE ip_address = ? AND scope = ? LIMIT 1 FOR UPDATE'
        );
        $stmt->execute([$ip, $scope]);
        $row = $stmt->fetch();

        $stale = !$row || (time() - strtotime($row['window_start'])) >= $window;
        if ($stale) {
            $db->prepare(
                'INSERT INTO rate_limits (ip_address, scope, count, window_start) VALUES (?, ?, 1, UTC_TIMESTAMP())
                 ON DUPLICATE KEY UPDATE count = 1, window_start = UTC_TIMESTAMP()'
            )->execute([$ip, $scope]);
            $count = 1;
            $window_start = time();
        } else {
            $count = (int)$row['count'] + 1;
            $window_start = (int)strtotime($row['window_start']);
            $db->prepare('UPDATE rate_limits SET count = count + 1 WHERE ip_address = ? AND scope = ?')
               ->execute([$ip, $scope]);
        }
        $db->commit();
    } catch (Exception $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        // Fail CLOSED: an uncountable limiter must deny, never wave through.
        log_err('Rate limit increment failed (fail closed): ' . $e->getMessage());
        return ['blocked' => true, 'remaining' => $window, 'count' => 0];
    }
    return [
        'blocked'   => $count >= $max,
        'remaining' => max(0, $window - (time() - $window_start)),
        'count'     => $count,
    ];
}

// Legacy shape for callers that only spend budget without reading the
// verdict — every decision-making path should use rl_hit() instead.
function rl_increment(string $scope = 'public'): void {
    rl_hit($scope);
}

// Reset a scope's counter for the current IP (called on a successful attempt).
function rl_reset(string $scope = 'public'): void {
    try {
        get_db()->prepare('DELETE FROM rate_limits WHERE ip_address = ? AND scope = ?')
            ->execute([get_client_ip(), $scope]);
    } catch (Exception $e) {
        // best-effort
    }
}

// ── Session failure bucket ───────────────────────────────────────────────────
// The IP limiter has two blind spots: many strangers behind one NAT/VPN exit
// can lock each other out, while an attacker rotating cheap IPs spreads
// attempts wide. This per-session counter (the session cookie IS the bucket)
// is enforced alongside the IP budget — whoever trips EITHER is blocked.
// Legit users behind shared NAT keep their own bucket; an attacker must now
// rotate both IP and cookie per attempt. Server-side storage means clearing
// cookies is also visible as a brand-new session with zero history.

function bucket_fail(string $scope = 'public'): void {
    $cur = $_SESSION['pw_fail'][$scope] ?? null;
    if (!$cur || (time() - $cur['ts']) >= 900) {
        $_SESSION['pw_fail'][$scope] = ['n' => 1, 'ts' => time()];
        return;
    }
    $cur['n']++;
    $_SESSION['pw_fail'][$scope] = $cur;
}

function bucket_status(string $scope = 'public', int $max = 10): array {
    $cur = $_SESSION['pw_fail'][$scope] ?? null;
    $n   = ($cur && (time() - $cur['ts']) < 900) ? (int)$cur['n'] : 0;
    return ['count' => $n, 'blocked' => $n >= max(1, $max)];
}

function bucket_remaining(string $scope = 'public'): int {
    $cur = $_SESSION['pw_fail'][$scope] ?? null;
    return $cur ? max(0, 900 - (time() - $cur['ts'])) : 0;
}

function bucket_clear(string $scope = 'public'): void {
    unset($_SESSION['pw_fail'][$scope]);
}

// ── Enrollment secrets (single-use claim credentials) ────────────────────────
// Issued when an account is created passwordless; the recipient must present
// it once at first login to reach the choose-password step. 256-bit random,
// stored SHA-256-hashed, expires, cleared on successful claim.

function enrollment_secret_generate(): string {
    return bin2hex(random_bytes(32)); // 256 bits → 64 hex chars
}

function enrollment_secret_hash(string $secret): string {
    return hash('sha256', trim($secret));
}

function enrollment_secret_valid(int $user_id, string $secret): bool {
    try {
        $stmt = get_db()->prepare(
            'SELECT enrollment_hash FROM users
             WHERE id = ? AND enrollment_hash IS NOT NULL
               AND (enrollment_expires IS NULL OR enrollment_expires > NOW())
             LIMIT 1'
        );
        $stmt->execute([$user_id]);
        $row = $stmt->fetch();
        return $row && hash_equals((string)$row['enrollment_hash'], enrollment_secret_hash($secret));
    } catch (Exception $e) {
        return false;
    }
}
