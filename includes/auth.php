<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

// ── Session ───────────────────────────────────────────────────────────────────

function start_secure_session(): void {
    if (session_status() !== PHP_SESSION_NONE) return;
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => isset($_SERVER['HTTPS']),
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
function admin_finish_login(int $user_id, string $role, string $username): void {
    session_regenerate_id(true);
    $_SESSION['user_id']    = $user_id;
    $_SESSION['user_role']  = $role;
    $_SESSION['user_name']  = $username;
    $_SESSION['login_time'] = time();
    unset($_SESSION['csrf_token'], $_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_time']);
}

// Returns 'ok' (fully logged in), 'need_2fa' (password ok, TOTP code required
// next), or 'fail' (bad credentials).
function admin_login(string $username, string $password): string {
    require_once dirname(__DIR__) . '/includes/db.php';
    try {
        $db = get_db();

        // Auto-seed owner from config constants if the users table is empty
        $count = (int)$db->query('SELECT COUNT(*) FROM users')->fetchColumn();
        if ($count === 0 && defined('ADMIN_USERNAME') && defined('ADMIN_PASSWORD_HASH')) {
            $db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, "owner")')
               ->execute([ADMIN_USERNAME, ADMIN_PASSWORD_HASH]);
        }

        $stmt = $db->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
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

    if (!$user || !password_verify($password, $user['password_hash'])) {
        return 'fail';
    }

    if (!empty($user['totp_enabled'])) {
        session_regenerate_id(true);
        $_SESSION['pending_2fa_user_id'] = (int)$user['id'];
        $_SESSION['pending_2fa_time']    = time();
        unset($_SESSION['csrf_token']);
        return 'need_2fa';
    }

    admin_finish_login((int)$user['id'], $user['role'], $user['username']);
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

    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }

    if ($admin) {
        header('Referrer-Policy: strict-origin');
        $nonce = base64_encode(random_bytes(18));
        header('Permissions-Policy: geolocation=(self), camera=(), microphone=()');
        header(
            "Content-Security-Policy: default-src 'self'; " .
            "style-src 'self' https://fonts.googleapis.com; " .
            "font-src 'self' https://fonts.gstatic.com; " .
            "script-src 'self' 'nonce-{$nonce}'; " .
            "img-src 'self' data: blob: https://*.tile.openstreetmap.org; " .
            "connect-src 'self' https://nominatim.openstreetmap.org;"
        );
        return $nonce;
    }

    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
    header(
        "Content-Security-Policy: default-src 'self'; " .
        "style-src 'self' https://fonts.googleapis.com; " .
        "font-src 'self' https://fonts.gstatic.com; " .
        "img-src 'self'; " .
        "frame-src https://www.openstreetmap.org;"
    );
    return '';
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
        return ['blocked' => false, 'remaining' => 0, 'count' => 0];
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

function rl_increment(string $scope = 'public'): void {
    if (!rl_enabled()) return;
    require_once dirname(__DIR__) . '/includes/settings.php';
    $ip     = get_client_ip();
    $window = rl_window_seconds();
    try {
        $db   = get_db();
        $stmt = $db->prepare('SELECT window_start FROM rate_limits WHERE ip_address = ? AND scope = ? LIMIT 1');
        $stmt->execute([$ip, $scope]);
        $row = $stmt->fetch();
        if (!$row || (time() - strtotime($row['window_start'])) >= $window) {
            $db->prepare(
                'INSERT INTO rate_limits (ip_address, scope, count, window_start) VALUES (?, ?, 1, UTC_TIMESTAMP())
                 ON DUPLICATE KEY UPDATE count = 1, window_start = UTC_TIMESTAMP()'
            )->execute([$ip, $scope]);
        } else {
            $db->prepare('UPDATE rate_limits SET count = count + 1 WHERE ip_address = ? AND scope = ?')
               ->execute([$ip, $scope]);
        }
    } catch (Exception $e) {
        log_err('Rate limit increment failed: ' . $e->getMessage());
    }
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
