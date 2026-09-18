<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once __DIR__ . '/net.php';
require_once __DIR__ . '/settings.php';

// ── Session ───────────────────────────────────────────────────────────────────

function start_secure_session(): void {
    if (session_status() !== PHP_SESSION_NONE) return;
    // Harden the mechanism itself, explicitly rather than trusting php.ini
    // defaults: strict mode refuses uninitialized IDs (kills fixation via
    // SID injection — regenerate_id() alone only helps after login),
    // cookies-only keeps SIDs out of URLs (Referer/logs), trans_sid off.
    // Must precede session_start(); no-op when already started (guard above).
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
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
    // isset, not !empty: the config-fallback owner authenticates with
    // user_id 0 (no users row exists yet) and must stay logged in.
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_role']);
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
    // Sliding inactivity window: every authenticated admin request refreshes
    // the timestamp, so the timeout above measures idleness, not time since
    // login. Refreshed AFTER the check so an expired session can never be
    // revived by the very request that should kill it.
    $_SESSION['login_time'] = time();

    // Single active session: a newer login elsewhere supersedes this one.
    // The superseded browser is logged out with an explanatory flag (not a
    // silent bounce) so the legitimate owner notices the conflict.
    if (admin_session_superseded()) {
        admin_logout();
        header('Location: /admin/index.php?superseded=1');
        exit;
    }

    // 2FA is mandatory for couriers (optional for the owner). Gate every
    // page but the enrollment page itself and routes flagged 2fa-exempt
    // (logout, self-service preferences touching only the caller's own
    // row). The flag comes from the dispatch route table — or is set by
    // 2fa.php itself, the one standalone page that needs it — never from
    // the script name, so shims and canonical dispatch URLs gate alike.
    if (is_courier() && empty($_SESSION['totp_enabled'])) {
        if (empty($GLOBALS['DDMGMT_ROUTE_2FA_EXEMPT'])) {
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

// True when another login has superseded this session: the session id the
// account holder authenticated with no longer matches the id recorded at
// the latest login. The config-fallback owner (user_id 0, no users row),
// rows predating the column rollout (NULL), and unreadable rows (fail OPEN:
// a transient read error must not log out every admin) never count as
// superseded — the mismatch path still catches every real conflict.
function admin_session_superseded(): bool {
    $uid = (int)($_SESSION['user_id'] ?? 0);
    if ($uid <= 0) {
        return false;
    }
    try {
        $stmt = get_db()->prepare('SELECT active_session_id FROM users WHERE id = ? LIMIT 1');
        $stmt->execute([$uid]);
        $active = $stmt->fetchColumn();
    } catch (Exception $e) {
        return false;
    }
    if (!is_string($active) || $active === '') {
        return false;
    }
    return !hash_equals($active, session_id());
}

// ── Login / logout ────────────────────────────────────────────────────────────

// Completes login: sets the full session and clears any pending-2FA state.
// Starts the session itself — library code must not depend on every caller
// remembering to (an unstarted session would silently lose the login state
// and skip the fixation-protection regenerate below).
function admin_finish_login(int $user_id, string $role, string $username, bool $totp_enabled = false, string $lang = 'en'): void {
    start_secure_session();
    session_regenerate_id(true);
    $_SESSION['user_id']      = $user_id;
    $_SESSION['user_role']    = $role;
    $_SESSION['user_name']    = $username;
    $_SESSION['totp_enabled'] = $totp_enabled;
    $_SESSION['user_lang']    = $lang;
    $_SESSION['login_time']   = time();
    unset($_SESSION['csrf_token'], $_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_time'],
          $_SESSION['pending_setup_user_id'], $_SESSION['pending_setup_time']);
    // Single active session: this login supersedes any other holding these
    // credentials (stolen-cookie coexistence ends at the victim's next
    // request). Best-effort — a record failure must not deny the login the
    // session itself just granted; the config-fallback owner (user_id 0, no
    // users row) has nothing to record against.
    if ($user_id > 0) {
        try {
            get_db()->prepare('UPDATE users SET active_session_id = ? WHERE id = ?')
                ->execute([session_id(), $user_id]);
        } catch (Exception $e) {
            log_err('Login session record failed: ' . $e->getMessage());
        }
    }
}

// True only when the users table itself is absent (fresh install, schema not
// yet applied) — SQLSTATE 42S02 / driver error 1146, or the equivalent
// message on other drivers. Used to scope the config-owner login fallback:
// a missing table means "nobody can exist yet", while any other DB failure
// (connection lost, server gone) must fail closed instead of answering 'ok'
// from config credentials and skipping the DB account's TOTP.
function _db_table_missing(Throwable $e): bool {
    if ($e instanceof PDOException && (string)$e->getCode() === '42S02') {
        return true;
    }
    $msg = strtolower($e->getMessage());
    return str_contains($msg, "doesn't exist") || str_contains($msg, 'no such table');
}

// Returns 'ok' (fully logged in), 'need_2fa' (password ok, TOTP code required
// next), 'need_setup' (account exists but has no password yet — first login;
// the pending-setup session state is armed), or 'fail' (bad credentials).
function admin_login(string $username, string $password): string {
    require_once dirname(__DIR__) . '/includes/db.php';
    start_secure_session();
    try {
        $stmt = get_db()->prepare('SELECT * FROM users WHERE username = ? LIMIT 1');
        $stmt->execute([$username]);
        $user = $stmt->fetch();
    } catch (Exception $e) {
        // Fresh-install fallback ONLY (see _db_table_missing): on any other
        // DB error this returns 'fail' — a mid-operation outage must never
        // downgrade a TOTP-enrolled owner to password-only config login.
        if (_db_table_missing($e) && defined('ADMIN_USERNAME') && defined('ADMIN_PASSWORD_HASH') &&
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
    // username must never reach the setup step. Anything else just fails,
    // after burning the same bcrypt cost as every other rejection so the
    // empty-hash branch is not a timing oracle for "this account exists
    // and awaits enrollment".
    if ($hash === '') {
        $enrollment = trim((string)($_POST['enrollment'] ?? ''));
        if ($password !== '' || $enrollment === '' || !enrollment_secret_valid((int)$user['id'], $enrollment)) {
            password_verify($password, DUMMY_AUTH_HASH);
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
    // Tell the browser to drop everything this origin kept: bfcache pages,
    // localStorage, service workers. Server-side the session is already
    // dead; this closes the shared-computer gap where a cached admin page
    // could still be rendered from browser storage. No-op without a secure
    // context, harmless otherwise.
    header('Clear-Site-Data: "cache", "cookies", "storage"');
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

function generate_csrf(): string {
    start_secure_session();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(mixed $token, bool $rotate = true): bool {
    start_secure_session();
    // Array-shaped input (csrf_token[]=x) must fail the check, not TypeError
    // at the hash_equals() boundary — outside every try, and catches are
    // Exception-only, so a bare array would 500 instead of answering false.
    if (!is_string($token) || $token === '') return false;
    if (empty($_SESSION['csrf_token'])) return false;
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        return false;
    }
    // One token, one use: a token stolen by XSS (or leaked via referer/
    // history) cannot be replayed for further state-changing requests —
    // every successful verification mints a fresh value. Form flows pick
    // the new token up on the next render; endpoints answering via fetch
    // must include it in their JSON response so the caller can continue.
    // Read-only probes ($rotate = false) reveal nothing an attacker could
    // reuse, and skipping the churn there keeps high-frequency callers
    // (per-keystroke setup checks) from desyncing their token.
    if ($rotate) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return true;
}

// Read-only probes (setup check, log verification) must not rotate: with
// rotation, a high-frequency caller would mint a token its page never picks
// up and desync itself. The named wrapper exists so call sites state that
// intent — a bare verify_csrf(..., rotate: false) is how the next read-only
// endpoint silently breaks its callers.
function verify_csrf_readonly(mixed $token): bool {
    return verify_csrf($token, rotate: false);
}

// JSON reply for fetch-called endpoints. Because verify_csrf() rotates the
// session token on success, every state-changing AJAX response must hand the
// caller its next token — otherwise the second request from a page that was
// rendered once would fail CSRF forever.
function json_out(array $payload, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    // Overwrite, never += : a caller-supplied 'csrf' would be the pre-rotation
    // token verify_csrf() just invalidated, desyncing the client forever.
    $payload['csrf'] = generate_csrf();
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

// ── Security headers ──────────────────────────────────────────────────────────

// Pure builder behind set_security_headers(): returning the header lines
// instead of emitting them makes both profiles assertable in-process
// (header() is a no-op under CLI, so FailClosedTest pins this list).
// Referrer-Policy is no-referrer on BOTH profiles: photo URLs are
// unguessable-but-bearer capability links, and nothing server-side reads
// the Referer — no HTTP_REFERER consumer exists anywhere — so not even the
// origin is disclosed to third parties (map tiles, judges) or logs.
/** @return array<int,string> */
function _security_headers_list(bool $admin, string $nonce): array {
    $h = [
        'X-Frame-Options: DENY',
        'X-Content-Type-Options: nosniff',
        'X-XSS-Protection: 0',
        // Never let the browser cache or bfcache-restore a rendered page —
        // these carry decrypted locations, passwords, or TOTP secrets.
        // Applies to every page (public reveal included), so nothing lingers
        // after logout or navigating away.
        'Cache-Control: no-store, no-cache, must-revalidate, private',
        'Pragma: no-cache',
        'Referrer-Policy: no-referrer',
    ];

    if (request_is_https()) {
        $h[] = 'Strict-Transport-Security: max-age=31536000; includeSubDomains';
    }

    if ($admin) {
        $h[] = 'Permissions-Policy: geolocation=(self), camera=(), microphone=()';
        $h[] = "Content-Security-Policy: default-src 'self'; " .
            "style-src 'self'; " .
            "font-src 'self'; " .
            "script-src 'self' 'nonce-{$nonce}'; " .
            "img-src 'self' data: blob:; " .
            "connect-src 'self'; " .
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
        return $h;
    }

    $h[] = 'Permissions-Policy: geolocation=(), camera=(), microphone=()';
    $h[] = "Content-Security-Policy: default-src 'self'; " .
        "style-src 'self'; " .
        "font-src 'self'; " .
        "script-src 'self' 'nonce-{$nonce}'; " .
        "img-src 'self'; " .
        'frame-src https://www.openstreetmap.org; ' .
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none';";
    return $h;
}

function set_security_headers(bool $admin = false): string {
    $nonce = base64_encode(random_bytes(18));
    foreach (_security_headers_list($admin, $nonce) as $line) {
        header($line);
    }
    return $nonce;
}

// ── Rate limiting (IP-based, DB-backed, togglable via settings) ───────────────
// scope separates independent budgets (e.g. 'public' pickup guessing vs
// 'admin_login' vs 'admin_2fa') so abuse on one surface doesn't lock out another.

function rl_enabled(): bool {
    require_once dirname(__DIR__) . '/includes/settings.php';
    return get_setting('rate_limit_enabled', '1') === '1';
}

// window_start is written by MySQL UTC_TIMESTAMP() — a bare DATETIME with
// no zone. Parsing it with plain strtotime() interprets it in PHP's
// default timezone, skewing every window by the UTC offset: east of UTC
// (Europe/Warsaw) windows expire hours early and budgets reset constantly
// (fail-open for guessing); west of UTC they never roll and visitors stay
// sticky-blocked with absurd cooldowns. Anchoring the parse to UTC keeps
// the read side on the same clock the write side used. Returns false for
// values the database should never hold (fail-closed callers decide).
function _rl_parse_window_start(string $v): int|false {
    $v = trim($v);
    if ($v === '') {
        return false;
    }
    return strtotime($v . ' UTC');
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
    if (!$row) {
        return ['blocked' => false, 'remaining' => $window, 'count' => 0];
    }
    // Corrupt timestamps fail CLOSED: _rl_parse_window_start() answers false
    // for values the database should never hold, and legacy zero-dates
    // parse to year 0 — both would otherwise read as "window started ages
    // ago", silently resetting the budget so a damaged row could never
    // block. A garbage counter denies (loudly) rather than waving traffic
    // through.
    $started = _rl_parse_window_start((string)$row['window_start']);
    if ($started === false || $started <= 0) {
        log_err('Rate limit status: unparseable window_start, failing closed');
        return ['blocked' => true, 'remaining' => $window, 'count' => 0];
    }
    if ((time() - $started) >= $window) {
        return ['blocked' => false, 'remaining' => $window, 'count' => 0];
    }
    return [
        'blocked'   => (int)$row['count'] >= $max,
        'remaining' => max(0, $window - (time() - $started)),
        'count'     => (int)$row['count'],
    ];
}

// Spend one attempt from the IP budget AND decide, atomically. The whole
// read-decide-write runs inside one transaction on a row lock (SELECT ...
// FOR UPDATE): concurrent requests from the same IP are serialized, so no
// increment can be lost and two simultaneous visitors can never both see
// "one attempt left". The returned 'blocked' verdict comes from the
// post-increment count of that single state transition.
function rl_hit(string $scope = 'public', ?int $max_override = null, ?int $window_override = null): array {
    if (!rl_enabled()) {
        return ['blocked' => false, 'remaining' => 0, 'count' => 0];
    }
    require_once dirname(__DIR__) . '/includes/settings.php';
    $ip     = get_client_ip();
    $max    = $max_override ?? rl_max();
    $window = $window_override ?? rl_window_seconds();
    $db     = get_db();
    try {
        $db->beginTransaction();
        $stmt = $db->prepare(
            'SELECT count, window_start FROM rate_limits WHERE ip_address = ? AND scope = ? LIMIT 1 FOR UPDATE'
        );
        $stmt->execute([$ip, $scope]);
        $row = $stmt->fetch();

        // Unparseable window_start fails CLOSED (see rl_status): rolling back
        // and denying beats resetting the budget on a damaged row.
        $started = $row ? _rl_parse_window_start((string)$row['window_start']) : time();
        if ($started === false || $started <= 0) {
            $db->rollBack();
            log_err('Rate limit increment: unparseable window_start, failing closed');
            return ['blocked' => true, 'remaining' => $window, 'count' => 0];
        }

        $stale = !$row || (time() - $started) >= $window;
        if ($stale) {
            $db->prepare(
                'INSERT INTO rate_limits (ip_address, scope, count, window_start) VALUES (?, ?, 1, UTC_TIMESTAMP())
                 ON DUPLICATE KEY UPDATE count = 1, window_start = UTC_TIMESTAMP()'
            )->execute([$ip, $scope]);
            $count = 1;
            $window_start = time();
        } else {
            $count = (int)$row['count'] + 1;
            $window_start = $started;
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
        // count > max (not >=): the max-th attempt still executes, matching
        // rl_status's "blocked when the stored count reached max" semantics —
        // the budget buys max real attempts, the max+1-th is denied.
        'blocked'   => $count > $max,
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
// Window follows the configured IP-limiter window (rl_window_seconds) so the
// two layers can never silently diverge when an admin retunes one of them.

function bucket_fail(string $scope = 'public'): void {
    $cur = $_SESSION['pw_fail'][$scope] ?? null;
    if (!$cur || (time() - $cur['ts']) >= rl_window_seconds()) {
        $_SESSION['pw_fail'][$scope] = ['n' => 1, 'ts' => time()];
        return;
    }
    $cur['n']++;
    $_SESSION['pw_fail'][$scope] = $cur;
}

function bucket_status(string $scope = 'public', int $max = 10): array {
    $cur = $_SESSION['pw_fail'][$scope] ?? null;
    $n   = ($cur && (time() - $cur['ts']) < rl_window_seconds()) ? (int)$cur['n'] : 0;
    return ['count' => $n, 'blocked' => $n >= max(1, $max)];
}

function bucket_remaining(string $scope = 'public'): int {
    $cur = $_SESSION['pw_fail'][$scope] ?? null;
    return $cur ? max(0, rl_window_seconds() - (time() - $cur['ts'])) : 0;
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
        // No IS NULL arm: a missing expiry is a damaged row, not a perpetual
        // credential. Every creation path stamps NOW() + 24h; NULL must fail.
        $stmt = get_db()->prepare(
            'SELECT enrollment_hash FROM users
             WHERE id = ? AND enrollment_hash IS NOT NULL
               AND enrollment_expires > NOW()
             LIMIT 1'
        );
        $stmt->execute([$user_id]);
        $row = $stmt->fetch();
        return $row && hash_equals((string)$row['enrollment_hash'], enrollment_secret_hash($secret));
    } catch (Exception $e) {
        return false;
    }
}

// ── TOTP replay resistance ──────────────────────────────────────────────────
// A code is valid inside its ±1-step window (~90 s) — without a burn list it
// is valid AGAIN for a second login in the same window. Each accepted
// counter is claimed at most once per user: the conditional UPDATE is the
// atomic test-and-set, so two concurrent logins with the same code cannot
// both succeed. Counters grow with time, so a stale value can only ever
// reject (fail closed, self-healing as time advances) — a NULL (never used,
// freshly enrolled) accepts any valid counter.
function totp_claim_counter(int $user_id, int $counter): bool {
    try {
        $stmt = get_db()->prepare(
            'UPDATE users SET totp_last_counter = ?
             WHERE id = ? AND (totp_last_counter IS NULL OR totp_last_counter < ?)'
        );
        $stmt->execute([$counter, $user_id, $counter]);
        return $stmt->rowCount() === 1;
    } catch (Exception $e) {
        return false;
    }
}
