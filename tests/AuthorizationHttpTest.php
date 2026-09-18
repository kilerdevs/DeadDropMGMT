<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Aggressive authorization tests over real HTTP ─────────────────────────────
// courier_owns_order() unit checks live in AuthorizationTest; THIS suite drives
// the actual endpoints with a logged-in courier and tries everything a
// malicious courier would try: IDOR on other couriers' orders, destructive
// actions on them, privilege escalation, owner-only surfaces, and destructive
// calls without CSRF. The database is the verdict — "redirected" is not
// enough, the target row must be untouched.

$port = 8941;
$root = dirname(__DIR__);
$cmd  = escapeshellarg(PHP_BINARY)
      . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
      . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
// Portable null device (same pattern as PublicFlow/StateRace): hardcoded NUL
// would create a stray ./NUL file on Linux and stop suppressing output.
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
register_shutdown_function(function () use ($proc): void {
    // Portable teardown: taskkill is Windows-only — on Linux an orphaned
    // php -S keeps the output pipe open and hangs the whole job.
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
});
$B = "http://127.0.0.1:$port";

function _az(string $method, string $url, ?array $f, string $ck): array {
    $opts = ['http' => [
        'method' => $method, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 15,
        'header' => ($f !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                  . ($ck !== '' ? "Cookie: $ck\r\n" : ''),
    ]];
    if ($f !== null) { $opts['http']['content'] = http_build_query($f); }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0; $sc = ''; $loc = '';
    // PHP 8.5 deprecates $http_response_header: new API where it exists.
    $headers = function_exists('http_get_last_response_headers')
        ? (http_get_last_response_headers() ?? [])
        : ($http_response_header ?? []);
    foreach ($headers as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $p = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($p !== '' && str_contains($p, '=')) { $sc = $p; }
        }
        if (preg_match('#^Location:#i', $h)) { $loc = trim(substr($h, 9)); }
    }
    return [$status, $body === false ? '' : $body, $sc ?: $ck, $loc];
}
$csrfOf = static function (string $b): string {
    preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
    return $m[1] ?? '';
};

// Wait for the server — ALWAYS sleep between probes: a tight loop burns all
// attempts before php -S even binds on a cold CI runner.
$up = false;
for ($i = 0; $i < 50; $i++) {
    try { [$st] = _az('GET', "$B/healthz.php", null, ''); if ($st === 200) { $up = true; break; } }
    catch (Throwable) { }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { exit(T::done()); }

// ── Seed: owner, two couriers, three orders ───────────────────────────────────
$db = get_db();
$db->prepare("DELETE FROM users WHERE username IN ('t_ah_owner','t_ah_courier_a','t_ah_courier_b')")->execute();
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'ahtoken%'")->execute();

$hash = password_hash('AzPass123!', PASSWORD_BCRYPT);
$mk   = static function (string $u, string $r) use ($db, $hash): int {
    $db->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, '$r')")->execute([$u, $hash]);
    return (int)$db->lastInsertId();
};
$ownerId   = $mk('t_ah_owner', 'owner');
$courierA  = $mk('t_ah_courier_a', 'courier');
$courierB  = $mk('t_ah_courier_b', 'courier');

$ins = $db->prepare(
    "INSERT INTO orders (created_by, order_token, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, 'x', 'ZQ==', 'abababababababababababab', 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
);
$ins->execute([$courierA, 'ahtokenA00000001']); $orderA = (int)$db->lastInsertId();
$ins->execute([$courierB, 'ahtokenB00000002']); $orderB = (int)$db->lastInsertId();
$ins->execute([null,       'ahtokenO00000003']); $orderO = (int)$db->lastInsertId();

$login = static function (string $user, string $pass) use ($B, $csrfOf): array {
    [, $b, $ck] = _az('GET', "$B/admin/index.php", null, '');
    [$st, , $ck, $loc] = _az('POST', "$B/admin/login.php",
        ['csrf_token' => $csrfOf($b), 'username' => $user, 'password' => $pass], $ck);
    if ($st !== 302) {
        fwrite(STDERR, "LOGIN FAILED for $user: status $st\n");
        exit(1);
    }
    // Success is proven by the redirect target: orders.php (fully logged in)
    // or the mandatory 2FA enrollment gate for couriers.
    $needs2fa = str_contains($loc, '2fa.php');
    if (!$needs2fa) {
        if (!str_contains($loc, 'orders.php')) {
            // A bounce anywhere else is a failed login — surface the flash.
            [, $errPage] = _az('GET', "$B$loc", null, $ck);
            preg_match('/class="(?:alert|flash|login-error)[^"]*"[^>]*>(.{0,200})/s', $errPage, $em);
            fwrite(STDERR, "LOGIN REJECTED for $user -> $loc: "
                . trim(preg_replace('/\s+/', ' ', strip_tags($em[1] ?? '(no flash)'))) . "\n");
            exit(1);
        }
        // A successful password login for a COURIER still bounces orders.php
        // straight into the mandatory 2FA enrollment — that is success too.
        [, $b,, $loc2] = _az('GET', "$B/admin/orders.php", null, $ck);
        if (str_contains($loc2, '2fa.php')) {
            $needs2fa = true;
        } elseif (str_contains($b, 'name="password"') || $b === '') {
            fwrite(STDERR, "LOGIN INEFFECTIVE for $user: orders.php did not render\n");
            exit(1);
        }
    }
    return [$ck, $needs2fa];
};
[$ck, $needs2fa] = $login('t_ah_courier_a', 'AzPass123!');
T::ok('courier A logged in (gated to 2FA enrollment)', $needs2fa);

// ── Failed logins are audited (brute-force visibility) ──────────────────────
// The audit row carries the attempted username (never the password) plus the
// client IP audit() always records; the limiter caps attempts per IP, so
// this cannot be turned into log spam.
$db->exec("DELETE FROM audit_log WHERE action = 'login_failed'");
[, $bL, $ckL] = _az('GET', "$B/admin/index.php", null, '');
[$stL] = _az('POST', "$B/admin/login.php",
    ['csrf_token' => $csrfOf($bL), 'username' => 't_ah_owner', 'password' => 'WrongPass1!'], $ckL);
T::eq('wrong password bounces to login', 302, $stL);
$aud = $db->query("SELECT detail, ip_address FROM audit_log WHERE action = 'login_failed' ORDER BY id DESC LIMIT 1")->fetch();
T::eq('failed login audited with attempted username', 't_ah_owner', $aud['detail'] ?? null);
T::ok('failed login carries the client IP', ($aud['ip_address'] ?? '') !== '');
$db->exec("DELETE FROM audit_log WHERE action = 'login_failed'");

// 2FA is mandatory for couriers: every admin page bounces to the enrollment
// form until TOTP is enabled. Enroll through the real UI flow: pull the
// pending secret off the page, compute the current code, confirm.
[, $b] = _az('GET', "$B/admin/2fa.php", null, $ck);
T::ok('courier gated into 2FA enrollment', str_contains($b, 'action" value="enable'));
preg_match('/id="totp-secret">([^<]+)</', $b, $mSecret);
$secret = preg_replace('/\s+/', '', $mSecret[1] ?? '');
T::ok('pending TOTP secret displayed', preg_match('/^[A-Z2-7]{32}$/', $secret) === 1);
$code = totp_code($secret);
[, $b] = _az('POST', "$B/admin/2fa.php",
    ['csrf_token' => $csrfOf($b), 'action' => 'enable', 'code' => $code], $ck);
T::ok('2FA enrollment accepted', str_contains($b, 'totp_enabled') === false && !str_contains($b, 'action" value="enable'));

// Couriers have no forms on orders.php — their CSRF token comes from the
// edit page of their OWN order.
[$stE, $bE] = _az('GET', "$B/admin/edit.php?id=$orderA", null, $ck);
$csrf = $csrfOf($bE);
T::ok('courier session has a CSRF token'
    . " [st=$stE len=" . strlen($bE) . ' hasform=' . (int)str_contains($bE, '<form') . ']', $csrf !== '');

$orderBExists = static fn(): bool => (bool)$db->query("SELECT 1 FROM orders WHERE id = $orderB")->fetch();

// ── IDOR: courier A against courier B's order ────────────────────────────────
[$st, $b] = _az('GET', "$B/admin/edit.php?id=$orderB", null, $ck);
T::ok('edit of foreign order redirects away', $st === 302);
T::ok('edit of foreign order leaks no token', !str_contains($b, 'ahtokenB'));

foreach ([
    'delete.php'         => ['id' => $orderB, 'confirm' => '1'],
    'mark_delivered.php' => ['id' => $orderB],
    'order_close.php'    => ['id' => $orderB],
    'order_remove.php'   => ['id' => $orderB],
    'extend.php'         => ['id' => $orderB, 'hours' => '48', 'ref' => 'orders'],
] as $ep => $fields) {
    _az('POST', "$B/admin/$ep", ['csrf_token' => $csrf] + $fields, $ck);
    T::ok("courier A cannot destroy foreign order via $ep", $orderBExists());
}

// Orphan order (created_by NULL) is equally out of reach.
[$st, $b] = _az('GET', "$B/admin/edit.php?id=$orderO", null, $ck);
T::ok('edit of orphan order redirects away', $st === 302);
_az('POST', "$B/admin/delete.php", ['csrf_token' => $csrf, 'id' => $orderO], $ck);
T::ok('courier A cannot delete the orphan order',
    (bool)$db->query("SELECT 1 FROM orders WHERE id = $orderO")->fetch());

// ── Privilege escalation: courier promotes himself ───────────────────────────
_az('POST', "$B/admin/user_action.php",
    ['csrf_token' => $csrf, 'action' => 'promote', 'user_id' => $courierA], $ck);
$role = $db->query("SELECT role FROM users WHERE id = $courierA")->fetchColumn();
T::eq('courier cannot promote himself to owner', 'courier', $role);

// ── Owner-only surfaces ──────────────────────────────────────────────────────
foreach (['settings.php', 'users.php', 'panic.php', 'analytics.php', 'audit_log.php'] as $page) {
    [$st] = _az('GET', "$B/admin/$page", null, $ck);
    T::ok("courier A bounced from $page", $st === 302);
}
// The most damaging one: disabling the rate limiter via the settings API.
_az('POST', "$B/admin/save_setting.php",
    ['csrf_token' => $csrf, 'key' => 'rate_limit_enabled', 'value' => '0'], $ck);
T::eq('courier cannot disable the rate limiter via save_setting',
    '1', get_setting('rate_limit_enabled', '1'));
_az('POST', "$B/admin/save_setting.php",
    ['csrf_token' => $csrf, 'key' => 'site_name', 'value' => 'PWNED'], $ck);
T::ok('courier cannot change settings via save_setting',
    get_setting('site_name', 'MGT') !== 'PWNED');
[, $b] = _az('GET', "$B/admin/download_log.php?file=app", null, $ck);
T::ok('courier gets no log download', !str_contains($b, '"level"'));

// ── CSRF negative on a destructive endpoint ──────────────────────────────────
_az('POST', "$B/admin/delete.php", ['id' => $orderA], $ck);
T::ok('own order survives destructive call without CSRF token',
    (bool)$db->query("SELECT 1 FROM orders WHERE id = $orderA")->fetch());

// ── Positive control: courier A CAN act on his own order ─────────────────────
[$st] = _az('POST', "$B/admin/extend.php",
    ['csrf_token' => $csrf, 'id' => $orderA, 'hours' => '48', 'ref' => 'orders'], $ck);
$row = $db->query("SELECT expires_at FROM orders WHERE id = $orderA")->fetch();
T::ok('courier A extends his OWN order (positive control)',
    $row !== null && (time() - strtotime((string)$row['expires_at'])) < 49 * 3600);

// ── Owner control: owner CAN delete courier B's order ────────────────────────
$ock = $login('t_ah_owner', 'AzPass123!')[0];
[, $b] = _az('GET', "$B/admin/orders.php", null, $ock);
$ocsrf = $csrfOf($b);
T::ok('owner logged in', $ocsrf !== '');
_az('POST', "$B/admin/delete.php", ['csrf_token' => $ocsrf, 'id' => $orderB, 'confirm' => '1'], $ock);
T::ok('owner deletes foreign order (positive control)', !$orderBExists());

// ── Stale keystroke poll across login must not clobber the auth cookie ─────
// The login form polls check_setup.php per keystroke, so a poll is routinely
// in flight across login's session_regenerate_id(true): it lands with a dead
// session id, and a cookie-emitting start would mint an empty session whose
// Set-Cookie overwrites the brand-new auth cookie (instant post-login
// logout). Replay it deterministically: log in, then present the PRE-login
// cookie to the poll endpoint.
[, $bS, $ckS] = _az('GET', "$B/admin/index.php", null, '');
[$stS,, $ckS2] = _az('POST', "$B/admin/login.php",
    ['csrf_token' => $csrfOf($bS), 'username' => 't_ah_owner', 'password' => 'AzPass123!'], $ckS);
T::eq('re-login for stale-poll probe', 302, $stS);
[, , $ckAfter] = _az('GET', "$B/admin/check_setup.php?username=t_ah_owner", null, $ckS);
T::eq('stale poll sends no Set-Cookie', $ckS, $ckAfter);
[$stO, $bO] = _az('GET', "$B/admin/orders.php", null, $ckS2);
T::ok('auth cookie survives the stale poll',
    $stO === 200 && str_contains($bO, '/admin/logout.php'));

// ── Cleanup ──────────────────────────────────────────────────────────────────
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'ahtoken%'")->execute();
$db->prepare('DELETE FROM users WHERE id IN (?, ?, ?)')->execute([$ownerId, $courierA, $courierB]);

exit(T::done());
