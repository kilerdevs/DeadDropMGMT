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
purge_orders_like($db, 'ahtoken');

$hash = password_hash('AzPass123!', PASSWORD_BCRYPT);
$mk   = static function (string $u, string $r) use ($db, $hash): int {
    $db->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, '$r')")->execute([$u, $hash]);
    return (int)$db->lastInsertId();
};
$ownerId   = $mk('t_ah_owner', 'owner');
$courierA  = $mk('t_ah_courier_a', 'courier');
$courierB  = $mk('t_ah_courier_b', 'courier');

$ins = $db->prepare(
    "INSERT INTO orders (created_by, token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, ?, ?, 'x', 'ZQ==', 'abababababababababababab', 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
);
$ins->execute([$courierA, ...tk('ahtokenA00000001')]); $orderA = (int)$db->lastInsertId();
$ins->execute([$courierB, ...tk('ahtokenB00000002')]); $orderB = (int)$db->lastInsertId();
$ins->execute([null,       ...tk('ahtokenO00000003')]); $orderO = (int)$db->lastInsertId();

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

// ── Token display (ADR-019): the database holds only an index and an encrypted
// copy, so every admin page that shows a token must open it — and none may 500.
set_setting('analytics_enabled', '1');
log_event('lookup', $orderO, 'ahtokenO00000003');
audit('t_ah_tokview', $orderO, 'ahtokenO00000003');
T::ok('orders page lists the readable token', str_contains($b, 'ahtokenO00000003'));
[$stV, $bV] = _az('GET', "$B/admin/edit.php?id=$orderO", null, $ock);
T::ok('edit page shows the readable token', $stV === 200 && str_contains($bV, 'ahtokenO00000003'));
[$stV, $bV] = _az('GET', "$B/admin/analytics.php", null, $ock);
T::ok('analytics page shows the readable token', $stV === 200 && str_contains($bV, 'ahtokenO00000003'));
[$stV, $bV] = _az('GET', "$B/admin/audit_log.php", null, $ock);
T::ok('audit log shows the readable token for a live order', $stV === 200 && str_contains($bV, 'ahtokenO00000003'));
$db->prepare("DELETE FROM audit_log WHERE action = 't_ah_tokview'")->execute();
$db->exec("DELETE FROM order_events WHERE event_type = 'lookup' AND order_id = $orderO");
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

// (The owner session below is the one the stale-poll probe logged in: any
// later login supersedes an older cookie — single active session.)
// ── Live CSRF token: stale page tokens must not break language/logout ───────
// verify_csrf() rotates the session token on every success, so the copy
// rendered into a page is stale once ANY request from it was verified (an
// autosave, a status poll). The sidebar language switch and every POST form
// take the live token from /admin/csrf_token.php instead.
[, $bTok] = _az('GET', "$B/admin/settings.php", null, $ckS2);
preg_match('/var rendered = "([0-9a-f]{64})"/', $bTok, $mTok);
$renderedTok = $mTok[1] ?? '';
T::ok('sidebar renders a language token', $renderedTok !== '');
[$stPoll, $bPoll] = _az('POST', "$B/admin/maps_action.php", ['csrf_token' => $renderedTok, 'action' => 'status'], $ckS2);
T::ok('an in-page poll verifies (and thereby rotates) the token', $stPoll === 200 && str_contains($bPoll, '"ok":true'));
[$stStale] = _az('POST', "$B/admin/set_lang.php", ['csrf_token' => $renderedTok, 'lang' => 'en'], $ckS2);
T::eq('the rendered token is now stale (the bug being fixed)', 403, $stStale);
[$stLive, $bLive] = _az('GET', "$B/admin/csrf_token.php", null, $ckS2);
$liveTok = (string)(json_decode($bLive, true)['csrf'] ?? '');
T::ok('token endpoint answers the live token', $stLive === 200 && preg_match('/^[0-9a-f]{64}$/', $liveTok) === 1);
[, $bLive2] = _az('GET', "$B/admin/csrf_token.php", null, $ckS2);
T::eq('asking does not rotate it', $liveTok, (string)(json_decode($bLive2, true)['csrf'] ?? ''));
[$stFresh, $bFresh] = _az('POST', "$B/admin/set_lang.php", ['csrf_token' => $liveTok, 'lang' => 'en'], $ckS2);
T::ok('language switch works with the live token', $stFresh === 200 && str_contains($bFresh, '"ok":true'));
[$stAnon,,, $locAnon] = _az('GET', "$B/admin/csrf_token.php", null, '');
T::ok('the token endpoint is not public', $stAnon === 302 && str_contains($locAnon, 'index.php'));
[$stPost] = _az('POST', "$B/admin/csrf_token.php", [], $ckS2);
T::eq('the token endpoint is GET-only', 405, $stPost);
$xs = stream_context_create(['http' => ['method' => 'GET', 'ignore_errors' => true, 'header' => "Cookie: $ckS2\r\nSec-Fetch-Site: cross-site\r\n"]]);
$bXs = (string)@file_get_contents("$B/admin/csrf_token.php", false, $xs);
T::ok('a cross-site request gets no token', !str_contains($bXs, '"csrf":"') || str_contains($bXs, 'Forbidden'));
T::ok('admin.js refreshes the token before any POST form', str_contains((string)file_get_contents(dirname(__DIR__) . '/admin/admin.js'), 'csrf_token.php'));

// ── CLI-only scripts are inert over HTTP ─────────────────────────────────────
// Maintenance tools, the container journey, browser-test seeds and test
// harness files carry no auth of their own; one that a web server ever
// executes must answer 404 without doing anything. (php -S ignores
// .htaccess, so this proves the scripts' own SAPI guard.)
foreach ([
    'tools/purge_pickup_password_recovery.php', 'tools/separate_keys.php', 'tools/migrate_cbc_to_gcm.php',
    'tools/rotate_aes_key.php', 'tools/mutation_probe.php', 'docker/e2e_journey.php', 'e2e/seed.php',
    'cron/cleanup.php', 'cron/maps_sync.php', 'tests/schema_loader.php', 'tests/bootstrap.php', 'tests/run_all.php',
] as $cliOnly) {
    [$stCli, $bCli] = _az('GET', "$B/$cliOnly", null, '');
    T::ok("$cliOnly is inert over HTTP", $stCli === 404 && trim($bCli) === '');
}

// ── Sessions belong to live accounts ─────────────────────────────────────────
// A deleted account, or one whose sessions the owner revoked, is refused on
// its very next request — not when the cookie finally times out.
$mkOwner = static function (string $u) use ($db, $hash): int {
    $db->prepare('DELETE FROM users WHERE username = ?')->execute([$u]);
    $db->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'owner')")->execute([$u, $hash]);
    return (int)$db->lastInsertId();
};
$tmpA = $mkOwner('t_ah_temp_a');
$ckA  = $login('t_ah_temp_a', 'AzPass123!')[0];
[$stOk] = _az('GET', "$B/admin/orders.php", null, $ckA);
T::eq('live account session works', 200, $stOk);
$db->prepare('DELETE FROM users WHERE id = ?')->execute([$tmpA]);
[$stGone,,, $locGone] = _az('GET', "$B/admin/orders.php", null, $ckA);
T::ok('deleted account is refused on the next request', $stGone === 302 && str_contains($locGone, 'revoked=1'));

$tmpB = $mkOwner('t_ah_temp_b');
$ckB  = $login('t_ah_temp_b', 'AzPass123!')[0];
$db->prepare('UPDATE users SET active_session_id = ? WHERE id = ?')->execute(['revoked', $tmpB]);
[$stRev,,, $locRev] = _az('GET', "$B/admin/orders.php", null, $ckB);
T::ok('revoked sessions are refused on the next request', $stRev === 302 && str_contains($locRev, 'revoked=1'));
$db->prepare('DELETE FROM users WHERE id = ?')->execute([$tmpB]);

// ── A valid login of one's own must not launder guesses at someone else ─────
// Budget 3, an attacker alternating wrong guesses at the owner with genuine
// logins of a courier account they hold: successes used to reset the shared
// per-IP counter, so the guesses were never throttled.
$prevMax = get_setting('rate_limit_max', '10');
set_setting('rate_limit_max', '3');
$db->exec("DELETE FROM rate_limits WHERE scope LIKE 'admin_login%'");
$attempt = static function (string $user, string $pass) use ($B, $csrfOf): array {
    [, $b, $ck] = _az('GET', "$B/admin/index.php", null, '');
    [$st, , $ck, $loc] = _az('POST', "$B/admin/login.php",
        ['csrf_token' => $csrfOf($b), 'username' => $user, 'password' => $pass], $ck);
    return [$st, $loc, $ck];
};
for ($i = 0; $i < 3; $i++) {
    $attempt('t_ah_owner', 'wrong-guess-' . $i);
    $attempt('t_ah_courier_a', 'AzPass123!'); // the attacker's own valid credentials
}
[, $locFinal, $ckFinal] = $attempt('t_ah_owner', 'AzPass123!');
[$stAfter] = _az('GET', "$B/admin/orders.php", null, $ckFinal);
T::ok('interleaved valid logins did not reset the guess budget', $stAfter === 302);
set_setting('rate_limit_max', $prevMax);
$db->exec("DELETE FROM rate_limits WHERE scope LIKE 'admin_login%'");

// ── Cleanup ──────────────────────────────────────────────────────────────────
purge_orders_like($db, 'ahtoken');
$db->prepare('DELETE FROM users WHERE id IN (?, ?, ?)')->execute([$ownerId, $courierA, $courierB]);

exit(T::done());
