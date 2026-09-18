<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Dispatcher contract: route table, handlers, shims, 2FA flag ─────────────
// Part A is pure structural (no server): every route declares a valid
// envelope, every handler exists guarded with no pulls of its own, every
// legacy URL shims to a real route, and the 2FA gate consults the route
// flag instead of script basenames. Part B drives both the shim and the
// canonical dispatch URLs over HTTP and asserts identical outcomes.

$root = dirname(__DIR__);
/** @var array<string,array<string,mixed>> */
$routes = require $root . '/admin/routes.php';

T::ok('eight routes', count($routes) === 8);
foreach ($routes as $name => $r) {
    T::ok("route $name auth domain", in_array($r['auth'] ?? null, ['admin', 'owner', null], true));
    T::ok("route $name headers domain", in_array($r['headers'] ?? null, [true, false, 'json'], true));
    T::ok("route $name method domain", in_array($r['method'] ?? null, ['POST', 'GET', null], true));
    T::ok("route $name csrf domain", in_array($r['csrf'] ?? false, [true, 'optional', false], true));
    foreach (['method_fail', 'csrf_fail'] as $fk) {
        if (($fk === 'method_fail' && empty($r['method'])) || ($fk === 'csrf_fail' && ($r['csrf'] ?? false) !== true)) {
            continue;
        }
        $spec = $r[$fk] ?? null;
        $shapeOk = is_array($spec) && (
            (isset($spec['redirect']) && is_string($spec['redirect']) && $spec['redirect'] !== '')
            || (isset($spec['flash_redirect']) && is_string($spec['flash_redirect']))
            || (isset($spec['json']) && is_array($spec['json']) && is_int($spec['json'][0]) && is_array($spec['json'][1]))
        );
        T::ok("route $name $fk shape", $shapeOk);
    }
    if (isset($r['owns_order'])) {
        $oo = $r['owns_order'];
        T::ok("route $name owns_order source", is_array($oo['source'] ?? null)
            && in_array($oo['source'][0] ?? null, ['POST', 'GET'], true)
            && is_string($oo['source'][1] ?? null));
        T::ok("route $name owns_order deny", isset($oo['deny']['redirect']) || isset($oo['deny']['flash_redirect']));
    }
    $hf = $root . '/admin/actions/' . $r['handler'] . '.php';
    T::ok("route $name handler exists", is_file($hf));
    $hs = (string)file_get_contents($hf);
    T::ok("route $name handler guards its route",
        str_contains($hs, "DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== '$name'"));
    $pulls = [];
    foreach (explode("\n", $hs) as $line) {
        if (preg_match('/\b(require|include)(_once)?\b/', $line)) { $pulls[] = trim($line); }
    }
    T::ok("route $name handler pulls nothing", $pulls === []);
    preg_match_all('/^function\s+(\w+)/mi', $hs, $hm);
    T::ok("route $name handler defines no functions", $hm[1] === []);
    $shim = $root . '/admin/' . $name . '.php';
    T::ok("route $name legacy shim exists", is_file($shim));
}

// The 2FA gate consults the route flag, never script basenames.
$authSrc = (string)file_get_contents($root . '/includes/auth.php');
T::ok('require_admin consults the route flag', str_contains($authSrc, 'DDMGMT_ROUTE_2FA_EXEMPT'));
T::ok('basename allow-list gone', !str_contains($authSrc, "['2fa.php', 'logout.php'"));
T::ok('2fa.php sets its own exemption',
    str_contains((string)file_get_contents($root . '/admin/2fa.php'), 'DDMGMT_ROUTE_2FA_EXEMPT'));

// ── HTTP parity: shims and dispatch URLs behave identically ──────────────────
$port = 8944;
$cmd  = escapeshellarg(PHP_BINARY)
      . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
      . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
register_shutdown_function(function () use ($proc): void {
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

function _dt(string $method, string $url, ?array $f, string $ck): array {
    $opts = ['http' => [
        'method' => $method, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 15,
        'header' => ($f !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                  . ($ck !== '' ? "Cookie: $ck\r\n" : ''),
    ]];
    if ($f !== null) { $opts['http']['content'] = http_build_query($f); }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0; $sc = ''; $loc = '';
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

$up = false;
for ($i = 0; $i < 50; $i++) {
    try { [$st] = _dt('GET', "$B/healthz.php", null, ''); if ($st === 200) { $up = true; break; } }
    catch (Throwable) { }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { exit(T::done()); }

// Pin the rate-limiter budget: suites share one DB and a zeroed budget
// locks the login flow after a single attempt. Restored at the end.
$oldMax = rl_max();
$oldWin = rl_window_seconds();
$oldSite = site_name();
set_setting('rate_limit_max', '10');
set_setting('rate_limit_window_min', '15');

// ── Seed ────────────────────────────────────────────────────────────────────
$db = get_db();
$db->prepare("DELETE FROM users WHERE username LIKE 't_dt\\_%'")->execute();
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'tdtoken%'")->execute();
$hash = password_hash('DtPass123!', PASSWORD_BCRYPT);
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_dt_owner', ?, 'owner')")->execute([$hash]);
$ownerId = (int)$db->lastInsertId();
$db->prepare("INSERT INTO users (username, password_hash, role) VALUES ('t_dt_courier', ?, 'courier')")->execute([$hash]);
$courierId = (int)$db->lastInsertId();
$mkOrder = static function (int $by, string $tok, string $status) use ($db): int {
    $db->prepare(
        "INSERT INTO orders (created_by, order_token, pickup_password_hash, location_encrypted, location_iv,
                             status, delivered_at, expires_at)
         VALUES (?, ?, 'x', 'ZQ==', 'abababababababababababab', ?, NULL, NOW() + INTERVAL 24 HOUR)"
    )->execute([$by, $tok, $status]);
    return (int)$db->lastInsertId();
};
$oidShim = $mkOrder($ownerId, 'tdtoken00000001', 'preparing');
$oidDisp = $mkOrder($ownerId, 'tdtoken00000002', 'preparing');

$login = static function (string $user, string $pass) use ($B, $csrfOf): array {
    [, $b, $ck] = _dt('GET', "$B/admin/index.php", null, '');
    [$st, , $ck, $loc] = _dt('POST', "$B/admin/login.php",
        ['csrf_token' => $csrfOf($b), 'username' => $user, 'password' => $pass], $ck);
    if ($st !== 302) {
        fwrite(STDERR, "LOGIN FAILED for $user: status $st\n");
        exit(1);
    }
    return [$ck, $loc];
};
$ownerCsrf = static function (string $ck) use ($B, $csrfOf): string {
    [, $b] = _dt('GET', "$B/admin/orders.php", null, $ck);
    return $csrfOf($b);
};

// ── Unknown action ──────────────────────────────────────────────────────────
[$st,,, $loc] = _dt('GET', "$B/admin/dispatch.php?action=nope", null, '');
T::ok('unknown action redirects logged-out', $st === 302 && str_contains($loc, 'index.php'));
[$ock] = $login('t_dt_owner', 'DtPass123!');
[$st,,, $loc] = _dt('GET', "$B/admin/dispatch.php?action=nope", null, $ock);
T::ok('unknown action redirects logged-in', $st === 302 && str_contains($loc, 'index.php'));

// ── Method enforcement parity (GET on POST routes) ──────────────────────────
foreach (["$B/admin/mark_delivered.php", "$B/admin/dispatch.php?action=mark_delivered"] as $u) {
    [$st,,, $loc] = _dt('GET', $u, null, $ock);
    T::ok("GET rejected like legacy: $u", $st === 302 && str_contains($loc, 'orders.php'));
}

// ── CSRF failure: redirect + row untouched, both URLs ───────────────────────
foreach ([["$B/admin/mark_delivered.php", $oidShim], ["$B/admin/dispatch.php?action=mark_delivered", $oidDisp]] as [$u, $oid]) {
    [$st,,, $loc] = _dt('POST', $u, ['csrf_token' => str_repeat('0', 64), 'id' => $oid], $ock);
    $st2 = $db->prepare('SELECT status FROM orders WHERE id = ?');
    $st2->execute([$oid]);
    T::ok("bad CSRF bounced, row untouched: $u",
        $st === 302 && str_contains($loc, 'orders.php') && $st2->fetchColumn() === 'preparing');
}

// ── Success path parity: valid token delivers, both URLs ────────────────────
[$st,,, $loc] = _dt('POST', "$B/admin/mark_delivered.php",
    ['csrf_token' => $ownerCsrf($ock), 'id' => $oidShim], $ock);
$st2 = $db->prepare('SELECT status FROM orders WHERE id = ?');
$st2->execute([$oidShim]);
T::ok('shim delivers', $st === 302 && str_contains($loc, 'orders.php') && $st2->fetchColumn() === 'delivered');
[$st,,, $loc] = _dt('POST', "$B/admin/dispatch.php?action=mark_delivered",
    ['csrf_token' => $ownerCsrf($ock), 'id' => $oidDisp], $ock);
$st2->execute([$oidDisp]);
T::ok('dispatch delivers', $st === 302 && str_contains($loc, 'orders.php') && $st2->fetchColumn() === 'delivered');

// ── set_lang JSON via dispatch ──────────────────────────────────────────────
[$st, $b] = _dt('POST', "$B/admin/dispatch.php?action=set_lang",
    ['csrf_token' => $ownerCsrf($ock), 'lang' => 'pl'], $ock);
T::ok('set_lang ok', $st === 200 && str_contains($b, '"ok":true'));
$st2 = $db->prepare('SELECT lang FROM users WHERE id = ?');
$st2->execute([$ownerId]);
T::ok('set_lang persisted', $st2->fetchColumn() === 'pl');
[$st] = _dt('POST', "$B/admin/dispatch.php?action=set_lang",
    ['csrf_token' => str_repeat('0', 64), 'lang' => 'de'], $ock);
T::ok('set_lang bad CSRF 403', $st === 403);

// ── save_setting owner-only via dispatch ────────────────────────────────────
[$st, $b] = _dt('POST', "$B/admin/dispatch.php?action=save_setting",
    ['csrf_token' => $ownerCsrf($ock), 'key' => 'site_name', 'value' => 'TDT'], $ock);
T::ok('save_setting ok', $st === 200 && str_contains($b, '"ok":true'));
$st2 = $db->prepare("SELECT value FROM settings WHERE key_name = 'site_name'");
$st2->execute();
T::ok('save_setting persisted', $st2->fetchColumn() === 'TDT');

// ── user_action create + delete via dispatch ────────────────────────────────
[$st,,, $loc] = _dt('POST', "$B/admin/dispatch.php?action=user_action",
    ['csrf_token' => $ownerCsrf($ock), 'action' => 'create_courier',
     'username' => 't_dt_courier2', 'password' => 'DtPass123!'], $ock);
$st2 = $db->prepare("SELECT COUNT(*) FROM users WHERE username = 't_dt_courier2'");
$st2->execute();
T::ok('dispatch creates courier', $st === 302 && str_contains($loc, 'users.php') && (int)$st2->fetchColumn() === 1);
$uid2 = (int)$db->query("SELECT id FROM users WHERE username = 't_dt_courier2'")->fetchColumn();
[$st,,, $loc] = _dt('POST', "$B/admin/dispatch.php?action=user_action",
    ['csrf_token' => $ownerCsrf($ock), 'action' => 'delete_courier', 'user_id' => $uid2], $ock);
$st2->execute();
T::ok('dispatch deletes courier', $st === 302 && (int)$st2->fetchColumn() === 0);

// ── logout: GET is a no-op, POST destroys, both URLs ────────────────────────
[$st,,, $loc] = _dt('GET', "$B/admin/logout.php", null, $ock);
[$stO] = _dt('GET', "$B/admin/orders.php", null, $ock);
T::ok('GET logout keeps session', $st === 302 && $stO === 200);
[$st,,, $loc] = _dt('POST', "$B/admin/logout.php",
    ['csrf_token' => $ownerCsrf($ock)], $ock);
T::ok('shim logout redirects', $st === 302 && str_contains($loc, 'index.php'));
[$stO] = _dt('GET', "$B/admin/orders.php", null, $ock);
T::ok('shim logout destroyed session', $stO === 302);
[$ock] = $login('t_dt_owner', 'DtPass123!');
[$st,,, $loc] = _dt('POST', "$B/admin/dispatch.php?action=logout",
    ['csrf_token' => $ownerCsrf($ock)], $ock);
T::ok('dispatch logout redirects', $st === 302 && str_contains($loc, 'index.php'));
[$stO] = _dt('GET', "$B/admin/orders.php", null, $ock);
T::ok('dispatch logout destroyed session', $stO === 302);
[$ock] = $login('t_dt_owner', 'DtPass123!');
[$st,,, $loc] = _dt('POST', "$B/admin/logout.php", ['csrf_token' => str_repeat('0', 64)], $ock);
[$stO] = _dt('GET', "$B/admin/orders.php", null, $ock);
T::ok('bad-CSRF logout keeps session', $st === 302 && $stO === 200);

// ── 2FA gate: a courier without enrolled TOTP logs in, but every ─────────
// non-exempt page bounces them to enrollment (legacy require_admin did
// the same — the flag only moved from basename to route table).
[$cck, $cloc] = $login('t_dt_courier', 'DtPass123!');
T::ok('unenrolled courier logs in', str_contains($cloc, 'orders.php'));
[$st,,, $loc] = _dt('GET', "$B/admin/orders.php", null, $cck);
T::ok('unenrolled courier gated to enrollment', $st === 302 && str_contains($loc, '2fa.php'));
[, $cb] = _dt('GET', "$B/admin/2fa.php", null, $cck);
$ccsrf = $csrfOf($cb);
T::ok('2fa page carries a token', $ccsrf !== '');
[$st,,, $loc] = _dt('POST', "$B/admin/logout.php", ['csrf_token' => $ccsrf], $cck);
T::ok('pending courier can log out', $st === 302 && str_contains($loc, 'index.php'));
[$cck] = $login('t_dt_courier', 'DtPass123!');
[, $cb] = _dt('GET', "$B/admin/2fa.php", null, $cck);
[$st,,, $loc] = _dt('POST', "$B/admin/dispatch.php?action=mark_delivered",
    ['csrf_token' => $csrfOf($cb), 'id' => $oidShim], $cck);
T::ok('pending courier gated from actions', $st === 302 && str_contains($loc, '2fa.php'));
[$st, $b] = _dt('POST', "$B/admin/dispatch.php?action=set_lang",
    ['csrf_token' => $csrfOf($cb), 'lang' => 'de'], $cck);
T::ok('pending courier keeps set_lang', $st === 200 && str_contains($b, '"ok":true'));
// Courier-owned ask: the 2FA gate fires before owner-auth (as in legacy
// require_owner → require_admin), so an unenrolled courier is sent to
// enrollment, not to orders.php.
[$st,,, $loc] = _dt('POST', "$B/admin/dispatch.php?action=save_setting",
    ['csrf_token' => $csrfOf($cb), 'key' => 'site_name', 'value' => 'X'], $cck);
T::ok('courier bounced from owner route', $st === 302 && str_contains($loc, '2fa.php'));

// ── Cleanup ─────────────────────────────────────────────────────────────────
$db->prepare("DELETE FROM users WHERE username LIKE 't_dt\\_%'")->execute();
$db->prepare("DELETE FROM orders WHERE order_token LIKE 'tdtoken%'")->execute();
set_setting('site_name', $oldSite);
set_setting('rate_limit_max', (string)$oldMax);
set_setting('rate_limit_window_min', (string)$oldWin);

exit(T::done());
