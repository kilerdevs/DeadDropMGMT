<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── First-run setup flow over real HTTP ─────────────────────────────────────
// The owner bootstrap issues a one-time recovery enrollment code shown on
// the set-password screen. Three UI guarantees, all regressed here:
//   1. the code renders in an informational (amber) .notice, never the
//      error-red .alert — red means "something failed";
//   2. a FAILED password attempt (too short, mismatch, bad CSRF) re-shows
//      the code — the screen holds the only copy the creator will ever see;
//   3. a successful set consumes it (burned server-side, never rendered
//      again) and the intro paragraph keeps its spacing (.setup-explain).
// Shares the isolated test DB with the other suites (same pattern as
// AuthorizationHttpTest): the bootstrap requires zero users, so leftovers
// are wiped first and the created owner removed at the end.

// Let the OS pick a free port: a fixed one collides with any stray listener
// on a shared runner, and then the whole suite fails as "server booted".
$port  = 8942;
$probe = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($probe !== false) {
    $port = (int)substr((string)strrchr((string)stream_socket_get_name($probe, false), ':'), 1) ?: $port;
    fclose($probe);
}
$root = dirname(__DIR__);
$cmd  = escapeshellarg(PHP_BINARY)
      . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
      . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$null   = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
// The server's own stderr ("Address already in use", a fatal in a router
// script) is the only clue when it does not come up, so keep it.
$errLog = tempnam(sys_get_temp_dir(), 'ddsp');
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $errLog, 'w']], $p);
register_shutdown_function(function () use ($proc, $errLog): void {
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
    @unlink($errLog);
});
$B = "http://127.0.0.1:$port";

function _sp(string $method, string $url, ?array $f, string $ck): array {
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
// 64-hex strings on the page are the CSRF token AND the enrollment code —
// the code is whichever one is not the form token.
$codeOf = static function (string $b, string $csrf): string {
    preg_match_all('/[0-9a-f]{64}/', $b, $m);
    foreach ($m[0] as $hex) {
        if ($hex !== $csrf) { return $hex; }
    }
    return '';
};

$up = false;
for ($i = 0; $i < 100; $i++) {
    try { [$st] = _sp('GET', "$B/healthz.php", null, ''); if ($st === 200) { $up = true; break; } }
    catch (Throwable) { }
    usleep(200000);
}
if (!$up) {
    fwrite(STDERR, "built-in server on port $port did not answer; its stderr:\n" . (string)@file_get_contents($errLog) . "\n");
}
T::ok('server booted', $up);
if (!$up) { exit(T::done()); }

// Static CSS guards: the classes the markup below depends on must exist.
$css = (string)@file_get_contents(dirname(__DIR__) . '/admin/style.css');
T::ok('style.css defines .setup-explain', str_contains($css, '.setup-explain'));
T::ok('style.css defines .notice', str_contains($css, '.notice'));
T::ok('panels center in .main, no viewport offset hack', !str_contains($css, 'left: -115px')
    && str_contains($css, 'margin-inline: auto'));

// Bootstrap needs an empty users table; rate_limits are wiped too so no
// earlier suite's 127.0.0.1 budget can rate-limit this flow.
$db = get_db();
$db->exec('DELETE FROM users');
$db->exec("DELETE FROM rate_limits WHERE scope = 'admin_login'");

[, $b, $ck] = _sp('GET', "$B/admin/index.php", null, '');
T::ok('fresh install shows create-account form', str_contains($b, 'CREATE YOUR ACCOUNT') || str_contains($b, 'admin.bootstrap.h1') === false);
T::ok('bootstrap explain paragraph present', str_contains($b, 'class="setup-explain"'));
$csrf = $csrfOf($b);
T::ok('bootstrap form has CSRF token', $csrf !== '');

[$st,, $ck, $loc] = _sp('POST', "$B/admin/bootstrap.php",
    ['csrf_token' => $csrf, 'username' => 't_setup_owner'], $ck);
T::ok('bootstrap claims instance', $st === 302 && str_contains($loc, 'setup_password.php'));

[$st, $b, $ck] = _sp('GET', "$B/admin/setup_password.php", null, $ck);
T::ok('setup screen renders', $st === 200);
$csrf = $csrfOf($b);
$code = $codeOf($b, $csrf);
T::ok('enrollment code shown (64-hex)', preg_match('/^[0-9a-f]{64}$/', $code) === 1);
T::ok('code renders in .notice, not .alert',
    str_contains($b, '<div class="notice">') && !str_contains($b, '<div class="alert">'));

// ── Too-short password: error AND the code again ──────────────────────────
[$st, $b, $ck] = _sp('POST', "$B/admin/setup_password.php",
    ['csrf_token' => $csrf, 'password' => 'short', 'password2' => 'short'], $ck);
T::ok('short password rejected', $st === 200 && str_contains($b, 'at least 8'));
$csrf2 = $csrfOf($b);
T::ok('code re-shown after short password', $codeOf($b, $csrf2) === $code);
T::ok('error stays .alert, code stays .notice',
    str_contains($b, '<div class="alert">') && str_contains($b, '<div class="notice">'));

// ── Mismatched passwords: same deal ───────────────────────────────────────
[$st, $b, $ck] = _sp('POST', "$B/admin/setup_password.php",
    ['csrf_token' => $csrf2, 'password' => 'LongEnough1!', 'password2' => 'Different2@'], $ck);
T::ok('mismatch rejected', $st === 200 && str_contains($b, 'do not match'));
$csrf3 = $csrfOf($b);
T::ok('code re-shown after mismatch', $codeOf($b, $csrf3) === $code);

// ── Bad CSRF: error must not eat the code either ──────────────────────────
[$st, $b, $ck] = _sp('POST', "$B/admin/setup_password.php",
    ['csrf_token' => str_repeat('0', 64), 'password' => 'LongEnough1!', 'password2' => 'LongEnough1!'], $ck);
T::ok('bad CSRF rejected', $st === 200 && str_contains($b, 'Invalid CSRF'));
$csrf4 = $csrfOf($b);
T::ok('code re-shown after bad CSRF', $codeOf($b, $csrf4) === $code);

// ── Valid password: claimed, code burned ──────────────────────────────────
[$st,, $ck, $loc] = _sp('POST', "$B/admin/setup_password.php",
    ['csrf_token' => $csrf4, 'password' => 'Str0ngSetup!Pass1', 'password2' => 'Str0ngSetup!Pass1'], $ck);
T::ok('valid password logs in', $st === 302 && str_contains($loc, 'orders.php'));
$row = $db->query("SELECT password_hash, enrollment_hash FROM users WHERE username = 't_setup_owner'")->fetch();
T::ok('password stored', is_array($row) && $row['password_hash'] !== '');
T::ok('enrollment burned server-side', is_array($row) && $row['enrollment_hash'] === null);

// Pending state is gone: revisiting renders no code (shown-once holds).
[$st, $b] = _sp('GET', "$B/admin/setup_password.php", null, $ck);
T::ok('setup screen unreachable after claim', $st === 302 && !str_contains($b, $code));

// Leave no trace for later suites.
$db->prepare("DELETE FROM users WHERE username = 't_setup_owner'")->execute();

exit(T::done());
