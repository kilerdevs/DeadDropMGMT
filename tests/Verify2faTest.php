<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── 2FA code screen over real HTTP: the stale-token sibling ─────────────────
// Same root cause as SetupPasswordTest: verify_csrf() rotates the session
// token on success, so a re-rendered form must embed the post-rotation
// value. A wrong 2FA code used to brick the NEXT attempt with "Invalid
// CSRF token" — the exact dead end from the setup-screen screenshots.

$port = 8943;
$root = dirname(__DIR__);
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

function _v2(string $method, string $url, ?array $f, string $ck): array {
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
    try { [$st] = _v2('GET', "$B/healthz.php", null, ''); if ($st === 200) { $up = true; break; } }
    catch (Throwable) { }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { exit(T::done()); }

$db = get_db();
$db->exec('DELETE FROM users');
$db->exec("DELETE FROM rate_limits WHERE scope IN ('admin_login', 'admin_2fa')");
// Pin the limiter budget: the shared test DB can carry extreme settings rows
// (e.g. max=0 from clamp checks), which would lock out after one attempt.
$prevMax = (string)$db->query("SELECT value FROM settings WHERE key_name = 'rate_limit_max'")->fetchColumn();
$prevWin = (string)$db->query("SELECT value FROM settings WHERE key_name = 'rate_limit_window_min'")->fetchColumn();
$db->prepare("UPDATE settings SET value = '10' WHERE key_name = 'rate_limit_max'")->execute();
$db->prepare("UPDATE settings SET value = '15' WHERE key_name = 'rate_limit_window_min'")->execute();

// Owner with password + TOTP already on.
$secret = totp_generate_secret();
$encArr = encrypt_secret($secret); // assoc: ['ciphertext' => ..., 'iv' => ...]
[$enc, $iv] = [$encArr['ciphertext'], $encArr['iv']];
$db->prepare("INSERT INTO users (username, password_hash, role, totp_enabled, totp_secret_enc, totp_secret_iv)
              VALUES ('t_2fa_owner', ?, 'owner', 1, ?, ?)")
   ->execute([password_hash('AzPass123!', PASSWORD_BCRYPT), $enc, $iv]);

[, $b, $ck] = _v2('GET', "$B/admin/index.php", null, '');
[$st,, $ck, $loc] = _v2('POST', "$B/admin/login.php",
    ['csrf_token' => $csrfOf($b), 'username' => 't_2fa_owner', 'password' => 'AzPass123!'], $ck);
T::ok('password step gates into 2FA', $st === 302 && str_contains($loc, 'verify_2fa.php'));

[$st, $b, $ck] = _v2('GET', "$B/admin/verify_2fa.php", null, $ck);
T::ok('code form renders', $st === 200 && str_contains($b, 'name="code"'));
$csrf1 = $csrfOf($b);
T::ok('code form has CSRF token', $csrf1 !== '');

// A wrong code that cannot equal the real one (1:1M collision guarded).
$real = totp_code($secret);
$wrong = ($real === '000000') ? '000001' : '000000';
[$st, $b, $ck] = _v2('POST', "$B/admin/verify_2fa.php",
    ['csrf_token' => $csrf1, 'code' => $wrong], $ck);
T::ok('wrong code rejected', $st === 200 && str_contains($b, 'Invalid code.'));
$csrf2 = $csrfOf($b);

// Guessing visibility mirrors the password step: the rejected code lands in
// the audit trail with the targeted account, never the tried code.
$aud2 = $db->query("SELECT detail FROM audit_log WHERE action = '2fa_failed' ORDER BY id DESC LIMIT 1")->fetch();
T::eq('rejected code audited with targeted account', 't_2fa_owner', $aud2['detail'] ?? null);

// THE regression: the re-rendered form must carry a live token, so the
// next attempt is judged on its code — not killed as "Invalid CSRF".
[$st, $b, $ck] = _v2('POST', "$B/admin/verify_2fa.php",
    ['csrf_token' => $csrf2, 'code' => $wrong], $ck);
T::ok('second attempt judged on code, not CSRF',
    $st === 200 && str_contains($b, 'Invalid code.') && !str_contains($b, 'Invalid CSRF'));

// And the chain stays live through to a correct code.
$csrf3 = $csrfOf($b);
[$st,, , $loc] = _v2('POST', "$B/admin/verify_2fa.php",
    ['csrf_token' => $csrf3, 'code' => totp_code($secret)], $ck);
T::ok('correct code logs in', $st === 302 && str_contains($loc, 'orders.php'));

// Enrollment round-trip: the pending secret crosses the QR render via the
// session SEALED (never plaintext at rest) and still verifies on enable.
$db->prepare("INSERT INTO users (username, password_hash, role, totp_enabled) VALUES ('t_2fa_enroll', ?, 'owner', 0)")
   ->execute([password_hash('EnPass123!', PASSWORD_BCRYPT)]);
[, $bE, $ckE] = _v2('GET', "$B/admin/index.php", null, '');
[$stE,, $ckE, $locE] = _v2('POST', "$B/admin/login.php",
    ['csrf_token' => $csrfOf($bE), 'username' => 't_2fa_enroll', 'password' => 'EnPass123!'], $ckE);
T::ok('unenrolled owner logs in', $stE === 302 && str_contains($locE, 'orders.php'));
[, $bEnroll, $ckE] = _v2('GET', "$B/admin/2fa.php", null, $ckE);
preg_match('/id="totp-secret">([A-Z2-7 ]+)</', (string)$bEnroll, $mS);
$enrollSecret = str_replace(' ', '', $mS[1] ?? '');
T::ok('enrollment shows a secret', $enrollSecret !== '');
$csrfE = $csrfOf($bEnroll);
$realE = totp_code($enrollSecret);
$wrongE = ($realE === '000000') ? '000001' : '000000';
[$stBad, $bBad, $ckE] = _v2('POST', "$B/admin/2fa.php",
    ['csrf_token' => $csrfE, 'action' => 'enable', 'code' => $wrongE], $ckE);
T::ok('wrong enable code rejected',
    $stBad === 200 && str_contains((string)$bBad, 'Invalid code')
    && (int)$db->query("SELECT totp_enabled FROM users WHERE username = 't_2fa_enroll'")->fetchColumn() === 0);
$csrfE2 = $csrfOf($bBad);
[, $bOk, $ckE] = _v2('POST', "$B/admin/2fa.php",
    ['csrf_token' => $csrfE2, 'action' => 'enable', 'code' => totp_code($enrollSecret)], $ckE);
$enrolled = $db->query("SELECT totp_enabled FROM users WHERE username = 't_2fa_enroll'")->fetchColumn();
T::ok('correct enable code enrolls (sealed round-trip)', (int)$enrolled === 1);
$db->prepare("DELETE FROM users WHERE username IN ('t_2fa_owner', 't_2fa_enroll')")->execute();
// Restore the limiter rows this suite pinned above.
$db->prepare('UPDATE settings SET value = ? WHERE key_name = \'rate_limit_max\'')->execute([$prevMax]);
$db->prepare('UPDATE settings SET value = ? WHERE key_name = \'rate_limit_window_min\'')->execute([$prevWin]);

exit(T::done());
