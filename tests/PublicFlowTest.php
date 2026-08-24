<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── End-to-end public flow over a live PHP built-in server ───────────────────
// Token lookup → status step → password unlock (wrong/right, preparing vs
// delivered) → PRG reveal → confirmation → receipt deletion → rate limiting.

// Spawn the server with the same env this process has (bootstrap forces the
// test DB), so requests hit deaddrops_test, never a real install.
$port = 8100 + (int)(getmypid() % 400);
$root = dirname(__DIR__);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
// The child server must store sessions where this CLI user can write — it
// does NOT inherit ini settings, only environment.
$cmd  = escapeshellarg(PHP_BINARY)
    . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
    . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $pipes);
if (!is_resource($proc)) {
    fwrite(STDERR, "cannot spawn built-in server\n");
    exit(1);
}
register_shutdown_function(static function () use ($proc): void {
    // proc_terminate alone leaves the listener alive on Windows; kill the tree
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

// Wait until it answers (or bail after ~6 s). Early polls hit connection
// refused — a warning our error handler turns into an exception, so swallow.
$up = false;
for ($i = 0; $i < 30; $i++) {
    try { [$st] = _pf_get("http://127.0.0.1:$port/"); }
    catch (Throwable) { $st = 0; usleep(200000); continue; }
    if ($st === 200) { $up = true; break; }
    usleep(200000);
}
T::ok('built-in server booted', $up && $st === 200);
if (!$up) { exit(T::done()); }

// Seed one delivered + one preparing order
$db   = get_db();
$tokD  = 'PFTOKENDELIVER01';
$tokD2 = 'PFTOKENDELIVER02';
$tokP  = 'PFTOKENPREPARIN2';
$pass  = 'RevealPass1!';
foreach ([$tokD, $tokD2, $tokP] as $t) { $db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$t]); }
$enc = encrypt_location_data([
    'text'         => 'PUBLICFLOWTEST skrzynka pod trzecią ławą',
    'lat'          => 52.2297,
    'lng'          => 21.0122,
    'instructions' => "kod do bramy 4321",
]);
$hash = password_hash($pass, PASSWORD_BCRYPT);
$ins  = $db->prepare(
    "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, delivered_at, expires_at, notes)
     VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL 24 HOUR, ?)"
);
$ins->execute([$tokD, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), 'notka dla odbiorcy']);
$ins->execute([$tokD2, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
$ins->execute([$tokP, $hash, $enc['ciphertext'], $enc['iv'], 'preparing', null, '']);

set_setting('rate_limit_max', '3');
set_setting('rate_limit_window_min', '15');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';

// 1. Unknown token → not-found alert, no reveal
[, $body, $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => 'UNKNOWN00000000AA'], $cookie);
T::ok('unknown token rejected', str_contains($body, 'class="alert"'));
$unknownBody = $body;

// 1b. Enumeration resistance: unknown token WITH a password must answer
// exactly like a wrong password for an existing order — same body.
[, $bodyWrong] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD, 'pickup_password' => 'nope'], $cookie);
[, $bodyUnknownPw] = _pf_post("http://127.0.0.1:$port/", ['order_token' => 'UNKNOWN0000000AB', 'pickup_password' => 'nope'], $cookie);
preg_match('/<div class="alert">(.*?)<\/div>/s', $bodyWrong, $mW);
preg_match('/<div class="alert">(.*?)<\/div>/s', $bodyUnknownPw, $mU);
T::ok('unknown token + password ≡ wrong password (same answer)',
    ($mW[1] ?? 'a') === ($mU[1] ?? 'b') && ($mW[1] ?? '') !== '');

// Those were two burned failures — start clean before the scripted budget math.
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';

// 2. Status lookup (empty password) → badge + password step for delivered order
[, $body, $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD], $cookie);
T::ok('status lookup shows delivered badge', str_contains($body, 'status-badge delivered'));
T::ok('status lookup asks for password', str_contains($body, 'name="pickup_password"') && !str_contains($body, 'reveal-value'));

// 3. Wrong passwords trigger the limiter (max=3)
[, $body, $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD, 'pickup_password' => 'nope'], $cookie);
T::ok('wrong password shows alert, no reveal', str_contains($body, 'class="alert"') && !str_contains($body, 'reveal-value'));
_pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD, 'pickup_password' => 'nope'], $cookie);
_pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD, 'pickup_password' => 'nope'], $cookie);

// 4. Budget exhausted → cooldown card, EVEN with the correct password
[, $body, $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD, 'pickup_password' => $pass], $cookie);
T::ok('rate limited: cooldown card instead of reveal', str_contains($body, 'cooldown-heading'));

// 5. Clear the IP counter AND switch to a fresh session (the old session's
// failure bucket is full by design), then unlock for real → PRG redirect
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';
[$st, , $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD, 'pickup_password' => $pass], $cookie);
T::eq('correct password redirects (PRG)', 302, $st);
[, $body, $cookie] = _pf_get("http://127.0.0.1:$port/", $cookie);
T::ok('reveal shows decrypted location', str_contains($body, 'PUBLICFLOWTEST skrzynka pod trzecią ławą'));
T::ok('reveal shows instructions + notes', str_contains($body, 'kod do bramy 4321') && str_contains($body, 'notka dla odbiorcy'));
T::ok('reveal offers the receive button', preg_match('/name="step" value="1"/', $body) === 1 && str_contains($body, 'name="csrf_token"'));
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $body, $m);
$csrf  = $m[1] ?? '';
$token = $tokD;

// 6. Reveal must NOT persist across a fresh session (once-only display)
[, $bodyFresh] = _pf_get("http://127.0.0.1:$port/");
T::ok('fresh session sees no leftover reveal', !str_contains((string)$bodyFresh, 'reveal-value'));

// 7. Confirmation page (receive step=1) requires the session CSRF token
[, $body, $cookie] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $csrf, 'order_token' => $token, 'step' => '1'],
    $cookie
);
T::ok('confirmation page shows the token', str_contains($body, $token));
T::ok('confirmation page has the final button', str_contains($body, 'name="step" value="2"'));
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $body, $m2);
$csrf2 = $m2[1] ?? '';

// 8. Step=2 without a valid CSRF token must NOT delete
_pf_post("http://127.0.0.1:$port/receive.php", ['csrf_token' => str_repeat('0', 64), 'order_token' => $token, 'step' => '2'], $cookie);
T::ok('bad CSRF blocks deletion',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$token'")->fetch());

// 9. Correct confirmation actually deletes the order
[, $body] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $csrf2, 'order_token' => $token, 'step' => '2'],
    $cookie
);
T::ok('receipt confirmed (done page)', str_contains($body, 'status-badge delivered'));
T::ok('order deleted from DB',
    !$db->query("SELECT 1 FROM orders WHERE order_token = '$token'")->fetch());

// 9b. Replaying the receipt is a safe failure — nothing resurrects, no oracle
// (fresh budget first so the block below comes from STATE, not the limiter)
set_setting('rate_limit_max', '50');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
[, $bodyReplay] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $csrf2, 'order_token' => $token, 'step' => '2'],
    $cookie
);
T::ok('replayed receipt shows a safe error', str_contains((string)$bodyReplay, 'class="alert"'));
T::ok('replayed receipt does not resurrect the order',
    !$db->query("SELECT 1 FROM orders WHERE order_token = '$token'")->fetch());

// 9c. A PREPARING order cannot even reach the confirmation page
[$stPrep] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $csrf2, 'order_token' => $tokP, 'step' => '1'],
    $cookie
);
T::eq('preparing order bounced from confirmation (redirect)', 302, $stPrep);
[$stPrep2] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $csrf2, 'order_token' => $tokP, 'step' => '2'],
    $cookie
);
T::ok('preparing order cannot be destroyed via step 2', $stPrep2 === 200);
T::ok('preparing order still exists after attack',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokP'")->fetch());

// 10. Preparing order: correct password → "not ready yet" note, no location
[$st, , $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokP, 'pickup_password' => $pass], $cookie);
T::eq('correct password on preparing order redirects too', 302, $st);
[, $body, $cookie] = _pf_get("http://127.0.0.1:$port/", $cookie);
T::ok('preparing order hides location', !str_contains($body, 'PUBLICFLOWTEST'));

// 11. Session cookie bucket: blocks on ITS OWN budget even when the IP row is
// clean — and does not punish a different browser behind the same IP.
set_setting('rate_limit_max', '3');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieA = '';
for ($i = 0; $i < 3; $i++) {
    [, , $cookieA] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokP, 'pickup_password' => 'nope'], $cookieA);
}
[, $body] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokP, 'pickup_password' => $pass], $cookieA);
T::ok('session bucket blocks despite clean IP budget', str_contains($body, 'cooldown-heading'));
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
[, $body] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokP], '');
T::ok('fresh session same IP is not blocked by another bucket',
    str_contains($body, 'status-badge') && !str_contains($body, 'cooldown-heading'));

// 12. receive.php burns budget on the confirmation probe too — a blocked
// visitor cannot even enumerate step 1. Needs a real unlocked session first:
// only the reveal page issues the CSRF token receive.php accepts.
set_setting('rate_limit_max', '3');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';
[$stU, , $cookie] = _pf_post("http://127.0.0.1:$port/", ['order_token' => $tokD2, 'pickup_password' => $pass], $cookie);
[, $body, $cookie] = _pf_get("http://127.0.0.1:$port/", $cookie);
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $body, $mR);
$rcsrf = $mR[1] ?? '';
T::eq('unlock for confirmation flow redirects (test setup)', 302, $stU);
T::ok('reveal page offers confirmation form (test setup)', $rcsrf !== '');

for ($i = 0; $i < 3; $i++) {
    [, , $cookie] = _pf_post(
        "http://127.0.0.1:$port/receive.php",
        ['csrf_token' => $rcsrf, 'order_token' => $tokD2, 'step' => '1'],
        $cookie
    );
}
[, $body] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $rcsrf, 'order_token' => $tokD2, 'step' => '2'],
    $cookie
);
T::ok('blocked budget refuses even the destructive confirmation', str_contains($body, 'class="alert"'));
T::ok('order survives blocked deletion attempt',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokD2'")->fetch());

// Cleanup
$db->prepare('DELETE FROM orders WHERE order_token IN (?, ?, ?)')->execute([$tokD, $tokD2, $tokP]);
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");

exit(T::done());

// ── tiny HTTP helpers (cookie-aware, no redirects followed) ──────────────────

function _pf_get(string $url, string $cookie = ''): array {
    return _pf_req($url, null, $cookie);
}

function _pf_post(string $url, array $fields, string $cookie = ''): array {
    return _pf_req($url, $fields, $cookie);
}

function _pf_req(string $url, ?array $fields, string $cookie): array {
    $opts = [
        'http' => [
            'method'          => $fields !== null ? 'POST' : 'GET',
            'ignore_errors'   => true,
            'follow_location' => 0,
            'timeout'         => 15,
            'header'          => ($fields !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                               . ($cookie !== '' ? "Cookie: $cookie\r\n" : ''),
        ],
        'ssl' => ['verify_peer' => false],
    ];
    if ($fields !== null) {
        $opts['http']['content'] = http_build_query($fields);
    }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0;
    $setCookie = '';
    foreach ($http_response_header ?? [] as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $pair = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($pair !== '' && !str_contains($pair, '=')) { continue; }
            $setCookie = $pair; // single-session app: last wins
        }
    }
    return [$status, $body === false ? '' : $body, $setCookie ?: $cookie];
}
