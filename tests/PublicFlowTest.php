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
$tokD3 = 'PFTOKENDELIVER03';
$tokD4 = 'PFTOKENDELIVER04';
$tokP  = 'PFTOKENPREPARIN2';
$pass  = 'RevealPass1!';
foreach ([$tokD, $tokD2, $tokD3, $tokD4, $tokP] as $t) { $db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$t]); }
$enc = encrypt_location_data([
    'text'         => 'PUBLICFLOWTEST skrzynka pod trzecią ławą',
    'lat'          => 52.2297,
    'lng'          => 21.0122,
    'instructions' => 'kod do bramy 4321',
]);
$hash = password_hash($pass, PASSWORD_BCRYPT);
$ins  = $db->prepare(
    'INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, delivered_at, expires_at, notes)
     VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL 24 HOUR, ?)'
);
$ins->execute([$tokD, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), 'notka dla odbiorcy']);
$ins->execute([$tokD2, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
$ins->execute([$tokD3, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
$ins->execute([$tokD4, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
$ins->execute([$tokP, $hash, $enc['ciphertext'], $enc['iv'], 'preparing', null, '']);

set_setting('rate_limit_max', '3');
set_setting('rate_limit_window_min', '15');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';

// Unlock (and token-only lookup) POSTs carry the single-use CSRF token:
// harvest a live one from a fresh GET first — rotation retires each token
// on use, so every POST needs its own.
$pf_unlock = static function (string $tok, string $pw, string &$ck) use ($port): array {
    [, $g, $ck] = _pf_get("http://127.0.0.1:$port/", $ck);
    preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', (string)$g, $m);
    [$st, $b, $ck2] = _pf_post("http://127.0.0.1:$port/",
        ['csrf_token' => $m[1] ?? '', 'order_token' => $tok, 'pickup_password' => $pw], $ck);
    $ck = $ck2;
    return [$st, $b, $ck];
};

// 1. Unknown token → not-found alert, no reveal
[, $body, $cookie] = $pf_unlock('UNKNOWN00000000AA', '', $cookie);
T::ok('unknown token rejected', str_contains($body, 'class="alert"'));
$unknownBody = $body;

// 1b. Enumeration resistance: unknown token WITH a password must answer
// exactly like a wrong password for an existing order — same body.
[, $bodyWrong] = $pf_unlock($tokD, 'nope', $cookie);
[, $bodyUnknownPw] = $pf_unlock('UNKNOWN0000000AB', 'nope', $cookie);
preg_match('/<div class="alert">(.*?)<\/div>/s', $bodyWrong, $mW);
preg_match('/<div class="alert">(.*?)<\/div>/s', $bodyUnknownPw, $mU);
T::ok('unknown token + password ≡ wrong password (same answer)',
    ($mW[1] ?? 'a') === ($mU[1] ?? 'b') && ($mW[1] ?? '') !== '');

// 1c. Unlock POST without a CSRF token dies BEFORE the limiter spend:
// forged cross-site submits must not burn the victim's budget.
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieCsrf = '';
for ($i = 0; $i < 3; $i++) {
    [, $bodyCsrf, $cookieCsrf] = _pf_post("http://127.0.0.1:$port/",
        ['order_token' => $tokD, 'pickup_password' => 'nope'], $cookieCsrf);
    T::ok("tokenless unlock rejected [$i]", str_contains($bodyCsrf, 'class="alert"'));
}
[$stCsrf, , $cookieCsrf] = $pf_unlock($tokD, $pass, $cookieCsrf);
T::eq('rejected forgeries spent no budget', 302, $stCsrf);

// Those were two burned failures — start clean before the scripted budget math.
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';

// 2. Status lookup (empty password) → badge + password step for delivered order
[, $body, $cookie] = $pf_unlock($tokD, '', $cookie);
T::ok('status lookup shows delivered badge', str_contains($body, 'status-badge delivered'));
T::ok('status lookup asks for password', str_contains($body, 'name="pickup_password"') && !str_contains($body, 'reveal-value'));

// 3. Wrong passwords trigger the limiter (max=3)
[, $body, $cookie] = $pf_unlock($tokD, 'nope', $cookie);
T::ok('wrong password shows alert, no reveal', str_contains($body, 'class="alert"') && !str_contains($body, 'reveal-value'));
$pf_unlock($tokD, 'nope', $cookie);
$pf_unlock($tokD, 'nope', $cookie);

// 4. Budget exhausted → cooldown card, EVEN with the correct password
[, $body, $cookie] = $pf_unlock($tokD, $pass, $cookie);
T::ok('rate limited: cooldown card instead of reveal', str_contains($body, 'cooldown-heading'));

// 5. Clear the IP counter AND switch to a fresh session (the old session's
// failure bucket is full by design), then unlock for real → PRG redirect
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';
[$st, , $cookie] = $pf_unlock($tokD, $pass, $cookie);
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
// (fresh budget first so the block below comes from STATE, not the limiter).
// CSRF rotation retires the spent token, so the replay is bounced to / —
// equally harmless, and the order stays gone either way.
set_setting('rate_limit_max', '50');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
[$stReplay, $bodyReplay] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $csrf2, 'order_token' => $token, 'step' => '2'],
    $cookie
);
T::ok('replayed receipt is refused',
      $stReplay === 302 || str_contains((string)$bodyReplay, 'class="alert"'));
T::ok('replayed receipt does not resurrect the order',
    !$db->query("SELECT 1 FROM orders WHERE order_token = '$token'")->fetch());

// 9d. A session that NEVER unlocked cannot arm destruction: even posting a
// freshly harvested (fully valid) token without the receipt capability is
// bounced — CSRF authorizes the session, only the unlock arms the action.
set_setting('rate_limit_max', '50');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
[, $bodyNoUnlock, $cookieNoUnlock] = _pf_get("http://127.0.0.1:$port/");
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', (string)$bodyNoUnlock, $mN);
T::ok('unlock form hands out a session token (test setup)', ($mN[1] ?? '') !== '');
[$stNoUnlock, $bodyNoUnlock2] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $mN[1] ?? '', 'order_token' => $tokD3, 'step' => '2'],
    $cookieNoUnlock
);
T::ok('token-only destruction attempt fails closed (alert, no delete)',
    $stNoUnlock === 200 && str_contains((string)$bodyNoUnlock2, 'class="alert"'));
T::ok('order survives token-only deletion attempt',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokD3'")->fetch());

// 9e. THE CORE INVARIANT: even a fully valid session (own CSRF, completed
// unlock of tokD3) may only destroy the token it unlocked. The receipt
// capability is sealed, bound to that one token, and single-use.
set_setting('rate_limit_max', '50');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieE = '';
$pf_unlock($tokD3, '', $cookieE);
[$stE, , $cookieE] = $pf_unlock($tokD3, $pass, $cookieE);
T::eq('unlock arms the receipt capability (redirect)', 302, $stE);
[, $bodyE, $cookieE] = _pf_get("http://127.0.0.1:$port/", $cookieE);
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $bodyE, $mE);
[, $bodyCross] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $mE[1] ?? '', 'order_token' => $tokD4, 'step' => '2'],
    $cookieE
);
T::ok('capability for another token is rejected (cross-token attack)',
    str_contains((string)$bodyCross, 'class="alert"'));
T::ok('cross-token target survives',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokD4'")->fetch());
// The denied attempt still consumed the single-use capability:
T::ok('order intact after denied cross-token attempt',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokD3'")->fetch());

// Fresh unlock re-arms the capability: own-token receipt now completes.
$pf_unlock($tokD3, '', $cookieE);
[, , $cookieE] = $pf_unlock($tokD3, $pass, $cookieE);
[, $bodyOwn, $cookieE] = _pf_get("http://127.0.0.1:$port/", $cookieE);
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $bodyOwn, $mO);
[, $bodyOwn2] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $mO[1] ?? '', 'order_token' => $tokD3, 'step' => '2'],
    $cookieE
);
T::ok('own-token receipt completes after re-unlock',
    str_contains((string)$bodyOwn2, 'status-badge delivered'));
T::ok('unlocked order deleted by its own capability',
    !$db->query("SELECT 1 FROM orders WHERE order_token = '$tokD3'")->fetch());

// 9c. A PREPARING order cannot be confirmed or destroyed over HTTP, even by
// a fully valid session holding fresh tokens. CSRF rotation retires tokens
// after every successful POST, so each step harvests a live one from a
// delivered-order session; the preparing target is then refused by the
// fail-closed layers (capability binding / state gate — the state rule
// itself is pinned in StateTransitionTest::receive refuses preparing).
$pf_csrf_after_unlock = static function (string $tok, string $pw, string &$ck) use ($port, $pf_unlock): string {
    $pf_unlock($tok, '', $ck);
    $pf_unlock($tok, $pw, $ck);
    [, $b, $ck] = _pf_get("http://127.0.0.1:$port/", $ck);
    preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
    return $m[1] ?? '';
};
set_setting('rate_limit_max', '50');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieP = '';
$pc1 = $pf_csrf_after_unlock($tokD4, $pass, $cookieP);
T::ok('delivered unlock hands out a live token (test setup)', $pc1 !== '');
[$stPrep] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $pc1, 'order_token' => $tokP, 'step' => '1'],
    $cookieP
);
T::eq('preparing order bounced from confirmation (redirect)', 302, $stPrep);
$pc2 = $pf_csrf_after_unlock($tokD4, $pass, $cookieP);
[$stPrep2, $bodyPrep2] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $pc2, 'order_token' => $tokP, 'step' => '2'],
    $cookieP
);
T::ok('preparing order cannot be destroyed via step 2',
      $stPrep2 === 200 && str_contains((string)$bodyPrep2, 'class="alert"'));
T::ok('preparing order still exists after attack',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokP'")->fetch());

// 10. Preparing order: correct password → "not ready yet" note, no location
[$st, , $cookie] = $pf_unlock($tokP, $pass, $cookie);
T::eq('correct password on preparing order redirects too', 302, $st);
[, $body, $cookie] = _pf_get("http://127.0.0.1:$port/", $cookie);
T::ok('preparing order hides location', !str_contains($body, 'PUBLICFLOWTEST'));

// 11. Session cookie bucket: blocks on ITS OWN budget even when the IP row is
// clean — and does not punish a different browser behind the same IP.
set_setting('rate_limit_max', '3');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieA = '';
for ($i = 0; $i < 3; $i++) {
    [, , $cookieA] = $pf_unlock($tokP, 'nope', $cookieA);
}
[, $body] = $pf_unlock($tokP, $pass, $cookieA);
T::ok('session bucket blocks despite clean IP budget', str_contains($body, 'cooldown-heading'));
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieFresh = '';
[, $body] = $pf_unlock($tokP, '', $cookieFresh);
T::ok('fresh session same IP is not blocked by another bucket',
    str_contains($body, 'status-badge') && !str_contains($body, 'cooldown-heading'));

// 12. receive.php burns budget on the confirmation probe too — a blocked
// visitor cannot even enumerate step 1. Every spend needs a freshly
// harvested token: single-use rotation retires each one on use.
set_setting('rate_limit_max', '3');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookie = '';
[$stU, , $cookie] = $pf_unlock($tokD2, $pass, $cookie);
T::eq('unlock for confirmation flow redirects (test setup)', 302, $stU);
$harvest = static function () use ($port, &$cookie): string {
    [, $g, $cookie] = _pf_get("http://127.0.0.1:$port/", $cookie);
    preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', (string)$g, $m);
    return $m[1] ?? '';
};
for ($i = 0; $i < 3; $i++) {
    $tok = $harvest();
    T::ok("confirmation token harvestable [$i]", $tok !== '');
    [, , $cookie] = _pf_post(
        "http://127.0.0.1:$port/receive.php",
        ['csrf_token' => $tok, 'order_token' => $tokD2, 'step' => '1'],
        $cookie
    );
}
[, $body] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $harvest(), 'order_token' => $tokD2, 'step' => '2'],
    $cookie
);
T::ok('blocked budget refuses even the destructive confirmation', str_contains($body, 'class="alert"'));
T::ok('order survives blocked deletion attempt',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokD2'")->fetch());

// 12b. Forged (tokenless) receive POSTs spend NOTHING: even a full budget
// worth of forgeries must leave the victim's limiter untouched, and a
// legitimate confirmation afterwards must still go through.
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieF = '';
for ($i = 0; $i < 5; $i++) {
    [$stF, , $cookieF] = _pf_post(
        "http://127.0.0.1:$port/receive.php",
        ['order_token' => $tokD2, 'step' => '1'],
        $cookieF
    );
    T::eq("forged receive POST redirected [$i]", 302, $stF);
}
T::eq('forgeries created no limiter row',
    0, (int)$db->query("SELECT COUNT(*) FROM rate_limits WHERE scope = 'public'")->fetchColumn());
[$stL, , $cookieF] = $pf_unlock($tokD2, $pass, $cookieF);
T::eq('unlock still works after forgery flood', 302, $stL);
[, $gL, $cookieF] = _pf_get("http://127.0.0.1:$port/", $cookieF);
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', (string)$gL, $mL);
[$stC, $bodyC] = _pf_post(
    "http://127.0.0.1:$port/receive.php",
    ['csrf_token' => $mL[1] ?? '', 'order_token' => $tokD2, 'step' => '1'],
    $cookieF
);
T::eq('legitimate confirmation proceeds after forgery flood', 200, $stC);
T::ok('confirmation page renders after forgery flood', str_contains($bodyC, 'name="step" value="2"'));

// Reveal dies with the row: unlock, then an owner panic deletes the order
// before the consuming GET — the sealed blob alone must reveal nothing.
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$cookieR = '';
[$stR, , $cookieR] = $pf_unlock($tokD2, $pass, $cookieR);
T::eq('reveal-after-delete setup unlock redirects', 302, $stR);
$db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$tokD2]);
[, $bodyR] = _pf_get("http://127.0.0.1:$port/", $cookieR);
T::ok('deleted order reveals nothing after unlock',
    !str_contains($bodyR, 'reveal-value') && !str_contains($bodyR, 'PUBLICFLOWTEST skrzynka'));

// 10. Expiry is exact: an order past its lifetime is gone for recipients even
// though the periodic sweep has not deleted the row yet.
$tokX = 'PFTOKENEXPIRED01';
$db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$tokX]);
$db->prepare(
    'INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv, status, delivered_at, expires_at, notes)
     VALUES (?, ?, ?, ?, "delivered", NOW() - INTERVAL 30 HOUR, NOW() - INTERVAL 1 HOUR, "")'
)->execute([$tokX, $hash, $enc['ciphertext'], $enc['iv']]);
set_setting('rate_limit_max', '50');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$ckX = '';
[$stX, $bX, $ckX] = $pf_unlock($tokX, $pass, $ckX);
T::ok('expired order refuses the correct password', $stX !== 302 && str_contains($bX, 'class="alert"'));
[, $bX] = $pf_unlock($tokX, '', $ckX);
T::ok('expired order shows no status card', !str_contains($bX, 'status-badge'));
[, $bX] = _pf_get("http://127.0.0.1:$port/?token=$tokX");
T::ok('expired order token link prefills nothing', !str_contains($bX, 'status-badge') && preg_match('/id="order_token"[^>]*value="' . $tokX . '"/s', $bX) !== 1);
T::ok('the row itself is still there (sweep has not run)',
    (bool)$db->query("SELECT 1 FROM orders WHERE order_token = '$tokX'")->fetch());
$db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$tokX]);

// 11. Free requests cannot launder guesses: with a budget of 3, wrong
// passwords interleaved with token-only lookups AND with successful unlocks
// of another (the attacker's own) order must still exhaust the IP budget.
// Every guess uses a fresh session, so only the per-IP counter can be what
// blocks. Dedicated orders: the shared ones above were consumed by earlier
// steps, which would turn "successful unlock" into a mere unknown token.
$tokG1 = 'PFTOKENGUESS0001'; // the victim's order
$tokG2 = 'PFTOKENGUESS0002'; // the attacker's own, legitimately unlockable
foreach ([$tokG1, $tokG2] as $tg) {
    $db->prepare('DELETE FROM orders WHERE order_token = ?')->execute([$tg]);
    $ins->execute([$tg, $hash, $enc['ciphertext'], $enc['iv'], 'delivered', date('Y-m-d H:i:s'), '']);
}
set_setting('rate_limit_max', '3');
$db->exec("DELETE FROM rate_limits WHERE scope = 'public'");
$ckLook = '';
for ($i = 0; $i < 3; $i++) {
    $ckG = '';
    $pf_unlock($tokG1, 'wrong-guess-' . $i, $ckG);
    $pf_unlock($tokG1, '', $ckLook);          // status lookup between guesses
    if ($i < 2) { // (a third one would rightly meet the exhausted budget)
        $ckOk = '';
        [$stOwn] = $pf_unlock($tokG2, $pass, $ckOk); // the attacker's own valid unlock
        T::eq("attacker's own unlock really succeeds [$i]", 302, $stOwn);
    }
}
$ckFinal = '';
[, $bFinal] = $pf_unlock($tokG1, 'wrong-guess-final', $ckFinal);
T::ok('interleaved lookups and unlocks did not reset the budget', str_contains($bFinal, 'cooldown-heading'));
$db->prepare('DELETE FROM orders WHERE order_token IN (?, ?)')->execute([$tokG1, $tokG2]);

// Cleanup
$db->prepare('DELETE FROM orders WHERE order_token IN (?, ?, ?, ?, ?)')->execute([$tokD, $tokD2, $tokD3, $tokD4, $tokP]);
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
    // PHP 8.5 deprecates $http_response_header: new API where it exists.
    $headers = function_exists('http_get_last_response_headers')
        ? (http_get_last_response_headers() ?? [])
        : ($http_response_header ?? []);
    foreach ($headers as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $pair = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($pair !== '' && !str_contains($pair, '=')) { continue; }
            $setCookie = $pair; // single-session app: last wins
        }
    }
    return [$status, $body === false ? '' : $body, $setCookie ?: $cookie];
}
