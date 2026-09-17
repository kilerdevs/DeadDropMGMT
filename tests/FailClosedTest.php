<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Fail-closed paths and guards, in-process ─────────────────────────────────
// The HTTP suites drive these behaviours through real endpoints, but that
// runs inside the php -S worker where pcov cannot see — so regressions here
// were invisible to the coverage floor. This suite exercises the library
// functions directly: security headers, guard pre-exit conditions, rate-limit
// failure branches, session-failure buckets, and every "deny on error" path
// in wipe/order-state/crypto/db. Actual exit() statements stay covered by
// AuthorizationHttpTest over HTTP; everything reachable before them lives here.

$db = get_db();

/** Rename a table away, run $fn, always put it back. */
function with_table_hidden(string $table, callable $fn): mixed {
    $bak = $table . '_cov_bak';
    $db  = get_db();
    $db->exec("RENAME TABLE {$table} TO {$bak}");
    try {
        return $fn();
    } finally {
        $db->exec("RENAME TABLE {$bak} TO {$table}");
    }
}

// ── Security headers (both CSP profiles + HSTS branches) ────────────────────
$_SERVER['HTTPS'] = 'on';
$nonce_pub_https = set_security_headers();
T::eq('public nonce decodes to 18 bytes', 18, strlen(base64_decode($nonce_pub_https, true) ?: ''));

// The header list is pure (header() is a no-op under CLI), so both profiles
// are pinned here instead of over HTTP.
$pub_list = _security_headers_list(false, 'testnonce');
$adm_list = _security_headers_list(true, 'testnonce');
T::ok('public profile sends no-referrer', in_array('Referrer-Policy: no-referrer', $pub_list, true));
T::ok('admin profile sends no-referrer', in_array('Referrer-Policy: no-referrer', $adm_list, true));
foreach (['public' => $pub_list, 'admin' => $adm_list] as $prof => $list) {
    $csp = implode("\n", $list);
    T::ok("$prof CSP carries the request nonce", str_contains($csp, "'nonce-testnonce'"));
    T::ok("$prof CSP keeps frame-ancestors none", str_contains($csp, "frame-ancestors 'none'"));
    T::ok("$prof CSP keeps object-src none", str_contains($csp, "object-src 'none'"));
}
T::ok('public CSP keeps OSM frame-src',
    str_contains(implode("\n", $pub_list), 'frame-src https://www.openstreetmap.org'));

putenv('DDMGMT_TRUST_PROXY=1');
$origRemote = $_SERVER['REMOTE_ADDR'] ?? null;
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
T::ok('trusted proxy XFP https detected', request_is_https());
set_security_headers(); // HSTS via proxy-reported scheme

// Same header from an untrusted peer must not flip the scheme (shared
// _proxy_peer_trusted() gate with get_client_ip()). HTTPS is cleared here
// so the assertion isolates the XFP path from PHP's own view below.
$_SERVER['REMOTE_ADDR'] = '198.51.100.77';
$httpsKept = $_SERVER['HTTPS'] ?? null;
$_SERVER['HTTPS'] = '';
T::ok('untrusted peer XFP https ignored', !request_is_https());
if ($httpsKept === null) {
    unset($_SERVER['HTTPS']);
} else {
    $_SERVER['HTTPS'] = $httpsKept;
}
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'http';
T::ok('trusted proxy XFP http NOT https', !request_is_https());
putenv('DDMGMT_TRUST_PROXY=0');
unset($_SERVER['HTTP_X_FORWARDED_PROTO']);

// Multi-hop XFF behind a trusted peer: earlier entries are client-controlled
// (the peer appends), so the last hop — the only one the client cannot forge
// — is authoritative. Single-entry headers are untouched.
putenv('DDMGMT_TRUST_PROXY=1');
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 5.6.7.8';
T::eq('multi-hop XFF resolves to the peer-appended last hop', '5.6.7.8', get_client_ip());
$_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9';
T::eq('single-entry XFF unchanged', '9.9.9.9', get_client_ip());
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
putenv('DDMGMT_TRUST_PROXY=0');
if ($origRemote === null) {
    unset($_SERVER['REMOTE_ADDR']);
} else {
    $_SERVER['REMOTE_ADDR'] = $origRemote;
}

$_SERVER['HTTPS'] = '';
$nonce_admin = set_security_headers(true);
T::eq('admin nonce decodes to 18 bytes', 18, strlen(base64_decode($nonce_admin, true) ?: ''));
T::ok('nonces are per-call random', $nonce_admin !== $nonce_pub_https);
$nonce_plain = set_security_headers();
T::ok('plain-http nonce generated', strlen(base64_decode($nonce_plain, true) ?: '') === 18);

// ── Session mechanism hardening (explicit, not php.ini defaults) ────────────
start_secure_session();
T::eq('strict mode refuses uninitialized SIDs', '1', ini_get('session.use_strict_mode'));
T::eq('cookies carry the SID exclusively', '1', ini_get('session.use_only_cookies'));
T::eq('transparent SID off', '0', ini_get('session.use_trans_sid'));

// ── Guards: conditions reachable before their exit() redirects ───────────────
$_SESSION = [];
start_secure_session();
$_SESSION['user_id'] = 999;
$_SESSION['user_role'] = 'owner';
$_SESSION['user_name'] = 't_cov_owner';
$_SESSION['login_time'] = time();
$_SERVER['SCRIPT_NAME'] = '/admin/orders.php';
require_admin(); // owner, fresh login: passes timeout + gate checks
T::ok('owner passes require_admin', is_admin_logged_in());
require_owner(); // owner passes the owner check too
T::ok('owner passes require_owner', true);

// Courier without TOTP on a 2fa-exempt ROUTE gets through the gate check
// (the flag 2fa.php and exempt dispatch routes set — script basenames no
// longer gate anything; the gated negative is exit-covered over HTTP by
// DispatchTest's 'pending courier gated from actions').
$_SESSION['user_role'] = 'courier';
$_SESSION['totp_enabled'] = false;
$GLOBALS['DDMGMT_ROUTE_2FA_EXEMPT'] = true;
require_admin();
T::ok('courier pre-enrollment allowed on exempt route', true);
unset($GLOBALS['DDMGMT_ROUTE_2FA_EXEMPT']);

// Non-owner would be redirected by require_owner (exit-covered over HTTP);
// the ownership predicate itself stays unit-checkable:
$_SESSION['user_role'] = 'courier';
T::ok('courier fails is_owner', !is_owner());
unset($_SERVER['SCRIPT_NAME']);

// The ownership predicate fails closed when the orders table is unreadable
// (deny, never assume ownership on error):
$_SESSION['user_id'] = 4242;
with_table_hidden('orders', static function (): void {
    T::ok('courier_owns_order false on DB failure', !courier_owns_order(1));
});

// Config-fallback owner login: on a fresh install (users table absent) the
// owner authenticates against ADMIN_* constants with user_id 0 — and must
// STAY logged in (isset, not !empty, in is_admin_logged_in).
if (!defined('ADMIN_USERNAME')) {
    define('ADMIN_USERNAME', 'fallback_owner');
}
if (!defined('ADMIN_PASSWORD_HASH')) {
    define('ADMIN_PASSWORD_HASH', password_hash('fallback-pass-1', PASSWORD_BCRYPT));
}
$_SESSION = [];
start_secure_session();
with_table_hidden('users', static function (): void {
    T::eq('fallback owner login ok without users table', 'ok', admin_login('fallback_owner', 'fallback-pass-1'));
    T::ok('fallback owner stays logged in with id 0', is_admin_logged_in() && current_user_id() === 0);
    T::eq('wrong fallback password fails', 'fail', admin_login('fallback_owner', 'nope'));
    T::eq('unknown user fails without users table', 'fail', admin_login('nobody', 'nope'));
});
$_SESSION = [];

// The config-owner fallback answers ONLY for a genuinely absent users table
// (fresh install). Any other DB failure — connection lost, server gone —
// fails closed even with correct config credentials, so a mid-operation
// outage can never downgrade a TOTP-enrolled owner to password-only login.
T::ok('missing-table message counts as absent table',
    _db_table_missing(new PDOException("SQLSTATE[42S02]: Base table or view not found: 1146 Table 'deaddrops_test.users' doesn't exist")));
T::ok('connection failure is not an absent table',
    !_db_table_missing(new PDOException('SQLSTATE[HY000] [2002] Connection refused')));
T::ok('syntax failure is not an absent table',
    !_db_table_missing(new PDOException('SQLSTATE[42000]: Syntax error or access violation')));

// Sliding inactivity: an authenticated request refreshes the session clock.
$_SESSION = [];
start_secure_session();
$_SESSION['user_id'] = 7;
$_SESSION['user_role'] = 'owner';
$_SESSION['user_name'] = 'sliding-owner';
$_SESSION['login_time'] = time() - 100;
require_admin();
T::ok('require_admin refreshes login_time on activity', $_SESSION['login_time'] >= time() - 5);
$_SESSION = [];

// A non-missing-table DB error fails closed even with correct config
// credentials: the users table is swapped for a VIEW that breaks only
// afterwards (MariaDB validates the SELECT at CREATE VIEW time, so the
// view must start valid). Reading through it then throws HY000 — not
// 42S02 — and the fresh-install fallback must answer 'fail', never 'ok'.
// The finally below is deliberately bulletproof: an earlier version with a
// bare DROP VIEW masked the restore and orphaned the renamed table.
$db->exec('RENAME TABLE users TO users_scope_bak');
try {
    $db->exec('CREATE VIEW users AS SELECT * FROM users_scope_bak');
    $db->exec('RENAME TABLE users_scope_bak TO users_scope_bak2');
    T::eq('broken-view login fails closed', 'fail', admin_login('fallback_owner', 'fallback-pass-1'));
} finally {
    try {
        $db->exec('DROP VIEW IF EXISTS users');
    } catch (Throwable) {
    }
    foreach (['users_scope_bak2', 'users_scope_bak'] as $bak) {
        try {
            $db->exec("RENAME TABLE `$bak` TO users");
        } catch (Throwable) {
        }
    }
}
T::ok('users table restored after scope probe',
    $db->query("SHOW TABLES LIKE 'users'")->fetch() !== false);
$_SESSION = [];

// ── Rate limiter: disabled short-circuit + fail-closed branches ─────────────
set_setting('rate_limit_enabled', '0');
T::eq('rl_status disabled short-circuit',
      ['blocked' => false, 'remaining' => 0, 'count' => 0], rl_status('cov'));
T::eq('rl_hit disabled short-circuit',
      ['blocked' => false, 'remaining' => 0, 'count' => 0], rl_hit('cov'));
set_setting('rate_limit_enabled', '1');

// Counter unreadable → status reports BLOCKED (fail closed)
with_table_hidden('rate_limits', function (): void {
    $s = rl_status('cov');
    T::ok('rl_status fail-closed blocks when counter unreadable',
          $s['blocked'] === true && $s['count'] === 0);
});

// Increment unreadable → spend denied, transaction rolled back
with_table_hidden('rate_limits', function (): void {
    $s = rl_hit('cov');
    T::ok('rl_hit fail-closed denies when counter unwritable',
          $s['blocked'] === true && $s['count'] === 0);
});
T::ok('rate_limits table survived fail-closed probe',
      get_db()->query("SHOW TABLES LIKE 'rate_limits'")->fetch() !== false);

// Reset is best-effort: silent on an unreadable counter, limiter stays
// fail-closed throughout.
with_table_hidden('rate_limits', function (): void {
    rl_reset('cov');
    T::ok('rl_reset survives missing table, limiter stays closed',
          rl_status('cov')['blocked'] === true);
});

// ── Session failure buckets ──────────────────────────────────────────────────
// The bucket window follows the configured IP-limiter window, so pin it:
// the assertions below assume the 15-minute default, and the shared test DB
// may hold leftovers from limiter-lockout suites.
$fc_prev_window = get_setting('rate_limit_window_min', '15');
set_setting('rate_limit_window_min', '15');
bucket_clear('b1');
bucket_fail('b1'); // fresh window starts at 1
bucket_fail('b1'); // same window increments
T::eq('bucket counts two failures', 2, bucket_status('b1')['count']);
T::ok('bucket below default max not blocked', !bucket_status('b1')['blocked']);

bucket_clear('b2');
bucket_fail('b2');
bucket_fail('b2');
T::ok('bucket blocks at custom max', bucket_status('b2', 2)['blocked']);

// A max of 0 clamps up so a bucket can never be configured wide open
bucket_clear('b3');
bucket_fail('b3');
T::ok('bucket max clamps to at least 1', bucket_status('b3', 0)['blocked']);

// Expired window restarts from one
$_SESSION['pw_fail']['b4'] = ['n' => 9, 'ts' => time() - 901];
bucket_fail('b4');
T::eq('expired bucket window restarts', 1, bucket_status('b4')['count']);

// Remaining-time reporting
bucket_clear('b5');
T::eq('no bucket means no remaining time', 0, bucket_remaining('b5'));
$_SESSION['pw_fail']['b5'] = ['n' => 1, 'ts' => time()];
T::ok('fresh bucket has remaining time', bucket_remaining('b5') > 890);
$_SESSION['pw_fail']['b5'] = ['n' => 1, 'ts' => time() - 1000];
T::eq('stale bucket has no remaining time', 0, bucket_remaining('b5'));

bucket_clear('b1');
T::eq('clear empties the bucket', 0, bucket_status('b1')['count']);

// The bucket window tracks the limiter setting instead of a constant.
set_setting('rate_limit_window_min', '30');
$_SESSION['pw_fail']['b6'] = ['n' => 1, 'ts' => time()];
T::ok('bucket window follows the configured window', bucket_remaining('b6') > 1700);
bucket_clear('b6');
set_setting('rate_limit_window_min', '15');
set_setting('rate_limit_window_min', $fc_prev_window);

// ── Enrollment secrets ───────────────────────────────────────────────────────
$enr = enrollment_secret_generate();
T::eq('enrollment secret is 64 hex chars', 64, strlen($enr));
T::ok('enrollment secret is hex', ctype_xdigit($enr));

// Unreadable users table must deny, never admit
with_table_hidden('users', function (): void {
    T::ok('enrollment check fails closed on DB error', enrollment_secret_valid(1, 'x') === false);
    // Login falls back to config-owner mode; with no config constants the
    // fallback must answer a plain 'fail' instead of crashing
    T::eq('login without users table answers fail', 'fail', admin_login('someone', 'whatever'));
});

// A NULL expiry is a damaged row, not a perpetual credential: valid hash +
// NULL expiry must deny. Positive control (future expiry) proves the query.
$dbE = get_db();
$dbE->prepare('DELETE FROM users WHERE username = ?')->execute(['fc_enroll_probe']);
$knownSecret = enrollment_secret_generate();
$dbE->prepare('INSERT INTO users (username, password_hash, role, enrollment_hash, enrollment_expires)
               VALUES (?, "", "courier", ?, NOW() + INTERVAL 24 HOUR)')
    ->execute(['fc_enroll_probe', enrollment_secret_hash($knownSecret)]);
$probeId = (int)$dbE->lastInsertId();
T::ok('live enrollment secret validates', enrollment_secret_valid($probeId, $knownSecret));
$dbE->prepare('UPDATE users SET enrollment_expires = NULL WHERE id = ?')->execute([$probeId]);
T::ok('NULL expiry denies even with the right secret', !enrollment_secret_valid($probeId, $knownSecret));
$dbE->prepare('DELETE FROM users WHERE id = ?')->execute([$probeId]);

// ── Wipe: every pre-transaction count is guarded ────────────────────────────
// Hiding order_photos used to escape as a raw PDOException before the
// transaction even began; now it reports -1 and the wipe still proceeds.
with_table_hidden('order_photos', function (): void {
    $rep = do_panic_wipe();
    T::eq('unreadable photos table reports -1, wipe still runs', -1, $rep['photos']);
    T::eq('wipe with hidden photos table destroys nothing else', 0, $rep['files_failed']);
});
with_table_hidden('audit_log', function (): void {
    $msg = '';
    try {
        do_panic_wipe();
    } catch (PDOException $e) { // must NOT surface as the raw PDO error
        $msg = 'raw PDOException escaped: ' . $e->getMessage();
    } catch (RuntimeException $e) {
        $msg = $e->getMessage();
    }
    T::ok('wipe aborts atomically when evidence is unreadable',
          str_starts_with($msg, 'DB wipe failed, nothing destroyed'));
});

// Missing file sweep stays quiet (idempotent retries)
$rep = ['files' => 0, 'files_failed' => 0];
_panic_unlink(dirname(__DIR__) . '/uploads/does-not-exist/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg', $rep);
T::eq('panic unlink skips vanished files quietly', 0, $rep['files_failed'] + $rep['files']);

// ── Order state machine: SQL failures answer false/null, never throw ────────
with_table_hidden('orders', function (): void {
    T::ok('deliver transition fails closed on DB error', order_deliver_atomic(1, 24) === false);
    T::ok('delete transition fails closed on DB error', order_delete_atomic(1) === null);
});

// ── Crypto rejects malformed inputs ──────────────────────────────────────────
T::ok('decrypt_secret rejects short IV',
      decrypt_secret(base64_encode(str_repeat('a', 20)), 'abc') === false);
T::ok('decrypt_secret rejects truncated payload',
      decrypt_secret(base64_encode('short'), str_repeat('a', 24)) === false);

$not_json = encrypt_location('definitely-not-json');
T::ok('legacy non-JSON plaintext still decrypts as text-only location',
      decrypt_location_data($not_json['ciphertext'], $not_json['iv']) !== false);
$raw_ct = base64_decode($not_json['ciphertext'], true);
$raw_ct[0] = $raw_ct[0] ^ chr(0x01); // flip one bit: GCM tag must reject it
T::ok('tampered ciphertext rejects decryption',
      decrypt_location_data(base64_encode($raw_ct), $not_json['iv']) === false);

T::ok('open_payload rejects missing iv', open_payload(['ct' => base64_encode(str_repeat('a', 32))]) === false);
T::ok('open_payload rejects undecodable ciphertext',
      open_payload(['ct' => '!!!not-base64!!!', 'iv' => str_repeat('a', 24)]) === false);
// Length-correct but non-hex IVs: hex2bin() answers false there, and the
// decryptors must reject — not TypeError inside openssl_decrypt().
$ct = encrypt_location('hex-guard probe');
T::ok('decrypt_location rejects 24-char non-hex IV',
      decrypt_location($ct['ciphertext'], str_repeat('z', 24)) === false);
T::ok('decrypt_secret rejects 24-char non-hex IV',
      decrypt_secret(base64_encode(str_repeat('b', 20)), str_repeat('g', 24)) === false);
T::ok('open_payload rejects 24-char non-hex IV',
      open_payload(['ct' => base64_encode(str_repeat('c', 32)), 'iv' => str_repeat('q', 24)]) === false);
// Invalid UTF-8 never reaches the ciphers as a false: loud failure instead.
T::throws('encrypt_location_data rejects invalid UTF-8',
          fn() => encrypt_location_data(['text' => "\xff\xfe invalid"]),
          RuntimeException::class);
T::throws('seal_payload rejects invalid UTF-8',
          fn() => seal_payload(['text' => "\xff\xfe invalid"]),
          RuntimeException::class);

// ── Database options factory: TLS matrix without a TLS database ─────────────
$base = db_options('', '', '', true);
T::eq('no CA means exactly the three base options', 3, count($base));
T::ok('base options disable emulation', $base[PDO::ATTR_EMULATE_PREPARES] === false);

$full = db_options('/ca.pem', '/client.pem', '/client.key', false);
$caKey = db_mysql_attr('SSL_CA');
$certKey = db_mysql_attr('SSL_CERT');
$keyKey = db_mysql_attr('SSL_KEY');
T::ok('CA option carried through', $full[$caKey] === '/ca.pem');
T::ok('client cert carried through', $full[$certKey] === '/client.pem');
T::ok('client key carried through', $full[$keyKey] === '/client.key');
if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT') || defined('Pdo\\Mysql::ATTR_SSL_VERIFY_SERVER_CERT')) {
    T::ok('verify toggle carried through',
          $full[db_mysql_attr('SSL_VERIFY_SERVER_CERT')] === false);
} else {
    // Neither the legacy nor the driver constant exists: base 3 + CA/cert/key.
    T::eq('verify toggle omitted when unsupported', 6, count($full));
}

$partial = db_options('/ca.pem', '', '', false);
T::eq('CA-only setup adds no client cert', false, isset($partial[$certKey]));
T::eq('CA-only setup adds no client key', false, isset($partial[$keyKey]));
T::throws('client cert without CA refuses plaintext fallback',
          fn() => db_options('', '/client.pem', '', true),
          RuntimeException::class);
T::throws('client key without CA refuses plaintext fallback',
          fn() => db_options('', '', '/client.key', true),
          RuntimeException::class);

// A refused connect surfaces as PDOException — the exact input get_db's
// fail-closed catch receives (503 + die, exit-covered over HTTP smoke tests)
$refused = 'mysql:host=127.0.0.1;port=1;dbname=deaddrops_test;charset=utf8mb4';
T::throws('unreachable database throws PDOException',
          fn() => db_connect($refused, 'root', '', db_options('', '', '', true)),
          PDOException::class);

exit(T::done());
