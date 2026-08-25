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

putenv('DDMGMT_TRUST_PROXY=1');
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
T::ok('trusted proxy XFP https detected', request_is_https());
set_security_headers(); // HSTS via proxy-reported scheme
$_SERVER['HTTP_X_FORWARDED_PROTO'] = 'http';
T::ok('trusted proxy XFP http NOT https', !request_is_https());
putenv('DDMGMT_TRUST_PROXY=0');
unset($_SERVER['HTTP_X_FORWARDED_PROTO']);

$_SERVER['HTTPS'] = '';
$nonce_admin = set_security_headers(true);
T::eq('admin nonce decodes to 18 bytes', 18, strlen(base64_decode($nonce_admin, true) ?: ''));
T::ok('nonces are per-call random', $nonce_admin !== $nonce_pub_https);
$nonce_plain = set_security_headers();
T::ok('plain-http nonce generated', strlen(base64_decode($nonce_plain, true) ?: '') === 18);

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

// Courier without TOTP on an ALLOWED script name gets through the gate check
$_SESSION['user_role'] = 'courier';
$_SESSION['totp_enabled'] = false;
$_SERVER['SCRIPT_NAME'] = '/admin/2fa.php';
require_admin();
T::ok('courier pre-enrollment allowed on 2fa.php itself', true);

// Non-owner would be redirected by require_owner (exit-covered over HTTP);
// the ownership predicate itself stays unit-checkable:
$_SESSION['user_role'] = 'courier';
T::ok('courier fails is_owner', !is_owner());
unset($_SERVER['SCRIPT_NAME']);

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

// Reset is best-effort: silent on an unreadable counter
with_table_hidden('rate_limits', function (): void {
    rl_reset('cov');
    T::ok('rl_reset survives missing table silently', true);
});

// ── Session failure buckets ──────────────────────────────────────────────────
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

// ── Wipe: unreadable audit table aborts the whole transaction ───────────────
// (order_photos is deliberately NOT hidden here: its COUNT sits outside any
// guard, so hiding it would escape as a raw PDOException before the
// transaction even begins — a different, unguarded failure mode.)
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

// ── Database options factory: TLS matrix without a TLS database ─────────────
$base = db_options('', '', '', true);
T::eq('no CA means exactly the three base options', 3, count($base));
T::ok('base options disable emulation', $base[PDO::ATTR_EMULATE_PREPARES] === false);

$full = db_options('/ca.pem', '/client.pem', '/client.key', false);
T::ok('CA option carried through', $full[PDO::MYSQL_ATTR_SSL_CA] === '/ca.pem');
T::ok('client cert carried through', $full[PDO::MYSQL_ATTR_SSL_CERT] === '/client.pem');
T::ok('client key carried through', $full[PDO::MYSQL_ATTR_SSL_KEY] === '/client.key');
if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
    T::ok('verify toggle carried through',
          $full[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] === false);
} else {
    T::ok('verify constant absent - toggle correctly omitted', !isset($full[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT]));
}

$partial = db_options('/ca.pem', '', '', false);
T::eq('CA-only setup adds no client cert', false, isset($partial[PDO::MYSQL_ATTR_SSL_CERT]));
T::eq('CA-only setup adds no client key', false, isset($partial[PDO::MYSQL_ATTR_SSL_KEY]));

// A refused connect surfaces as PDOException — the exact input get_db's
// fail-closed catch receives (503 + die, exit-covered over HTTP smoke tests)
$refused = 'mysql:host=127.0.0.1;port=1;dbname=deaddrops_test;charset=utf8mb4';
T::throws('unreachable database throws PDOException',
          fn() => db_connect($refused, 'root', '', db_options('', '', '', true)),
          PDOException::class);

exit(T::done());
