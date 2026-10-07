<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── IP-based rate limiting: budgets, scope isolation, window expiry, toggle ──

$db = get_db();
$ip    = '198.51.100.77';
$scope = 'test_public';

// Configure before any get_settings() call caches the table
set_setting('rate_limit_enabled', '1');
set_setting('rate_limit_max', '3');
set_setting('rate_limit_window_min', '15');

$_SERVER['REMOTE_ADDR'] = $ip;
unset($_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP']);
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ? OR ip_address LIKE ?')->execute([$ip, '198.51.100.%']);

// Fresh state
$s = rl_status($scope);
T::ok('fresh status not blocked', !$s['blocked'] && $s['count'] === 0);

// Budget of 3: blocked exactly at the limit
rl_increment($scope); rl_increment($scope);
T::ok('under budget not blocked', !rl_status($scope)['blocked']);
T::eq('count tracks increments', 2, rl_status($scope)['count']);
rl_increment($scope);
$s = rl_status($scope);
T::ok('blocked at limit', $s['blocked'] === true && $s['count'] === 3);

// Boundary agreement between the read path and the spend path: stored >=
// max and stored+1 > max are the SAME predicate for integer counts, so a
// "blocked" cooldown never hides a remaining attempt (and vice versa).
$bscope = 'test_boundary';
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ? AND scope = ?')->execute([$ip, $bscope]);
rl_increment($bscope); rl_increment($bscope); // count = max-1
T::ok('status allows at max-1', !rl_status($bscope)['blocked']);
$last = rl_hit($bscope); // the max-th attempt still executes
T::ok('hit executes the max-th attempt', !$last['blocked'] && $last['count'] === 3);
T::ok('status blocks exactly at max', rl_status($bscope)['blocked']);
$denied = rl_hit($bscope);
T::ok('hit denies past max', $denied['blocked'] && $denied['count'] === 4);
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ? AND scope = ?')->execute([$ip, $bscope]);

// Scope isolation: other surface unaffected by this budget
rl_increment('test_admin_login');
T::ok('separate scope has own budget', !rl_status('test_admin_login')['blocked']);

// Window expiry: backdate past the 15-minute window
$db->prepare('UPDATE rate_limits SET window_start = NOW() - INTERVAL 20 MINUTE WHERE ip_address = ? AND scope = ?')
   ->execute([$ip, $scope]);
$s = rl_status($scope);
T::ok('expired window not blocked', !$s['blocked']);
rl_increment($scope);
T::eq('increment after expiry resets to 1', 1, rl_status($scope)['count']);

// Successful attempt resets the counter entirely
rl_reset($scope);
T::ok('reset clears the row', !rl_status($scope)['blocked'] && rl_status($scope)['count'] === 0);

// Kill switch: disabled limiter neither counts nor blocks. Checked in child
// processes because get_settings() caches per process — a toggle must be
// observed by code that loads settings fresh, exactly like the next request.
rl_increment($scope); rl_increment($scope);

$probe = static function (string $enabled): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_rl_toggle.php')
         . ' ' . escapeshellarg($enabled);
    return json_decode(shell_exec($cmd) ?: '{}', true) ?: [];
};
putenv('RL_TEST_IP=' . $ip);

$s = $probe('0');
T::ok('disabled limiter never blocks', ($s['blocked'] ?? true) === false && ($s['count'] ?? -1) === 0);
$s = $probe('1');
T::ok('re-enabled limiter sees existing count', ($s['count'] ?? -1) === 2);
set_setting('rate_limit_enabled', '1');

// Client IP resolution (config.php): proxy headers are ignored unless the
// deployment opts in via DDMGMT_TRUST_PROXY=1 AND the direct peer is a
// trusted proxy. A spoofable header from an internet peer must never rotate
// the limiter's idea of the client — flag or no flag.
$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.1';
$_SERVER['HTTP_X_FORWARDED_FOR']  = '203.0.113.2';
T::eq('proxy headers ignored without DDMGMT_TRUST_PROXY', $ip, get_client_ip());
putenv('DDMGMT_TRUST_PROXY=1');
T::eq('public peer: headers ignored despite trust flag', $ip, get_client_ip());
putenv('DDMGMT_TRUSTED_PROXIES=' . $ip);
T::eq('listed peer: default header is XFF, a client-sent CF header is ignored', '203.0.113.2', get_client_ip());
putenv('DDMGMT_CLIENT_IP_HEADER=CF-Connecting-IP');
T::eq('CF header only when configured', '203.0.113.1', get_client_ip());
putenv('DDMGMT_CLIENT_IP_HEADER=X-Bogus');
T::eq('unknown configured header falls back to peer', $ip, get_client_ip());
putenv('DDMGMT_CLIENT_IP_HEADER');
unset($_SERVER['HTTP_CF_CONNECTING_IP']);
T::eq('XFF honored', '203.0.113.2', get_client_ip());
putenv('DDMGMT_TRUSTED_PROXIES');
T::eq('default list excludes public peer', $ip, get_client_ip());
unset($_SERVER['HTTP_X_FORWARDED_FOR']);

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.2';
T::eq('loopback peer honored by default list', '203.0.113.2', get_client_ip());
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
T::eq('REMOTE_ADDR fallback', '127.0.0.1', get_client_ip());
$_SERVER['REMOTE_ADDR'] = '192.168.55.3';
$_SERVER['HTTP_X_REAL_IP'] = '198.51.100.9';
T::eq('X-Real-IP ignored unless configured', '192.168.55.3', get_client_ip());
putenv('DDMGMT_CLIENT_IP_HEADER=X-Real-IP');
T::eq('RFC1918 peer: configured X-Real-IP honored', '198.51.100.9', get_client_ip());
putenv('DDMGMT_CLIENT_IP_HEADER');
unset($_SERVER['HTTP_X_REAL_IP']);
$_SERVER['REMOTE_ADDR'] = '::1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-an-ip';
T::eq('invalid header skipped, v6 loopback used', '::1', get_client_ip());
$_SERVER['HTTP_X_FORWARDED_FOR'] = '2001:db8::7';
T::eq('v6 loopback peer: header honored', '2001:db8::7', get_client_ip());
unset($_SERVER['HTTP_X_FORWARDED_FOR']);

// A malformed proxy entry must stay safe AND visible: it is skipped (the
// peer falls back to REMOTE_ADDR) and warned about once per process.
$_SERVER['REMOTE_ADDR'] = $ip;
putenv('DDMGMT_TRUSTED_PROXIES=10.0.0.0/abc, ' . $ip);
$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.1';
T::eq('bad CIDR skipped, listed peer still trusted', '203.0.113.1', get_client_ip());
putenv('DDMGMT_TRUSTED_PROXIES=10.0.0.0/abc,,');
T::eq('all-bad list with empty entry falls back to peer', $ip, get_client_ip());
putenv('DDMGMT_TRUSTED_PROXIES');

// Multi-hop XFF from a trusted peer walks right-to-left: neither hop is in
// the trusted set, so the first untrusted entry from the right wins —
// earlier entries stay client-controlled, never authoritative.
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.2, 70.41.3.18';
T::eq('multihop XFF uses first untrusted from the right', '70.41.3.18', get_client_ip());
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
putenv('DDMGMT_TRUST_PROXY');

// Budget subject: IPv6 clients count per /64 (one subscriber holds a whole
// /64); IPv4 and v4-mapped addresses stay exact.
$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:aaaa:bbbb:cccc:dddd';
T::eq('IPv6 subject is the /64', '2001:db8:1:2::/64', rl_client_subject());
$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::9';
T::eq('same /64, same budget', '2001:db8:1:2::/64', rl_client_subject());
$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.4';
T::eq('v4-mapped stays exact', '::ffff:198.51.100.4', rl_client_subject());
$_SERVER['REMOTE_ADDR'] = '198.51.100.4';
T::eq('IPv4 stays exact', '198.51.100.4', rl_client_subject());
$_SERVER['REMOTE_ADDR'] = $ip;

// CIDR syntax gate backing the trusted-proxy decision
T::ok('cidr-valid: bare v4', _cidr_valid('10.0.0.1'));
T::ok('cidr-valid: v4 range', _cidr_valid('10.0.0.0/8'));
T::ok('cidr-valid: v6 range', _cidr_valid('2001:db8::/32'));
T::ok('cidr-valid: rejects garbage', !_cidr_valid('not-a-cidr'));
T::ok('cidr-valid: rejects bad bits', !_cidr_valid('10.0.0.0/abc'));
T::ok('cidr-valid: rejects oversized bits', !_cidr_valid('10.0.0.0/33'));
T::ok('cidr-valid: rejects bad net', !_cidr_valid('999.1.1.1/24'));

// CIDR matcher backing the trusted-proxy decision
T::ok('cidr: /24 range hit',            _ip_in_cidr('10.1.2.3', '10.1.2.0/24'));
T::ok('cidr: /24 range miss',          !_ip_in_cidr('10.1.3.3', '10.1.2.0/24'));
T::ok('cidr: bare address exact match', _ip_in_cidr('192.168.0.9', '192.168.0.9'));
T::ok('cidr: family mismatch refused', !_ip_in_cidr('::1', '127.0.0.0/8'));
T::ok('cidr: mapped v4 normalized',     _ip_in_cidr('::ffff:10.1.2.3', '10.1.2.0/24'));
T::ok('cidr: /25 boundary hit',         _ip_in_cidr('10.1.2.5', '10.1.2.0/25'));
T::ok('cidr: /25 boundary miss',       !_ip_in_cidr('10.1.2.129', '10.1.2.0/25'));
T::ok('cidr: /32 single host',          _ip_in_cidr('10.1.2.3', '10.1.2.3/32'));
T::ok('cidr: /0 matches all v4',        _ip_in_cidr('8.8.8.8', '0.0.0.0/0'));
T::ok('cidr: invalid ip refused',      !_ip_in_cidr('not-an-ip', '10.0.0.0/8'));
T::ok('cidr: invalid range refused',   !_ip_in_cidr('10.1.2.3', '10.1.2.0/abc'));
$_SERVER['REMOTE_ADDR'] = $ip;

// Fail-closed: if the limiter subsystem breaks (table gone), pickup/login
// must be DENIED, never silently unblocked (child process = fresh settings
// cache, exactly like the next request). stderr is silenced portably:
// /dev/null on Unix, NUL on Windows.
$devnull = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
$fc = json_decode(shell_exec(
    escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_rl_failclosed.php') . " 2>$devnull"
) ?: '{}', true) ?: [];
T::ok('broken limiter blocks (fail closed)', ($fc['blocked'] ?? false) === true);
T::ok('fail-closed block carries a cooldown', (int)($fc['remaining'] ?? 0) > 0);
$s = rl_status($scope);
T::eq('rate_limits table restored after probe (data intact)', 2, rl_status($scope)['count']);

// Corrupt window_start fails CLOSED: strtotime() answers false for values
// the column should never hold (legacy zero-dates, damaged rows), and the
// old code read that as "window started in 1970" — silently resetting the
// budget so the row could never block. Zero-dates need a relaxed session
// sql_mode to store (MySQL 8 rejects them strictly); the mode is captured
// and restored so later suites in this process are unaffected.
$cscp = 'test_corrupt';
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ? AND scope = ?')->execute([$ip, $cscp]);
$mode = (string)$db->query('SELECT @@SESSION.sql_mode')->fetchColumn();
$db->exec("SET SESSION sql_mode = ''");
$db->prepare("INSERT INTO rate_limits (ip_address, scope, count, window_start) VALUES (?, ?, 2, '0000-00-00 00:00:00')")
   ->execute([$ip, $cscp]);
$db->exec('SET SESSION sql_mode = ' . $db->quote($mode));
T::ok('corrupt window status fails closed', rl_status($cscp)['blocked'] === true);
T::ok('corrupt window spend fails closed', rl_hit($cscp)['blocked'] === true);
T::eq('corrupt row is not reset by the probe', 2, (int)$db->query(
    'SELECT count FROM rate_limits WHERE ip_address = ' . $db->quote($ip) . " AND scope = '$cscp'")->fetchColumn());
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ? AND scope = ?')->execute([$ip, $cscp]);

// ── Refund, never reset: a free request must not wipe earned failures ───────
$rfs = 'rl_refund_probe';
rl_reset($rfs);
rl_hit($rfs);
rl_hit($rfs);
rl_hit($rfs);
rl_refund($rfs);
T::eq('refund gives back exactly one attempt', 2, rl_status($rfs)['count']);
rl_refund($rfs);
rl_refund($rfs);
rl_refund($rfs);
T::eq('refund floors at zero', 0, rl_status($rfs)['count']);
rl_reset($rfs);

// ── Per-subject budgets sit next to the per-IP ones ─────────────────────────
$subj = rl_account_subject('l:', 'Admin');
T::eq('account subject ignores case and padding', $subj, rl_account_subject('l:', '  aDMIN '));
T::ok('account subject differs per name', $subj !== rl_account_subject('l:', 'admin2'));
T::ok('account subject fits the ip_address column', strlen($subj) <= 45);
rl_reset($rfs, $subj);
rl_hit($rfs, null, null, $subj);
rl_hit($rfs, null, null, $subj);
T::eq('subject budget counts by itself', 2, rl_status($rfs, $subj)['count']);
T::eq('subject hits leave the IP budget alone', 0, rl_status($rfs)['count']);
rl_refund($rfs, $subj);
T::eq('subject refund works', 1, rl_status($rfs, $subj)['count']);
rl_reset($rfs, $subj);
T::eq('subject reset clears only that subject', 0, rl_status($rfs, $subj)['count']);

// ── _rl_parse_window_start: every engine's datetime shape parses ────────────
// The limiter reads window_start back from MySQL/MariaDB (bare UTC), but the
// parser also accepts PostgreSQL offsets, ISO-8601 and bare dates so a
// migrated or hand-touched row cannot silently reset a budget: unparseable
// input answers false (blocked), never "long ago" (reset).
$noonUtc = gmmktime(12, 0, 0, 10, 4, 2026);
T::eq('bare UTC datetime parses as UTC', $noonUtc, _rl_parse_window_start('2026-10-04 12:00:00'));
T::eq('ISO-8601 Z parses as UTC', $noonUtc, _rl_parse_window_start('2026-10-04T12:00:00Z'));
T::eq('ISO-8601 offset parses', $noonUtc, _rl_parse_window_start('2026-10-04T12:00:00+00:00'));
T::eq('ISO-8601 negative offset shifts', $noonUtc + 5 * 3600, _rl_parse_window_start('2026-10-04T12:00:00-05:00'));
T::eq('postgres offset parses', $noonUtc, _rl_parse_window_start('2026-10-04 12:00:00+00'));
T::eq('bare date parses as midnight UTC', gmmktime(0, 0, 0, 10, 4, 2026), _rl_parse_window_start('2026-10-04'));
T::eq('unanchored text falls back to strtotime UTC', $noonUtc, _rl_parse_window_start('04 Oct 2026 12:00:00'));
T::eq('garbage fails closed', false, _rl_parse_window_start('not-a-date'));
// Impossible values match a strategy regex but never parse: each strategy's
// catch falls through and the input still ends closed, never reset.
T::eq('impossible ISO falls through to closed', false, _rl_parse_window_start('2026-10-04T25:00:00Z'));
T::eq('impossible datetime fails closed', false, _rl_parse_window_start('2026-13-04 12:00:00'));
T::eq('impossible date fails closed', false, _rl_parse_window_start('2026-13-40'));
T::eq('impossible PG-offset datetime fails closed', false, _rl_parse_window_start('2026-10-04 25:00:00+05'));

// Legacy spend-only shim still spends exactly once.
rl_reset('cov_legacy_spend');
rl_increment('cov_legacy_spend');
T::eq('rl_increment spends one attempt', 1, rl_status('cov_legacy_spend')['count']);
rl_reset('cov_legacy_spend');

// Self-reauth refuses when its own budget is exhausted (guessing capped).
$me = current_user_id();
for ($i = 0; $i < 11; $i++) { rl_hit('admin_reauth', 10, 900, 'u:' . $me); }
T::ok('self-reauth blocked on exhausted budget', admin_self_reauth_ok($me, 'anything') === false);
rl_reset('admin_reauth', 'u:' . $me);

// Cleanup
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ?')->execute([$ip]);

exit(T::done());
