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

// Client IP resolution precedence (config.php)
$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.1';
$_SERVER['HTTP_X_FORWARDED_FOR']  = '203.0.113.2';
T::eq('CF header wins when present', '203.0.113.1', get_client_ip());
unset($_SERVER['HTTP_CF_CONNECTING_IP']);
T::eq('XFF first entry wins next', '203.0.113.2', get_client_ip());
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
T::eq('REMOTE_ADDR is final fallback', $ip, get_client_ip());
$_SERVER['HTTP_X_FORWARDED_FOR'] = 'not-an-ip, 203.0.113.9';
T::eq('invalid header skipped, REMOTE_ADDR used', $ip, get_client_ip());

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

// Cleanup
$db->prepare('DELETE FROM rate_limits WHERE ip_address = ?')->execute([$ip]);

exit(T::done());
