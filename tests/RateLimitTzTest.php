<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Rate-limiter windows are UTC-anchored ─────────────────────────────────────
// window_start is stamped by MySQL UTC_TIMESTAMP(); reading it back through
// a timezone-naive parse skewed every window by the UTC offset — east of
// UTC budgets reset constantly (fail-open), west never rolls (sticky
// block). These pins hold the verdict identical across five timezones.
//
// State hygiene: the coverage runner executes all suites in ONE process, so
// the default timezone, settings, and test rows are saved and restored.

$origTz = date_default_timezone_get();
$orig = [
    'rate_limit_enabled' => get_setting('rate_limit_enabled', '1'),
    'rate_limit_max' => get_setting('rate_limit_max', '10'),
    'rate_limit_window_min' => get_setting('rate_limit_window_min', '15'),
];
set_setting('rate_limit_enabled', '1');
set_setting('rate_limit_max', '3');
set_setting('rate_limit_window_min', '15');

$_SERVER['REMOTE_ADDR'] = '10.8.8.8';
$db = get_db();
$db->exec("DELETE FROM rate_limits WHERE ip_address = '10.8.8.8'");
// Fresh window at max count, stamped exactly like rl_hit() writes it.
$db->exec("INSERT INTO rate_limits (ip_address, scope, count, window_start) VALUES ('10.8.8.8', 'public', 3, UTC_TIMESTAMP())");

$zones = ['UTC', 'Pacific/Kiritimati', 'Europe/Warsaw', 'America/New_York', 'Pacific/Midway'];
foreach ($zones as $tz) {
    date_default_timezone_set($tz);
    $s = rl_status('public');
    T::eq("maxed window stays blocked [$tz]", true, $s['blocked']);
    T::eq("count survives [$tz]", 3, $s['count']);
    T::ok("remaining within the window [$tz]",
        $s['remaining'] > 0 && $s['remaining'] <= 15 * 60);
}

// A spend under an eastern zone must increment, never silently reset.
date_default_timezone_set('Europe/Warsaw');
$hit = rl_hit('public');
T::eq('eastern-zone hit increments, not resets', 4, $hit['count']);
T::eq('eastern-zone hit stays blocked past max', true, $hit['blocked']);

// The UTC-anchored parser rejects what the database should never hold.
T::eq('empty window_start unparseable', false, _rl_parse_window_start(''));
T::eq('garbage window_start unparseable', false, _rl_parse_window_start('not-a-date'));
T::ok('UTC timestamp parses to roughly now',
    abs(_rl_parse_window_start(gmdate('Y-m-d H:i:s')) - time()) < 5);

$db->exec("DELETE FROM rate_limits WHERE ip_address = '10.8.8.8'");
foreach ($orig as $k => $v) { set_setting($k, $v); }
date_default_timezone_set($origTz);
unset($_SERVER['REMOTE_ADDR']);

exit(T::done());
