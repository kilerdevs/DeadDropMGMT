<?php
declare(strict_types=1);

// DiagnosticsTest — the owner metrics collector (includes/diagnostics.php).
//
// - diagnostics_collect() returns the seven sections plus a timestamp, each
//   section self-describing (ok true/false) so one degraded source never
//   fails the page.
// - The fail-soft contract is pinned directly: a throwing collector degrades
//   to ok:false instead of escaping.
// - Display helpers never lie: unknown stays unknown (never "0 B"), and a
//   missing heartbeat renders "never", never an epoch date.

require_once __DIR__ . '/bootstrap.php';

$diag = diagnostics_collect();
T::ok('collect returns an array', is_array($diag));
T::ok('collect timestamps itself', isset($diag['generated_at']) && $diag['generated_at'] <= time());
foreach (['system', 'jobs', 'logs', 'traffic', 'security', 'data', 'backups'] as $sec) {
    T::ok("section $sec present", isset($diag[$sec]) && is_array($diag[$sec]));
    T::ok("section $sec self-describes", array_key_exists('ok', $diag[$sec]));
}

$soft = _diag_try('function_that_does_not_exist_xyz');
T::eq('throwing collector degrades to ok:false', ['ok' => false, 'error' => 'unavailable'], $soft);

T::eq('bytes unknown stays unknown', '—', diagnostics_bytes(null));
T::eq('bytes zero is zero', '0 B', diagnostics_bytes(0));
T::eq('bytes scale', '1.5 KiB', diagnostics_bytes(1536));
T::eq('bytes megabytes', '2.0 MiB', diagnostics_bytes(2097152));
T::eq('age zero is never', 'never', diagnostics_age(0));
T::eq('age future is never', 'never', diagnostics_age(time() + 60));
T::eq('age minutes', '1m ago', diagnostics_age(time() - 90));
T::eq('age hours', '2h ago', diagnostics_age(time() - 7200));

if (($diag['data']['ok'] ?? false) === true) {
    $unknown = array_diff(array_keys($diag['data']['orders_by_status'] ?? []), ['preparing', 'delivered']);
    T::eq('order statuses are known values', [], array_values($unknown));
}
if (($diag['jobs']['ok'] ?? false) === true) {
    foreach (['last_cleanup', 'maps_steward_at', 'proxy_heal_last'] as $beat) {
        T::ok("heartbeat $beat tracked", isset($diag['jobs']['heartbeats'][$beat]));
    }
}
if (($diag['traffic']['ok'] ?? false) === true) {
    T::ok('log sample size reported', is_int($diag['traffic']['log_sampled_lines'] ?? null));
}

$du = _diag_dir_usage(__DIR__);
T::ok('dir usage works on a readable tree', ($du['ok'] ?? false) === true && ($du['files'] ?? 0) > 0);
$duMissing = _diag_dir_usage(__DIR__ . '/no-such-dir-xyz');
T::eq('dir usage degrades on a missing tree', false, $duMissing['ok'] ?? true);

exit(T::done());
