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

// ── Sections under load: seed one row per aggregation so the loops, the
// chain tip and the log histogram all execute (not just the empty queries).
$db = get_db();
$prevLock = get_setting('maps_worker_lock', '');
$prevCpId = (int)$db->query('SELECT COALESCE(MAX(id), 0) FROM log_checkpoints')->fetchColumn();
$db->prepare("INSERT INTO order_events (order_id, token_hmac, event_type, ip_address, created_at) VALUES (NULL, NULL, 'lookup', '198.51.100.7', NOW())")->execute();
$db->prepare("INSERT INTO order_events (order_id, token_hmac, event_type, ip_address, created_at) VALUES (NULL, NULL, 'lookup', '198.51.100.7', NOW())")->execute();
$db->prepare("INSERT INTO order_events (order_id, token_hmac, event_type, ip_address, created_at) VALUES (NULL, NULL, 'unlock_success', '198.51.100.7', NOW())")->execute();
$db->prepare("INSERT INTO audit_log (username, action, ip_address, created_at) VALUES ('diag', 'diag_probe', '198.51.100.9', NOW())")->execute();
$db->prepare("INSERT INTO audit_log (username, action, ip_address, created_at) VALUES ('diag', 'diag_probe', '198.51.100.9', NOW())")->execute();
$db->prepare("INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, status, bytes_expected, bytes_done) VALUES ('diag-zone', 20.0, 52.0, 21.0, 53.0, 'ready', 1000, 500)")->execute();
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, last_checked) VALUES ('http://127.0.0.1:9/diag', 'diag', 'ok', NOW())")->execute();
set_setting('maps_worker_lock', (string)json_encode(['by' => 'diag-test', 'at' => time() - 60]));
$db->prepare("INSERT INTO log_checkpoints (tip_hash, tip_seq, created_at) VALUES ('diag-probe-hash', 7, NOW())")->execute();
log_err('diag_hist_probe');
$loaded = diagnostics_collect();

$tr = $loaded['traffic'] ?? [];
T::ok('24h lookup count covers the probes', ($tr['events_24h_by_type']['lookup'] ?? 0) >= 2);
T::ok('top ip surfaces', count(array_filter($tr['top_ips_24h'] ?? [], static fn(array $r): bool => $r['ip'] === '198.51.100.7')) === 1);
T::ok('top events list the probes', count($tr['log_top_events'] ?? []) >= 1);
T::ok('log histogram counts the probe line', ($tr['log_levels']['error'] ?? 0) >= 1);
T::ok('histogram is labeled by sample size', ($tr['log_sampled_lines'] ?? 0) >= 1);

$sec = $loaded['security'] ?? [];
T::ok('audit mix counts the probe action', ($sec['audit_24h_by_action']['diag_probe'] ?? 0) >= 1);
T::ok('audit total covers the probes', ($sec['audit_24h_total'] ?? 0) >= 2);

$data = $loaded['data'] ?? [];
$zoneNames = array_column($data['zones'] ?? [], 'name');
T::ok('seeded zone listed at 50%', in_array('diag-zone', $zoneNames, true));
T::ok('pool counts the seeded proxy', ($data['proxy_pool']['total'] ?? 0) >= 1);

$tip = $loaded['logs']['tip'] ?? null;
T::ok('chain tip resolves to a seq', is_array($tip) && is_int($tip['seq'] ?? null));
T::ok('worker lock holder surfaces', ($loaded['jobs']['maps_worker_lock']['by'] ?? '') === 'diag-test');
T::ok('checkpoint surfaces', ($loaded['logs']['checkpoint']['tip_seq'] ?? 0) === 7);

// ── Cleanup: marker rows, zone and proxy gone ───────────────────────────────
if ($prevLock === '') {
    delete_setting('maps_worker_lock');
} else {
    set_setting('maps_worker_lock', $prevLock);
}
$db->exec("DELETE FROM order_events WHERE ip_address = '198.51.100.7'");
$db->exec("DELETE FROM audit_log WHERE action = 'diag_probe'");
$db->exec("DELETE FROM map_zones WHERE name = 'diag-zone'");
$db->exec("DELETE FROM osm_proxies WHERE url = 'http://127.0.0.1:9/diag'");
$db->prepare('DELETE FROM log_checkpoints WHERE id > ?')->execute([$prevCpId]);

exit(T::done());
