<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Free shared hosting: no Docker, no cron, no exec, no CLI PHP, no env vars ─
// Every feature that leans on one of those must degrade on its own instead of
// breaking. This suite pins the degradations: switches settable from
// config.php constants, capability answers, proxy upkeep that runs inline when
// no detached job is possible, routing that cannot wedge a host that can never
// build a pool, and zone downloads refused up front where they cannot work.

$db = get_db();
$restore = ['osm_proxy_enabled' => get_setting('osm_proxy_enabled', '1')];
$teardown = t_teardown(static function () use ($restore): void {
    $db = get_db();
    $db->exec('DELETE FROM osm_proxies');
    $db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_checked', 'proxy_seed_failures', 'osm_proxy_auto_off')");
    $db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");
    foreach ($restore as $k => $v) { set_setting($k, $v); }
    host_override(null, true);
    osm_proxy_heal_spawner(static fn(): bool => false);
});
$reset = static function () use ($db): void {
    $db->exec('DELETE FROM osm_proxies');
    $db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_checked', 'proxy_seed_failures', 'osm_proxy_auto_off')");
    $db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");
    $c = &_settings_store(); $c = null;
    set_setting('osm_proxy_enabled', '1');
    host_override(null, true);
};
$fresh = static fn(string $u): array => ['url' => $u, 'latency_ms' => 300, 'source' => 'proxifly'];
$neverDiscover = static function (): array { throw new RuntimeException('discovery must not run'); };
$noHost = ['exec' => false, 'proc_open' => false, 'curl' => true, 'linux' => true, 'cli' => null];

// ── switches: environment, then a config.php constant, then the default ──────
T::ok('unset flag takes the default (on)', host_flag('DDMGMT_T_UNSET', true) === true);
T::ok('unset flag takes the default (off)', host_flag('DDMGMT_T_UNSET', false) === false);
putenv('DDMGMT_T_ENV=0');
T::ok('env 0 is off', host_flag('DDMGMT_T_ENV', true) === false);
foreach (['false', 'off', 'no', 'OFF'] as $v) {
    putenv("DDMGMT_T_ENV=$v");
    T::ok("env $v is off", host_flag('DDMGMT_T_ENV', true) === false);
}
putenv('DDMGMT_T_ENV=1');
T::ok('env 1 is on', host_flag('DDMGMT_T_ENV', false) === true);
putenv('DDMGMT_T_ENV');
define('DDMGMT_T_CONST_OFF', false);
define('DDMGMT_T_CONST_ON', true);
T::ok('a config.php constant set to false turns the flag off (shared hosting)', host_flag('DDMGMT_T_CONST_OFF', true) === false);
T::ok('a config.php constant set to true turns it on', host_flag('DDMGMT_T_CONST_ON', false) === true);
putenv('DDMGMT_T_CONST_OFF=1');
T::ok('the environment wins over the constant', host_flag('DDMGMT_T_CONST_OFF', false) === true);
putenv('DDMGMT_T_CONST_OFF');

// ── a host with no exec, no CLI PHP ───────────────────────────────────────────
host_override($noHost);
T::ok('no exec/CLI: cannot detach', host_can_detach() === false);
T::ok('no exec/CLI: zone downloads unsupported', maps_downloads_supported() === false);
$caps = array_column(host_capabilities(), 'status', 'id');
T::eq('capabilities: exec unavailable', 'unavailable', $caps['exec']);
T::eq('capabilities: jobs limited (they run inline)', 'limited', $caps['jobs']);
T::eq('capabilities: zone downloads unavailable', 'unavailable', $caps['zones']);
T::eq('capabilities: cURL still fine', 'ok', $caps['curl']);
T::ok('every capability row has an id, a valid status and a note',
      count(host_capabilities()) === 6
      && array_reduce(host_capabilities(), static fn(bool $c, array $r): bool => $c
          && in_array($r['status'], ['ok', 'limited', 'unavailable'], true) && is_string($r['note']), true));

host_override(['exec' => true, 'proc_open' => true, 'curl' => true, 'linux' => true, 'cli' => '/usr/bin/php']);
T::ok('exec + CLI on Linux: can detach', host_can_detach() === true);
host_override(['linux' => false]);
T::ok('not Linux: cannot detach', host_can_detach() === false);
host_override(null, true);

// ── no cURL: proxy routing cannot be honoured, so it is not applied ──────────
$reset();
set_setting('osm_proxy_enabled', '1');
host_override(['curl' => false]);
T::ok('no cURL: routing is not applied (OSM requests go direct, not fail closed)', osm_proxy_enabled() === false);
host_override(['curl' => true]);
T::ok('with cURL the same setting applies', osm_proxy_enabled() === true);
host_override(null, true);

// ── proxy upkeep with no way to detach: inline, after the response ───────────
$reset();
host_override($noHost);
osm_proxy_heal_spawner(null, true); // uninstall the suite's no-op stand-in: the real capability check decides
T::ok('no exec/CLI: the kick spawns nothing', osm_proxy_heal_kick() === false);
T::eq('...and does not burn the cooldown the inline pass needs', '', get_setting('proxy_heal_last', ''));
osm_proxy_heal_pseudo_cron(fn() => [$fresh('http://10.9.9.1:80'), $fresh('http://10.9.9.2:80')], $neverDiscover);
T::eq('the pseudo-cron slot seeds the first pool inline', 2, (int)$db->query('SELECT COUNT(*) FROM osm_proxies')->fetchColumn());
T::ok('the inline pass stamps the cooldown', (int)get_setting('proxy_heal_last', '0') > time() - 5);
$again = 0;
osm_proxy_heal_pseudo_cron(function () use (&$again): array { $again++; return []; }, $neverDiscover);
T::eq('inside the cooldown nothing runs again', 0, $again);
osm_proxy_heal_spawner(static fn(): bool => false);

// a healthy pool costs one query per cooldown, not one per request
$reset();
$db->exec("INSERT INTO osm_proxies (url, source, last_status, last_checked) VALUES ('http://10.0.0.1:80', 'proxifly', 'ok', NOW())");
T::ok('healthy pool: nothing pending', osm_proxy_heal_pending(true) === false);
T::ok('...and the "checked" stamp is written', (int)get_setting('proxy_heal_checked', '0') > time() - 5);
$db->exec("UPDATE osm_proxies SET last_status = 'fail'");
T::ok('...so a failure inside that window waits for the cooldown (throttled path)', osm_proxy_heal_pending(true) === false);
T::ok('...but a failure seen by live traffic (unthrottled path) is pending at once', osm_proxy_heal_pending(false) === true);

// ── a host that can never build a pool must not stay wedged fail-closed ──────
$reset();
osm_proxy_heal(fn() => [], null);
T::eq('first empty discovery: still routing, counted', '1', get_setting('proxy_seed_failures', ''));
T::ok('...routing still on', osm_proxy_enabled() === true);
osm_proxy_heal(fn() => [], null);
T::ok('second empty discovery: still on', osm_proxy_enabled() === true);
osm_proxy_heal(fn() => [], null);
T::ok('third empty discovery: routing switched off automatically', osm_proxy_enabled() === false);
$st = osm_proxy_auto_off_state();
T::ok('...with a recorded reason for Settings to show', is_array($st) && $st['reason'] !== '' && $st['at'] > time() - 30);
T::eq('...and an audit entry', 1, (int)$db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'proxy_auto_off'")->fetchColumn());
T::eq('...the failure counter is reset', '', get_setting('proxy_seed_failures', ''));
osm_proxy_auto_off_clear();
T::ok('the owner re-enabling clears the notice', osm_proxy_auto_off_state() === null);

// A host that kills the script mid-discovery never reaches any failure code:
// the attempt is counted before it starts, so it still runs out of tries.
$reset();
set_setting('proxy_seed_failures', '3');
$r = osm_proxy_heal($neverDiscover, null);
T::eq('tries already used up: no more discovery, routing switched off instead', 'routing switched off', $r['skipped']);
T::ok('...routing is off with a notice', osm_proxy_enabled() === false && osm_proxy_auto_off_state() !== null);
$reset();
set_setting('proxy_seed_failures', '2');
osm_proxy_heal(function () { throw new RuntimeException('killed mid-pass'); }, null);
T::eq('a pass that dies mid-discovery still counted as an attempt', '3', get_setting('proxy_seed_failures', ''));

$reset();
osm_proxy_heal(fn() => [], null);
osm_proxy_heal(fn() => [], null);
T::eq('two empty discoveries counted', '2', get_setting('proxy_seed_failures', ''));
$db->exec("DELETE FROM settings WHERE key_name = 'proxy_heal_lock'");
osm_proxy_heal(fn() => [$fresh('http://10.9.9.1:80')], null);
T::eq('a successful seeding resets the counter', '', get_setting('proxy_seed_failures', ''));
T::ok('...and routing stays on', osm_proxy_enabled() === true);

// ── static contracts that need a web request to observe ──────────────────────
$root = dirname(__DIR__);
$act = (string)file_get_contents($root . '/admin/maps_action.php');
T::eq('zone add/retry/refresh are all refused on an unsupported host', 3, substr_count($act, 'maps_downloads_supported()'));
$set = (string)file_get_contents($root . '/admin/settings.php');
T::ok('Settings lists the host capabilities', str_contains($set, 'host_capabilities()') && str_contains($set, 'host-list'));
T::ok('Settings warns about missing cURL and about the automatic switch-off',
      str_contains($set, 'admin.proxies.no_curl') && str_contains($set, 'admin.proxies.auto_off'));
T::ok('the zone Queue button is disabled where downloads cannot work', str_contains($set, "\$zones_ok ? '' : ' disabled'"));
$sav = (string)file_get_contents($root . '/admin/actions/save_setting.php');
T::ok('re-enabling routing clears the auto-off notice', str_contains($sav, 'osm_proxy_auto_off_clear()'));
$cfg = (string)file_get_contents($root . '/config.php.example');
T::ok('config.php.example documents the constant alternatives to env vars',
      str_contains($cfg, 'DDMGMT_PSEUDO_CRON') && str_contains($cfg, 'DDMGMT_PROXY_HEAL'));
$teardown();
exit(T::done());
