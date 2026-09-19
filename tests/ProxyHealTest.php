<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Self-healing proxy pool ───────────────────────────────────────────────────
// A failed discovered proxy is confirmed dead, deleted and replaced by a fresh
// one from proxy_discover() — but never on a hunch: manual entries are exempt,
// nothing is deleted without a replacement (outage safety), a recovered proxy
// is kept, one healer runs at a time, and live traffic only *kicks* a detached
// job (cooldown-limited) instead of running discovery in the request.
// Discovery and probing are injected: no network is touched here.

$db = get_db();
$restore = [
    'osm_proxy_enabled' => get_setting('osm_proxy_enabled', '0'),
];
register_shutdown_function(static function () use ($restore): void {
    $db = get_db();
    $db->exec('DELETE FROM osm_proxies');
    $db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last')");
    $db->exec("DELETE FROM audit_log WHERE action = 'proxy_replace'");
    foreach ($restore as $k => $v) { set_setting($k, $v); }
});

$reset = static function () use ($db): void {
    $db->exec('DELETE FROM osm_proxies');
    $db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last')");
    $db->exec("DELETE FROM audit_log WHERE action = 'proxy_replace'");
    // Settings are cached per process: drop what was just deleted.
    $c = &_settings_store();
    $c = null;
    set_setting('osm_proxy_enabled', '1');
};
$add = static function (string $url, string $source, string $status) use ($db): void {
    $db->prepare('INSERT INTO osm_proxies (url, source, last_status, last_checked) VALUES (?, ?, ?, NOW())')
       ->execute([$url, $source, $status]);
};
$urls = static fn(): array => array_column(
    $db->query('SELECT url FROM osm_proxies ORDER BY url')->fetchAll(), 'url'
);
$deadProbe  = static fn(array $u): array => array_fill_keys($u, [0, 0]);
$fresh = static fn(string $u, int $ms = 500): array => ['url' => $u, 'latency_ms' => $ms, 'source' => 'proxifly'];
$neverDiscover = static function (): array { throw new RuntimeException('discovery must not run'); };

// ── heal: the swap ───────────────────────────────────────────────────────────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');   // discovered + dead  → replaced
$add('http://10.0.0.2:80', 'manual',   'fail');   // owner's own        → kept
$add('http://10.0.0.3:80', 'monosans', 'ok');     // healthy            → kept
$r = osm_proxy_heal(fn() => [$fresh('http://10.9.9.1:80', 300), $fresh('http://10.0.0.3:80', 100)], $deadProbe);
T::eq('dead discovered proxy replaced', 1, $r['replaced']);
T::eq('pool after swap',
      ['http://10.0.0.2:80', 'http://10.0.0.3:80', 'http://10.9.9.1:80'], $urls());
$row = $db->query("SELECT source, last_status, latency_ms FROM osm_proxies WHERE url = 'http://10.9.9.1:80'")->fetch();
T::ok('replacement stored as ok with its measured latency and source',
      $row && $row['last_status'] === 'ok' && (int)$row['latency_ms'] === 300 && $row['source'] === 'proxifly');
T::eq('manual dead entry survives', 'fail',
      $db->query("SELECT last_status FROM osm_proxies WHERE url = 'http://10.0.0.2:80'")->fetchColumn());
T::eq('swap is audited', 1,
      (int)$db->query("SELECT COUNT(*) FROM audit_log WHERE action = 'proxy_replace'")->fetchColumn());
T::eq('lock released afterwards', 0,
      (int)$db->query("SELECT COUNT(*) FROM settings WHERE key_name = 'proxy_heal_lock'")->fetchColumn());

// ── heal: outage safety — discovery finds nothing, nothing is deleted ─────────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
$add('http://10.0.0.4:80', 'proxifly', 'fail');
$r = osm_proxy_heal(fn() => [], $deadProbe);
T::eq('no replacement found: nothing replaced', 0, $r['replaced']);
T::eq('no replacement found: pool intact', ['http://10.0.0.1:80', 'http://10.0.0.4:80'], $urls());

// ── heal: pool never shrinks (fewer fresh than dead) ─────────────────────────
$reset();
foreach (['1', '2', '3'] as $n) { $add("http://10.0.0.$n:80", 'proxifly', 'fail'); }
$r = osm_proxy_heal(fn() => [$fresh('http://10.9.9.1:80')], $deadProbe);
T::eq('one fresh replaces one of three dead', 1, $r['replaced']);
T::eq('pool size unchanged', 3, count($urls()));

// ── heal: fresh candidates already in the pool are not "replacements" ────────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
$add('http://10.0.0.2:80', 'proxifly', 'ok');
$r = osm_proxy_heal(fn() => [$fresh('http://10.0.0.2:80')], $deadProbe);
T::eq('duplicate of an existing entry is not a replacement', 0, $r['replaced']);
T::ok('dead entry kept when only duplicates were found', in_array('http://10.0.0.1:80', $urls(), true));

// ── heal: a proxy that answers the confirmation probe is kept ────────────────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
$r = osm_proxy_heal($neverDiscover, fn(array $u): array => array_fill_keys($u, [200, 120]));
T::eq('recovered proxy counted', 1, $r['recovered']);
T::eq('recovered proxy not deleted', ['http://10.0.0.1:80'], $urls());
T::eq('recovered proxy marked ok again', 'ok',
      $db->query("SELECT last_status FROM osm_proxies WHERE url = 'http://10.0.0.1:80'")->fetchColumn());

// ── heal: gates ──────────────────────────────────────────────────────────────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
set_setting('osm_proxy_enabled', '0');
$r = osm_proxy_heal($neverDiscover, $deadProbe);
T::eq('routing disabled: healer stays out', 'routing disabled', $r['skipped']);
set_setting('osm_proxy_enabled', '1');

$reset();
$add('http://10.0.0.1:80', 'proxifly', 'ok');
$r = osm_proxy_heal($neverDiscover, $deadProbe);
T::eq('healthy pool: nothing to do', 'nothing to replace', $r['skipped']);

$reset();
$add('http://10.0.0.2:80', 'manual', 'fail');
$r = osm_proxy_heal($neverDiscover, $deadProbe);
T::eq('only a manual entry failed: nothing to do', 'nothing to replace', $r['skipped']);

// ── heal: scheduled callers honour the cooldown, the kicked job does not ─────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
set_setting('proxy_heal_last', (string)time());
$r = osm_proxy_heal($neverDiscover, $deadProbe, true);
T::eq('cleanup cron inside the cooldown: skipped', 'cooldown', $r['skipped']);
$r = osm_proxy_heal(fn() => [$fresh('http://10.9.9.1:80')], $deadProbe);
T::eq('the kicked job (stamped by the kick itself) still runs', 1, $r['replaced']);
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
set_setting('proxy_heal_last', (string)(time() - OSM_PROXY_HEAL_COOLDOWN - 5));
$r = osm_proxy_heal(fn() => [$fresh('http://10.9.9.1:80')], $deadProbe, true);
T::eq('cleanup cron after the cooldown: runs', 1, $r['replaced']);

// ── heal: single instance ────────────────────────────────────────────────────
$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
$db->prepare("INSERT INTO settings (key_name, value, label) VALUES ('proxy_heal_lock', ?, '')")
   ->execute([json_encode(['by' => 'other', 'at' => time()])]);
$r = osm_proxy_heal($neverDiscover, $deadProbe);
T::eq('a fresh lock blocks a second healer', 'another heal is running', $r['skipped']);
T::eq('the blocked run did not delete the other holder\'s lock', 1,
      (int)$db->query("SELECT COUNT(*) FROM settings WHERE key_name = 'proxy_heal_lock'")->fetchColumn());
$db->prepare("UPDATE settings SET value = ? WHERE key_name = 'proxy_heal_lock'")
   ->execute([json_encode(['by' => 'dead-process', 'at' => time() - OSM_PROXY_HEAL_LOCK_STALL - 5])]);
$r = osm_proxy_heal(fn() => [$fresh('http://10.9.9.1:80')], $deadProbe);
T::eq('a stale lock (dead process) is stolen', 1, $r['replaced']);

// ── kick: what live traffic may start ────────────────────────────────────────
$started = 0;
osm_proxy_heal_spawner(static function () use (&$started): bool { $started++; return true; });

$reset();
$add('http://10.0.0.1:80', 'proxifly', 'ok');
T::ok('kick: healthy pool starts nothing', osm_proxy_heal_kick() === false && $started === 0);

$reset();
$add('http://10.0.0.2:80', 'manual', 'fail');
T::ok('kick: a failed manual entry starts nothing', osm_proxy_heal_kick() === false && $started === 0);

$reset();
$add('http://10.0.0.1:80', 'proxifly', 'fail');
set_setting('osm_proxy_enabled', '0');
T::ok('kick: routing disabled starts nothing', osm_proxy_heal_kick() === false && $started === 0);
set_setting('osm_proxy_enabled', '1');

T::ok('kick: failed discovered entry starts one job', osm_proxy_heal_kick() === true && $started === 1);
T::ok('kick: cooldown suppresses the next one', osm_proxy_heal_kick() === false && $started === 1);

// ── osm_fetch kicks the healer when the pool fails ───────────────────────────
$reset();
$add('http://127.0.0.1:1', 'proxifly', 'new');   // refuses connections instantly
$started = 0;
T::ok('all-dead pool: fetch still fails closed', osm_fetch('http://127.0.0.1:1/x', 1024) === false);
osm_last_via_stage(null);
T::eq('all-dead pool: fetch kicked the healer once', 1, $started);
T::eq('the failed member was marked failed', 'fail',
      $db->query("SELECT last_status FROM osm_proxies WHERE url = 'http://127.0.0.1:1'")->fetchColumn());

osm_proxy_heal_spawner(null, true);
osm_proxy_heal_spawner(static fn(): bool => false);
exit(T::done());
