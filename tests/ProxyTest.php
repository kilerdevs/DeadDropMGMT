<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Proxy anonymity gate ──────────────────────────────────────────────────────
// proxy_filter_anonymity() is the single decision point that decides which
// working proxies may carry OSM traffic. It used to be inline in the discovery
// routine, where an array-vs-false comparison made the whole anonymity round
// silently never run (found by PHPStan, not by tests — this suite exists so
// the next such bug needs two mistakes, not zero).

// Shape helpers matching the discovery routine's data structures.
$mkWorking = static fn(string $url, int $ms = 100): array => [
    ['url' => $url, 'latency_ms' => $ms, 'source' => 'test'],
];
// candidates: url => ['rated' => bool, 'source' => string]
$cRated   = static fn(): array => ['rated' => true,  'source' => 'curated'];
$cUnrated = static fn(): array => ['rated' => false, 'source' => 'public-list'];

$httpUnrated = 'http://unrated.example:8080';
$httpRated   = 'http://rated.example:8080';
$httpsUnrated = 'https://unrated.example:8443';

// 1 ── Rated proxies always pass, regardless of judge outcomes.
$working  = $mkWorking($httpRated);
$cands    = [$httpRated => $cRated()];
T::eq('rated HTTP proxy kept (judge reachable, anonymous)', 1,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpRated => false])));

// 2 ── HTTPS proxies are opaque to the filter chain — kept even unrated+unjudged.
$working  = $mkWorking($httpsUnrated);
$cands    = [$httpsUnrated => $cUnrated()];
T::eq('unrated HTTPS proxy kept without judging', 1,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [])));

// 3 ── Unrated HTTP: kept only when the judge says anonymous.
$working = $mkWorking($httpUnrated);
$cands   = [$httpUnrated => $cUnrated()];
T::eq('unrated HTTP proxy judged anonymous → kept', 1,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpUnrated => true])));
T::eq('unrated HTTP proxy judged leaking → dropped', 0,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpUnrated => false])));
T::eq('unrated HTTP proxy never judged → dropped', 0,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [])));
// Fail-closed default: a working entry with NO candidate record at all
// (missing key, not rated:false) and no judge verdict must be dropped.
// (With a positive verdict it is kept per the judged-anonymous row above.)
T::eq('proxy missing from candidates, unjustified → dropped', 0,
    count(proxy_filter_anonymity($working, [], '203.0.113.9', [])));

// 4 ── Judge unreachable (no public IP): EVERY unrated HTTP proxy is dropped —
// fail closed is the whole point of the round. Rated and HTTPS survive.
$working = array_merge(
    $mkWorking($httpUnrated),
    $mkWorking($httpRated),
    $mkWorking($httpsUnrated)
);
$cands = [
    $httpUnrated  => $cUnrated(),
    $httpRated    => $cRated(),
    $httpsUnrated => $cUnrated(),
];
$kept = proxy_filter_anonymity($working, $cands, null, []);
T::eq('no public IP: unrated HTTP dropped, everything else kept', 2, count($kept));
T::ok('survivors are exactly rated + https',
    !in_array($httpUnrated, array_column($kept, 'url'), true));

// 5 ── Mixed pool keeps order-independent correctness and latency sort input.
$working = array_merge(
    $mkWorking($httpUnrated, 50),
    $mkWorking($httpsUnrated, 30),
    $mkWorking($httpRated, 40)
);
$cands = [
    $httpUnrated  => $cUnrated(),
    $httpsUnrated => $cUnrated(),
    $httpRated    => $cRated(),
];
$kept = proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpUnrated => true]);
T::eq('mixed pool: all three survive with positive verdicts', 3, count($kept));
$kept = proxy_filter_anonymity($working, $cands, '203.0.113.9', []);
T::eq('mixed pool: only rated + https survive without verdicts', 2, count($kept));

// ── Reverse-geocode place labels (lat/lng hidden from owners by policy) ───
T::eq('country + state join', 'Poland, Masovian Voivodeship',
    osm_place_label(['country' => 'Poland', 'state' => 'Masovian Voivodeship', 'city' => 'Warsaw']));
T::eq('country alone when no state', 'Poland', osm_place_label(['country' => 'Poland']));
T::eq('state alone when no country', 'Mazowieckie', osm_place_label(['state' => 'Mazowieckie']));
T::eq('nothing known is empty', '', osm_place_label(['city' => 'Nowhere']));
T::eq('non-array is empty', '', osm_place_label(null));
T::eq('blank parts ignored', 'Poland', osm_place_label(['country' => ' Poland ', 'state' => '  ']));

// Reverse URL builder (pure half of the lookup — the fetch itself must never
// run in unit suites).
T::eq('valid point builds the reverse URL',
    'https://nominatim.openstreetmap.org/reverse?lat=52.2297000&lon=21.0122000&format=json&accept-language=en',
    osm_reverse_url(52.2297, 21.0122));
T::eq('latitude out of range is null', null, osm_reverse_url(91.0, 21.0));
T::eq('longitude out of range is null', null, osm_reverse_url(52.0, 181.0));
T::eq('non-finite is null', null, osm_reverse_url(NAN, 21.0));
T::ok('lookup rejects geography without network', osm_reverse_lookup(91.0, 21.0) === null);

// Reverse answer decoding (pure — no network in any arm).
T::eq('parse keeps the address', ['country' => 'Poland', 'state' => 'X'],
    osm_reverse_parse('{"address":{"country":"Poland","state":"X"}}'));
T::eq('parse without address is null', null, osm_reverse_parse('{"error":"nope"}'));
T::eq('parse garbage is null', null, osm_reverse_parse('not json'));

// Fail-closed lookup: routing enabled with an empty pool answers null
// without touching the network (covers the fetch-failed arm). Pool and
// setting restored below — later suites inherit sanity.
$db = get_db();
$prevProxies = $db->query('SELECT url, source, last_status, latency_ms, last_checked FROM osm_proxies')->fetchAll();
$prevRouting = get_setting('osm_proxy_enabled', '0');
set_setting('osm_proxy_enabled', '1');
$db->prepare('DELETE FROM osm_proxies')->execute();
T::ok('lookup fails closed on empty pool', osm_reverse_lookup(52.2297, 21.0122) === null);
$db->prepare('DELETE FROM osm_proxies')->execute();
$pxIns = $db->prepare(
    'INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
     VALUES (?, ?, ?, ?, ?)'
);
foreach ($prevProxies as $px) {
    $pxIns->execute([$px['url'], $px['source'], $px['last_status'], $px['latency_ms'], $px['last_checked']]);
}
set_setting('osm_proxy_enabled', $prevRouting);

// Tiny coordinates must not turn into scientific notation in the URL.
T::ok('tiny coordinates stay fixed-point',
    str_contains((string)osm_reverse_url(0.00001, -0.00002), 'lat=0.0000100&lon=-0.0000200'));

// Only a genuine PNG counts as a tile.
T::ok('png signature accepted', osm_is_png("\x89PNG\r\n\x1a\n" . 'rest'));
T::ok('html rejected as tile', !osm_is_png('<html>proxy landing page</html>'));
T::ok('empty rejected as tile', !osm_is_png(''));

// Tile cache upkeep: aged entries and everything past the byte cap go,
// oldest first; a fresh small cache is left alone.
$tc = sys_get_temp_dir() . '/ddmgmt_tilecache_' . getmypid();
@mkdir("$tc/3/1", 0770, true);
file_put_contents("$tc/3/1/old.png", str_repeat('o', 100));
touch("$tc/3/1/old.png", time() - 20 * 86400);
file_put_contents("$tc/3/1/a.png", str_repeat('a', 400));
touch("$tc/3/1/a.png", time() - 300);
file_put_contents("$tc/3/1/b.png", str_repeat('b', 400));
touch("$tc/3/1/b.png", time() - 200);
file_put_contents("$tc/3/1/c.png", str_repeat('c', 400));
touch("$tc/3/1/c.png", time() - 100);
T::eq('expired tile removed, in-cap cache untouched', 1, osm_tile_cache_prune($tc, 100000, 7 * 86400));
T::ok('fresh tiles survive an in-cap prune', is_file("$tc/3/1/a.png") && is_file("$tc/3/1/b.png") && is_file("$tc/3/1/c.png"));
T::eq('over-cap removes the oldest first', 1, osm_tile_cache_prune($tc, 900, 7 * 86400));
T::ok('oldest tile went, newest stayed', !is_file("$tc/3/1/a.png") && is_file("$tc/3/1/b.png") && is_file("$tc/3/1/c.png"));
T::eq('missing cache dir is a no-op', 0, osm_tile_cache_prune($tc . '/nope'));
foreach (glob("$tc/3/1/*") ?: [] as $f) { @unlink($f); }
@rmdir("$tc/3/1"); @rmdir("$tc/3"); @rmdir($tc);

// SOCKS builders are total: over-long inputs clamp to honest framing
// instead of throwing ValueError on some builds (chr()/pack() of an
// out-of-range length) or wrapping it silently on others. A 300-byte
// credential cannot authenticate either way — it fails at auth/connect,
// never as a fatal in the proxy path.
$longUser = str_repeat('u', 300);
T::eq('socks5 auth clamps over-long credentials honestly',
    "\x01" . chr(255) . str_repeat('u', 255) . chr(1) . 'p',
    proxy_socks5_auth($longUser, 'p'));
T::eq('socks5 connect clamps an over-long domain',
    "\x05\x01\x00\x03" . chr(255) . str_repeat('h', 255) . pack('n', 80),
    proxy_socks5_connect(str_repeat('h', 300), 80));
T::eq('socks5 connect folds an over-wide port like tolerant pack()',
    "\x05\x01\x00\x03" . chr(3) . 'hst' . pack('n', 70000 & 0xFFFF),
    proxy_socks5_connect('hst', 70000));
T::eq('socks4 keeps literal IPv4 inline',
    "\x04\x01" . pack('n', 80) . inet_pton('1.2.3.4') . "u\x00",
    proxy_socks4_connect('1.2.3.4', 80, 'u'));
T::eq('socks4 routes NUL hosts to the 4a hostname form',
    "\x04\x01" . pack('n', 80) . "\x00\x00\x00\xff" . "u\x00" . "1.2.3\0.4" . "\x00",
    proxy_socks4_connect("1.2.3\0.4", 80, 'u'));

// Proxy URL validation: every arm must reject, never admit a dud.
// (A weakened arm routes traffic at a proxy that cannot serve it.)
T::ok('port zero rejected', proxy_parse('http://example.com:0/') === null);
T::ok('over-long user rejected', proxy_parse('http://' . str_repeat('u', 256) . '@example.com:80/') === null);
T::ok('over-long password rejected', proxy_parse('http://user:' . str_repeat('p', 256) . '@example.com:80/') === null);
T::ok('sane proxy accepted', proxy_parse('http://10.0.0.1:8080/') !== null);
// Absolute target paths survive parsing untouched (a flipped comparison
// would double-slash every absolute path into a broken request line).
$absTgt = proxy_parse_target('https://tile.example.org/13/4051/2749.png');
T::eq('absolute path kept', '/13/4051/2749.png', is_array($absTgt) ? ($absTgt['path'] ?? null) : null);

// Host header default-port elision: 443 on TLS and 80 on plain travel bare,
// anything else explicit (a dropped :8443 routes to the wrong vhost).
$hh = static fn(string $dial, int $port, bool $tls): string =>
    proxy_host_header(['host' => $dial, 'dial' => $dial, 'port' => $port, 'tls' => $tls]);
T::eq('tls 443 bare', 'example.com', $hh('example.com', 443, true));
T::eq('plain 80 bare', 'example.com', $hh('example.com', 80, false));
T::eq('tls 8443 explicit', 'example.com:8443', $hh('example.com', 8443, true));
T::eq('plain 8080 explicit', 'example.com:8080', $hh('example.com', 8080, false));
T::eq('tls 80 explicit', 'example.com:80', $hh('example.com', 80, true));
// cURL proxy option as data: direct stays direct, proxied stays proxied.
// (A dead branch here leaks traffic past the pool or breaks direct fetches.)
T::eq('direct yields no proxy opt', [], proxy_curl_opts(null));
T::eq('proxy yields its normalized URL',
    [CURLOPT_PROXY => 'socks5h://10.0.0.1:1080'], proxy_curl_opts('socks5://10.0.0.1:1080'));

// Seed-attempt boundary: the MAX-th failure switches routing off instead of
// granting another discovery pass.
set_setting('proxy_seed_failures', (string)(OSM_PROXY_SEED_MAX_FAILURES - 1));
T::ok('one try left is granted', osm_proxy_seed_attempt() === true);
T::eq('...and counted', (string)OSM_PROXY_SEED_MAX_FAILURES, get_setting('proxy_seed_failures', ''));
set_setting('proxy_seed_failures', (string)OSM_PROXY_SEED_MAX_FAILURES);
T::ok('tries used up: no more discovery', osm_proxy_seed_attempt() === false);
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_seed_failures', 'osm_proxy_auto_off')");
$db->exec("DELETE FROM audit_log WHERE action = 'proxy_auto_off'");

// Reverse-geocode cache hit without network: a fresh cache file answers,
// the lookup never runs. (An assoc/object mix-up would sail past the hit
// and either leak a live Nominatim request or answer null.)
$geoUid = 999999991;
$geoDir = dirname(__DIR__) . '/cache/geocode/' . $geoUid;
@mkdir($geoDir, 0770, true);
$geoKey = sprintf('%.2F_%.2F', round(12.3456, 2), round(65.4321, 2));
file_put_contents($geoDir . '/' . $geoKey . '.json', '{"country":"Testland","state":"Provinz"}');
T::eq('fresh cache answers without lookup', ['country' => 'Testland', 'state' => 'Provinz'],
    osm_reverse_cached($geoUid, 12.3456, 65.4321));
@unlink($geoDir . '/' . $geoKey . '.json');
@rmdir($geoDir);

// Fail-closed fetch with a seeded-but-dead pool: the attempt is recorded
// (attempts=1), not skipped (an inverted pool check would return the same
// false with attempts=0 and hide that routing is broken).
osm_pool_circuit_clear();
set_setting('osm_proxy_enabled', '1');
$db->prepare('DELETE FROM osm_proxies')->execute();
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked) VALUES ('http://127.0.0.1:9', 'manual', 'new', NULL, NULL)")->execute();
T::ok('dead pool still fails', osm_fetch('http://127.0.0.1:9/nope', 512) === false);
$via = osm_last_via_stage();
T::eq('...but the attempt is recorded', 1, is_array($via) ? ($via['attempts'] ?? null) : null);
T::eq('...and flagged failed', true, is_array($via) ? ($via['failed'] ?? null) : null);
// The wholesale failure trips the breaker: the next request against the
// same pool short-circuits with zero attempts, still marked failed.
T::ok('tripped pool still fails', osm_fetch('http://127.0.0.1:9/nope', 512) === false);
$via2 = osm_last_via_stage();
T::eq('...with zero attempts', 0, is_array($via2) ? ($via2['attempts'] ?? null) : null);
T::eq('...marked failed', true, is_array($via2) ? ($via2['failed'] ?? null) : null);
osm_last_via_stage(null);
// An empty pool trips nothing: the fail-closed refusal is not a pool
// failure (an always-trip mutant would wedge fresh installs for a minute).
$db->prepare('DELETE FROM osm_proxies')->execute();
$db->exec("DELETE FROM settings WHERE key_name IN ('pool_down_until', 'pool_down_fp')");
settings_invalidate();
T::ok('empty pool still fails', osm_fetch('http://127.0.0.1:9/nope', 512) === false);
T::eq('...without tripping the breaker', '0', get_setting('pool_down_until', '0'));
osm_last_via_stage(null);
$db->prepare('DELETE FROM osm_proxies')->execute();
osm_pool_circuit_clear();
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_urgent', 'proxy_heal_last', 'pool_down_until', 'pool_down_fp')");
set_setting('osm_proxy_enabled', $prevRouting);

// SOCKS5 unacceptable-method aborts: the client sends the greeting and then
// nothing — specifically no CONNECT to a proxy that refused to serve it.
// The refusal is pre-written: bytes in the socket buffer wait until the
// client reads, so no concurrency is needed to stage it.
$greet = proxy_socks5_greet('');
$socksPair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
if ($socksPair === false) {
    T::ok('socket pair unavailable here — socks abort skipped', true);
} else {
    [$socksCli, $socksSrv] = $socksPair;
    @fwrite($socksSrv, "\x05\xFF"); // "no acceptable methods"
    $socksPx = ['scheme' => 'socks5', 'user' => '', 'pass' => ''];
    $socksTgt = ['host' => 'example.com', 'port' => 80, 'tls' => false, 'dial' => 'example.com'];
    $socksOpened = proxy_sock_open_from($socksCli, $socksPx, $socksTgt, microtime(true) + 2.0);
    // Drain everything the client sent: the greeting, and nothing after.
    stream_set_blocking($socksSrv, false);
    $socksSent = '';
    $socksT0 = microtime(true);
    while (microtime(true) - $socksT0 < 0.5) {
        $chunk = @fread($socksSrv, 8192);
        if (is_string($chunk) && $chunk !== '') {
            $socksSent .= $chunk;
        } else {
            usleep(10000);
        }
    }
    T::ok('unacceptable auth method aborts the handshake', $socksOpened === null);
    T::eq('...sending the greeting and nothing after', $greet, $socksSent);
    fclose($socksCli);
    fclose($socksSrv);
}

// Round-1 probe verdicts: 2xx under 3 s works; anything else does not.
// (A weakened arm would feed dead proxies to the anonymity round or starve
// live ones out of the pool.)
$wCands = ['http://a.test:80' => ['source' => 's1'], 'http://b.test:80' => ['source' => 's2']];
$wRes = ['http://a.test:80' => [200, 100], 'http://b.test:80' => [500, 100]];
T::eq('only the 2xx verdict works', ['http://a.test:80'],
    array_keys(proxy_filter_working($wRes, $wCands)));
$wResSlow = ['http://a.test:80' => [200, 3000]];
T::eq('3 s is too slow', [], proxy_filter_working($wResSlow, $wCands));
$wResEdge = ['http://a.test:80' => [199, 100], 'http://b.test:80' => [300, 100]];
T::eq('off-2xx edges fail', [], proxy_filter_working($wResEdge, $wCands));

// Response acceptance: 2xx with a body inside the cap; the cap itself fits.
T::ok('exact-cap body accepted', osm_fetch_body_ok(200, str_repeat('x', 64), 64));
T::ok('over-cap body refused', !osm_fetch_body_ok(200, str_repeat('x', 65), 64));
T::ok('off-2xx refused', !osm_fetch_body_ok(404, 'x', 64));
T::ok('non-string refused', !osm_fetch_body_ok(200, false, 64));

// Healer lock: a fresh lock holds, a stale one is stealable.
$db->exec("DELETE FROM settings WHERE key_name = 'proxy_heal_lock'");
$db->prepare("INSERT INTO settings (key_name, value, label) VALUES ('proxy_heal_lock', ?, '')")
    ->execute([json_encode(['by' => 'other:1', 'at' => time()])]);
T::ok('fresh lock is held', osm_proxy_heal_lock() === false);
$db->prepare("UPDATE settings SET value = ? WHERE key_name = 'proxy_heal_lock'")
    ->execute([json_encode(['by' => 'dead:1', 'at' => time() - OSM_PROXY_HEAL_LOCK_STALL - 1])]);
T::ok('stale lock is stolen', osm_proxy_heal_lock() === true);
$db->exec("DELETE FROM settings WHERE key_name = 'proxy_heal_lock'");

// Mark dedup: an unchanged fresh row is not rewritten (last_checked stays).
$db->prepare('DELETE FROM osm_proxies')->execute();
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked) VALUES ('http://127.0.0.1:9', 'manual', 'fail', 12, DATE_SUB(NOW(), INTERVAL 30 SECOND))")->execute();
$markId = (int)$db->lastInsertId();
$markBefore = $db->query("SELECT last_checked FROM osm_proxies WHERE id = $markId")->fetchColumn();
$markPrev = ['last_status' => 'fail', 'latency_ms' => 12, 'last_checked' => $markBefore];
osm_proxy_mark($markId, false, 12, $markPrev);
T::eq('unchanged fresh row not rewritten', $markBefore,
    $db->query("SELECT last_checked FROM osm_proxies WHERE id = $markId")->fetchColumn());
osm_proxy_mark($markId, true, 12, $markPrev);
T::ok('status flip writes through', $db->query("SELECT last_status FROM osm_proxies WHERE id = $markId")->fetchColumn() === 'ok');
$db->prepare('DELETE FROM osm_proxies')->execute();

// Stale-pool revalidation against a refused host: every entry probes false,
// and the verdict map (not null) comes back.
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked) VALUES ('http://127.0.0.1:9', 'manual', 'fail', NULL, NULL)")->execute();
$reval = osm_proxy_revalidate_stale(3, 7, 'http://127.0.0.1:9/tile.png');
T::eq('refused host revalidates to all-false', ['http://127.0.0.1:9' => false], $reval);
$db->prepare('DELETE FROM osm_proxies')->execute();

// Empty discovery is reported, not silently absorbed: the heal result names
// it and the failure counter moves. Reset first — earlier suites in the run
// may have left their own heal counters behind.
$db->exec("DELETE FROM osm_proxies");
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_checked', 'proxy_heal_urgent', 'proxy_seed_failures', 'osm_proxy_auto_off')");
$db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");
settings_invalidate();
set_setting('osm_proxy_enabled', '1');
$healEmpty = osm_proxy_heal(static fn(): array => [], null);
T::eq('empty discovery reported', 'no proxies found', $healEmpty['skipped'] ?? null);
T::eq('...and counted', '1', get_setting('proxy_seed_failures', ''));
// Routing off leaves the pool alone (a dead routing check would seed and
// count behind the owner's back).
set_setting('osm_proxy_enabled', '0');
$healOff = osm_proxy_heal(static fn(): array => [], null);
T::eq('routing off is left alone', 'routing disabled', $healOff['skipped'] ?? null);
set_setting('osm_proxy_enabled', '1');
// One swap is counted once (a counter starting at one would report phantom
// replacements and audit them). Reset first — only the seeded dead row may
// be in the pool.
$db->exec("DELETE FROM osm_proxies");
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_urgent', 'proxy_seed_failures', 'osm_proxy_auto_off')");
$db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");
settings_invalidate();
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, last_checked) VALUES ('http://10.0.0.1:80', 'proxifly', 'fail', NOW())")->execute();
$healSwap = osm_proxy_heal(
    static fn(): array => [['url' => 'http://10.9.9.1:80', 'latency_ms' => 300, 'source' => 'proxifly']],
    static fn(array $u): array => array_fill_keys($u, [0, 0]));
T::eq('one swap counted once', 1, $healSwap['replaced'] ?? null);
$db->exec("DELETE FROM osm_proxies");
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_checked', 'proxy_heal_urgent', 'proxy_seed_failures', 'osm_proxy_auto_off')");
$db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");

// Expected body length from headers: numeric lengths honoured, anything
// else reads until close (a weakened arm would truncate garbage-length
// bodies to empty).
T::eq('numeric length honoured', 128, proxy_body_want(['content-length' => '128']));
T::eq('garbage length reads until close', null, proxy_body_want(['content-length' => 'abc']));
T::eq('missing length reads until close', null, proxy_body_want([]));

// Heal cooldown edge: the window must fully pass — the edge itself still
// cools down (a live clock can never pin this, exact values can).
T::ok('fresh run cools down', osm_heal_cooled_down(1000, 1000 + 3600, 3600));
T::ok('edge still cooling', !osm_heal_cooled_down(1000, 1000 + 3599, 3600));
T::ok('zero window always due', osm_heal_cooled_down(1000, 1000, 0));

// Curl-less transport answers refused hosts with the code-0 sentinel (forced
// through the override seam — the suite never depends on the local build).
host_override(['curl' => false]);
try {
    [$streamBody, $streamErr] = pmtiles_range_stream('http://127.0.0.1:9/x', 0, 10, null, 5);
    T::eq('streams refusal fails as data', [null, 'request failed'], [$streamBody, $streamErr]);
} finally {
    host_override(null, true);
}

// SOCKS4 granted handshake completes: the client sends the request and the
// socket comes back open (a dropped write-check would abort here instead).
$socks4Pair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
if ($socks4Pair === false) {
    T::ok('socket pair unavailable here — socks4 grant skipped', true);
} else {
    [$socks4Cli, $socks4Srv] = $socks4Pair;
    @fwrite($socks4Srv, "\x00\x5a" . str_repeat("\x00", 6)); // request granted
    $socks4Px = ['scheme' => 'socks4', 'user' => 'u', 'pass' => ''];
    $socks4Tgt = ['host' => '1.2.3.4', 'port' => 80, 'tls' => false, 'dial' => '1.2.3.4'];
    $socks4Opened = proxy_sock_open_from($socks4Cli, $socks4Px, $socks4Tgt, microtime(true) + 2.0);
    T::ok('granted socks4 handshake opens the socket', is_array($socks4Opened));
    fclose($socks4Cli);
    fclose($socks4Srv);
}

// TLS enablement fails against a plaintext peer (a flipped enable flag
// would report success without handshaking — and then send secrets in the
// clear believing the channel is encrypted).
$tlsPair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
if ($tlsPair === false) {
    T::ok('socket pair unavailable here — TLS enable skipped', true);
} else {
    T::ok('plaintext peer fails TLS enable', proxy_enable_tls($tlsPair[0], 2) === false);
    fclose($tlsPair[0]);
    fclose($tlsPair[1]);
}

// Proxifly list bodies: socks always, plain HTTP only anonymous-or-better,
// empties and address-less entries never become candidates.
$pxList = json_encode([
    ['protocol' => 'socks5', 'anonymity' => 'transparent', 'ip' => '10.0.0.1', 'port' => '1080'],
    ['protocol' => 'http', 'anonymity' => 'anonymous', 'ip' => '10.0.0.2', 'port' => '8080'],
    ['protocol' => 'http', 'anonymity' => 'transparent', 'ip' => '10.0.0.3', 'port' => '8080'],
    ['protocol' => '', 'anonymity' => 'elite', 'ip' => '10.0.0.4', 'port' => '8080'],
    ['protocol' => 'http', 'anonymity' => 'elite', 'ip' => '', 'port' => '8080'],
    'garbage-entry',
]);
T::eq('proxifly gate keeps socks + anonymous http',
    ['socks5://10.0.0.1:1080', 'http://10.0.0.2:8080'], proxy_parse_proxifly_list((string)$pxList));
T::eq('garbage body yields nothing', [], proxy_parse_proxifly_list('not json'));

// Discovery default probes a full round (a zeroed default would silently
// test nothing on the button path).
T::eq('discovery default tests hundreds', 400,
    (new ReflectionFunction('proxy_discover'))->getParameters()[0]->getDefaultValue());

// Socket writes are all-or-nothing before the deadline (a flipped readiness
// check would report failure on a writable socket and leak half-frames).
$writePair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
if ($writePair === false) {
    T::ok('socket pair unavailable here — write-all skipped', true);
} else {
    [$writeCli, $writeSrv] = $writePair;
    T::ok('writable socket writes', proxy_write_all($writeCli, 'hello', microtime(true) + 2.0));
    stream_set_blocking($writeSrv, false);
    $writeGot = '';
    $writeT0 = microtime(true);
    while (microtime(true) - $writeT0 < 0.5 && $writeGot === '') {
        $chunk = @fread($writeSrv, 8192);
        if (is_string($chunk) && $chunk !== '') {
            $writeGot .= $chunk;
        } else {
            usleep(10000);
        }
    }
    T::eq('...the bytes arrive intact', 'hello', $writeGot);
    fclose($writeCli);
    fclose($writeSrv);
}

// Heal recovery: a dead entry that answers the re-probe is kept and counted,
// not swapped out from under a live proxy.
$db->exec("DELETE FROM osm_proxies");
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_urgent', 'proxy_seed_failures', 'osm_proxy_auto_off')");
$db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");
settings_invalidate();
set_setting('osm_proxy_enabled', '1');
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, last_checked) VALUES ('http://10.0.0.9:80', 'proxifly', 'fail', NOW())")->execute();
$healRec = osm_proxy_heal(static fn(): array => [],
    static fn(array $u): array => array_fill_keys($u, [200, 50]));
$recUrls = array_column($db->query('SELECT url FROM osm_proxies')->fetchAll(), 'url');
T::ok('recovered proxy kept', in_array('http://10.0.0.9:80', $recUrls, true));
T::eq('...and counted', 1, $healRec['recovered'] ?? null);
$db->exec("DELETE FROM osm_proxies");
$db->exec("DELETE FROM settings WHERE key_name IN ('proxy_heal_lock', 'proxy_heal_last', 'proxy_heal_urgent', 'proxy_seed_failures', 'osm_proxy_auto_off')");
$db->exec("DELETE FROM audit_log WHERE action IN ('proxy_seed', 'proxy_replace', 'proxy_auto_off')");

// Revalidation default leaves fresh pools alone (a zeroed default would
// re-probe the whole pool on every cleanup run).
$db->prepare("INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked) VALUES ('http://127.0.0.1:9', 'manual', 'ok', 5, DATE_SUB(NOW(), INTERVAL 30 SECOND))")->execute();
T::eq('fresh pool needs no revalidation', [], osm_proxy_revalidate_stale());
$db->prepare('DELETE FROM osm_proxies')->execute();

// Geocode prune on a missing dir removes nothing (a flipped base would
// report phantom removals).
T::eq('missing geocode cache prunes nothing', 0,
    osm_geocode_cache_prune(sys_get_temp_dir() . '/ddmgmt_no_such_geocode_' . getmypid()));

// Opener dispatch: an http proxy to a plain target connects (kernel backlog
// completes the handshake with no accept needed); an exhausted deadline
// refuses before dialing at all.
$listen = @stream_socket_server('tcp://127.0.0.1:0', $listenErrno, $listenErrstr);
if ($listen === false) {
    T::ok('loopback listener unavailable here — opener dispatch skipped', true);
} else {
    $listenPort = (int)explode(':', (string)stream_socket_get_name($listen, false))[1];
    $openTgt = ['host' => '127.0.0.1', 'dial' => '127.0.0.1', 'port' => $listenPort, 'tls' => false, 'path' => '/'];
    $openPx = ['scheme' => 'http', 'host' => '127.0.0.1', 'dial' => '127.0.0.1', 'port' => $listenPort, 'user' => '', 'pass' => ''];
    $openedDirect = proxy_sock_open(null, $openTgt, microtime(true) + 2.0, null);
    T::ok('http opener connects', is_array($openedDirect));
    if (is_array($openedDirect)) {
        fclose($openedDirect[0]);
    }
    $refusedPast = proxy_sock_open(null, $openTgt, microtime(true) - 1.0, null);
    T::ok('exhausted deadline refuses before dialing', $refusedPast === null);
    fclose($listen);
}

exit(T::done());
