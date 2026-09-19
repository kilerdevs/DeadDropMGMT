<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Self-hosted map provider: accessors, fail-back, style builder ────────────

$db = get_db();

// Snapshot shared settings (see SettingsTest): provider probes below write
// real rows and must not poison later suites.
$prevSettings = [];
foreach ($db->query('SELECT key_name, value FROM settings')->fetchAll() as $r) {
    $prevSettings[$r['key_name']] = $r['value'];
}
// The proxy-path probe below empties the shared pool — snapshot it too.
$prevProxies = $db->query('SELECT url, source, last_status, latency_ms, last_checked FROM osm_proxies')->fetchAll();

// Missing row answers the historic default (OSM path, untouched behaviour).
$db->prepare("DELETE FROM settings WHERE key_name = 'map_provider'")->execute();
$cache = &_settings_store();
$cache = null;
T::eq('missing provider defaults to osm', MAP_PROVIDER_OSM, map_provider());

set_setting('map_provider', MAP_PROVIDER_SELFHOSTED);
T::eq('selfhosted provider reads back', MAP_PROVIDER_SELFHOSTED, map_provider());

// Unknown/corrupt values fail back to OSM, never to a broken map.
set_setting('map_provider', 'tiles.example.com');
T::eq('garbage provider fails back to osm', MAP_PROVIDER_OSM, map_provider());

// Phase 1: no zones exist yet — the stub answers empty, the style carries
// no sources, pages render the map chrome + empty-state overlay.
T::eq('phase 1 has no ready zones', [], maps_ready_zones());

$empty = maps_style([]);
T::eq('empty style is v8', 8, $empty['version']);
T::eq('empty style has no sources', [], $empty['sources']);
T::eq('empty style is background-only', ['background'], array_column($empty['layers'], 'id'));

$one = maps_style([['id' => 'zone_7', 'file' => 'zone_7.pmtiles']]);
T::ok('zone source registered', isset($one['sources']['zone_7']));
T::eq('zone source is pmtiles vector',
    ['type' => 'vector', 'url' => 'pmtiles:///tiles/zone_7.pmtiles',
     'maxzoom' => MAPS_SOURCE_MAXZOOM,
     'attribution' => '© OpenStreetMap contributors'],
    $one['sources']['zone_7']);
$layerIds = array_column($one['layers'], 'id');
T::eq('layer ids are unique', count($layerIds), count(array_unique($layerIds)));
T::eq('style declares the vendored glyph endpoint', MAPS_GLYPHS_URL, $one['glyphs']);
$basemapLayers = ['earth', 'landcover', 'landuse', 'water', 'roads', 'buildings', 'boundaries', 'places', 'pois'];
$fonts = [];
$types = [];
foreach ($one['layers'] as $layer) {
    if ($layer['id'] === 'background') {
        continue;
    }
    $types[$layer['type']] = true;
    T::ok("layer {$layer['id']} binds the zone source",
        ($layer['source'] ?? '') === 'zone_7');
    T::ok("layer {$layer['id']} names a real basemap layer",
        in_array($layer['source-layer'] ?? '', $basemapLayers, true));
    T::ok("layer {$layer['id']} id carries the source suffix", str_ends_with($layer['id'], '_zone_7'));
    foreach ($layer['layout']['text-font'] ?? [] as $font) {
        $fonts[$font] = true;
    }
}
T::ok('style has geometry, dots and labels', isset($types['fill'], $types['line'], $types['circle'], $types['symbol']));
T::ok('style labels streets, places and POIs',
    in_array('road_label_zone_7', $layerIds, true)
    && in_array('place_city_zone_7', $layerIds, true)
    && in_array('poi_a_label_zone_7', $layerIds, true));
// Roads must paint over buildings, or the map turns into grey blobs.
T::ok('buildings paint under the roads',
    array_search('buildings_zone_7', $layerIds, true) < array_search('road_casing_zone_7', $layerIds, true));

// Every font a symbol layer names must ship as glyphs, or labels vanish
// silently (MapLibre only logs a 404 per range).
T::ok('style names at least one font', $fonts !== []);
foreach (array_keys($fonts) as $font) {
    foreach (['0-255', '256-511'] as $range) {
        T::ok("glyphs shipped for {$font} {$range}",
            is_file(dirname(__DIR__) . "/fonts/glyphs/{$font}/{$range}.pbf"));
    }
}

// Two zones: every zone's labels sit above every zone's geometry, so a later
// zone's ground never covers an earlier zone's street names.
$two = maps_style([
    ['id' => 'zone_1', 'file' => 'zone_1.pmtiles'],
    ['id' => 'zone_2', 'file' => 'zone_2.pmtiles'],
]);
$order = array_column($two['layers'], 'type', 'id');
$ids2 = array_keys($order);
$lastGeometry = 0;
$firstLabel = PHP_INT_MAX;
foreach ($ids2 as $i => $id) {
    if ($order[$id] === 'symbol') {
        $firstLabel = min($firstLabel, $i);
    } elseif ($id !== 'background' && $order[$id] !== 'circle') {
        $lastGeometry = max($lastGeometry, $i);
    }
}
T::ok('all geometry precedes all labels across zones', $lastGeometry < $firstLabel);
T::eq('two zones register two sources', ['zone_1', 'zone_2'], array_keys($two['sources']));

// The style endpoint json_encodes this array — it must survive the round trip.
$rt = json_decode(json_encode($one, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), true);
T::eq('style survives JSON round trip', $one, $rt);

// Pinned vendored builds (drift here means /maplibre/ was updated without
// the constants — cache-busting and notices depend on them).
T::ok('maplibre version pinned', MAPLIBRE_VERSION !== '');
T::ok('pmtiles js version pinned', PMTILES_JS_VERSION !== '');

// ── Phase 2: bbox, progress, overlap, errors, zones, worker ────────────────

[$bok, $berr] = maps_validate_bbox(20.85, 52.05, 21.30, 52.40);
T::ok('valid bbox passes', $bok);
T::eq('lon range code', 'code:lon_range', maps_validate_bbox(20.85, 52.05, 181.0, 52.40)[1]);
T::eq('lat range code', 'code:lat_range', maps_validate_bbox(20.85, -86.0, 21.30, 52.40)[1]);
T::eq('unordered code', 'code:unordered', maps_validate_bbox(21.30, 52.05, 20.85, 52.40)[1]);
T::eq('tiny code', 'code:tiny', maps_validate_bbox(21.0, 52.0, 21.00001, 52.00001)[1]);

// Real CLI lines captured in the P0 spike (units, missing groups, \r tails).
$p0 = maps_parse_progress('fetching chunks   0% |                                   | ( 0 B/32 MB) [0s:0s]');
T::eq('opening line parses', ['pct' => 0, 'done' => 0, 'total' => 33554432, 'speed' => 0, 'eta' => 0], $p0);
$p1 = maps_parse_progress('fetching chunks   0% |                     | (24 kB/32 MB, 50 kB/s) [0s:10m55s]');
T::eq('mid line parses', ['pct' => 0, 'done' => 24576, 'total' => 33554432, 'speed' => 51200, 'eta' => 655], $p1);
$p2 = maps_parse_progress("fetching chunks   4% |x| (1.4/32 MB, 1.2 MB/s) [0s:24s]\r");
T::eq('unitless done inherits total unit', ['pct' => 4, 'done' => 1468006, 'total' => 33554432, 'speed' => 1258291, 'eta' => 24], $p2);
$p3 = maps_parse_progress('fetching chunks 100% |xxx| (32/32 MB, 1.1 MB/s)');
T::eq('closing line parses without eta', ['pct' => 100, 'done' => 33554432, 'total' => 33554432, 'speed' => 1153434, 'eta' => 0], $p3);
T::eq('non-progress line is null', null, maps_parse_progress('Completed in 43s'));
T::eq('directory line is null', null, maps_parse_progress('extract.go:401: fetching 7 dirs'));

T::eq('bytes MB', 33554432, maps_parse_bytes('32', 'MB'));
T::eq('bytes fractional', 1468006, maps_parse_bytes('1.4', 'MB'));
T::eq('bytes kB lowercase', 51200, maps_parse_bytes('50', 'kB'));
T::eq('bytes unknown unit', null, maps_parse_bytes('3', 'XB'));
T::eq('dur seconds', 24, maps_parse_dur('24s'));
T::eq('dur minutes', 655, maps_parse_dur('10m55s'));
T::eq('dur hours', 3723, maps_parse_dur('1h02m03s'));
T::eq('dur zero', 0, maps_parse_dur('0s'));
T::eq('dur garbage', 0, maps_parse_dur('soon'));

$boxA = ['min_lon' => 20.0, 'min_lat' => 52.0, 'max_lon' => 22.0, 'max_lat' => 54.0];
T::eq('identical overlap is 1', 1.0, maps_overlap_frac($boxA, $boxA));
T::eq('disjoint overlap is 0', 0.0, maps_overlap_frac($boxA, ['min_lon' => 30.0, 'min_lat' => 52.0, 'max_lon' => 32.0, 'max_lat' => 54.0]));
T::eq('half overlap is 0.5', 0.5, maps_overlap_frac(
    ['min_lon' => 20.0, 'min_lat' => 52.0, 'max_lon' => 21.0, 'max_lat' => 54.0], $boxA));

// Error codes render localized; details append raw (numbers/CLI tails only).
$diskMsg = maps_zone_error_text('code:disk_short|2097152');
T::ok('disk_short formats bytes', str_contains($diskMsg, '2 MiB') && !str_contains($diskMsg, 'code:'));
T::ok('stalled translates', ($m = maps_zone_error_text('code:stalled')) !== '' && !str_contains($m, 'code:'));
T::eq('free text passes through', 'boom', maps_zone_error_text('boom'));
T::eq('empty error is empty', '', maps_zone_error_text(null));
T::ok('sizing detail appends', str_ends_with((string)maps_zone_error_text('code:sizing_failed|exit 1'), 'exit 1'));

// Zone round trip (rows cleaned below; files never created for queued rows).
[$zid, $zerr] = maps_zone_add('P2 Test Zone', 20.85, 52.05, 21.30, 52.40, 14, false);
T::ok('zone add queues', $zid !== null && $zid > 0);
T::eq('bad name code', 'code:bad_name', maps_zone_add('', 20.85, 52.05, 21.30, 52.40, 14, false)[1]);
T::eq('bad zoom code', 'code:bad_zoom', maps_zone_add('x', 20.85, 52.05, 21.30, 52.40, 13, false)[1]);
T::eq('unordered add code', 'code:unordered', maps_zone_add('x', 21.30, 52.05, 20.85, 52.40, 14, false)[1]);
$names = array_column(maps_zone_list(), 'name');
T::ok('zone listed', in_array('P2 Test Zone', $names, true));
T::eq('queued zone not ready', [], maps_ready_zones());
$db->prepare("UPDATE map_zones SET status = 'ready' WHERE id = ?")->execute([$zid]);
$ready = maps_ready_zones();
$ztok = (string)$db->query('SELECT file_token FROM map_zones WHERE id = ' . (int)$zid)->fetchColumn();
T::ok('new zones get a 128-bit file token', preg_match('/^[0-9a-f]{32}$/', $ztok) === 1);
T::eq('ready zone advertised under its secret name', [['id' => 'zone_' . $zid, 'file' => 'zone_' . $zid . '_' . $ztok . '.pmtiles']], $ready);
T::ok('the guessable name is never advertised', $ready[0]['file'] !== 'zone_' . $zid . '.pmtiles');

// A row from before the column (no token) gets one on first touch, and its
// guessable legacy file is renamed with it — nothing stays reachable under
// the old name.
[$lid] = maps_zone_add('P7 Legacy Zone', 20.0, 52.0, 20.5, 52.5, 14, false);
$db->prepare("UPDATE map_zones SET file_token = NULL, status = 'ready' WHERE id = ?")->execute([$lid]);
@mkdir(maps_tiles_dir(), 0775, true);
$legacyPath = maps_tiles_dir() . '/zone_' . (int)$lid . '.pmtiles';
file_put_contents($legacyPath, 'LEGACY-BYTES');
$legacyEntry = null;
foreach (maps_ready_zones() as $e) {
    if ($e['id'] === 'zone_' . (int)$lid) {
        $legacyEntry = $e;
    }
}
T::ok('legacy zone advertised under a tokenized name',
    $legacyEntry !== null && preg_match('/^zone_' . (int)$lid . '_[0-9a-f]{32}\.pmtiles$/', $legacyEntry['file']) === 1);
T::ok('legacy file no longer reachable by its old name', !is_file($legacyPath));
T::eq('legacy bytes followed the rename', 'LEGACY-BYTES', (string)@file_get_contents(maps_tiles_dir() . '/' . ($legacyEntry['file'] ?? 'none')));
T::ok('minted token persisted', preg_match('/^[0-9a-f]{32}$/', (string)$db->query('SELECT file_token FROM map_zones WHERE id = ' . (int)$lid)->fetchColumn()) === 1);
T::ok('tokens differ between zones', ($legacyEntry['file'] ?? '') !== $ready[0]['file']
    && $ztok !== (string)$db->query('SELECT file_token FROM map_zones WHERE id = ' . (int)$lid)->fetchColumn());
T::eq('unknown zone has no token', null, maps_zone_ensure_token(2147000000));
T::ok('unknown zone path cannot exist', !is_file(maps_zone_path(2147000000)));
@unlink(maps_tiles_dir() . '/' . ($legacyEntry['file'] ?? 'none'));
$db->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$lid]);

// ── Phase 4: covering zones for the public reveal ─────────────────────────
// Only ready zones containing the pin reach the recipient's style.
$coverWarsaw = maps_covering_zones(52.2297, 21.0122);
T::eq('covering zone found', [['id' => 'zone_' . $zid, 'file' => 'zone_' . $zid . '_' . $ztok . '.pmtiles']], $coverWarsaw);
T::eq('outside point matches nothing', [], maps_covering_zones(48.85, 2.35));
T::eq('edge point is inside', $coverWarsaw, maps_covering_zones(52.05, 20.85));
T::eq('non-finite matches nothing', [], maps_covering_zones(NAN, 21.0));
T::eq('covering style carries only that source', ['zone_' . $zid], array_keys(maps_style($coverWarsaw)['sources']));
[$covQ] = maps_zone_add('P4 Cover Queued', 20.0, 52.0, 22.0, 54.0, 14, false);
T::eq('queued zone never covers', $coverWarsaw, maps_covering_zones(52.2297, 21.0122));
$db->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$covQ]);

// ── Phase 5: freshness + refresh ──────────────────────────────────────────
$db->prepare("UPDATE map_zones SET build_key = '20260918' WHERE id = ?")->execute([$zid]);
$zrow = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$zid) {
        $zrow = $z;
    }
}
set_setting('maps_build_key', '20260918');
T::ok('current build is fresh', !maps_zone_is_stale($zrow));
set_setting('maps_build_key', '20260919');
T::ok('newer build marks stale', maps_zone_is_stale($zrow));
T::ok('non-ready never stale', !maps_zone_is_stale(['status' => 'queued', 'build_key' => 'x']));
set_setting('maps_build_key', '');
T::ok('unknown build is not stale', !maps_zone_is_stale($zrow));
$db->prepare('UPDATE map_zones SET bytes_done = 5 WHERE id = ?')->execute([$zid]);
T::ok('refresh re-queues ready', maps_zone_refresh((int)$zid));
$rrow = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$zid) {
        $rrow = $z;
    }
}
T::eq('refresh lands queued', 'queued', $rrow['status'] ?? null);
T::eq('refresh resets progress', 0, (int)($rrow['bytes_done'] ?? -1));
T::ok('refresh refuses in-flight', !maps_zone_refresh((int)$zid));
T::ok('refresh refuses bad id', !maps_zone_refresh(0));
$db->prepare("UPDATE map_zones SET status = 'ready' WHERE id = ?")->execute([$zid]);
$styled = maps_style($ready);
T::ok('style carries the zone source', isset($styled['sources']['zone_' . $zid]));
T::ok('zone delete removes the row', maps_zone_delete((int)$zid));
T::ok('zone gone after delete', !in_array('P2 Test Zone', array_column(maps_zone_list(), 'name'), true));

// Steward fails jobs whose worker died without a word.
[$sid] = maps_zone_add('P2 Stale Zone', 20.85, 52.05, 21.30, 52.40, 14, false);
$db->prepare("UPDATE map_zones SET status = 'downloading', updated_at = '2020-01-01 00:00:00' WHERE id = ?")->execute([$sid]);
maps_steward();
$stale = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$sid) {
        $stale = $z;
    }
}
T::eq('stale job failed', 'failed', $stale['status'] ?? null);
T::eq('stale reason coded', 'code:stalled', $stale['error'] ?? null);

// Full pipeline against a stub CLI (no network, no real binary): sizing →
// extract with live progress → verify → atomic publish → ready.
set_setting('maps_build_key', '20260918');
set_setting('maps_build_at', (string)time());
$seenEnv = null;
maps_cli_runner(static function (array $args, ?array $env, ?callable $onChunk) use (&$seenEnv): array {
    if ($env !== null) {
        $seenEnv = $env; // verify passes none — only extract calls carry env
    }
    if ($args[0] === 'version') {
        return [true, 'pmtiles ' . PMTILES_CLI_VERSION];
    }
    if ($args[0] === 'extract') {
        if ($onChunk !== null) {
            $onChunk("fetching chunks 100% |x| (1.0/1.0 MB, 2.0 MB/s) [1s:0s]\r");
        }
        $body = "Completed in 1s\nExtract transferred 1.0 MB (overfetch 0.05) for an archive size of 1.0 MB";
        if (!in_array('--dry-run', $args, true)) {
            file_put_contents($args[2], str_repeat('x', 1048576));
        }
        return [true, $body];
    }
    if ($args[0] === 'verify') {
        return [true, 'Completed verify'];
    }
    return [false, 'stub: unknown command'];
});
[$pid] = maps_zone_add('P2 Pipe Zone', 20.85, 52.05, 21.30, 52.40, 14, false);
$prow = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$pid) {
        $prow = $z;
    }
}
[$pok, $perr] = maps_process_one($prow);
T::ok('stubbed pipeline succeeds: ' . $perr, $pok);
$final = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$pid) {
        $final = $z;
    }
}
T::eq('pipeline ends ready', 'ready', $final['status'] ?? null);
T::eq('sizing recorded exact bytes', 1048576, (int)($final['bytes_expected'] ?? 0));
T::ok('published file exists under its secret name', is_file(maps_zone_path((int)$pid))
    && preg_match('/^zone_' . (int)$pid . '_[0-9a-f]{32}\.pmtiles$/', basename(maps_zone_path((int)$pid))) === 1);
T::ok('no file under the guessable name', !is_file(maps_tiles_dir() . '/zone_' . $pid . '.pmtiles'));
T::eq('direct run passes no proxy env', null, $seenEnv);

// Proxy path: pool proxy is exported to the CLI env, never bypassed.
$db->prepare('INSERT INTO osm_proxies (url, source, last_status) VALUES (?, "manual", "new")')
    ->execute(['http://127.0.0.1:9/']);
[$qid] = maps_zone_add('P2 Proxy Zone', 20.85, 52.05, 21.30, 52.40, 14, true);
$qrow = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$qid) {
        $qrow = $z;
    }
}
[$qok] = maps_process_one($qrow);
T::ok('proxied pipeline succeeds', $qok);
T::eq('proxy exported to CLI env', 'http://127.0.0.1:9/', $seenEnv['HTTP_PROXY'] ?? null);

// Fail-closed: proxy requested, pool empty → failed, no direct attempt.
$db->prepare('DELETE FROM osm_proxies')->execute();
[$fid] = maps_zone_add('P2 Fail Zone', 20.85, 52.05, 21.30, 52.40, 14, true);
$frow = null;
foreach (maps_zone_list() as $z) {
    if ((int)$z['id'] === (int)$fid) {
        $frow = $z;
    }
}
[$fok, $ferr] = maps_process_one($frow);
T::ok('empty pool fails the job', !$fok && $ferr === 'code:proxy_empty');

// Cleanup: rows, published files, scratch settings, stub runner.
foreach ([$pid, $qid, $fid, $sid] as $cid) {
    @unlink(maps_zone_path((int)$cid));
    $db->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$cid]);
}
maps_cli_runner(null, true);
$db->prepare('DELETE FROM osm_proxies')->execute();
$pxIns = $db->prepare(
    'INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
     VALUES (?, ?, ?, ?, ?)'
);
foreach ($prevProxies as $px) {
    $pxIns->execute([$px['url'], $px['source'], $px['last_status'], $px['latency_ms'], $px['last_checked']]);
}
foreach (['maps_build_key', 'maps_build_at'] as $k) {
    if (!array_key_exists($k, $prevSettings)) {
        $db->prepare('DELETE FROM settings WHERE key_name = ?')->execute([$k]);
    }
}

// Restore every row the probes above touched so later suites inherit sanity.
foreach ($prevSettings as $k => $v) {
    set_setting($k, $v);
}
if (!array_key_exists('map_provider', $prevSettings)) {
    $db->prepare("DELETE FROM settings WHERE key_name = 'map_provider'")->execute();
}
$cache = &_settings_store();
$cache = null;

// ── Zone colours: one palette for the map layers and the list swatches ────────
$palette = MAPS_ZONE_COLORS;
T::ok('zone palette: eight valid, distinct colours',
      count($palette) === 8 && count(array_unique($palette)) === 8
      && count(array_filter($palette, static fn(string $c): bool => preg_match('/^#[0-9a-f]{6}$/', $c) === 1)) === 8);
T::eq('zone colour is chosen by id', 3, maps_zone_color_index(3));
T::eq('zone colour wraps around the palette', 1, maps_zone_color_index(9));
T::ok('zone colour is stable per id', maps_zone_color_index(41) === maps_zone_color_index(41));
T::ok('every zone id maps inside the palette',
      count(array_filter(range(1, 200), static fn(int $i): bool => maps_zone_color_index($i) >= 0 && maps_zone_color_index($i) < count($palette))) === 200);

exit(T::done());
