<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── PHP download engine against a stub planet ───────────────────────────────
// A synthetic PMTiles archive (built with the engine's own writer) is served
// by a loopback php -S router with Range support; maps_process_php() runs
// its real plan → fetch → assemble → verify → publish path against it. No
// external traffic, hermetic on any platform — including Windows, where the
// auto-selected engine must already be 'php' (the point of the feature).

foreach (['NO_PROXY', 'no_proxy', 'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'] as $k) {
    putenv($k);
}
unset($_SERVER['NO_PROXY'], $_SERVER['no_proxy']);

// Auto engine on this box (no override yet): Linux+exec+cURL → cli,
// everywhere else with a transport → php. Never 'off' here.
T::ok('auto engine is usable here', in_array(maps_engine(), ['cli', 'php'], true));
if (PHP_OS_FAMILY === 'Windows') {
    T::eq('Windows auto-selects the PHP engine', 'php', maps_engine());
}
T::ok('downloads supported here', maps_downloads_supported());

putenv('DDMGMT_MAPS_ENGINE=php');
T::eq('engine override sticks', 'php', maps_engine());

// ── Synthetic planet: gzip tiles over a small grid, z0..z2 ────────────────
$tiles = []; // tileId => raw bytes
foreach ([[0, 0, 0], [1, 0, 0], [1, 1, 0], [1, 0, 1], [1, 1, 1],
          [2, 2, 1], [2, 3, 1], [2, 2, 2], [2, 3, 2], [2, 0, 0]] as [$z, $x, $y]) {
    $id = pmtiles_tile_id($z, $x, $y);
    $tiles[$id] = (string)gzencode("TILE $z/$x/$y");
}
ksort($tiles, SORT_NUMERIC);
$meta = '{"name":"stub","format":"pbf"}';
$data = implode('', $tiles);
$dirIn = [];
$off = 0;
foreach ($tiles as $id => $bytes) {
    $dirIn[] = ['id' => $id, 'len' => strlen($bytes), 'off' => $off];
    $off += strlen($bytes);
}
$rootDir = pmtiles_dir_encode($dirIn);
// Two levels like the real planet: the root holds one leaf pointer, the
// leaf holds the data entries (exercises leaf-relative addressing).
$leafBytes = $rootDir;
$firstId = array_key_first($tiles);
$rootPtr = pmtiles_dir_encode([['id' => $firstId, 'run' => 0, 'len' => strlen($leafBytes), 'off' => 0]]);
$metaOff = PMTILES_HEADER_LEN + strlen($rootPtr);
$leafOff = $metaOff + strlen($meta);
$tileOff = $leafOff + strlen($leafBytes);
$header = PMTILES_MAGIC . chr(PMTILES_VERSION)
    . pmtiles_u64le(PMTILES_HEADER_LEN) . pmtiles_u64le(strlen($rootPtr))
    . pmtiles_u64le($metaOff) . pmtiles_u64le(strlen($meta))
    . pmtiles_u64le($leafOff) . pmtiles_u64le(strlen($leafBytes))
    . pmtiles_u64le($tileOff) . pmtiles_u64le(strlen($data))
    . pmtiles_u64le(count($tiles)) . pmtiles_u64le(count($tiles)) . pmtiles_u64le(count($tiles))
    . chr(1) . chr(PMTILES_COMP_GZIP) . chr(PMTILES_COMP_GZIP) . chr(PMTILES_TYPE_MVT)
    . chr(0) . chr(2)
    . pmtiles_i32le((int)(-180 * 1e7)) . pmtiles_i32le((int)(-85 * 1e7))
    . pmtiles_i32le((int)(180 * 1e7)) . pmtiles_i32le((int)(85 * 1e7))
    . chr(0) . pmtiles_i32le(0) . pmtiles_i32le(0);
$planetBytes = $header . $rootPtr . $meta . $leafBytes . $data;
T::ok('synthetic planet parses', pmtiles_parse_header(substr($planetBytes, 0, 127)) !== null);

// ── Loopback stub with Range support ───────────────────────────────────────
$port = 0;
$stubDir = sys_get_temp_dir() . '/ddmgmt_phpmaps_stub_' . getmypid();
if (!is_dir($stubDir)) {
    mkdir($stubDir, 0700, true);
}
file_put_contents($stubDir . '/planet.pmtiles', $planetBytes);
// A second planet holding ONLY z5 tiles: any low-zoom query plans empty.
$farId = pmtiles_tile_id(5, 10, 10);
$farBytes = (string)gzencode('FAR');
$farDir = pmtiles_dir_encode([['id' => $farId, 'len' => strlen($farBytes), 'off' => 0]]);
$farMeta = '{}';
$farMetaOff = PMTILES_HEADER_LEN + strlen($farDir);
$farTileOff = $farMetaOff + strlen($farMeta);
$farHeader = PMTILES_MAGIC . chr(PMTILES_VERSION)
    . pmtiles_u64le(PMTILES_HEADER_LEN) . pmtiles_u64le(strlen($farDir))
    . pmtiles_u64le($farMetaOff) . pmtiles_u64le(strlen($farMeta))
    . pmtiles_u64le($farTileOff) . pmtiles_u64le(0)
    . pmtiles_u64le($farTileOff) . pmtiles_u64le(strlen($farBytes))
    . pmtiles_u64le(1) . pmtiles_u64le(1) . pmtiles_u64le(1)
    . chr(1) . chr(PMTILES_COMP_GZIP) . chr(PMTILES_COMP_GZIP) . chr(PMTILES_TYPE_MVT)
    . chr(5) . chr(5)
    . pmtiles_i32le(0) . pmtiles_i32le(0) . pmtiles_i32le(0) . pmtiles_i32le(0)
    . chr(5) . pmtiles_i32le(0) . pmtiles_i32le(0);
file_put_contents($stubDir . '/planet5.pmtiles', $farHeader . $farDir . $farMeta . $farBytes);
$router = $stubDir . '/router.php';
file_put_contents($router, <<<'PHP'
<?php
$p = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$serve = null;
if ($p === '/planet.pmtiles' || $p === '/planet5.pmtiles') {
    $serve = __DIR__ . $p;
}
if ($serve !== null) {
    $body = file_get_contents($serve);
    $range = $_SERVER['HTTP_RANGE'] ?? '';
    if (preg_match('/bytes=(\d+)-(\d*)/', $range, $m)) {
        $start = (int)$m[1];
        $end = $m[2] === '' ? strlen($body) - 1 : min((int)$m[2], strlen($body) - 1);
        if ($start >= strlen($body)) {
            http_response_code(416);
            return true;
        }
        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . strlen($body));
        header('Content-Length: ' . ($end - $start + 1));
        echo substr($body, $start, $end - $start + 1);
        return true;
    }
    header('Content-Length: ' . strlen($body));
    echo $body;
    return true;
}
http_response_code(404);
echo 'not found';
return true;
PHP);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = null;
for ($t = 0; $t < 10 && $port === 0; $t++) {
    $cand = 9137 + ((getmypid() + $t * 131) % 200);
    $probe = @fsockopen('127.0.0.1', $cand, $errno, $errstr, 0.2);
    if (is_resource($probe)) {
        fclose($probe);
        continue;
    }
    $cmd = escapeshellarg(PHP_BINARY)
        . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
        . " -S 127.0.0.1:$cand " . escapeshellarg($router);
    $try = proc_open(t_exec_cmd($cmd), [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $pipes);
    if (!is_resource($try)) {
        continue;
    }
    $ready = false;
    for ($i = 0; $i < 15; $i++) {
        $ctx = stream_context_create(['http' => ['timeout' => 2]]);
        $body = @file_get_contents("http://127.0.0.1:$cand/planet.pmtiles", false, $ctx, 0, 8);
        if ($body === 'PMTiles' . chr(3)) {
            $ready = true;
            break;
        }
        usleep(50000);
    }
    if ($ready) {
        $port = $cand;
        $proc = $try;
    } else {
        if (!empty(proc_get_status($try)['running'])) {
            if (DIRECTORY_SEPARATOR === '\\') {
                exec('taskkill /F /T /PID ' . (int)proc_get_status($try)['pid'] . ' >NUL 2>&1');
            } else {
                proc_terminate($try);
            }
        }
        proc_close($try);
    }
}
if (!is_resource($proc) || $port === 0) {
    fwrite(STDERR, "cannot spawn stub server\n");
    exit(1);
}
register_shutdown_function(static function () use ($proc, $router, $stubDir): void {
    if (!empty(proc_get_status($proc)['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)proc_get_status($proc)['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
    @unlink($router);
    @unlink($stubDir . '/planet.pmtiles');
    @unlink($stubDir . '/planet5.pmtiles');
    @rmdir($stubDir);
});
T::ok('stub server booted', $port !== 0);

putenv('DDMGMT_MAPS_PLANET_URL=http://127.0.0.1:' . $port . '/planet.pmtiles');
// Build list is cached: point it at the stub build, no network.
$prevKey = get_setting('maps_build_key', '');
$prevAt = get_setting('maps_build_at', '0');
set_setting('maps_build_key', 'stub');
set_setting('maps_build_at', (string)time());

// Zone bbox: covers z1 tiles (1,0),(1,1) and z2 tiles (3,1),(3,2) — lon
// 90..180, lat 0..66 — plus the z0 root. (2,0,0) stays out. Raw INSERT: the
// UI only offers z14/z15, but the pipeline takes any zoom (test zoom 2 keeps
// the synthetic planet tiny).
$db = get_db();
$db->prepare(
    'INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, via_proxy)
     VALUES (?, ?, ?, ?, ?, ?, 0)'
)->execute(['PHP Engine Zone', 90.0, 0.0, 180.0, 66.0, 2]);
$zoneId = (int)$db->lastInsertId();
T::ok('zone queued', $zoneId > 0);
$row = maps_zone_get($zoneId);
T::ok('row readable', $row !== null);
[$st, $err] = maps_process_php($row, 0);
T::eq('extract completes', ['done', ''], [$st, $err]);
$row = maps_zone_get($zoneId);
T::eq('row ready', 'ready', $row['status'] ?? null);
$final = maps_zone_path($zoneId);
T::ok('archive published', is_file($final) && pmtiles_verify_path($final));
if (is_file($final)) {
    $raw = (string)file_get_contents($final);
    $hdr = pmtiles_parse_header(substr($raw, 0, 127));
    T::ok('extract header parses', $hdr !== null);
    if ($hdr !== null) {
        $root = pmtiles_parse_dir(substr($raw, $hdr['rootOff'], $hdr['rootLen']), $hdr['intComp']);
        T::ok('extract root parses', $root !== null);
        if ($root !== null) {
            // Every extracted tile byte-matches the synthetic planet…
            $want = pmtiles_covering_ids(90.0, 0.0, 180.0, 66.0, 2);
            T::eq('extract holds the covering set', count($want), count($root));
            $exact = true;
            foreach ($root as $e) {
                $got = substr($raw, $hdr['tileOff'] + $e['off'], $e['len']);
                if (!isset($tiles[$e['id']]) || $got !== $tiles[$e['id']]) {
                    $exact = false;
                    break;
                }
            }
            T::ok('extracted bytes match the planet', $exact);
            // …and the out-of-bbox tile is absent.
            T::ok('out-of-bbox tile excluded',
                pmtiles_find_entry($root, pmtiles_tile_id(2, 0, 0)) === null);
            T::eq('maxzoom honored', 2, $hdr['maxZoom']);
        }
    }
}

// ── Resume: a partial span file continues where it stopped ────────────────
$db->prepare(
    'INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, via_proxy)
     VALUES (?, ?, ?, ?, ?, ?, 0)'
)->execute(['PHP Engine Resume', 90.0, 0.0, 180.0, 66.0, 2]);
$zone2 = (int)$db->lastInsertId();
T::ok('resume zone queued', $zone2 > 0);
[$planPath, $tilesPath] = maps_zone_workspace($zone2);
[$plan, $planErr] = pmtiles_build_plan(
    (string)getenv('DDMGMT_MAPS_PLANET_URL'), null, 90.0, 0.0, 180.0, 66.0, 2);
T::ok('plan builds', $plan !== null);
if ($plan !== null) {
    T::ok('plan saved', pmtiles_plan_save($planPath, $plan));
    // Plant exactly the first span, as an interrupted slice would leave it.
    [$first] = $plan['spans'];
    [$body, $fetchErr] = pmtiles_http_range(
        (string)getenv('DDMGMT_MAPS_PLANET_URL'), $first[0], $first[1] - $first[0], null);
    T::ok('first span plants', $body !== null);
    if ($body !== null) {
        file_put_contents($tilesPath, $body);
        $row2 = maps_zone_get($zone2);
        [$st2, $err2] = maps_process_php($row2, 0);
        T::eq('resumed extract completes', ['done', ''], [$st2, $err2]);
        T::ok('resumed archive verifies', pmtiles_verify_path(maps_zone_path($zone2)));
    }
}

// ── Transport + planner failure arms (stub server) ─────────────────────────
$stubBase = 'http://127.0.0.1:' . $port;
foreach (['curl', 'stream'] as $via) {
    $fn = $via === 'curl' ? 'pmtiles_range_curl' : 'pmtiles_range_stream';
    [$b404, $e404] = $fn($stubBase . '/missing', 0, 10, null, 10);
    T::ok("$via 404 fails", $b404 === null && str_contains($e404, '404'));
    [$b200, $e200] = $fn($stubBase . '/planet.pmtiles', 0, 8, null, 10);
    T::ok("$via first bytes", $b200 === 'PMTiles' . chr(3) && $e200 === '');
}
[$ocean, $oceanErr] = pmtiles_build_plan($stubBase . '/planet5.pmtiles', null, 90.0, 0.0, 180.0, 66.0, 2);
T::ok('missing zooms plan empty', $ocean === null && $oceanErr === 'empty');
[$badH, $badHErr] = pmtiles_build_plan($stubBase . '/missing', null, 90.0, 0.0, 180.0, 66.0, 2);
T::ok('missing planet fails planning', $badH === null && str_contains($badHErr, '404'));

// ── Slice states: failed host, time-boxed 'more', then resume ──────────────
$deadPlan = $plan;
$deadPlan['url'] = 'http://127.0.0.1:9/planet.pmtiles';
$tmpTiles = sys_get_temp_dir() . '/ddmgmt_phpmaps_tiles_' . getmypid();
@unlink($tmpTiles);
[$fst, $ferr] = pmtiles_fetch_due($deadPlan, $tmpTiles, 0);
T::ok('dead host fails the slice', $fst === 'failed' && $ferr !== '');
@unlink($tmpTiles);
// Split the first span so the sleepy slice provably runs out of box mid-plan.
$split = $plan;
$fs = $plan['spans'][0];
$mid = $fs[0] + (int)(($fs[1] - $fs[0]) / 2);
$split['spans'] = array_merge([[$fs[0], $mid], [$mid, $fs[1]]], array_slice($plan['spans'], 1));
$sleepy = static function (): void {
    usleep(1500000);
};
[$mst, , $mbytes] = pmtiles_fetch_due($split, $tmpTiles, 1, $sleepy);
T::eq('boxed slice reports more', 'more', $mst);
T::ok('boxed slice kept its bytes', $mbytes === $mid - $fs[0] && filesize($tmpTiles) === $mbytes);
[$dst, , $dbytes] = pmtiles_fetch_due($split, $tmpTiles, 0);
$wantBytes = 0;
foreach ($split['spans'] as [$a, $b]) {
    $wantBytes += $b - $a;
}
T::eq('resume completes the spans', 'done', $dst);
T::eq('resumed byte count exact', $wantBytes, $dbytes);
@unlink($tmpTiles);

// ── Poll slice + inline completion honor the kick switch ────────────────────
$prevKick = get_setting('maps_worker_kick', '1');
set_setting('maps_worker_kick', '1');
$db->prepare(
    'INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, via_proxy)
     VALUES (?, ?, ?, ?, ?, ?, 0)'
)->execute(['PHP Engine Poll', 90.0, 0.0, 180.0, 66.0, 2]);
$pollId = (int)$db->lastInsertId();
maps_php_poll_slice();
$prow = maps_zone_get($pollId);
T::eq('poll slice finishes a stub zone', 'ready', $prow['status'] ?? null);
T::ok('poll slice published', pmtiles_verify_path(maps_zone_path($pollId)));
set_setting('maps_worker_kick', '0');
$db->prepare(
    'INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, via_proxy)
     VALUES (?, ?, ?, ?, ?, ?, 0)'
)->execute(['PHP Engine Parked', 90.0, 0.0, 180.0, 66.0, 2]);
$parkId = (int)$db->lastInsertId();
maps_php_poll_slice();
maps_php_inline($parkId);
$parked = maps_zone_get($parkId);
T::eq('kick off parks the queue (hermetic)', 'queued', $parked['status'] ?? null);
set_setting('maps_worker_kick', '1');
maps_php_inline($parkId);
$parked = maps_zone_get($parkId);
T::eq('inline completes with kick on', 'ready', $parked['status'] ?? null);
T::ok('inline published', pmtiles_verify_path(maps_zone_path($parkId)));
T::ok('poll zone deleted', maps_zone_delete($pollId));
T::ok('inline zone deleted', maps_zone_delete($parkId));
set_setting('maps_worker_kick', $prevKick);

// ── Engine off refuses everywhere ───────────────────────────────────────────
putenv('DDMGMT_MAPS_ENGINE=off');
T::ok('engine off unsupported', !maps_downloads_supported());
putenv('DDMGMT_MAPS_ENGINE=php');

// ── Cleanup: rows, files, settings, env ────────────────────────────────────
T::ok('delete removes zone + sidecars', maps_zone_delete($zoneId));
T::ok('published file gone', !is_file(maps_zone_path($zoneId)));
T::ok('resume zone deleted', maps_zone_delete($zone2));
set_setting('maps_build_key', $prevKey);
set_setting('maps_build_at', $prevAt);
putenv('DDMGMT_MAPS_ENGINE');
putenv('DDMGMT_MAPS_PLANET_URL');

exit(T::done());
