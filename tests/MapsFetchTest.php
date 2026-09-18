<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Maps downloads against a local stub server ──────────────────────────────
// maps_fetch_file / maps_ensure_cli run their real curl/PharData/proc_open
// code here, but the "remote" endpoint is a php -S router in a child process
// (ProxyClientTest pattern): no external traffic, hermetic on any platform.

foreach (['NO_PROXY', 'no_proxy', 'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'] as $k) {
    putenv($k);
}
unset($_SERVER['NO_PROXY'], $_SERVER['no_proxy']);

$port = 0; // chosen by the probe loop below
$stubDir = sys_get_temp_dir() . '/ddmgmt_maps_stub_' . getmypid();
if (!is_dir($stubDir)) {
    mkdir($stubDir, 0700, true);
}
$fixture = file_get_contents(dirname(__DIR__) . '/tests/fixtures/pmtiles-stub.tgz');
$router = $stubDir . '/router.php';
file_put_contents($router, <<<'PHP'
<?php
$p = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($p === '/cli.tgz') {
    header('Content-Type: application/gzip');
    readfile(__DIR__ . '/cli.tgz');
    return true;
}
if ($p === '/file') {
    $body = str_repeat('F', 65536);
    $range = $_SERVER['HTTP_RANGE'] ?? '';
    if (preg_match('/bytes=(\d+)-/', $range, $m)) {
        $start = min((int)$m[1], strlen($body));
        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . (strlen($body) - 1) . '/' . strlen($body));
        echo substr($body, $start);
        return true;
    }
    header('Content-Type: application/octet-stream');
    echo $body;
    return true;
}
http_response_code(404);
echo 'not found';
return true;
PHP);
file_put_contents($stubDir . '/cli.tgz', $fixture);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
// CI runners share loopback with unrelated processes: probe a few pid-based
// ports and take the first one that is both free and actually serves (a
// taken port makes php -S exit, which the boot loop below detects).
$proc = null;
for ($t = 0; $t < 10 && $port === 0; $t++) {
    $cand = 8937 + ((getmypid() + $t * 131) % 200);
    $probe = @fsockopen('127.0.0.1', $cand, $errno, $errstr, 0.2);
    if (is_resource($probe)) {
        fclose($probe);
        continue; // occupied — try the next candidate
    }
    $cmd = escapeshellarg(PHP_BINARY)
        . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
        . " -S 127.0.0.1:$cand " . escapeshellarg($router);
    $try = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $pipes);
    if (!is_resource($try)) {
        continue;
    }
    $ready = false;
    for ($i = 0; $i < 15; $i++) {
        $ch = curl_init("http://127.0.0.1:$cand/file");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 2);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit
        if ($code === 200 && $body === str_repeat('F', 65536)) {
            $ready = true;
            break;
        }
        usleep(200000);
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
    // SIGTERM ends php -S on POSIX; on Windows the listener survives
    // proc_terminate, so the whole tree gets force-killed instead.
    // (The immediate child is cmd.exe wrapping php.exe — /T takes the tree.)
    if (!empty(proc_get_status($proc)['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)proc_get_status($proc)['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
    @unlink($router);
    @unlink($stubDir . '/cli.tgz');
    @rmdir($stubDir);
});
$up = $port !== 0;
T::ok('stub server booted', $up);

$db = get_db();
$dlDir = sys_get_temp_dir() . '/ddmgmt_maps_dl_' . getmypid();
if (!is_dir($dlDir)) {
    mkdir($dlDir, 0700, true);
}

// ── maps_fetch_file ─────────────────────────────────────────────────────────
[$ok, $err] = maps_fetch_file("http://127.0.0.1:$port/file", $dlDir . '/full.bin', null);
T::ok('full download succeeds: ' . $err, $ok);
T::eq('full download content', str_repeat('F', 65536), file_get_contents($dlDir . '/full.bin'));

// Resume: a partial file continues via Range instead of restarting.
file_put_contents($dlDir . '/part.bin', str_repeat('F', 1000));
[$ok, $err] = maps_fetch_file("http://127.0.0.1:$port/file", $dlDir . '/part.bin', null);
T::ok('resumed download succeeds: ' . $err, $ok);
T::eq('resumed download completes', str_repeat('F', 65536), file_get_contents($dlDir . '/part.bin'));

[$ok, $err] = maps_fetch_file("http://127.0.0.1:$port/missing", $dlDir . '/nf.bin', null);
T::ok('404 fails', !$ok && str_contains($err, '404'));

[$ok, $err] = maps_fetch_file('http://127.0.0.1:9/unreachable', $dlDir . '/dead.bin', null);
T::ok('dead host fails direct', !$ok && str_contains($err, 'download failed (HTTP'));

[$ok, $err] = maps_fetch_file('http://127.0.0.1:9/unreachable', $dlDir . '/dead2.bin', 'http://127.0.0.1:9/');
T::ok('dead host fails through proxy', !$ok && str_contains($err, 'download failed through proxy'));

[$ok, $err] = maps_fetch_file("http://127.0.0.1:$port/file", $dlDir . '/no-dir-at-all/x.bin', null);
T::ok('unwritable dest fails', !$ok);

// ── maps_cli_exec real proc_open arms ───────────────────────────────────────
putenv('DDMGMT_PMTILES_BIN=' . PHP_BINARY);
[$ok, $out] = maps_cli_exec(['-r', "echo 'pmtiles " . PMTILES_CLI_VERSION . "';"]);
T::ok('proc_open success path', $ok && str_contains($out, PMTILES_CLI_VERSION));
[$ok, $out] = maps_cli_exec(['-r', "fwrite(STDERR, 'x'); exit(3);"]);
T::ok('proc_open exit-code path', !$ok && str_contains($out, 'pmtiles exit 3'));
$seen = '';
[$ok, $out] = maps_cli_exec(['-r', "echo 'chunked';"], ['P2_PROBE' => 'yes'],
    static function (string $c) use (&$seen): void { $seen .= $c; });
T::ok('proc_open env passthrough', $ok && str_contains($out, 'chunked'));
T::ok('proc_open streams chunks', str_contains($seen, 'chunked'));
putenv('DDMGMT_PMTILES_BIN');

// ── maps_ensure_cli download path (stub asset from the local server) ───────
$prevHash = get_setting('maps_cli_sha256', '');
// Killed runs can leave a partial tgz behind; the resume logic would then
// send Range to a stub that answers 200 — start clean for determinism.
@unlink(maps_data_dir() . '/pmtiles.tgz');
@unlink(maps_data_dir() . '/pmtiles');
putenv('DDMGMT_PMTILES_URL=http://127.0.0.1:' . $port . '/cli.tgz');
[$ok, $err] = maps_ensure_cli(false, null);
if (PHP_OS_FAMILY === 'Linux') {
    T::ok('ensure fetches + verifies stub cli: ' . $err, $ok);
    T::ok('stub cli is executable', is_executable(maps_data_dir() . '/pmtiles'));
    T::ok('TOFU hash pinned', get_setting('maps_cli_sha256', '') !== '');
} else {
    // Windows cannot exec the fixture's sh script — the version check arm.
    T::ok('ensure reports version mismatch on Windows', !$ok && $err === 'code:version_mismatch');
}
putenv('DDMGMT_PMTILES_URL');
// Remove the fetched tool dir (gitignored, but keep the tree clean).
$toolDir = maps_data_dir();
if (is_dir($toolDir)) {
    foreach (glob($toolDir . '/*') ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($toolDir);
}
if ($prevHash === '') {
    $db->prepare("DELETE FROM settings WHERE key_name = 'maps_cli_sha256'")->execute();
} else {
    set_setting('maps_cli_sha256', $prevHash);
}
$cache = &_settings_store();
$cache = null;

// A present binary under a stubbed runner walks the trust-on-first-use pin
// instead of re-downloading: hash recorded once, verified thereafter.
@mkdir(maps_data_dir(), 0750, true);
file_put_contents(maps_data_dir() . '/pmtiles', 'P2FAKEBIN');
maps_cli_runner(static fn(): array => [true, 'pmtiles ' . PMTILES_CLI_VERSION]);
[$ok, $err] = maps_ensure_cli(false, null);
maps_cli_runner(null, true);
T::ok('present stub binary verifies: ' . $err, $ok);
T::eq('TOFU hash pinned', hash('sha256', 'P2FAKEBIN'), get_setting('maps_cli_sha256', ''));
$db->prepare("DELETE FROM settings WHERE key_name = 'maps_cli_sha256'")->execute();
$cache = &_settings_store();
$cache = null;
@unlink(maps_data_dir() . '/pmtiles');

// ── Worker lock / retry / kick ──────────────────────────────────────────────
[$locked] = maps_worker_lock();
T::ok('lock acquires', $locked);
[$locked2] = maps_worker_lock();
T::ok('second lock refuses', !$locked2);
maps_worker_touch();
maps_worker_unlock();
[$locked3] = maps_worker_lock();
T::ok('lock re-acquires after unlock', $locked3);
maps_worker_unlock();
// A lock older than the stall window belongs to a dead worker: stealable.
set_setting('maps_worker_lock', json_encode(['by' => 'dead:test', 'at' => 1]));
[$stolen] = maps_worker_lock();
T::ok('stale lock is stolen', $stolen);
maps_worker_unlock();
// A corrupt lock row never wedges the worker.
set_setting('maps_worker_lock', '###not-json###');
[$healed] = maps_worker_lock();
T::ok('corrupt lock is healed', $healed);
maps_worker_unlock();

[$rid] = maps_zone_add('P2 Retry Zone', 20.85, 52.05, 21.30, 52.40, 14, false);
$db->prepare("UPDATE map_zones SET status = 'failed', error = 'code:stalled' WHERE id = ?")->execute([$rid]);
T::ok('failed zone retries', maps_zone_retry((int)$rid));
$row = $db->query('SELECT status, error FROM map_zones WHERE id = ' . (int)$rid)->fetch();
T::eq('retry resets to queued', 'queued', $row['status']);
T::ok('queued zone does not retry', !maps_zone_retry((int)$rid));
T::ok('retry rejects bad ids', !maps_zone_retry(0) && !maps_zone_retry(999999999));
T::ok('delete rejects bad ids', !maps_zone_delete(0) && !maps_zone_delete(-5));
T::ok('kick answers bool', is_bool(maps_kick_worker()));
$db->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$rid]);

// ── process_one failure arms (stub runner, no network) ──────────────────────
set_setting('maps_build_key', '20260918');
set_setting('maps_build_at', (string)time());

$runPipe = static function (string $name, callable $stub): array {
    [$id] = maps_zone_add($name, 20.85, 52.05, 21.30, 52.40, 14, false);
    maps_cli_runner($stub);
    $row = get_db()->query('SELECT * FROM map_zones WHERE id = ' . (int)$id)->fetch();
    [$ok, $err] = maps_process_one($row);
    $st = get_db()->query('SELECT status, error FROM map_zones WHERE id = ' . (int)$id)->fetch();
    maps_cli_runner(null, true);
    get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$id]);
    return [$ok, $err, $st];
};
$verStub = static fn(): array => [true, 'pmtiles ' . PMTILES_CLI_VERSION];

[$ok, $err, $st] = $runPipe('P2 Arm SizFail', static function (array $a) use ($verStub): array {
    if ($a[0] === '--version') {
        return $verStub();
    }
    return [false, 'boom'];
});
T::ok('sizing exec failure codes', !$ok && $err === 'code:sizing_failed' && $st['error'] === 'code:sizing_failed|boom');

[$ok, $err, $st] = $runPipe('P2 Arm SizEmpty', static function (array $a) use ($verStub): array {
    if ($a[0] === '--version') {
        return $verStub();
    }
    return [true, 'Completed with no size line'];
});
T::ok('sizing without size codes', !$ok && $err === 'code:sizing_empty');

[$ok, $err] = $runPipe('P2 Arm DlFail', static function (array $a) use ($verStub): array {
    if ($a[0] === '--version') {
        return $verStub();
    }
    if (in_array('--dry-run', $a, true)) {
        return [true, 'for an archive size of 1.0 MB'];
    }
    return [false, 'net down'];
});
T::ok('extract failure codes', !$ok && $err === 'code:download_failed');

[$ok, $err] = $runPipe('P2 Arm VerifyFail', static function (array $a) use ($verStub): array {
    if ($a[0] === '--version') {
        return $verStub();
    }
    if ($a[0] === 'verify') {
        return [false, 'corrupt'];
    }
    if ($a[0] === 'extract' && !in_array('--dry-run', $a, true)) {
        file_put_contents($a[2], 'x');
    }
    return [true, 'for an archive size of 1.0 MB'];
});
T::ok('verify failure codes', !$ok && $err === 'code:verify_failed');

// Full pipeline success: sizing → extract (one progress line streams into
// the row) → verify → atomic publish. The stub lays down the .part file the
// real CLI would have downloaded.
[$rid2] = maps_zone_add('P2 Arm Ready', 20.85, 52.05, 21.30, 52.40, 14, false);
maps_cli_runner(static function (array $a, ?array $env = null, ?callable $onChunk = null) use ($verStub): array {
    if ($a[0] === '--version') {
        return $verStub();
    }
    if ($a[0] === 'verify') {
        return [true, 'verified ok'];
    }
    if ($a[0] === 'extract' && in_array('--dry-run', $a, true)) {
        return [true, 'for an archive size of 1.5 MB'];
    }
    if ($onChunk !== null) {
        $onChunk("fetching chunks 50% (0.5 MB/1.0 MB, 1.0 MB/s) [elapsed:0:01, eta:0:01]\n");
    }
    file_put_contents($a[2], 'PARTDATA');
    return [true, 'done'];
});
$rrow = get_db()->query('SELECT * FROM map_zones WHERE id = ' . (int)$rid2)->fetch();
[$ok, $err] = maps_process_one($rrow);
maps_cli_runner(null, true);
$st = get_db()->query('SELECT status, error, bytes_done FROM map_zones WHERE id = ' . (int)$rid2)->fetch();
T::ok('full pipeline reaches ready: ' . $err, $ok && $err === '' && $st['status'] === 'ready');
T::eq('ready row carries byte count', 8, (int)$st['bytes_done']);
$final = maps_tiles_dir() . '/zone_' . $rid2 . '.pmtiles';
T::ok('published pmtiles kept', is_file($final) && file_get_contents($final) === 'PARTDATA');
@unlink($final);
get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$rid2]);

// Fail-closed pipeline arms: an empty proxy pool never falls back to
// direct, and a dead CLI download aborts before any tile is kept.
$savedProxies = $db->query('SELECT url, source, last_status, latency_ms, last_checked FROM osm_proxies')->fetchAll();
$db->prepare('DELETE FROM osm_proxies')->execute();
[$pid] = maps_zone_add('P2 Arm ProxyEmpty', 20.85, 52.05, 21.30, 52.40, 14, true);
$prow = get_db()->query('SELECT * FROM map_zones WHERE id = ' . (int)$pid)->fetch();
maps_cli_runner($verStub);
[$ok, $err] = maps_process_one($prow);
maps_cli_runner(null, true);
T::ok('empty pool fails closed', !$ok && $err === 'code:proxy_empty');
get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$pid]);
foreach ($savedProxies as $px) {
    $db->prepare('INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked) VALUES (?, ?, ?, ?, ?)')
        ->execute([$px['url'], $px['source'], $px['last_status'], $px['latency_ms'], $px['last_checked']]);
}

putenv('DDMGMT_PMTILES_URL=http://127.0.0.1:' . $port . '/missing');
[$fid] = maps_zone_add('P2 Arm FetchFail', 20.85, 52.05, 21.30, 52.40, 14, false);
// No CLI runner here: ensure_cli must walk the real download path and fail
// on the 404 before any tile is kept.
$frow = get_db()->query('SELECT * FROM map_zones WHERE id = ' . (int)$fid)->fetch();
[$ok, $err] = maps_process_one($frow);
putenv('DDMGMT_PMTILES_URL');
T::ok('dead CLI download aborts', !$ok && $err === 'code:fetch_failed|download failed (HTTP 404)');
get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$fid]);

// Sizing past every disk on earth fails before a byte is kept.
[$did] = maps_zone_add('P2 Arm DiskShort', 20.85, 52.05, 21.30, 52.40, 14, false);
maps_cli_runner(static function (array $a) use ($verStub): array {
    if ($a[0] === '--version') {
        return $verStub();
    }
    return [true, 'for an archive size of 99 TB'];
});
$drow = get_db()->query('SELECT * FROM map_zones WHERE id = ' . (int)$did)->fetch();
[$ok, $err] = maps_process_one($drow);
maps_cli_runner(null, true);
T::ok('absurd size fails on disk', !$ok && $err === 'code:disk_short');
get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$did]);

// Without a known CLI triplet there is no download URL to fetch.
if (maps_arch() === null) {
    putenv('DDMGMT_PMTILES_URL');
    T::ok('cli asset null without arch', maps_cli_asset() === null);
    T::ok('cli url null without arch', maps_cli_url() === null);
}

// Steward: a zone stuck in downloading past the stall window fails shut.
[$sid] = maps_zone_add('P2 Stalled', 20.85, 52.05, 21.30, 52.40, 14, false);
$db->prepare("UPDATE map_zones SET status = 'downloading', updated_at = '2000-01-01 00:00:00' WHERE id = ?")->execute([$sid]);
maps_steward();
$srow = $db->query('SELECT status, error FROM map_zones WHERE id = ' . (int)$sid)->fetch();
T::ok('steward fails stalled zones', $srow['status'] === 'failed' && $srow['error'] === 'code:stalled');
$db->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$sid]);
maps_steward_if_due(0.0); // degenerate chance still reaches the steward run
T::ok('steward slot timestamps', get_setting('maps_steward_at', '') !== '');
maps_steward_if_due(1.0); // static $ran — second call is a no-op
$db->prepare("DELETE FROM settings WHERE key_name = 'maps_steward_at'")->execute();

// ── misc ────────────────────────────────────────────────────────────────────
T::eq('degenerate box overlaps nothing', 0.0,
    maps_overlap_frac(
        ['min_lon' => 20.0, 'min_lat' => 52.0, 'max_lon' => 21.0, 'max_lat' => 53.0],
        ['min_lon' => 1.0, 'min_lat' => 1.0, 'max_lon' => 1.0, 'max_lat' => 1.0]
    ));
T::eq('unknown code falls back to itself', 'nope_xyz', maps_zone_error_text('code:nope_xyz'));
$savedPx = $db->query('SELECT url, source, last_status, latency_ms, last_checked FROM osm_proxies')->fetchAll();
$db->prepare('DELETE FROM osm_proxies')->execute();
$db->prepare("INSERT INTO osm_proxies (url, source, last_status) VALUES ('http://dead.example:8080', 'manual', 'fail')")->execute();
T::ok('all-fail pool picks nothing', maps_pick_proxy() === null);
$db->prepare('DELETE FROM osm_proxies')->execute();
foreach ($savedPx as $px) {
    $db->prepare('INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked) VALUES (?, ?, ?, ?, ?)')
        ->execute([$px['url'], $px['source'], $px['last_status'], $px['latency_ms'], $px['last_checked']]);
}
T::eq('fmt bytes', '512 B', maps_fmt_bytes(512));
T::eq('fmt kib', '1.5 KiB', maps_fmt_bytes(1536));
T::eq('fmt gib', '3 GiB', maps_fmt_bytes(3221225472));
T::ok('arch answers null-or-triplet on dev', maps_arch() === null || str_starts_with((string)maps_arch(), 'Linux_'));

// Cleanup downloads + scratch settings from this file.
foreach (glob($dlDir . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir($dlDir);
// The fetch-failure arm leaves a stub 404 body where the CLI tgz would land
// (ensure_cli only unlinks after a successful fetch) — sweep the tool dir.
foreach (glob(maps_data_dir() . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir(maps_data_dir());
$db->prepare("DELETE FROM settings WHERE key_name IN ('maps_build_key', 'maps_build_at')")->execute();
$cache = &_settings_store();
$cache = null;

exit(T::done());
