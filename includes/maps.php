<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/settings.php';

// ── Self-hosted map provider (PMTiles + MapLibre GL JS) ──────────────────────
// Dual-provider design: 'osm' (default, current tile_proxy/embed path,
// untouched) vs 'selfhosted' (same-origin PMTiles zones rendered by vendored
// MapLibre in /maplibre/). Nothing here touches the network: the style is
// built from zone files on local disk, fonts/glyphs/JS are vendored.
//
// Phase 1: no zones exist yet — maps_ready_zones() returns [] and the style
// carries no sources (pages render the map chrome + an empty-state overlay).
// Phase 2/3 replace the stub with the map_zones table read.

const MAP_PROVIDER_OSM = 'osm';
const MAP_PROVIDER_SELFHOSTED = 'selfhosted';

// Pinned vendored builds in /maplibre/ (see THIRD-PARTY-NOTICES.md).
const MAPLIBRE_VERSION = '5.13.0';
const PMTILES_JS_VERSION = '4.5.0';

// MapLibre renders vector tiles with WebGL workers built from Blob URLs,
// which the default CSP (script-src 'self' + nonce, no worker-src) blocks.
// Both CSP profiles therefore carry worker-src 'self' blob: (see auth.php).
// The glyph path below is reserved for Phase 3 (labels); the Phase 1 style
// deliberately has no symbol layers so it renders with zero font files.
const MAPS_GLYPHS_URL = '/fonts/glyphs/{fontstack}/{range}.pbf';

// Native detail of our extracts; the client overzooms crisply beyond it.
const MAPS_SOURCE_MAXZOOM = 14;

// Which tile backend renders maps. Unknown/corrupt values fail back to OSM
// (the historic behaviour) rather than to a broken map.
function map_provider(): string {
    $v = get_setting('map_provider', MAP_PROVIDER_OSM);
    return $v === MAP_PROVIDER_SELFHOSTED ? MAP_PROVIDER_SELFHOSTED : MAP_PROVIDER_OSM;
}

// Ready-to-render zones: each ['id' => 'zone_<n>', 'file' => '<name>.pmtiles'].
/** @return array<int,array{id:string,file:string}> */
function maps_ready_zones(): array {
    try {
        $rows = get_db()->query(
            "SELECT id FROM map_zones WHERE status = 'ready' ORDER BY id ASC"
        )->fetchAll();
    } catch (Throwable) {
        return []; // table missing (setup.sql not re-run) — no zones, no crash
    }
    $out = [];
    foreach ($rows as $r) {
        $out[] = ['id' => 'zone_' . (int)$r['id'], 'file' => 'zone_' . (int)$r['id'] . '.pmtiles'];
    }
    return $out;
}

// Build a MapLibre v8 style array for the given zones. One vector source per
// zone file; the dark layer stack is emitted per source (later zones paint
// over earlier ones where they overlap — the zone list warns about that).
/** @param array<int,array{id:string,file:string}> $zones */
function maps_style(array $zones): array {
    $style = [
        'version' => 8,
        'sources' => [],
        'layers'  => [
            [
                'id'    => 'background',
                'type'  => 'background',
                'paint' => ['background-color' => '#111418'],
            ],
        ],
    ];
    foreach ($zones as $zone) {
        $src = (string)$zone['id'];
        $style['sources'][$src] = [
            'type'        => 'vector',
            'url'         => 'pmtiles:///tiles/' . (string)$zone['file'],
            'maxzoom'     => MAPS_SOURCE_MAXZOOM,
            'attribution' => '© OpenStreetMap contributors',
        ];
        foreach (maps_layer_stack($src) as $layer) {
            $style['layers'][] = $layer;
        }
    }
    return $style;
}

// The dark layer stack for one source. Geometry only (fill/line) — symbol/
// text layers wait for vendored glyphs in Phase 3.
/** @return array<int,array<string,mixed>> */
function maps_layer_stack(string $source): array {
    $s = $source;
    return [
        [
            'id' => "earth_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'earth',
            'paint' => ['fill-color' => '#1a1e24'],
        ],
        [
            'id' => "landuse_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'landuse',
            'paint' => ['fill-color' => '#1e242c'],
        ],
        [
            'id' => "water_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'water',
            'paint' => ['fill-color' => '#0e2a3f'],
        ],
        [
            'id' => "roads_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'roads',
            'paint' => [
                'line-color' => '#5a636e',
                'line-width' => ['interpolate', ['linear'], ['zoom'], 8, 0.5, 14, 3],
            ],
        ],
        [
            'id' => "buildings_$s", 'type' => 'fill', 'source' => $s,
            'source-layer' => 'buildings',
            'paint' => ['fill-color' => '#2a2f37'],
        ],
        [
            'id' => "boundaries_$s", 'type' => 'line', 'source' => $s,
            'source-layer' => 'boundaries',
            'paint' => [
                'line-color'   => '#3a4552',
                'line-width'   => 1,
                'line-dasharray' => [3, 2],
            ],
        ],
    ];
}

// ── Phase 2: zone downloads ─────────────────────────────────────────────────
// The worker (cron/maps_sync.php, detached or via system cron) advances queued
// zones: ensure CLI → resolve planet build → dry-run sizing → disk check →
// extract with live progress → verify → atomic publish. Extracts cannot
// resume, so page visits NEVER run them — the pseudo-cron steward only fails
// stalled jobs. Proxy consent is per zone (via_proxy): proxy path is
// fail-closed (no working pool proxy = failed job, never silent direct).

const PMTILES_CLI_VERSION = '1.31.2';
const MAPS_PLANET_BUILDS_URL = 'https://build-metadata.protomaps.dev/builds.json';
const MAPS_PLANET_FILE_URL = 'https://build.protomaps.com/';
const MAPS_BUILD_CACHE_TTL = 86400;
const MAPS_WORKER_STALL_SECS = 2700; // 45 min without progress = dead
const MAPS_HEADROOM_MIN = 536870912; // 512 MiB always kept free

function maps_tiles_dir(): string {
    return dirname(__DIR__) . '/tiles';
}

function maps_data_dir(): string {
    return dirname(__DIR__) . '/data/maps';
}

// CLI asset triplet for this host, or null when the worker cannot run here
// (non-Linux, unknown arch — the admin UI says so instead of failing oddly).
function maps_arch(): ?string {
    if (PHP_OS_FAMILY !== 'Linux') {
        return null;
    }
    $m = php_uname('m');
    if ($m === 'x86_64') {
        return 'Linux_x86_64';
    }
    if ($m === 'aarch64') {
        return 'Linux_arm64';
    }
    return null;
}

function maps_cli_asset(): ?string {
    $arch = maps_arch();
    if ($arch === null) {
        return null;
    }
    return 'go-pmtiles_' . PMTILES_CLI_VERSION . '_' . $arch . '.tar.gz';
}

function maps_cli_url(): ?string {
    // DDMGMT_PMTILES_URL overrides for tests (local stub server).
    $env = getenv('DDMGMT_PMTILES_URL');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    $asset = maps_cli_asset();
    if ($asset === null) {
        return null;
    }
    return 'https://github.com/protomaps/go-pmtiles/releases/download/v'
        . PMTILES_CLI_VERSION . '/' . $asset;
}

// Test seam (see _cleanup_roll precedent): unit tests inject a stub runner;
// production always uses proc_open through maps_cli_exec(). Pass $clear to
// uninstall the stub (suites must not leak it into later files).
function maps_cli_runner(?callable $fn = null, bool $clear = false): ?callable {
    static $runner = null;
    if ($clear) {
        $runner = null;
        return null;
    }
    if ($fn !== null) {
        $runner = $fn;
    }
    return $runner;
}

/** @return array{bool,string} [ok, output-or-error] */
function maps_cli_exec(array $args, ?array $env = null, ?callable $onChunk = null): array {
    $runner = maps_cli_runner();
    if ($runner !== null) {
        return $runner($args, $env, $onChunk);
    }
    $bin = maps_cli_bin();
    $cmd = escapeshellarg($bin);
    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg((string)$a);
    }
    $base = ['PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'TMPDIR' => sys_get_temp_dir()];
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes, null, $env !== null ? $env + $base : null);
    if (!is_resource($proc)) {
        return [false, 'could not spawn pmtiles CLI'];
    }
    fclose($pipes[2]); // progress + logs both arrive on stdout; drop stderr
    $out = '';
    while (!feof($pipes[1])) {
        $chunk = fread($pipes[1], 65536);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $out .= $chunk;
        if ($onChunk !== null) {
            $onChunk($chunk);
        }
    }
    fclose($pipes[1]);
    $code = proc_close($proc);
    if ($code !== 0) {
        return [false, 'pmtiles exit ' . $code . ': ' . substr($out, -500)];
    }
    return [true, $out];
}

// Binary path. DDMGMT_PMTILES_BIN overrides for tests (stub executable).
function maps_cli_bin(): string {
    $env = getenv('DDMGMT_PMTILES_BIN');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    return maps_data_dir() . '/pmtiles';
}

/** @return array{bool,string} [ok, error] */
function maps_ensure_cli(bool $viaProxy, ?string $proxy): array {
    if (!function_exists('curl_init')) {
        return [false, 'code:no_curl'];
    }
    $bin = maps_cli_bin();
    // A test runner installed via maps_cli_runner() answers the version
    // probe below, so the file check is skipped in that case — hermetic
    // suites must never reach the network for a CLI download.
    if ((is_file($bin) && is_executable($bin)) || maps_cli_runner() !== null) {
        [$ok, $out] = maps_cli_exec(['--version']);
        if ($ok && str_contains($out, PMTILES_CLI_VERSION)) {
            if (!is_file($bin)) {
                return [true, '']; // stubbed CLI under test
            }
            // Trust-on-first-use pin: record the hash, verify it on every
            // later run. (Upstream publishes no checksums file; the release
            // tag itself is maintainer-signed and the fetch is TLS.)
            $hash = hash_file('sha256', $bin);
            $known = get_setting('maps_cli_sha256', '');
            if ($known === '') {
                set_setting('maps_cli_sha256', (string)$hash);
                audit('maps_cli_fetch', null, null, 'v' . PMTILES_CLI_VERSION . ' sha256=' . substr((string)$hash, 0, 16) . '…');
            } elseif (!hash_equals($known, (string)$hash)) {
                return [false, 'code:hash_mismatch'];
            }
            return [true, ''];
        }
        // Stale or broken binary — fall through to re-fetch.
    }
    $url = maps_cli_url();
    if ($url === null) {
        return [false, 'code:no_build'];
    }
    if ($viaProxy && $proxy === null) {
        return [false, 'code:proxy_empty'];
    }
    $dir = maps_data_dir();
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        return [false, 'code:mkdir'];
    }
    $tmp = $dir . '/pmtiles.tgz';
    [$ok, $err] = maps_fetch_file($url, $tmp, $viaProxy ? $proxy : null);
    if (!$ok) {
        return [false, 'code:fetch_failed|' . $err];
    }
    try {
        $phar = new PharData($tmp);
        $phar->extractTo($dir, 'pmtiles', true);
    } catch (Throwable $e) {
        @unlink($tmp);
        return [false, 'code:bad_archive'];
    }
    @unlink($tmp);
    @chmod($bin, 0750);
    [$ok, $out] = maps_cli_exec(['--version']);
    if (!$ok || !str_contains($out, PMTILES_CLI_VERSION)) {
        return [false, 'code:version_mismatch'];
    }
    $hash = hash_file('sha256', $bin);
    $known = get_setting('maps_cli_sha256', '');
    if ($known === '') {
        set_setting('maps_cli_sha256', (string)$hash);
        audit('maps_cli_fetch', null, null, 'v' . PMTILES_CLI_VERSION . ' sha256=' . substr((string)$hash, 0, 16) . '…');
    } elseif (!hash_equals($known, (string)$hash)) {
        return [false, 'code:hash_mismatch'];
    }
    return [true, ''];
}

// Stream a URL to disk with resume (Range) across calls. Proxy failures are
// returned, never silently retried direct — the caller owns fail-closed.
/** @return array{bool,string} [ok, error] */
function maps_fetch_file(string $url, string $dest, ?string $proxy): array {
    $ch = curl_init($url);
    if ($ch === false) {
        return [false, 'could not start download'];
    }
    $have = is_file($dest) ? filesize($dest) : 0;
    // @: an unwritable path warns — the false branch below owns the error.
    $fh = @fopen($dest, $have > 0 ? 'ab' : 'wb');
    if ($fh === false) {
        unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit
        return [false, 'cannot write download file'];
    }
    curl_setopt($ch, CURLOPT_FILE, $fh);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
    curl_setopt($ch, CURLOPT_TIMEOUT, 600);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    if ($have > 0) {
        curl_setopt($ch, CURLOPT_RANGE, $have . '-');
    }
    if ($proxy !== null) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }
    $ok = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit
    fclose($fh);
    if ($ok && ($code === 200 || ($have > 0 && $code === 206))) {
        return [true, ''];
    }
    return [false, $proxy !== null
        ? 'download failed through proxy (HTTP ' . $code . ($err !== '' ? ': ' . $err : '') . ')'
        : 'download failed (HTTP ' . $code . ($err !== '' ? ': ' . $err : '') . ')'];
}

// Latest planet build key (e.g. 20260918), cached a day. Reuses osm_fetch so
// the global proxy toggle + pool apply exactly like every other OSM fetch.
/** @return array{?string,string} [key-or-null, error] */
function maps_latest_build(): array {
    $cached = get_setting('maps_build_key', '');
    $at = (int)get_setting('maps_build_at', '0');
    if ($cached !== '' && (time() - $at) < MAPS_BUILD_CACHE_TTL) {
        return [$cached, ''];
    }
    $body = osm_fetch(MAPS_PLANET_BUILDS_URL, 1048576);
    if ($body === false) {
        return [null, 'code:build_list_unreachable'];
    }
    try {
        $list = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return [null, 'code:build_list_invalid'];
    }
    $best = null;
    foreach (is_array($list) ? $list : [] as $entry) {
        $key = is_array($entry) ? ($entry['key'] ?? '') : '';
        if (is_string($key) && str_ends_with($key, '.pmtiles')
            && ($best === null || $key > $best)) {
            $best = $key;
        }
    }
    if ($best === null) {
        return [null, 'code:build_list_empty'];
    }
    $key = substr($best, 0, -8);
    set_setting('maps_build_key', $key);
    set_setting('maps_build_at', (string)time());
    return [$key, ''];
}

// Validate a zone bbox. Numbers arrive pre-cast; this enforces geography:
// lon ±180, lat ±85 (WebMercator wall), ordered, non-degenerate, and no
// antimeridian crossing in Phase 2 (the CLI supports it, our overlap and
// budget math does not — unlock later).
/** @return array{bool,string} [ok, error] */
function maps_validate_bbox(float $minLon, float $minLat, float $maxLon, float $maxLat): array {
    foreach (['min_lon' => $minLon, 'max_lon' => $maxLon] as $k => $v) {
        if (!is_finite($v) || $v < -180.0 || $v > 180.0) {
            return [false, 'code:lon_range'];
        }
    }
    foreach (['min_lat' => $minLat, 'max_lat' => $maxLat] as $k => $v) {
        if (!is_finite($v) || $v < -85.0 || $v > 85.0) {
            return [false, 'code:lat_range'];
        }
    }
    if ($minLon >= $maxLon || $minLat >= $maxLat) {
        return [false, 'code:unordered'];
    }
    if (($maxLon - $minLon) < 0.0001 || ($maxLat - $minLat) < 0.0001) {
        return [false, 'code:tiny'];
    }
    return [true, ''];
}

/** @return array{?int,string} [id-or-null, error] */
function maps_zone_add(string $name, float $minLon, float $minLat, float $maxLon, float $maxLat, int $maxzoom, bool $viaProxy): array {
    $name = trim($name);
    if ($name === '' || mb_strlen($name) > 64) {
        return [null, 'code:bad_name'];
    }
    [$ok, $err] = maps_validate_bbox($minLon, $minLat, $maxLon, $maxLat);
    if (!$ok) {
        return [null, $err];
    }
    if ($maxzoom !== 14 && $maxzoom !== 15) {
        return [null, 'code:bad_zoom'];
    }
    if (maps_disk_free() < MAPS_HEADROOM_MIN) {
        return [null, 'code:disk_full_queue'];
    }
    try {
        $db = get_db();
        $db->prepare(
            'INSERT INTO map_zones (name, min_lon, min_lat, max_lon, max_lat, maxzoom, via_proxy)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([$name, $minLon, $minLat, $maxLon, $maxLat, $maxzoom, $viaProxy ? 1 : 0]);
        $id = (int)$db->lastInsertId();
    } catch (Throwable $e) {
        log_err('Zone add: ' . $e->getMessage());
        return [null, 'code:save_failed'];
    }
    audit('maps_zone_add', null, null, "id={$id} name={$name}");
    return [$id, ''];
}

/** @return array<int,array<string,mixed>> */
function maps_zone_list(): array {
    try {
        return get_db()->query('SELECT * FROM map_zones ORDER BY id ASC')->fetchAll();
    } catch (Throwable) {
        return [];
    }
}

function maps_zone_delete(int $id): bool {
    if ($id <= 0) {
        return false;
    }
    try {
        get_db()->prepare('DELETE FROM map_zones WHERE id = ?')->execute([$id]);
    } catch (Throwable $e) {
        log_err('Zone delete: ' . $e->getMessage());
        return false;
    }
    @unlink(maps_tiles_dir() . '/zone_' . $id . '.pmtiles');
    @unlink(maps_tiles_dir() . '/zone_' . $id . '.part');
    audit('maps_zone_delete', null, null, "id={$id}");
    return true;
}

function maps_zone_retry(int $id): bool {
    if ($id <= 0) {
        return false;
    }
    try {
        $st = get_db()->prepare(
            "UPDATE map_zones SET status = 'queued', error = NULL,
             bytes_expected = NULL, bytes_done = 0, speed_bps = NULL, eta_secs = NULL
             WHERE id = ? AND status = 'failed'"
        );
        $st->execute([$id]);
        return $st->rowCount() === 1;
    } catch (Throwable $e) {
        log_err('Zone retry: ' . $e->getMessage());
        return false;
    }
}

// Best pool proxy URL for a long download (same ok → new → dead ordering as
// osm_fetch), or null when none is usable. Never falls back to direct here.
function maps_pick_proxy(): ?string {
    $pool = osm_proxy_pool();
    if (!$pool) {
        return null;
    }
    usort($pool, function ($a, $b) {
        $rank = static fn($p) => match ($p['last_status'] ?? '') {
            'ok'   => 0,
            'new'  => 1,
            default => 2,
        };
        $ra = $rank($a);
        if ($ra !== ($rb = $rank($b))) {
            return $ra <=> $rb;
        }
        return ((int)($a['latency_ms'] ?? PHP_INT_MAX)) <=> ((int)($b['latency_ms'] ?? PHP_INT_MAX));
    });
    foreach ($pool as $px) {
        if (($px['last_status'] ?? '') !== 'fail') {
            return (string)$px['url'];
        }
    }
    return null;
}

function maps_disk_free(): int {
    $free = @disk_free_space(maps_tiles_dir());
    return $free === false ? 0 : (int)$free;
}

// Refuse a download unless the exact sized bytes plus headroom fit.
function maps_disk_ok(int $needBytes): bool {
    return maps_disk_free() >= $needBytes + MAPS_HEADROOM_MIN
        && maps_disk_free() >= MAPS_HEADROOM_MIN;
}

// Fraction of $b covered by $a (0–1): the UI warns on overlapping zones
// because each zone file carries its own copy of shared tiles.
/** @param array{min_lon:float,min_lat:float,max_lon:float,max_lat:float} $a $b */
function maps_overlap_frac(array $a, array $b): float {
    $w = max(0.0, min($a['max_lon'], $b['max_lon']) - max($a['min_lon'], $b['min_lon']));
    $h = max(0.0, min($a['max_lat'], $b['max_lat']) - max($a['min_lat'], $b['min_lat']));
    $areaB = max(0.0, ($b['max_lon'] - $b['min_lon']) * ($b['max_lat'] - $b['min_lat']));
    if ($areaB <= 0.0) {
        return 0.0;
    }
    return min(1.0, ($w * $h) / $areaB);
}

// Parse one CLI progress line:
//   fetching chunks  42% |███| (1.4/32 MB, 1.1 MB/s) [3s:24s]
// Done-bytes without a unit inherit the total's (the CLI prints "1.4/32 MB").
// The opening (0 B/32 MB, no speed yet) and closing (100%, no ETA) lines lack
// a group each — both are optional, missing values answer 0.
/** @return ?array{pct:int,done:int,total:int,speed:int,eta:int} */
function maps_parse_progress(string $line): ?array {
    if (!str_contains($line, 'fetching chunks')) {
        return null;
    }
    if (!preg_match('/(\d+)%/', $line, $pm)) {
        return null;
    }
    if (!preg_match('/\(\s*([\d.]+)\s*([KMGT]?B)?\s*\/\s*([\d.]+)\s*([KMGT]?B)\s*(?:,\s*([\d.]+)\s*([KMGT]?B)\/s\s*)?\)/i', $line, $m)) {
        return null;
    }
    $done = maps_parse_bytes($m[1], $m[2] !== '' ? $m[2] : $m[4]);
    $total = maps_parse_bytes($m[3], $m[4]);
    $speed = isset($m[5], $m[6]) && $m[5] !== '' ? maps_parse_bytes($m[5], $m[6]) : 0;
    if ($done === null || $total === null || $speed === null) {
        return null;
    }
    $eta = 0;
    if (preg_match('/\[\s*[^:\]]+\s*:\s*([^\]]+)\s*\]/', $line, $t)) {
        $eta = maps_parse_dur($t[1]);
    }
    return [
        'pct'   => min(100, (int)$pm[1]),
        'done'  => $done,
        'total' => $total,
        'speed' => $speed,
        'eta'   => $eta,
    ];
}

function maps_parse_bytes(string $num, string $unit): ?int {
    $n = (float)$num;
    if (!is_finite($n) || $n < 0) {
        return null;
    }
    $mult = match (strtoupper($unit)) {
        'B' => 1, 'KB' => 1024, 'MB' => 1048576,
        'GB' => 1073741824, 'TB' => 1099511627776,
        default => null,
    };
    if ($mult === null) {
        return null;
    }
    return (int)round($n * $mult);
}

// CLI durations: 24s, 10m55s, 1h2m3s, 0s.
function maps_parse_dur(string $s): int {
    if (!preg_match('/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/', trim($s), $m)) {
        return 0;
    }
    if ($m[0] === '') {
        return 0;
    }
    return ((int)($m[1] ?? 0)) * 3600 + ((int)($m[2] ?? 0)) * 60 + ((int)($m[3] ?? 0));
}

// Worker lock (settings rows, no new table): one extractor at a time.
// A lock older than the stall window belongs to a dead process — stealable.
/** @return array{bool,string} [acquired, holder-or-error] */
function maps_worker_lock(): array {
    $raw = get_setting('maps_worker_lock', '');
    if ($raw !== '') {
        try {
            $lock = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
            if (is_array($lock) && (time() - (int)($lock['at'] ?? 0)) < MAPS_WORKER_STALL_SECS) {
                return [false, 'worker already running (' . substr((string)($lock['by'] ?? '?'), 0, 32) . ')'];
            }
        } catch (Throwable) {
            // Corrupt lock — fall through and overwrite it.
        }
    }
    set_setting('maps_worker_lock', json_encode(['by' => php_uname('n') . ':' . getmypid(), 'at' => time()]));
    return [true, ''];
}

function maps_worker_touch(): void {
    set_setting('maps_worker_lock', json_encode(['by' => php_uname('n') . ':' . getmypid(), 'at' => time()]));
}

function maps_worker_unlock(): void {
    $db = get_db();
    try {
        $db->prepare("DELETE FROM settings WHERE key_name = 'maps_worker_lock'")->execute();
    } catch (Throwable) {
    }
    $cache = &_settings_store();
    $cache = null;
}

// Hourly steward (called from the pseudo-cron slot): fail jobs whose CLI
// died without a word, release the lock behind them. Never downloads.
function maps_steward(): void {    try {
        $db = get_db();
        $cutoff = gmdate('Y-m-d H:i:s', time() - MAPS_WORKER_STALL_SECS);
        $st = $db->prepare(
            "UPDATE map_zones SET status = 'failed', error = 'code:stalled'
             WHERE status IN ('sizing','downloading') AND updated_at < ?"
        );
        $st->execute([$cutoff]);
        if ($st->rowCount() > 0) {
            log_err('Maps steward failed ' . $st->rowCount() . ' stalled zone(s)');
            maps_worker_unlock();
        }
    } catch (Throwable $e) {
        log_err('Maps steward: ' . $e->getMessage());
    }
}

// Throttled wrapper for page visits: a dice roll first (same rationale as
// _cleanup_roll — no DB touch on most visits), then an hourly timestamp.
function maps_steward_if_due(float $chance = 0.01): void {
    static $ran = false;
    if ($ran) {
        return;
    }
    if ($chance < 1.0) {
        try {
            if (random_int(1, max(1, (int)round(1 / $chance))) !== 1) {
                return;
            }
        } catch (Throwable) {
            // Dead CSPRNG — run the (cheap, guarded) steward rather than skip.
        }
    }
    $ran = true;
    try {
        $last = (int)get_setting('maps_steward_at', '0');
        if ((time() - $last) < 3600) {
            return;
        }
        set_setting('maps_steward_at', (string)time());
        maps_steward();
    } catch (Throwable $e) {
        log_err('Maps steward slot: ' . $e->getMessage());
    }
}

// Detached kick after queueing (Linux + exec only): the worker then runs
// without holding any request. False = admin waits for system cron.
function maps_kick_worker(): bool {
    if (PHP_OS_FAMILY !== 'Linux' || !function_exists('exec')) {
        return false;
    }
    $php = escapeshellarg(PHP_BINARY);
    $script = escapeshellarg(dirname(__DIR__) . '/cron/maps_sync.php');
    @exec($php . ' ' . $script . ' > /dev/null 2>&1 &');
    return true;
}

// Full pipeline for one zone. Every state change hits the DB so the UI (and
// a killed worker's successor) always sees the truth.
/** @return array{bool,string} [ok, error] */
function maps_process_one(array $zone): array {
    $id = (int)$zone['id'];
    $db = get_db();
    $mark = static function (string $status, array $extra = []) use ($db, $id): void {
        $sets = 'status = ?';
        $params = [$status];
        foreach ($extra as $k => $v) {
            $sets .= ", {$k} = ?";
            $params[] = $v;
        }
        $params[] = $id;
        try {
            $db->prepare("UPDATE map_zones SET {$sets} WHERE id = ?")->execute($params);
        } catch (Throwable) {
        }
    };

    $viaProxy = ((int)($zone['via_proxy'] ?? 1)) === 1;
    $proxy = $viaProxy ? maps_pick_proxy() : null;
    if ($viaProxy && $proxy === null) {
        $mark('failed', ['error' => 'code:proxy_empty']);
        return [false, 'code:proxy_empty'];
    }

    [$ok, $err] = maps_ensure_cli($viaProxy, $proxy);
    if (!$ok) {
        $mark('failed', ['error' => substr($err, 0, 200)]);
        return [false, $err];
    }

    [$build, $err] = maps_latest_build();
    if ($build === null) {
        $mark('failed', ['error' => substr($err, 0, 200)]);
        return [false, $err];
    }
    $planet = MAPS_PLANET_FILE_URL . $build . '.pmtiles';
    $bbox = $zone['min_lon'] . ',' . $zone['min_lat'] . ',' . $zone['max_lon'] . ',' . $zone['max_lat'];
    $maxzoom = (int)$zone['maxzoom'];

    // ── Sizing: exact bytes before a single tile is kept ──
    $mark('sizing', ['build_key' => $build]);
    [$ok, $out] = maps_cli_exec(
        ['extract', $planet, maps_tiles_dir() . '/zone_' . $id . '.part',
         '--bbox=' . $bbox, '--maxzoom=' . $maxzoom, '--dry-run'],
        $viaProxy ? ['HTTP_PROXY' => $proxy, 'HTTPS_PROXY' => $proxy] : null
    );
    if (!$ok) {
        $mark('failed', ['error' => 'code:sizing_failed|' . substr($out, -160)]);
        return [false, 'code:sizing_failed'];
    }
    if (!preg_match('/archive size of ([\d.]+)\s*([KMGT]?B)/', $out, $sm)) {
        $mark('failed', ['error' => 'code:sizing_empty']);
        return [false, 'code:sizing_empty'];
    }
    $expected = maps_parse_bytes($sm[1], $sm[2]);
    if ($expected === null || $expected <= 0) {
        $mark('failed', ['error' => 'code:sizing_empty']);
        return [false, 'code:sizing_empty'];
    }
    if (!maps_disk_ok($expected)) {
        $mark('failed', ['error' => 'code:disk_short|' . $expected]);
        return [false, 'code:disk_short'];
    }
    $mark('downloading', ['bytes_expected' => $expected, 'bytes_done' => 0]);

    // ── Extract: progress lines stream into the row (throttled) ──
    $lastWrite = 0;
    $onChunk = static function (string $chunk) use ($db, $id, &$lastWrite): void {
        $prog = null;
        foreach (preg_split('/[\r\n]+/', $chunk) as $line) {
            $p = maps_parse_progress((string)$line);
            if ($p !== null) {
                $prog = $p;
            }
        }
        if ($prog === null || (microtime(true) - $lastWrite) < 2.0) {
            return;
        }
        $lastWrite = microtime(true);
        try {
            $db->prepare(
                'UPDATE map_zones SET bytes_done = ?, speed_bps = ?, eta_secs = ? WHERE id = ?'
            )->execute([$prog['done'], $prog['speed'], $prog['eta'], $id]);
        } catch (Throwable) {
        }
    };
    [$ok, $out] = maps_cli_exec(
        ['extract', $planet, maps_tiles_dir() . '/zone_' . $id . '.part',
         '--bbox=' . $bbox, '--maxzoom=' . $maxzoom,
         '--download-threads=' . ($viaProxy ? '1' : '4')],
        $viaProxy ? ['HTTP_PROXY' => $proxy, 'HTTPS_PROXY' => $proxy] : null,
        $onChunk
    );
    $part = maps_tiles_dir() . '/zone_' . $id . '.part';
    if (!$ok || !is_file($part)) {
        $mark('failed', ['error' => 'code:download_failed|' . substr($out, -160)]);
        @unlink($part);
        return [false, 'code:download_failed'];
    }

    // ── Verify + publish atomically ──
    [$ok, $out] = maps_cli_exec(['verify', $part]);
    if (!$ok) {
        $mark('failed', ['error' => 'code:verify_failed']);
        @unlink($part);
        return [false, 'code:verify_failed'];
    }
    $final = maps_tiles_dir() . '/zone_' . $id . '.pmtiles';
    if (!@rename($part, $final)) {
        $mark('failed', ['error' => 'code:publish_failed']);
        @unlink($part);
        return [false, 'code:publish_failed'];
    }
    $mark('ready', [
        'bytes_done' => filesize($final),
        'speed_bps' => null, 'eta_secs' => null, 'error' => null,
    ]);
    audit('maps_zone_ready', null, null, "id={$id} bytes=" . filesize($final));
    return [true, ''];
}

function maps_fmt_bytes(int $n): string {
    if ($n < 1024) {
        return $n . ' B';
    }
    $units = ['KiB', 'MiB', 'GiB', 'TiB'];
    $e = (int)floor(log($n, 1024));
    $e = min($e, 4);
    return round($n / (1024 ** $e), 1) . ' ' . $units[$e - 1];
}

// Zone error column holds either a code ('code:disk_short|12345') or legacy
// free text. Codes translate through admin.maps.err.*; details (byte counts,
// CLI tails) append raw — they are numbers and tool output, never secrets.
function maps_zone_error_text(?string $raw): string {
    if ($raw === null || $raw === '') {
        return '';
    }
    if (!str_starts_with($raw, 'code:')) {
        return $raw;
    }
    $parts = explode('|', substr($raw, 5), 2);
    $key = 'admin.maps.err.' . $parts[0];
    $msg = t($key);
    $text = $msg !== $key ? $msg : $parts[0];
    if (isset($parts[1]) && $parts[1] !== '') {
        $detail = $parts[1];
        if ($parts[0] === 'disk_short' && ctype_digit($detail)) {
            $detail = maps_fmt_bytes((int)$detail);
        }
        $text .= ' — ' . $detail;
    }
    return $text;
}
