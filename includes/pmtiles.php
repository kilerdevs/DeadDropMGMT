<?php
declare(strict_types=1);
require_once __DIR__ . '/proxy.php'; // range fetches ride the shared proxy transport (proxy_request_streams)

// ── PMTiles v3 in pure PHP ──────────────────────────────────────────────────
// Reads planet archives and writes zone extracts with no process execution,
// no cURL and no platform binary: the download engine for hosts that cannot
// run go-pmtiles (free shared hosting, Windows, hardened boxes without
// proc_open). Only what the zone pipeline needs is implemented —
// root + leaf directories, gzip-compressed directories, verbatim tile bytes —
// everything else fails closed with an error, never silently.
//
// Layout reference (PMTiles v3, 127-byte header): magic "PMTiles" + u8
// version 3; u64 root/metadata/leaf/tile offsets+lengths; u64 addressed /
// entries / contents counts; u8 clustered, internal compression, tile
// compression, tile type, min/max zoom; i32 bbox ×1e7; u8 center zoom + i32
// center ×1e7. Directories: varint count, then N tile-id deltas (first
// absolute, rest cumulative), N run lengths, N lengths, N offsets (past the
// first entry, a 0 means previous offset + previous length); run length 0
// marks a leaf-directory pointer, never tile data.
//
// Number encoding is manual little-endian throughout (never pack/unpack
// machine-order codes), so archives match byte-for-byte on any platform.

const PMTILES_MAGIC = 'PMTiles';
const PMTILES_VERSION = 3;
const PMTILES_HEADER_LEN = 127;
// Directory compression codes (header byte 97).
const PMTILES_COMP_GZIP = 2;
const PMTILES_COMP_NONE = 1;
// Tile type codes (header byte 99) — copied verbatim, never interpreted.
const PMTILES_TYPE_MVT = 1;
// Fetch tuning: adjacent tile ranges merge into one request under this gap,
// and no single request exceeds the span cap (a failed span is retried whole,
// so spans stay small enough to redo cheaply).
const PMTILES_MERGE_GAP = 65536;
const PMTILES_SPAN_MAX = 8388608;
// Planet metadata is JSON kilobytes; anything past the cap is corruption.
const PMTILES_META_MAX = 1048576;

/** Little-endian uint64 of the 8 bytes at $off. */
function pmtiles_u64(string $b, int $off): int {
    $out = 0;
    for ($i = 7; $i >= 0; $i--) {
        $out = ($out << 8) | ord($b[$off + $i]);
    }
    return $out;
}

/** Little-endian int32 of the 4 bytes at $off. */
function pmtiles_i32(string $b, int $off): int {
    $u = ord($b[$off]) | (ord($b[$off + 1]) << 8) | (ord($b[$off + 2]) << 16) | (ord($b[$off + 3]) << 24);
    return ($u & 0x80000000) !== 0 ? $u - 0x100000000 : $u;
}

function pmtiles_u64le(int $v): string {
    $out = '';
    for ($i = 0; $i < 8; $i++) {
        $out .= chr($v & 0xFF);
        $v >>= 8;
    }
    return $out;
}

function pmtiles_i32le(int $v): string {
    return chr($v & 0xFF) . chr(($v >> 8) & 0xFF) . chr(($v >> 16) & 0xFF) . chr(($v >> 24) & 0xFF);
}

/** Unsigned LEB128. Values here (ids, lengths, offsets) are never negative. */
function pmtiles_vint_encode(int $v): string {
    $out = '';
    do {
        $b = $v & 0x7F;
        $v >>= 7;
        if ($v > 0) {
            $b |= 0x80;
        }
        $out .= chr($b);
    } while ($v > 0);
    return $out;
}

/** @return ?int null on truncation or overflow */
function pmtiles_vint_decode(string $b, int &$pos): ?int {
    $out = 0;
    $shift = 0;
    $n = strlen($b);
    while (true) {
        if ($pos >= $n || $shift > 63) {
            return null;
        }
        $c = ord($b[$pos++]);
        $out |= ($c & 0x7F) << $shift;
        if (($c & 0x80) === 0) {
            return $out;
        }
        $shift += 7;
    }
}

// ── Tile ids ────────────────────────────────────────────────────────────────
// Hilbert curve over the z/x/y grid plus the per-level offset, exactly as the
// PMTiles spec: tileId(z,x,y) = levelOffset(z) + hilbert(z,x,y) with
// levelOffset(z) = (4^z - 1) / 3.

function pmtiles_level_offset(int $z): int {
    return (int)((((1 << (2 * $z)) - 1)) / 3);
}

function pmtiles_hilbert_id(int $z, int $x, int $y): int {
    $id = 0;
    for ($s = (1 << $z) >> 1; $s > 0; $s >>= 1) {
        $rx = (($x & $s) !== 0) ? 1 : 0;
        $ry = (($y & $s) !== 0) ? 1 : 0;
        $id += $s * $s * ((3 * $rx) ^ $ry);
        if ($ry === 0) {
            if ($rx === 1) {
                $x = $s - 1 - $x;
                $y = $s - 1 - $y;
            }
            $t = $x;
            $x = $y;
            $y = $t;
        }
    }
    return $id;
}

function pmtiles_tile_id(int $z, int $x, int $y): int {
    return pmtiles_level_offset($z) + pmtiles_hilbert_id($z, $x, $y);
}

/** WebMercator lon/lat to tile x/y at zoom, clamped to the grid. @return array{int,int} */
function pmtiles_lonlat_to_xy(float $lon, float $lat, int $z): array {
    $n = 1 << $z;
    $x = (int)floor(($lon + 180.0) / 360.0 * $n);
    $lat = max(-85.05112878, min(85.05112878, $lat));
    $m = log(tan(deg2rad($lat)) + 1.0 / cos(deg2rad($lat)));
    $y = (int)floor((1.0 - $m / M_PI) / 2.0 * $n);
    return [max(0, min($n - 1, $x)), max(0, min($n - 1, $y))];
}

/** Every tile id from z0..maxzoom covering the bbox, ascending, deduplicated. @return list<int> */
function pmtiles_covering_ids(float $minLon, float $minLat, float $maxLon, float $maxLat, int $maxzoom): array {
    $seen = [];
    for ($z = 0; $z <= $maxzoom; $z++) {
        [$x0, $y0] = pmtiles_lonlat_to_xy($minLon, $maxLat, $z);
        [$x1, $y1] = pmtiles_lonlat_to_xy($maxLon, $minLat, $z);
        for ($x = min($x0, $x1); $x <= max($x0, $x1); $x++) {
            for ($y = min($y0, $y1); $y <= max($y0, $y1); $y++) {
                $seen[pmtiles_tile_id($z, $x, $y)] = true;
            }
        }
    }
    $ids = array_keys($seen);
    sort($ids, SORT_NUMERIC);
    return $ids;
}

// ── HTTP ranges without cURL ────────────────────────────────────────────────
// cURL first when present; the shared proxy transport otherwise (direct,
// HTTP-proxy forwarding, CONNECT tunnels, SOCKS — every scheme works on
// both). Servers that ignore Range fail closed: a 200 to a nonzero offset,
// or a short 206, is corruption, never silently accepted.

/** @return array{?string,string} [body-or-null, error] */
function pmtiles_http_range(string $url, int $off, int $len, ?string $proxy, int $timeout = 120): array {
    if ($off < 0 || $len < 0) {
        return [null, 'bad range'];
    }
    if ($len === 0) {
        return ['', ''];
    }
    if (host_has_curl()) {
        return pmtiles_range_curl($url, $off, $len, $proxy, $timeout);
    }
    return pmtiles_range_stream($url, $off, $len, $proxy, $timeout);
}

/** Proxy usable on THIS transport, or null when no proxy is wanted. Every scheme works curl-less now. */
function pmtiles_proxy_usable(?string $proxy): bool {
    if ($proxy === null) {
        return true;
    }
    return proxy_parse($proxy) !== null;
}

/** @return array{?string,string} */
function pmtiles_range_curl(string $url, int $off, int $len, ?string $proxy, int $timeout): array {
    $ch = curl_init($url);
    if ($ch === false) {
        return [null, 'could not start request'];
    }
    $cap = $len + 1048576; // servers that ignore Range must not fill memory
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_RANGE => $off . '-' . ($off + $len - 1),
        CURLOPT_USERAGENT => 'DeadDropMGMT/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_NOPROGRESS => false,
        CURLOPT_PROGRESSFUNCTION => static function ($ch, $dlTotal, $dlNow) use ($cap): int {
            return $dlNow > $cap ? 1 : 0;
        },
    ]);
    if ($proxy !== null) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit
    if (!is_string($body)) {
        return [null, $err !== '' ? $err : 'request failed'];
    }
    if ($code === 206) {
        return strlen($body) === $len ? [$body, ''] : [null, 'short range body'];
    }
    if ($code === 200 && $off === 0) {
        return strlen($body) >= $len ? [substr($body, 0, $len), ''] : [null, 'short body'];
    }
    return [null, 'HTTP ' . $code];
}

/** @return array{?string,string} */
function pmtiles_range_stream(string $url, int $off, int $len, ?string $proxy, int $timeout): array {
    // Redirects followed (planet hosts move); the cap is the exact length —
    // a 200 to offset 0 keeps its first $len bytes like the old wrapper did,
    // anything longer is the caller's exact-length check below.
    $res = proxy_request_streams('GET', $url,
        ['Range: bytes=' . $off . '-' . ($off + $len - 1)], $proxy, $timeout, $len);
    if ($res['code'] === 206) {
        return strlen($res['body']) === $len ? [$res['body'], ''] : [null, 'short range body'];
    }
    if ($res['code'] === 200 && $off === 0) {
        return strlen($res['body']) >= $len ? [substr($res['body'], 0, $len), ''] : [null, 'short body'];
    }
    return [null, $res['code'] === 0 ? 'request failed' : 'HTTP ' . $res['code']];
}

// Whether the pure-PHP engine can run here at all: directory math needs
// zlib, HTTPS needs a transport (cURL, or raw sockets with OpenSSL — the
// http wrapper's allow_url_fopen is no longer involved).
function pmtiles_transport_ok(): bool {
    if (!extension_loaded('zlib')) {
        return false;
    }
    if (host_has_curl()) {
        return true;
    }
    return extension_loaded('openssl');
}

// ── Extract planning ────────────────────────────────────────────────────────
// A plan resolves every wanted tile to its planet offset once, then merges
// adjacent ranges so a city extract costs dozens of requests, not thousands
// (one TLS handshake per tile would take longer than the bytes).
// Sidecar JSON shape: {url,proxy,bbox:[4],maxzoom,tileType,tileComp,
// outMaxZoom,meta:string(base64),entries:[[tileId,srcOff,srcLen]... by src
// offset],spans:[[start,end]...],expected:int}.

/**
 * Walk the planet directories for the bbox tiles.
 * @return array{?array,string} [plan-or-null, error]
 */
function pmtiles_build_plan(string $url, ?string $proxy, float $minLon, float $minLat, float $maxLon, float $maxLat, int $maxzoom): array {
    [$hRaw, $err] = pmtiles_http_range($url, 0, PMTILES_HEADER_LEN, $proxy, 60);
    if ($hRaw === null) {
        return [null, 'header: ' . $err];
    }
    $hdr = pmtiles_parse_header($hRaw);
    if ($hdr === null) {
        return [null, 'bad header'];
    }
    [$rootRaw, $err] = pmtiles_http_range($url, $hdr['rootOff'], $hdr['rootLen'], $proxy, 60);
    if ($rootRaw === null) {
        return [null, 'root directory: ' . $err];
    }
    $root = pmtiles_parse_dir($rootRaw, $hdr['intComp']);
    if ($root === null) {
        return [null, 'bad root directory'];
    }
    $meta = '';
    if ($hdr['metaLen'] > 0) {
        if ($hdr['metaLen'] > PMTILES_META_MAX) {
            return [null, 'metadata too large'];
        }
        [$meta, $err] = pmtiles_http_range($url, $hdr['metaOff'], $hdr['metaLen'], $proxy, 60);
        if ($meta === null) {
            return [null, 'metadata: ' . $err];
        }
    }
    $leaves = [];
    $leafErr = '';
    $fetchLeaf = static function (int $off, int $len) use ($url, $proxy, $hdr, &$leaves, &$leafErr): ?array {
        $key = $off . ':' . $len;
        if (!array_key_exists($key, $leaves)) {
            if ($len <= 0 || $len > PMTILES_SPAN_MAX) {
                $leafErr = 'bad leaf directory';
                return null;
            }
            [$leafRaw, $err] = pmtiles_http_range($url, $hdr['leafOff'] + $off, $len, $proxy, 60);
            if ($leafRaw === null) {
                $leafErr = 'leaf directory: ' . $err;
                return null;
            }
            $leaf = pmtiles_parse_dir($leafRaw, $hdr['intComp']);
            if ($leaf === null) {
                $leafErr = 'bad leaf directory';
                return null;
            }
            $leaves[$key] = $leaf;
        }
        return $leaves[$key];
    };
    $wanted = pmtiles_covering_ids($minLon, $minLat, $maxLon, $maxLat, $maxzoom);
    $entries = [];
    foreach ($wanted as $id) {
        $e = pmtiles_lookup_id($root, $fetchLeaf, $id);
        if ($e === null) {
            if ($leafErr !== '') {
                // A failed leaf fetch must fail the plan: skipping would
                // silently publish an extract with holes.
                return [null, $leafErr];
            }
            continue; // tile absent upstream (ocean, unmapped) — extracts skip it
        }
        if ($e['len'] <= 0) {
            return [null, 'bad tile entry'];
        }
        if ($e['off'] < 0 || $e['off'] + $e['len'] > $hdr['tileLen']) {
            return [null, 'tile outside data section'];
        }
        $entries[] = [$id, $hdr['tileOff'] + $e['off'], $e['len']];
    }
    if ($entries === []) {
        return [null, 'empty'];
    }
    usort($entries, static fn(array $a, array $b): int => $a[1] <=> $b[1] ?: $a[0] <=> $b[0]);
    // Merge adjacent ranges (gap cap) into spans for fetching.
    $spans = [];
    [$s, $e] = [$entries[0][1], $entries[0][1] + $entries[0][2]];
    foreach (array_slice($entries, 1) as $en) {
        if ($en[1] - $e <= PMTILES_MERGE_GAP && $en[1] + $en[2] - $s <= PMTILES_SPAN_MAX) {
            $e = max($e, $en[1] + $en[2]);
        } else {
            $spans[] = [$s, $e];
            [$s, $e] = [$en[1], $en[1] + $en[2]];
        }
    }
    $spans[] = [$s, $e];
    $dataBytes = 0;
    foreach ($entries as $en) {
        $dataBytes += $en[2];
    }
    // Sizing: header + gzipped root estimate + metadata + tile bytes. The
    // directory over-estimates slightly (varints); the disk check keeps a
    // 512 MiB headroom, so exactness is not required here.
    $expected = PMTILES_HEADER_LEN + count($entries) * 8 + 256 + strlen($meta) + $dataBytes;
    return [[
        'url' => $url, 'proxy' => $proxy,
        'bbox' => [$minLon, $minLat, $maxLon, $maxLat], 'maxzoom' => $maxzoom,
        'tileType' => $hdr['tileType'], 'tileComp' => $hdr['tileComp'],
        'outMaxZoom' => min($maxzoom, $hdr['maxZoom']),
        'meta' => base64_encode($meta),
        'entries' => $entries, 'spans' => $spans, 'expected' => $expected,
    ], ''];
}

/**
 * Fetch due spans into $tilesPath, resumable by construction: spans land
 * whole (a failed span appends nothing), so the file size is always a span
 * boundary and a later call continues where this one stopped.
 * Progress callback receives (fetchedBytes, expectedBytes) after each span.
 * @param array{url:string,proxy:?string,bbox:list<float>,maxzoom:int,tileType:int,tileComp:int,outMaxZoom:int,meta:string,entries:list<array{int,int,int}>,spans:list<array{int,int}>,expected:int} $plan
 * @return array{string,string,int} [done|more|failed, error, fetchedBytes]
 */
function pmtiles_fetch_due(array $plan, string $tilesPath, int $timeBox, ?callable $progress = null): array {
    $have = is_file($tilesPath) ? (int)@filesize($tilesPath) : 0;
    $cumulative = 0;
    $spans = $plan['spans'];
    $start = microtime(true);
    $fh = @fopen($tilesPath, $have > 0 ? 'ab' : 'wb');
    if (!is_resource($fh)) {
        return ['failed', 'cannot write tile data', $have];
    }
    $status = 'done';
    $err = '';
    foreach ($spans as [$s, $e]) {
        $spanLen = $e - $s;
        if ($cumulative + $spanLen <= $have) {
            $cumulative += $spanLen; // already on disk from an earlier slice
            continue;
        }
        if ($timeBox > 0 && (microtime(true) - $start) >= $timeBox) {
            $status = 'more';
            break;
        }
        [$body, $err] = pmtiles_http_range((string)$plan['url'], $s, $spanLen, $plan['proxy']);
        if ($body === null) {
            $status = 'failed';
            break;
        }
        if (fwrite($fh, $body) !== strlen($body)) {
            $status = 'failed';
            $err = 'cannot write tile data';
            break;
        }
        $cumulative += $spanLen;
        if ($progress !== null) {
            $progress($cumulative, (int)$plan['expected']);
        }
    }
    fclose($fh);
    return [$status, $err, $cumulative];
}

// ── Archive assembly + verification ─────────────────────────────────────────
// Tiles stream from the span file (src-offset order) into tile-id order; the
// root directory then compresses contiguous runs to zero-offset entries, the
// same clustered layout go-pmtiles writes.

/** Encode entries (id-ascending) to a gzipped root directory. Data entries
 * carry run 1; callers may pass run 0 for leaf-directory pointers. */
function pmtiles_dir_encode(array $entries): string {
    $n = count($entries);
    $out = pmtiles_vint_encode($n);
    $prev = 0;
    foreach ($entries as $i => $e) {
        $out .= pmtiles_vint_encode($i === 0 ? $e['id'] : $e['id'] - $prev);
        $prev = $e['id'];
    }
    foreach ($entries as $e) {
        $out .= pmtiles_vint_encode($e['run'] ?? 1);
    }
    foreach ($entries as $e) {
        $out .= pmtiles_vint_encode($e['len']);
    }
    $prevOff = 0;
    $prevLen = 0;
    foreach ($entries as $i => $e) {
        $contig = $i > 0 && $e['off'] === $prevOff + $prevLen;
        // Mirror the parse bias: stored offsets are true + 1, 0 compresses
        // the contiguous case — the clustered layout go-pmtiles writes.
        $out .= pmtiles_vint_encode($contig ? 0 : $e['off'] + 1);
        $prevOff = $e['off'];
        $prevLen = $e['len'];
    }
    $gz = gzencode($out, 9);
    return is_string($gz) ? $gz : '';
}

/**
 * @param array{url:string,proxy:?string,bbox:list<float>,maxzoom:int,tileType:int,tileComp:int,outMaxZoom:int,meta:string,entries:list<array{int,int,int}>,spans:list<array{int,int}>,expected:int} $plan
 * @return ?string null when the span map cannot locate an entry (corrupt plan/state)
 */
function pmtiles_assemble(array $plan, string $tilesPath, string $destPath): ?string {
    // Entry order for the directory: id-ascending. Data order on disk:
    // src-offset ascending (span order). Map src offset → file position via
    // the cumulative span layout (deterministic from the plan).
    $byId = [];
    foreach ($plan['entries'] as [$t, $o, $l]) {
        $byId[] = ['id' => $t, 'src' => $o, 'len' => $l];
    }
    usort($byId, static fn(array $a, array $b): int => $a['id'] <=> $b['id']);
    $spanBase = [];
    $pos = 0;
    foreach ($plan['spans'] as [$s, $e]) {
        $spanBase[] = [$s, $pos];
        $pos += $e - $s;
    }
    $locate = static function (int $src) use ($spanBase, $plan): ?int {
        $spans = $plan['spans'];
        $lo = 0;
        $hi = count($spans) - 1;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            if ($src < $spans[$mid][0]) {
                $hi = $mid - 1;
            } elseif ($src >= $spans[$mid][1]) {
                $lo = $mid + 1;
            } else {
                return $spanBase[$mid][1] + ($src - $spans[$mid][0]);
            }
        }
        return null;
    };
    // Final data offsets are cumulative in id order — known before reading.
    $dirEntries = [];
    $doff = 0;
    foreach ($byId as $i => $e) {
        $at = $locate($e['src']);
        if ($at === null) {
            return null;
        }
        $dirEntries[] = ['id' => $e['id'], 'len' => $e['len'], 'off' => $doff, 'at' => $at];
        $doff += $e['len'];
    }
    $rootDir = pmtiles_dir_encode($dirEntries);
    if ($rootDir === '') {
        return null;
    }
    $meta = base64_decode((string)$plan['meta'], true);
    if (!is_string($meta)) {
        return null;
    }
    [$minLon, $minLat, $maxLon, $maxLat] = $plan['bbox'];
    $maxzoom = (int)$plan['outMaxZoom'];
    $n = count($dirEntries);
    $metaOff = PMTILES_HEADER_LEN + strlen($rootDir);
    $tileOff = $metaOff + strlen($meta);
    $header = PMTILES_MAGIC . chr(PMTILES_VERSION)
        . pmtiles_u64le(PMTILES_HEADER_LEN) . pmtiles_u64le(strlen($rootDir))
        . pmtiles_u64le($metaOff) . pmtiles_u64le(strlen($meta))
        . pmtiles_u64le($tileOff) . pmtiles_u64le(0)
        . pmtiles_u64le($tileOff) . pmtiles_u64le($doff)
        . pmtiles_u64le($n) . pmtiles_u64le($n) . pmtiles_u64le($n)
        . chr(1) . chr(PMTILES_COMP_GZIP) . chr((int)$plan['tileComp']) . chr((int)$plan['tileType'])
        . chr(0) . chr($maxzoom)
        . pmtiles_i32le((int)round($minLon * 1e7)) . pmtiles_i32le((int)round($minLat * 1e7))
        . pmtiles_i32le((int)round($maxLon * 1e7)) . pmtiles_i32le((int)round($maxLat * 1e7))
        . chr($maxzoom)
        . pmtiles_i32le((int)round(($minLon + $maxLon) / 2 * 1e7))
        . pmtiles_i32le((int)round(($minLat + $maxLat) / 2 * 1e7));
    if (strlen($header) !== PMTILES_HEADER_LEN) {
        return null;
    }
    $src = @fopen($tilesPath, 'rb');
    if (!is_resource($src)) {
        return null;
    }
    $dst = @fopen($destPath, 'wb');
    if (!is_resource($dst)) {
        fclose($src);
        return null;
    }
    $ok = fwrite($dst, $header) === PMTILES_HEADER_LEN
        && fwrite($dst, $rootDir) === strlen($rootDir)
        && (strlen($meta) === 0 || fwrite($dst, $meta) === strlen($meta));
    foreach ($dirEntries as $e) {
        if (!$ok) {
            break;
        }
        if (fseek($src, $e['at']) !== 0) {
            $ok = false;
            break;
        }
        $left = $e['len'];
        while ($left > 0 && $ok) {
            $chunk = fread($src, min(1048576, $left));
            if (!is_string($chunk) || $chunk === '') {
                $ok = false;
                break;
            }
            $ok = fwrite($dst, $chunk) === strlen($chunk);
            $left -= strlen($chunk);
        }
    }
    fclose($src);
    fclose($dst);
    if (!$ok) {
        @unlink($destPath);
        return null;
    }
    return $destPath;
}

/**
 * Structural verification of a finished archive: header, directory, every
 * entry inside the tile section with gzip magic (planet tiles are gzip MVT).
 */
function pmtiles_verify_path(string $path): bool {
    $size = @filesize($path);
    if (!is_int($size) || $size < PMTILES_HEADER_LEN + 1) {
        return false;
    }
    $fh = @fopen($path, 'rb');
    if (!is_resource($fh)) {
        return false;
    }
    $hRaw = fread($fh, PMTILES_HEADER_LEN);
    if (!is_string($hRaw) || strlen($hRaw) !== PMTILES_HEADER_LEN) {
        fclose($fh);
        return false;
    }
    $hdr = pmtiles_parse_header($hRaw);
    if ($hdr === null || $hdr['leafLen'] !== 0) {
        fclose($fh);
        return false;
    }
    if ($hdr['rootOff'] !== PMTILES_HEADER_LEN
        || $hdr['rootOff'] + $hdr['rootLen'] + $hdr['metaLen'] + $hdr['tileLen'] !== $size
        || $hdr['tileOff'] !== $hdr['rootOff'] + $hdr['rootLen'] + $hdr['metaLen']
    ) {
        fclose($fh);
        return false;
    }
    fseek($fh, $hdr['rootOff']);
    $rootRaw = fread($fh, $hdr['rootLen']);
    if (!is_string($rootRaw) || strlen($rootRaw) !== $hdr['rootLen']) {
        fclose($fh);
        return false;
    }
    $entries = pmtiles_parse_dir($rootRaw, $hdr['intComp']);
    if ($entries === null) {
        fclose($fh);
        return false;
    }
    $data = 0;
    foreach ($entries as $e) {
        if ($e['run'] !== 1 || $e['len'] <= 0
            || $e['off'] < 0 || $e['off'] + $e['len'] > $hdr['tileLen']
        ) {
            fclose($fh);
            return false;
        }
        $data += $e['len'];
        if ($hdr['tileComp'] === PMTILES_COMP_GZIP) {
            fseek($fh, $hdr['tileOff'] + $e['off']);
            $magic = fread($fh, 2);
            if ($magic !== "\x1f\x8b") {
                fclose($fh);
                return false;
            }
        }
    }
    fclose($fh);
    return $data === $hdr['tileLen']
        && count($entries) === $hdr['nEntries']
        && count($entries) === $hdr['nAddr'];
}

/** Plan sidecar surroundings: atomic-enough for a worker file (write tmp + rename). */
function pmtiles_plan_save(string $path, array $plan): bool {
    $tmp = $path . '.tmp';
    if (@file_put_contents($tmp, json_encode($plan, JSON_UNESCAPED_SLASHES)) === false) {
        return false;
    }
    return @rename($tmp, $path);
}

/**
 * Validate a decoded plan (sidecars are untrusted bytes: a half-written,
 * hand-edited or version-skewed file must rebuild, never misdirect).
 * @return ?array{url:string,proxy:?string,bbox:list<float>,maxzoom:int,tileType:int,tileComp:int,outMaxZoom:int,meta:string,entries:list<array{int,int,int}>,spans:list<array{int,int}>,expected:int}
 */
function pmtiles_plan_validate(mixed $plan): ?array {
    if (!is_array($plan)) {
        return null;
    }
    $url = $plan['url'] ?? null;
    if (!is_string($url) || $url === '') {
        return null;
    }
    $proxy = $plan['proxy'] ?? null;
    if ($proxy !== null && !is_string($proxy)) {
        return null;
    }
    $rawBox = $plan['bbox'] ?? null;
    if (!is_array($rawBox) || count($rawBox) !== 4) {
        return null;
    }
    $bbox = [];
    foreach ($rawBox as $v) {
        if (!is_int($v) && !is_float($v)) {
            return null;
        }
        $bbox[] = (float)$v;
    }
    $ints = [];
    foreach (['maxzoom', 'tileType', 'tileComp', 'outMaxZoom', 'expected'] as $k) {
        $v = $plan[$k] ?? null;
        if (!is_int($v)) {
            return null;
        }
        $ints[$k] = $v;
    }
    if ($ints['expected'] <= 0 || $ints['maxzoom'] < 0 || $ints['maxzoom'] > 31) {
        return null;
    }
    $meta = $plan['meta'] ?? null;
    if (!is_string($meta)) {
        return null;
    }
    $rawEntries = $plan['entries'] ?? null;
    if (!is_array($rawEntries) || $rawEntries === []) {
        return null;
    }
    $entries = [];
    foreach ($rawEntries as $e) {
        if (!is_array($e) || count($e) !== 3) {
            return null;
        }
        [$t, $o, $l] = array_values($e);
        if (!is_int($t) || !is_int($o) || !is_int($l) || $t < 0 || $o < 0 || $l <= 0) {
            return null;
        }
        $entries[] = [$t, $o, $l];
    }
    $rawSpans = $plan['spans'] ?? null;
    if (!is_array($rawSpans) || $rawSpans === []) {
        return null;
    }
    $spans = [];
    foreach ($rawSpans as $s) {
        if (!is_array($s) || count($s) !== 2) {
            return null;
        }
        [$a, $b] = array_values($s);
        if (!is_int($a) || !is_int($b) || $a < 0 || $b <= $a) {
            return null;
        }
        $spans[] = [$a, $b];
    }
    return [
        'url' => $url, 'proxy' => $proxy, 'bbox' => $bbox,
        'maxzoom' => $ints['maxzoom'], 'tileType' => $ints['tileType'],
        'tileComp' => $ints['tileComp'], 'outMaxZoom' => $ints['outMaxZoom'],
        'meta' => $meta, 'entries' => $entries, 'spans' => $spans,
        'expected' => $ints['expected'],
    ];
}

/** @return ?array{url:string,proxy:?string,bbox:list<float>,maxzoom:int,tileType:int,tileComp:int,outMaxZoom:int,meta:string,entries:list<array{int,int,int}>,spans:list<array{int,int}>,expected:int} null on missing/corrupt plan */
function pmtiles_plan_load(string $path): ?array {
    if (!is_file($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if (!is_string($raw)) {
        return null;
    }
    try {
        $plan = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return null;
    }
    return pmtiles_plan_validate($plan);
}


// ── Archive reading ─────────────────────────────────────────────────────────

/**
 * Parse and validate the 127-byte header.
 * @return ?array{rootOff:int,rootLen:int,metaOff:int,metaLen:int,leafOff:int,leafLen:int,tileOff:int,tileLen:int,nAddr:int,nEntries:int,nContents:int,clustered:int,intComp:int,tileComp:int,tileType:int,minZoom:int,maxZoom:int,minLon:float,minLat:float,maxLon:float,maxLat:float,centerZoom:int,centerLon:float,centerLat:float}
 */
function pmtiles_parse_header(string $b): ?array {
    if (strlen($b) !== PMTILES_HEADER_LEN
        || substr($b, 0, 7) !== PMTILES_MAGIC
        || ord($b[7]) !== PMTILES_VERSION
    ) {
        return null;
    }
    return [
        'rootOff' => pmtiles_u64($b, 8), 'rootLen' => pmtiles_u64($b, 16),
        'metaOff' => pmtiles_u64($b, 24), 'metaLen' => pmtiles_u64($b, 32),
        'leafOff' => pmtiles_u64($b, 40), 'leafLen' => pmtiles_u64($b, 48),
        'tileOff' => pmtiles_u64($b, 56), 'tileLen' => pmtiles_u64($b, 64),
        'nAddr' => pmtiles_u64($b, 72), 'nEntries' => pmtiles_u64($b, 80),
        'nContents' => pmtiles_u64($b, 88),
        'clustered' => ord($b[96]), 'intComp' => ord($b[97]),
        'tileComp' => ord($b[98]), 'tileType' => ord($b[99]),
        'minZoom' => ord($b[100]), 'maxZoom' => ord($b[101]),
        'minLon' => pmtiles_i32($b, 102) / 1e7, 'minLat' => pmtiles_i32($b, 106) / 1e7,
        'maxLon' => pmtiles_i32($b, 110) / 1e7, 'maxLat' => pmtiles_i32($b, 114) / 1e7,
        'centerZoom' => ord($b[118]),
        'centerLon' => pmtiles_i32($b, 119) / 1e7, 'centerLat' => pmtiles_i32($b, 123) / 1e7,
    ];
}

/**
 * Decode one directory (decompressing when needed) with offset resolution.
 * @return ?list<array{id:int,run:int,len:int,off:int}> null on any corruption
 */
function pmtiles_parse_dir(string $raw, int $comp): ?array {
    if ($comp === PMTILES_COMP_GZIP) {
        $d = @gzdecode($raw);
        if (!is_string($d)) {
            return null;
        }
        $raw = $d;
    } elseif ($comp !== PMTILES_COMP_NONE) {
        return null;
    }
    $pos = 0;
    $n = pmtiles_vint_decode($raw, $pos);
    if ($n === null || $n < 0 || $n > 5000000) {
        return null;
    }
    $ids = [];
    $last = 0;
    for ($i = 0; $i < $n; $i++) {
        $v = pmtiles_vint_decode($raw, $pos);
        if ($v === null) {
            return null;
        }
        $last = ($i === 0) ? $v : $last + $v;
        if ($last < 0) {
            return null;
        }
        $ids[] = $last;
    }
    $runs = [];
    for ($i = 0; $i < $n; $i++) {
        $v = pmtiles_vint_decode($raw, $pos);
        if ($v === null) {
            return null;
        }
        $runs[] = $v;
    }
    $lens = [];
    for ($i = 0; $i < $n; $i++) {
        $v = pmtiles_vint_decode($raw, $pos);
        if ($v === null || $v < 0) {
            return null;
        }
        $lens[] = $v;
    }
    $out = [];
    $prevOff = 0;
    $prevLen = 0;
    for ($i = 0; $i < $n; $i++) {
        $v = pmtiles_vint_decode($raw, $pos);
        if ($v === null || $v < 0) {
            return null;
        }
        // Stored offsets are biased +1 (0, past the first entry, means
        // "directly after the previous entry"); true offsets are -1.
        if ($i === 0) {
            if ($v < 1) {
                return null;
            }
            $off = $v - 1;
        } else {
            $off = $v === 0 ? $prevOff + $prevLen : $v - 1;
        }
        $out[] = ['id' => $ids[$i], 'run' => $runs[$i], 'len' => $lens[$i], 'off' => $off];
        $prevOff = $off;
        $prevLen = $lens[$i];
    }
    return $out;
}

/** Binary search by tile id (directories are id-ascending). */
function pmtiles_find_entry(array $entries, int $id): ?array {
    $lo = 0;
    $hi = count($entries) - 1;
    while ($lo <= $hi) {
        $mid = ($lo + $hi) >> 1;
        $midId = $entries[$mid]['id'];
        if ($midId === $id) {
            return $entries[$mid];
        }
        if ($midId < $id) {
            $lo = $mid + 1;
        } else {
            $hi = $mid - 1;
        }
    }
    return null;
}

/**
 * Resolve one tile id through root + leaf levels. Leaf pointers cover id
 * ranges starting at their own id, so the lookup takes the greatest entry
 * at or below the wanted id and descends when that entry is a leaf (run
 * 0); a data entry below the wanted id means the tile is absent.
 * $fetchLeaf(off, len) fetches+parses one leaf directory (cached by caller).
 * @return ?array{id:int,run:int,len:int,off:int} data entry or null
 */
function pmtiles_lookup_id(array $entries, callable $fetchLeaf, int $id, int $depth = 0): ?array {
    if ($depth > 3) {
        return null;
    }
    $cand = null;
    $lo = 0;
    $hi = count($entries) - 1;
    while ($lo <= $hi) {
        $mid = ($lo + $hi) >> 1;
        $midId = $entries[$mid]['id'];
        if ($midId === $id) {
            $cand = $entries[$mid];
            break;
        }
        if ($midId < $id) {
            $cand = $entries[$mid];
            $lo = $mid + 1;
        } else {
            $hi = $mid - 1;
        }
    }
    if ($cand === null) {
        return null;
    }
    if ($cand['run'] === 0) {
        $leaf = $fetchLeaf($cand['off'], $cand['len']);
        if ($leaf === null) {
            return null;
        }
        return pmtiles_lookup_id($leaf, $fetchLeaf, $id, $depth + 1);
    }
    return $cand['id'] === $id ? $cand : null;
}
