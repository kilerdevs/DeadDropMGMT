<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';
require_admin();

// Release the session lock immediately — a slow proxy chain must not lock
// out every other admin page the user tries to open meanwhile. The badge
// info is staged by osm_fetch and written back at the end via
// osm_last_via_flush(), which re-opens the session only for milliseconds.
session_write_close();

$z = filter_input(INPUT_GET, 'z', FILTER_VALIDATE_INT);
$x = filter_input(INPUT_GET, 'x', FILTER_VALIDATE_INT);
$y = filter_input(INPUT_GET, 'y', FILTER_VALIDATE_INT);

if ($z === null || $z === false || $z < 0 || $z > 19
    || $x === null || $x === false || $x < 0 || $x >= (1 << $z)
    || $y === null || $y === false || $y < 0 || $y >= (1 << $z)
) {
    http_response_code(400);
    exit;
}

// Street-level tiles are cached PER ACCOUNT: a shared cache answers a hit
// instantly and a miss slowly, so any courier could probe z13+ tiles around
// a city and learn where the owner or other couriers recently looked — i.e.
// roughly where their pins are. Overview zooms reveal nothing and stay shared.
$cacheFile = dirname(__DIR__) . '/cache/osm_tiles/' . ($z >= 13 ? 'u' . current_user_id() . '/' : '') . "$z/$x/$y.png";
$cacheTtl  = 7 * 24 * 3600;

if (is_file($cacheFile)) {
    $cmtime = (int)@filemtime($cacheFile);
    $csize  = (int)@filesize($cacheFile);
    if ((time() - $cmtime) < $cacheTtl) {
        // Validators over the cached bytes: repeat views revalidate with a
        // cheap 304 instead of re-downloading the PNG. max-age counts down
        // the remaining lifetime, not the full TTL.
        $etag = '"' . dechex($cmtime) . '-' . dechex($csize) . '"';
        header('Content-Type: image/png');
        header('Cache-Control: private, max-age=' . max(0, $cacheTtl - (time() - $cmtime)));
        header('ETag: ' . $etag);
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $cmtime) . ' GMT');
        $none = trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? ''));
        if ($none === $etag || $none === '*') {
            http_response_code(304);
            exit;
        }
        $since = trim((string)($_SERVER['HTTP_IF_MODIFIED_SINCE'] ?? ''));
        if ($none === '' && $since !== '' && ($st = strtotime($since)) !== false && $st >= $cmtime) {
            http_response_code(304);
            exit;
        }
        readfile($cacheFile);
        exit;
    }
}

// Cache misses reach OSM from THIS server's address: budget them per admin
// so no account (a courier's included) can turn the panel into a tile
// scraper that gets the server banned. Hits above never count.
$budget = rl_hit('admin_tiles', 600, 60, 'u:' . current_user_id());
if ($budget['blocked']) {
    header('Retry-After: ' . max(1, (int)$budget['remaining']));
    http_response_code(429);
    exit;
}

$subdomain = ['a', 'b', 'c'][random_int(0, 2)];
$url = "https://$subdomain.tile.openstreetmap.org/$z/$x/$y.png";

$data = osm_fetch($url, 1048576); // dense-vector tiles stay well under 1 MiB

// Record which proxy served the request (re-opens session briefly).
osm_last_via_flush();

// The pool proxies are public strangers: only a genuine PNG is served or
// cached, whatever else they answer with 200.
if ($data !== false && !osm_is_png($data)) {
    $data = false;
}

if ($data === false) {
    header('Content-Type: text/plain');
    http_response_code(502);
    exit('tile fetch failed');
}

$dir = dirname($cacheFile);
if (!is_dir($dir)) {
    @mkdir($dir, 0750, true);
}
// Atomic publish: readers never see a half-written PNG (and a crash never
// leaves a torn file that later reads as a valid cache hit).
$tmp = $cacheFile . '.tmp';
if (@file_put_contents($tmp, $data) === strlen($data)) {
    @rename($tmp, $cacheFile);
} else {
    @unlink($tmp);
}

header('Content-Type: image/png');
header('Cache-Control: private, max-age=86400');
echo $data;
