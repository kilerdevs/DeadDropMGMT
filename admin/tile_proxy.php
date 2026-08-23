<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/proxy.php';
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

$cacheFile = dirname(__DIR__) . "/cache/osm_tiles/$z/$x/$y.png";
$cacheTtl  = 7 * 24 * 3600;

if (is_file($cacheFile) && (time() - filemtime($cacheFile)) < $cacheTtl) {
    header('Content-Type: image/png');
    header('Cache-Control: private, max-age=86400');
    readfile($cacheFile);
    exit;
}

$subdomain = ['a', 'b', 'c'][random_int(0, 2)];
$url = "https://$subdomain.tile.openstreetmap.org/$z/$x/$y.png";

$data = osm_fetch($url);

// Record which proxy served the request (re-opens session briefly).
osm_last_via_flush();

if ($data === false) {
    header('Content-Type: text/plain');
    http_response_code(502);
    exit('tile fetch failed');
}

$dir = dirname($cacheFile);
if (!is_dir($dir)) {
    @mkdir($dir, 0750, true);
}
@file_put_contents($cacheFile, $data);

header('Content-Type: image/png');
header('Cache-Control: private, max-age=86400');
echo $data;
