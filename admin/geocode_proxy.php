<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/proxy.php';
require_admin();

// Release the session lock during the proxy chain (see tile_proxy.php).
session_write_close();

$q = trim((string)($_GET['q'] ?? ''));
if ($q === '' || strlen($q) > 200) {
    http_response_code(400);
    exit;
}

$url = 'https://nominatim.openstreetmap.org/search?q=' . urlencode($q) . '&format=json&limit=1';

$data = osm_fetch($url);
osm_last_via_flush();
if ($data === false) {
    header('Content-Type: text/plain');
    http_response_code(502);
    exit('geocode fetch failed');
}

header('Content-Type: application/json');
// Re-encode instead of echoing raw upstream bytes: the client is guaranteed
// well-formed JSON no matter what Nominatim returned (and request-derived
// query strings can never smuggle content through).
$decoded = json_decode((string)$data, true);
if (!is_array($decoded)) {
    http_response_code(502);
    exit('{"error":"upstream returned invalid JSON"}');
}
echo json_encode($decoded);
