<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';
require_admin();

// Release the session lock during the proxy chain (see tile_proxy.php).
session_write_close();

// Reverse mode for pin labels: ?reverse=1&lat=..&lon=.. answers
// {"country": .., "state": ..} ('' when Nominatim knows no name for the
// half). The client shows the joined label and must never fall back to raw
// coordinates — lat/lng stay out of owner-facing surfaces by policy.
if (($_GET['reverse'] ?? '') === '1') {
    $lat = is_numeric($_GET['lat'] ?? null) ? (float)$_GET['lat'] : null;
    $lon = is_numeric($_GET['lon'] ?? null) ? (float)$_GET['lon'] : null;
    $addr = ($lat === null || $lon === null) ? null : osm_reverse_lookup($lat, $lon);
    if ($addr === null) {
        header('Content-Type: text/plain');
        http_response_code(502);
        exit('reverse lookup failed');
    }
    osm_last_via_flush();
    header('Content-Type: application/json');
    echo json_encode([
        'country' => trim((string)($addr['country'] ?? '')),
        'state'   => trim((string)($addr['state'] ?? '')),
    ]);
    exit;
}

$q = trim(get_string('q'));
if ($q === '' || strlen($q) > 200) {
    http_response_code(400);
    exit;
}

$url = 'https://nominatim.openstreetmap.org/search?q=' . urlencode($q) . '&format=json&limit=1';

$data = osm_fetch($url, 262144); // Nominatim limit=1 answers are small JSON
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
