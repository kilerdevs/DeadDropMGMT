<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/proxy.php';
require_admin();

$q = trim((string)($_GET['q'] ?? ''));
if ($q === '' || strlen($q) > 200) {
    http_response_code(400);
    exit;
}

$url = 'https://nominatim.openstreetmap.org/search?q=' . urlencode($q) . '&format=json&limit=1';

$data = osm_fetch($url);
if ($data === false) {
    header('Content-Type: text/plain');
    http_response_code(502);
    exit('geocode fetch failed');
}

header('Content-Type: application/json');
echo $data;
