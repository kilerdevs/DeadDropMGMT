<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/auth.php';
require_admin();

$q = trim((string)($_GET['q'] ?? ''));
if ($q === '' || strlen($q) > 200) {
    http_response_code(400);
    exit;
}

$url = 'https://nominatim.openstreetmap.org/search?q=' . urlencode($q) . '&format=json&limit=1';

$context = stream_context_create(['http' => [
    'method'  => 'GET',
    'header'  => "User-Agent: DeadDropMGMT/1.0 (admin panel geocode proxy)\r\nAccept-Language: pl\r\n",
    'timeout' => 5,
]]);

$data = @file_get_contents($url, false, $context);
if ($data === false) {
    http_response_code(502);
    exit;
}

header('Content-Type: application/json');
echo $data;
