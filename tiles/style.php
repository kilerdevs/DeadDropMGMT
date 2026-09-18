<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';
require_admin();

// Self-hosted map style for the admin panel (MapLibre v8 JSON). The zone
// list is server-side: the browser only ever learns the files it may fetch.
// Session lock released — tile range requests never touch PHP, but the
// style fetch itself must not block other admin pages.
session_write_close();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: private, max-age=300');
echo json_encode(
    maps_style(maps_ready_zones()),
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);
