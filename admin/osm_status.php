<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

header('Content-Type: application/json');
start_secure_session();
require_admin();

header('Cache-Control: no-store');

echo json_encode([
    'enabled'  => osm_proxy_enabled(),
    'via'      => $_SESSION['osm_last_via']['via']      ?? null,
    'latency'  => $_SESSION['osm_last_via']['latency_ms'] ?? null,
    'failed'   => $_SESSION['osm_last_via']['failed']     ?? false,
    'attempts' => $_SESSION['osm_last_via']['attempts']   ?? 0,
    'skipped'  => $_SESSION['osm_last_via']['skipped']    ?? [],
]);
exit;
