<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

start_secure_session();
require_owner();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    exit('{"valid":false,"checked":0,"broken_line":null,"reason":"method"}');
}

// Read-only probe: verification succeeds but the session token is NOT
// consumed — the owner may re-run the check from the same rendered page.
if (!verify_csrf($_POST['csrf_token'] ?? '', rotate: false)) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    exit('{"valid":false,"checked":0,"broken_line":null,"reason":"csrf"}');
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

[$valid, $checked, $broken, $reason] = verify_log_chain();
echo json_encode([
    'valid'       => $valid,
    'checked'     => $checked,
    'broken_line' => $broken,
    'reason'      => $reason,
], JSON_UNESCAPED_UNICODE);
