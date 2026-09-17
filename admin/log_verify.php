<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

start_secure_session();
require_owner();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    exit('{"valid":false,"checked":0,"broken_line":null,"reason":"method"}');
}

// Read-only probe: verification succeeds but the session token is NOT
// consumed — the owner may re-run the check from the same rendered page.
if (!verify_csrf_readonly($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    exit('{"valid":false,"checked":0,"broken_line":null,"reason":"csrf"}');
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

[$valid, $checked, $broken, $reason] = verify_log_chain();
try {
    $cont = verify_log_continuity();
} catch (Throwable $e) {
    $cont = ['status' => 'error', 'detail' => 'continuity check failed'];
}
echo json_encode([
    'valid'       => $valid,
    'checked'     => $checked,
    'broken_line' => $broken,
    'reason'      => $reason,
    // Truncation verdict against the newest DB checkpoint (extends /
    // truncated / rotated / none / error) — chain validity above only
    // covers modification, never pure tail deletion.
    'continuity'            => $cont['status'] ?? 'error',
    'continuity_detail'     => $cont['detail'] ?? '',
    'continuity_tip_seq'    => $cont['tip_seq'] ?? null,
    'continuity_anchor_seq' => $cont['checkpoint_seq'] ?? null,
], JSON_UNESCAPED_UNICODE);
