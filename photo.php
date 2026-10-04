<?php
// Photo serving endpoint for encrypted photos at rest
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/auth.php';

// Must be logged in (admin or recipient with valid token)
start_secure_session();

$rel = filter_input(INPUT_GET, 'file', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? '';
$thumb = (filter_input(INPUT_GET, 'thumb', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? '') === '1';

if ($rel === '' || !preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $rel)) {
    http_response_code(400);
    exit('Invalid file parameter');
}

$base = dirname(__DIR__) . '/uploads/';
$path = $base . ($thumb ? photo_thumb_rel($rel) : $rel);

if (!is_file($path)) {
    http_response_code(404);
    exit('Not found');
}

// Check authorization: admin can see all, recipient can see only their order
$uid = (int)($_SESSION['user_id'] ?? 0);
$orderId = (int)explode('/', $rel)[0];

if ($uid > 0) {
    try {
        $db = get_db();
        $stmt = $db->prepare('SELECT created_by FROM orders WHERE id = ? LIMIT 1');
        $stmt->execute([$orderId]);
        $row = $stmt->fetch();
        if ($row && (int)$row['created_by'] !== $uid && !in_array($_SESSION['user_role'] ?? '', ['owner', 'courier'], true)) {
            http_response_code(403);
            exit('Forbidden');
        }
    } catch (Exception) {
        // DB error - deny access
        http_response_code(403);
        exit('Forbidden');
    }
}

// If the requested file already looks like a thumbnail (_thumb.jpg),
// don't call photo_thumb_rel again — it would double-transform.
$isThumb = str_ends_with($rel, '_thumb.jpg');
$path = $base . ($isThumb ? $rel : ($thumb ? photo_thumb_rel($rel) : $rel));

if (!is_file($path)) {
    http_response_code(404);
    exit('Not found');
}

// Check authorization: admin can see all, recipient can see only their order
$uid = (int)($_SESSION['user_id'] ?? 0);
$orderId = (int)explode('/', $rel)[0];

if ($uid > 0) {
    try {
        $db = get_db();
        $stmt = $db->prepare('SELECT created_by FROM orders WHERE id = ? LIMIT 1');
        $stmt->execute([$orderId]);
        $row = $stmt->fetch();
        if ($row && (int)$row['created_by'] !== $uid && !in_array($_SESSION['user_role'] ?? '', ['owner', 'courier'], true)) {
            http_response_code(403);
            exit('Forbidden');
        }
    } catch (Exception) {
        // DB error - deny access
        http_response_code(403);
        exit('Forbidden');
    }
}

// Decrypt to temp and serve
$tmp = sys_get_temp_dir() . '/photo_serve_' . bin2hex(random_bytes(8));
if (!photo_decrypt_to_temp($path, $tmp)) {
    http_response_code(500);
    exit('Decrypt failed');
}

$mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
header('Content-Type: ' . $mime);
header('Content-Length: ' . filesize($tmp));
header('Cache-Control: private, max-age=3600');
header('X-Content-Type-Options: nosniff');
readfile($tmp);
@unlink($tmp);
exit;