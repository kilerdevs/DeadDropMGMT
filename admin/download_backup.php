<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

// Owner backup download: backups/ is web-denied on every server profile, so
// a finished bundle leaves the host only through here — owner session,
// strict filename, streamed. Mirrors admin/download_log.php.

start_secure_session();
require_owner();

$raw = $_GET['file'] ?? null;
// Array-shaped input (?file[]=x) must 404, not "Array to string" warn.
$name = is_string($raw) ? $raw : '';
if (preg_match(BACKUP_NAME_RE, $name) !== 1) {
    http_response_code(404);
    exit;
}
$path = backup_dir() . '/' . $name;
if (!is_file($path)) {
    http_response_code(404);
    exit;
}

$size = @filesize($path);
$mime = str_ends_with($name, '.zip') ? 'application/zip' : 'application/json';
header('Content-Type: ' . $mime);
header('Content-Disposition: attachment; filename="' . $name . '"');
if ($size !== false) {
    header('Content-Length: ' . $size);
}
header('Cache-Control: no-store');

readfile($path);
exit;
