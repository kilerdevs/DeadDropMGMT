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
if ($name === '' || preg_match(BACKUP_NAME_RE, $name) !== 1) {
    http_response_code(404);
    exit;
}
// Allowlist, not just a pattern: the served path is built from the
// server-generated listing (glob + basename), never from request bytes, so
// no crafted ?file= can name a path outside backups/ even if the regex and
// this check ever disagreed. Constant-time compare: backup names carry
// timestamps, and enumeration timing must not confirm them.
$listed = null;
foreach (backup_list() as $b) {
    $cand = (string)($b['name'] ?? '');
    if ($cand !== '' && hash_equals($cand, $name)) {
        $listed = $cand;
        break;
    }
}
if ($listed === null) {
    http_response_code(404);
    exit;
}
$path = backup_dir() . '/' . $listed;
if (!is_file($path)) {
    http_response_code(404);
    exit;
}

$size = @filesize($path);
$mime = str_ends_with($listed, '.zip') ? 'application/zip' : 'application/json';
header('Content-Type: ' . $mime);
header('Content-Disposition: attachment; filename="' . $listed . '"');
if ($size !== false) {
    header('Content-Length: ' . $size);
}
header('Cache-Control: no-store');

readfile($path);
exit;
