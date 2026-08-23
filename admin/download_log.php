<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

start_secure_session();
require_owner();

if (get_setting('show_error_log', '0') !== '1') {
    http_response_code(403);
    exit;
}

if (($_GET['file'] ?? '') === 'app') {
    $path     = APP_LOG_PATH;
    $prefix   = 'structured';
    $is_app   = true;
} else {
    $path   = ERROR_LOG_PATH;
    $prefix = 'error';
}

if (!is_file($path)) {
    http_response_code(404);
    exit;
}

$size     = filesize($path);
$filename = $prefix . '-' . date('Y-m-d_His') . '.log';

header('Content-Type: text/plain; charset=utf-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . $size);
header('Cache-Control: no-store');

readfile($path);
exit;
