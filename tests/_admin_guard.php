<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Probe used by AuthTest: calls require_admin() with no admin session. The
// guard must exit before any admin code runs — reaching past it means the
// check is dead and the admin area is open. Prints a marker only if the
// guard is bypassed.

require_once __DIR__ . '/bootstrap.php';

$_SESSION = [];
require_admin();
echo 'PAST-GUARD';
