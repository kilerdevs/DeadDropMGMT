<?php
declare(strict_types=1);

// DeadDropMGMT service kernel — the single entry point for admin pages:
//
//     require_once dirname(__DIR__) . '/includes/kernel.php';
//
// The kernel loads config.php (deployment constants, error handling, logger)
// and every service module exactly once. Services stay plain PHP functions —
// the kernel is a loader, not a framework — and each service file keeps its
// own require_once guards, so loading services directly (tests, cron jobs,
// CLI scripts) keeps working unchanged. Centralizing the list here means an
// entry script never maintains its own require block again: adding a new
// service is one line in the manifest below, not a change to N pages.
//
// Shared handles (e.g. the PDO singleton in includes/db.php) stay where they
// are; if one ever needs centralizing, this file is where it moves.

if (defined('DDMGMT_KERNEL')) {
    return;
}
define('DDMGMT_KERNEL', true);

require_once dirname(__DIR__) . '/config.php';

// Service manifest. Load order mirrors the dependency direction (core
// first); every file is require_once-guarded, so the order is belt and
// braces rather than load-bearing.
foreach ([
    'logger',
    'db',
    'net',
    'settings',
    'i18n',
    'auth',
    'crypto',
    'totp',
    'audit',
    'analytics',
    'order_state',
    'proxy',
    'maps',
    'cleanup',
    'wipe',
    'version',
] as $service) {
    require_once __DIR__ . '/' . $service . '.php';
}

// ── Last-resort error boundary ──────────────────────────────────────────────
// Any Throwable escaping a page (TypeError from array-shaped input, an
// unexpected Error deep in a flow) is logged and answered with the localized
// 500 page instead of the webserver's default blank 500. Presentation only:
// nothing is retried and no state is committed here — by the time this runs,
// the request is already dead. Details go to the log, never to the client.
// JSON callers (fetch) are answered in JSON; everything else gets the HTML
// error page. CLI/cron keeps machine-readable failure (log + exit 1).
set_exception_handler(static function (Throwable $e): void {
    try {
        log_err('Uncaught ' . get_class($e) . ': ' . $e->getMessage());
    } catch (Throwable) {
        // Logging itself broken — never recurse into the handler.
    }
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, "Fatal error\n");
        exit(1);
    }
    if (headers_sent()) {
        return;
    }
    http_response_code(500);
    $accept = (string)($_SERVER['HTTP_ACCEPT'] ?? '');
    if (str_contains($accept, 'application/json')) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Server error'], JSON_UNESCAPED_UNICODE);
        return;
    }
    try {
        $title = t('error.500.title');
        $body  = t('error.500.body');
    } catch (Throwable) {
        $title = 'Server error';
        $body  = 'An internal server error occurred.<br>Please try again shortly.';
    }
    // $title/$body are t()-built (HTML-safe); raw echo by contract.
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        . '<title>' . $title . '</title>'
        . '<link rel="stylesheet" href="/style.css"></head><body><main>'
        . '<div class="alert">' . $body . '</div>'
        . '</main></body></html>';
});
