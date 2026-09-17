<?php
declare(strict_types=1);

// Handler for the logout dispatch route. Runs INSIDE the dispatcher envelope
// (security headers, session; deliberately NO auth gate) — direct requests
// are refused.
//
// POST-only with a valid token destroys the session; anything else (GET,
// CSRF failure) redirects without touching it — a state-changing GET would
// let any hostile page log the admin out with a single <img> tag.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'logout') {
    http_response_code(404);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && ($GLOBALS['DDMGMT_CSRF_VALID'] ?? false)) {
    admin_logout();
}

header('Location: /admin/index.php');
exit;
