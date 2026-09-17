<?php
declare(strict_types=1);

// Admin action dispatcher — the single security envelope for state-changing
// endpoints. Canonical URL: /admin/dispatch.php?action=<route> (same method
// and parameters the legacy endpoint took). Legacy filenames stay working
// as thin shims that pin the action and delegate here, so every posted form
// keeps working untouched.
//
// Envelope order mirrors what each endpoint did on its own (headers →
// session → 2FA flag → method → auth → CSRF → ownership → handler), so the
// only observable change is WHERE the checks live, never their outcome.

require_once dirname(__DIR__) . '/includes/kernel.php';

/** @var array<string,array<string,mixed>> */
$DDMGMT_ROUTES = require __DIR__ . '/routes.php';

$action = $_GET['action'] ?? null;
$route = (is_string($action) && isset($DDMGMT_ROUTES[$action])) ? $DDMGMT_ROUTES[$action] : null;
if ($route === null) {
    header('Location: /admin/index.php');
    exit;
}
define('DDMGMT_DISPATCH', $action);

// ── Headers ─────────────────────────────────────────────────────────────────
$headers = $route['headers'] ?? true;
if ($headers === 'json') {
    header('Content-Type: application/json');
} else {
    set_security_headers($headers === true);
}

start_secure_session();

// The 2FA gate in require_admin() consults this, never the script name.
$GLOBALS['DDMGMT_ROUTE_2FA_EXEMPT'] = !empty($route['2fa_exempt']);

// ── Method ──────────────────────────────────────────────────────────────────
if (!empty($route['method']) && ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== $route['method']) {
    _dispatch_fail($route['method_fail']);
}

// ── Auth ────────────────────────────────────────────────────────────────────
if (($route['auth'] ?? null) === 'admin') {
    require_admin();
} elseif (($route['auth'] ?? null) === 'owner') {
    require_owner();
}

// ── CSRF ────────────────────────────────────────────────────────────────────
$csrf_valid = true;
if (($route['csrf'] ?? false) === true) {
    $csrf_valid = verify_csrf($_POST['csrf_token'] ?? '');
    if (!$csrf_valid) {
        _dispatch_fail($route['csrf_fail']);
    }
} elseif (($route['csrf'] ?? false) === 'optional') {
    // logout: no failure exit — the handler acts only on success, exactly
    // as the legacy endpoint's verify-in-condition did.
    $csrf_valid = verify_csrf($_POST['csrf_token'] ?? '');
}
$GLOBALS['DDMGMT_CSRF_VALID'] = $csrf_valid;

// ── Order ownership (couriers act only on their own orders) ─────────────────
// Positive ids only: non-positive input falls through to the handler's own
// validation, which answers with the legacy redirect for that case.
if (isset($route['owns_order'])) {
    [$from, $key] = $route['owns_order']['source'];
    $bag = ($from === 'POST') ? $_POST : $_GET;
    $order_id = (int)($bag[$key] ?? 0);
    if ($order_id > 0 && !courier_owns_order($order_id)) {
        _dispatch_fail($route['owns_order']['deny']);
    }
}

// ── Handler (business logic only; envelope already established) ─────────────
require __DIR__ . '/actions/' . $route['handler'] . '.php';

// ── Envelope failure responses ──────────────────────────────────────────────
/**
 * @param array<string,mixed> $spec
 */
function _dispatch_fail(array $spec): never {
    if (isset($spec['redirect'])) {
        header('Location: ' . $spec['redirect']);
        exit;
    }
    if (isset($spec['flash_redirect'])) {
        $_SESSION['flash']    = t($spec['flash_key'] ?? 'admin.common.invalid_csrf');
        $_SESSION['flash_ok'] = false;
        header('Location: ' . $spec['flash_redirect']);
        exit;
    }
    if (isset($spec['json'])) {
        json_out($spec['json'][1], $spec['json'][0]);
    }
    header('Location: /admin/index.php');
    exit;
}
