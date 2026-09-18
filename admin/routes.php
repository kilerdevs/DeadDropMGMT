<?php
declare(strict_types=1);

// Admin action route table — pure data, no execution. Required by
// admin/dispatch.php (the envelope) and by tests/DispatchTest.php (the
// contract). Each route declares everything the envelope needs so action
// handlers contain business logic only:
//
//   handler    file admin/actions/<handler>.php (guarded, envelope assumed)
//   auth       'admin' | 'owner' | null (logout: none — it must work with a
//              half-open session, exactly as before)
//   headers    true  → set_security_headers(true)
//              false → set_security_headers(false)
//              'json' → Content-Type: application/json (JSON endpoints never
//              sent security headers, preserved as-is)
//   method     required REQUEST_METHOD (null = any; logout accepts GET as a
//              no-op redirect, exactly as before)
//   method_fail / csrf_fail / owns_order.deny failure specs:
//              ['redirect' => url] plain redirect
//              ['flash_redirect' => url, 'flash_key' => t-key] flash + redirect
//              ['json' => [code, payload]] JSON error (json_out exits)
//   csrf       true (verify, fail on mismatch) | 'optional' (verify, expose
//              the result to the handler — logout acts only on success)
//   owns_order ['source' => [where, key], 'deny' => spec] — enforced only for
//              a positive id; non-positive ids fall through to the handler's
//              own validation, which answers with the legacy redirect
//   (csrf_token: read-only, needs no token of its own — it IS the token source)
//   2fa_exempt feeds require_admin(): couriers pending TOTP enrollment may
//              still reach the route (logout, self-service set_lang)

return [
    'mark_delivered' => [
        'handler' => 'mark_delivered', 'auth' => 'admin', 'headers' => true,
        'method' => 'POST', 'method_fail' => ['redirect' => '/admin/orders.php'],
        'csrf' => true, 'csrf_fail' => ['flash_redirect' => '/admin/orders.php'],
        'owns_order' => [
            'source' => ['POST', 'id'],
            'deny' => ['flash_redirect' => '/admin/orders.php', 'flash_key' => 'admin.orders.flash.no_access'],
        ],
    ],
    'order_close' => [
        'handler' => 'order_close', 'auth' => 'admin', 'headers' => true,
        'method' => 'POST', 'method_fail' => ['redirect' => '/admin/orders.php'],
        'csrf' => true, 'csrf_fail' => ['flash_redirect' => '/admin/orders.php'],
        'owns_order' => [
            'source' => ['POST', 'id'],
            'deny' => ['flash_redirect' => '/admin/orders.php', 'flash_key' => 'admin.orders.flash.no_access'],
        ],
    ],
    'photo_delete' => [
        'handler' => 'photo_delete', 'auth' => 'admin', 'headers' => true,
        'method' => 'POST', 'method_fail' => ['redirect' => '/admin/orders.php'],
        'csrf' => true, 'csrf_fail' => ['flash_redirect' => '/admin/orders.php'],
        'owns_order' => [
            'source' => ['POST', 'order_id'],
            'deny' => ['redirect' => '/admin/orders.php'],
        ],
    ],
    'extend' => [
        'handler' => 'extend', 'auth' => 'admin', 'headers' => true,
        'method' => 'POST', 'method_fail' => ['redirect' => '/admin/orders.php'],
        'csrf' => true, 'csrf_fail' => ['flash_redirect' => '/admin/orders.php'],
        'owns_order' => [
            'source' => ['POST', 'id'],
            'deny' => ['flash_redirect' => '/admin/orders.php', 'flash_key' => 'admin.orders.flash.no_access'],
        ],
    ],
    'save_setting' => [
        'handler' => 'save_setting', 'auth' => 'owner', 'headers' => 'json',
        'method' => 'POST', 'method_fail' => ['json' => [405, ['error' => 'Method not allowed']]],
        'csrf' => true, 'csrf_fail' => ['json' => [403, ['error' => 'CSRF']]],
    ],
    'user_action' => [
        'handler' => 'user_action', 'auth' => 'owner', 'headers' => true,
        'method' => 'POST', 'method_fail' => ['redirect' => '/admin/users.php'],
        'csrf' => true, 'csrf_fail' => ['flash_redirect' => '/admin/users.php'],
    ],
    'set_lang' => [
        'handler' => 'set_lang', 'auth' => 'admin', 'headers' => 'json',
        '2fa_exempt' => true,
        'method' => 'POST', 'method_fail' => ['json' => [405, ['error' => 'Method not allowed']]],
        'csrf' => true, 'csrf_fail' => ['json' => [403, ['error' => 'CSRF']]],
    ],
    // The current session token, for same-origin scripts. verify_csrf() rotates
    // the token on every success, so a page's server-rendered copy goes stale
    // as soon as ANY request from that page (an autosave, a status poll) has
    // been verified — a language switch or a logout after that would fail with
    // a bogus "CSRF". Forms and fetch callers ask for the live one instead.
    // Same-origin by construction: no CORS headers, SameSite=Strict cookie.
    'csrf_token' => [
        'handler' => 'csrf_token', 'auth' => 'admin', 'headers' => 'json',
        '2fa_exempt' => true,
        'method' => 'GET', 'method_fail' => ['json' => [405, ['error' => 'Method not allowed']]],
    ],
    'logout' => [
        'handler' => 'logout', 'auth' => null, 'headers' => false,
        '2fa_exempt' => true, 'method' => null, 'csrf' => 'optional',
    ],
];
