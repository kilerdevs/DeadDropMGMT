<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── CSRF token generation and verification ───────────────────────────────────

$_SESSION = [];

$token = generate_csrf();
T::eq('token is 64 hex chars (32 bytes)', 64, strlen($token));
T::ok('token is hex', ctype_xdigit($token));

// Stable within the session — one token per session lifetime
T::eq('token stable across calls', $token, generate_csrf());

// Verification
T::ok('valid token accepted', verify_csrf($token));
T::ok('wrong token rejected', !verify_csrf(str_repeat('0', 64)));
T::ok('empty token rejected', !verify_csrf(''));
T::ok('prefix-extended token rejected', !verify_csrf($token . '00'));

// One token, one use: a successful verification rotates the session value,
// so the just-used token is dead for the next request...
$second = generate_csrf();
T::ok('session holds a fresh token after use', $second !== $token);
T::ok('used token cannot be replayed', !verify_csrf($token));
// ...while the fresh one verifies and rotates again.
T::ok('fresh token accepted', verify_csrf($second));
$third = generate_csrf();
T::ok('rotation minted a different value', $third !== $second);

// Read-only probes can opt out of rotation: the same token keeps working
// (this is what the per-keystroke setup check on the login page relies on).
$stable = generate_csrf();
T::ok('non-rotating verification accepts', verify_csrf($stable, rotate: false));
T::ok('non-rotating verification keeps token valid', verify_csrf($stable, rotate: false));

// No token in session yet → everything rejected
unset($_SESSION['csrf_token']);
T::ok('missing session token rejects verification', !verify_csrf($token));

// Regenerated when absent, differs from the old one
$fresh = generate_csrf();
T::ok('new token generated when absent', strlen($fresh) === 64 && $fresh !== $token);

exit(T::done());
