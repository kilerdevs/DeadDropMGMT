<?php
declare(strict_types=1);

// Handler for the csrf_token dispatch route. Runs INSIDE the dispatcher
// envelope (JSON headers, session, admin auth, GET) — direct requests are
// refused. Answers the live session token (json_out() attaches it as `csrf`);
// nothing is rotated, so it can be called as often as a form is submitted.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'csrf_token') {
    http_response_code(404);
    exit;
}

// Defence in depth on top of same-origin + SameSite=Strict: a browser that
// says the request came from another site gets nothing (older browsers send
// no Sec-Fetch-Site header at all and fall through to the cookie rules).
$site = (string)($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
if ($site !== '' && !in_array($site, ['same-origin', 'none'], true)) {
    json_out(['error' => 'Forbidden'], 403);
}
json_out(['ok' => true]);
