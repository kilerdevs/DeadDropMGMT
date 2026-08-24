<?php
declare(strict_types=1);
// ── Liveness endpoint ─────────────────────────────────────────────────────────
// Deliberately dumb: no DB, no session, no autoloading of app code. It answers
// one question — "is this PHP surface executing code right now?" — for Docker
// HEALTHCHECKs, load balancers and uptime monitors. Deep health (database
// reachable, limiter table readable) is intentionally NOT reported here:
// fail-closed subsystems already deny service on their own, and a health
// endpoint that depends on the DB turns a partial outage into a full one.
// Note: the FPM image cannot HTTP-probe itself (FastCGI has no HTTP surface);
// reverse proxies and load balancers should target this file end-to-end.

http_response_code(200);
header('Content-Type: text/plain');
header('Cache-Control: no-store');
exit('ok');
