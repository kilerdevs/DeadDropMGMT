<?php
declare(strict_types=1);

// ── Request-bag string readers ──────────────────────────────────────────────
// Form fields arrive as strings, but a crafted order_token[]=x (or any
// field) arrives as an ARRAY: trim()/strlen() TypeError on it, outside
// every try, and the catches are Exception-only — an uncaught 500 where the
// normal error path belongs. These answer the default for non-strings, so
// every downstream sink stays total on strings. (CSRF tokens are guarded
// inside verify_csrf() itself, covering all its call sites at once.)
function post_string(string $key, string $default = ''): string {
    $v = $_POST[$key] ?? $default;
    return is_string($v) ? $v : $default;
}

function get_string(string $key, string $default = ''): string {
    $v = $_GET[$key] ?? $default;
    return is_string($v) ? $v : $default;
}

// ── Client IP resolution (used by rate limiting, audit log) ────────────────
// Lives OUTSIDE config.php on purpose: operators customize their config and
// a typo there must not be able to silently weaken who counts as a trusted
// proxy. The one proxy header named by DDMGMT_CLIENT_IP_HEADER (default
// X-Forwarded-For; or CF-Connecting-IP / X-Real-IP) is trusted ONLY when BOTH hold: the deployment opts in (DDMGMT_TRUST_PROXY=1)
// AND the DIRECT PEER (REMOTE_ADDR) matches DDMGMT_TRUSTED_PROXIES. Without
// the flag nothing but the TCP peer address is believed. With the flag but an
// unlisted peer (app directly reachable, flag left over from another
// environment) headers are ignored too — otherwise any client could spoof
// its address and sidestep IP rate limiting or poison the audit log. When
// DDMGMT_TRUSTED_PROXIES is unset, the implicit default trusts loopback and
// RFC1918 space only, which covers same-host nginx/Apache and private
// docker networks. Values are always validated as literal IPs.
function get_client_ip(): string {
    $peer = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
    if (_secret('DDMGMT_TRUST_PROXY', '0') === '1') {
        if (!_proxy_peer_trusted($peer)) {
            // Warn once per process: the flag says "behind a proxy" while
            // the connection plainly is not — either the app is reachable
            // around its proxy or the env var is stale. (No log cycle here:
            // app_log() records the TCP peer directly, never re-entering
            // this function — see the note on the ip field in logger.php.)
            static $untrusted_warned = false;
            if (!$untrusted_warned) {
                $untrusted_warned = true;
                log_warn('proxy_headers_untrusted', ['msg' => 'DDMGMT_TRUST_PROXY is on but REMOTE_ADDR is not a trusted proxy; ignoring proxy headers for this peer']);
            }
            return $peer;
        }
        // ONE header, named by the operator (DDMGMT_CLIENT_IP_HEADER,
        // default X-Forwarded-For). Trying several in turn was spoofable: a
        // proxy only rewrites the header it knows, so a client-sent
        // CF-Connecting-IP / X-Real-IP passed straight through a plain
        // nginx/Caddy and won over the proxy's own X-Forwarded-For.
        $name = strtolower(trim(_secret('DDMGMT_CLIENT_IP_HEADER', 'X-Forwarded-For')));
        $key = ['x-forwarded-for' => 'HTTP_X_FORWARDED_FOR', 'cf-connecting-ip' => 'HTTP_CF_CONNECTING_IP',
                'x-real-ip' => 'HTTP_X_REAL_IP'][$name] ?? null;
        if ($key === null) {
            static $bad_header_warned = false;
            if (!$bad_header_warned) {
                $bad_header_warned = true;
                log_warn('client_ip_header_unknown', ['msg' => 'DDMGMT_CLIENT_IP_HEADER must be X-Forwarded-For, CF-Connecting-IP or X-Real-IP; using REMOTE_ADDR']);
            }
            return $peer;
        }
        if (!empty($_SERVER[$key])) {
            $raw = trim((string)$_SERVER[$key]);
            // Multi-hop XFF walks RIGHT to LEFT through the trusted set:
            // chain = header entries + the TCP peer, then discard trusted
            // entries from the right and take the first untrusted one. The
            // peer itself is trusted (checked above), so it always pops
            // first and the walk starts at the header's last entry. Why not
            // "last entry", the old rule: in client, proxy-1, proxy-2 the
            // last header entry is proxy-1 — a proxy, not the client — so
            // rate limiting keyed on it shares one budget across every
            // client behind it, and audit logs name a proxy instead of the
            // actor. Why not "first entry": under an appending proxy every
            // entry left of the peer's own is client-controlled. The walk
            // takes proxy-1 when only proxy-2 is trusted, and the client
            // when both are. When EVERYTHING is trusted the walk bottoms
            // out at the leftmost entry — asserted by the outermost trusted
            // proxy, still spoofable if that proxy appends rather than
            // overwrites, so outer proxies must overwrite (same caveat as
            // nginx real_ip_recursive). Garbage entries are never trusted,
            // so the walk stops at them and the literal-IP check below
            // falls back to the peer: fail-closed.
            if ($key === 'HTTP_X_FORWARDED_FOR') {
                $hops = array_map('trim', explode(',', $raw));
                if (count($hops) > 1) {
                    static $multihop_warned = false;
                    if (!$multihop_warned) {
                        $multihop_warned = true;
                        log_warn('xff_multihop', ['msg' => 'X-Forwarded-For carries multiple hops; walking right-to-left through DDMGMT_TRUSTED_PROXIES — outer proxies must overwrite, not append, client input']);
                    }
                }
                $chain = [...$hops, $peer];
                while (count($chain) > 1 && _proxy_peer_trusted((string)end($chain))) {
                    array_pop($chain);
                }
                $raw = (string)end($chain);
            }
            $ip = trim(explode(',', $raw)[0]);
            // NUL pre-check (see _cidr_valid): the header is fully
            // attacker-controlled and must fail closed, never throw.
            if (!str_contains($ip, "\0") && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return $peer;
}

// Single choke point for "may this request's proxy headers be believed".
// Both get_client_ip() and request_is_https() answer through here, so a
// directly-reachable app cannot have its client IP spoofed AND its scheme
// flipped by the same forged headers. Unset DDMGMT_TRUSTED_PROXIES means
// loopback + RFC1918 only (same-host nginx/Apache, private docker nets).
function _proxy_peer_trusted(string $peer): bool {
    if (_secret('DDMGMT_TRUST_PROXY', '0') !== '1') {
        return false;
    }
    $cfg = trim(_secret('DDMGMT_TRUSTED_PROXIES', ''));
    $proxies = $cfg === ''
        ? ['127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        : array_map('trim', explode(',', $cfg));
    foreach ($proxies as $cidr) {
        if ($cidr === '') {
            continue;
        }
        // A misparsed range silently falls back to REMOTE_ADDR — safe,
        // but invisible. Say so once per process instead.
        if (!_cidr_valid($cidr)) {
            static $bad_warned = [];
            if (!isset($bad_warned[$cidr])) {
                $bad_warned[$cidr] = true;
                log_warn('proxy_cidr_invalid', ['msg' => 'DDMGMT_TRUSTED_PROXIES entry does not parse as IP[/bits] and is ignored', 'cidr' => $cidr]);
            }
            continue;
        }
        if (_ip_in_cidr($peer, $cidr)) {
            return true;
        }
    }
    return false;
}

// ── Request scheme detection (session cookie "secure" flag, HSTS) ────────────
// Behind a TLS-terminating reverse proxy PHP sees plain HTTP, so $_SERVER
//['HTTPS'] lies about the browser-side security context. With
// DDMGMT_TRUST_PROXY=1 the X-Forwarded-Proto header decides (only the literal
// "https" counts) — but ONLY from a trusted proxy
// peer (same _proxy_peer_trusted() gate as get_client_ip()): otherwise anyone
// reaching the app directly could flip the scheme, planting a "secure" cookie
// over plain HTTP that the browser then refuses to send back. Without proxy
// trust PHP's own view wins.
// A multi-hop list keeps the LAST entry: the scheme is not an address, so
// there is no trusted set to walk — the last entry is the one the trusted
// peer wrote closest to the app, and earlier entries may be client input
// passed through by an appending proxy. Deployments whose outer proxy
// appends rather than overwrites must point the header at it via a single
// entry (the proxy overwriting is the only safe shape here).
function request_is_https(): bool {
    if (_proxy_peer_trusted((string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'))) {
        $hops  = explode(',', (string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ''));
        if (count($hops) > 1) {
            static $multihop_warned = false;
            if (!$multihop_warned) {
                $multihop_warned = true;
                log_warn('xfp_multihop', ['msg' => 'X-Forwarded-Proto carries multiple hops; last entry used (peer-appended) — verify the proxy overwrites the header']);
            }
        }
        $proto = strtolower(trim((string)end($hops)));
        if ($proto !== '') {
            return $proto === 'https';
        }
    }
    return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
}

// Syntax check for one DDMGMT_TRUSTED_PROXIES entry ("a.b.c.d" or
// "network/bits", either family, bits within family range). Deliberately
// separate from _ip_in_cidr(): match-failure is normal operation, parse-
// failure is an operator mistake that must be visible in the log.
function _cidr_valid(string $cidr): bool {
    // NUL bytes never appear in a valid IP[/bits] — and on some builds the
    // validators below throw ValueError on them instead of answering false
    // (an operator typo or a fuzzed header must not become a 500).
    if (str_contains($cidr, "\0")) {
        return false;
    }
    if (!str_contains($cidr, '/')) {
        return filter_var($cidr, FILTER_VALIDATE_IP) !== false;
    }
    [$net, $bits] = explode('/', $cidr, 2);
    if (filter_var($net, FILTER_VALIDATE_IP) === false || !ctype_digit($bits)) {
        return false;
    }
    $maxBits = str_contains($net, ':') ? 128 : 32;
    return (int)$bits >= 0 && (int)$bits <= $maxBits;
}

// True when $ip falls inside $cidr (bare address for an exact match, or
// "network/bits"). IPv4-mapped IPv6 forms (::ffff:a.b.c.d) are normalized
// down to plain IPv4 so a mapped address cannot dodge a v4 range — nor be
// waved through by a v4-looking string against a v6 network (family
// mismatches always compare false).
function _ip_in_cidr(string $ip, string $cidr): bool {
    $norm = static function (string $addr): ?string {
        if (str_starts_with(strtolower($addr), '::ffff:') && str_contains($addr, '.')) {
            $addr = substr($addr, 7);
        }
        // As in _cidr_valid(): NUL bytes are never a valid address, and
        // inet_pton() throws ValueError on them on some builds (Windows
        // answers false) — a hostile X-Forwarded-For must fail closed here,
        // not fatal the rate limiter that called us.
        if (str_contains($addr, "\0")) {
            return null;
        }
        $packed = @inet_pton($addr);
        return $packed === false ? null : $packed;
    };
    $ipP = $norm($ip);
    if ($ipP === null || !str_contains($cidr, '/')) {
        if ($ipP === null) {
            return false;
        }
        $netP = $norm($cidr);
        return $netP !== null && $ipP === $netP;
    }
    [$net, $bits] = explode('/', $cidr, 2);
    $netP = $norm($net);
    if ($netP === null || !ctype_digit($bits)) {
        return false;
    }
    $bits = (int)$bits;
    if ($bits < 0 || $bits > strlen($netP) * 8 || strlen($ipP) !== strlen($netP)) {
        return false;
    }
    $fullBytes = intdiv($bits, 8);
    if ($fullBytes > 0 && substr($ipP, 0, $fullBytes) !== substr($netP, 0, $fullBytes)) {
        return false;
    }
    $restBits = $bits % 8;
    if ($restBits > 0) {
        $mask = (0xFF << (8 - $restBits)) & 0xFF;
        if (((ord($ipP[$fullBytes]) ^ ord($netP[$fullBytes])) & $mask) !== 0) {
            return false;
        }
    }
    return true;
}
