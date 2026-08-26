<?php
declare(strict_types=1);

// ── Client IP resolution (used by rate limiting, audit log) ────────────────
// Lives OUTSIDE config.php on purpose: operators customize their config and
// a typo there must not be able to silently weaken who counts as a trusted
// proxy. Proxy headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are
// trusted ONLY when BOTH hold: the deployment opts in (DDMGMT_TRUST_PROXY=1)
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
        $cfg = trim(_secret('DDMGMT_TRUSTED_PROXIES', ''));
        $proxies = $cfg === ''
            ? ['127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
            : array_map('trim', explode(',', $cfg));
        $trusted = false;
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
                $trusted = true;
                break;
            }
        }
        if (!$trusted) {
            // Warn once per process: the flag says "behind a proxy" while
            // the connection plainly is not — either the app is reachable
            // around its proxy or the env var is stale. Static guard breaks
            // the get_client_ip() <-> app_log() call cycle (the logger asks
            // this very function for the request IP).
            static $untrusted_warned = false;
            if (!$untrusted_warned) {
                $untrusted_warned = true;
                log_warn('proxy_headers_untrusted', ['msg' => 'DDMGMT_TRUST_PROXY is on but REMOTE_ADDR is not a trusted proxy; ignoring proxy headers for this peer']);
            }
            return $peer;
        }
        $candidates = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
        ];
        foreach ($candidates as $key) {
            if (!empty($_SERVER[$key])) {
                $raw = trim((string)$_SERVER[$key]);
                // Multi-hop XFF: a proxy that APPENDS leaves earlier entries
                // client-controlled, so "first entry" is then attacker-chosen.
                // This deployment contract expects an OVERWRITING proxy — say
                // so loudly when the header looks multi-hop.
                if ($key === 'HTTP_X_FORWARDED_FOR' && str_contains($raw, ',')) {
                    static $multihop_warned = false;
                    if (!$multihop_warned) {
                        $multihop_warned = true;
                        log_warn('xff_multihop', ['msg' => 'X-Forwarded-For carries multiple hops; first entry used — verify the proxy overwrites (not appends) this header']);
                    }
                }
                $ip = trim(explode(',', $raw)[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
    }
    return $peer;
}

// Syntax check for one DDMGMT_TRUSTED_PROXIES entry ("a.b.c.d" or
// "network/bits", either family, bits within family range). Deliberately
// separate from _ip_in_cidr(): match-failure is normal operation, parse-
// failure is an operator mistake that must be visible in the log.
function _cidr_valid(string $cidr): bool {
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
