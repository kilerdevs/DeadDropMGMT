<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/settings.php';

// ── Outbound proxy pool for OpenStreetMap requests ────────────────────────────
// The admin panel's tile/geocode proxies normally talk to OSM from the
// server's own IP. Owners who want to keep even that metadata away from
// OSM can maintain a pool of HTTP(S) proxies here and enable routing.
//
// Design notes:
// - Fail-closed: when routing is enabled but every proxy fails, the request
//   fails (HTTP 502 to the admin browser) instead of silently leaking the
//   server's real IP to OSM.
// - Proxy health is tracked per URL so dead entries are visible in settings.
// - Discovery pulls candidate lists from Proxifly's free-proxy-list (GitHub,
//   MIT-licensed, regularly refreshed) — see proxy_discover().

function osm_proxy_pool(): array {
    try {
        $stmt = get_db()->query(
            'SELECT id, url, label, source, last_status, latency_ms, last_checked
             FROM osm_proxies ORDER BY created_at ASC'
        );
        return $stmt->fetchAll();
    } catch (Exception $e) {
        log_err('Proxy pool load: ' . $e->getMessage());
        return [];
    }
}

// Normalize user input into a proxy URL cURL accepts (http://host:port).
// Accepts "host:port", "http(s)://host:port", "socks4/5/5h://host:port" and
// optional "user:pass@" credentials. Returns null when the input is not
// usable.
// cURL resolves the TARGET hostname locally for socks5:// and socks4://, so
// every OSM / protomaps lookup would hit this server's resolver in the clear
// — the opposite of routing through a proxy. The "h"/"a" variants resolve at
// the proxy, like the bundled socket engine always does.
function proxy_curl_url(string $url): string {
    if (str_starts_with($url, 'socks5://')) return 'socks5h://' . substr($url, 9);
    if (str_starts_with($url, 'socks4://')) return 'socks4a://' . substr($url, 9);
    return $url;
}

// scheme://host:port only — never the userinfo. For anything that leaves the
// owner-only proxy settings: the courier-visible status caption, the audit log.
function osm_proxy_redact(string $url): string {
    $p = parse_url($url);
    if (!is_array($p) || empty($p['host'])) return '(proxy)';
    $host = str_contains($p['host'], ':') && !str_starts_with($p['host'], '[') ? '[' . $p['host'] . ']' : $p['host'];
    return ($p['scheme'] ?? 'http') . '://' . $host . (isset($p['port']) ? ':' . $p['port'] : '');
}

// True only for a proxy URL whose host is a literal, globally routable IP.
// Discovered (third-party list) entries must pass this; owner-added manual
// proxies may still live on the LAN.
function osm_proxy_host_public(string $url): bool {
    $host = trim((string)parse_url($url, PHP_URL_HOST), '[]');
    return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function osm_proxy_normalize(string $raw): ?string {
    $raw = trim($raw);
    if ($raw === '' || strlen($raw) > 255) return null;
    if (!str_contains($raw, '://')) {
        $raw = 'http://' . $raw;
    }
    $p = parse_url($raw);
    if (!$p || empty($p['host']) || empty($p['port'])) return null;
    $host = strtolower(trim((string)$p['host'], '[]')); // parse_url keeps IPv6 brackets; validate the bare address
    if (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN)) return null;
    $port = filter_var($p['port'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
    if ($port === false) return null;
    if (!in_array($p['scheme'] ?? 'http', ['http', 'https', 'socks4', 'socks5', 'socks5h'], true)) return null;

    $url = $p['scheme'] . '://';
    if (!empty($p['user'])) {
        // Decode first: callers pass raw ("p@ss") or encoded ("p%40ss") credentials — either way exactly one encoding lands in the URL.
        $url .= rawurlencode(rawurldecode($p['user']));
        if (isset($p['pass'])) $url .= ':' . rawurlencode(rawurldecode($p['pass']));
        $url .= '@';
    }
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $host = '[' . $host . ']';
    }
    $url .= $host . ':' . $port;
    return $url;
}

// ── Pure-PHP proxy transport ─────────────────────────────────────────────────
// cURL stays the fast path wherever it exists (parallel probes, hardened
// TLS); everything below is the fallback that keeps proxy routing working
// without it: raw sockets, HTTP-proxy forwarding, a CONNECT tunnel, and a
// SOCKS handshake, every wait bounded by an explicit deadline. Nothing here
// blocks past $timeout; nothing throws (callers get code 0).
//
// Privacy rule: SOCKS always resolves the target hostname AT THE PROXY
// (address type DOMAIN, cURL's socks5h behaviour) — never via the owner's
// local resolver, which would disclose every OSM hostname to local DNS.
// cURL's plain "socks5" resolves locally; ours deliberately does not, for
// either spelling.

/** @return ?array{host:string,dial:string,port:int,tls:bool,path:string} */
function proxy_parse_target(string $url): ?array {
    $p = parse_url($url);
    if (!is_array($p)) return null;
    if (isset($p['user'])) return null; // credentials in a target URL are never legitimate here
    $scheme = strtolower((string)($p['scheme'] ?? ''));
    if ($scheme !== 'http' && $scheme !== 'https') return null;
    $host = strtolower(trim((string)($p['host'] ?? ''), '[]')); // parse_url keeps IPv6 brackets
    if ($host === '' || strlen($host) > 253 || str_contains($host, ' ')) return null;
    $port = isset($p['port']) ? (int)$p['port'] : ($scheme === 'https' ? 443 : 80);
    if ($port < 1 || $port > 65535) return null;
    $path = (string)($p['path'] ?? '');
    if ($path === '' || !str_starts_with($path, '/')) $path = '/' . $path;
    if (isset($p['query']) && $p['query'] !== '') $path .= '?' . $p['query'];
    // parse_url strips the IPv6 brackets; the dial form needs them back.
    $dial = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host;
    return ['host' => $host, 'dial' => $dial, 'port' => $port, 'tls' => $scheme === 'https', 'path' => $path];
}

/** @return ?array{scheme:string,host:string,dial:string,port:int,user:string,pass:string} */
function proxy_parse(string $proxy): ?array {
    $norm = osm_proxy_normalize($proxy);
    if ($norm === null) return null;
    $p = parse_url($norm);
    if (!is_array($p)) return null;
    $scheme = strtolower((string)($p['scheme'] ?? 'http'));
    $host = strtolower(trim((string)($p['host'] ?? ''), '[]')); // parse_url keeps IPv6 brackets
    $port = (int)($p['port'] ?? 0);
    $user = rawurldecode((string)($p['user'] ?? ''));
    $pass = rawurldecode((string)($p['pass'] ?? ''));
    if ($host === '' || $port < 1 || strlen($user) > 255 || strlen($pass) > 255) return null;
    $dial = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host;
    return ['scheme' => $scheme, 'host' => $host, 'dial' => $dial, 'port' => $port, 'user' => $user, 'pass' => $pass];
}

function proxy_basic_auth(string $user, string $pass): string {
    return 'Basic ' . base64_encode($user . ':' . $pass);
}

function proxy_connect_head(string $host, int $port, string $user, string $pass): string {
    $h = "CONNECT {$host}:{$port} HTTP/1.1\r\nHost: {$host}:{$port}\r\n";
    if ($user !== '') {
        $h .= 'Proxy-Authorization: ' . proxy_basic_auth($user, $pass) . "\r\n";
    }
    return $h . "\r\n";
}

/** SOCKS5 greeting: no-auth alone, or no-auth + username/password when we have credentials. */
function proxy_socks5_greet(string $user): string {
    return $user === '' ? "\x05\x01\x00" : "\x05\x02\x00\x02";
}

function proxy_socks5_auth(string $user, string $pass): string {
    return "\x01" . chr(strlen($user)) . $user . chr(strlen($pass)) . $pass;
}

/** SOCKS5 CONNECT with a domain address (remote DNS — see the privacy rule above). */
function proxy_socks5_connect(string $host, int $port): string {
    return "\x05\x01\x00\x03" . chr(strlen($host)) . $host . pack('n', $port);
}

/** SOCKS4 CONNECT: literal IPv4 inline, anything else in 4a form (hostname after the user field). */
function proxy_socks4_connect(string $host, int $port, string $user): string {
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $ip = inet_pton($host);
        if (is_string($ip)) {
            return "\x04\x01" . pack('n', $port) . $ip . $user . "\x00";
        }
    }
    return "\x04\x01" . pack('n', $port) . "\x00\x00\x00\xff" . $user . "\x00" . $host . "\x00";
}

/** Status code of an HTTP response head, 0 when it is not one. */
function proxy_status_code(string $head): int {
    if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $head, $m) === 1) {
        return (int)$m[1];
    }
    return 0;
}

/** Split a buffer at the end of the HTTP head. @return ?array{string,string} [head, rest] */
function proxy_head_split(string $buf): ?array {
    $i = strpos($buf, "\r\n\r\n");
    if ($i === false) return null;
    return [substr($buf, 0, $i), substr($buf, $i + 4)];
}

// One step of a chunked body: [decoded new bytes, still-unparsed buffer, done].
// Null means corrupt framing (a hostile proxy speaking garbage fails closed).
/** @return ?array{string,string,bool} */
// Bounds for hostile framing: a size line has no business being longer than
// a few KiB, and no sane server sends multi-MiB chunks. Without them a peer
// announcing "7fffffffffff" made the caller buffer (and re-copy) whatever it
// sent until the deadline — memory exhaustion even for streamed downloads.
const PROXY_CHUNK_LINE_MAX = 4096;
const PROXY_CHUNK_MAX      = 8388608; // 8 MiB

function proxy_chunked_feed(string $buf): ?array {
    $out = '';
    while (true) {
        $i = strpos($buf, "\r\n");
        if ($i === false) {
            return strlen($buf) > PROXY_CHUNK_LINE_MAX ? null : [$out, $buf, false];
        }
        $line = substr($buf, 0, $i);
        if (strlen($line) > PROXY_CHUNK_LINE_MAX) return null;
        if (preg_match('/^([0-9a-fA-F]{1,8})(;[^\r]*)?$/', $line, $m) !== 1) return null;
        $size = hexdec($m[1]);
        if ($size > PROXY_CHUNK_MAX) return null;
        $buf = substr($buf, $i + 2);
        if ($size === 0) return [$out, '', true]; // trailers ignored: nothing after the body is trusted
        if (strlen($buf) < $size + 2) return [$out, $line . "\r\n" . $buf, false];
        $out .= substr($buf, 0, $size);
        $buf = substr($buf, $size + 2);
    }
}

// Incremental chunked decoder for the response reader below: the same
// framing rules as proxy_chunked_feed (kept for its unit pins), but with a
// parse offset across reads — re-feeding the whole buffered remainder on
// every read re-scans and re-copies megabytes for multi-MB chunks.
// Payload bytes emit as they arrive (completion still waits for the chunk's
// trailing CRLF); a corrupt frame fails the whole response either way, so
// early emission never smuggles bytes past the caller's checks.
function proxy_chunked_state(): array {
    return ['buf' => '', 'off' => 0, 'size' => null, 'done' => false];
}

/** @return ?array{string,bool} [newly-decoded bytes, done] (null = corrupt framing) */
function proxy_chunked_push(array &$st, string $more): ?array {
    $st['buf'] .= $more;
    $out = '';
    while (true) {
        if ($st['done']) {
            return [$out, true];
        }
        if ($st['size'] === null) {
            $i = strpos($st['buf'], "\r\n", $st['off']);
            if ($i === false) {
                if (strlen($st['buf']) - $st['off'] > PROXY_CHUNK_LINE_MAX) {
                    return null;
                }
                break; // partial size line — wait for more
            }
            $line = substr($st['buf'], $st['off'], $i - $st['off']);
            if (strlen($line) > PROXY_CHUNK_LINE_MAX
                || preg_match('/^([0-9a-fA-F]{1,8})(;[^\r]*)?$/', $line, $m) !== 1) {
                return null;
            }
            $size = hexdec($m[1]);
            if ($size > PROXY_CHUNK_MAX) {
                return null;
            }
            $st['off'] = $i + 2;
            if ($size === 0) {
                $st['done'] = true;
                $st['buf'] = '';
                $st['off'] = 0;
                return [$out, true];
            }
            $st['size'] = $size;
        }
        $take = min($st['size'], strlen($st['buf']) - $st['off']);
        if ($take > 0) {
            $out .= substr($st['buf'], $st['off'], $take);
            $st['off'] += $take;
            $st['size'] -= $take;
        }
        if ($st['size'] > 0) {
            break; // need more payload bytes
        }
        if (strlen($st['buf']) - $st['off'] < 2) {
            break; // chunk complete, trailing CRLF not here yet
        }
        if (substr($st['buf'], $st['off'], 2) !== "\r\n") {
            return null;
        }
        $st['off'] += 2;
        $st['size'] = null;
        // Compact the parsed prefix so the buffer never holds more than a
        // sliver of already-emitted bytes.
        if ($st['off'] > 1048576) {
            $st['buf'] = substr($st['buf'], $st['off']);
            $st['off'] = 0;
        }
    }
    return [$out, false];
}

// Response header lines (without the status line) as name => value, names
// lowercased; repeated headers keep the first — Content-Length games between
// duplicates fail closed downstream via the exact-length checks.
function proxy_head_fields(string $head): array {
    $fields = [];
    $lines = explode("\r\n", $head);
    array_shift($lines);
    foreach ($lines as $line) {
        $i = strpos($line, ':');
        if ($i === false) continue;
        $name = strtolower(trim(substr($line, 0, $i)));
        if ($name === '' || isset($fields[$name])) continue;
        $fields[$name] = trim(substr($line, $i + 1));
    }
    return $fields;
}

// Resolve a Location against the request URL (absolute, protocol-relative,
// root-relative, or relative — anything else fails closed to null).
function proxy_resolve_url(string $base, string $loc): ?string {
    $loc = trim($loc);
    if ($loc === '') return null;
    if (preg_match('/^https?:\/\//i', $loc) === 1) return $loc;
    $b = parse_url($base);
    if (!is_array($b) || empty($b['scheme']) || empty($b['host'])) return null;
    $origin = strtolower((string)$b['scheme']) . '://' . $b['host']
        . (isset($b['port']) ? ':' . $b['port'] : '');
    if (str_starts_with($loc, '//')) return strtolower((string)$b['scheme']) . ':' . $loc;
    if (str_starts_with($loc, '/')) return $origin . $loc;
    $path = (string)($b['path'] ?? '/');
    $cut = strrpos($path, '/');
    $dir = $cut === false ? '/' : substr($path, 0, $cut + 1);
    return $origin . $dir . $loc;
}

// Write everything or nothing (false): partial writes on a non-blocking
// socket wait for writability instead of spinning.
function proxy_write_all(mixed $sock, string $data, float $deadline): bool {
    while ($data !== '') {
        $left = $deadline - microtime(true);
        if ($left <= 0) return false;
        $r = null;
        $w = [$sock];
        $e = null;
        if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) !== 1) return false;
        $n = @fwrite($sock, $data);
        if (!is_int($n) || $n <= 0) return false;
        $data = substr($data, $n);
    }
    return true;
}

// Read until $done($buffer) returns non-null, the cap is passed, the peer
// hangs up, or the deadline passes. Returns $done's answer, or null.
function proxy_read_until(mixed $sock, float $deadline, callable $done, int $cap): mixed {
    $buf = '';
    while (true) {
        $res = $done($buf);
        if ($res !== null) return $res;
        if (strlen($buf) > $cap) return null;
        $left = $deadline - microtime(true);
        if ($left <= 0) return null;
        $r = [$sock];
        $w = null;
        $e = null;
        if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) !== 1) return null;
        $chunk = @fread($sock, 65536);
        if (!is_string($chunk) || $chunk === '') return null; // EOF or error before $done fired
        $buf .= $chunk;
    }
}

// Read exactly $n bytes for the SOCKS fixed-size replies. Reads are sized
// to the remainder: fread may return MORE than asked would discard (the
// 10-byte SOCKS reply is read as 4+6 — a 64K gulp would eat the tail),
// never more than needed.
function proxy_read_n(mixed $sock, int $n, float $deadline): ?string {
    $buf = '';
    while (strlen($buf) < $n) {
        $left = $deadline - microtime(true);
        if ($left <= 0) return null;
        $r = [$sock];
        $w = null;
        $e = null;
        if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) !== 1) return null;
        $chunk = @fread($sock, $n - strlen($buf));
        if (!is_string($chunk) || $chunk === '') return null;
        $buf .= $chunk;
    }
    return $buf;
}

// TLS handshake on a connected socket, bounded to ~$secs. The handshake
// loop inside PHP may wait on default_socket_timeout rather than the
// stream's own timeout, so both are pinned and restored — a blackholing
// peer stalls seconds, never a minute.
function proxy_enable_tls(mixed $sock, int $secs = 5): bool {
    $prev = ini_get('default_socket_timeout');
    @ini_set('default_socket_timeout', (string)max(1, $secs));
    @stream_set_timeout($sock, max(1, $secs));
    try {
        return (bool)@stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    } finally {
        if (is_string($prev)) {
            @ini_set('default_socket_timeout', $prev);
        }
    }
}

// TLS to the TARGET through a tunnel: the socket's context still names the
// proxy (peer_name drives both SNI and certificate verification), so point
// it at the target first — otherwise every tunnelled handshake verifies the
// target's certificate against the proxy's name and fails.
function proxy_target_tls(mixed $sock, array $t, ?string $caFile, int $secs = 5): bool {
    $ssl = [
        'peer_name' => $t['host'],
        'verify_peer' => true,
        'verify_peer_name' => true,
    ];
    if ($caFile !== null) {
        $ssl['cafile'] = $caFile;
    }
    @stream_context_set_option($sock, ['ssl' => $ssl]);
    return proxy_enable_tls($sock, $secs);
}

function proxy_ssl_context(string $peerHost, ?string $caFile): mixed {
    $ssl = [
        'peer_name' => $peerHost,
        'verify_peer' => true,
        'verify_peer_name' => true,
    ];
    if ($caFile !== null) {
        $ssl['cafile'] = $caFile;
    }
    return stream_context_create(['ssl' => $ssl]);
}

// Open a socket to the target: direct, forwarded by an HTTP proxy (plain
// HTTP targets need no tunnel), CONNECT-tunnelled, or SOCKS-handshaked.
// Returns [socket, isForwardProxy] or null. TLS to the target is enabled by
// the caller for tunnels (direct TLS connects with the tls:// wrapper,
// which handshakes inside the connect timeout).
/** @return ?array{mixed,bool} */
function proxy_sock_open(?array $px, array $t, float $deadline, ?string $caFile): ?array {
    if (!function_exists('stream_socket_client')) return null;
    $left = static function () use ($deadline): float {
        return $deadline - microtime(true);
    };
    if ($px === null) {
        if ($left() <= 0) return null;
        $s = @stream_socket_client(
            ($t['tls'] ? 'tls' : 'tcp') . '://' . $t['dial'] . ':' . $t['port'],
            $eno, $estr, max(0.5, min(15.0, $left())),
            STREAM_CLIENT_CONNECT, proxy_ssl_context($t['host'], $caFile)
        );
        return is_resource($s) ? [$s, false] : null;
    }
    if ($left() <= 0) return null;
    $s = @stream_socket_client(
        'tcp://' . $px['dial'] . ':' . $px['port'],
        $eno, $estr, max(0.5, min(10.0, $left())),
        STREAM_CLIENT_CONNECT, proxy_ssl_context($px['host'], $caFile)
    );
    if (!is_resource($s)) return null;
    $scheme = $px['scheme'];
    if ($scheme === 'https') {
        // TLS to the proxy itself first, then the proxy protocol inside it.
        if (!proxy_enable_tls($s, 5)) {
            fclose($s);
            return null;
        }
        $scheme = 'http';
    }
    if ($scheme === 'http') {
        if (!$t['tls']) {
            return [$s, true]; // plain HTTP: the request carries the absolute URI, no tunnel
        }
        if (!proxy_write_all($s, proxy_connect_head($t['dial'], $t['port'], $px['user'], $px['pass']), $deadline)) {
            fclose($s);
            return null;
        }
        $split = proxy_read_until($s, $deadline,
            static fn(string $b): ?array => proxy_head_split($b), 32768);
        if (!is_array($split) || proxy_status_code($split[0]) !== 200) {
            fclose($s); // anything but 200 (407, 403, garbage) fails closed
            return null;
        }
        return [$s, false];
    }
    if ($scheme === 'socks5' || $scheme === 'socks5h') {
        if (!proxy_write_all($s, proxy_socks5_greet($px['user']), $deadline)) {
            fclose($s);
            return null;
        }
        $greet = proxy_read_n($s, 2, $deadline);
        if ($greet === null || $greet[0] !== "\x05") {
            fclose($s);
            return null;
        }
        if ($greet[1] === "\x02") {
            if ($px['user'] === '') {
                fclose($s); // auth demanded, none configured
                return null;
            }
            if (!proxy_write_all($s, proxy_socks5_auth($px['user'], $px['pass']), $deadline)) {
                fclose($s);
                return null;
            }
            $auth = proxy_read_n($s, 2, $deadline);
            if ($auth === null || $auth[1] !== "\x00") {
                fclose($s);
                return null;
            }
        } elseif ($greet[1] !== "\x00") {
            fclose($s);
            return null;
        }
        if (strlen($t['host']) > 255 || !proxy_write_all($s, proxy_socks5_connect($t['host'], $t['port']), $deadline)) {
            fclose($s);
            return null;
        }
        $rep = proxy_read_n($s, 4, $deadline);
        if ($rep === null || $rep[1] !== "\x00") {
            fclose($s);
            return null;
        }
        // The bind address length depends on its type; drain it, trust nothing in it.
        $tail = match ($rep[3]) {
            "\x01" => 6, // IPv4 + port
            "\x04" => 18, // IPv6 + port
            default => null,
        };
        if ($tail === null) {
            if ($rep[3] !== "\x03") {
                fclose($s);
                return null;
            }
            $ln = proxy_read_n($s, 1, $deadline);
            if ($ln === null) {
                fclose($s);
                return null;
            }
            $tail = ord($ln) + 2;
        }
        if (proxy_read_n($s, $tail, $deadline) === null) {
            fclose($s);
            return null;
        }
        return [$s, false];
    }
    if ($scheme === 'socks4') {
        if (!proxy_write_all($s, proxy_socks4_connect($t['host'], $t['port'], $px['user'] ?: 'ddmgmt'), $deadline)) {
            fclose($s);
            return null;
        }
        $rep = proxy_read_n($s, 8, $deadline);
        if ($rep === null || $rep[0] !== "\x00" || $rep[1] !== "\x5a") {
            fclose($s);
            return null;
        }
        return [$s, false];
    }
    fclose($s);
    return null;
}

// One HTTP request over any transport: direct, HTTP-proxy forwarded,
// CONNECT-tunnelled (TLS inside for https targets), or SOCKS-handshaked.
// Follows redirects (same rules as cURL: 301/302/303 re-issue as GET, 307/8
// keep the method), decodes chunked bodies, caps the body at $maxBytes+1 to
// detect over-long answers. $sink receives body chunks for callers that
// stream to disk (no cap then, no body kept). $caFile pins the CA bundle
// (tests); null uses the system default. Never throws.
// @return array{code:int,headers:list<string>,body:string,bytes:int,truncated:bool}
// code 0 means the transport itself failed.
function proxy_request_streams(string $method, string $url, array $headers = [], ?string $proxy = null, int $timeout = 5, int $maxBytes = 2097152, int $maxRedirects = 3, ?callable $sink = null, ?string $caFile = null): array {
    $fail = ['code' => 0, 'headers' => [], 'body' => '', 'bytes' => 0, 'truncated' => false];
    try {
        if ($method !== 'GET' && $method !== 'HEAD') return $fail;
        if ($maxBytes < 0) return $fail;
        $deadline = microtime(true) + max(1, $timeout);
        $px = null;
        if ($proxy !== null) {
            $px = proxy_parse($proxy);
            if ($px === null) return $fail;
        }
        $cur = $url;
        for ($r = 0; $r <= max(0, $maxRedirects); $r++) {
            $t = proxy_parse_target($cur);
            if ($t === null) return $fail;
            $opened = proxy_sock_open($px, $t, $deadline, $caFile);
            if ($opened === null) return $fail;
            [$s, $forward] = $opened;
            $done = static function () use ($s): void {
                if (is_resource($s)) fclose($s);
            };
            // TLS inside a tunnel cannot use the tls:// wrapper (the socket
            // is already connected): enable crypto on it, bounded so a
            // blackholing proxy cannot stall past the handshake.
            if ($t['tls'] && ($px !== null)) {
                if (!proxy_target_tls($s, $t, $caFile, 5)) {
                    $done();
                    return $fail;
                }
            }
            $target = $forward ? $cur : $t['path'];
            $req = "{$method} {$target} HTTP/1.1\r\n"
                . 'Host: ' . $t['dial'] . (($t['tls'] && $t['port'] === 443) || (!$t['tls'] && $t['port'] === 80) ? '' : ':' . $t['port']) . "\r\n"
                . "User-Agent: DeadDropMGMT/1.0\r\nConnection: close\r\n";
            if ($forward && $px !== null && $px['user'] !== '') {
                $req .= 'Proxy-Authorization: ' . proxy_basic_auth($px['user'], $px['pass']) . "\r\n";
            }
            foreach ($headers as $h) {
                $h = trim((string)$h);
                if ($h !== '') $req .= $h . "\r\n";
            }
            $req .= "\r\n";
            if (!proxy_write_all($s, $req, $deadline)) {
                $done();
                return $fail;
            }
            $split = proxy_read_until($s, $deadline,
                static fn(string $b): ?array => proxy_head_split($b), 32768);
            if (!is_array($split)) {
                $done();
                return $fail;
            }
            [$head, $rest] = $split;
            $code = proxy_status_code($head);
            $respHeaders = explode("\r\n", $head);
            if ($code === 0) {
                $done();
                return $fail;
            }
            if (in_array($code, [301, 302, 303, 307, 308], true) && $r < max(0, $maxRedirects)) {
                $fields = proxy_head_fields($head);
                $done();
                if (!isset($fields['location'])) return [...$fail, 'code' => $code, 'headers' => $respHeaders];
                $next = proxy_resolve_url($cur, $fields['location']);
                if ($next === null) return [...$fail, 'code' => $code, 'headers' => $respHeaders];
                if (in_array($code, [301, 302, 303], true) && $method !== 'HEAD') {
                    $method = 'GET'; // cURL parity: only HEAD stays HEAD
                }
                $cur = $next;
                continue;
            }
            $body = '';
            $bytes = 0;
            $truncated = false;
            $emit = static function (string $chunk) use (&$body, &$bytes, $sink): void {
                $bytes += strlen($chunk);
                if ($sink !== null) {
                    $sink($chunk);
                } else {
                    $body .= $chunk;
                }
            };
            $cap = $sink !== null ? null : $maxBytes + 1; // one byte past the cap proves over-long
            $fields = proxy_head_fields($head);
            $noBody = $method === 'HEAD' || $code === 204 || $code === 304;
            $ok = true;
            if (!$noBody && ($fields['transfer-encoding'] ?? '') !== '' && str_contains(strtolower($fields['transfer-encoding']), 'chunked')) {
                $st = proxy_chunked_state();
                $fed = proxy_chunked_push($st, $rest);
                $rest = '';
                while (true) {
                    if ($fed === null) {
                        $ok = false;
                        break;
                    }
                    [$dec, $fin] = $fed;
                    if ($cap !== null && $bytes + strlen($dec) > $cap) {
                        // Over the cap: keep the head of it (callers that
                        // tolerate long bodies, like Range-ignoring servers,
                        // need those bytes), flag it, stop.
                        $keep = $cap - $bytes;
                        if ($keep > 0) {
                            $emit(substr($dec, 0, $keep));
                        }
                        $truncated = true;
                        break;
                    }
                    $emit($dec);
                    if ($fin) break;
                    if (microtime(true) >= $deadline) {
                        $ok = false;
                        break;
                    }
                    $more = proxy_read_until($s, $deadline,
                        static fn(string $b): ?string => $b !== '' ? $b : null, 65536);
                    if (!is_string($more)) {
                        $ok = false; // EOF mid-chunks is corruption, never a short body
                        break;
                    }
                    $fed = proxy_chunked_push($st, $more);
                }
            } elseif (!$noBody) {
                $buf = $rest;
                $rest = '';
                $want = null;
                if (isset($fields['content-length']) && preg_match('/^\d+$/', $fields['content-length']) === 1) {
                    $want = (int)$fields['content-length'];
                }
                while (true) {
                    if ($buf !== '') {
                        $take = $buf;
                        if ($want !== null) {
                            $need = $want - $bytes;
                            if ($need <= 0) break;
                            $take = substr($buf, 0, $need);
                        }
                        if ($cap !== null && $bytes + strlen($take) > $cap) {
                            $keep = $cap - $bytes;
                            if ($keep > 0) {
                                $emit(substr($take, 0, $keep));
                            }
                            $truncated = true;
                            break;
                        }
                        $emit($take);
                        $buf = substr($buf, strlen($take));
                        if ($want !== null && $bytes >= $want) break;
                    }
                    if ($want !== null && $bytes >= $want) break;
                    if (microtime(true) >= $deadline) {
                        $ok = false;
                        break;
                    }
                    $rset = [$s];
                    $w = null;
                    $e = null;
                    $left = $deadline - microtime(true);
                    $n = @stream_select($rset, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000));
                    if ($n !== 1) {
                        // No more data: EOF ends a close-delimited body, but a
                        // Content-Length shortfall is corruption.
                        $ok = $want === null;
                        break;
                    }
                    $chunk = @fread($s, 65536);
                    if (!is_string($chunk) || $chunk === '') {
                        $ok = $want === null;
                        break;
                    }
                    $buf .= $chunk;
                }
                if (!$truncated && $ok && $want !== null && $bytes !== $want) $ok = false;
            }
            $done();
            if (!$ok) return $fail;
            if ($truncated) return [...$fail, 'code' => $code, 'headers' => $respHeaders, 'body' => $sink !== null ? '' : $body, 'bytes' => $bytes, 'truncated' => true];
            return ['code' => $code, 'headers' => $respHeaders, 'body' => $sink !== null ? '' : $body, 'bytes' => $bytes, 'truncated' => false];
        }
        return $fail; // redirect loop exhausted
    } catch (Throwable) {
        return $fail;
    }
}

// One GET through a specific proxy (or direct when $proxy is null).
// Returns body on HTTP 2xx, false otherwise. cURL first when present; the
// pure-PHP transport above otherwise — every proxy scheme works on both.
// Never throws. $maxBytes caps the response body on BOTH transports.
function osm_fetch_via(string $url, ?string $proxy, int $timeout = 5, int $maxBytes = 2097152): string|false {
    if (host_has_curl()) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_MAXFILESIZE    => $maxBytes,
            CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        if ($proxy !== null) {
            curl_setopt($ch, CURLOPT_PROXY, proxy_curl_url($proxy));
        }

        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit

        if ($code < 200 || $code >= 300 || !is_string($body) || strlen($body) > $maxBytes) {
            return false;
        }
        return $body;
    }

    // No cURL on this host — the pure-PHP transport speaks every proxy
    // scheme (CONNECT, SOCKS) as well as direct. Over-long bodies fail the
    // same way as the cURL ceiling above; redirects are not followed, also
    // matching the cURL branch (FOLLOWLOCATION is off there).
    $res = proxy_request_streams('GET', $url, [], $proxy, $timeout, $maxBytes, 0);
    if ($res['code'] < 200 || $res['code'] >= 300 || $res['truncated']) {
        return false;
    }
    return $res['body'];
}

// ── Tile cache upkeep ───────────────────────────────────────────────────────
// cache/osm_tiles/<z>/<x>/<y>.png is filled by tile_proxy.php on demand. Aged
// entries and everything beyond the byte cap are dropped (oldest first) by
// the hourly cleanup, so the cache cannot grow without bound however many
// distinct tiles an admin (or a runaway script) requests. Returns the number
// of files removed; never throws.
function osm_tile_cache_prune(?string $dir = null, int $maxBytes = 268435456, int $ttl = 604800): int {
    $dir = $dir ?? dirname(__DIR__) . '/cache/osm_tiles';
    if (!is_dir($dir)) {
        return 0;
    }
    $removed = 0;
    try {
        $files = [];
        $total = 0;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        $now = time();
        foreach ($it as $f) {
            if ($f->isDir()) {
                @rmdir($f->getPathname()); // only succeeds when empty
                continue;
            }
            if ($f->isLink() || !$f->isFile()) {
                @unlink($f->getPathname());
                continue;
            }
            if (($now - $f->getMTime()) >= $ttl) {
                if (@unlink($f->getPathname())) {
                    $removed++;
                }
                continue;
            }
            $files[] = [$f->getMTime(), $f->getSize(), $f->getPathname()];
            $total += $f->getSize();
        }
        if ($total > $maxBytes) {
            usort($files, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
            foreach ($files as [, $size, $path]) {
                if ($total <= $maxBytes) {
                    break;
                }
                if (@unlink($path)) {
                    $total -= $size;
                    $removed++;
                }
            }
        }
    } catch (Throwable $e) {
        log_err('Tile cache prune: ' . $e->getMessage());
    }
    return $removed;
}

// A real PNG starts with the fixed 8-byte signature. Anything else that came
// back from a (possibly hostile, public) pool proxy is not a tile.
function osm_is_png(string $data): bool {
    return str_starts_with($data, "\x89PNG\r\n\x1a\n");
}

function osm_proxy_mark(int $id, bool $ok, ?int $latency_ms = null, ?array $prev = null): void {
    try {
        // One tile miss used to UPDATE on every attempt: skip the write when
        // nothing material changed (same status, fresh check, similar
        // latency). Status flips and stale rows always write through.
        if (is_array($prev)) {
            $sameStatus = ($prev['last_status'] ?? null) === ($ok ? 'ok' : 'fail');
            $prevMs = (int)($prev['latency_ms'] ?? ($latency_ms ?? 0));
            $latencyClose = $latency_ms === null || abs($prevMs - $latency_ms) < 500;
            $checkedAt = isset($prev['last_checked']) ? strtotime((string)$prev['last_checked']) : false;
            if ($sameStatus && $latencyClose && $checkedAt !== false && (time() - $checkedAt) < 60) {
                return;
            }
        }
        get_db()->prepare(
            'UPDATE osm_proxies
             SET last_status = ?, latency_ms = ?, last_checked = NOW()
             WHERE id = ?'
        )->execute([$ok ? 'ok' : 'fail', $latency_ms, $id]);
    } catch (Exception $e) {
        log_err('Proxy mark: ' . $e->getMessage());
    }
}

// ── Stale-pool revalidation ─────────────────────────────────────────────────
// A manually added proxy is only format-checked at insert, and a stored one
// is only re-probed when live traffic happens to exercise it. Entries nobody
// exercises — routing disabled, or an earlier pool member always winning —
// keep their stale 'ok'/'new' forever, including typo'd-but-well-formed
// URLs. The cleanup passes re-probe the stalest few so the settings page
// never shows a healthy pool that is actually dead.
//
// Bounded: at most $max entries per pass, oldest-unchecked first, one
// parallel probe round with short timeouts. Never throws; an empty pool is
// one cheap SELECT, no network.
function osm_proxy_revalidate_stale(int $max = 3, int $stale_days = 7, ?string $probe_url = null): array {
    try {
        $db = get_db();
        $stmt = $db->prepare(
            'SELECT id, url FROM osm_proxies
             WHERE last_checked IS NULL OR last_checked < DATE_SUB(NOW(), INTERVAL ? DAY)
             ORDER BY last_checked IS NOT NULL, last_checked ASC
             LIMIT ' . max(1, $max)
        );
        $stmt->execute([$stale_days]);
        $due = $stmt->fetchAll();
        if (!$due) return [];
        $urls = [];
        foreach ($due as $row) {
            $urls[(int)$row['id']] = (string)$row['url'];
        }
        $probe = $probe_url ?? 'https://a.tile.openstreetmap.org/13/4051/2749.png';
        $res = proxy_multi_probe(array_values($urls), $probe, 3, 2);
        $out = [];
        foreach ($urls as $id => $url) {
            [$code, $ms] = $res[$url] ?? [0, 0];
            $ok = $code >= 200 && $code < 300;
            osm_proxy_mark($id, $ok, $ms);
            $out[$url] = $ok;
        }
        return $out;
    } catch (Throwable $e) {
        log_err('Proxy revalidate: ' . $e->getMessage());
        return [];
    }
}

// ── Pool circuit breaker ──────────────────────────────────────────────────
// One map view fires 15-30 tile requests at once; when every proxy is dead
// they all walk the whole pool (seconds each) and take every PHP worker
// with them. Tripping records "pool down until T" plus a fingerprint of the
// pool that failed, so later requests against the SAME pool fail at once
// instead of re-probing. A changed pool (heal/discovery swapped members)
// clears the trip implicitly through the fingerprint; any success clears it
// explicitly. Shared through the settings table so all FPM workers see it.
function osm_pool_circuit_fp(array $pool): string {
    $ids = [];
    foreach ($pool as $px) {
        $ids[] = (int)($px['id'] ?? 0);
    }
    sort($ids);
    return implode(',', $ids);
}

function osm_pool_circuit_open(array $pool): bool {
    if ((int)get_setting('pool_down_until', '0') <= time()) {
        return false;
    }
    return get_setting('pool_down_fp', '') === osm_pool_circuit_fp($pool);
}

function osm_pool_circuit_trip(array $pool, int $secs = 60): void {
    set_setting('pool_down_until', (string)(time() + $secs));
    set_setting('pool_down_fp', osm_pool_circuit_fp($pool));
}

function osm_pool_circuit_clear(): void {
    set_setting('pool_down_until', '0');
    set_setting('pool_down_fp', '');
}

// Fetch an OSM resource honouring the osm_proxy_enabled setting. Tries each
// pool member fastest-first; gives up (returns false) if all fail while
// routing is enabled — that is the point of fail-closed.
//
// Session note: this function never touches $_SESSION directly. The caller
// is expected to session_write_close() before invoking it (so a slow proxy
// chain doesn't lock out every other admin page) and then call
// osm_last_via_flush() afterwards, which re-opens the session just long
// enough to record what happened for the admin badge.
//
// Bail-outs between attempts: an overall wall-clock budget (a big pool
// must not churn for minutes) and a client-disconnect check, so a user who
// navigated away stops generating further proxy attempts.
function osm_fetch(string $url, int $maxBytes = 2097152): string|false {
    if (!osm_proxy_enabled()) {
        return osm_fetch_via($url, null, 5, $maxBytes);
    }

    $pool = osm_proxy_pool();
    if (!$pool) {
        osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => 0, 'skipped' => []]);
        osm_proxy_heal_kick(); // first run / emptied pool: discover one in the background
        return false; // enabled with an empty pool would mean going direct = leak
    }

    // Try the fastest known-good proxy first: working ones ordered by last
    // measured latency, then untested, then previously-dead as last resort.
    // Each attempt gets 2 seconds before moving on to the next candidate;
    // the whole request is capped at 10 s. A tripped circuit breaker (the
    // same pool failed wholesale under a minute ago) skips the walk and
    // fails at once — one map view fires dozens of parallel tile requests,
    // and without this they re-probe the dead pool together and stall
    // every PHP worker.
    usort($pool, function ($a, $b) {
        $rank = function ($p) {
            return match ($p['last_status'] ?? '') {
                'ok'   => 0,
                'new'  => 1,
                default => 2,
            };
        };
        $ra = $rank($a);
        if ($ra !== ($rb = $rank($b))) return $ra <=> $rb;
        return ((int)($a['latency_ms'] ?? PHP_INT_MAX)) <=> ((int)($b['latency_ms'] ?? PHP_INT_MAX));
    });

    $deadline = microtime(true) + 10.0; // whole-request budget across all attempts
    $attempts = 0;
    $skipped  = []; // proxies that timed out / failed before the winner
    if (osm_pool_circuit_open($pool)) {
        osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => 0, 'skipped' => []]);
        return false; // same pool just failed wholesale — don't re-probe it
    }
    foreach ($pool as $px) {
        if (microtime(true) >= $deadline || connection_aborted()) {
            break; // budget exhausted or client gone — stop burning the pool
        }
        $attempts++;
        $t0     = microtime(true);
        $result = osm_fetch_via($url, $px['url'], 2, $maxBytes);
        $ms     = (int)round((microtime(true) - $t0) * 1000);
        osm_proxy_mark((int)$px['id'], $result !== false, $ms, $px);
        if ($result !== false) {
            osm_pool_circuit_clear(); // the pool works again — lift any trip
            osm_last_via_set([
                'via'        => osm_proxy_redact($px['url']),
                'latency_ms' => $ms,
                'failed'     => false,
                'attempts'   => $attempts,
                'skipped'    => $skipped,
            ]);
            if ($skipped) {
                osm_proxy_heal_kick(); // members ahead of the winner just failed
            }
            return $result;
        }
        $skipped[] = osm_proxy_redact($px['url']);
    }
    osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => $attempts, 'skipped' => $skipped]);
    if ($attempts > 0) {
        osm_pool_circuit_trip($pool); // wholesale failure — spare the next requests the walk
    }
    if ($skipped) {
        osm_proxy_heal_kick();
    }
    return false;
}

// Reverse-geocode one point through Nominatim (same proxy routing as the
// forward search — never direct when routing is enabled). Returns the raw
// address array or null. Callers display osm_place_label(), never raw
// coordinates: owner-facing surfaces hide lat/lng by policy.
/** @return ?array<string,mixed> */
function osm_reverse_lookup(float $lat, float $lng): ?array {
    $url = osm_reverse_url($lat, $lng);
    if ($url === null) {
        return null;
    }
    $data = osm_fetch($url, 65536);
    if ($data === false) {
        return null;
    }
    return osm_reverse_parse($data);
}

// Decode one Nominatim reverse answer to its address array (pure half of
// the lookup — garbage in answers null, never a partial address).
/** @return ?array<string,mixed> */
function osm_reverse_parse(string $data): ?array {
    $j = json_decode($data, true);
    if (!is_array($j)) {
        return null;
    }
    $addr = $j['address'] ?? null;
    return is_array($addr) ? $addr : null;
}

// Cached reverse lookup: pin labels repeat for every pin click, drag and
// edit-page load, and each one costs a full proxied Nominatim request plus
// a slice of the 60/minute budget. Labels change with map data, not with
// time — a per-account file cache keyed by coordinates rounded to 0.01°
// (≈1 km, matching the endpoint's own rounding) with a 30-day life.
// Per account like the tile cache (one account's viewed areas must never
// leak into another's). Only the address array is stored, never raw coords
// beyond the rounded cache key. Never throws; a dead cache just misses.
/** @return ?array<string,mixed> */
function osm_reverse_cached(int $uid, float $lat, float $lng): ?array {
    $lat = round($lat, 2);
    $lng = round($lng, 2);
    $key = sprintf('%.2F_%.2F', $lat, $lng);
    $dir = dirname(__DIR__) . '/cache/geocode/' . $uid;
    $file = $dir . '/' . $key . '.json';
    try {
        if (is_file($file) && (time() - (int)@filemtime($file)) < 2592000) {
            $hit = json_decode((string)@file_get_contents($file), true);
            if (is_array($hit)) {
                return $hit;
            }
        }
    } catch (Throwable) {
    }
    $addr = osm_reverse_lookup($lat, $lng);
    if ($addr !== null) {
        try {
            if (!is_dir($dir)) {
                @mkdir($dir, 0770, true);
            }
            @file_put_contents($file, json_encode($addr, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } catch (Throwable) {
        }
    }
    return $addr;
}

// Prune aged reverse-label entries (hourly cleanup). Returns files removed;
// never throws.
function osm_geocode_cache_prune(?string $dir = null, int $ttl = 2592000): int {
    $dir = $dir ?? dirname(__DIR__) . '/cache/geocode';
    if (!is_dir($dir)) {
        return 0;
    }
    $removed = 0;
    try {
        $now = time();
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            $p = $f->getPathname();
            if ($f->isDir()) {
                @rmdir($p); // only succeeds when empty
                continue;
            }
            if ($f->isLink() || !$f->isFile()) {
                @unlink($p);
                continue;
            }
            if (($now - $f->getMTime()) >= $ttl && @unlink($p)) {
                $removed++;
            }
        }
    } catch (Throwable $e) {
        log_err('Geocode cache prune: ' . $e->getMessage());
    }
    return $removed;
}
// Nominatim reverse URL for a point, or null outside geography (pure —
// the network half of osm_reverse_lookup stays thin and untested by unit
// suites, which must never reach tile hosts).
function osm_reverse_url(float $lat, float $lng): ?string {
    if (!is_finite($lat) || !is_finite($lng) || $lat < -90.0 || $lat > 90.0 || $lng < -180.0 || $lng > 180.0) {
        return null;
    }
    // Fixed-point, never (string)$float: tiny values would print as "1.0E-5",
    // which Nominatim rejects.
    return 'https://nominatim.openstreetmap.org/reverse?lat=' . sprintf('%.7F', $lat)
        . '&lon=' . sprintf('%.7F', $lng) . '&format=json&accept-language=en';
}

// Human label for a Nominatim address: "Country, State". Either half may be
// absent (sea points, nameless hamlets) — what's there is what's shown.
// Nothing known renders '' and the caller falls back to a generic
// placed/draft text instead of coordinates.
function osm_place_label(mixed $addr): string {
    if (!is_array($addr)) {
        return '';
    }
    $parts = [];
    foreach (['country', 'state'] as $k) {
        $v = trim((string)($addr[$k] ?? ''));
        if ($v !== '') {
            $parts[] = $v;
        }
    }
    return implode(', ', $parts);
}

// Shared storage for the staged badge info of the current request.
// func_num_args() distinguishes an explicit osm_last_via_stage(null)
// ("consume") from a parameterless read — the previous !== null check made
// the consume call a silent no-op, so stale badge info survived the flush.
function osm_last_via_stage(?array $info = null): ?array {
    static $staged = null;
    if (func_num_args() > 0) {
        $staged = $info;
    }
    return $staged;
}

// Stash badge info for the current request; flushed to the session later by
// osm_last_via_flush() once the caller has released the session lock.
function osm_last_via_set(array $info): void {
    osm_last_via_stage($info);
}

// Write the staged badge info to the session. Safe to call even when the
// session was closed (or never started) — it re-opens the session briefly,
// writes, and closes again so locks are held only for milliseconds.
// Identical re-writes are skipped: 30 parallel tile misses would otherwise
// serialize on the session file for no new information.
function osm_last_via_flush(): void {
    $staged = osm_last_via_stage();
    if ($staged === null) return;
    osm_last_via_stage(null); // consume
    if (session_status() !== PHP_SESSION_ACTIVE && !headers_sent()) {
        session_start();
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        if (($_SESSION['osm_last_via'] ?? null) !== $staged) {
            $_SESSION['osm_last_via'] = $staged;
        }
        session_write_close();
    }
}

// ── Discovery ────────────────────────────────────────────────────────────────

// Sources of candidate proxies — all free, community-maintained, fetched
// from GitHub raw. 'rated' marks sources whose HTTP entries carry a real
// anonymity rating (anonymous/elite); HTTP entries from unrated sources are
// only accepted after passing a live anonymity check (see proxy_discover).
// SOCKS proxies are header-anonymous by protocol and always qualify.
const PROXY_DISCOVERY_SOURCES = [
    // rated JSON with anonymity metadata
    ['name' => 'proxifly',   'url' => 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json', 'type' => 'proxifly', 'rated' => true],
    // hourly pre-checked plain lists
    ['name' => 'monosans',   'url' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',    'type' => 'plain', 'proto' => 'http',   'rated' => false],
    ['name' => 'monosans',   'url' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',  'type' => 'plain', 'proto' => 'socks4', 'rated' => true],
    ['name' => 'monosans',   'url' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',  'type' => 'plain', 'proto' => 'socks5', 'rated' => true],
    // high-volume lists
    ['name' => 'thespeedx',  'url' => 'https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/http.txt',   'type' => 'plain', 'proto' => 'http',   'rated' => false],
    ['name' => 'thespeedx',  'url' => 'https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/socks4.txt', 'type' => 'plain', 'proto' => 'socks4', 'rated' => true],
    ['name' => 'thespeedx',  'url' => 'https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/socks5.txt', 'type' => 'plain', 'proto' => 'socks5', 'rated' => true],
    // curated, regularly refreshed
    ['name' => 'roosterkid', 'url' => 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',  'type' => 'plain', 'proto' => 'http',   'rated' => false],
    ['name' => 'roosterkid', 'url' => 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt', 'type' => 'plain', 'proto' => 'socks5', 'rated' => true],
];

// Header-echo judge used to verify that an HTTP proxy does not leak our IP
// via Via / X-Forwarded-For style headers. Plain HTTP on purpose — it must
// work through proxies that lack CONNECT support.
const PROXY_ANONYMITY_JUDGES = [
    'http://httpbin.org/get',
    'http://azenv.net/',
];

// Learn this server's public IP so the judge response can be scanned for it.
// Privacy trade-off, stated openly: this makes a DIRECT clearnet connection
// to ipify/httpbin, disclosing the server IP to exactly those two parties.
// That is the price of verifying the pool hides it from everyone else (OSM);
// the call happens only on owner-initiated discovery, never per request.
function proxy_public_ip(): ?string {
    foreach (['https://api.ipify.org?format=text', 'http://httpbin.org/ip'] as $url) {
        // An IP is bytes, not megabytes: cap the read like every other fetch.
        // Through the shared fetcher so it works via cURL where
        // allow_url_fopen is off (common on shared hosting).
        $raw = osm_fetch_via($url, null, 8, 4096);
        if (!is_string($raw)) {
            continue;
        }
        if (preg_match('/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/', $raw, $m)) {
            return $m[1];
        }
    }
    return null;
}

// Run one anonymity judge through a proxy. Returns true only when EVERY
// reachable judge's response is clean: a leaking proxy may be visible to
// just one judge (different judges echo different fields), so the first
// clean answer must not accept the proxy. Unreachable judges are skipped;
// when none are reachable the answer is false (could not verify — maximum
// security means reject). $judges override exists for tests.
function proxy_judge_anonymous(string $pxUrl, string $ourIp, int $timeout_s = 6, ?array $judges = null): bool {
    $got = [];
    foreach ($judges ?? PROXY_ANONYMITY_JUDGES as $judge) {
        $body = osm_fetch_via($judge, $pxUrl, $timeout_s);
        // Unreachable judges contribute nothing (skipped below); a false
        // body must not stringify into an accidental "clean" vote.
        $got[] = $body === false ? [0, ''] : [200, $body];
    }
    return proxy_judge_bodies_verdict($got, $ourIp);
}

// Shared anonymity verdict over parallel- or sequential-fetched judge
// answers: at least one judge reachable, and no reachable answer leaks our
// IP. One decision point, so the discovery round and the single check can
// never disagree on what "anonymous" means.
/** @param list<array{int,string}> $got [httpCode, body] per judge */
function proxy_judge_bodies_verdict(array $got, string $ourIp): bool {
    $seen = false;
    foreach ($got as [$code, $body]) {
        if ($code < 200 || $code >= 300) {
            continue; // judge unreachable through this proxy — try next judge
        }
        $seen = true;
        if (str_contains($body, $ourIp)) {
            return false; // our IP leaked into the request as seen by the target
        }
    }
    return $seen;
}

// One parallel round of GETs, each through its own proxy (or direct when
// 'proxy' is null). Returns [jobKey => [httpCode, body]]; failures are
// [0, '']. curl_multi is the fast path (bodies via multi_getcontent);
// without cURL the same jobs run sequentially through the streams
// transport. Never throws.
// @param list<array{k:string,url:string,proxy:?string}> $jobs
/** @return array<string,array{int,string}> */
function proxy_multi_fetch(array $jobs, int $timeout_s, int $maxBytes = 65536): array {
    $out = [];
    foreach ($jobs as $j) {
        $out[$j['k']] = [0, ''];
    }
    if ($jobs === []) {
        return $out;
    }
    if (!host_has_curl()) {
        foreach ($jobs as $j) {
            $res = proxy_request_streams('GET', $j['url'], [], $j['proxy'], $timeout_s, $maxBytes, 0);
            if ($res['code'] >= 200 && $res['code'] < 300 && !$res['truncated']) {
                $out[$j['k']] = [$res['code'], $res['body']];
            }
        }
        return $out;
    }
    $mh = curl_multi_init();
    $handles = [];
    foreach ($jobs as $j) {
        $ch = curl_init($j['url']);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout_s,
            CURLOPT_CONNECTTIMEOUT => min($timeout_s, 10),
            CURLOPT_MAXFILESIZE    => $maxBytes,
            CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
        ]);
        if ($j['proxy'] !== null) {
            curl_setopt($ch, CURLOPT_PROXY, proxy_curl_url($j['proxy']));
        }
        curl_multi_add_handle($mh, $ch);
        $handles[$j['k']] = $ch;
    }
    do {
        $status = curl_multi_exec($mh, $active);
        if ($active) {
            curl_multi_select($mh, 0.2);
        }
    } while ($active && $status === CURLM_OK);
    foreach ($handles as $k => $ch) {
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $body = curl_multi_getcontent($ch);
        if ($code >= 200 && $code < 300 && is_string($body)) {
            $out[$k] = [$code, $body];
        }
        curl_multi_remove_handle($mh, $ch);
        unset($ch); // PHP 8.5 deprecates curl_close(); removal + scope exit frees it
    }
    curl_multi_close($mh);
    return $out;
}

// The 9 proxy lists in one parallel round (direct — list downloads never
// touch the pool, so privacy is unchanged). Returns [url => body|false].
// Without cURL the same downloads run sequentially through the fetcher.
function proxy_fetch_lists_parallel(array $urls, int $timeout_s): array {
    $jobs = [];
    foreach ($urls as $u) {
        $jobs[] = ['k' => $u, 'url' => $u, 'proxy' => null];
    }
    $got = proxy_multi_fetch($jobs, $timeout_s, 2097152);
    $out = [];
    foreach ($urls as $u) {
        [$code, $body] = $got[$u] ?? [0, ''];
        $out[$u] = ($code >= 200 && $code < 300 && $body !== '') ? $body : false;
    }
    return $out;
}

// Pull candidates from public sources, then probe them in parallel against a
// real OSM tile URL. Returns [['url' => ..., 'latency_ms' => ...], ...],
// sorted fastest first.
//
// Acceptance is security-first:
//   1. must answer an HTTPS OSM tile (proves CONNECT/socks tunneling works),
//   2. must be under 3000 ms — slower proxies are useless for a map UI,
//   3. HTTP proxies without a source anonymity rating must additionally pass
//      a live judge check proving our IP stays out of the request headers;
//      SOCKS is header-anonymous by protocol and rated lists are trusted.
//
// $budget_s is for hosts that run this inside a page visit (no exec, no CLI,
// a wall-clock limit of ~30 s): list downloads get at most 60% of it, the
// anonymity round only runs while time is left, and unrated HTTP proxies that
// could not be judged in time are dropped — the same fail-closed rule as when
// the judge is unreachable. Null = the unbounded CLI/button behaviour.
function proxy_discover(int $max_test = 400, int $timeout_s = 4, ?float $budget_s = null): array {
    $started   = microtime(true);
    $remaining = static fn(): float => $budget_s === null ? INF : $budget_s - (microtime(true) - $started);
    $candidates = []; // url => ['rated' => bool, 'source' => list name]

    // The 9 lists download in ONE parallel round (direct, never through the
    // pool) instead of one slow download after another.
    $fetchTimeout = $budget_s === null ? 10 : max(2, min(6, (int)floor($budget_s * 0.6)));
    $bodies = proxy_fetch_lists_parallel(
        array_column(PROXY_DISCOVERY_SOURCES, 'url'), $fetchTimeout);
    foreach (PROXY_DISCOVERY_SOURCES as $src) {
        // Third-party list bodies are the largest untrusted input on this
        // path — capped at 2 MiB by the parallel fetcher above.
        $raw = $bodies[$src['url']] ?? false;
        if (!is_string($raw)) {
            continue;
        }

        $record = function (string $norm) use ($src, &$candidates): void {
            // A list line is attacker-controlled: never let one point the
            // prober at loopback, RFC1918, link-local or reserved space.
            if (!osm_proxy_host_public($norm)) return;
            // first source wins, but a rated listing outranks an unrated one
            if (!isset($candidates[$norm])) {
                $candidates[$norm] = ['rated' => $src['rated'], 'source' => $src['name']];
            } elseif ($src['rated'] && !$candidates[$norm]['rated']) {
                $candidates[$norm]['rated'] = true;
                $candidates[$norm]['source'] = $src['name'];
            }
        };

        if ($src['type'] === 'proxifly') {
            $list = json_decode($raw, true);
            if (!is_array($list)) continue;
            foreach ($list as $entry) {
                if (!is_array($entry)) continue;
                $proto = strtolower((string)($entry['protocol'] ?? ''));
                if ($proto === '') continue;
                $anon = strtolower((string)($entry['anonymity'] ?? ''));
                if (!str_starts_with($proto, 'socks')
                    && !in_array($anon, ['anonymous', 'elite'], true)) {
                    continue;
                }
                $ip   = (string)($entry['ip'] ?? '');
                $port = (string)($entry['port'] ?? '');
                if ($ip === '' || $port === '') continue;
                $norm = osm_proxy_normalize("$proto://$ip:$port");
                if ($norm !== null) $record($norm);
            }
        } else {
            foreach (preg_split('/\r?\n/', trim($raw)) ?: [] as $line) {
                // plain lists are one ip:port per line, but tolerate stray
                // annotations by extracting the first ip:port on the line
                if (!preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})\b/', $line, $m)) continue;
                $norm = osm_proxy_normalize($src['proto'] . '://' . $m[1]);
                if ($norm !== null) $record($norm);
            }
        }
    }

    if (!$candidates) return [];
    $all = array_keys($candidates);
    shuffle($all); // lists are ordered; random slice spreads the load
    $toTest = array_slice($all, 0, $max_test);

    // Round 1: functional + latency probe against a real OSM tile.
    $probeUrl = 'https://a.tile.openstreetmap.org/13/4051/2749.png';
    $results  = proxy_multi_probe($toTest, $probeUrl, $timeout_s, $timeout_s);

    $working = [];
    foreach ($results as $pxUrl => [$code, $ms]) {
        if ($code >= 200 && $code < 300 && $ms < 3000) {
            $working[$pxUrl] = [
                'url'        => $pxUrl,
                'latency_ms' => $ms,
                'source'     => $candidates[$pxUrl]['source'],
            ];
        }
    }
    if (!$working) return [];

    // Round 2: live anonymity verification for unrated HTTP proxies — both
    // judges in ONE parallel round (proxy × judge jobs), verdicts from the
    // fetched bodies. The old code probed judge[0] in parallel, threw the
    // bodies away, then re-fetched both judges sequentially per proxy.
    $unrated = array_values(array_filter($working, fn($p) => $candidates[$p['url']]['rated'] === false
        && str_starts_with($p['url'], 'http://')));
    $unrated = array_slice($unrated, 0, $budget_s === null ? 100 : 10);
    $judged = [];
    if ($unrated !== [] && $remaining() > 8.0) {
        $ourIp = proxy_public_ip();
        if ($ourIp !== null) {
            $jobs = [];
            foreach ($unrated as $p) {
                foreach (PROXY_ANONYMITY_JUDGES as $ji => $judge) {
                    $jobs[] = ['k' => $p['url'] . "\0" . $ji, 'url' => $judge, 'proxy' => $p['url']];
                }
            }
            $got = proxy_multi_fetch($jobs, $timeout_s);
            foreach ($unrated as $p) {
                if ($remaining() < 4.0) {
                    $judged[$p['url']] = false; // out of time: unproven means rejected
                    continue;
                }
                $answers = [];
                foreach (PROXY_ANONYMITY_JUDGES as $ji => $judge) {
                    $answers[] = $got[$p['url'] . "\0" . $ji] ?? [0, ''];
                }
                $judged[$p['url']] = proxy_judge_bodies_verdict($answers, $ourIp);
            }
        }
    }
    $working = proxy_filter_anonymity($working, $candidates, $ourIp ?? null, $judged);

    usort($working, fn($a, $b) => $a['latency_ms'] <=> $b['latency_ms']);
    return $working;
}

// ── Anonymity gate (pure — see ProxyTest) ─────────────────────────────────────
// The single decision point for which working proxies may serve OSM traffic:
//   rated proxies (from a curated list)        → keep
//   HTTPS proxies (content opaque to filters)  → keep
//   unrated HTTP proxies, judge reachable      → keep only if judged anonymous
//   unrated HTTP proxies, judge unreachable    → DROP ALL (fail closed — when
//     we cannot learn our own IP we cannot prove a proxy hides it)
// This function is where the "array === false" bug lived: the entire anonymity
// round silently never ran. ProxyTest pins the decision table.
function proxy_filter_anonymity(array $working, array $candidates, ?string $our_ip, array $judged): array {
    return array_values(array_filter($working, static fn(array $p): bool =>
        ($candidates[$p['url']]['rated'] ?? false) !== false
        || !str_starts_with($p['url'], 'http://')
        || ($our_ip !== null && ($judged[$p['url']] ?? false))
    ));
}

// Run a batch of GETs through different proxies in parallel.
// Returns [proxyUrl => [httpCode, totalMs]]. $head controls HEAD vs GET.
// curl_multi is the fast path; without cURL the sockets below probe with
// concurrent connects and sequential handshakes under the same budgets.
function proxy_multi_probe(array $proxies, string $url, int $timeout_s, int $connect_s, bool $head = true): array {
    if (!host_has_curl()) {
        return proxy_multi_probe_streams($proxies, $url, $timeout_s, $connect_s, $head);
    }
    $mh = curl_multi_init();
    /** @var CurlHandle[] $handles */
    $handles = [];
    foreach ($proxies as $pxUrl) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROXY          => proxy_curl_url($pxUrl),
            CURLOPT_TIMEOUT        => $timeout_s,
            CURLOPT_CONNECTTIMEOUT => $connect_s,
            CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
            CURLOPT_NOBODY         => $head,
        ]);
        curl_multi_add_handle($mh, $ch);
        $handles[$pxUrl] = $ch;
    }

    do {
        $status = curl_multi_exec($mh, $active);
        if ($active) {
            curl_multi_select($mh, 0.2);
        }
    } while ($active && $status === CURLM_OK);

    $out = [];
    foreach ($handles as $pxUrl => $ch) {
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $ms   = (int)round((float)curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
        $out[$pxUrl] = [$code, $ms];
        curl_multi_remove_handle($mh, $ch);
        unset($ch); // PHP 8.5 deprecates curl_close(); removal + scope exit frees it
    }
    curl_multi_close($mh);
    return $out;
}

// The curl-less parallel probe: all TCP connects race concurrently (the
// slow phase — dead proxies fail here, fast), then each connected proxy
// handshakes and answers sequentially under one global deadline (a proxy
// that connected but never answers cannot stall past it; only the single
// in-flight TLS handshake is bounded by its own short stream timeout).
// Same contract as proxy_multi_probe: every input URL gets [code, ms],
// failures are [0, 0]. Never throws.
/** @return array<string,array{int,int}> */
function proxy_multi_probe_streams(array $proxies, string $url, int $timeout_s, int $connect_s, bool $head = true): array {
    $out = [];
    foreach ($proxies as $u) {
        $out[(string)$u] = [0, 0];
    }
    try {
        $t = proxy_parse_target($url);
        if ($t === null) return $out;
        $seen = [];
        foreach ($out as $u => $_) {
            $p = proxy_parse($u);
            if ($p !== null) $seen[$u] = $p;
        }
        if ($seen === []) return $out;
        if (!function_exists('stream_socket_client')) return $out;
        $t0 = microtime(true);
        $connectDl = $t0 + max(1, $connect_s);
        $endDl = $connectDl + max(1, $timeout_s) * 2;
        $method = $head ? 'HEAD' : 'GET';

        // Phase 1: every TCP connect at once, async.
        $socks = [];
        foreach ($seen as $u => $p) {
            $s = @stream_socket_client('tcp://' . $p['dial'] . ':' . $p['port'],
                $eno, $estr, 0, STREAM_CLIENT_ASYNC_CONNECT,
                proxy_ssl_context($p['host'], null));
            if (is_resource($s)) {
                stream_set_blocking($s, false);
                $socks[$u] = $s;
            }
        }
        $connected = [];
        while ($socks !== [] && microtime(true) < $connectDl) {
            $left = $connectDl - microtime(true);
            $r = null;
            $w = array_values($socks);
            $e = null;
            if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) === false) break;
            // Finished sockets leave the set: connected ones stay writable,
            // so re-selecting them would return at once and spin hot until
            // the deadline while the hangers pend. (A writable socket may
            // still be a FAILED connect — the peer-name check below sorts
            // those out; both end up in $connected here.)
            $moved = false;
            foreach ($socks as $u => $s) {
                if (in_array($s, $w, true)) {
                    $connected[$u] = $s;
                    unset($socks[$u]);
                    $moved = true;
                }
            }
            if (!$moved && ($w === [] || $w === null)) {
                continue; // quiet timeout slice — re-wait the remainder
            }
        }
        $socks = $connected + $socks;
        foreach ($socks as $u => $s) {
            // A failed async connect also selects writable — no peer name means it never connected.
            if (@stream_socket_get_name($s, true) === false) {
                fclose($s);
                unset($socks[$u]);
            }
        }

        // Phase 2: handshake + request each survivor, one after another,
        // sharing the remaining global budget.
        foreach ($socks as $u => $s) {
            // Per-proxy latency from THIS proxy's start, not the batch
            // start: later proxies must not inherit earlier handshakes and
            // wrongly fail the 3000 ms cut / sort last.
            $p0 = microtime(true);
            $close = static function () use ($s): void {
                if (is_resource($s)) fclose($s);
            };
            if (microtime(true) >= $endDl) {
                $close();
                continue;
            }
            $p = $seen[$u];
            $dl = $endDl;
            $opened = proxy_sock_open_from($s, $p, $t, $dl);
            if ($opened === null) {
                $close();
                continue;
            }
            [$s2, $forward] = $opened;
            if ($t['tls']) {
                // Crypto runs its own blocking handshake: park the
                // non-blocking prober socket first.
                @stream_set_blocking($s2, true);
                if (!proxy_target_tls($s2, $t, null, 3)) {
                    $close();
                    continue;
                }
            }
            $target = $forward ? $url : $t['path'];
            $req = "{$method} {$target} HTTP/1.1\r\n"
                . 'Host: ' . $t['dial'] . (($t['tls'] && $t['port'] === 443) || (!$t['tls'] && $t['port'] === 80) ? '' : ':' . $t['port']) . "\r\n"
                . "User-Agent: DeadDropMGMT/1.0\r\nConnection: close\r\n";
            if ($forward && $p['user'] !== '') {
                $req .= 'Proxy-Authorization: ' . proxy_basic_auth($p['user'], $p['pass']) . "\r\n";
            }
            $req .= "\r\n";
            if (!proxy_write_all($s2, $req, $dl)) {
                $close();
                continue;
            }
            // Headers only: the probe wants a status line, never a body.
            $split = proxy_read_until($s2, $dl,
                static fn(string $b): ?array => proxy_head_split($b), 32768);
            $close();
            if (!is_array($split)) continue;
            $code = proxy_status_code($split[0]);
            if ($code >= 100) {
                $out[$u] = [$code, (int)round((microtime(true) - $p0) * 1000)];
            }
        }
        return $out;
    } catch (Throwable) {
        return $out;
    }
}

// Finish a proxy handshake on an already-connected socket (the prober's
// phase 1): CONNECT tunnel or SOCKS exchange. Returns [socket, isForward]
// like proxy_sock_open, or null. The socket is parked blocking: the TLS
// handshake below runs its own blocking exchange, and the select-driven
// readers work on blocking sockets too.
function proxy_sock_open_from(mixed $s, array $px, array $t, float $deadline): ?array {
    @stream_set_blocking($s, true);
    $scheme = $px['scheme'];
    if ($scheme === 'https') {
        if (!proxy_enable_tls($s, 5)) {
            return null;
        }
        $scheme = 'http';
    }
    if ($scheme === 'http') {
        if (!$t['tls']) {
            return [$s, true];
        }
        if (!proxy_write_all($s, proxy_connect_head($t['dial'], $t['port'], $px['user'], $px['pass']), $deadline)) {
            return null;
        }
        $split = proxy_read_until($s, $deadline,
            static fn(string $b): ?array => proxy_head_split($b), 32768);
        if (!is_array($split) || proxy_status_code($split[0]) !== 200) {
            return null;
        }
        return [$s, false];
    }
    if ($scheme === 'socks5' || $scheme === 'socks5h') {
        if (!proxy_write_all($s, proxy_socks5_greet($px['user']), $deadline)) return null;
        $greet = proxy_read_n($s, 2, $deadline);
        if ($greet === null || $greet[0] !== "\x05") return null;
        if ($greet[1] === "\x02") {
            if ($px['user'] === '') return null;
            if (!proxy_write_all($s, proxy_socks5_auth($px['user'], $px['pass']), $deadline)) return null;
            $auth = proxy_read_n($s, 2, $deadline);
            if ($auth === null || $auth[1] !== "\x00") return null;
        } elseif ($greet[1] !== "\x00") {
            return null;
        }
        if (strlen($t['host']) > 255 || !proxy_write_all($s, proxy_socks5_connect($t['host'], $t['port']), $deadline)) return null;
        $rep = proxy_read_n($s, 4, $deadline);
        if ($rep === null || $rep[1] !== "\x00") return null;
        $tail = match ($rep[3]) {
            "\x01" => 6,
            "\x04" => 18,
            default => null,
        };
        if ($tail === null) {
            if ($rep[3] !== "\x03") return null;
            $ln = proxy_read_n($s, 1, $deadline);
            if ($ln === null) return null;
            $tail = ord($ln) + 2;
        }
        if (proxy_read_n($s, $tail, $deadline) === null) return null;
        return [$s, false];
    }
    if ($scheme === 'socks4') {
        if (!proxy_write_all($s, proxy_socks4_connect($t['host'], $t['port'], $px['user'] ?: 'ddmgmt'), $deadline)) return null;
        $rep = proxy_read_n($s, 8, $deadline);
        if ($rep === null || $rep[0] !== "\x00" || $rep[1] !== "\x5a") return null;
        return [$s, false];
    }
    return null;
}

// ── Self-healing pool ─────────────────────────────────────────────────────────
// Public proxies die constantly. A pool entry that failed is confirmed dead
// by a fresh probe, deleted, and replaced by a newly discovered one chosen by
// exactly the criteria of the Auto-discover button (proxy_discover(): answers
// an HTTPS OSM tile in under 3 s, anonymity gate for unrated HTTP proxies).
//
// Safety rules:
//   - Only while routing is enabled, and only entries that discovery itself
//     could have added: `manual` entries are the owner's own choice (maybe
//     their own server) and are never deleted automatically.
//   - The same job seeds the pool: once the owner turns routing on, an empty
//     pool fails closed, so on the first run (or after the pool was emptied) it
//     runs discovery and stores everything the Auto-discover button would.
//   - DDMGMT_PROXY_HEAL=0 turns all of it off (replacement and seeding) for
//     deployments that must never start discovery on their own.
//   - Replace, never just delete: nothing is removed until discovery has
//     produced a replacement, so a network outage (where every proxy "fails"
//     and discovery finds nothing) cannot wipe the pool, and the pool never
//     shrinks — at most min(dead, fresh) entries are swapped.
//   - Discovery is heavy and makes the same outbound calls as the button
//     (list downloads, the public-IP lookup, up to 400 probes), so it runs
//     in a detached CLI job (cron/proxy_heal.php), never inside a request,
//     under a lock and a cooldown.
const OSM_PROXY_HEAL_COOLDOWN    = 600;  // seconds between discovery runs
const OSM_PROXY_HEAL_INLINE_BUDGET = 22.0; // wall-clock seconds of an inline pass (shared hosts stop scripts at ~30 s)
const OSM_PROXY_SEED_MAX_FAILURES = 3;   // empty-pool discoveries in a row before routing is switched off
const OSM_PROXY_HEAL_LOCK_STALL  = 900;  // a lock older than this is dead
const OSM_PROXY_HEAL_PROBE_URL   = 'https://a.tile.openstreetmap.org/13/4051/2749.png';

// Automatic discovery (replacement and first-run seeding) can be switched off
// for the whole deployment; disabling routing in Settings also stops it.
function osm_proxy_heal_allowed(): bool {
    return host_flag('DDMGMT_PROXY_HEAL', true);
}

function osm_proxy_pool_empty(): bool {
    return (int)get_db()->query('SELECT COUNT(*) FROM osm_proxies')->fetchColumn() === 0;
}

// Failed entries the healer may replace, longest-dead first.
/** @return list<array{id:int,url:string}> */
function osm_proxy_replaceable_dead(): array {
    $rows = get_db()->query(
        "SELECT id, url FROM osm_proxies
         WHERE last_status = 'fail' AND source <> 'manual'
         ORDER BY last_checked IS NULL DESC, last_checked ASC, id ASC"
    )->fetchAll();
    return array_map(static fn(array $r): array => ['id' => (int)$r['id'], 'url' => (string)$r['url']], $rows);
}

// One healer at a time: compare-and-swap on a settings row (same scheme as
// the map worker lock — no new table). A lock older than the stall window
// belongs to a dead process and is stealable.
function osm_proxy_heal_lock(): bool {
    $mine = json_encode(['by' => php_uname('n') . ':' . getmypid(), 'at' => time()]);
    try {
        $db = get_db();
        $st = $db->query("SELECT value FROM settings WHERE key_name = 'proxy_heal_lock' LIMIT 1");
        $raw = $st === false ? false : $st->fetchColumn();
        if ($raw === false) {
            $win = $db->prepare("INSERT IGNORE INTO settings (key_name, value, label) VALUES ('proxy_heal_lock', ?, '')");
            $win->execute([$mine]);
        } else {
            $raw = (string)$raw;
            if ($raw !== '') {
                $held = json_decode($raw, true);
                if (is_array($held) && (time() - (int)($held['at'] ?? 0)) < OSM_PROXY_HEAL_LOCK_STALL) {
                    return false;
                }
            }
            $win = $db->prepare("UPDATE settings SET value = ? WHERE key_name = 'proxy_heal_lock' AND value = ?");
            $win->execute([$mine, $raw]);
        }
        return $win->rowCount() === 1;
    } catch (Throwable $e) {
        log_err('Proxy heal lock: ' . $e->getMessage());
        return false;
    }
}

function osm_proxy_heal_unlock(): void {
    try {
        get_db()->exec("DELETE FROM settings WHERE key_name = 'proxy_heal_lock'");
    } catch (Throwable) {
    }
}

// Test seam: production spawns the detached CLI; a suite installs a stand-in
// (or a no-op) so no real process — and no real network — is ever started.
function osm_proxy_heal_spawner(?callable $set = null, bool $reset = false): ?callable {
    static $spawner = null;
    if ($reset) {
        $spawner = null;
    } elseif ($set !== null) {
        $spawner = $set;
    }
    return $spawner;
}

// Is there heal work that is allowed right now? Routing on and possible,
// automatic discovery not disabled, the cooldown passed, and either a
// replaceable dead entry or an empty pool. $throttle (the pseudo-cron slot,
// which asks on every request) also remembers "nothing to do" for one
// cooldown so a healthy pool costs a single query per interval.
function osm_proxy_heal_pending(bool $throttle = false): bool {
    if (!osm_proxy_heal_allowed() || !osm_proxy_enabled()) return false;
    $since = (int)get_setting('proxy_heal_last', '0');
    if ($throttle) {
        $since = max($since, (int)get_setting('proxy_heal_checked', '0'));
    }
    if ((time() - $since) < OSM_PROXY_HEAL_COOLDOWN) return false;
    if (osm_proxy_replaceable_dead() !== [] || osm_proxy_pool_empty()) return true;
    if ($throttle) {
        set_setting('proxy_heal_checked', (string)time());
    }
    return false;
}

// The pseudo-cron's proxy slot (runs after the response). Where a detached
// job can be started, start one; where it cannot — shared hosting without
// exec or CLI PHP — run a time-budgeted pass right here. Never throws.
// ($discover / $probe: test seams, as in osm_proxy_heal().)
function osm_proxy_heal_pseudo_cron(?callable $discover = null, ?callable $probe = null): void {
    try {
        if (!osm_proxy_heal_pending(true)) return;
        if (osm_proxy_heal_spawner() !== null || host_can_detach()) {
            osm_proxy_heal_kick();
            return;
        }
        @set_time_limit(60);
        osm_proxy_heal($discover, $probe, false, OSM_PROXY_HEAL_INLINE_BUDGET);
    } catch (Throwable $e) {
        log_err('Proxy heal slot: ' . $e->getMessage());
    }
}

// Once routing is on, a host that can never build a pool (outbound
// connections blocked, every list unreachable, a wall-clock limit too short to
// finish a pass) would answer 502 on every map view forever. After a few
// empty-pool discoveries in a row, switch routing off — loudly: audit +
// warning + a notice in Settings — so OSM requests go direct and the owner
// decides. Re-enabling the toggle clears the notice.
//
// The attempt is counted BEFORE discovery starts: a host that kills the script
// mid-pass never reaches any "it failed" code, and must still run out of tries.
// Returns false when the tries were already used up (routing was just switched
// off instead of trying again).
function osm_proxy_seed_attempt(): bool {
    $n = (int)get_setting('proxy_seed_failures', '0');
    if ($n >= OSM_PROXY_SEED_MAX_FAILURES) {
        osm_proxy_auto_off('no working proxy could be found from this host');
        return false;
    }
    set_setting('proxy_seed_failures', (string)($n + 1));
    return true;
}

// After an attempt that produced nothing: was that the last try?
function osm_proxy_seed_failed(): void {
    if ((int)get_setting('proxy_seed_failures', '0') >= OSM_PROXY_SEED_MAX_FAILURES) {
        osm_proxy_auto_off('no working proxy could be found from this host');
    }
}

function osm_proxy_auto_off(string $reason): void {
    set_setting('osm_proxy_enabled', '0');
    set_setting('osm_proxy_auto_off', (string)json_encode(['at' => time(), 'reason' => $reason]));
    delete_setting('proxy_seed_failures');
    audit('proxy_auto_off', null, null, $reason);
    log_warn('proxy_auto_off', ['msg' => 'OSM proxy routing switched off automatically: ' . $reason]);
}

/** @return ?array{at:int,reason:string} */
function osm_proxy_auto_off_state(): ?array {
    $raw = get_setting('osm_proxy_auto_off', '');
    if ($raw === '') return null;
    $d = json_decode($raw, true);
    return is_array($d) ? ['at' => (int)($d['at'] ?? 0), 'reason' => (string)($d['reason'] ?? '')] : null;
}

function osm_proxy_auto_off_clear(): void {
    delete_setting('osm_proxy_auto_off', 'proxy_seed_failures');
}

// Start a detached heal job when one is warranted: routing on, a replaceable
// dead entry exists (or the pool is empty and needs seeding), and the
// cooldown has passed. Cheap when nothing is due
// (one setting read plus one SELECT), never throws, never blocks. Returns
// whether a job was started.
function osm_proxy_heal_kick(): bool {
    try {
        $spawn = osm_proxy_heal_spawner();
        // No way to detach here (no exec / CLI PHP): the pseudo-cron slot runs
        // the pass inline instead — and must not find the cooldown burnt.
        if ($spawn === null && !host_can_detach()) return false;
        if (!osm_proxy_heal_pending()) return false;
        // Stamp before spawning: concurrent requests must not each start a job.
        set_setting('proxy_heal_last', (string)time());
        if ($spawn !== null) {
            return (bool)$spawn();
        }
        $cli = host_php_cli();
        if ($cli === null) return false;
        @exec(escapeshellarg($cli) . ' ' . escapeshellarg(dirname(__DIR__) . '/cron/proxy_heal.php') . ' > /dev/null 2>&1 &');
        return true;
    } catch (Throwable $e) {
        log_err('Proxy heal kick: ' . $e->getMessage());
        return false;
    }
}

// Replace confirmed-dead pool entries with freshly discovered ones. $discover
// and $probe exist for tests (default: proxy_discover / proxy_multi_probe).
// $honorCooldown: see the note in the body. $budget: wall-clock seconds for
// the inline pass on hosts that cannot run a detached job (see
// proxy_discover()); null = unbounded (CLI job, cron, the button).
// Blocking and network-heavy — call from CLI only.
/** @return array{skipped:?string,dead:int,recovered:int,replaced:int,seeded:int} */
function osm_proxy_heal(?callable $discover = null, ?callable $probe = null, bool $honorCooldown = false, ?float $budget = null): array {
    $out = ['skipped' => null, 'dead' => 0, 'recovered' => 0, 'replaced' => 0, 'seeded' => 0];
    if (!osm_proxy_heal_allowed()) { $out['skipped'] = 'disabled by DDMGMT_PROXY_HEAL'; return $out; }
    if (!osm_proxy_enabled()) { $out['skipped'] = 'routing disabled'; return $out; }
    // Scheduled callers (the cleanup cron) honour the cooldown so they cannot
    // run discovery back-to-back with a job a live request just started; a job
    // started BY the kick has stamped the cooldown itself and must not honour it.
    if ($honorCooldown && (time() - (int)get_setting('proxy_heal_last', '0')) < OSM_PROXY_HEAL_COOLDOWN) {
        $out['skipped'] = 'cooldown';
        return $out;
    }
    if (!osm_proxy_heal_lock()) { $out['skipped'] = 'another heal is running'; return $out; }
    $db = get_db();
    try {
        set_setting('proxy_heal_last', (string)time());

        // First run (or a pool that was emptied): nothing to replace, so seed
        // it with what the Auto-discover button would store. Routing is on and
        // an empty pool fails closed, so waiting for the owner would leave the
        // maps dead until they found the button.
        if (osm_proxy_pool_empty()) {
            if (!osm_proxy_seed_attempt()) { $out['skipped'] = 'routing switched off'; return $out; }
            $found = ($discover ?? static fn(): array => proxy_discover(
                $budget !== null ? 120 : 400, $budget !== null ? 3 : 4, $budget
            ))();
            if ($found === []) {
                $out['skipped'] = 'no proxies found';
                osm_proxy_seed_failed();
                return $out;
            }
            delete_setting('proxy_seed_failures');
            $seed = $db->prepare(
                'INSERT IGNORE INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
                 VALUES (?, ?, "ok", ?, NOW())'
            );
            foreach ($found as $px) {
                $seed->execute([$px['url'], (string)($px['source'] ?? 'discovered'), $px['latency_ms'] ?? null]);
                $out['seeded'] += $seed->rowCount();
            }
            if ($out['seeded'] > 0) {
                audit('proxy_seed', null, null, 'added=' . $out['seeded']);
                log_info('proxy_seeded', ['msg' => "first-run discovery added {$out['seeded']} proxies", 'added' => $out['seeded']]);
            }
            return $out;
        }

        $dead = osm_proxy_replaceable_dead();
        if ($dead === []) { $out['skipped'] = 'nothing to replace'; return $out; }

        // Confirm before deleting: a slow answer or a one-off OSM hiccup marks
        // a good proxy 'fail'. Probe them once more, the way the stale
        // revalidation does, and keep whoever answers now.
        $probeFn = $probe ?? static fn(array $urls): array
            => proxy_multi_probe($urls, OSM_PROXY_HEAL_PROBE_URL, 4, 4);
        $res = $probeFn(array_column($dead, 'url'));
        $confirmed = [];
        foreach ($dead as $row) {
            [$code, $ms] = $res[$row['url']] ?? [0, 0];
            if ($code >= 200 && $code < 300) {
                osm_proxy_mark($row['id'], true, (int)$ms);
                $out['recovered']++;
            } else {
                $confirmed[] = $row;
            }
        }
        $out['dead'] = count($confirmed);
        if ($confirmed === []) { $out['skipped'] = 'all recovered'; return $out; }

        // Same criteria as the Auto-discover button, fastest first.
        $found = ($discover ?? static fn(): array => proxy_discover(
            $budget !== null ? 120 : 400, $budget !== null ? 3 : 4, $budget
        ))();
        $have = array_flip($db->query('SELECT url FROM osm_proxies')->fetchAll(PDO::FETCH_COLUMN));
        $fresh = array_values(array_filter(
            $found,
            static fn(array $p): bool => !isset($have[$p['url']])
        ));
        $n = min(count($confirmed), count($fresh));
        if ($n === 0) { $out['skipped'] = 'no replacement found'; return $out; }

        $del = $db->prepare("DELETE FROM osm_proxies WHERE id = ? AND last_status = 'fail' AND source <> 'manual'");
        $ins = $db->prepare(
            'INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
             VALUES (?, ?, "ok", ?, NOW())'
        );
        $db->beginTransaction();
        try {
            $swapped = 0;
            foreach (array_slice($confirmed, 0, $n) as $row) {
                $del->execute([$row['id']]);
                if ($del->rowCount() !== 1) continue; // recovered or removed meanwhile
                $px = $fresh[$swapped];
                $ins->execute([$px['url'], (string)($px['source'] ?? 'discovered'), $px['latency_ms'] ?? null]);
                $swapped++;
            }
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            throw $e;
        }
        $out['replaced'] = $swapped;
        if ($swapped > 0) {
            audit('proxy_replace', null, null, "replaced={$swapped} dead={$out['dead']}");
            log_info('proxy_replaced', ['msg' => "replaced {$swapped} of {$out['dead']} dead proxies", 'replaced' => $swapped, 'dead' => $out['dead']]);
        }
        return $out;
    } catch (Throwable $e) {
        log_err('Proxy heal: ' . $e->getMessage());
        $out['skipped'] = 'error';
        return $out;
    } finally {
        osm_proxy_heal_unlock();
    }
}
