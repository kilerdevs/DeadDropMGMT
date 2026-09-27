<?php
// DeadDropMGMT web installer — ONE file. Upload to empty (or existing) hosting
// dir, open in browser, follow the wizard. Downloads the app from GitHub
// releases, extracts it, writes config.php, creates storage dirs and imports
// the schema. No sessions, no dependencies, CSS+JS embedded. Delete when done.
declare(strict_types=1);

const INST_VERSION = '1.0.0';
const INST_MASTER_ZIP = 'https://github.com/kilerdevs/DeadDropMGMT/archive/refs/heads/master.zip';
const INST_TAGS_API = 'https://api.github.com/repos/kilerdevs/DeadDropMGMT/tags';
const INST_TABLES = ['users','orders','order_photos','osm_proxies','map_zones','order_events','rate_limits','audit_log','settings','log_checkpoints'];
const INST_DIRS = ['logs','cache','cache/osm_tiles','cache/sessions','tiles','data/maps','uploads'];

// Cheap hosts disableini_set/ini_get/disk_free_space via disable_functions —
// and on PHP 8 calling one throws Error, which @ cannot suppress. So every
// such call below goes through a function_exists-guarded wrapper; the check
// step then reports "unknown" instead of white-screening.
if (function_exists('ini_set')) { @ini_set('display_errors', '0'); }
if (function_exists('error_reporting')) { @error_reporting(E_ALL & ~E_DEPRECATED); }
function eini(string $k): string { return function_exists('ini_get') ? (string)@ini_get($k) : ''; }
function edisk(string $p) { return function_exists('disk_free_space') ? @disk_free_space($p) : false; }
function pver(string $e): string { return function_exists('phpversion') ? (string)@phpversion($e) : 'unknown'; }

// String helpers are PHP 8+: polyfill so a PHP 7 host gets the readable
// "needs PHP 8.2" row instead of a parse-error blank page. (No other 8.x-only
// syntax is used in this file for the same reason.)
if (!function_exists('str_contains')) {
    function str_contains(string $h, string $n): bool { return $n === '' || strpos($h, $n) !== false; }
}
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $h, string $n): bool { return strncmp($h, $n, strlen($n)) === 0; }
}
// php.ini shorthand ("8M", "512K", "-1") → bytes; -1/empty = unlimited.
function shorthand_bytes(string $v): int {
    $v = trim($v);
    if ($v === '' || $v === '-1') return PHP_INT_MAX;
    $u = strtolower(substr($v, -1));
    $n = (int)$v;
    if ($u === 'g') $n *= 1073741824;
    elseif ($u === 'm') $n *= 1048576;
    elseif ($u === 'k') $n *= 1024;
    return $n;
}

// ── tiny helpers ─────────────────────────────────────────────────────────────
function jout(array $d): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d, JSON_UNESCAPED_SLASHES);
    exit;
}
function jer(string $msg, array $extra = []): void { jout(['ok' => false, 'error' => $msg] + $extra); }
function row(string $id, string $label, string $st, string $detail = ''): array {
    return ['id' => $id, 'label' => $label, 'status' => $st, 'detail' => $detail];
}
function unlimit(): void {
    if (function_exists('set_time_limit')) { try { @set_time_limit(60); } catch (Throwable) {} }
}
function base(): string { return rtrim(str_replace('\\', '/', __DIR__), '/'); }
function dl_paths(): array {
    $b = base();
    return [$b . '/.__install_dl.zip', $b . '/.__install_src'];
}
function pq(string $v): string { // php-quote for config patching
    return str_replace(['\\', "'"], ['\\\\', "\\'"], $v);
}

// ── HTTP fetch with optional proxy + manual redirect loop ────────────────────
// Transports tried in order, first success wins (every hop re-tried on the
// next transport when one fails, so allow_url_fopen=off without cURL still
// works via the bundled socket engine):
//   curl    — everything incl. SOCKS5 with remote DNS (fast path)
//   streams — direct http/https, or plain-HTTP via an HTTP proxy
//   sockets — proxy.php's no-cURL engine (raw sockets: CONNECT tunnel,
//             SOCKS4/5/5h with remote DNS, chunked decoding), ported below
// Returns [status, headers, body, 'via' => transport] or ['error' => msg].
function transport_order(string $url, array $proxy): array {
    $order = [];
    if (function_exists('curl_init')) $order[] = 'curl';
    $https = str_starts_with($url, 'https:');
    if (filter_var(eini('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)
        && ($proxy['type'] === 'none' || ($proxy['type'] === 'http' && !$https))) {
        $order[] = 'streams';
    }
    if (function_exists('stream_socket_client')) $order[] = 'sockets';
    return $order;
}
function http_fetch(string $url, array $proxy, string $method = 'GET'): array {
    $order = transport_order($url, $proxy);
    if ($order === []) return ['error' => 'no HTTP transport on this host (need cURL, allow_url_fopen, or sockets)'];
    $last = 'unreachable';
    foreach ($order as $t) {
        $u = $url;
        for ($hop = 0; $hop < 8; $hop++) {
            $r = $t === 'curl' ? curl_hop($u, $proxy, $method)
                : ($t === 'streams' ? stream_hop($u, $proxy, $method) : ix_sock_hop($u, $proxy, $method));
            if (isset($r['error'])) {
                $last = $t . ': ' . $r['error'];
                break;
            }
            [$code, $hdrs, $body] = [$r[0], $r[1], $r[2]];
            if ($code >= 300 && $code < 400 && isset($hdrs['location'])) {
                $u = rel_url($u, $hdrs['location']);
                continue;
            }
            return [$code, $hdrs, $body, 'via' => $t];
        }
        if (!isset($r['error'])) $last = $t . ': too many redirects (8) — proxy loop?';
    }
    return ['error' => $last];
}
function rel_url(string $base, string $loc): string {
    if (preg_match('#^https?://#i', $loc)) return $loc;
    $p = parse_url($base);
    $root = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
    return str_starts_with($loc, '/') ? $root . $loc : $root . '/' . $loc;
}
function hdrs_parse(string $raw): array {
    $out = [];
    foreach (explode("\r\n", $raw) as $ln) {
        $pos = strpos($ln, ':');
        if ($pos !== false) $out[strtolower(trim(substr($ln, 0, $pos)))] = trim(substr($ln, $pos + 1));
    }
    return $out;
}
function curl_hop(string $url, array $proxy, string $method): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 25,
        CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_USERAGENT => 'DeadDropMGMT-installer/' . INST_VERSION,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_HTTPHEADER => ['Accept: */*'],
    ]);
    if ($method === 'HEAD') curl_setopt($ch, CURLOPT_NOBODY, true);
    if ($proxy['type'] === 'http') {
        curl_setopt($ch, CURLOPT_PROXY, $proxy['host'] . ':' . $proxy['port']);
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    } elseif ($proxy['type'] === 'socks5') {
        curl_setopt($ch, CURLOPT_PROXY, $proxy['host'] . ':' . $proxy['port']);
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME); // remote DNS: no leak
    }
    if ($proxy['user'] !== '') curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy['user'] . ':' . $proxy['pass']);
    $raw = curl_exec($ch);
    if ($raw === false) { $e = curl_error($ch); curl_close($ch); return ['error' => 'cURL: ' . $e]; }
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hsz = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    return [$code, hdrs_parse(substr($raw, 0, $hsz)), substr($raw, $hsz)];
}
function stream_hop(string $url, array $proxy, string $method): array {
    if ($proxy['type'] === 'socks5') return ['error' => 'SOCKS5 over plain streams unsupported — trying sockets'];
    if ($proxy['type'] === 'http' && str_starts_with($url, 'https:'))
        return ['error' => 'HTTPS via HTTP proxy over plain streams unsupported — trying sockets'];
    $h = ['User-Agent: DeadDropMGMT-installer/' . INST_VERSION, 'Accept: */*', 'Connection: close'];
    $opt = ['http' => ['method' => $method, 'header' => implode("\r\n", $h), 'timeout' => 25,
        'ignore_errors' => true, 'follow_location' => 0, 'protocol_version' => 1.1]];
    if ($proxy['type'] === 'http') {
        $opt['http']['proxy'] = 'tcp://' . $proxy['host'] . ':' . $proxy['port'];
        $opt['http']['request_fulluri'] = true;
        if ($proxy['user'] !== '') $opt['http']['header'] .= "\r\nProxy-Authorization: Basic " . base64_encode($proxy['user'] . ':' . $proxy['pass']);
    }
    $ctx = stream_context_create($opt);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) return ['error' => 'connection failed (DNS / firewall / allow_url_fopen?)'];
    if (empty($http_response_header)) {
        // Non-HTTP wrappers (file://) have no status line — a body means success.
        return str_starts_with($url, 'file://') ? [200, [], (string)$body] : ['error' => 'empty response (proxy hung up?)'];
    }
    $code = 0;
    if (preg_match('#HTTP/\S+\s+(\d+)#', (string)$http_response_header[0], $m)) $code = (int)$m[1];
    if ($method === 'HEAD') $body = '';
    return [$code, hdrs_parse(implode("\r\n", $http_response_header)), (string)$body];
}

// ── No-cURL socket engine (ported from includes/proxy.php) ───────────────────
// Same battle-tested fallback the app uses for OSM traffic: raw sockets,
// HTTP-proxy forwarding, CONNECT tunnel for https, SOCKS4/5/5h handshake with
// remote DNS (target hostname resolved AT the proxy, never locally), chunked
// decoding, redirect-following by the caller. Adapted: GET-only, installer
// error convention, no PHP 8-only syntax (this file stays 7.x-parseable),
// 16 MB body cap (release zips are ~4 MB). Never throws.
const IX_MAX_BODY = 16777216;
function ix_norm(string $raw): ?string {
    $raw = trim($raw);
    if ($raw === '' || strlen($raw) > 255) return null;
    if (!str_contains($raw, '://')) $raw = 'http://' . $raw;
    $p = parse_url($raw);
    if (!is_array($p) || empty($p['host']) || empty($p['port'])) return null;
    $host = strtolower(trim((string)$p['host'], '[]'));
    if (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) return null;
    $port = (int)$p['port'];
    if ($port < 1 || $port > 65535) return null;
    if (!in_array(strtolower($p['scheme'] ?? 'http'), ['http', 'https', 'socks4', 'socks5', 'socks5h'], true)) return null;
    $url = strtolower($p['scheme']) . '://';
    if (!empty($p['user'])) {
        $url .= rawurlencode(rawurldecode($p['user']));
        if (isset($p['pass'])) $url .= ':' . rawurlencode(rawurldecode($p['pass']));
        $url .= '@';
    }
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) $host = '[' . $host . ']';
    return $url . $host . ':' . $port;
}
function ix_parse_proxy(array $proxy): ?array {
    if ($proxy['type'] === 'none') return null;
    if ($proxy['host'] === '' || $proxy['port'] < 1) return null;
    $auth = $proxy['user'] !== '' ? $proxy['user'] . ':' . $proxy['pass'] . '@' : '';
    $norm = ix_norm($proxy['type'] . '://' . $auth . $proxy['host'] . ':' . $proxy['port']);
    if ($norm === null) return null;
    $p = parse_url($norm);
    $host = strtolower(trim((string)$p['host'], '[]'));
    return ['scheme' => strtolower($p['scheme']), 'host' => $host,
        'dial' => filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host,
        'port' => (int)$p['port'], 'user' => rawurldecode((string)($p['user'] ?? '')), 'pass' => rawurldecode((string)($p['pass'] ?? ''))];
}
function ix_parse_target(string $url): ?array {
    $p = parse_url($url);
    if (!is_array($p) || isset($p['user'])) return null;
    $scheme = strtolower((string)($p['scheme'] ?? ''));
    if ($scheme !== 'http' && $scheme !== 'https') return null;
    $host = strtolower(trim((string)($p['host'] ?? ''), '[]'));
    if ($host === '' || strlen($host) > 253 || str_contains($host, ' ')) return null;
    $port = isset($p['port']) ? (int)$p['port'] : ($scheme === 'https' ? 443 : 80);
    if ($port < 1 || $port > 65535) return null;
    $path = (string)($p['path'] ?? '');
    if ($path === '' || !str_starts_with($path, '/')) $path = '/' . $path;
    if (isset($p['query']) && $p['query'] !== '') $path .= '?' . $p['query'];
    return ['host' => $host,
        'dial' => filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host,
        'port' => $port, 'tls' => $scheme === 'https', 'path' => $path];
}
function ix_write_all($sock, string $data, float $deadline): bool {
    while ($data !== '') {
        $left = $deadline - microtime(true);
        if ($left <= 0) return false;
        $r = null; $w = [$sock]; $e = null;
        if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) !== 1) return false;
        $n = @fwrite($sock, $data);
        if (!is_int($n) || $n <= 0) return false;
        $data = substr($data, $n);
    }
    return true;
}
function ix_read_until($sock, float $deadline, callable $done, int $cap) {
    $buf = '';
    while (true) {
        $res = $done($buf);
        if ($res !== null) return $res;
        if (strlen($buf) > $cap) return null;
        $left = $deadline - microtime(true);
        if ($left <= 0) return null;
        $r = [$sock]; $w = null; $e = null;
        if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) !== 1) return null;
        $chunk = @fread($sock, 65536);
        if (!is_string($chunk) || $chunk === '') return null;
        $buf .= $chunk;
    }
}
function ix_read_n($sock, int $n, float $deadline): ?string {
    $buf = '';
    while (strlen($buf) < $n) {
        $left = $deadline - microtime(true);
        if ($left <= 0) return null;
        $r = [$sock]; $w = null; $e = null;
        if (@stream_select($r, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000)) !== 1) return null;
        $chunk = @fread($sock, $n - strlen($buf));
        if (!is_string($chunk) || $chunk === '') return null;
        $buf .= $chunk;
    }
    return $buf;
}
function ix_enable_tls($sock, int $secs = 5): bool {
    $prev = function_exists('ini_get') ? @ini_get('default_socket_timeout') : null;
    if (function_exists('ini_set')) @ini_set('default_socket_timeout', (string)max(1, $secs));
    @stream_set_timeout($sock, max(1, $secs));
    try {
        return (bool)@stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    } catch (Throwable $t) {
        return false;
    } finally {
        if (is_string($prev) && function_exists('ini_set')) @ini_set('default_socket_timeout', $prev);
    }
}
function ix_sock_open(?array $px, array $t, float $deadline): ?array {
    if (!function_exists('stream_socket_client')) return null;
    $ctx = function_exists('stream_context_create')
        ? @stream_context_create(['ssl' => ['peer_name' => $t['host'], 'verify_peer' => true, 'verify_peer_name' => true]])
        : null;
    if ($px === null) {
        $left = $deadline - microtime(true);
        if ($left <= 0) return null;
        $s = @stream_socket_client(($t['tls'] ? 'tls' : 'tcp') . '://' . $t['dial'] . ':' . $t['port'],
            $eno, $estr, max(0.5, min(15.0, $left)), STREAM_CLIENT_CONNECT, $ctx ?: null);
        return is_resource($s) ? [$s, false] : null;
    }
    $left = $deadline - microtime(true);
    if ($left <= 0) return null;
    $s = @stream_socket_client('tcp://' . $px['dial'] . ':' . $px['port'],
        $eno, $estr, max(0.5, min(10.0, $left)), STREAM_CLIENT_CONNECT);
    if (!is_resource($s)) return null;
    $close = function () use ($s): void { if (is_resource($s)) fclose($s); };
    $scheme = $px['scheme'];
    if ($scheme === 'https') {
        if (!ix_enable_tls($s, 5)) { $close(); return null; }
        $scheme = 'http';
    }
    if ($scheme === 'http') {
        if (!$t['tls']) return [$s, true];
        $head = "CONNECT {$t['dial']}:{$t['port']} HTTP/1.1\r\nHost: {$t['dial']}:{$t['port']}\r\n";
        if ($px['user'] !== '') $head .= 'Proxy-Authorization: Basic ' . base64_encode($px['user'] . ':' . $px['pass']) . "\r\n";
        if (!ix_write_all($s, $head . "\r\n", $deadline)) { $close(); return null; }
        $split = ix_read_until($s, $deadline, function (string $b): ?array {
            $i = strpos($b, "\r\n\r\n");
            return $i === false ? null : [substr($b, 0, $i), substr($b, $i + 4)];
        }, 32768);
        if (!is_array($split) || ix_status($split[0]) !== 200) { $close(); return null; }
        @stream_context_set_option($s, ['ssl' => ['peer_name' => $t['host'], 'verify_peer' => true, 'verify_peer_name' => true]]);
        if (!ix_enable_tls($s, 5)) { $close(); return null; }
        return [$s, false];
    }
    if ($scheme === 'socks5' || $scheme === 'socks5h') {
        if (!ix_write_all($s, $px['user'] === '' ? "\x05\x01\x00" : "\x05\x02\x00\x02", $deadline)) { $close(); return null; }
        $greet = ix_read_n($s, 2, $deadline);
        if ($greet === null || $greet[0] !== "\x05") { $close(); return null; }
        if ($greet[1] === "\x02") {
            if ($px['user'] === '') { $close(); return null; }
            if (!ix_write_all($s, "\x01" . chr(strlen($px['user'])) . $px['user'] . chr(strlen($px['pass'])) . $px['pass'], $deadline)) { $close(); return null; }
            $auth = ix_read_n($s, 2, $deadline);
            if ($auth === null || $auth[1] !== "\x00") { $close(); return null; }
        } elseif ($greet[1] !== "\x00") { $close(); return null; }
        if (strlen($t['host']) > 255) { $close(); return null; }
        if (!ix_write_all($s, "\x05\x01\x00\x03" . chr(strlen($t['host'])) . $t['host'] . pack('n', $t['port']), $deadline)) { $close(); return null; }
        $rep = ix_read_n($s, 4, $deadline);
        if ($rep === null || $rep[1] !== "\x00") { $close(); return null; }
        if ($rep[3] === "\x01") $tail = 6;
        elseif ($rep[3] === "\x04") $tail = 18;
        elseif ($rep[3] === "\x03") {
            $ln = ix_read_n($s, 1, $deadline);
            if ($ln === null) { $close(); return null; }
            $tail = ord($ln) + 2;
        } else { $close(); return null; }
        if (ix_read_n($s, $tail, $deadline) === null) { $close(); return null; }
        return [$s, false];
    }
    if ($scheme === 'socks4') {
        $user = $px['user'] !== '' ? $px['user'] : 'ddmgmt';
        if (filter_var($t['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && is_string(inet_pton($t['host']))) {
            $req = "\x04\x01" . pack('n', $t['port']) . inet_pton($t['host']) . $user . "\x00";
        } else {
            $req = "\x04\x01" . pack('n', $t['port']) . "\x00\x00\x00\xff" . $user . "\x00" . $t['host'] . "\x00";
        }
        if (!ix_write_all($s, $req, $deadline)) { $close(); return null; }
        $rep = ix_read_n($s, 8, $deadline);
        if ($rep === null || $rep[0] !== "\x00" || $rep[1] !== "\x5a") { $close(); return null; }
        return [$s, false];
    }
    $close();
    return null;
}
function ix_status(string $head): int {
    if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $head, $m) === 1) return (int)$m[1];
    return 0;
}
// One GET over raw sockets. Returns [code, headersAssoc, body] or ['error'].
function ix_sock_hop(string $url, array $proxy, string $method): array {
    try {
        if ($method !== 'GET') return ['error' => 'socket engine is GET-only'];
        if (!function_exists('stream_socket_client')) return ['error' => 'sockets unavailable (stream_socket_client missing)'];
        $px = ix_parse_proxy($proxy);
        if ($proxy['type'] !== 'none' && $px === null) return ['error' => 'proxy address unusable (need scheme://host:port)'];
        $t = ix_parse_target($url);
        if ($t === null) return ['error' => 'URL unusable (need http(s)://host/path)'];
        if ($t['tls'] && !extension_loaded('openssl')) return ['error' => 'HTTPS over sockets needs openssl'];
        $deadline = microtime(true) + 25;
        $opened = ix_sock_open($px, $t, $deadline);
        if ($opened === null) return ['error' => 'connect/handshake failed (proxy down, blocked, or DNS)'];
        [$s, $forward] = $opened;
        $close = function () use ($s): void { if (is_resource($s)) fclose($s); };
        if ($t['tls'] && $px !== null) {
            @stream_context_set_option($s, ['ssl' => ['peer_name' => $t['host'], 'verify_peer' => true, 'verify_peer_name' => true]]);
            if (!ix_enable_tls($s, 5)) { $close(); return ['error' => 'TLS handshake failed']; }
        }
        $target = $forward ? $url : $t['path'];
        $req = "GET {$target} HTTP/1.1\r\nHost: {$t['dial']}" . (($t['tls'] && $t['port'] === 443) || (!$t['tls'] && $t['port'] === 80) ? '' : ':' . $t['port']) . "\r\n"
            . 'User-Agent: DeadDropMGMT-installer/' . INST_VERSION . "\r\nConnection: close\r\n";
        if ($forward && $px !== null && $px['user'] !== '') {
            $req .= 'Proxy-Authorization: Basic ' . base64_encode($px['user'] . ':' . $px['pass']) . "\r\n";
        }
        if (!ix_write_all($s, $req . "\r\n", $deadline)) { $close(); return ['error' => 'request write failed']; }
        $split = ix_read_until($s, $deadline, function (string $b): ?array {
            $i = strpos($b, "\r\n\r\n");
            return $i === false ? null : [substr($b, 0, $i), substr($b, $i + 4)];
        }, 32768);
        if (!is_array($split)) { $close(); return ['error' => 'no HTTP response (timeout or garbage)']; }
        [$head, $rest] = $split;
        $code = ix_status($head);
        if ($code === 0) { $close(); return ['error' => 'not an HTTP response']; }
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
        $body = '';
        if (isset($fields['transfer-encoding']) && str_contains(strtolower($fields['transfer-encoding']), 'chunked')) {
            $buf = $rest;
            while (true) {
                $i = strpos($buf, "\r\n");
                if ($i === false) {
                    $more = ix_read_until($s, $deadline, function (string $b): ?string { return $b !== '' ? $b : null; }, 65536);
                    if (!is_string($more)) { $close(); return ['error' => 'truncated chunked body']; }
                    $buf .= $more;
                    continue;
                }
                if (preg_match('/^([0-9a-fA-F]+)(;[^\r]*)?$/', substr($buf, 0, $i), $m) !== 1) { $close(); return ['error' => 'corrupt chunk framing']; }
                $size = hexdec($m[1]);
                $buf = substr($buf, $i + 2);
                if ($size === 0) break;
                while (strlen($buf) < $size + 2) {
                    $more = ix_read_until($s, $deadline, function (string $b): ?string { return $b !== '' ? $b : null; }, 65536);
                    if (!is_string($more)) { $close(); return ['error' => 'truncated chunked body']; }
                    $buf .= $more;
                }
                $body .= substr($buf, 0, $size);
                if (strlen($body) > IX_MAX_BODY) { $close(); return ['error' => 'body exceeds 16 MB cap']; }
                $buf = substr($buf, $size + 2);
            }
        } else {
            $want = isset($fields['content-length']) && preg_match('/^\d+$/', $fields['content-length']) === 1 ? (int)$fields['content-length'] : null;
            $buf = $rest;
            while (true) {
                if ($buf !== '') {
                    $take = $buf;
                    if ($want !== null) {
                        $need = $want - strlen($body);
                        if ($need <= 0) break;
                        $take = substr($buf, 0, $need);
                    }
                    $body .= $take;
                    if (strlen($body) > IX_MAX_BODY) { $close(); return ['error' => 'body exceeds 16 MB cap']; }
                    $buf = substr($buf, strlen($take));
                    if ($want !== null && strlen($body) >= $want) break;
                }
                if ($want !== null && strlen($body) >= $want) break;
                $rset = [$s]; $w = null; $e = null;
                $left = $deadline - microtime(true);
                if ($left <= 0) { $close(); return $want === null ? [$code, $fields, $body] : ['error' => 'body shortfall (declared ' . $want . ', got ' . strlen($body) . ')']; }
                $n = @stream_select($rset, $w, $e, (int)$left, (int)(($left - (int)$left) * 1000000));
                if ($n !== 1) {
                    $close();
                    if ($want === null) return [$code, $fields, $body]; // close-delimited: EOF ends it
                    return ['error' => 'body shortfall (declared ' . $want . ', got ' . strlen($body) . ')'];
                }
                $chunk = @fread($s, 65536);
                if (!is_string($chunk) || $chunk === '') {
                    $close();
                    if ($want === null) return [$code, $fields, $body];
                    return ['error' => 'body shortfall (declared ' . $want . ', got ' . strlen($body) . ')'];
                }
                $buf .= $chunk;
            }
            if ($want !== null && strlen($body) !== $want) { $close(); return ['error' => 'body length mismatch']; }
        }
        $close();
        return [$code, $fields, $body];
    } catch (Throwable $t) {
        return ['error' => 'socket engine: ' . $t->getMessage()];
    }
}
function read_proxy(): array {
    $t = strtolower(trim((string)($_REQUEST['proxy_type'] ?? 'none')));
    if (!in_array($t, ['none', 'http', 'socks5'], true)) $t = 'none';
    $host = trim((string)($_REQUEST['proxy_host'] ?? ''));
    $port = max(1, min(65535, (int)($_REQUEST['proxy_port'] ?? 0)));
    if ($t !== 'none' && ($host === '' || $port === 0))
        jer('proxy selected but host/port missing');
    return ['type' => $t, 'host' => $host, 'port' => $port ?: 1080,
        'user' => (string)($_REQUEST['proxy_user'] ?? ''), 'pass' => (string)($_REQUEST['proxy_pass'] ?? '')];
}

// ── capability check (mirrors includes/setup_check.php rows, standalone) ─────
function cap_checks(): array {
    $out = [];
    $out[] = version_compare(PHP_VERSION, '8.2.0', '>=')
        ? row('php', 'PHP ' . PHP_VERSION, 'ok')
        : row('php', 'PHP ' . PHP_VERSION, 'fail', 'DeadDropMGMT needs PHP 8.2+. Ask the host to switch the PHP version for this domain.');
    foreach (['pdo_mysql' => 'fail', 'mbstring' => 'fail', 'openssl' => 'warn', 'zlib' => 'warn'] as $ext => $lvl) {
        $out[] = extension_loaded($ext)
            ? row('ext_' . $ext, $ext . ' ' . pver($ext), 'ok')
            : row('ext_' . $ext, $ext . ($lvl === 'fail' ? ' MISSING' : ' missing'), $lvl,
                $lvl === 'fail' ? "Required. Enable $ext in the panel (Select PHP Version / extensions)."
                    : "Optional: without $ext some features degrade (updates need zlib).");
    }
    $hasCurl = function_exists('curl_init');
    $out[] = $hasCurl ? row('ext_curl', 'curl ' . pver('curl'), 'ok')
        : row('ext_curl', 'curl missing', 'info', 'Optional. Without cURL: no SOCKS proxy, no HTTPS-via-proxy; direct downloads use streams.');
    $fopen = filter_var(eini('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN);
    $tls = $hasCurl || ($fopen && function_exists('stream_socket_client') && extension_loaded('openssl'));
    $out[] = $tls ? row('tls', 'HTTPS transport', 'ok')
        : row('tls', 'HTTPS transport', 'fail', 'Neither cURL nor (allow_url_fopen + openssl) available — GitHub downloads are impossible. Enable cURL.');
    $out[] = $fopen ? row('fopen', 'allow_url_fopen on', 'ok')
        : row('fopen', 'allow_url_fopen off', $hasCurl ? 'info' : 'fail',
            $hasCurl ? 'Fine — cURL covers downloads.' : (function_exists('stream_socket_client')
                ? 'Downloads fall back to the bundled socket engine.'
                : 'With cURL also missing, downloads cannot work.'));
    $out[] = class_exists('ZipArchive') ? row('zip', 'ZipArchive', 'ok')
        : row('zip', 'ZipArchive MISSING', 'fail', 'Required to unpack the release. Enable the zip extension in the panel.');
    $w = is_writable(base());
    $out[] = $w ? row('writedir', 'directory writable', 'ok')
        : row('writedir', 'directory NOT writable', 'fail', 'The installer cannot write here. Fix ownership/permissions (755/775) or pick another dir.');
    $free = edisk(base());
    $out[] = $free === false ? row('disk', 'disk space unknown', 'info')
        : ($free > 32 * 1048576 ? row('disk', 'disk free: ' . round($free / 1048576) . ' MB', 'ok')
            : row('disk', 'disk free: ' . round($free / 1048576) . ' MB', 'fail', 'Release needs ~5 MB + room for tiles/maps. Free space first.'));
    // Upload fallback viability: the release zip is ~4 MB and panel PHP
    // builds often cap uploads at 2 MB — know BEFORE downloading fails.
    $upMax = shorthand_bytes(eini('upload_max_filesize'));
    $postMax = shorthand_bytes(eini('post_max_size'));
    $upCap = min($upMax, $postMax);
    $out[] = $upCap === PHP_INT_MAX ? row('upload', 'upload limit: unlimited', 'ok')
        : ($upCap >= 5 * 1048576 ? row('upload', 'upload limit: ' . round($upCap / 1048576) . ' MB', 'ok')
            : row('upload', 'upload limit: ' . round($upCap / 1048576) . ' MB', 'warn',
                'The ~4 MB release zip may not fit a manual upload — prefer direct download on this host.'));
    $met = eini('max_execution_time');
    $out[] = row('max_time', 'max_execution_time=' . ($met !== '' ? $met : '?'),
        ($met !== '' && (int)$met > 0 && (int)$met < 20) ? 'warn' : 'info',
        'The package downloads in one request (~4 MB); under ~20 s limits a slow link can time out — retry or upload the zip manually.');
    $out[] = function_exists('set_time_limit') ? row('set_time_limit', 'set_time_limit', 'ok')
        : row('set_time_limit', 'set_time_limit disabled', 'warn', 'Long steps run in small chunks anyway — slower but fine.');
    $out[] = function_exists('proc_open') ? row('proc_open', 'proc_open', 'ok')
        : row('proc_open', 'proc_open disabled', 'info', 'Fine — the app runs its pure-PHP maps pipeline instead.');
    $sp = eini('session.save_path');
    // @: the path may sit outside open_basedir — report, don't warn.
    $out[] = ($sp === '' || @is_writable($sp)) ? row('sessions', 'session path' . ($sp !== '' ? ': ' . $sp : ''), 'ok')
        : row('sessions', 'session path not writable', 'warn', 'The installer pre-creates cache/sessions and the app falls back to it automatically.');
    $sw = (string)($_SERVER['SERVER_SOFTWARE'] ?? '');
    $out[] = stripos($sw, 'apache') !== false ? row('server', $sw, 'ok')
        : row('server', $sw !== '' ? $sw : 'web server', 'warn', 'Only Apache honors .htaccess. On nginx apply docs/nginx-deaddrop.conf after install.');
    $ob = eini('open_basedir');
    if ($ob !== '') $out[] = row('open_basedir', 'open_basedir=' . $ob, 'info', 'May block temp paths outside this dir — the installer keeps everything local.');
    $out[] = row('memory', 'memory_limit=' . (eini('memory_limit') !== '' ? eini('memory_limit') : '?'), 'info');
    return $out;
}

// ── schema splitter/apply (same rules as includes/setup_check.php) ───────────
function schema_statements(string $sql, bool $keepCreate = false): array {
    $out = [];
    foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
        $body = implode("\n", array_filter(explode("\n", $stmt),
            function (string $l): bool {
                return trim($l) !== '' && !str_starts_with(ltrim($l), '--');
            }));
        if ($body === '' || preg_match('/^USE\s+/i', $body) === 1) continue;
        if (str_starts_with($body, 'CREATE DATABASE') && !$keepCreate) continue;
        $out[] = $body;
    }
    return $out;
}
function schema_apply(PDO $pdo, array $stmts): array {
    $n = 0;
    foreach ($stmts as $body) {
        try {
            $st = $pdo->query($body);
            if ($st instanceof PDOStatement) { while ($st->nextRowset()) {} $st->closeCursor(); }
            $n++;
        } catch (PDOException $e) {
            return ['applied' => $n, 'error' => $e->getMessage(), 'statement' => $body];
        }
    }
    return ['applied' => $n, 'error' => '', 'statement' => ''];
}

// ── action dispatch ──────────────────────────────────────────────────────────
$action = (string)($_GET['action'] ?? $_POST['action'] ?? '');
if ($action !== '') {
    unlimit();
    if ($action === 'check') {
        $rows = cap_checks();
        $fails = 0;
        foreach ($rows as $r) if ($r['status'] === 'fail') $fails++;
        jout(['ok' => true, 'rows' => $rows, 'fails' => $fails]);
    }
    if ($action === 'tags') {
        $proxy = read_proxy();
        $src = trim((string)($_POST['src'] ?? ''));
        if ($src === '') $src = INST_TAGS_API;
        if (!preg_match('#^https?://#i', $src) && !str_starts_with($src, 'file://')) jer('not an http(s) URL');
        $r = http_fetch($src, $proxy);
        if (isset($r['error'])) jer('version list failed: ' . $r['error']);
        if ($r[0] !== 200) jer('version source answered HTTP ' . $r[0] . ' — proxy/auth issue? Add a proxy below or paste a zip URL manually.');
        $tags = json_decode($r[2], true);
        if (!is_array($tags)) jer('version source returned garbage — paste a zip URL manually.');
        $out = [];
        foreach ($tags as $t) {
            if (!isset($t['name'], $t['zipball_url'])) continue;
            $out[] = ['tag' => (string)$t['name'], 'zip' => (string)$t['zipball_url']];
            if (count($out) >= 15) break;
        }
        jout(['ok' => true, 'tags' => $out, 'via' => $r['via'] ?? '?']);
    }
    if ($action === 'tree') { // already-extracted app present?
        jout(['ok' => true, 'present' => is_file(base() . '/setup.sql') && is_file(base() . '/includes/kernel.php'),
            'has_config' => is_file(base() . '/config.php')]);
    }
    if ($action === 'download') {
        // One single request: GitHub's archive endpoint (codeload) ignores
        // Range, so resume/chunking is impossible there — but the package is
        // only a few MB and hosts that cannot reach GitHub at all get the
        // manual-upload button instead. A failed fetch never touches a
        // previous good package: it lands in .part, is validated, and only
        // then replaces the download.
        $proxy = read_proxy();
        $url = trim((string)($_POST['url'] ?? ''));
        if (!preg_match('#^https?://#i', $url)) jer('not an http(s) URL');
        [$zip] = dl_paths();
        $tmp = $zip . '.part';
        @unlink($tmp);
        $r = http_fetch($url, $proxy);
        if (isset($r['error'])) jer($r['error']);
        [$code, $hdrs, $body] = [$r[0], $r[1], $r[2]];
        if ($code !== 200) jer('GitHub answered HTTP ' . $code . ' — wrong URL, or the proxy blocks it?');
        $ct = strtolower($hdrs['content-type'] ?? '');
        if ($body === '' || (!str_contains($ct, 'zip') && !str_contains($ct, 'octet-stream') && substr($body, 0, 2) !== 'PK'))
            jer('that URL did not return a zip (HTTP ' . $code . ', ' . ($ct !== '' ? $ct : 'no content-type') . ') — check the version/URL.');
        if (@file_put_contents($tmp, $body) === false) jer('cannot write download — directory not writable?');
        @unlink($zip);
        if (!@rename($tmp, $zip)) {
            @unlink($tmp);
            jer('cannot store download — directory not writable?');
        }
        $size = filesize($zip);
        jout(['ok' => true, 'size' => $size, 'total' => $size, 'done' => true, 'via' => $r['via'] ?? '?',
            'log' => 'download complete: ' . number_format($size) . ' B']);
    }
    // Probe any URL through any proxy: powers the pool's Test buttons (and
    // the test-suite). Reports transport used, status, size, latency.
    if ($action === 'fetch') {
        $proxy = read_proxy();
        $url = trim((string)($_POST['url'] ?? ''));
        if (!preg_match('#^https?://#i', $url)) jer('not an http(s) URL');
        $t0 = microtime(true);
        $r = http_fetch($url, $proxy);
        $ms = (int)round((microtime(true) - $t0) * 1000);
        if (isset($r['error'])) jout(['ok' => false, 'error' => $r['error'], 'ms' => $ms, 'via' => $r['via'] ?? '?']);
        jout(['ok' => true, 'code' => $r[0], 'bytes' => strlen($r[2]), 'ms' => $ms, 'via' => $r['via'] ?? '?']);
    }
    // Public proxy discovery (same community sources as the app's
    // proxy_discover): fetches the Proxifly list over the current route,
    // keeps SOCKS + rated-anonymous HTTP entries, returns candidates
    // UNTESTED — the UI probes each through fetch before pooling it.
    if ($action === 'discover') {
        $proxy = read_proxy();
        $src = trim((string)($_POST['src'] ?? ''));
        if ($src === '') $src = 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json';
        if (!preg_match('#^https?://#i', $src) && !str_starts_with($src, 'file://')) jer('not an http(s) URL');
        $r = http_fetch($src, $proxy);
        if (isset($r['error'])) jer('list download failed: ' . $r['error'] . ' — discovery needs a working route first (direct or a manual proxy).');
        if ($r[0] !== 200) jer('list source answered HTTP ' . $r[0]);
        $list = json_decode($r[2], true);
        if (!is_array($list)) jer('list source returned garbage');
        $out = [];
        $seen = [];
        foreach ($list as $entry) {
            if (!is_array($entry)) continue;
            $proto = strtolower((string)($entry['protocol'] ?? ''));
            if ($proto === '') continue;
            $anon = strtolower((string)($entry['anonymity'] ?? ''));
            if (!str_starts_with($proto, 'socks') && !in_array($anon, ['anonymous', 'elite'], true)) continue;
            $ip = (string)($entry['ip'] ?? '');
            $port = (string)($entry['port'] ?? '');
            if ($ip === '' || $port === '') continue;
            $norm = ix_norm($proto . '://' . $ip . ':' . $port);
            if ($norm === null || isset($seen[$norm])) continue;
            $seen[$norm] = true;
            $out[] = ['url' => $norm, 'source' => 'proxifly'];
            if (count($out) >= 40) break;
        }
        jout(['ok' => true, 'candidates' => $out, 'via' => $r['via'] ?? '?',
            'log' => count($out) . ' candidates (untested — probe them before use)']);
    }
    if ($action === 'upload') {
        if (!class_exists('ZipArchive')) jer('ZipArchive missing — enable the zip extension in the panel first.');
        if (empty($_FILES['zip']['tmp_name']) || !is_uploaded_file($_FILES['zip']['tmp_name'])) jer('no file received');
        [$zip] = dl_paths();
        if (!@move_uploaded_file($_FILES['zip']['tmp_name'], $zip)) jer('cannot store upload — directory not writable?');
        $z = new ZipArchive();
        if ($z->open($zip) !== true) { @unlink($zip); jer('not a valid zip archive'); }
        $n = $z->numFiles; $z->close();
        jout(['ok' => true, 'size' => filesize($zip), 'files' => $n,
            'log' => 'upload received: ' . number_format((int)filesize($zip)) . ' B, ' . $n . ' entries']);
    }
    if ($action === 'extract') {
        if (!class_exists('ZipArchive')) jer('ZipArchive missing — enable the zip extension.');
        [$zip, $src] = dl_paths();
        if (!is_file($zip)) jer('no package yet — download or upload the release zip first');
        $z = new ZipArchive();
        if ($z->open($zip) !== true) jer('cannot open zip — re-download (interrupted transfer?)');
        $first = (string)$z->getNameIndex(0);
        $prefix = str_contains($first, '/') ? substr($first, 0, strpos($first, '/') + 1) : '';
        $n = $z->numFiles;
        @mkdir($src, 0755, true);
        if (!$z->extractTo($src)) { $z->close(); jer('extract failed — disk full or permissions?'); }
        $z->close();
        $from = $src . '/' . $prefix;
        if (!is_dir($from)) { rmdir_r($src); jer('unexpected zip layout (no top folder)'); }
        $keepCfg = !empty($_POST['keep_config']) && is_file(base() . '/config.php');
        $moved = 0; $skipped = 0;
        foreach (scandir($from) as $e) {
            if ($e === '.' || $e === '..') continue;
            if ($keepCfg && $e === 'config.php') { $skipped++; continue; }
            if ($e === basename(__FILE__)) { $skipped++; continue; } // never overwrite the running installer
            $dst = base() . '/' . $e;
            rmdir_r($dst);
            if (!@rename($from . '/' . $e, $dst)) { rmdir_r($src); jer('cannot move ' . $e . ' into place — permissions?'); }
            $moved++;
        }
        rmdir_r($src); @unlink($zip);
        jout(['ok' => true, 'moved' => $moved, 'entries' => $n, 'kept_config' => $keepCfg,
            'log' => "extracted $n entries, placed $moved top-level items" . ($keepCfg ? ' (existing config.php kept)' : '')]);
    }
    if ($action === 'dbtest' || $action === 'setup') {
        if (!class_exists('PDO') || !extension_loaded('pdo_mysql')) {
            jer('database step needs pdo_mysql (missing here) — enable it in the panel, then re-run this step only.');
        }
        $h = trim((string)($_POST['db_host'] ?? 'localhost'));
        $port = max(1, min(65535, (int)($_POST['db_port'] ?? 3306)));
        $name = trim((string)($_POST['db_name'] ?? ''));
        $user = trim((string)($_POST['db_user'] ?? ''));
        $pass = (string)($_POST['db_pass'] ?? '');
        if ($name === '' || $user === '') jer('database name and user are required');
        if (!preg_match('/^[0-9A-Za-z_$]+$/', $name)) jer('database name must be plain [A-Za-z0-9_$] (panel-prefixed names are fine)');
        try {
            $pdo = new PDO("mysql:host=$h;port=$port;dbname=$name;charset=utf8mb4", $user, $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10]);
        } catch (PDOException $e) {
            jer('connect failed: ' . $e->getMessage() . ' — create the database + user in the panel first (the installer has no CREATE DATABASE privilege there).');
        }
        $ver = (string)$pdo->query('SELECT VERSION()')->fetchColumn();
        if ($action === 'dbtest') {
            $have = [];
            try {
                foreach ($pdo->query('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()')->fetchAll(PDO::FETCH_COLUMN) as $t) $have[] = $t;
            } catch (Throwable) {}
            jout(['ok' => true, 'version' => $ver,
                'tables' => count(array_intersect(INST_TABLES, $have)) . '/' . count(INST_TABLES),
                'log' => "connected: MySQL $ver, schema tables present: " . count(array_intersect(INST_TABLES, $have)) . '/' . count(INST_TABLES)]);
        }
        // — full setup —
        $log = ["connected: MySQL $ver"];
        if (!is_file(base() . '/config.php.example') || !is_file(base() . '/setup.sql'))
            jer('app files missing — extract the release first (config.php.example / setup.sql not found).');
        // 1. storage dirs
        foreach (INST_DIRS as $d) {
            $p = base() . '/' . $d;
            if (!is_dir($p) && !@mkdir($p, 0755, true)) jer('cannot create ' . $d . ' — permissions?');
            $probe = $p . '/.__w';
            if (@file_put_contents($probe, '1') === false || !@unlink($probe)) jer($d . ' is not writable — permissions?');
            $log[] = 'dir ok: ' . $d;
        }
        // 2. config.php (patch the shipped example so future options stay in sync)
        $tpl = (string)file_get_contents(base() . '/config.php.example');
        $key = bin2hex(random_bytes(32));
        $rep = [
            "_secret('DDMGMT_DB_HOST', 'localhost')" => "_secret('DDMGMT_DB_HOST', '" . pq($h) . "')",
            "_secret('DDMGMT_DB_PORT', '3306')" => "_secret('DDMGMT_DB_PORT', '" . $port . "')",
            "_secret('DDMGMT_DB_NAME', 'deaddrops')" => "_secret('DDMGMT_DB_NAME', '" . pq($name) . "')",
            "_secret('DDMGMT_DB_USER', 'root')" => "_secret('DDMGMT_DB_USER', '" . pq($user) . "')",
            "_secret('DDMGMT_DB_PASS', '')" => "_secret('DDMGMT_DB_PASS', '" . pq($pass) . "')",
            'REPLACE_WITH_64_HEX_CHARS_FROM_PHP_R_ABOVE__________' => $key,
        ];
        foreach ($rep as $from => $to) {
            if (!str_contains($tpl, $from)) jer('config template changed upstream (anchor missing: ' . substr($from, 0, 40) . '…) — update the installer.');
            $tpl = str_replace($from, $to, $tpl);
        }
        $cfgHead = "<?php\n// Generated by DeadDropMGMT web installer " . INST_VERSION . ' on ' . gmdate('Y-m-d H:i:s') . " UTC.\n";
        if (@file_put_contents(base() . '/config.php', $cfgHead . substr($tpl, 5)) === false)
            jer('cannot write config.php — directory not writable?');
        $log[] = 'config.php written (AES key generated fresh)';
        // 3. schema
        $stmts = schema_statements((string)file_get_contents(base() . '/setup.sql'));
        $res = schema_apply($pdo, $stmts);
        $log[] = 'schema: ' . $res['applied'] . '/' . count($stmts) . ' statements applied';
        if ($res['error'] !== '') jer('schema failed after ' . $res['applied'] . ' statements: ' . $res['error'] . ' — statement: ' . substr($res['statement'], 0, 200));
        // 4. verify
        $have = [];
        $engines = [];
        try {
            foreach ($pdo->query('SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()')->fetchAll() as $r) {
                $have[] = $r['TABLE_NAME']; $engines[$r['TABLE_NAME']] = strtoupper((string)$r['ENGINE']);
            }
        } catch (Throwable) {}
        $missing = array_values(array_diff(INST_TABLES, $have));
        if ($missing !== []) jer('schema applied but tables missing: ' . implode(', ', $missing));
        $log[] = 'schema verified: ' . count(INST_TABLES) . '/' . count(INST_TABLES) . ' tables';
        $badEng = [];
        foreach (INST_TABLES as $t) if (($engines[$t] ?? 'INNODB') !== 'INNODB') $badEng[] = $t . ':' . $engines[$t];
        if ($badEng !== []) $log[] = 'WARNING non-InnoDB tables: ' . implode(', ', $badEng) . ' (ask host to default to InnoDB)';
        // 5. session fallback dir + server note
    $sp = eini('session.save_path');
        $log[] = ($sp === '' || is_writable($sp)) ? 'sessions: default path usable'
            : 'sessions: default NOT writable — app auto-falls back to cache/sessions (pre-created)';
        $sw = (string)($_SERVER['SERVER_SOFTWARE'] ?? '');
        if (stripos($sw, 'apache') === false)
            $log[] = 'NOTE non-Apache server (' . ($sw !== '' ? $sw : 'unknown') . '): apply docs/nginx-deaddrop.conf manually';
        elseif (!is_file(base() . '/.htaccess'))
            $log[] = 'WARNING .htaccess missing from package — protection rules absent!';
        else $log[] = 'server: Apache + .htaccess present';
        jout(['ok' => true, 'log' => $log, 'applied' => $res['applied']]);
    }
    if ($action === 'remove') {
        $me = __FILE__;
        if (@unlink($me)) jout(['ok' => true]);
        jer('could not delete itself — remove ' . basename($me) . ' via FTP/file manager.');
    }
    jer('unknown action');
}
function rmdir_r(string $p): void {
    if (is_link($p) || is_file($p)) { @unlink($p); return; }
    if (!is_dir($p)) return;
    foreach (scandir($p) as $e) {
        if ($e === '.' || $e === '..') continue;
        rmdir_r($p . '/' . $e);
    }
    @rmdir($p);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DeadDropMGMT installer</title>
<style>
:root{--bg:#0a0a0a;--surface:#111111;--border:#222222;--text:#e8e8e8;--muted:#666666;--accent:#ffffff;--error:#ff3333;--warn:#e0a100;--info:#4caf50}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.65;padding:48px 24px 80px}
.wrap{max-width:720px;margin:0 auto}
.wordmark{font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);padding-bottom:20px;border-bottom:1px solid var(--border);margin-bottom:28px}
h1{font-size:20px;font-weight:300;letter-spacing:.06em;text-transform:uppercase;color:var(--accent);margin-bottom:8px}
.sub{color:var(--text);margin-bottom:32px;font-size:15px}
.card{background:transparent;border:1px solid var(--border);border-radius:0;padding:24px;margin-bottom:40px}
.steps{display:flex;gap:0;margin-bottom:40px;border:1px solid var(--border)}
.step{flex:1;min-width:90px;font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);padding:12px 8px;text-align:center;border-right:1px solid var(--border)}
.step:last-child{border-right:0}.step.on{color:var(--text);background:var(--surface)}.step.done{color:var(--muted)}
.sec{font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:20px 0 12px}
.sec:first-child{margin-top:0}
label{display:block;margin:14px 0 2px;color:var(--muted);font-size:13px}
input[type=text],input[type=password],input[type=number],select{width:100%;background:transparent;border:0;border-bottom:1px solid var(--border);color:var(--text);font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:14px;padding:10px 0;outline:none;border-radius:0}
input:focus,select:focus{border-bottom-color:var(--accent)}
input::placeholder{color:var(--muted);font-size:13px}
select option{background:var(--surface)}
input[type=checkbox]{accent-color:var(--accent)}
input[type=number]{-moz-appearance:textfield;appearance:textfield}
input[type=number]::-webkit-inner-spin-button,input[type=number]::-webkit-outer-spin-button{-webkit-appearance:none;margin:0}
input[type=file]{width:100%;font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:13px;color:var(--muted);padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer;background:transparent;border-radius:0}
input[type=file]::file-selector-button{background:transparent;border:1px solid var(--border);color:var(--muted);font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:6px 14px;cursor:pointer;margin-right:14px}
input[type=file]::file-selector-button:hover{background:var(--accent);color:var(--bg)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:0 16px}
button{display:inline-block;background:transparent;color:var(--text);border:1px solid var(--border);font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:11px;letter-spacing:.12em;text-transform:uppercase;padding:12px 28px;cursor:pointer;margin:16px 16px 0 0;border-radius:0}
button:hover{background:var(--accent);color:var(--bg);border-color:var(--accent)}
button.ghost{border:0;color:var(--muted);padding:12px 0}
button.ghost:hover{background:transparent;color:var(--text)}
button.sm{padding:8px 18px;font-size:10px;margin:8px 8px 0 0}
button:disabled{opacity:.35;cursor:default}button:disabled:hover{background:transparent;color:var(--text);border-color:var(--border)}
button.ghost:disabled:hover{color:var(--muted)}
.row{display:flex;gap:12px;align-items:baseline;padding:8px 0;border-top:1px solid var(--border);font-size:13px}
.st{margin-left:auto;flex:0 0 auto;font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.st-ok{color:var(--info)}.st-fail{color:var(--error)}.st-warn{color:var(--warn)}.st-info{color:var(--muted)}
.det{color:var(--muted);font-size:12px}
.bar{height:2px;background:var(--border);margin:16px 0 8px}.bar>i{display:block;height:100%;background:var(--accent);width:0}
#log{background:#000;border:1px solid var(--border);border-radius:0;padding:14px 16px;height:240px;overflow-y:auto;font:12px/1.7 ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;white-space:pre-wrap}
#log .t{color:#444}#log .ok{color:var(--info)}#log .fail{color:var(--error)}#log .warn{color:var(--warn)}#log .info{color:var(--text)}
.hint{font-size:13px;color:var(--muted)}a{color:var(--accent)}.hidden{display:none}
code{font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace;font-size:12px;color:var(--text)}
.pxrow{display:flex;gap:10px;align-items:baseline;padding:8px 0;border-top:1px solid var(--border);font-size:12px;font-family:ui-monospace,'IBM Plex Mono',Menlo,Consolas,monospace}
.pxrow .u{flex:1;word-break:break-all}.pxrow .src{color:var(--muted);font-size:10px}
.copy-scratch{position:fixed;opacity:0;top:0;left:0}
@media(max-width:640px){.grid2,.grid3{grid-template-columns:1fr}body{padding:24px 12px 60px}}
</style>
</head>
<body>
<div class="wrap">
<div class="wordmark">DeadDrop MGMT — installer v<?= INST_VERSION ?></div>
<h1>Install</h1>
<p class="sub">Upload this one file to your hosting directory, then follow the steps. Everything is logged below — copy it if you need help.</p>
<div class="steps" id="steps">
<div class="step" data-s="0">1. Server check</div><div class="step" data-s="1">2. Package</div><div class="step" data-s="2">3. Database</div><div class="step" data-s="3">4. Finish</div>
</div>

<div class="card" id="p0">
<div class="sec">Server capability check</div>
<p class="hint">Same checks as the app's own setup_check: PHP, extensions, HTTPS transport, zip support, writability, disk space.</p>
<div id="checks"><p class="hint">Running…</p></div>
<label><input type="checkbox" id="override"> Continue despite failures (I know what I'm doing)</label>
<div><button id="b0" disabled>Continue →</button><button class="ghost" id="recheck">Re-check</button></div>
</div>

<div class="card hidden" id="p1">
<div class="sec">App package</div>
<div id="treeinfo"></div>
<label>Version</label><select id="ver"><option value="">Loading versions from GitHub…</option></select>
<label>…or paste a release zip URL manually</label><input type="text" id="url" placeholder="https://github.com/…/archive/refs/tags/v1.5.0.zip">
<div class="sec">Route: how this server reaches GitHub</div>
<p class="hint">Direct first; when the host cannot reach github.com, add proxies to the pool and switch to auto (tried in order) or pin one. Every request — versions, download, discovery — uses the route shown here. SOCKS resolves hostnames at the proxy (no local DNS leak).</p>
<label>Mode</label><select id="mode"><option value="direct">direct (no proxy)</option><option value="auto">auto — try pool in order</option></select>
<div id="pool"></div>
<div class="sec">Add proxy</div>
<div class="grid3">
<div><label>Type</label><select id="pt"><option value="http">HTTP</option><option value="socks5">SOCKS5</option><option value="socks4">SOCKS4</option></select></div>
<div><label>Host</label><input type="text" id="ph" placeholder="127.0.0.1"></div>
<div><label>Port</label><input type="number" id="pp" placeholder="1080"></div>
</div>
<div class="grid2">
<div><label>User (optional)</label><input type="text" id="pu"></div>
<div><label>Password (optional)</label><input type="password" id="pw"></div>
</div>
<div><button class="ghost" id="badd">Add to pool</button><button class="ghost" id="bdisc">Discover public proxies</button><button class="ghost hidden" id="btestall">Test all</button></div>
<div class="bar"><i id="dbar"></i></div><div class="hint" id="dtxt"></div>
<div><button id="bdl">Download</button><button class="ghost" id="bup">Upload a zip instead…</button><input type="file" id="fup" accept=".zip" class="hidden"></div>
<div id="dlbtns" class="hidden"><label><input type="checkbox" id="keepcfg" checked> Keep existing config.php (upgrade mode)</label><br><button id="bex">Extract into this directory</button></div>
<div><button id="b1" class="hidden">Continue →</button></div>
</div>

<div class="card hidden" id="p2">
<div class="sec">Database + site setup</div>
<p class="hint">Create the database and user in your hosting panel first (the installer has no such privilege there), then enter them here. Writes <code>config.php</code>, creates storage dirs, imports the schema.</p>
<div class="grid2">
<div><label>Host</label><input type="text" id="dh" value="localhost"></div>
<div><label>Port</label><input type="number" id="dp" value="3306"></div>
<div><label>Database name</label><input type="text" id="dn" placeholder="user_deaddrops"></div>
<div><label>User</label><input type="text" id="du" placeholder="user_ddmgmt"></div>
</div>
<label>Password</label><input type="password" id="dk">
<div><button class="ghost" id="btest">Test connection</button><button id="b2">Install now</button></div>
<div id="setuprows"></div>
</div>

<div class="card hidden" id="p3">
<div class="sec">Done 🎉</div>
<div id="finlinks"></div>
<div class="sec">Maintenance</div>
<p class="hint">No cron needed: hourly cleanup runs from page visits (pseudo-cron, on by default). Map sync advances from the admin UI. If your panel offers real cron, <code>php /path/to/cron/cleanup.php</code> hourly lets you turn pseudo-cron off.</p>
<div><button id="bdel">Delete this installer</button></div>
</div>

<div class="card"><div class="sec">Log <button class="ghost" id="copylog" style="margin:0 0 0 8px;padding:3px 10px;font-size:12px">Copy</button></div><div id="log"></div></div>
</div>
<script>
(function(){
"use strict";
var $=function(id){return document.getElementById(id)};
var step=0;
function stamp(){var d=new Date();return d.toISOString().substr(11,8)}
function log(msg,cls){var el=$("log");var s=document.createElement("span");s.innerHTML='<span class="t">['+stamp()+'] </span><span class="'+(cls||"info")+'"></span>';s.lastChild.textContent=msg;el.appendChild(s);el.appendChild(document.createTextNode("\n"));el.scrollTop=el.scrollHeight}
function go(n){step=n;["p0","p1","p2","p3"].forEach(function(id,i){$(id).classList.toggle("hidden",i!==n)});
var st=document.querySelectorAll("#steps .step");st.forEach(function(e,i){e.classList.toggle("on",i===n);e.classList.toggle("done",i<n)});window.scrollTo(0,0)}
function fd(o){var f=new FormData();for(var k in o)f.append(k,o[k]);return f}
function api(action,data,files){
var f=files||fd(data||{});f.append("action",action);
return fetch("?action="+encodeURIComponent(action),{method:"POST",body:f}).then(function(r){return r.json()}).catch(function(e){return {ok:false,error:"request failed: "+e}});
}
function get(action,qs){return fetch("?action="+encodeURIComponent(action)+(qs||""),{method:"GET"}).then(function(r){return r.json()}).catch(function(e){return {ok:false,error:"request failed: "+e}})}
/* proxy pool: [{t,h,p,u,w,src,st}] st = untested|ok|fail (+ms). persisted. */
var pool=[];try{pool=JSON.parse(localStorage.getItem("ddm_inst_px")||"[]")}catch(e){pool=[]}
if(!Array.isArray(pool))pool=[];
var lastGood=null;
function savePool(){try{localStorage.setItem("ddm_inst_px",JSON.stringify(pool))}catch(e){}}
function routeName(p){return p?p.t+"://"+p.h+":"+p.p+(p.u?" (auth)":""):"direct"}
function routes(){
var m=$("mode").value;
if(m==="direct"||!pool.length)return [null];
if(m.indexOf("px:")===0){var p=pool[+m.slice(3)];return [p||null]}
return pool.slice();
}
function pxObj(p){return p?{proxy_type:p.t,proxy_host:p.h,proxy_port:p.p,proxy_user:p.u||"",proxy_pass:p.w||""}:{proxy_type:"none"}}
function renderPool(){
var h="",m=$("mode"),keep=m.value;
m.innerHTML='<option value="direct">direct (no proxy)</option><option value="auto">auto — try pool in order</option>';
pool.forEach(function(p,i){
var o=document.createElement("option");o.value="px:"+i;o.textContent=routeName(p);m.appendChild(o);
var st=p.st==="ok"?"ok ("+p.ms+" ms)":(p.st||"untested");
h+='<div class="pxrow"><span class="u">'+routeName(p)+'</span><span class="src">'+(p.src||"manual")+'</span><span class="st st-'+(p.st==="ok"?"ok":p.st==="fail"?"fail":"info")+'">'+st+'</span><span><button class="sm" data-t="'+i+'">test</button><button class="sm" data-u="'+i+'">use</button><button class="sm" data-d="'+i+'">del</button></span></div>';
});
if(!pool.length)h='<p class="hint">Pool empty — direct unless you add proxies.</p>';
$("pool").innerHTML=h;
if(keep==="auto"||keep==="direct"||keep.indexOf("px:")===0)m.value=keep;
$("btestall").classList.toggle("hidden",!pool.length);
Array.prototype.forEach.call($("pool").querySelectorAll("[data-t]"),function(b){b.onclick=function(){testPx(pool[+b.getAttribute("data-t")])}});
Array.prototype.forEach.call($("pool").querySelectorAll("[data-u]"),function(b){b.onclick=function(){$("mode").value="px:"+b.getAttribute("data-u");log("route pinned: "+routeName(pool[+b.getAttribute("data-u")]),"info");loadTags()}});
Array.prototype.forEach.call($("pool").querySelectorAll("[data-d]"),function(b){b.onclick=function(){pool.splice(+b.getAttribute("data-d"),1);savePool();renderPool()}});
}
function testPx(p,cb){
if(!p){if(cb)cb(null);return}
log("probing "+routeName(p)+"…","info");
api("fetch",Object.assign({url:"https://api.github.com/repos/kilerdevs/DeadDropMGMT/tags"},pxObj(p))).then(function(r){
if(r.ok&&r.code===200){p.st="ok";p.ms=r.ms;lastGood=p;log("proxy OK: "+routeName(p)+" — HTTP 200, "+r.bytes+" B, "+r.ms+" ms via "+r.via,"ok")}
else{p.st="fail";log("proxy FAIL: "+routeName(p)+" — "+(r.error||("HTTP "+r.code))+" ("+r.ms+" ms)","fail")}
savePool();renderPool();if(cb)cb(p.st==="ok"?p:null);
});
}
var stw={ok:"ok",fail:"blocked",warn:"limited",info:"info"};

/* step 0 */
function runCheck(){
$("checks").innerHTML="<p class='hint'>Running…</p>";$("b0").disabled=true;
get("check").then(function(r){
if(!r.ok){$("checks").innerHTML="<p class='hint'>check failed: "+r.error+"</p>";return}
var h="",fails=r.fails||0;
r.rows.forEach(function(x){h+='<div class="row"><span><b>'+x.label+'</b>'+(x.detail?'<br><span class="det">'+x.detail+'</span>':"")+'</span><span class="st st-'+x.status+'">'+stw[x.status]+"</span></div>";log(x.label+(x.detail?" — "+x.detail:""),x.status)});
$("checks").innerHTML=h;
$("b0").disabled=fails>0&&!$("override").checked;
log("capability check: "+r.rows.length+" rows, "+fails+" blocking failure(s)",fails>0?"fail":"ok");
});
}
$("recheck").onclick=runCheck;$("override").onchange=runCheck;
$("b0").onclick=function(){go(1);loadTree();loadTags()};

/* step 1 */
function loadTree(){
get("tree").then(function(r){
if(!r.ok)return;
$("treeinfo").innerHTML=r.present
?'<p class="hint">App files already present in this directory'+(r.has_config?" <b>and config.php exists</b> (upgrade mode — your config is kept).":" (no config.php yet).")+" You may skip straight to extraction or setup.</p>"
:'<p class="hint">No app files here yet — download the release package below.</p>';
if(r.present){$("dlbtns").classList.remove("hidden");$("b1").classList.remove("hidden")}
log("tree probe: app files "+(r.present?"present":"absent")+", config.php "+(r.has_config?"present":"absent"),"info");
});
}
function loadTags(){
renderPool();
var list=routes(),i=0;
(function next(){
if(i>=list.length){$("ver").innerHTML='<option value="">all routes failed — add a proxy or paste URL manually</option>';log("version list failed on every route","fail");return}
var px=pxObj(list[i]);i++;
log("version list via "+routeName(list[i-1])+"…","info");
api("tags",px).then(function(r){
if(r.ok&&r.tags&&r.tags.length){
var s=$("ver");s.innerHTML="";r.tags.forEach(function(t,j){var o=document.createElement("option");o.value=t.zip;o.textContent=t.tag+(j===0?" (latest)":"");s.appendChild(o)});
var m=document.createElement("option");m.value="MASTER";m.textContent="master (bleeding edge)";s.appendChild(m);
if(list[i-1])lastGood=list[i-1];
log("versions via "+(r.via||"?")+": "+r.tags.map(function(t){return t.tag}).join(", "),"ok");
}else{log("route failed: "+(r.error||"empty"),"warn");next()}
});
})();
}
$("mode").onchange=function(){renderPool();loadTags()};
$("badd").onclick=function(){
var h=$("ph").value.trim(),p=+$("pp").value;
if(!h||!p){log("proxy host + port required","warn");return}
pool.push({t:$("pt").value,h:h,p:p,u:$("pu").value,w:$("pw").value,src:"manual",st:"untested"});
savePool();renderPool();log("proxy added: "+routeName(pool[pool.length-1]),"info");
testPx(pool[pool.length-1]);
};
$("bdisc").onclick=function(){
var list=routes(),i=0;
log("discovering public proxies (needs one working route)…","info");$("bdisc").disabled=true;
(function next(){
if(i>=list.length){$("bdisc").disabled=false;log("discovery failed on every route","fail");return}
var px=pxObj(list[i]);i++;
api("discover",px).then(function(r){
if(r.ok&&r.candidates&&r.candidates.length){
var n=0;r.candidates.forEach(function(c){
var m=c.url.match(/^(\w+):\/\/([^:]+):(\d+)$/);
if(!m)return;
if(pool.some(function(p){return p.t===m[1]&&p.h===m[2]&&+p.p===+m[3]}))return;
pool.push({t:m[1],h:m[2],p:+m[3],u:"",w:"",src:c.source||"discovered",st:"untested"});n++;
});
savePool();renderPool();$("bdisc").disabled=false;
log("discovered "+n+" new candidates via "+(r.via||"?")+" — testing all…","ok");
testAll();
}else{log("discovery route failed: "+(r.error||"empty"),"warn");next()}
});
})();
};
function testAll(){
var q=pool.filter(function(p){return p.st!=="ok"});
if(!q.length){log("pool: everything already tested OK","info");return}
log("testing "+q.length+" proxies…","info");
(function next(i){if(i>=q.length)return;testPx(q[i],function(){next(i+1)})})(0);
}
$("btestall").onclick=testAll;
$("bup").onclick=function(){$("fup").click()};
$("fup").onchange=function(){
if(!$("fup").files.length)return;
log("uploading "+$("fup").files[0].name+"…","info");
var f=new FormData();f.append("zip",$("fup").files[0]);
api("upload",null,f).then(function(r){
if(!r.ok){log("upload failed: "+r.error,"fail");return}
log(r.log,"ok");$("dtxt").textContent="upload complete: "+r.size+" B";
$("dlbtns").classList.remove("hidden");
});
};
$("bdl").onclick=function(){
var url=$("url").value.trim();
if(!url){if(!$("ver").value){log("pick a version or paste a URL","warn");return}
url=$("ver").value==="MASTER"?"<?= INST_MASTER_ZIP ?>":$("ver").value}
log("downloading "+url+" (one request, a few MB)…","info");$("bdl").disabled=true;$("dtxt").textContent="downloading…";
var d=Object.assign({url:url},pxObj(lastGood||routes()[0]||null));
log("download route: "+routeName(lastGood||routes()[0]||null),"info");
api("download",d).then(function(r){
$("bdl").disabled=false;
if(!r.ok){log("download failed: "+r.error,"fail");$("dtxt").textContent="failed";return}
$("dbar").style.width="100%";$("dtxt").textContent=Math.round(r.size/1024)+" KB";
log(r.log+" via "+(r.via||"?"),"ok");$("dlbtns").classList.remove("hidden");
});
};
$("bex").onclick=function(){
log("extracting…","info");$("bex").disabled=true;
api("extract",{keep_config:$("keepcfg").checked?"1":""}).then(function(r){
$("bex").disabled=false;
if(!r.ok){log("extract failed: "+r.error,"fail");return}
log(r.log,"ok");$("b1").classList.remove("hidden");
});
};
$("b1").onclick=function(){go(2)};

/* step 2 */
function dbObj(){return {db_host:$("dh").value,db_port:$("dp").value,db_name:$("dn").value.trim(),db_user:$("du").value.trim(),db_pass:$("dk").value}}
$("btest").onclick=function(){
var d=dbObj();if(!d.db_name||!d.db_user){log("enter database name + user first","warn");return}
log("testing connection to "+d.db_user+"@"+d.db_host+"/"+d.db_name+"…","info");
api("dbtest",d).then(function(r){
if(!r.ok){log("DB: "+r.error,"fail");return}
log("DB: "+r.log,"ok");
});
};
$("b2").onclick=function(){
var d=dbObj();if(!d.db_name||!d.db_user){log("enter database name + user first","warn");return}
log("installing: config → dirs → schema → verify","info");$("b2").disabled=true;
api("setup",d).then(function(r){
$("b2").disabled=false;
if(!r.ok){log("SETUP FAILED: "+r.error,"fail");return}
(r.log||[]).forEach(function(m){log(m,/^warn|not |non-/i.test(m)?"warn":"ok")});
$("setuprows").innerHTML='<div class="row"><span><b>Setup complete</b><br><span class="det">'+r.applied+' schema statements, all checks passed.</span></span><span class="st st-ok">ok</span></div>';
var base=location.href.split("?")[0].replace(/\/[^\/]*$/,"/");
$("finlinks").innerHTML='<p>1. Open <a href="'+base+'admin/">admin/</a> — with zero accounts it shows the <b>create-owner form</b>.<br>2. Then run the full diagnostics at <a href="'+base+'admin/setup_check.php">admin/setup_check.php</a>.<br>3. Delete this installer (button below).</p>';
log("setup complete — create the owner at admin/","ok");go(3);
});
};

/* step 3 */
$("bdel").onclick=function(){
if(!confirm("Delete the installer file?"))return;
api("remove",{}).then(function(r){
log(r.ok?"installer deleted. Installation finished.":"DELETE FAILED: "+r.error,r.ok?"ok":"fail");
if(r.ok)$("bdel").disabled=true;
});
};
$("copylog").onclick=function(){
var t=$("log").innerText;
function done(){log("log copied to clipboard","info")}
function fallback(){
var ta=document.createElement("textarea");ta.className="copy-scratch";ta.value=t;
document.body.appendChild(ta);ta.select();
try{document.execCommand("copy");done()}catch(e){log("copy failed — select the log text manually","warn")}
document.body.removeChild(ta);
}
/* clipboard API needs a secure context (https/localhost) — plain-IP http
   hosting is not one, so fall back to the execCommand scratch element. */
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done,fallback)}
else fallback();
};
log("installer <?= INST_VERSION ?> ready — checking this server…","info");
runCheck();
})();
</script>
</body>
</html>
