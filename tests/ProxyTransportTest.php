<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Pure-PHP proxy transport ─────────────────────────────────────────────────
// Framing units plus end-to-end fetches through loopback stub servers: a
// plain origin, a TLS origin (in-process generated CA, so peer verification
// is really exercised), a CONNECT proxy and a SOCKS5 proxy. Everything runs
// against 127.0.0.1 — no outside network, no cURL needed for most of it
// (the streams path is forced via host_override where the branch matters).

// ── framing + parsing (no network) ──────────────────────────────────────────
// cURL honours *proxy env vars (including NO_PROXY bypasses): pin a clean
// room so the dispatcher assertions mean the same on every machine.
$proxyEnv = [];
foreach (['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'] as $k) {
    $v = getenv($k);
    if (is_string($v)) {
        $proxyEnv[$k] = $v;
    }
    putenv($k);
}
t_teardown(static function () use ($proxyEnv): void {
    foreach ($proxyEnv as $k => $v) {
        putenv($k . '=' . $v);
    }
});
T::eq('socks5 greeting without credentials', '050100', bin2hex(proxy_socks5_greet('')));
T::eq('socks5 greeting offers user/pass auth', '05020002', bin2hex(proxy_socks5_greet('u')));
T::eq('socks5 auth message', '0101750170', bin2hex(proxy_socks5_auth('u', 'p')));
$sc = proxy_socks5_connect('example.com', 443);
T::ok('socks5 connect is domain-type with packed port',
    str_starts_with($sc, "\x05\x01\x00\x03\x0bexample.com") && substr($sc, -2) === pack('n', 443));
$s4 = proxy_socks4_connect('10.1.2.3', 1080, 'bob');
T::ok('socks4 literal IPv4 inline',
    str_starts_with($s4, "\x04\x01" . pack('n', 1080) . "\x0a\x01\x02\x03") && str_ends_with($s4, "bob\x00"));
$s4a = proxy_socks4_connect('some.host', 1080, 'bob');
T::ok('socks4 hostname uses the 4a form',
    str_starts_with($s4a, "\x04\x01" . pack('n', 1080) . "\x00\x00\x00\xff") && str_ends_with($s4a, "some.host\x00"));
$ch = proxy_connect_head('example.com', 443, '', '');
T::ok('CONNECT head without credentials',
    str_starts_with($ch, "CONNECT example.com:443 HTTP/1.1\r\n")
    && str_contains($ch, "Host: example.com:443\r\n")
    && !str_contains($ch, 'Proxy-Authorization'));
$cha = proxy_connect_head('example.com', 443, 'user', 'pass');
T::ok('CONNECT head carries proxy auth', str_contains($cha, 'Proxy-Authorization: Basic dXNlcjpwYXNz'));
T::eq('status line 200', 200, proxy_status_code("HTTP/1.1 200 OK\r\nX: y"));
T::eq('status line 404', 404, proxy_status_code("HTTP/1.0 404 nope\r\n"));
T::eq('garbage is not a status line', 0, proxy_status_code('CONNECT example.com:443'));
[$h, $rest] = proxy_head_split("HTTP/1.1 200 OK\r\nA: b\r\n\r\nBODY") ?? ['', ''];
T::eq('head split', ['HTTP/1.1 200 OK' . "\r\n" . 'A: b', 'BODY'], [$h, $rest]);
T::ok('head split misses without terminator', proxy_head_split("HTTP/1.1 200 OK\r\n") === null);
T::eq('absolute location kept', 'https://x.test/a', proxy_resolve_url('http://h/t', 'https://x.test/a'));
T::eq('protocol-relative inherits scheme', 'http://x.test/a', proxy_resolve_url('http://h/t', '//x.test/a'));
T::eq('root-relative keeps origin', 'http://h:81/a', proxy_resolve_url('http://h:81/t', '/a'));
T::eq('relative merges into the directory', 'http://h/d/a', proxy_resolve_url('http://h/d/t', 'a'));
T::ok('empty location is null', proxy_resolve_url('http://h/d/t', '  ') === null);
[$dec, $left, $fin] = proxy_chunked_feed("5\r\nhello\r\n0\r\n\r\n") ?? ['', '', false];
T::eq('chunked single feed', ['hello', '', true], [$dec, $left, $fin]);
$step1 = proxy_chunked_feed("5\r\nhel");
T::ok('chunked split feed waits', $step1 !== null && $step1[2] === false);
$step2 = $step1 !== null ? proxy_chunked_feed($step1[1] . "lo\r\n0\r\n\r\n") : null;
T::eq('chunked split feed completes', ['hello', '', true], $step2 ?? ['', '', false]);
T::ok('chunked garbage fails closed', proxy_chunked_feed("zz\r\nhello\r\n") === null);
$fields = proxy_head_fields("HTTP/1.1 200 OK\r\nContent-Length: 5\r\ncontent-length: 9\r\nX-A: b");
T::eq('first duplicate header wins, names lowercase', ['content-length' => '5', 'x-a' => 'b'], $fields);
$pt = proxy_parse_target('https://a.tile.openstreetmap.org/13/4051/2749.png');
T::eq('https target defaults', ['host' => 'a.tile.openstreetmap.org', 'dial' => 'a.tile.openstreetmap.org', 'port' => 443, 'tls' => true, 'path' => '/13/4051/2749.png'], $pt);
$pt6 = proxy_parse_target('http://[::1]:8080/a?b=c');
T::ok('IPv6 target keeps brackets for dialling',
    $pt6 !== null && $pt6['dial'] === '[::1]' && $pt6['host'] === '::1' && $pt6['path'] === '/a?b=c');
T::ok('target with userinfo rejected', proxy_parse_target('https://u@h.test/') === null);
T::ok('non-http target rejected', proxy_parse_target('ftp://h.test/f') === null);
$pp = proxy_parse('socks5h://user:p%40ss@10.0.0.1:1080');
T::eq('socks5h parses with decoded credentials',
    ['scheme' => 'socks5h', 'host' => '10.0.0.1', 'dial' => '10.0.0.1', 'port' => 1080, 'user' => 'user', 'pass' => 'p@ss'], $pp);
T::ok('unknown proxy scheme rejected', proxy_parse('ftp://10.0.0.1:21') === null);
T::ok('proxy without port rejected', proxy_parse('http://10.0.0.1') === null);
T::ok('normalizer accepts socks5h', osm_proxy_normalize('socks5h://10.0.0.1:1080') === 'socks5h://10.0.0.1:1080');

// ── stub servers ────────────────────────────────────────────────────────────
$stubDir = sys_get_temp_dir() . '/ddmgmt_pxstub_' . getmypid();
if (!is_dir($stubDir)) {
    mkdir($stubDir, 0700, true);
}
$BODY = str_repeat('0123456789ABCDEF', 256); // 4096 bytes, position-verifiable

$originPhp = <<<'PHP'
<?php
// argv: 1=port 2=pem path or '' for plain HTTP
$port = (int)$argv[1];
$pem = (string)($argv[2] ?? '');
$tls = $pem !== '';
$BODY = str_repeat('0123456789ABCDEF', 256);
if ($tls) {
    $srv = stream_socket_server('tls://127.0.0.1:' . $port, $eno, $estr,
        STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
        stream_context_create(['ssl' => ['local_cert' => $pem]]));
} else {
    $srv = stream_socket_server('tcp://127.0.0.1:' . $port, $eno, $estr);
}
if (!$srv) exit(2);
stream_set_blocking($srv, false);
$until = time() + 180;
$handled = 0;
while (time() < $until && $handled < 400) {
    $r = [$srv]; $w = null; $e = null;
    if (@stream_select($r, $w, $e, 1) !== 1) continue;
    $c = @stream_socket_accept($srv, 1);
    if (!$c) continue;
    stream_set_blocking($c, true); // accepted sockets inherit non-blocking: reads would return partial data
    $handled++;
    if ($tls && !@stream_socket_enable_crypto($c, false, STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | STREAM_CRYPTO_METHOD_TLSv1_3_SERVER)) {
        fclose($c);
        continue;
    }
    stream_set_timeout($c, 5);
    $buf = '';
    while (strpos($buf, "\r\n\r\n") === false && strlen($buf) < 32768) {
        $ch = @fread($c, 8192);
        if (!is_string($ch) || $ch === '') break;
        $buf .= $ch;
    }
    $line = (string)strtok($buf, "\r\n");
    $parts = explode(' ', $line, 3);
    $method = strtoupper($parts[0] ?? 'GET');
    $path = parse_url($parts[1] ?? '/', PHP_URL_PATH);
    if (!is_string($path) || $path === '') $path = '/';
    $range = '';
    foreach (explode("\r\n", $buf) as $hl) {
        if (stripos($hl, 'range:') === 0) $range = trim(substr($hl, 6));
    }
    $headOnly = $method === 'HEAD';
    if ($path === '/tile') {
        if (preg_match('/bytes=(\d+)-(\d*)/', $range, $m)) {
            $s = (int)$m[1];
            $e2 = $m[2] === '' ? strlen($BODY) - 1 : min((int)$m[2], strlen($BODY) - 1);
            if ($s >= strlen($BODY)) {
                fwrite($c, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                fclose($c);
                continue;
            }
            $part = substr($BODY, $s, $e2 - $s + 1);
            fwrite($c, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes $s-$e2/" . strlen($BODY) . "\r\nContent-Length: " . strlen($part) . "\r\nConnection: close\r\n\r\n" . ($headOnly ? '' : $part));
            fclose($c);
            continue;
        }
        fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($BODY) . "\r\nConnection: close\r\n\r\n" . ($headOnly ? '' : $BODY));
        fclose($c);
    } elseif ($path === '/full') {
        // Range-ignoring server: always the whole body with 200.
        fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($BODY) . "\r\nConnection: close\r\n\r\n" . ($headOnly ? '' : $BODY));
        fclose($c);
    } elseif ($path === '/chunked') {
        $b = 'Hello, chunked world!';
        $wire = '7' . "\r\n" . substr($b, 0, 7) . "\r\n" . '7' . "\r\n" . substr($b, 7, 7) . "\r\n" . dechex(strlen($b) - 14) . "\r\n" . substr($b, 14) . "\r\n0\r\n\r\n";
        fwrite($c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" . ($headOnly ? '' : $wire));
        fclose($c);
    } elseif ($path === '/big') {
        $big = str_repeat('B', 65536);
        fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: " . strlen($big) . "\r\nConnection: close\r\n\r\n" . ($headOnly ? '' : $big));
        fclose($c);
    } elseif ($path === '/redirect') {
        fwrite($c, "HTTP/1.1 302 Found\r\nLocation: /tile\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        fclose($c);
    } else {
        fwrite($c, "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\n" . ($headOnly ? '' : 'nope'));
        fclose($c);
    }
}
fclose($srv);
PHP;

$connectPhp = <<<'PHP'
<?php
// argv: 1=port 2=logPath 3=requireAuth(0/1) 4=expected Proxy-Authorization value 5=extra allowed target hosts, comma-separated ('' = loopback only)
$port = (int)$argv[1]; $log = $argv[2]; $reqAuth = ($argv[3] ?? '0') === '1'; $expAuth = (string)($argv[4] ?? '');
$allow = array_filter(array_map('strtolower', explode(',', (string)($argv[5] ?? ''))));
$okHost = static function (string $h) use ($allow): bool {
    $h = strtolower($h);
    return in_array($h, ['127.0.0.1', 'localhost'], true) || in_array($h, $allow, true);
};
$srv = stream_socket_server('tcp://127.0.0.1:' . $port, $eno, $estr);
if (!$srv) exit(2);
stream_set_blocking($srv, false);
$pipe = static function ($a, $b, int $secs): void {
    $until = microtime(true) + $secs;
    stream_set_blocking($a, false);
    stream_set_blocking($b, false);
    while (microtime(true) < $until) {
        $r = [$a, $b]; $w = null; $e = null;
        if (@stream_select($r, $w, $e, 1) !== 1) continue;
        foreach ($r as $s) {
            $d = @fread($s, 65536);
            if (!is_string($d) || $d === '') return;
            @fwrite($s === $a ? $b : $a, $d);
        }
    }
};
$until = time() + 180;
$handled = 0;
while (time() < $until && $handled < 400) {
    $r = [$srv]; $w = null; $e = null;
    if (@stream_select($r, $w, $e, 1) !== 1) continue;
    $c = @stream_socket_accept($srv, 1);
    if (!$c) continue;
    stream_set_blocking($c, true); // accepted sockets inherit non-blocking: reads would return partial data
    $handled++;
    stream_set_timeout($c, 5);
    $buf = '';
    while (strpos($buf, "\r\n\r\n") === false && strlen($buf) < 32768) {
        $ch = @fread($c, 8192);
        if (!is_string($ch) || $ch === '') break;
        $buf .= $ch;
    }
    $lines = explode("\r\n", $buf);
    $line = (string)($lines[0] ?? '');
    @file_put_contents($log, $line . "\n", FILE_APPEND);
    $auth = '';
    foreach ($lines as $hl) {
        if (stripos($hl, 'proxy-authorization:') === 0) $auth = trim(substr($hl, 20));
    }
    if ($auth !== '') @file_put_contents($log, 'AUTH:' . $auth . "\n", FILE_APPEND);
    if ($reqAuth && $auth !== $expAuth) {
        fwrite($c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        fclose($c);
        continue;
    }
    if (str_starts_with($line, 'CONNECT ')) {
        $hp = explode(' ', $line)[1] ?? '';
        $pp = explode(':', $hp);
        $pt = (int)array_pop($pp);
        $h = strtolower(implode(':', $pp));
        if (!$okHost($h)) {
            fwrite($c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            fclose($c);
            continue;
        }
        $up = @stream_socket_client('tcp://' . $h . ':' . $pt, $eno, $estr, 5);
        if (!$up) {
            fwrite($c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            fclose($c);
            continue;
        }
        fwrite($c, "HTTP/1.1 200 Connection Established\r\n\r\n");
        $pipe($c, $up, 15);
        fclose($c);
        fclose($up);
    } elseif (preg_match('#^(GET|HEAD) (https?://[^ ]+)#', $line, $m)) {
        $u = parse_url($m[2]);
        $h = strtolower((string)($u['host'] ?? ''));
        $pt = (int)($u['port'] ?? 80);
        if (!$okHost($h)) {
            fwrite($c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            fclose($c);
            continue;
        }
        $up = @stream_socket_client('tcp://' . $h . ':' . $pt, $eno, $estr, 5);
        if (!$up) {
            fwrite($c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            fclose($c);
            continue;
        }
        $path = (string)($u['path'] ?? '/') . (isset($u['query']) ? '?' . $u['query'] : '');
        $out = $m[1] . ' ' . $path . " HTTP/1.1\r\n";
        foreach (array_slice($lines, 1) as $hl) {
            if ($hl === '' || stripos($hl, 'proxy-authorization:') === 0) continue;
            if (stripos($hl, 'host:') === 0) {
                $out .= 'Host: ' . $h . ($pt === 80 ? '' : ':' . $pt) . "\r\n";
                continue;
            }
            $out .= $hl . "\r\n";
        }
        $out .= "\r\n";
        fwrite($up, $out);
        $pipe($up, $c, 15);
        fclose($c);
        fclose($up);
    } else {
        fwrite($c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        fclose($c);
    }
}
fclose($srv);
PHP;

$socksPhp = <<<'PHP'
<?php
// argv: 1=port 2=logPath 3=requireAuth(0/1) 4=user 5=pass 6=extra allowed target hosts, comma-separated ('' = loopback only)
$port = (int)$argv[1]; $log = $argv[2]; $reqAuth = ($argv[3] ?? '0') === '1';
$user = (string)($argv[4] ?? ''); $pass = (string)($argv[5] ?? '');
$allow = array_filter(array_map('strtolower', explode(',', (string)($argv[6] ?? ''))));
$srv = stream_socket_server('tcp://127.0.0.1:' . $port, $eno, $estr);
if (!$srv) exit(2);
stream_set_blocking($srv, false);
$readN = static function ($c, int $n): ?string {
    $b = '';
    stream_set_timeout($c, 5);
    while (strlen($b) < $n) {
        $ch = @fread($c, $n - strlen($b));
        if (!is_string($ch) || $ch === '') return null;
        $b .= $ch;
    }
    return $b;
};
$until = time() + 180;
$handled = 0;
while (time() < $until && $handled < 400) {
    $r = [$srv]; $w = null; $e = null;
    if (@stream_select($r, $w, $e, 1) !== 1) continue;
    $c = @stream_socket_accept($srv, 1);
    if (!$c) continue;
    stream_set_blocking($c, true); // accepted sockets inherit non-blocking: reads would return partial data
    $handled++;
    $g = $readN($c, 2);
    if ($g === null || $g[0] !== "\x05") { fclose($c); continue; }
    $methods = $readN($c, ord($g[1]));
    if ($methods === null) { fclose($c); continue; }
    if ($reqAuth) {
        if (!str_contains($methods, "\x02")) { fwrite($c, "\x05\xff"); fclose($c); continue; }
        fwrite($c, "\x05\x02");
        $ah = $readN($c, 2);
        if ($ah === null) { fclose($c); continue; }
        $au = $readN($c, ord($ah[1]));
        $pl = $readN($c, 1);
        $ap = $pl === null ? null : $readN($c, ord($pl));
        if ($au === null || $ap === null || $au !== $user || $ap !== $pass) {
            fwrite($c, "\x01\xff");
            fclose($c);
            continue;
        }
        fwrite($c, "\x01\x00");
    } else {
        fwrite($c, "\x05\x00");
    }
    $q = $readN($c, 4);
    if ($q === null || $q[1] !== "\x01") { fclose($c); continue; }
    $atyp = $q[3];
    if ($atyp === "\x01") {
        $rest = $readN($c, 6);
        if ($rest === null) { fclose($c); continue; }
        $host = implode('.', [ord($rest[0]), ord($rest[1]), ord($rest[2]), ord($rest[3])]);
        $tport = (ord($rest[4]) << 8) | ord($rest[5]);
    } elseif ($atyp === "\x03") {
        $ln = $readN($c, 1);
        if ($ln === null) { fclose($c); continue; }
        $rest = $readN($c, ord($ln) + 2);
        if ($rest === null) { fclose($c); continue; }
        $host = substr($rest, 0, ord($ln));
        $tport = (ord($rest[ord($ln)]) << 8) | ord($rest[ord($ln) + 1]);
    } else {
        fwrite($c, "\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00");
        fclose($c);
        continue;
    }
    @file_put_contents($log, 'ATYP=' . ord($atyp) . ' HOST=' . $host . ' PORT=' . $tport . "\n", FILE_APPEND);
    $h = strtolower($host);
    if (!in_array($h, ['127.0.0.1', 'localhost'], true) && !in_array($h, $allow, true)) {
        fwrite($c, "\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"); // not allowed
        fclose($c);
        continue;
    }
    $up = @stream_socket_client('tcp://' . $host . ':' . $tport, $eno, $estr, 5);
    if (!$up) {
        fwrite($c, "\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00");
        fclose($c);
        continue;
    }
    fwrite($c, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    $fin = microtime(true) + 15;
    stream_set_blocking($c, false);
    stream_set_blocking($up, false);
    while (microtime(true) < $fin) {
        $r2 = [$c, $up]; $w2 = null; $e2 = null;
        if (@stream_select($r2, $w2, $e2, 1) !== 1) continue;
        foreach ($r2 as $s) {
            $d = @fread($s, 65536);
            if (!is_string($d) || $d === '') break 2;
            @fwrite($s === $c ? $up : $c, $d);
        }
    }
    fclose($c);
    fclose($up);
}
fclose($srv);
PHP;

file_put_contents($stubDir . '/origin.php', $originPhp);
file_put_contents($stubDir . '/connect.php', $connectPhp);
file_put_contents($stubDir . '/socks5.php', $socksPhp);

// Live TLS target: PHP cannot serve TLS to itself on every build (verified
// broken on the dev box), so the tunnelled-TLS tests below run through the
// loopback stubs against the same probe tile the pool prober uses — real
// chain verification with the system CA, a few requests per suite run.
// (Hermetic loopback stubs cover everything plaintext.)
$liveTile = 'https://a.tile.openstreetmap.org/13/4051/2749.png';
$liveHost = 'a.tile.openstreetmap.org';
$planetHost = 'build.protomaps.com';
$stubAllow = $liveHost . ',' . $planetHost;

// ── spawn helper: free port scan, readiness probe, shutdown kill ────────────
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$procs = [];
$kill = static function ($proc): void {
    if (!is_resource($proc)) return;
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
};
$boot = static function (string $script, callable $argsFn, callable $ready) use ($null, &$procs, $kill, $stubDir): int {
    for ($t = 0; $t < 20; $t++) {
        $cand = 18101 + ((getmypid() + $t * 131) % 3000);
        $probe = @fsockopen('127.0.0.1', $cand, $errno, $errstr, 0.2);
        if (is_resource($probe)) {
            fclose($probe);
            continue;
        }
        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script);
        foreach ($argsFn($cand) as $a) {
            $cmd .= ' ' . escapeshellarg((string)$a);
        }
        $errLog = $stubDir . '/' . pathinfo($script, PATHINFO_FILENAME) . '_' . $cand . '.err';
        $try = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $errLog, 'w']], $pipes);
        if (!is_resource($try)) {
            continue;
        }
        $ok = false;
        for ($i = 0; $i < 25; $i++) {
            if ($ready($cand)) {
                $ok = true;
                break;
            }
            usleep(200000);
        }
        if ($ok) {
            $procs[] = $try;
            return $cand;
        }
        $kill($try);
    }
    fwrite(STDERR, "cannot spawn stub $script\n");
    exit(1);
};
register_shutdown_function(static function () use (&$procs, $kill, $stubDir): void {
    foreach ($procs as $p) {
        $kill($p);
    }
    foreach (['origin.php', 'connect.php', 'socks5.php', 'connect.log', 'socks.log'] as $f) {
        @unlink($stubDir . '/' . $f);
    }
    foreach (glob($stubDir . '/*.err') ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($stubDir);
});

$originPort = $boot($stubDir . '/origin.php', static fn(int $cand): array => [$cand, ''], static function (int $port): bool {
    // TCP up is not enough (the accept loop may lag): require the route.
    $ctx = stream_context_create(['http' => ['timeout' => 2]]);
    return @file_get_contents("http://127.0.0.1:$port/tile", false, $ctx, 0, 8) === '01234567';
});
T::ok('origin stub serves', $originPort > 0);
$originBase = "http://127.0.0.1:$originPort";

$connectLog = $stubDir . '/connect.log';
$connectPort = $boot($stubDir . '/connect.php', static fn(int $cand): array => [$cand, $connectLog, '0', '', $stubAllow], static function (int $port) use ($originPort): bool {
    $s = @fsockopen('127.0.0.1', $port, $errno, $errstr, 2);
    if (!is_resource($s)) return false;
    stream_set_timeout($s, 5);
    fwrite($s, "GET http://127.0.0.1:$originPort/tile HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    $data = stream_get_contents($s);
    fclose($s);
    return is_string($data) && str_contains($data, '01234567');
});
T::ok('CONNECT proxy stub serves', $connectPort > 0);
$connectPx = "http://127.0.0.1:$connectPort";

$socksLog = $stubDir . '/socks.log';
$socksPort = $boot($stubDir . '/socks5.php', static fn(int $cand): array => [$cand, $socksLog, '0', '', '', $stubAllow], static function (int $port) use ($originPort): bool {
    $s = @fsockopen('127.0.0.1', $port, $errno, $errstr, 2);
    if (!is_resource($s)) return false;
    stream_set_timeout($s, 5);
    fwrite($s, "\x05\x01\x00");
    $g = fread($s, 2);
    if ($g !== "\x05\x00") {
        fclose($s);
        return false;
    }
    fwrite($s, "\x05\x01\x00\x03\x09127.0.0.1" . pack('n', $originPort));
    $rep = fread($s, 10);
    fclose($s);
    return $rep === "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00";
});
T::ok('SOCKS5 stub serves', $socksPort > 0);
$socksPx = "socks5://127.0.0.1:$socksPort";

// ── direct transport ────────────────────────────────────────────────────────
$res = proxy_request_streams('GET', $originBase . '/tile', [], null, 10, 8192);
T::eq('direct GET code', 200, $res['code']);
T::eq('direct GET body', $BODY, $res['body']);
[$rb, $re] = pmtiles_http_range($originBase . '/tile', 4, 4, null, 10);
T::eq('range 206 exact bytes', ['4567', ''], [$rb, $re]);
[$fb, $fe] = pmtiles_http_range($originBase . '/full', 0, 16, null, 10);
T::eq('Range-ignoring server keeps its first bytes', [substr($BODY, 0, 16), ''], [$fb, $fe]);
[$mb, $me] = pmtiles_http_range($originBase . '/missing', 0, 10, null, 10);
T::ok('404 surfaces as an HTTP error', $mb === null && str_contains($me, '404'));
$big = proxy_request_streams('GET', $originBase . '/big', [], null, 10, 100);
T::ok('over-long body flagged with its head kept', $big['code'] === 200 && $big['truncated'] === true && strlen($big['body']) === 101);
T::ok('over-long body fails the simple fetcher', osm_fetch_via($originBase . '/big', null, 10, 100) === false);
$redir = proxy_request_streams('GET', $originBase . '/redirect', [], null, 10, 8192);
T::eq('redirect followed with redirects allowed', 200, $redir['code']);
T::eq('redirect lands on the tile', $BODY, $redir['body']);
T::ok('the curl-matching fetcher does not follow redirects', osm_fetch_via($originBase . '/redirect', null, 10) === false);
$chunk = proxy_request_streams('GET', $originBase . '/chunked', [], null, 10, 8192);
T::eq('chunked body decoded', 'Hello, chunked world!', $chunk['body']);
T::eq('HEAD answers without a body', 200, proxy_request_streams('HEAD', $originBase . '/tile', [], null, 10, 8192)['code']);
$dead = proxy_request_streams('GET', $originBase . '/tile', [], 'http://127.0.0.1:9', 5, 8192);
T::eq('dead proxy is a transport failure', 0, $dead['code']);
T::eq('garbage proxy is a transport failure', 0, proxy_request_streams('GET', $originBase . '/tile', [], 'bogus://x', 5, 8192)['code']);

// ── CONNECT proxy ───────────────────────────────────────────────────────────
$res = proxy_request_streams('GET', $originBase . '/tile', [], $connectPx, 10, 8192);
T::eq('forwarded HTTP through CONNECT proxy', $BODY, $res['body']);
// ── tunneled TLS against the live tile host (system CA verifies) ────────────
// PHP cannot serve TLS to itself on every build, so these run through the
// loopback stubs at a real HTTPS endpoint: CONNECT/SOCKS mechanics stay
// hermetic, only the TLS peer is live (same probe tile discovery uses).
$live = proxy_request_streams('GET', $liveTile, [], $connectPx, 25, 300000);
T::eq('tunneled HTTPS through CONNECT proxy verifies', 200, $live['code']);
T::ok('tunneled tile is a real PNG', osm_is_png($live['body']));
$badCa = proxy_request_streams('GET', $liveTile, [], $connectPx, 25, 300000, 3, null, $stubDir . '/connect.php');
T::eq('wrong CA fails the tunnel (verification is real)', 0, $badCa['code']);
[$rb, $re] = pmtiles_http_range($liveTile, 4, 4, $connectPx, 25);
T::eq('range through a tunnel matches the fetched bytes', [substr($live['body'], 4, 4), ''], [$rb, $re]);

// CONNECT proxy with required auth.
$authPort = $boot($stubDir . '/connect.php', static fn(int $cand): array => [$cand, $connectLog, '1', 'Basic dXNlcjpwYXNz', ''], static function (int $port): bool {
    $s = @fsockopen('127.0.0.1', $port, $errno, $errstr, 2);
    if (!is_resource($s)) return false;
    fclose($s);
    return true;
});
$authPx = "http://user:pass@127.0.0.1:$authPort";
T::eq('proxy auth accepted', $BODY, proxy_request_streams('GET', $originBase . '/tile', [], $authPx, 10, 8192)['body']);
$wrongPx = "http://user:wrong@127.0.0.1:$authPort";
T::eq('proxy auth rejected is challenged, never served', 407, proxy_request_streams('GET', $originBase . '/tile', [], $wrongPx, 10, 8192)['code']);

// ── SOCKS5 ──────────────────────────────────────────────────────────────────
$res = proxy_request_streams('GET', $originBase . '/tile', [], $socksPx, 10, 8192);
T::eq('HTTP through SOCKS5', $BODY, $res['body']);
$res = proxy_request_streams('GET', $liveTile, [], $socksPx, 25, 300000);
T::eq('HTTPS through SOCKS5 verifies', 200, $res['code']);
T::ok('SOCKS tile is a real PNG', osm_is_png($res['body']));
$res = proxy_request_streams('GET', $originBase . '/tile', [], 'socks5h://127.0.0.1:' . $socksPort, 10, 8192);
T::eq('socks5h behaves the same', $BODY, $res['body']);
$slog = (string)@file_get_contents($socksLog);
T::ok('SOCKS asked for a domain, never an IP (remote DNS)', str_contains($slog, 'ATYP=3'));
T::ok('...and never resolved locally first', !str_contains($slog, 'ATYP=1'));
[$rb, $re] = pmtiles_http_range($originBase . '/tile', 4, 4, $socksPx, 10);
T::eq('pmtiles range through SOCKS5', ['4567', ''], [$rb, $re]);
// The full production path, curl-less: real planet header through the
// loopback SOCKS stub — remote DNS, tunnel, system-CA verification,
// PMTiles framing, all at once.
[$build, $buildErr] = maps_latest_build();
if ($build !== null) {
    host_override(['curl' => false]); // the curl-less production path, not curl's own SOCKS
    [$hRaw, $hErr] = pmtiles_http_range(maps_planet_url($build), 0, PMTILES_HEADER_LEN, $socksPx, 60);
    host_override(null, true);
    $hdr = is_string($hRaw) ? pmtiles_parse_header($hRaw) : null;
    T::ok('live planet header through SOCKS5 parses' . ($hErr !== '' ? ' (err: ' . $hErr . ')' : ''), $hdr !== null);
} else {
    T::ok('live planet build known (err: ' . $buildErr . ')', false);
}
T::ok('every proxy scheme usable curl-less',
    pmtiles_proxy_usable('http://127.0.0.1:1') && pmtiles_proxy_usable('socks5://127.0.0.1:1')
    && pmtiles_proxy_usable('socks5h://127.0.0.1:1') && pmtiles_proxy_usable('socks4://127.0.0.1:1')
    && !pmtiles_proxy_usable('bogus://x'));

// SOCKS5 with required auth.
$socksAuthPort = $boot($stubDir . '/socks5.php', static fn(int $cand): array => [$cand, $socksLog, '1', 'user', 'pass', ''], static function (int $port): bool {
    $s = @fsockopen('127.0.0.1', $port, $errno, $errstr, 2);
    if (!is_resource($s)) return false;
    fclose($s);
    return true;
});
$socksAuthPx = "socks5://user:pass@127.0.0.1:$socksAuthPort";
T::eq('SOCKS auth accepted', $BODY, proxy_request_streams('GET', $originBase . '/tile', [], $socksAuthPx, 10, 8192)['body']);
$socksWrongPx = "socks5://user:wrong@127.0.0.1:$socksAuthPort";
T::eq('SOCKS auth rejected fails closed', 0, proxy_request_streams('GET', $originBase . '/tile', [], $socksWrongPx, 10, 8192)['code']);

// ── curl-less concurrent probe ──────────────────────────────────────────────
$probe = proxy_multi_probe_streams([$connectPx, 'http://127.0.0.1:9', 'bogus://x'], $originBase . '/tile', 4, 3);
T::eq('streams probe: working proxy answers 200', 200, $probe[$connectPx][0] ?? 0);
T::ok('streams probe: latency field sane', ($probe[$connectPx][1] ?? -1) >= 0);
T::eq('streams probe: dead proxy is [0,0]', [0, 0], $probe['http://127.0.0.1:9']);
T::eq('streams probe: garbage proxy is [0,0]', [0, 0], $probe['bogus://x']);
$probeTls = proxy_multi_probe_streams([$socksPx], $liveTile, 12, 5);
T::eq('streams probe reaches HTTPS through SOCKS', 200, $probeTls[$socksPx][0] ?? 0);
$both = proxy_multi_probe([$connectPx, 'http://127.0.0.1:9'], $originBase . '/tile', 4, 3);
T::eq('dispatcher covers every input', [200, 0], [$both[$connectPx][0] ?? -1, $both['http://127.0.0.1:9'][0] ?? -1]);

// ── the curl-less branch of the shared fetcher ──────────────────────────────
host_override(['curl' => false]);
T::eq('no-cURL direct fetch still works', $BODY, osm_fetch_via($originBase . '/tile', null, 10));
T::eq('no-cURL proxied fetch works', $BODY, osm_fetch_via($originBase . '/tile', $connectPx, 10));
// DEBUG ONLY (throwaway branch): the CI-only failure leaves no trace, so
// dump the structured result plus stub aliveness to stderr (unbuffered).
$dbg = proxy_request_streams('GET', $originBase . '/tile', [], $socksPx, 10, 2097152, 0);
$aliveS = @fsockopen('127.0.0.1', $socksPort, $enS, $esS, 2);
$aliveO = @fsockopen('127.0.0.1', $originPort, $enO, $esO, 2);
fwrite(STDERR, 'DBG613 code=' . $dbg['code'] . ' bytes=' . $dbg['bytes']
    . ' trunc=' . ($dbg['truncated'] ? '1' : '0') . ' bodylen=' . strlen($dbg['body'])
    . ' expSha=' . hash('sha256', $BODY) . ' dbgSha=' . hash('sha256', $dbg['body'])
    . ' socksAlive=' . (is_resource($aliveS) ? 'y' : "n($enS/$esS)")
    . ' originAlive=' . (is_resource($aliveO) ? 'y' : "n($enO/$esO)")
    . ' sockslog=' . substr(str_replace("\n", '|', (string)@file_get_contents($socksLog)), -300) . "\n");
if (is_resource($aliveS)) fclose($aliveS);
if (is_resource($aliveO)) fclose($aliveO);
$fetch613 = osm_fetch_via($originBase . '/tile', $socksPx, 10);
fwrite(STDERR, 'DBG613B fetch613=' . (is_string($fetch613) ? 'str len=' . strlen($fetch613) . ' sha=' . hash('sha256', $fetch613) : gettype($fetch613)) . ' curlNow=' . (host_has_curl() ? '1' : '0') . "\n");
T::eq('no-cURL SOCKS fetch works', $BODY, $fetch613);
T::ok('no-cURL routing stays honoured', osm_proxy_enabled() === (get_setting('osm_proxy_enabled', '1') === '1'));
host_override(null, true);

// ── curl-less download-to-disk with resume ──────────────────────────────────
$dlDir = sys_get_temp_dir() . '/ddmgmt_pxdl_' . getmypid();
mkdir($dlDir, 0700, true);
$dest = $dlDir . '/tool.bin';
[$ok, $err] = maps_fetch_file_streams($originBase . '/big', $dest, null);
T::ok('fresh streams download (' . $err . ')', $ok && hash_file('sha256', $dest) === hash('sha256', str_repeat('B', 65536)));
file_put_contents($dest, str_repeat('B', 1000)); // partial: resume must append, not restart
[$ok, $err] = maps_fetch_file_streams($originBase . '/big', $dest, null);
T::ok('resumed streams download (' . $err . ')', $ok && filesize($dest) === 65536 && hash_file('sha256', $dest) === hash('sha256', str_repeat('B', 65536)));
[$ok, $err] = maps_fetch_file_streams($originBase . '/big', $dest, $connectPx);
T::ok('streams download through a proxy', $ok && filesize($dest) === 65536);
[$ok, ] = maps_fetch_file_streams($originBase . '/missing', $dlDir . '/nope.bin', null);
T::ok('failed streams download reports false', !$ok && !is_file($dlDir . '/nope.bin'));
@unlink($dest);
@rmdir($dlDir);

// DEBUG ONLY (throwaway branch): unmask the coverage-runner's post-floor
// "Fatal error" by dumping any late uncaught throwable with its trace.
set_exception_handler(static function (Throwable $e): void {
    fwrite(STDOUT, 'DBGSHUTDOWN ' . get_class($e) . ': ' . $e->getMessage() . "\n" . $e->getTraceAsString() . "\n");
});

exit(T::done());
