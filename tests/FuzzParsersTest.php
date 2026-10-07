<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Seeded generative (fuzz/property) tests for every hand-rolled parser ───
// The app parses hostile bytes in several places (proxy URLs, HTTP framing,
// chunked bodies, XFF chains, CIDR ranges, PMTiles headers/directories,
// encrypted envelopes). Unit pins cover the happy paths; THIS file throws
// thousands of seeded-random and evil-corpus inputs at the same functions
// and asserts PROPERTIES that must hold for every input: totality (never
// throws, never warns — a ValueError/TypeError/PHP warning on attacker
// bytes is a 500 or a log gap), shape (null or a well-formed value), and
// differential agreement (two implementations of one rule agree, or
// encode/decode round-trips).
//
// Deterministic: mt_srand() with a fixed seed, no network, no wall-clock
// dependence — the same seed must pass on every PHP version and OS. Counts
// are tuned so the file stays under ~30 s on CI.

// ── Harness ────────────────────────────────────────────────────────────────
mt_srand(0xF42201);

$fzViolations = [];
$fzCases = 0;
// PHP warnings/notices (undefined offsets, chr() overflow, ord('')…) on
// attacker bytes must FAIL the run, not scroll past: convert to throws.
set_error_handler(static function (int $no, string $str): bool {
    if ((error_reporting() & $no) === 0) {
        return false; // honor @-suppression: callers handle it themselves
    }
    throw new ErrorException($str, $no);
});

/** Run $fn, recording (not aborting on) any throw. Returns [ok, result]. */
$fzTry = static function (callable $fn): array {
    try {
        return [true, $fn()];
    } catch (Throwable $e) {
        return [false, get_class($e) . ': ' . substr($e->getMessage(), 0, 120)];
    }
};

$fzBytes = static function (int $n, string $alphabet = ''): string {
    if ($alphabet === '') {
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= chr(mt_rand(0, 255));
        }
        return $s;
    }
    $s = '';
    $m = strlen($alphabet) - 1;
    for ($i = 0; $i < $n; $i++) {
        $s .= $alphabet[mt_rand(0, $m)];
    }
    return $s;
};

$fzPick = static function (array $xs): mixed {
    return $xs[mt_rand(0, count($xs) - 1)];
};

// Random small edit: flip, insert, delete, truncate, splice.
$fzMutate = static function (string $s) use ($fzBytes): string {
    if ($s === '') {
        return $fzBytes(mt_rand(1, 8));
    }
    switch (mt_rand(0, 4)) {
        case 0:
            $s[mt_rand(0, strlen($s) - 1)] = chr(mt_rand(0, 255));
            return $s;
        case 1:
            $p = mt_rand(0, strlen($s));
            return substr($s, 0, $p) . $fzBytes(mt_rand(1, 4)) . substr($s, $p);
        case 2:
            $p = mt_rand(0, strlen($s) - 1);
            return substr($s, 0, $p) . substr($s, $p + mt_rand(1, min(4, strlen($s) - $p)));
        case 3:
            return substr($s, 0, mt_rand(0, strlen($s)));
        default:
            return $s . "\r\n" . $fzBytes(mt_rand(1, 6));
    }
};

$EVIL = ['', "\0", "\0\0\0", ' ', '  ', "\t", "\r", "\n", "\r\n", "\r\n\r\n",
    str_repeat('A', 5000), str_repeat("\xff", 100), '..', '../..', '..\\..\\',
    'http://a@b@c/', 'http://[::1', 'http://x:/', '://missing', 'http://',
    'HTTP://UPPER/', 'HtTp://MiXeD/', 'ftp://x/', 'gopher://x/', 'file:///etc/passwd',
    'javascript:alert(1)', 'data:text/plain,x', '//protocol-relative', '/root', 'relative',
    'not-an-ip', '1.2.3.4.5', '999.1.1.1', '1.2.3', '', '0x7f.1', '0177.1', '-1', '+1',
    '99999999999999999999999', '0x10', '1e2', ' ', ':::', ':::::', '1::2::3',
    '::ffff:1.2.3.4', '::FFFF:1.2.3.4', 'fe80::1%eth0', '[::1]', '[::1]:80',
    "\xc3\xa9xample.com", '１２３', 'a b', "a\0b", '%00', '%2e%2e', '%41',
    ':', '::', '/', '@', '#', '?', 'a:b:c', 'user:pass@', '@host', 'host:',
    "a\r\nInjected: x", "a\nb", '99999', '-80', '0', '65535', '65536',
    '10.0.0.0/abc', '10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/', '/24', '::1/129',
];
// Closures below cannot see file-scope locals: publish every helper.
$GLOBALS['fzTry'] = $fzTry;
$GLOBALS['fzBytes'] = $fzBytes;
$GLOBALS['fzPick'] = $fzPick;
$GLOBALS['fzMutate'] = $fzMutate;
$GLOBALS['EVIL'] = $EVIL;

/** Aggregate one property: every case must hold; report the first inputs. */
$fzAssert = static function (string $name, array $bad) use (&$fzCases): void {
    $fzCases++;
    T::eq($name . ' (' . count($bad) . ' violations)', [], array_slice($bad, 0, 3));
};

// ── 1. Proxy URL parsers ───────────────────────────────────────────────────
{
    $bad = [];
    $schemes = ['http', 'https', 'HTTP', 'HTTPS', 'Http', 'ftp', 'gopher', '', 'http:'];
    $hosts = ['example.com', 'a', 'a-b.cd', '192.168.1.1', '10.0.0.1', '::1', '[::1]',
        '2001:db8::1', 'evil.com@good.com', 'user:pass@h.com', '', ' ', 'a b',
        str_repeat('h', 300), '-bad-', '_under_', 'éxample.com', "\0bad", '..',
        '127.1', '0x7f.1', 'localhost', '%41', 'a/b', 'h:'];
    for ($i = 0; $i < 500; $i++) {
        $url = $GLOBALS['fzPick']($schemes) . '://'
            . ($i % 5 === 0 ? 'u:p@' : '')
            . $GLOBALS['fzPick']($hosts)
            . ($i % 3 === 0 ? ':' . $GLOBALS['fzPick'](['', '80', '0', '65535', '65536', '-1', 'abc', '808080']) : '')
            . ($i % 4 === 0 ? '/' . $GLOBALS['fzBytes'](mt_rand(0, 12), 'ab/?.%') : '');
        if ($i % 7 === 0) {
            $url = $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => proxy_parse_target($url));
        if (!$ok) {
            $bad[] = 'throw on ' . substr($url, 0, 60);
            continue;
        }
        if ($r === null) {
            continue;
        }
        // proxy_parse_target answers tls-bool, not a scheme string.
        if (!is_bool($r['tls'] ?? null)
            || ($r['host'] ?? '') === '' || strlen($r['host']) > 253 || str_contains($r['host'], ' ')
            || ($r['port'] ?? 0) < 1 || ($r['port'] ?? 0) > 65535
            || !str_starts_with($r['path'] ?? 'x', '/')
            || (($r['dial'] ?? '')[0] === '[') !== (filter_var($r['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false)
        ) {
            $bad[] = 'ill-shaped for ' . substr($url, 0, 60);
        }
    }
    $fzAssert('proxy target: total + well-shaped', $bad);
}
{
    $bad = [];
    for ($i = 0; $i < 300; $i++) {
        $px = $GLOBALS['fzPick'](['http://', 'https://', 'socks5://', 'socks5h://', 'socks4://', 'HTTP://', '']);
        $px .= $GLOBALS['fzBytes'](mt_rand(0, 40), 'ab09.:[]/%@_+-');
        if ($i % 5 === 0) {
            $px = $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => proxy_parse($px));
        if (!$ok) {
            $bad[] = 'throw on ' . substr($px, 0, 60);
            continue;
        }
        if ($r === null) {
            continue;
        }
        if (($r['host'] ?? '') === '' || ($r['port'] ?? 0) < 1 || ($r['port'] ?? 0) > 65535
            || strlen($r['user'] ?? '') > 255 || strlen($r['pass'] ?? '') > 255
        ) {
            $bad[] = 'ill-shaped for ' . substr($px, 0, 60);
        }
    }
    $fzAssert('proxy entry: total + well-shaped', $bad);
}

// ── 2. HTTP framing ────────────────────────────────────────────────────────
{
    $bad = [];
    $pins = ['HTTP/1.1 200 OK' => 200, 'HTTP/1.0 404 Not Found' => 404, 'HTTP/2 500 x' => 500,
        'garbage' => 0, '' => 0, 'HTTP/1.1 99 x' => 0, 'HTTP/1.1 600 x' => 600, "HTTP/1.1 200\r\nevil" => 200];
    foreach ($pins as $head => $want) {
        if (proxy_status_code($head) !== $want) {
            $bad[] = "pin $head";
        }
    }
    for ($i = 0; $i < 400; $i++) {
        $line = $GLOBALS['fzPick'](['HTTP/1.1', 'HTTP/1.0', 'HTTP/2', 'HTP/9', '', 'http/1.1'])
            . ' ' . $GLOBALS['fzBytes'](mt_rand(0, 10), '0123456789abcdefx /')
            . ($i % 3 === 0 ? ' ' . $GLOBALS['fzBytes'](mt_rand(0, 12)) : '');
        [$ok, $code] = $GLOBALS['fzTry'](static fn() => proxy_status_code($line));
        if (!$ok || !is_int($code) || ($code !== 0 && ($code < 0 || $code > 999))) {
            $bad[] = 'status: ' . substr($line, 0, 40);
        }
    }
    $fzAssert('status code: total + 0-or-3-digit', $bad);
}
{
    $bad = [];
    for ($i = 0; $i < 400; $i++) {
        $head = $GLOBALS['fzBytes'](mt_rand(0, 120), "abAB09:; \t/.-_");
        if ($i % 2 === 0) {
            $head .= "\r\n\r\n" . $GLOBALS['fzBytes'](mt_rand(0, 30));
        }
        if ($i % 9 === 0) {
            $head = $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => proxy_head_split($head));
        if (!$ok) {
            $bad[] = 'throw';
            continue;
        }
        $has = str_contains($head, "\r\n\r\n");
        if (($r === null) === $has) {
            $bad[] = 'split/disagree';
            continue;
        }
        if (is_array($r) && ($r[0] . "\r\n\r\n" . $r[1]) !== $head) {
            $bad[] = 'rejoin';
        }
    }
    $fzAssert('head split: null-iff-separator + rejoin', $bad);
}
{
    $bad = [];
    for ($i = 0; $i < 300; $i++) {
        $lines = ['HTTP/1.1 200 OK'];
        for ($j = 0, $n = mt_rand(0, 6); $j < $n; $j++) {
            $nm = $GLOBALS['fzBytes'](mt_rand(0, 14), "abAB09:; \t/.-_");
            $lines[] = $nm . ':' . $GLOBALS['fzBytes'](mt_rand(0, 20));
        }
        if ($i % 4 === 0) {
            $lines[] = 'Content-Length: 5';
            $lines[] = 'content-length: 99';
        }
        $head = implode("\r\n", $lines);
        [$ok, $f] = $GLOBALS['fzTry'](static fn() => proxy_head_fields($head));
        if (!$ok || !is_array($f)) {
            $bad[] = 'throw';
            continue;
        }
        foreach ($f as $k => $v) {
            // PHP casts numeric-string keys to int — a header literally
            // named "123" arrives as int(123). Normalize before judging.
            $k = (string)$k;
            if ($k === '' || $k !== strtolower($k) || $v !== trim($v)) {
                $bad[] = 'field shape';
                break;
            }
        }
        if (in_array('content-length: 99', $lines, true) && ($f['content-length'] ?? null) !== '5') {
            $bad[] = 'first-wins';
        }
    }
    $fzAssert('head fields: lowered + first-wins + trimmed', $bad);
}
{
    $bad = [];
    $bases = ['http://a/b/c', 'https://h:8443/x', 'http://h', 'garbage', '', 'ftp://h/x'];
    for ($i = 0; $i < 300; $i++) {
        $loc = $GLOBALS['fzBytes'](mt_rand(0, 40), 'ab09.:/%?#@_-');
        if ($i % 4 === 0) {
            $loc = $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => proxy_resolve_url($GLOBALS['fzPick']($bases), $loc));
        if (!$ok) {
            $bad[] = 'throw';
            continue;
        }
        if ($r !== null && preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $r) !== 1) {
            $bad[] = "relative out: $r";
        }
    }
    $fzAssert('resolve url: null-or-absolute + total', $bad);
}

// ── 3. Chunked decoder: feed/push differential ─────────────────────────────
{
    $bad = [];
    $mkValid = static function () : string {
        $fzBytes = $GLOBALS['fzBytes'];
        $fzPick = $GLOBALS['fzPick'];
        $s = '';
        for ($k = 0, $n = mt_rand(1, 6); $k < $n; $k++) {
            $len = $fzPick([0, 1, 2, 5, 17, 127, 1000, 8192]);
            if ($len === 0) {
                break;
            }
            $hex = dechex($len);
            if (mt_rand(0, 1)) {
                $hex = strtoupper($hex);
            }
            $s .= $hex . (mt_rand(0, 3) === 0 ? ';ext=' . mt_rand(0, 9) : '') . "\r\n";
            $s .= $fzBytes($len) . "\r\n";
        }
        return $s . "0\r\n\r\n";
    };
    for ($i = 0; $i < 250; $i++) {
        $stream = $mkValid();
        // Random re-segmentation into 1-4 pushes.
        $pieces = [$stream];
        for ($c = mt_rand(0, 3); $c > 0; $c--) {
            $p = mt_rand(0, count($pieces) - 1);
            $s = $pieces[$p];
            if (strlen($s) < 2) {
                break;
            }
            $at = mt_rand(1, strlen($s) - 1);
            array_splice($pieces, $p, 1, [substr($s, 0, $at), substr($s, $at)]);
        }
        [$okF, $f] = $GLOBALS['fzTry'](static fn() => proxy_chunked_feed($stream));
        $st = proxy_chunked_state();
        $outP = '';
        $doneP = false;
        $okP = true;
        foreach ($pieces as $pc) {
            $r = proxy_chunked_push($st, $pc);
            if ($r === null) {
                $okP = false;
                break;
            }
            $outP .= $r[0];
            $doneP = $r[1];
        }
        if (!$okF || $f === null || !$okP) {
            $bad[] = 'valid stream rejected';
            continue;
        }
        if ($f[0] !== $outP || $f[2] !== $doneP) {
            $bad[] = 'feed/push disagree';
        }
    }
    // Mutations: both must agree (both null, or equal bytes + done).
    for ($i = 0; $i < 250; $i++) {
        $stream = $GLOBALS['fzMutate']($mkValid());
        [$okF, $f] = $GLOBALS['fzTry'](static fn() => proxy_chunked_feed($stream));
        $st = proxy_chunked_state();
        [$okP2, $p] = $GLOBALS['fzTry'](static fn() => proxy_chunked_push($st, $stream));
        if (!$okF || !$okP2) {
            $bad[] = 'throw on mutated stream';
            continue;
        }
        if (($f === null) !== ($p === null)) {
            $bad[] = 'null-disagree';
            continue;
        }
        // On truncated (not corrupt) input the two legitimately differ:
        // push streams partial payload bytes as they arrive while feed
        // only emits complete chunks — so byte-equality holds only once
        // both agree the stream is DONE.
        if ($f !== null && $f[2] && $p[1] && ($f[0] !== $p[0])) {
            $bad[] = 'output-disagree';
        }
        if ($f !== null && $f[2] !== $p[1]) {
            $bad[] = 'done-disagree';
        }
    }
    // Bounds pins: >8 hex digits and >8 MiB refuse.
    T::eq('chunked: 9-digit size refuses', null, proxy_chunked_feed("123456789\r\n"));
    T::eq('chunked: oversize chunk refuses', null, proxy_chunked_feed("8000001\r\n"));
    $fzAssert('chunked: feed/push differential', $bad);
}

// ── 4. XFF walk: differential vs a 10-line reference ───────────────────────
{
    $bad = [];
    $refWalk = static function (array $hops, string $peer, array $trust): string {
        $chain = [...$hops, $peer];
        $in = static function (string $ip) use ($trust): bool {
            foreach ($trust as $cidr) {
                if (_ip_in_cidr($ip, $cidr)) {
                    return true;
                }
            }
            return false;
        };
        while (count($chain) > 1 && $in(end($chain))) {
            array_pop($chain);
        }
        $ip = trim((string)end($chain));
        return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : $peer;
    };
    $ipPool = ['203.0.113.7', '70.41.3.18', '1.2.3.4', '10.0.0.9', '192.168.0.5',
        '127.0.0.1', '::1', '2001:db8::7', 'not-an-ip', '', ' 203.0.113.7 ', '999.1.1.1',
        '::ffff:10.0.0.9', '8.8.8.8'];
    $trustPool = [[], ['127.0.0.0/8'], ['10.0.0.0/8', '192.168.0.0/16'], ['0.0.0.0/0'],
        ['203.0.113.7'], ['70.41.3.18', '1.2.3.4'], ['::1/128'], ['2001:db8::/32']];
    $saveServer = $_SERVER;
    putenv('DDMGMT_TRUST_PROXY=1');
    for ($i = 0; $i < 300; $i++) {
        $n = mt_rand(1, 5);
        $hops = [];
        for ($k = 0; $k < $n; $k++) {
            $hops[] = $GLOBALS['fzPick']($ipPool);
        }
        $peer = $GLOBALS['fzPick']($ipPool);
        $trust = $GLOBALS['fzPick']($trustPool);
        if (!filter_var($peer, FILTER_VALIDATE_IP)) {
            $peer = '127.0.0.1';
        }
        $_SERVER['REMOTE_ADDR'] = $peer;
        $_SERVER['HTTP_X_FORWARDED_FOR'] = implode(',', $hops);
        putenv('DDMGMT_TRUSTED_PROXIES=' . implode(',', $trust));
        [$ok, $got] = $GLOBALS['fzTry'](static fn() => get_client_ip());
        // Reference trusts bare IPs the same way the app does — including
        // the empty-config rule (unset/empty DDMGMT_TRUSTED_PROXIES means
        // loopback + RFC1918, not "trust nothing").
        $trustNorm = $trust === []
            ? ['127.0.0.0/8', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
            : [];
        foreach ($trust as $c) {
            if ($trust !== [] && _cidr_valid($c)) {
                $trustNorm[] = $c;
            }
        }
        $want = $refWalk(array_map('trim', $hops), $peer, $trustNorm);
        if (!$ok || $got !== $want) {
            $bad[] = "got $got want $want for [" . implode(',', $hops) . "] peer $peer";
        }
        // Hard property: a trusted proxy address is never returned while any
        // chain entry is untrusted.
        if ($ok && $got !== $peer) {
            $allTrusted = true;
            foreach (array_map('trim', $hops) as $h) {
                $t = false;
                foreach ($trustNorm as $c) {
                    if (_ip_in_cidr($h, $c)) {
                        $t = true;
                        break;
                    }
                }
                if (!$t) {
                    $allTrusted = false;
                    break;
                }
            }
            if (!$allTrusted) {
                foreach ($trustNorm as $c) {
                    if (_ip_in_cidr((string)$got, $c)) {
                        $bad[] = "trusted $got returned with untrusted chain";
                        break;
                    }
                }
            }
        }
    }
    $_SERVER = $saveServer;
    putenv('DDMGMT_TRUST_PROXY');
    putenv('DDMGMT_TRUSTED_PROXIES');
    $fzAssert('xff walk: reference differential + no-trusted-leak', $bad);
}

// ── 5. CIDR: differential vs an independent bit-compare ────────────────────
{
    $bad = [];
    $refIn = static function (string $ip, string $cidr): bool {
        // Same normalization POLICY as the app (documented in net.php):
        // mapped ::ffff:a.b.c.d counts as the v4 host itself — never as a
        // v6 address. The differential checks the bit-compare, not the
        // policy, so the reference applies the policy identically.
        if (str_starts_with(strtolower($ip), '::ffff:') && str_contains($ip, '.')) {
            $ip = substr($ip, 7);
        }
        if (!str_contains($cidr, '/')) {
            $a = @inet_pton($ip);
            $b = @inet_pton($cidr);
            return is_string($a) && is_string($b) && $a === $b;
        }
        [$net, $bits] = explode('/', $cidr, 2);
        $a = @inet_pton($ip);
        $b = @inet_pton($net);
        if (!is_string($a) || !is_string($b) || !ctype_digit($bits)) {
            return false;
        }
        $bi = (int)$bits;
        if ($bi < 0 || $bi > strlen($b) * 8 || strlen($a) !== strlen($b)) {
            return false;
        }
        for ($i = 0; $i < $bi; $i++) {
            $ba = (ord($a[intdiv($i, 8)]) >> (7 - ($i % 8))) & 1;
            $bb = (ord($b[intdiv($i, 8)]) >> (7 - ($i % 8))) & 1;
            if ($ba !== $bb) {
                return false;
            }
        }
        return true;
    };
    $randIp = static function () use ($fzBytes): string {
        switch (mt_rand(0, 4)) {
            case 0:
                return mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255);
            case 1:
                $p = [];
                for ($i = 0; $i < 8; $i++) {
                    $p[] = dechex(mt_rand(0, 65535));
                }
                return implode(':', $p);
            case 2:
                return '::ffff:' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255);
            case 3:
                return $GLOBALS['fzBytes'](mt_rand(0, 20), '0123456789abcdef:.');
            default:
                return $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
    };
    $randCidr = static function () use ($randIp): string {
        $r = mt_rand(0, 5);
        if ($r === 0) {
            return $randIp();
        }
        if ($r === 1) {
            return $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        $v6 = mt_rand(0, 1) === 1;
        $base = $v6 ? '2001:db8::' . dechex(mt_rand(0, 65535)) : mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.0.0';
        return $base . '/' . $GLOBALS['fzPick'](['0', '8', '16', '24', '25', '31', '32', '33', '64', '128', '129', '-1', 'abc', '']);
    };
    for ($i = 0; $i < 600; $i++) {
        $ip = $randIp();
        $cidr = $randCidr();
        [$okV, $v] = $GLOBALS['fzTry'](static fn() => _cidr_valid($cidr));
        [$okM, $m] = $GLOBALS['fzTry'](static fn() => _ip_in_cidr($ip, $cidr));
        if (!$okV || !$okM) {
            $bad[] = 'throw';
            continue;
        }
        // _cidr_valid must agree with "parses as IP[/bits]" (reference:
        // inet_pton + digit bits in family range).
        $refV = false;
        if (!str_contains($cidr, '/')) {
            $refV = @inet_pton($cidr) !== false;
        } else {
            [$nn, $bb] = explode('/', $cidr, 2);
            $pp = @inet_pton($nn);
            $refV = is_string($pp) && ctype_digit($bb) && (int)$bb >= 0 && (int)$bb <= strlen($pp) * 8;
        }
        if ((bool)$v !== $refV) {
            $bad[] = "valid-disagree: $cidr";
            continue;
        }
        if ((bool)$m !== $refIn($ip, $cidr)) {
            $bad[] = "match-disagree: $ip in $cidr";
        }
    }
    $fzAssert('cidr: valid+match differentials', $bad);
}

// ── 6. PMTiles primitives ──────────────────────────────────────────────────
{
    $bad = [];
    $vals = [0, 1, 127, 128, 255, 256, 16383, 16384, 2097151, 4294967295, 9007199254740991, PHP_INT_MAX];
    for ($i = 0; $i < 200; $i++) {
        $vals[] = mt_rand(0, PHP_INT_MAX);
    }
    foreach ($vals as $v) {
        $enc = pmtiles_vint_encode($v);
        $pos = 0;
        $dec = pmtiles_vint_decode($enc, $pos);
        if ($dec !== $v || $pos !== strlen($enc)) {
            $bad[] = "vint round-trip $v";
        }
    }
    for ($i = 0; $i < 300; $i++) {
        $b = $GLOBALS['fzBytes'](mt_rand(0, 12));
        $pos = mt_rand(0, 3);
        $pos0 = $pos;
        [$ok, $d] = $GLOBALS['fzTry'](static function () use ($b, &$pos) {
            return pmtiles_vint_decode($b, $pos);
        });
        if (!$ok || ($d !== null && ($d < 0 || $pos < $pos0 || $pos > strlen($b)))) {
            $bad[] = 'vint garbage';
        }
    }
    $fzAssert('vint: round-trip + garbage-total', $bad);
}
{
    $bad = [];
    for ($i = 0; $i < 300; $i++) {
        $b = $GLOBALS['fzBytes'](mt_rand(124, 130));
        if ($i % 2 === 0 && strlen($b) >= 8) {
            $b = substr(PMTILES_MAGIC, 0, 7) . chr(PMTILES_VERSION) . substr($b, 8);
        }
        if (strlen($b) > PMTILES_HEADER_LEN) {
            $b = substr($b, 0, PMTILES_HEADER_LEN);
        }
        while (strlen($b) < PMTILES_HEADER_LEN) {
            $b .= "\0";
        }
        [$ok, $h] = $GLOBALS['fzTry'](static fn() => pmtiles_parse_header($b));
        if (!$ok) {
            $bad[] = 'throw';
            continue;
        }
        if ($h === null) {
            continue;
        }
        $keys = ['rootOff', 'rootLen', 'metaOff', 'metaLen', 'leafOff', 'leafLen', 'tileOff', 'tileLen',
            'nAddr', 'nEntries', 'nContents', 'clustered', 'intComp', 'tileComp', 'tileType',
            'minZoom', 'maxZoom', 'minLon', 'minLat', 'maxLon', 'maxLat', 'centerZoom', 'centerLon', 'centerLat'];
        foreach ($keys as $k) {
            // u64 fields are 64-bit PATTERNS read into signed ints: values
            // with the top bit set come back negative, which is exactly
            // representable — the property is "int, never float" (no
            // precision loss on 64-bit offsets), not "non-negative".
            if (!array_key_exists($k, $h)) {
                $bad[] = "header key $k";
                break;
            }
            $floatKeys = ['minLon', 'minLat', 'maxLon', 'maxLat', 'centerLon', 'centerLat'];
            if (in_array($k, $floatKeys, true)) {
                if (!is_float($h[$k])) {
                    $bad[] = "header key $k";
                    break;
                }
            } elseif (!is_int($h[$k])) {
                $bad[] = "header key $k";
                break;
            }
        }
    }
    // Wrong lengths refuse (127 exact).
    foreach ([0, 1, 126, 128, 200] as $len) {
        if (pmtiles_parse_header($GLOBALS['fzBytes']($len)) !== null) {
            $bad[] = "length $len accepted";
        }
    }
    $fzAssert('header: total + shaped-or-null', $bad);
}
{
    $bad = [];
    // Handcrafted valid 1-entry directory round-trips.
    $raw = pmtiles_vint_encode(1) . pmtiles_vint_encode(5) . pmtiles_vint_encode(1)
        . pmtiles_vint_encode(10) . pmtiles_vint_encode(1);
    $dirs = pmtiles_parse_dir($raw, PMTILES_COMP_NONE);
    T::eq('dir: handcrafted entry decodes', [['id' => 5, 'run' => 1, 'len' => 10, 'off' => 0]], $dirs);
    T::eq('dir: empty decodes', [], pmtiles_parse_dir(pmtiles_vint_encode(0), PMTILES_COMP_NONE));
    for ($i = 0; $i < 300; $i++) {
        $raw = $GLOBALS['fzBytes'](mt_rand(0, 400));
        $comp = $GLOBALS['fzPick']([PMTILES_COMP_NONE, PMTILES_COMP_GZIP, 1, 2, 99, -1]);
        if ($i % 5 === 0) {
            $raw = (string)gzencode($GLOBALS['fzBytes'](mt_rand(0, 200)));
            $comp = PMTILES_COMP_GZIP;
        }
        [$ok, $d] = $GLOBALS['fzTry'](static fn() => pmtiles_parse_dir($raw, $comp));
        if (!$ok) {
            $bad[] = 'throw';
            continue;
        }
        if ($d === null) {
            continue;
        }
        foreach ($d as $e) {
            if (!is_array($e) || array_keys($e) !== ['id', 'run', 'len', 'off']) {
                $bad[] = 'entry shape';
                break;
            }
        }
    }
    $fzAssert('dir: total + shaped-or-null', $bad);
}

// ── 7. Encrypted envelopes ─────────────────────────────────────────────────
{
    $bad = [];
    foreach (['', 'x', "\0", str_repeat('A', 10000), 'hallöchen 👻', random_bytes(500)] as $pt) {
        $enc = encrypt_secret($pt);
        if (decrypt_secret($enc['ciphertext'], $enc['iv']) !== $pt) {
            $bad[] = 'round-trip';
        }
    }
    for ($i = 0; $i < 250; $i++) {
        $ct = $GLOBALS['fzBytes'](mt_rand(0, 200), 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=');
        $iv = $GLOBALS['fzBytes']($GLOBALS['fzPick']([0, 12, 23, 24, 25, 48]), '0123456789abcdefXYZ');
        if ($i % 6 === 0) {
            $ct = $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        if ($i % 11 === 0) {
            $iv = $GLOBALS['fzPick']($GLOBALS['EVIL']);
        }
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => decrypt_secret($ct, $iv));
        if (!$ok || ($r !== false && !is_string($r))) {
            $bad[] = 'open not-false';
        }
    }
    // Bit-flipped real ciphertexts must fail closed, never throw.
    $enc = encrypt_secret('flip me');
    $rawCt = (string)base64_decode($enc['ciphertext']);
    for ($i = 0; $i < 50; $i++) {
        $p = mt_rand(0, strlen($rawCt) - 1);
        $rawCt[$p] = chr(ord($rawCt[$p]) ^ (1 << mt_rand(0, 7)));
        $r = decrypt_secret(base64_encode($rawCt), $enc['iv']);
        if ($r !== false) {
            $bad[] = 'flipped verifies?!';
        }
        $rawCt[$p] = chr(ord($rawCt[$p]) ^ (1 << mt_rand(0, 7)));
    }
    $fzAssert('envelope open: round-trip + fail-closed', $bad);
}
{
    // Photo envelope files: JSON-decoded values are MIXED, so the parser
    // must reject non-strings with false — never a TypeError 500.
    $bad = [];
    $tmp = sys_get_temp_dir() . '/ddmgmt-fuzz-' . getmypid();
    @mkdir($tmp, 0700, true);
    $valid = encrypt_photo('photo-bytes');
    file_put_contents($tmp . '/ok.json', (string)json_encode(['v' => 1, 'ct' => $valid['ciphertext'], 'iv' => $valid['iv']]));
    $cases = [
        'ok' => true,
        'ct-array' => ['ct' => [], 'iv' => $valid['iv']],
        'ct-null' => ['ct' => null, 'iv' => $valid['iv']],
        'ct-int' => ['ct' => 7, 'iv' => $valid['iv']],
        'iv-array' => ['ct' => $valid['ciphertext'], 'iv' => []],
        'iv-short' => ['ct' => $valid['ciphertext'], 'iv' => 'abcd'],
        'iv-nonhex' => ['ct' => $valid['ciphertext'], 'iv' => str_repeat('z', 24)],
        'missing-ct' => ['iv' => $valid['iv']],
        'missing-iv' => ['ct' => $valid['ciphertext']],
        'top-array' => [1, 2],
        'top-string' => 'x',
    ];
    foreach ($cases as $name => $meta) {
        if ($name !== 'ok') {
            file_put_contents($tmp . '/' . $name . '.json', (string)json_encode($meta));
        }
        $f = $tmp . '/' . $name . '.json';
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => photo_decrypt_to_temp($f, $tmp . '/' . $name . '.out'));
        $want = $name === 'ok';
        if (!$ok || $r !== $want) {
            $bad[] = "$name: " . ($ok ? var_export($r, true) : $r);
        }
        @unlink($tmp . '/' . $name . '.out');
    }
    foreach (['not json{{{', '', "\0\1\2"] as $k => $raw) {
        file_put_contents($tmp . '/raw' . $k . '.json', $raw);
        [$ok, $r] = $GLOBALS['fzTry'](static fn() => photo_decrypt_to_temp($tmp . '/raw' . $k . '.json', $tmp . '/o.out'));
        if (!$ok || $r !== false) {
            $bad[] = 'raw garbage';
        }
    }
    foreach (glob($tmp . '/*') ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($tmp);
    $fzAssert('photo envelope: mixed-meta total + fail-closed', $bad);
}

// ── 8. Tokens, passphrases, SOCKS builders, basic-auth ─────────────────────
{
    $bad = [];
    $seen = [];
    for ($i = 0; $i < 200; $i++) {
        $t = generate_order_token();
        if (!preg_match('/^[A-Za-z0-9]{16}$/', $t)) {
            $bad[] = 'token shape';
        }
        $seen[$t] = true;
    }
    if (count($seen) !== 200) {
        $bad[] = 'token dup?!';
    }
    for ($i = 0; $i < 100; $i++) {
        $p = generate_passphrase();
        if (strlen($p) < 12 || preg_match('/\d/', $p) !== 1) {
            $bad[] = 'passphrase shape';
        }
    }
    $fzAssert('tokens: charset + length (+passphrase shape)', $bad);
}
{
    $bad = [];
    for ($i = 0; $i < 200; $i++) {
        $host = $i % 5 === 0 ? $GLOBALS['fzPick']($GLOBALS['EVIL']) : $GLOBALS['fzBytes'](mt_rand(0, 300), 'ab09.:-');
        $user = $GLOBALS['fzBytes'](mt_rand(0, 300));
        $pass = $GLOBALS['fzBytes'](mt_rand(0, 300));
        foreach ([
            static fn() => proxy_socks5_greet($user),
            static fn() => proxy_socks5_auth($user, $pass),
            static fn() => proxy_socks5_connect($host, mt_rand(0, 70000)),
            static fn() => proxy_socks4_connect($host, mt_rand(0, 70000), $user),
        ] as $fn) {
            [$ok] = $GLOBALS['fzTry']($fn);
            if (!$ok) {
                $bad[] = 'socks builder throw';
            }
        }
        [$ok, $h] = $GLOBALS['fzTry'](static fn() => proxy_basic_auth($user, $pass));
        if (!$ok || base64_decode(substr($h, 6), true) !== $user . ':' . $pass) {
            $bad[] = 'basic-auth round-trip';
        }
    }
    $fzAssert('socks/auth builders: total + basic-auth round-trip', $bad);
}

restore_error_handler();
exit(T::done());
