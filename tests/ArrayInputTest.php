<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Array-shaped input must never crash a page ────────────────────────────────
// `?order_token[]=x` (or a POST field sent as name[]=x) arrives in PHP as an
// array. Code that hands it to a string function throws a TypeError — with
// display_errors off the visitor gets a truncated page and the log gets a
// php_error. This once hit index.php (htmlspecialchars() on the re-rendered
// token field). The fields are read through post_string()/get_string() now; this
// suite is the guard that keeps every entry point that way: for every parameter
// name the code reads, every page is sent that name as an array — GET and POST,
// as a logged-in owner (the superset of what any visitor can reach) — and the
// server's answer and logs must stay clean.

$root = dirname(__DIR__);

// Parameter names the code reads, and the entry scripts to send them to.
$names = [];
$scan = array_merge(
    glob($root . '/*.php') ?: [],
    glob($root . '/admin/*.php') ?: [],
    glob($root . '/admin/actions/*.php') ?: []
);
foreach ($scan as $p) {
    $src = (string)file_get_contents($p);
    preg_match_all('/\$_(?:GET|POST|REQUEST|COOKIE)\[\'([A-Za-z0-9_]+)\'\]/', $src, $m1);
    preg_match_all('/(?:post_string|get_string)\(\s*\'([A-Za-z0-9_]+)\'/', $src, $m2);
    preg_match_all('/filter_input\(\s*INPUT_\w+,\s*\'([A-Za-z0-9_]+)\'/', $src, $m3);
    foreach ([$m1[1], $m2[1], $m3[1]] as $list) {
        foreach ($list as $n) { $names[$n] = true; }
    }
}
$names = array_keys($names);
sort($names);

// Not entry points (partials, data, dispatcher targets) or not worth a request:
// logout ends the session this suite rides on, panic wipes data (PanicTest owns it).
$skip = ['sidebar.php', 'totp_banner.php', 'osm_monit.php', 'routes.php', 'bootstrap.php', 'logout.php', 'panic.php', 'healthz.php'];
$endpoints = [];
foreach (array_merge(glob($root . '/*.php') ?: [], glob($root . '/admin/*.php') ?: []) as $p) {
    if (in_array(basename($p), $skip, true) || str_starts_with(basename($p), '.')) { continue; }
    $endpoints[] = substr($p, strlen($root));
}
sort($endpoints);
T::ok('parameter names were discovered from the source', count($names) > 30);
T::ok('entry points were discovered', count($endpoints) > 25);

$probe = stream_socket_server('tcp://127.0.0.1:0');
$port = (int)explode(':', (string)stream_socket_get_name($probe, false))[1];
fclose($probe);
$cmd = escapeshellarg(PHP_BINARY)
    . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
    . " -S 127.0.0.1:$port -t " . escapeshellarg($root);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
// Array-shaped POSTs to the login form count as failed attempts for the IP
// limiter: give the suite a big budget and leave no limiter rows behind, or a
// second run (and every later suite's login) would be locked out.
$prevMax = get_setting('rate_limit_max', '10');
set_setting('rate_limit_max', '1000');
$teardown = t_teardown(function () use ($proc, $prevMax): void {
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        if (DIRECTORY_SEPARATOR === '\\') {
            exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
        } else {
            proc_terminate($proc);
        }
    }
    proc_close($proc);
    get_db()->prepare("DELETE FROM users WHERE username = 't_ai_owner'")->execute();
    get_db()->exec('DELETE FROM rate_limits');
    set_setting('rate_limit_max', $prevMax);
});
$B = "http://127.0.0.1:$port";

function _ai(string $method, string $url, ?array $f, string $ck): array {
    $opts = ['http' => [
        'method' => $method, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 20,
        'header' => ($f !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '')
                  . ($ck !== '' ? "Cookie: $ck\r\n" : ''),
    ]];
    if ($f !== null) { $opts['http']['content'] = http_build_query($f); }
    $body = @file_get_contents($url, false, stream_context_create($opts));
    $status = 0; $sc = '';
    $headers = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
    foreach ($headers as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
        if (stripos($h, 'Set-Cookie:') === 0) {
            $c = trim(explode(';', trim(substr($h, 11)))[0]);
            if ($c !== '' && str_contains($c, '=')) { $sc = $c; }
        }
    }
    return [$status, $body === false ? '' : $body, $sc ?: $ck];
}

$up = false;
for ($i = 0; $i < 50; $i++) {
    [$st] = _ai('GET', "$B/healthz.php", null, '');
    if ($st === 200) { $up = true; break; }
    usleep(200000);
}
T::ok('server booted', $up);
if (!$up) { $teardown(); exit(T::done()); }

$db = get_db();
$db->exec('DELETE FROM rate_limits');
$db->prepare("DELETE FROM users WHERE username = 't_ai_owner'")->execute();
$db->prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
   ->execute(['t_ai_owner', password_hash('AiPass123!', PASSWORD_BCRYPT), 'owner']);
[, $b, $ck] = _ai('GET', "$B/admin/index.php", null, '');
preg_match('/name="csrf_token"\s*value="([0-9a-f]{64})"/', $b, $m);
[$st, , $ck] = _ai('POST', "$B/admin/login.php", ['csrf_token' => $m[1] ?? '', 'username' => 't_ai_owner', 'password' => 'AiPass123!'], $ck);
T::eq('owner logged in', 302, $st);
[$st, $b, $ck] = _ai('GET', "$B/admin/settings.php", null, $ck);
T::ok('the session really reaches the admin pages (the sweep below is not bouncing off the login form)', $st === 200 && str_contains($b, 'settings-panel'));

$freshCsrf = static function () use ($B, &$ck): string {
    [, $body, $ck] = _ai('GET', "$B/admin/csrf_token.php", null, $ck);
    $j = json_decode($body, true);
    return is_array($j) ? (string)($j['csrf'] ?? '') : '';
};
$logPaths = [APP_LOG_PATH, ERROR_LOG_PATH];
$offsets = static function () use ($logPaths): array {
    clearstatcache();
    $o = [];
    foreach ($logPaths as $l) { $o[$l] = is_file($l) ? (int)filesize($l) : 0; }
    return $o;
};
$bad = [];
$sent = 0;
foreach ($endpoints as $ep) {
    foreach ($names as $name) {
        foreach (['GET', 'POST'] as $method) {
            $before = $offsets();
            $fields = [$name . '[]' => 'x'];
            $url = $B . $ep;
            if ($method === 'GET') {
                $url .= '?' . http_build_query($fields);
                $fields = null;
            } else {
                $fields['csrf_token'] = $freshCsrf();
            }
            [$code, $body, $ck] = _ai($method, $url, $fields, $ck);
            $sent++;
            $why = '';
            if ($code >= 500) { $why = "HTTP $code"; }
            elseif (preg_match('/Uncaught|TypeError|Array to string|Fatal error/', $body) === 1) { $why = 'error text in the page'; }
            else {
                foreach ($logPaths as $l) {
                    clearstatcache();
                    $size = is_file($l) ? (int)filesize($l) : 0;
                    if ($size > $before[$l]) {
                        $fh = fopen($l, 'rb');
                        if ($fh !== false) {
                            fseek($fh, $before[$l]);
                            $new = (string)stream_get_contents($fh);
                            fclose($fh);
                            if (preg_match('/Uncaught|TypeError|Array to string|"php_error"/', $new) === 1) { $why = 'logged: ' . substr(trim($new), 0, 160); }
                        }
                    }
                }
            }
            if ($why !== '') { $bad["$method $ep {$name}[]"] = $why; }
        }
    }
}
T::ok("sent $sent array-shaped requests", $sent > 2000);
T::eq('no page crashes, renders an error, or logs a TypeError on array-shaped input', [], array_slice($bad, 0, 10, true));

$teardown();
exit(T::done());
