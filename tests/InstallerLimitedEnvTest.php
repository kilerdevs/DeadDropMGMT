<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Web installer on a crippled host ─────────────────────────────────────────
// Same black-box runner as InstallerTest, but the subprocess gets a hostile
// php.ini: `php -n` (zero extensions — no curl, no openssl, no pdo_mysql, no
// zip, no mbstring) and/or locked-down directives (disabled functions,
// open_basedir, 2M uploads, dead session path, allow_url_fopen=off). Every
// action must answer JSON and exit 0 — never a white-screen fatal. The last
// case forces the ported socket engine: with no curl and streams disabled,
// an http:// fetch can only succeed via sockets.

function ixl_tmp(string $prefix): string {
    $d = sys_get_temp_dir() . '/' . $prefix . getmypid();
    @mkdir($d, 0777, true);
    return $d;
}

function ixl_run(string $work, array $get, array $post, array $flags = []): array {
    $runner = $work . '/__runner.php';
    if (!is_file($runner)) {
        file_put_contents($runner, '<?php $_GET = json_decode((string)getenv("IX_GET"), true) ?: []; $_POST = json_decode((string)getenv("IX_POST"), true) ?: []; include __DIR__ . "/install.php";');
    }
    putenv('IX_GET=' . json_encode($get));
    putenv('IX_POST=' . json_encode($post));
    $cmd = escapeshellarg(PHP_BINARY);
    foreach ($flags as $f) $cmd .= ' ' . escapeshellarg($f);
    $cmd .= ' ' . escapeshellarg($runner) . ' 2>&1';
    exec($cmd, $out, $code);
    putenv('IX_GET');
    putenv('IX_POST');
    return [$code, json_decode(implode("\n", $out), true), implode("\n", $out)];
}

$work = ixl_tmp('ix_lim_');
copy(dirname(__DIR__) . '/tools/install.php', $work . '/install.php');
$teardown = t_teardown(static function () use ($work): void {
    foreach (glob($work . '/*') ?: [] as $f) @unlink($f);
    @rmdir($work);
});
file_put_contents($work . '/tags.json', json_encode([['name' => 'v0', 'zipball_url' => 'http://127.0.0.1:9/pkg.zip']]));

// ── 1. zero extensions: capability check degrades, nothing fatals ────────────
[$code, $check] = ixl_run($work, ['action' => 'check'], [], ['-n']);
T::eq('php -n check exits 0', 0, $code);
T::ok('php -n check is valid JSON with rows', is_array($check['rows'] ?? null) && count($check['rows']) > 5);
$fails = array_filter($check['rows'], static fn(array $r): bool => $r['status'] === 'fail');
T::ok('php -n check reports blocking failures', count($fails) > 0);
$ids = array_column($check['rows'], 'id');
foreach (['php', 'ext_pdo_mysql', 'ext_mbstring', 'zip', 'tls'] as $need) {
    T::ok('php -n row present: ' . $need, in_array($need, $ids, true));
}

// ── 2. database step without pdo_mysql: guided JSON error, no fatal ──────────
[$code, $db] = ixl_run($work, [], ['action' => 'dbtest', 'db_host' => 'x', 'db_name' => 'x', 'db_user' => 'x'], ['-n']);
T::eq('php -n dbtest exits 0', 0, $code);
T::eq('php -n dbtest refuses cleanly', false, $db['ok'] ?? true);
T::ok('php -n dbtest names pdo_mysql', str_contains(strtolower((string)($db['error'] ?? '')), 'pdo'));
[$code, $st] = ixl_run($work, [], ['action' => 'setup', 'db_host' => 'x', 'db_name' => 'x', 'db_user' => 'x'], ['-n']);
T::eq('php -n setup exits 0', 0, $code);
T::eq('php -n setup refuses cleanly', false, $st['ok'] ?? true);

// ── 3. version list with zero extensions (file:// needs no transport/TLS) ────
[$code, $tags] = ixl_run($work, [], ['action' => 'tags', 'src' => 'file://' . str_replace('\\', '/', $work . '/tags.json')], ['-n']);
T::eq('php -n tags exits 0', 0, $code);
T::eq('php -n tags parse', 'v0', $tags['tags'][0]['tag'] ?? null);

// ── 4. extract without ZipArchive: guided JSON error ─────────────────────────
[$code, $ex] = ixl_run($work, [], ['action' => 'extract'], ['-n']);
T::eq('php -n extract exits 0', 0, $code);
T::eq('php -n extract refuses cleanly', false, $ex['ok'] ?? true);

// ── 5. locked-down directives, normal extensions ─────────────────────────────
$crippled = [
    '-d', 'disable_functions=proc_open,exec,shell_exec,system,passthru,popen,set_time_limit',
    '-d', 'open_basedir=' . $work . (DIRECTORY_SEPARATOR === '\\' ? ';' : ':') . '/tmp',
    '-d', 'upload_max_filesize=2M',
    '-d', 'max_execution_time=30',
    '-d', 'session.save_path=/nonexistent-ix-probe',
    '-d', 'allow_url_fopen=0',
];
[$code, $crip] = ixl_run($work, ['action' => 'check'], [], $crippled);
T::eq('crippled check exits 0', 0, $code);
T::ok('crippled check is valid JSON', is_array($crip['rows'] ?? null));
$byId = [];
foreach ($crip['rows'] ?? [] as $r) $byId[$r['id']] = $r;
T::eq('proc_open reported disabled', 'info', $byId['proc_open']['status'] ?? null);
T::ok('proc_open says disabled', str_contains(strtolower((string)(($byId['proc_open']['label'] ?? '') . ' ' . ($byId['proc_open']['detail'] ?? ''))), 'disabled'));
T::eq('tiny upload limit warns', 'warn', $byId['upload']['status'] ?? null);
T::eq('dead session path warns', 'warn', $byId['sessions']['status'] ?? null);
T::ok('max_execution_time row present', isset($byId['max_time']));

// ── 6. no curl + streams off → the socket engine still fetches http ──────────
// Needs a real local HTTP origin: reuse the stub trick (parent HAS proc_open
// even when the child is crippled).
$server = null;
$stubPort = 0;
if (function_exists('proc_open')) {
    foreach ([0, 1, 2] as $off) {
        $port = 18700 + (getmypid() % 500) + $off;
        $p = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $work],
            [0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'],
             1 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w'],
             2 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w']],
            $pipes
        );
        if (!is_resource($p)) continue;
        $up = false;
        for ($i = 0; $i < 50; $i++) {
            $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $e, $str, 0.2);
            if (is_resource($s)) {
                fclose($s);
                $up = true;
                break;
            }
            usleep(100000);
        }
        if ($up) {
            $server = $p;
            $stubPort = $port;
            break;
        }
        @proc_terminate($p);
        @proc_close($p);
    }
}
if ($server !== null) {
    $teardown2 = t_teardown(static function () use ($server, $stubPort): void {
        @proc_terminate($server);
        for ($i = 0; $i < 20; $i++) {
            $s = @stream_socket_client('tcp://127.0.0.1:' . $stubPort, $e, $str, 0.1);
            if (!is_resource($s)) break;
            fclose($s);
            usleep(100000);
        }
        @proc_close($server);
    });
    file_put_contents($work . '/ping.txt', 'pong');
    // Pinned to the socket engine: proves the ported transport with no curl
    // involved at all (deterministic even where curl is compiled static).
    $noNet = array_merge(['-n'], ['-d', 'allow_url_fopen=0']);
    [$code, $sock] = ixl_run($work, [], ['action' => 'fetch', 'url' => 'http://127.0.0.1:' . $stubPort . '/ping.txt', 'transport' => 'sockets'], $noNet);
    T::eq('sockets-only fetch exits 0', 0, $code);
    T::eq('sockets-only fetch 200 + 4 bytes', [200, 4], [$sock['code'] ?? 0, $sock['bytes'] ?? -1]);
    T::eq('transport used is the socket engine', 'sockets', $sock['via'] ?? null);
    [$code, $bogus] = ixl_run($work, [], ['action' => 'fetch', 'url' => 'http://127.0.0.1:' . $stubPort . '/ping.txt', 'transport' => 'pigeon'], $noNet);
    T::eq('bogus transport pin refused', false, $bogus['ok'] ?? true);
} else {
    T::ok('SKIP sockets-engine proof (no local stub server here)', true);
}

exit(T::done());
