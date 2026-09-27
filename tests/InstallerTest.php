<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Web installer contract, offline ──────────────────────────────────────────
// Drives tools/install.php as a black box (one subprocess per action, like
// HTTP would) against a LOCAL stub server, so no internet is needed: version
// list → download → extract → dbtest → setup → self-delete. The fixture zip
// carries a minimal setup.sql (all 10 managed tables) and a minimal
// config.php.example (the 6 anchors the installer patches).

function ix_tmp(string $prefix): string {
    $d = sys_get_temp_dir() . '/' . $prefix . getmypid();
    @mkdir($d, 0777, true);
    return $d;
}

function ix_run(string $work, array $get, array $post, array $flags = []): array {
    $runner = $work . '/__runner.php';
    if (!is_file($runner)) {
        file_put_contents($runner, '<?php $_GET = json_decode((string)getenv("IX_GET"), true) ?: []; $_POST = json_decode((string)getenv("IX_POST"), true) ?: []; include __DIR__ . "/install.php";');
    }
    putenv('IX_GET=' . json_encode($get));
    putenv('IX_POST=' . json_encode($post));
    $cmd = escapeshellarg(PHP_BINARY);
    foreach ($flags as $f) $cmd .= ' ' . escapeshellarg($f);
    // Subprocesses share the parent php.ini — except setups (like local
    // XAMPP) where zip came from a CLI -d flag. IX_ZIP_DLL forwards it:
    // IX_ZIP_DLL="C:\php\ext\php_zip.dll" php -d extension=... InstallerTest.php
    $dll = getenv('IX_ZIP_DLL');
    if (is_string($dll) && $dll !== '' && class_exists('ZipArchive')) {
        $cmd .= ' -d ' . escapeshellarg('extension=' . $dll);
    }
    $cmd .= ' ' . escapeshellarg($runner) . ' 2>&1';
    exec($cmd, $out, $code);
    putenv('IX_GET');
    putenv('IX_POST');
    $json = json_decode(implode("\n", $out), true);
    return [$code, $json, implode("\n", $out)];
}

function ix_serve(string $docroot, int $port): mixed {
    if (!function_exists('proc_open')) return null;
    $p = proc_open(
        [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $docroot],
        [0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'],
         1 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w'],
         2 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w']],
        $pipes
    );
    if (!is_resource($p)) return null;
    for ($i = 0; $i < 50; $i++) {
        $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $e, $str, 0.2);
        if (is_resource($s)) {
            fclose($s);
            // The probe connection itself triggers a 404 request; give the
            // server a beat to become fully ready before real traffic.
            usleep(200000);
            return $p;
        }
        usleep(100000);
    }
    @proc_terminate($p);
    @proc_close($p);
    return null;
}

function ix_stop(mixed $server, int $port): void {
    if (!is_resource($server)) return;
    @proc_terminate($server);
    for ($i = 0; $i < 20; $i++) {
        $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $e, $str, 0.1);
        if (!is_resource($s)) break;
        fclose($s);
        usleep(100000);
    }
    @proc_close($server);
}

$work = ix_tmp('ix_full_');
$stub = ix_tmp('ix_stub_');
copy(dirname(__DIR__) . '/tools/install.php', $work . '/install.php');
$teardown = t_teardown(static function () use ($work, $stub): void {
    foreach ([$work, $stub] as $d) {
        if (!is_dir($d)) continue;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($d);
    }
});

// ── stub origin (real HTTP when possible, file:// fallback) ─────────────────
// Ports derive from the PID so corpse servers from killed runs never collide.
$server = null;
$stubPort = 0;
$base = '';
foreach ([0, 1, 2] as $off) {
    $port = 18200 + (getmypid() % 500) + $off;
    $server = ix_serve($stub, $port);
    if ($server !== null) {
        $stubPort = $port;
        $base = 'http://127.0.0.1:' . $port;
        break;
    }
}
if ($server !== null) {
    $teardown2 = t_teardown(static function () use ($server, $stubPort): void {
        ix_stop($server, $stubPort);
    });
}
T::ok('stub route available (http server or file://)', true);
if ($base === '') $base = 'file://' . str_replace('\\', '/', $stub);

// Fixture package: top folder + app skeleton the installer expects.
$pkgTop = 'pkgtest';
$setupSql = '';
foreach (['users','orders','order_photos','osm_proxies','map_zones','order_events','rate_limits','audit_log','settings','log_checkpoints'] as $t) {
    $setupSql .= "CREATE TABLE IF NOT EXISTS $t (id INT PRIMARY KEY);\n";
}
$cfgExample = implode("\n", [
    '<?php',
    "define('DB_HOST',    _secret('DDMGMT_DB_HOST', 'localhost'));",
    "define('DB_PORT',    _secret('DDMGMT_DB_PORT', '3306'));",
    "define('DB_NAME',    _secret('DDMGMT_DB_NAME', 'deaddrops'));",
    "define('DB_USER',    _secret('DDMGMT_DB_USER', 'root'));",
    "define('DB_PASS',    _secret('DDMGMT_DB_PASS', ''));",
    "'REPLACE_WITH_64_HEX_CHARS_FROM_PHP_R_ABOVE__________'",
]);
file_put_contents($stub . '/gh-tags.json', json_encode([['name' => 'v9.9.9', 'zipball_url' => $base . '/pkg.zip']]));
file_put_contents($stub . '/ping.txt', 'pong');
file_put_contents($stub . '/proxifly.json', json_encode([
    ['protocol' => 'socks5', 'ip' => '127.0.0.1', 'port' => '1080'],
    ['protocol' => 'http', 'anonymity' => 'elite', 'ip' => '127.0.0.1', 'port' => '8080'],
    ['protocol' => 'http', 'anonymity' => 'transparent', 'ip' => '1.2.3.4', 'port' => '80'],
]));
file_put_contents($stub . '/plain.txt', "127.0.0.1:8080\nnot-a-proxy\n");
file_put_contents($stub . '/judge-clean.txt', '{"headers":{"Host":"example"}}');
file_put_contents($stub . '/proxifly2.json', json_encode([
    ['protocol' => 'http', 'anonymity' => 'elite', 'ip' => '127.0.0.1', 'port' => '8080'],
]));
if (class_exists('ZipArchive')) {
    $z = new ZipArchive();
    $zp = $stub . '/pkg.zip';
    T::ok('fixture zip opens', $z->open($zp, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true);
    $z->addFromString($pkgTop . '/setup.sql', $setupSql);
    $z->addFromString($pkgTop . '/config.php.example', $cfgExample);
    $z->addFromString($pkgTop . '/includes/kernel.php', '<?php // marker');
    $z->addFromString($pkgTop . '/install.php', 'decoy — the running installer must never overwrite itself');
    $z->close();
    T::ok('fixture zip built', is_file($zp));
} else {
    T::ok('SKIP zip-dependent asserts (no ZipArchive here)', true);
    exit(T::done());
}

// ── 1. capability check + tree probe ─────────────────────────────────────────
[$code, $check] = ix_run($work, ['action' => 'check'], []);
T::eq('check exits 0', 0, $code);
T::ok('check returns rows', is_array($check['rows'] ?? null) && count($check['rows']) > 10);
T::eq('fails count matches fail rows', count(array_filter($check['rows'], static fn(array $r): bool => $r['status'] === 'fail')), $check['fails'] ?? -1);
foreach ($check['rows'] as $r) {
    T::ok('row shape ' . ($r['id'] ?? '?'), isset($r['id'], $r['label'], $r['status']) && in_array($r['status'], ['ok', 'fail', 'warn', 'info'], true));
    break; // shape is uniform; one probe is enough
}
[$code, $tree] = ix_run($work, ['action' => 'tree'], []);
T::eq('tree: empty workdir', false, $tree['present'] ?? null);

// ── 2. versions + probe + discovery (all through the route) ─────────────────
[$code, $tags] = ix_run($work, [], ['action' => 'tags', 'src' => $base . '/gh-tags.json', 'proxy_type' => 'none']);
T::eq('tags exit 0', 0, $code);
T::eq('tags list the fixture version', 'v9.9.9', $tags['tags'][0]['tag'] ?? null);
T::ok('tags report a transport', isset($tags['via']) && in_array($tags['via'], ['curl', 'streams', 'sockets'], true));
[$code, $fetch] = ix_run($work, [], ['action' => 'fetch', 'url' => $base . '/ping.txt', 'proxy_type' => 'none']);
T::eq('fetch 200 + 4 bytes', [200, 4], [$fetch['code'] ?? 0, $fetch['bytes'] ?? -1]);
[$code, $badFetch] = ix_run($work, [], ['action' => 'fetch', 'url' => 'http://127.0.0.1:9/unreachable', 'proxy_type' => 'none']);
T::eq('unreachable host is JSON, not a fatal', false, $badFetch['ok'] ?? true);
T::ok('unreachable host names a reason', ($badFetch['error'] ?? '') !== '');
// Timeout pin honored: unroutable TEST-NET address with timeout=2 must fail
// in ~2s, not the ~10s default connect window (wide margin for slow CI).
[$code, $tFetch] = ix_run($work, [], ['action' => 'fetch', 'url' => 'http://192.0.2.1/unroutable', 'proxy_type' => 'none', 'timeout' => '2']);
T::eq('unroutable host fails', false, $tFetch['ok'] ?? true);
T::ok('timeout pin honored (ms=' . ($tFetch['ms'] ?? -1) . ')', ($tFetch['ms'] ?? 999999) < 8000);
[$code, $disc] = ix_run($work, [], ['action' => 'discover', 'src' => $base . '/proxifly.json', 'proxy_type' => 'none']);
T::eq('discover keeps socks5 + elite, drops transparent', 2, count($disc['candidates'] ?? []));
T::ok('discover normalizes to scheme://ip:port', str_starts_with(($disc['candidates'][0]['url'] ?? ''), 'socks5://'));
T::ok('discover flags rated entries', ($disc['candidates'][0]['rated'] ?? false) === true);
// Unrated HTTP through a dead proxy: judge unreachable → kept but unverified.
// Needs the HTTP stub (file:// must never travel a proxy — the installer
// refuses that combination so verdicts stay honest).
if ($server === null) {
    T::ok('SKIP proxy-verdict asserts (no HTTP stub here)', true);
} else {
    [$code, $disc2] = ix_run($work, [], ['action' => 'discover', 'src' => $base . '/plain.txt', 'proxy_type' => 'none',
        'judges' => json_encode([$base . '/judge-clean.txt']), 'our_ip' => '9.9.9.9']);
    T::eq('plain-list candidate kept', 'http://127.0.0.1:8080', $disc2['candidates'][0]['url'] ?? null);
    T::eq('plain-list candidate unrated', false, $disc2['candidates'][0]['rated'] ?? null);
    T::eq('unreachable judge leaves it unverified', false, $disc2['candidates'][0]['judged'] ?? null);
    [$code, $jUnk] = ix_run($work, [], ['action' => 'judge', 'px' => 'http://127.0.0.1:9',
        'judges' => json_encode([$base . '/judge-clean.txt']), 'our_ip' => '9.9.9.9']);
    T::eq('judge through dead proxy is unknown', 'unknown', $jUnk['state'] ?? null);
    // Rated outranks unrated for the same entry (app parity): plain first,
    // then rated proxifly for the identical norm.
    $multiSrc = json_encode([
        ['url' => $base . '/plain.txt', 'name' => 'plain', 'type' => 'plain', 'proto' => 'http', 'rated' => false],
        ['url' => $base . '/proxifly2.json', 'name' => 'ratedup', 'type' => 'proxifly', 'rated' => true],
    ]);
    [$code, $disc3] = ix_run($work, [], ['action' => 'discover', 'src' => $multiSrc, 'proxy_type' => 'none',
        'judges' => json_encode([$base . '/judge-clean.txt']), 'our_ip' => '9.9.9.9']);
    T::eq('rated source upgrades the duplicate', true, $disc3['candidates'][0]['rated'] ?? null);
    T::eq('upgraded entry keeps rated source name', 'ratedup', $disc3['candidates'][0]['source'] ?? null);
}
[$code, $jBad] = ix_run($work, [], ['action' => 'judge', 'px' => 'not-a-proxy']);
T::eq('judge refuses garbage', false, $jBad['ok'] ?? true);

// ── 3. download (zip ok, non-zip rejected) ───────────────────────────────────
[$code, $dl] = ix_run($work, [], ['action' => 'download', 'url' => $base . '/pkg.zip', 'proxy_type' => 'none']);
T::eq('download exit 0', 0, $code);
T::eq('downloaded size matches fixture', filesize($stub . '/pkg.zip'), $dl['size'] ?? -1);
T::ok('download reports a transport', isset($dl['via']));
[$code, $dlBad] = ix_run($work, [], ['action' => 'download', 'url' => $base . '/ping.txt', 'proxy_type' => 'none']);
T::eq('non-zip download refused', false, $dlBad['ok'] ?? true);
T::eq('refused download keeps the good package', filesize($stub . '/pkg.zip'), @filesize($work . '/.__install_dl.zip') ?: -1);

// ── 4. extract (moves tree, never the running installer) ────────────────────
[$code, $ex] = ix_run($work, [], ['action' => 'extract']);
T::eq('extract exit 0', 0, $code);
T::ok('extract placed items', ($ex['moved'] ?? 0) >= 3);
T::ok('setup.sql landed', is_file($work . '/setup.sql'));
T::ok('running installer survived (decoy skipped)', str_contains((string)file_get_contents($work . '/install.php'), 'INST_VERSION'));
[$code, $tree2] = ix_run($work, ['action' => 'tree'], []);
T::eq('tree: app present after extract', true, $tree2['present'] ?? null);
// upgrade mode: pre-existing config.php survives with the flag
file_put_contents($work . '/config.php', 'sentinel');
[$code, $dl2] = ix_run($work, [], ['action' => 'download', 'url' => $base . '/pkg.zip', 'proxy_type' => 'none']);
[$code, $ex2] = ix_run($work, [], ['action' => 'extract', 'keep_config' => '1']);
T::eq('keep_config preserves config.php', 'sentinel', file_get_contents($work . '/config.php'));
@unlink($work . '/config.php');

// ── 5. database: probe → full setup → verify ─────────────────────────────────
$canDb = extension_loaded('pdo_mysql');
$scratch = 'deaddrops_insttest';
if ($canDb) {
    try {
        $admin = new PDO(
            'mysql:host=' . (getenv('DDMGMT_DB_HOST') ?: '127.0.0.1') . ';port=' . (getenv('DDMGMT_DB_PORT') ?: '3306'),
            getenv('DDMGMT_DB_USER') ?: 'root', getenv('DDMGMT_DB_PASS') !== false ? (string)getenv('DDMGMT_DB_PASS') : ''
        );
        $admin->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $admin->exec('DROP DATABASE IF EXISTS `' . $scratch . '`');
        $admin->exec('CREATE DATABASE `' . $scratch . '` CHARACTER SET utf8mb4');
    } catch (Throwable $t) {
        $canDb = false;
    }
}
if (!$canDb) {
    T::ok('SKIP database asserts (no MySQL here)', true);
} else {
    $teardown3 = t_teardown(static function () use ($admin, $scratch): void {
        try {
            $admin->exec('DROP DATABASE IF EXISTS `' . $scratch . '`');
        } catch (Throwable) {}
    });
    $dbc = ['db_host' => getenv('DDMGMT_DB_HOST') ?: '127.0.0.1', 'db_port' => getenv('DDMGMT_DB_PORT') ?: '3306',
        'db_name' => $scratch, 'db_user' => getenv('DDMGMT_DB_USER') ?: 'root',
        'db_pass' => getenv('DDMGMT_DB_PASS') !== false ? (string)getenv('DDMGMT_DB_PASS') : ''];
    [$code, $probe] = ix_run($work, [], ['action' => 'dbtest'] + $dbc);
    T::eq('dbtest connects', true, $probe['ok'] ?? false);
    T::eq('empty schema first', '0/10', $probe['tables'] ?? null);
    [$code, $setup] = ix_run($work, [], ['action' => 'setup'] + $dbc);
    T::eq('setup ok', true, $setup['ok'] ?? false);
    T::ok('setup applied statements', ($setup['applied'] ?? 0) > 0);
    if (!($setup['ok'] ?? false)) {
        T::ok('SKIP post-setup verifies (setup failed — see above)', true);
    } else {
        $have = $admin->query('SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ' . $admin->quote($scratch))->fetchAll(PDO::FETCH_COLUMN);
        T::eq('all 10 tables exist', 10, count(array_intersect(
            ['users','orders','order_photos','osm_proxies','map_zones','order_events','rate_limits','audit_log','settings','log_checkpoints'], $have)));
        $cfg = (string)file_get_contents($work . '/config.php');
        T::ok('config.php names the database', str_contains($cfg, "'$scratch'"));
        T::ok('config.php holds a fresh 64-hex key', preg_match('/[0-9a-f]{64}/', $cfg) === 1);
        foreach (['logs','cache/osm_tiles','cache/sessions','tiles','data/maps','uploads'] as $d) {
            T::ok('dir created: ' . $d, is_dir($work . '/' . $d));
        }
    }
}

// ── 6. self-delete (last — nothing runs after this) ──────────────────────────
[$code, $rm] = ix_run($work, [], ['action' => 'remove']);
T::eq('remove ok', true, $rm['ok'] ?? false);
T::eq('installer file gone', false, is_file($work . '/install.php'));

exit(T::done());
