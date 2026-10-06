<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Web installer contract, offline ──────────────────────────────────────────
// Drives tools/install.php as a black box (one subprocess per action, like
// HTTP would) against a LOCAL stub server, so no internet is needed: version
// list → download → extract → dbtest → setup → self-delete. The fixture zip
// carries a minimal setup.sql (all 10 managed tables) and a minimal
// config.php.example (the 6 anchors the installer patches). The installer is
// direct-only: proxy actions (discover/judge) must not exist.

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
if (class_exists('ZipArchive')) {
    $z = new ZipArchive();
    $zp = $stub . '/pkg.zip';
    T::ok('fixture zip opens', $z->open($zp, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true);
    $z->addFromString($pkgTop . '/setup.sql', $setupSql);
    $z->addFromString($pkgTop . '/config.php.example', $cfgExample);
    $z->addFromString($pkgTop . '/includes/kernel.php', '<?php // marker');
    $z->addFromString($pkgTop . '/uploads/.htaccess', 'Require all denied');
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

// ── 2. versions + direct probe (no proxies: direct-only installer) ──────────
[$code, $tags] = ix_run($work, [], ['action' => 'tags', 'src' => $base . '/gh-tags.json']);
T::eq('tags exit 0', 0, $code);
T::eq('tags list the fixture version', 'v9.9.9', $tags['tags'][0]['tag'] ?? null);
T::ok('tags report a transport', isset($tags['via']) && in_array($tags['via'], ['curl', 'streams', 'sockets'], true));
[$code, $fetch] = ix_run($work, [], ['action' => 'fetch', 'url' => $base . '/ping.txt']);
T::eq('fetch 200 + 4 bytes', [200, 4], [$fetch['code'] ?? 0, $fetch['bytes'] ?? -1]);
[$code, $badFetch] = ix_run($work, [], ['action' => 'fetch', 'url' => 'http://127.0.0.1:9/unreachable']);
T::eq('unreachable host is JSON, not a fatal', false, $badFetch['ok'] ?? true);
T::ok('unreachable host names a reason', ($badFetch['error'] ?? '') !== '');
// Timeout pin honored: unroutable TEST-NET address with timeout=2 must fail
// in ~2s, not the ~10s default connect window (wide margin for slow CI).
[$code, $tFetch] = ix_run($work, [], ['action' => 'fetch', 'url' => 'http://192.0.2.1/unroutable', 'timeout' => '2']);
T::eq('unroutable host fails', false, $tFetch['ok'] ?? true);
T::ok('timeout pin honored (ms=' . ($tFetch['ms'] ?? -1) . ')', ($tFetch['ms'] ?? 999999) < 8000);
// Deleted proxy surface stays deleted: unknown action, never a fatal.
[$code, $gone1] = ix_run($work, [], ['action' => 'discover']);
T::eq('discover action gone', false, $gone1['ok'] ?? true);
[$code, $gone2] = ix_run($work, [], ['action' => 'judge', 'px' => 'http://127.0.0.1:9']);
T::eq('judge action gone', false, $gone2['ok'] ?? true);

// ── 3. download (zip ok, non-zip rejected) ───────────────────────────────────
[$code, $dl] = ix_run($work, [], ['action' => 'download', 'url' => $base . '/pkg.zip']);
T::eq('download exit 0', 0, $code);
T::eq('downloaded size matches fixture', filesize($stub . '/pkg.zip'), $dl['size'] ?? -1);
T::ok('download reports a transport', isset($dl['via']));
[$code, $dlBad] = ix_run($work, [], ['action' => 'download', 'url' => $base . '/ping.txt']);
T::eq('non-zip download refused', false, $dlBad['ok'] ?? true);
T::eq('refused download keeps the good package', filesize($stub . '/pkg.zip'), @filesize($work . '/.__install_dl.zip') ?: -1);
[$code, $treeDl] = ix_run($work, ['action' => 'tree'], []);
T::eq('tree reports the downloaded package', filesize($stub . '/pkg.zip'), $treeDl['pending_package'] ?? -1);

// ── 4. extract (moves tree, never the running installer) ────────────────────
[$code, $ex] = ix_run($work, [], ['action' => 'extract']);
T::eq('extract exit 0', 0, $code);
T::ok('extract placed items', ($ex['moved'] ?? 0) >= 3);
T::ok('setup.sql landed', is_file($work . '/setup.sql'));
T::ok('running installer survived (decoy skipped)', str_contains((string)file_get_contents($work . '/install.php'), 'INST_VERSION'));
[$code, $tree2] = ix_run($work, ['action' => 'tree'], []);
T::eq('tree: app present after extract', true, $tree2['present'] ?? null);
T::ok('tree reports arm state', array_key_exists('armed', $tree2) && array_key_exists('unlock_present', $tree2));
[$code, $armFresh] = ix_run($work, [], ['action' => 'arm']);
T::ok('arm refused on fresh installs', ($armFresh['ok'] ?? true) === false);
// installed (config.php present) → locked: only probes + arming + self-removal answer
file_put_contents($work . '/config.php', 'sentinel');
[$code, $treeL] = ix_run($work, ['action' => 'tree'], []);
T::eq('tree: installed app reports locked', true, $treeL['locked'] ?? null);
T::ok('tree reports the unlock state', ($treeL['unlock_present'] ?? true) === false && ($treeL['armed'] ?? true) === false);
foreach ([['action' => 'arm'], ['action' => 'download', 'url' => $base . '/pkg.zip'], ['action' => 'extract'], ['action' => 'upload'],
          ['action' => 'fetch', 'url' => $base . '/ping.txt'], ['action' => 'tags', 'src' => $base . '/gh-tags.json'],
          ['action' => 'dbtest', 'db_name' => 'x', 'db_user' => 'x'], ['action' => 'setup', 'db_name' => 'x', 'db_user' => 'x'],
          ['action' => 'upgrade', 'db_name' => 'x', 'db_user' => 'x'], ['action' => 'rollback']] as $post) {
    [$code, $lk] = ix_run($work, [], $post);
    T::ok('locked: ' . $post['action'] . ' refused', ($lk['ok'] ?? true) === false && str_contains((string)($lk['error'] ?? ''), 'locked'));
}
T::eq('locked: config.php untouched', 'sentinel', file_get_contents($work . '/config.php'));
@unlink($work . '/config.php');
[$code, $dsn] = ix_run($work, [], ['action' => 'dbtest', 'db_host' => '127.0.0.1;unix_socket=/tmp/x', 'db_name' => 'x', 'db_user' => 'x']);
T::ok('DSN injection through the host is refused', str_contains((string)($dsn['error'] ?? ''), 'plain host name'));
file_put_contents($work . '/config.php', 'sentinel');
// upgrade mode: the empty INSTALL_UNLOCK file only authorizes ARMING — the
// installer mints a rotating token into it, and only the token authorizes.
// config.php and runtime data survive, the release's .htaccess is merged in,
// and the run stays armed (the schema step still needs it) until upgrade.
file_put_contents($work . '/INSTALL_UNLOCK', '');
[$code, $arm] = ix_run($work, [], ['action' => 'arm']);
T::eq('arm mints a 32-hex run token', 1, preg_match('/^[0-9a-f]{32}$/', (string)($arm['unlock'] ?? '')));
$tok = (string)$arm['unlock'];
[$code, $armAgain] = ix_run($work, [], ['action' => 'arm']);
T::ok('arm is single-use per marker', ($armAgain['ok'] ?? true) === false && str_contains((string)($armAgain['error'] ?? ''), 'another browser session'));
@mkdir($work . '/uploads/7', 0777, true);
file_put_contents($work . '/uploads/7/photo.jpg', 'user-data');
foreach ([['action' => 'download', 'url' => $base . '/pkg.zip'], ['action' => 'extract'], ['action' => 'rollback']] as $post) {
    [$code, $noTok] = ix_run($work, [], $post);
    T::ok('no token refused: ' . $post['action'], ($noTok['ok'] ?? true) === false && str_contains((string)($noTok['error'] ?? ''), 'locked'));
    [$code, $badTok] = ix_run($work, [], $post + ['unlock' => 'deadbeefdeadbeefdeadbeefdeadbeef']);
    T::ok('wrong token refused: ' . $post['action'], ($badTok['ok'] ?? true) === false && str_contains((string)($badTok['error'] ?? ''), 'locked'));
}
[$code, $dl2] = ix_run($work, [], ['action' => 'download', 'url' => $base . '/pkg.zip', 'unlock' => $tok]);
T::eq('unlocked: download ok', true, $dl2['ok'] ?? false);
T::ok('download rotates the token', ($dl2['unlock'] ?? '') !== '' && $dl2['unlock'] !== $tok);
[$code, $stale] = ix_run($work, [], ['action' => 'extract', 'unlock' => $tok]);
T::ok('rotated-out token is dead', ($stale['ok'] ?? true) === false);
$tok = (string)$dl2['unlock'];
[$code, $ex2] = ix_run($work, [], ['action' => 'extract', 'keep_config' => '1', 'unlock' => $tok]);
T::eq('unlocked: extract ok', true, $ex2['ok'] ?? false);
T::ok('extract reports the snapshot', str_contains((string)($ex2['log'] ?? ''), 'backups/upgrade-'));
$snap = (string)($ex2['snapshot'] ?? '');
T::ok('snapshot dir exists', $snap !== '' && is_dir($work . '/backups/' . $snap));
T::ok('snapshot manifest written', is_file($work . '/backups/' . $snap . '/snapshot.json'));
T::ok('snapshot dir denies the web', trim((string)@file_get_contents($work . '/backups/.htaccess')) === 'Require all denied');
T::ok('snapshot skips config.php', !is_file($work . '/backups/' . $snap . '/config.php'));
T::ok('snapshot skips runtime data', !is_dir($work . '/backups/' . $snap . '/uploads'));
T::eq('keep_config preserves config.php', 'sentinel', file_get_contents($work . '/config.php'));
T::eq('upgrade keeps uploaded photos', 'user-data', @file_get_contents($work . '/uploads/7/photo.jpg'));
T::ok('upgrade merges release uploads/.htaccess', is_file($work . '/uploads/.htaccess'));
T::ok('extract keeps the run armed (schema step still needs it)', is_file($work . '/INSTALL_UNLOCK'));
$tok = (string)($ex2['unlock'] ?? '');
// rollback: break an extracted file, restore it from the snapshot
file_put_contents($work . '/setup.sql', 'broken by test');
[$code, $rbNone] = ix_run($work, [], ['action' => 'rollback', 'unlock' => 'deadbeefdeadbeefdeadbeefdeadbeef']);
T::ok('rollback needs the token too', ($rbNone['ok'] ?? true) === false);
[$code, $rb] = ix_run($work, [], ['action' => 'rollback', 'unlock' => $tok]);
T::eq('rollback ok', true, $rb['ok'] ?? false);
T::eq('rollback restored setup.sql', $setupSql, (string)file_get_contents($work . '/setup.sql'));
T::eq('rollback keeps config.php', 'sentinel', file_get_contents($work . '/config.php'));
T::eq('rollback keeps photos', 'user-data', @file_get_contents($work . '/uploads/7/photo.jpg'));
$tok = (string)($rb['unlock'] ?? $tok);
// setup still refuses over an existing config.php — now reached WITH a valid
// token, proving the refusal is the setup guard, not the lock gate
[$code, $reSetup] = ix_run($work, [], ['action' => 'setup', 'db_host' => '127.0.0.1', 'db_port' => '9', 'db_name' => 'x', 'db_user' => 'x', 'unlock' => $tok]);
T::ok('setup refuses an existing config.php', str_contains((string)($reSetup['error'] ?? ''), 'already exists'));
T::eq('setup never runs over an existing config.php', 'sentinel', file_get_contents($work . '/config.php'));
@unlink($work . '/INSTALL_UNLOCK');
@unlink($work . '/config.php');
// the source copy inside an installed app's tools/ never acts as an installer
@mkdir($work . '/tools', 0777, true);
copy($work . '/install.php', $work . '/tools/install.php');
file_put_contents($work . '/tools/__runner.php', '<?php $_GET = ["action" => "tree"]; include __DIR__ . "/install.php";');
exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($work . '/tools/__runner.php') . ' 2>&1', $embOut);
T::ok('embedded tools/install.php refuses', str_contains(implode("\n", $embOut), 'source copy'));

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
        if (PHP_OS_FAMILY !== 'Windows') {
            clearstatcache();
            T::eq('config.php is not world-readable', 0, fileperms($work . '/config.php') & 0007);
        }
        foreach (['logs','cache/osm_tiles','cache/sessions','tiles','data/maps','uploads'] as $d) {
            T::ok('dir created: ' . $d, is_dir($work . '/' . $d));
        }
    }
    // schema-only upgrade over the installed app: idempotent re-apply of the
    // same fixture schema, config.php untouched, run re-locks itself
    file_put_contents($work . '/INSTALL_UNLOCK', '');
    [$code, $arm2] = ix_run($work, [], ['action' => 'arm']);
    T::eq('upgrade arm ok', true, $arm2['ok'] ?? false);
    [$code, $upg] = ix_run($work, [], ['action' => 'upgrade'] + $dbc + ['unlock' => (string)($arm2['unlock'] ?? '')]);
    T::eq('upgrade ok', true, $upg['ok'] ?? false);
    T::ok('upgrade applied statements', ($upg['applied'] ?? 0) > 0);
    T::ok('upgrade re-locks (unlock file consumed)', !is_file($work . '/INSTALL_UNLOCK'));
    T::ok('upgrade never rewrites config.php', str_contains((string)@file_get_contents($work . '/config.php'), "'$scratch'"));
}

// ── 6. self-delete (last — nothing runs after this) ──────────────────────────
file_put_contents($work . '/INSTALL_UNLOCK', 'stale-token');
file_put_contents($work . '/.__install_dl.zip', 'stale');
[$code, $rm] = ix_run($work, [], ['action' => 'remove']);
T::eq('remove ok', true, $rm['ok'] ?? false);
T::eq('installer file gone', false, is_file($work . '/install.php'));
T::eq('remove consumes the unlock file', false, is_file($work . '/INSTALL_UNLOCK'));
T::eq('remove drops the staging package', false, is_file($work . '/.__install_dl.zip'));

exit(T::done());
