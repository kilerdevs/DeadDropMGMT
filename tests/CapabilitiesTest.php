<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/includes/capabilities.php';
require_once dirname(__DIR__) . '/includes/setup_check.php';

// ── Capability registry: contract + hostile-host parity ─────────────────────
// includes/capabilities.php is the single source of truth; the standalone
// installer (tools/install.php) mirrors it as ix_cap_* because it can never
// load the kernel, and the setup check + hosting doctor evaluate it live.
// This suite pins three things:
//   1. registry shape: stable ids, valid flags, fallback keys that resolve;
//   2. evaluator + grants-parser logic on injected hostile environments;
//   3. behavioral parity: the installer's check step answers the registry's
//      answers under hostile php.ini combos (black-box, via subprocess).

// ── 1. registry shape ───────────────────────────────────────────────────────
$defs = capability_definitions();
$ids = array_column($defs, 'id');
T::eq('registry carries every hostile-host capability', [
    'php', 'pdo_mysql', 'mbstring', 'zlib', 'openssl', 'curl', 'tls',
    'zip', 'exec', 'proc_open', 'jobs', 'env', 'db_create',
    'set_time_limit', 'dirs', 'sessions', 'htaccess',
], $ids);
foreach ($defs as $d) {
    T::ok("definition complete: {$d['id']}",
        isset($d['label'], $d['probe'], $d['fallback'])
        && is_bool($d['required']) && in_array($d['soft'], ['warn', 'info'], true));
    T::ok("fallback key resolves: {$d['fallback']}",
        t($d['fallback'], ['v' => '8.2.0', 'bin' => '/usr/bin/unzip', 'dirs' => 'logs/']) !== $d['fallback']);
}
// Registry snapshot: ids, labels, probes, fallbacks and required flags are
// pinned — a flipped required flag or renamed fallback would silently move
// a hostile-host gate. Regenerate on intentional registry changes:
//   php -r "require 'tests/bootstrap.php'; echo hash('sha256', json_encode(capability_definitions(), JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)), PHP_EOL;"
T::eq('registry matches the snapshot',
    'fe960aacb6c1716814257c031c836656c9833a054d64c76239dfc58fe9bf2cd0',
    hash('sha256', (string)json_encode($defs, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)));
// statuses the consumers render are a closed set
foreach (capabilities_evaluate([]) as $r) {
    T::ok("empty env evaluates safely: {$r['id']}", in_array($r['state'], ['ok', 'limited', 'missing'], true));
    T::ok("consumer word closed: {$r['id']}",
        in_array(capabilities_consumer_status($r), ['ok', 'fail', 'warn', 'info'], true));
}

// ── 2. evaluator on injected environments ───────────────────────────────────
$okEnv = [
    'php_version' => '8.2.0',
    'ext' => ['pdo_mysql' => true, 'mbstring' => true, 'zlib' => true, 'openssl' => true],
    'curl' => true, 'sockets' => true, 'zip_ext' => true, 'unzip_bin' => null,
    'exec' => true, 'proc_open' => true, 'detach' => true, 'putenv_ok' => true,
    'grants' => "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'",
    'set_time_limit' => true, 'dirs' => ['logs/' => true],
    'session_path' => '/tmp', 'session_writable' => true,
    'server_sw' => 'Apache/2.4', 'htaccess_ok' => true,
];
foreach (capabilities_evaluate($okEnv) as $r) {
    T::eq("healthy host: {$r['id']} ok", 'ok', $r['state']);
}
// The panel-hostile fixture: no curl, no exec, no zip, no detach, no env
// control, a forced user_xxx account, set_time_limit disabled.
$hostile = [
    'php_version' => '8.3.1',
    'ext' => ['pdo_mysql' => true, 'mbstring' => true, 'zlib' => false, 'openssl' => false],
    'curl' => false, 'sockets' => true, 'zip_ext' => false, 'unzip_bin' => null,
    'exec' => false, 'proc_open' => false, 'detach' => false, 'putenv_ok' => false,
    'grants' => "GRANT SELECT, INSERT, UPDATE, DELETE ON `user_xxx`.* TO 'user_xxx'@'%'",
    'set_time_limit' => false, 'dirs' => ['logs/' => true, 'uploads/' => false],
    'session_path' => '/nonexistent', 'session_writable' => false,
    'server_sw' => 'nginx/1.24.0', 'htaccess_ok' => false,
];
$st = [];
foreach (capabilities_evaluate($hostile) as $r) {
    $st[$r['id']] = [$r['state'], capabilities_consumer_status($r)];
}
T::eq('hostile: php still ok', ['ok', 'ok'], $st['php']);
T::eq('hostile: zlib limited (warn)', ['limited', 'warn'], $st['zlib']);
T::eq('hostile: openssl limited (warn, no curl to cover)', ['limited', 'warn'], $st['openssl']);
T::eq('hostile: curl limited (info)', ['limited', 'info'], $st['curl']);
T::eq('hostile: tls missing→fail (no insecure fallback exists)', ['missing', 'fail'], $st['tls']);
T::eq('hostile: zip missing→fail (no ext, no binary)', ['missing', 'fail'], $st['zip']);
T::eq('hostile: exec limited (info)', ['limited', 'info'], $st['exec']);
T::eq('hostile: proc_open limited (info)', ['limited', 'info'], $st['proc_open']);
T::eq('hostile: jobs limited (warn)', ['limited', 'warn'], $st['jobs']);
T::eq('hostile: env limited (info)', ['limited', 'info'], $st['env']);
T::eq('hostile: db_create limited (info, never blocking)', ['limited', 'info'], $st['db_create']);
T::eq('hostile: set_time_limit limited (warn)', ['limited', 'warn'], $st['set_time_limit']);
T::eq('hostile: dirs missing→fail, naming uploads/', ['missing', 'fail'], $st['dirs']);
// Apache without htaccess proof is limited, not ok (a weakened check would
// bless rewrites that were never verified).
$noHtaccess = capabilities_evaluate(['server_sw' => 'Apache/2.4', 'htaccess_ok' => false]);
foreach ($noHtaccess as $r) {
    if ($r['id'] === 'htaccess') {
        T::eq('apache without htaccess proof is limited', 'limited', $r['state']);
    }
}
// openssl with cURL present is purely informational
$withCurl = capabilities_evaluate(['curl' => true, 'ext' => ['openssl' => false]]);
foreach ($withCurl as $r) {
    if ($r['id'] === 'openssl') {
        T::eq('openssl missing but curl present is info', 'info', capabilities_consumer_status($r));
    }
    if ($r['id'] === 'tls') {
        T::eq('curl alone carries TLS', 'ok', $r['state']);
    }
}
// zip triple: extension, binary fallback (naming it), nothing
$zipBin = capability_row('zip', ['zip_ext' => false, 'unzip_bin' => '/usr/bin/unzip']);
T::eq('zip via binary is limited', 'limited', $zipBin['state'] ?? null);
T::eq('zip via binary names the binary', '/usr/bin/unzip', $zipBin['note'] ?? null);
T::eq('unknown capability id answers null', null, capability_row('nope', []));
// Runtime label suffixes: versions named, the unzip binary named only while
// it carries the load (a flipped state check would credit it while the
// extension serves, or hide it while it does).
T::eq('zip-ok names no binary', 'ZipArchive / unzip', setup_runtime_label('zip', ['id' => 'zip', 'label' => 'ZipArchive / unzip', 'state' => 'ok', 'note' => ''])[0]);
T::eq('zip-limited names the binary', ['ZipArchive / unzip via unzip binary', ['bin' => '/usr/bin/unzip']],
    setup_runtime_label('zip', ['id' => 'zip', 'label' => 'ZipArchive / unzip', 'state' => 'limited', 'note' => '/usr/bin/unzip']));
T::eq('php names its version', ['PHP ' . PHP_VERSION, ['v' => PHP_VERSION]],
    setup_runtime_label('php', ['id' => 'php', 'label' => 'PHP', 'state' => 'ok', 'note' => '']));

// ── SHOW GRANTS parser: conservative by design ──────────────────────────────
T::ok('root ALL PRIVILEGES can create', capabilities_grants_allow_create("GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"));
T::ok('global CREATE can create',
    capabilities_grants_allow_create("GRANT SELECT, INSERT, CREATE ON *.* TO 'panel'@'%'"));
T::ok('scoped grant without CREATE cannot', !capabilities_grants_allow_create(
    "GRANT SELECT, INSERT, UPDATE, DELETE ON `user_xxx`.* TO 'user_xxx'@'%'"));
T::ok('CREATE VIEW inside one schema is not CREATE DATABASE', !capabilities_grants_allow_create(
    "GRANT SELECT, CREATE VIEW ON `user_xxx`.* TO 'user_xxx'@'%'"));
T::ok('unavailable grants read as restricted', !capabilities_grants_allow_create(null));
T::ok('empty grants read as restricted', !capabilities_grants_allow_create(''));
T::ok('non-grant lines are ignored', !capabilities_grants_allow_create("-- comment\nSELECT 1"));

// ── 3. installer parity (black-box, hostile php.ini combos) ─────────────────
// The probe child reports the environment the installer child will see (same
// flags, same binary); the registry evaluates that env in-process; the
// installer's check step must answer the same statuses on every probed row.
// Probed ids (installer row id => registry id).
$probed = ['php' => 'php', 'ext_pdo_mysql' => 'pdo_mysql', 'ext_mbstring' => 'mbstring',
    'ext_zlib' => 'zlib', 'ext_openssl' => 'openssl', 'ext_curl' => 'curl',
    'tls' => 'tls', 'zip' => 'zip', 'exec' => 'exec', 'proc_open' => 'proc_open',
    'set_time_limit' => 'set_time_limit'];
$work = sys_get_temp_dir() . '/cap_parity_' . getmypid();
@mkdir($work, 0777, true);
copy(dirname(__DIR__) . '/tools/install.php', $work . '/install.php');
$teardown = t_teardown(static function () use ($work): void {
    foreach (glob($work . '/*') ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($work);
});
$probeSrc = <<<'PHP'
<?php
$bin = null;
if (!class_exists('ZipArchive') && (function_exists('proc_open') || function_exists('exec'))) {
    $exe = 'unzip' . (DIRECTORY_SEPARATOR === '\\' ? '.exe' : '');
    $path = function_exists('getenv') ? (string)@getenv('PATH') : '';
    if ($path !== '') foreach (explode(PATH_SEPARATOR, $path) as $d) {
        $c = rtrim($d, '/\\') . DIRECTORY_SEPARATOR . $exe;
        if ($c !== $exe && is_file($c)) { $bin = $c; break; }
    }
    if ($bin === null) foreach (['/usr/bin/unzip', '/bin/unzip', '/usr/local/bin/unzip'] as $c) {
        if (is_file($c)) { $bin = $c; break; }
    }
}
echo json_encode([
    'php_version' => PHP_VERSION,
    'ext' => ['pdo_mysql' => extension_loaded('pdo_mysql'), 'mbstring' => extension_loaded('mbstring'),
              'zlib' => extension_loaded('zlib'), 'openssl' => extension_loaded('openssl')],
    'curl' => function_exists('curl_init'),
    'sockets' => function_exists('stream_socket_client'),
    'zip_ext' => class_exists('ZipArchive'),
    'unzip_bin' => $bin,
    'exec' => function_exists('exec'),
    'proc_open' => function_exists('proc_open'),
    'set_time_limit' => function_exists('set_time_limit'),
]);
PHP;
file_put_contents($work . '/probe.php', $probeSrc);
$runnerSrc = '<?php $_GET = json_decode((string)getenv("IX_GET"), true) ?: []; $_POST = json_decode((string)getenv("IX_POST"), true) ?: []; include __DIR__ . "/install.php";';
file_put_contents($work . '/__runner.php', $runnerSrc);
$run = static function (array $flags, string $script, array $get = [], array $post = []): array {
    $cmd = escapeshellarg(PHP_BINARY);
    foreach ($flags as $f) {
        $cmd .= ' ' . escapeshellarg($f);
    }
    $cmd .= ' ' . escapeshellarg($script) . ' 2>&1';
    putenv('IX_GET=' . json_encode($get));
    putenv('IX_POST=' . json_encode($post));
    $out = [];
    exec($cmd, $out, $code);
    putenv('IX_GET');
    putenv('IX_POST');
    return [$code, implode("\n", $out)];
};
$combos = [
    'baseline' => [],
    'no-process' => ['-d', 'disable_functions=proc_open,exec,shell_exec,system,passthru,popen,set_time_limit'],
    'no-extensions' => ['-n'],
];
foreach ($combos as $name => $flags) {
    [$pCode, $pRaw] = $run($flags, $work . '/probe.php');
    T::eq("parity $name: probe exits 0", 0, $pCode);
    $penv = json_decode($pRaw, true);
    T::ok("parity $name: probe is valid JSON env", is_array($penv) && isset($penv['ext']));
    if (!is_array($penv) || !isset($penv['ext'])) {
        continue;
    }
    $expected = [];
    foreach (capabilities_evaluate($penv) as $r) {
        $expected[$r['id']] = capabilities_consumer_status($r);
    }
    [$cCode, $cRaw] = $run($flags, $work . '/__runner.php', ['action' => 'check']);
    T::eq("parity $name: check exits 0", 0, $cCode);
    $check = json_decode($cRaw, true);
    T::ok("parity $name: check is valid JSON", is_array($check['rows'] ?? null));
    if (!is_array($check['rows'] ?? null)) {
        continue;
    }
    $byId = [];
    foreach ($check['rows'] as $r) {
        $byId[$r['id']] = $r;
    }
    foreach ($probed as $ixId => $regId) {
        T::eq("parity $name: $ixId matches registry $regId",
            $expected[$regId] ?? null, $byId[$ixId]['status'] ?? null);
    }
    // Static-info rows (the installer cannot probe detach and takes no env
    // vars) exist and never block; every problem row carries prose.
    foreach (['jobs', 'env'] as $static) {
        T::eq("parity $name: installer $static row is static info", 'info', $byId[$static]['status'] ?? null);
    }
    foreach ($check['rows'] as $r) {
        if (in_array($r['status'] ?? 'ok', ['fail', 'warn'], true)) {
            T::ok("parity $name: blocking row carries prose: {$r['id']}", ($r['detail'] ?? '') !== '');
        }
    }
}

// ── 4. dbtest names the privilege situation (live database) ─────────────────
$dbc = ['db_host' => getenv('DDMGMT_DB_HOST') ?: '127.0.0.1', 'db_port' => getenv('DDMGMT_DB_PORT') ?: '3306',
    'db_name' => TEST_DB_NAME, 'db_user' => getenv('DDMGMT_DB_USER') ?: 'root',
    'db_pass' => getenv('DDMGMT_DB_PASS') !== false ? (string)getenv('DDMGMT_DB_PASS') : ''];
[$dCode, $dRaw] = $run([], $work . '/__runner.php', [], ['action' => 'dbtest'] + $dbc);
T::eq('dbtest connects', 0, $dCode);
$dt = json_decode($dRaw, true);
T::eq('dbtest ok', true, $dt['ok'] ?? false);
T::eq('root answers create_priv true', true, $dt['create_priv'] ?? null);
// The panel-hostile shape: a user_xxx-style account scoped to one database,
// no global privileges — dbtest still connects, and says so honestly.
$db = get_db();
$limUser = 'ddmgmt_nocreate_' . getmypid();
$limPass = bin2hex(random_bytes(8));
$tDown2 = t_teardown(static function () use ($db, $limUser): void {
    try {
        $db->exec("DROP USER IF EXISTS '" . $limUser . "'@'%'");
    } catch (Throwable) {
    }
});
try {
    $db->exec("CREATE USER IF NOT EXISTS '" . $limUser . "'@'%' IDENTIFIED BY '" . $limPass . "'");
    $db->exec('GRANT SELECT, INSERT, UPDATE, DELETE ON `' . TEST_DB_NAME . "`.* TO '" . $limUser . "'@'%'");
    $lim = ['db_host' => $dbc['db_host'], 'db_port' => $dbc['db_port'],
        'db_name' => TEST_DB_NAME, 'db_user' => $limUser, 'db_pass' => $limPass];
    [$lCode, $lRaw] = $run([], $work . '/__runner.php', [], ['action' => 'dbtest'] + $lim);
    T::eq('restricted dbtest exits 0', 0, $lCode);
    $lt = json_decode($lRaw, true);
    T::eq('restricted account still connects', true, $lt['ok'] ?? false);
    T::eq('restricted account answers create_priv false', false, $lt['create_priv'] ?? null);
    T::ok('restricted log names the no-CREATE path', str_contains((string)($lt['log'] ?? ''), 'no CREATE DATABASE'));
} finally {
    $tDown2();
}

// ── 5. fast setup_check unit tests (the sampler's designated killer for
// setup_check.php runs this suite, not the slow schema-reloading one) ───
$dbCap = get_db();
T::eq('trivial statements apply', ['applied' => 2, 'error' => '', 'statement' => ''],
    schema_apply($dbCap, ['SELECT 1', 'SELECT 2']));
$badApply = schema_apply($dbCap, ['SELECT 1', 'GARBAGE SYNTAX (((']);
T::eq('one statement applied before the failure', 1, $badApply['applied'] ?? -1);
T::ok('failure names the error', ($badApply['error'] ?? '') !== '');
T::ok('...and the offending statement', str_contains((string)($badApply['statement'] ?? ''), 'GARBAGE'));

// unzip discovery through a fabricated PATH: only proc_open/exec qualify,
// and the binary found is the one named.
$uzDir = sys_get_temp_dir() . '/ddmgmt_unzip_' . getmypid();
@mkdir($uzDir, 0770, true);
$uzExe = 'unzip' . (DIRECTORY_SEPARATOR === '\\' ? '.exe' : '');
file_put_contents($uzDir . '/' . $uzExe, 'fake');
$oldPath = getenv('PATH');
putenv('PATH=' . $uzDir . PATH_SEPARATOR . (string)$oldPath);
T::eq('fabricated unzip found on PATH', $uzDir . DIRECTORY_SEPARATOR . $uzExe, capabilities_find_unzip());
putenv('PATH=' . (string)$oldPath);
@unlink($uzDir . '/' . $uzExe);
@rmdir($uzDir);

// Webserver row off Apache: warn with the nginx-snippet pointer (a deleted
// return would answer null and break the setup page shape).
$wsTmp = sys_get_temp_dir() . '/ddmgmt_ws_' . getmypid();
@mkdir($wsTmp, 0770, true);
$wsRow = setup_webserver_row('cli-server', $wsTmp);
T::eq('non-apache warns', 'warn', $wsRow['status'] ?? null);
T::ok('...pointing at the nginx snippet', str_contains($wsRow['detail'] ?? '', 'ginx'));
@rmdir($wsTmp);

// A runner that exists nowhere skips without enabling the binary: the fake
// unzip below must NOT be returned for a missing executor (a dropped skip
// would hand out a binary nothing can run).
$uzDir2 = sys_get_temp_dir() . '/ddmgmt_unzip2_' . getmypid();
@mkdir($uzDir2, 0770, true);
file_put_contents($uzDir2 . '/' . $uzExe, 'fake');
$oldPath2 = getenv('PATH');
putenv('PATH=' . $uzDir2 . PATH_SEPARATOR . (string)$oldPath2);
try {
    T::eq('missing executor never enables a binary', null, capabilities_find_unzip(['no_such_executor_xyz']));
} finally {
    putenv('PATH=' . (string)$oldPath2);
}
@unlink($uzDir2 . '/' . $uzExe);
@rmdir($uzDir2);

$teardown();
exit(T::done());
