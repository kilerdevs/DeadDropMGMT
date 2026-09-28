<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Minified installer contract ──────────────────────────────────────────────
// tools/install.min.php is AUTO-GENERATED from tools/install.php (see
// tools/build_installer_min.php) and committed to the repo so shared hosting
// needs a single small upload; CI rebuilds + commits it after every push.
// This suite pins three things: the committed file is in sync (freshness),
// it is actually smaller, and — the load-bearing one — the minified code
// RUNS: the same black-box smoke as InstallerTest (check → tags → fetch →
// download → extract → tree) against the .min copy, including one fetch
// pinned to the socket engine (the most minify-sensitive path: hand-rolled
// HTTP framing that must survive comment/whitespace stripping byte-exact).

$root = dirname(__DIR__);
$src = $root . '/tools/install.php';
$min = $root . '/tools/install.min.php';
$builder = $root . '/tools/build_installer_min.php';

function imn_php(string $args): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . $args . ' 2>&1';
    exec($cmd, $out, $code);
    return [$code, implode("\n", $out)];
}

// ── 1. freshness: committed .min matches what the builder produces ──────────
[$code, $msg] = imn_php(escapeshellarg($builder) . ' --check');
T::eq('builder --check exits 0 (in sync)', 0, $code);
T::ok('builder --check says so (' . $msg . ')', str_contains($msg, 'in sync'));

// ── 2. both files lint clean ─────────────────────────────────────────────────
[$code] = imn_php('-l ' . escapeshellarg($src));
T::eq('install.php lints', 0, $code);
[$code] = imn_php('-l ' . escapeshellarg($min));
T::eq('install.min.php lints', 0, $code);

// ── 3. actually smaller ──────────────────────────────────────────────────────
$srcBytes = filesize($src);
$minBytes = filesize($min);
T::ok('min sizes read', is_int($srcBytes) && is_int($minBytes) && $srcBytes > 0);
T::ok('min is smaller (' . $minBytes . ' < ' . $srcBytes . ')', $minBytes < $srcBytes);
T::ok('min saves real weight (ratio < 0.9)', $minBytes / $srcBytes < 0.9);

// ── 4. generated-file markers + entry-point contract ─────────────────────────
$minSrc = (string)file_get_contents($min);
T::ok('min carries the AUTO-GENERATED header', str_contains($minSrc, 'AUTO-GENERATED from tools/install.php'));
T::ok('min pins its source sha', (bool)preg_match('/Source sha256: [0-9a-f]{64}/', $minSrc));
T::ok('min pins the rebuild command', str_contains($minSrc, 'build_installer_min.php'));
T::ok('min is a browser wizard (no CLI guard)', !str_contains($minSrc, "PHP_SAPI !== 'cli'"));
T::ok('min pulls no service layer', !preg_match('/\b(require|include)(_once)?\b[^\n]*\/includes\//', $minSrc));
$bSrc = (string)file_get_contents($builder);
T::ok('builder is CLI-only', str_contains($bSrc, "PHP_SAPI !== 'cli'"));

// ── 5. behavioral smoke against the .min copy ────────────────────────────────
function imn_tmp(string $prefix): string {
    $d = sys_get_temp_dir() . '/' . $prefix . getmypid();
    @mkdir($d, 0777, true);
    return $d;
}

function imn_run(string $work, array $get, array $post): array {
    $runner = $work . '/__runner.php';
    if (!is_file($runner)) {
        file_put_contents($runner, '<?php $_GET = json_decode((string)getenv("IX_GET"), true) ?: []; $_POST = json_decode((string)getenv("IX_POST"), true) ?: []; include __DIR__ . "/install.php";');
    }
    putenv('IX_GET=' . json_encode($get));
    putenv('IX_POST=' . json_encode($post));
    $dll = getenv('IX_ZIP_DLL');
    $cmd = escapeshellarg(PHP_BINARY);
    if (is_string($dll) && $dll !== '' && class_exists('ZipArchive')) {
        $cmd .= ' -d ' . escapeshellarg('extension=' . $dll);
    }
    $cmd .= ' ' . escapeshellarg($runner) . ' 2>&1';
    exec($cmd, $out, $code);
    putenv('IX_GET');
    putenv('IX_POST');
    return [$code, json_decode(implode("\n", $out), true)];
}

$work = imn_tmp('imn_full_');
$stub = imn_tmp('imn_stub_');
copy($min, $work . '/install.php');
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

$server = null;
$stubPort = 0;
$base = '';
if (function_exists('proc_open')) {
    foreach ([0, 1, 2] as $off) {
        $port = 18400 + (getmypid() % 500) + $off;
        $p = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $stub],
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
            $base = 'http://127.0.0.1:' . $port;
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
}
if ($base === '') $base = 'file://' . str_replace('\\', '/', $stub);

file_put_contents($stub . '/gh-tags.json', json_encode([['name' => 'v9.9.9', 'zipball_url' => $base . '/pkg.zip']]));
file_put_contents($stub . '/ping.txt', 'pong');
if (class_exists('ZipArchive')) {
    $z = new ZipArchive();
    $zp = $stub . '/pkg.zip';
    T::ok('min fixture zip opens', $z->open($zp, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true);
    $z->addFromString('pkgtest/setup.sql', 'CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY);');
    $z->addFromString('pkgtest/config.php.example', 'no anchors needed here');
    $z->addFromString('pkgtest/includes/kernel.php', '<?php // marker');
    $z->close();
    T::ok('min fixture zip built', is_file($zp));
} else {
    T::ok('SKIP min smoke (no ZipArchive here)', true);
    exit(T::done());
}

[$code, $check] = imn_run($work, ['action' => 'check'], []);
T::eq('min check exits 0', 0, $code);
T::ok('min check returns rows', is_array($check['rows'] ?? null) && count($check['rows']) > 10);
[$code, $tree] = imn_run($work, ['action' => 'tree'], []);
T::eq('min tree: empty workdir', false, $tree['present'] ?? null);
[$code, $tags] = imn_run($work, [], ['action' => 'tags', 'src' => $base . '/gh-tags.json']);
T::eq('min tags list the fixture version', 'v9.9.9', $tags['tags'][0]['tag'] ?? null);

if ($server === null) {
    T::ok('SKIP min http asserts (no stub server here)', true);
} else {
    [$code, $fetch] = imn_run($work, [], ['action' => 'fetch', 'url' => $base . '/ping.txt']);
    T::eq('min fetch 200 + 4 bytes', [200, 4], [$fetch['code'] ?? 0, $fetch['bytes'] ?? -1]);
    [$code, $sock] = imn_run($work, [], ['action' => 'fetch', 'url' => $base . '/ping.txt', 'transport' => 'sockets']);
    T::eq('min socket-engine fetch 200 + 4 bytes', [200, 4], [$sock['code'] ?? 0, $sock['bytes'] ?? -1]);
    T::eq('min socket engine actually used', 'sockets', $sock['via'] ?? null);
    [$code, $dl] = imn_run($work, [], ['action' => 'download', 'url' => $base . '/pkg.zip']);
    T::eq('min download size matches fixture', filesize($stub . '/pkg.zip'), $dl['size'] ?? -1);
    [$code, $ex] = imn_run($work, [], ['action' => 'extract']);
    T::eq('min extract exit 0', 0, $code);
    T::ok('min setup.sql landed', is_file($work . '/setup.sql'));
    [$code, $tree2] = imn_run($work, ['action' => 'tree'], []);
    T::eq('min tree: app present after extract', true, $tree2['present'] ?? null);
}

exit(T::done());
