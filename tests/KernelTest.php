<?php
declare(strict_types=1);

// KernelTest — the includes/kernel.php service manifest.
//
// - Requiring the kernel twice is safe (idempotency guard, no
//   "already defined" fatals, no warnings under the test error handler).
// - Every service file directly under includes/ is loaded by the kernel,
//   with one callable smoke-checked per service.
// - Regression guard for the header-sprawl cleanup: every admin entry page
//   pulls services only via the kernel. The two view partials that must
//   also work standalone (sidebar.php, osm_monit.php) keep their single
//   i18n require and are the only allowed exception.

require_once __DIR__ . '/bootstrap.php';

$root = dirname(__DIR__);

// ── Idempotent load ─────────────────────────────────────────────────────────
require_once $root . '/includes/kernel.php';
require_once $root . '/includes/kernel.php'; // second load must be a no-op
T::ok('kernel guard defined', defined('DDMGMT_KERNEL') && DDMGMT_KERNEL === true);

// ── Manifest completeness: every top-level service file is loaded ──────────
$loaded = [];
foreach (get_included_files() as $f) {
    $loaded[strtolower(str_replace('\\', '/', (string)realpath($f)))] = true;
}
$services = [];
foreach (glob($root . '/includes/*.php') as $f) {
    if (basename($f) === 'kernel.php') {
        continue; // the loader, not a service
    }
    $services[] = strtolower(str_replace('\\', '/', (string)realpath($f)));
}
T::ok('service files found', count($services) === 17);
foreach ($services as $s) {
    T::ok('kernel loads ' . basename($s), isset($loaded[$s]));
}

// ── One callable per service ────────────────────────────────────────────────
foreach ([
    'logger'      => 'app_log',
    'host'        => 'host_flag',
    'db'          => 'get_db',
    'net'         => 'get_client_ip',
    'settings'    => 'get_setting',
    'i18n'        => 't',
    'auth'        => 'require_admin',
    'crypto'      => 'encrypt_secret',
    'totp'        => 'totp_verify',
    'audit'       => 'audit',
    'analytics'   => 'log_event',
    'order_state' => 'order_delete_atomic',
    'proxy'       => 'osm_proxy_pool',
    'maps'        => 'map_provider',
    'cleanup'     => 'run_cleanup_if_due',
    'wipe'        => 'do_panic_wipe',
] as $service => $fn) {
    T::ok("service $service exposes $fn()", function_exists($fn));
}

// ── Admin pages pull includes only via the kernel ───────────────────────────
// Dispatch shims (legacy action URLs delegating to admin/dispatch.php) are
// the one other allowed shape: they pin $_GET['action'] to a route in
// admin/routes.php and pull nothing else.
$partials = ['sidebar.php' => true, 'totp_banner.php' => true, 'osm_monit.php' => true];
// routes.php is pure data (required, never executed directly).
$unscanned = $partials + ['routes.php' => true];
/** @var array<string,array<string,mixed>> */
$routes = require $root . '/admin/routes.php';
$checked = 0;
foreach (glob($root . '/admin/*.php') as $f) {
    $name = basename($f);
    if (isset($unscanned[$name])) {
        continue;
    }
    $src = (string)file_get_contents($f);
    if ($name !== 'dispatch.php' && str_contains($src, 'dispatch.php')) {
        $checked += _dispatch_shim($name, $src, $routes);
        continue;
    }
    $checked += _kernel_guarded($name, $src);
}
T::ok('admin entry pages scanned', $checked === 34);

// ── Same rule for every other entry point: public pages, cron, CLI tools,
// and the docker journey script. Deliberate exceptions (not scanned):
// healthz.php answers liveness with zero dependencies by design,
// config.php IS the base layer, and tests/* keep their own bootstrap.
$others = array_merge(
    [$root . '/index.php', $root . '/receive.php', $root . '/cron/cleanup.php', $root . '/cron/maps_sync.php'],
    glob($root . '/tools/*.php') ?: [],
    [$root . '/docker/e2e_journey.php'],
);
foreach ($others as $f) {
    $checked += _kernel_guarded('entry ' . basename($f), (string)file_get_contents($f));
}
T::ok('non-admin entry points scanned', count($others) === 11);

// ── CLI-only scripts refuse every non-CLI SAPI, and the web server config
// keeps developer/ops material off the wire (Apache .htaccess, nginx, Caddy).
$cliOnly = array_merge(
    glob($root . '/tools/*.php') ?: [],
    glob($root . '/cron/*.php') ?: [],
    [$root . '/docker/e2e_journey.php', $root . '/e2e/seed.php'],
    glob($root . '/tests/*.php') ? array_values(array_filter(
        glob($root . '/tests/*.php'),
        static fn(string $f): bool => !str_ends_with($f, 'Test.php')
    )) : [],
);
foreach ($cliOnly as $f) {
    T::ok('CLI guard in ' . basename(dirname($f)) . '/' . basename($f),
        str_contains((string)file_get_contents($f), "PHP_SAPI !== 'cli'"));
}
$htaccess = (string)file_get_contents($root . '/.htaccess');
$nginx    = (string)file_get_contents($root . '/docker/nginx.conf');
$caddy    = (string)file_get_contents($root . '/docker/Caddyfile');
foreach (['cron', 'tools', 'tests', 'docker', 'e2e', 'backups', 'data'] as $blocked) {
    T::ok("Apache blocks /$blocked/", str_contains($htaccess, $blocked . '|') || str_contains($htaccess, '|' . $blocked));
    T::ok("nginx blocks /$blocked/", (bool)preg_match('#\^/\([^)]*\b' . $blocked . '\b[^)]*\)/#', $nginx));
    T::ok("Caddy blocks /$blocked/", str_contains($caddy, "/$blocked/*"));
}
T::ok('Apache blocks setup.sql and config.php.example', str_contains($htaccess, 'setup\.sql') && str_contains($htaccess, 'config\\.php\\.example'));

// ── No function collisions with the service layer ───────────────────────────
// PHP function names are case-insensitive: an entry script defining T()
// fatals against i18n's t() the moment the kernel loads it (silent 255
// under display_errors=0 — this exact crash killed the CI container
// journey). Every function an entry point defines must be unique across
// the whole loaded set.
$serviceFuncs = [];
foreach (glob($root . '/includes/*.php') as $f) {
    if (basename($f) === 'kernel.php') {
        continue;
    }
    preg_match_all('/^function\s+(\w+)/mi', (string)file_get_contents($f), $m);
    foreach ($m[1] as $n) {
        $serviceFuncs[strtolower($n)] = basename($f);
    }
}
$entryFiles = array_merge(
    glob($root . '/admin/*.php') ?: [],
    glob($root . '/admin/actions/*.php') ?: [],
    $others,
);
foreach ($entryFiles as $f) {
    preg_match_all('/^function\s+(\w+)/mi', (string)file_get_contents($f), $m);
    foreach (array_unique($m[1]) as $n) {
        $k = strtolower($n);
        T::ok('entry ' . basename($f) . " defines $n() without service collision",
            !isset($serviceFuncs[$k]));
    }
}

// ── Last-resort handler answers CLI fatals itself ─────────────────────────────
// A subprocess that throws past every catch: log + "Fatal error" + exit 1.
// (The probe is a file: a top-level throw in `php -r` bypasses the engine's
// handler dispatch on some builds and would test nothing.)
$probeFile = sys_get_temp_dir() . '/ddmgmt_kernel_probe_' . getmypid() . '.php';
file_put_contents($probeFile,
    '<?php require_once ' . var_export($root . '/includes/kernel.php', true)
    . '; throw new RuntimeException(\'kernel-probe\');');
$proc = proc_open(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($probeFile),
    [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (is_resource($proc)) {
    $kOut = stream_get_contents($pipes[1]);
    $kErr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $kCode = proc_close($proc);
    T::ok('kernel CLI handler exits 1', $kCode === 1);
    T::ok('kernel CLI handler stays silent on stdout', $kOut === '');
    T::ok('kernel CLI handler is machine-readable', str_contains($kErr, 'Fatal error'));
} else {
    T::ok('kernel CLI handler subprocess spawns', false);
}
@unlink($probeFile);

exit(T::done());

// Asserts one entry script loads services only via the kernel; returns 1
// when the file was checked (keeps the scanned-count pins honest).
function _kernel_guarded(string $name, string $src): int {
    T::ok("$name requires kernel", str_contains($src, 'includes/kernel.php'));
    $stray = [];
    foreach (explode("\n", $src) as $line) {
        if (preg_match('/\b(require|include)(_once)?\b/', $line)
            && str_contains($line, '/includes/')
            && !str_contains($line, 'kernel.php')) {
            $stray[] = trim($line);
        }
    }
    T::ok("$name has no direct includes pulls", $stray === []);
    return 1;
}

// Asserts a legacy-URL shim pins $_GET['action'] to a real route and pulls
// nothing but the dispatcher.
function _dispatch_shim(string $name, string $src, array $routes): int {
    $ok = preg_match('/\$_GET\s*\[\s*[\'"]action[\'"]\s*\]\s*=\s*[\'"]([A-Za-z0-9_]+)[\'"]/', $src, $m) === 1;
    T::ok("$name shim pins an action", $ok);
    if ($ok) {
        T::ok("$name shim action '{$m[1]}' is a route", isset($routes[$m[1]]));
    }
    $stray = [];
    foreach (explode("\n", $src) as $line) {
        if (preg_match('/\b(require|include)(_once)?\b/', $line)
            && !str_contains($line, 'dispatch.php')) {
            $stray[] = trim($line);
        }
    }
    T::ok("$name shim pulls only the dispatcher", $stray === []);
    return 1;
}
