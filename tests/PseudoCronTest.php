<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Pseudo-cron: any PHP page can start the hourly maintenance ────────────────
// The kernel hooks pseudo_cron_run() onto every web request, so an install
// used only through /admin/ (or only through a JSON poll) still gets its
// sweep. healthz.php stays code-free and never triggers it; DDMGMT_PSEUDO_CRON=0
// switches the whole thing off. Each arm ages the hourly stamp, makes one
// request, and watches the stamp — the sweep runs after the response.

$db = get_db();
$db->exec('DELETE FROM osm_proxies'); // nothing stale to re-probe over the network
putenv('DDMGMT_PROXY_HEAL=0');        // a sweep must not start real proxy discovery

$stamp = static fn(): int => (int)$db->query("SELECT value FROM settings WHERE key_name = 'last_cleanup'")->fetchColumn();
$age   = static function () use ($db): int {
    $old = time() - 7200;
    $db->prepare("INSERT INTO settings (key_name, value, label) VALUES ('last_cleanup', ?, '')
                  ON DUPLICATE KEY UPDATE value = VALUES(value)")->execute([(string)$old]);
    return $old;
};
$prev = $stamp();
$teardown = t_teardown(static function () use ($prev): void {
    get_db()->prepare("UPDATE settings SET value = ? WHERE key_name = 'last_cleanup'")->execute([(string)$prev]);
    putenv('DDMGMT_PROXY_HEAL');
    putenv('DDMGMT_PSEUDO_CRON=0'); // the bootstrap default
});

function _pc_get(string $url): int {
    $ctx = stream_context_create(['http' => ['timeout' => 15, 'ignore_errors' => true, 'follow_location' => 0]]);
    @file_get_contents($url, false, $ctx);
    $h = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
    return preg_match('#^HTTP/\S+\s+(\d{3})#', (string)($h[0] ?? ''), $m) ? (int)$m[1] : 0;
}

/** Start a php -S on a free port with the current environment; returns [proc, base-url, stop-handle]. */
function _pc_server(): array {
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int)explode(':', (string)stream_socket_get_name($probe, false))[1];
    fclose($probe);
    $cmd = escapeshellarg(PHP_BINARY)
        . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
        . " -S 127.0.0.1:$port -t " . escapeshellarg(dirname(__DIR__));
    $null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
    $proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $p);
    $stop = t_teardown(static function () use ($proc): void {
        $st = proc_get_status($proc);
        if (!empty($st['running'])) {
            if (DIRECTORY_SEPARATOR === '\\') {
                exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
            } else {
                proc_terminate($proc);
            }
        }
        proc_close($proc);
    });
    $base = "http://127.0.0.1:$port";
    for ($i = 0; $i < 50; $i++) {
        if (_pc_get("$base/healthz.php") === 200) { return [$proc, $base, $stop]; }
        usleep(200000);
    }
    return [$proc, '', $stop];
}

$waitFor = static function (callable $cond, int $ms = 6000): bool {
    for ($t = 0; $t < $ms; $t += 100) {
        if ($cond()) { return true; }
        usleep(100000);
    }
    return $cond();
};

// ── ON: every kind of kernel page starts it ──────────────────────────────────
putenv('DDMGMT_PSEUDO_CRON=1');
[, $on, $stopOn] = _pc_server();
T::ok('server (pseudo-cron on) booted', $on !== '');

foreach ([
    '/index.php'          => 'public page',
    '/receive.php'        => 'receipt page',
    '/admin/index.php'    => 'admin login page',
    '/admin/orders.php'   => 'admin page (redirects to login)',
    '/admin/osm_status.php' => 'admin JSON poll endpoint',
] as $path => $what) {
    $old = $age();
    _pc_get($on . $path);
    T::ok("$what triggers the sweep", $waitFor(static fn(): bool => $stamp() > $old));
}

// ── healthz stays out of it ──────────────────────────────────────────────────
$old = $age();
_pc_get($on . '/healthz.php');
usleep(1500000);
T::eq('healthz.php never triggers the sweep', $old, $stamp());

// ── a fresh stamp: nothing to do ─────────────────────────────────────────────
$fresh = time();
$db->prepare("UPDATE settings SET value = ? WHERE key_name = 'last_cleanup'")->execute([(string)$fresh]);
_pc_get($on . '/index.php');
usleep(1500000);
T::eq('a stamp younger than an hour is left alone', $fresh, $stamp());

// ── OFF: DDMGMT_PSEUDO_CRON=0 ────────────────────────────────────────────────
putenv('DDMGMT_PSEUDO_CRON=0');
[, $off, $stopOff] = _pc_server();
T::ok('server (pseudo-cron off) booted', $off !== '');
$old = $age();
_pc_get($off . '/index.php');
_pc_get($off . '/admin/index.php');
usleep(1500000);
T::eq('DDMGMT_PSEUDO_CRON=0 disables it', $old, $stamp());

T::ok('the switch is read from the environment', pseudo_cron_enabled() === false); // CLI never runs it either
$stopOn();
$stopOff();
$teardown();
exit(T::done());
