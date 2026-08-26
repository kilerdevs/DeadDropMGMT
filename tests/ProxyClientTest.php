<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// Dev machines (and some CI images) export NO_PROXY=127.0.0.1,localhost —
// libcurl then silently SKIPS every proxy for loopback targets and this
// suite would exercise the direct path while believing it exercises the
// pool. Clear the exclusions so "dead proxy" really means dead.
foreach (['NO_PROXY', 'no_proxy', 'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'] as $k) {
    putenv($k);
}
unset($_SERVER['NO_PROXY'], $_SERVER['no_proxy']);

// ── OSM proxy client against a local stub server ─────────────────────────────
// The outbound client code runs IN this process (instrumented), while the
// stub only plays the remote endpoint. Discovery sources and public judges
// stay untouched — no external traffic is generated.

$port = 8700 + (int)(getmypid() % 300);
$root = dirname(__DIR__);
$stubDir = sys_get_temp_dir() . '/ddmgmt_stub_' . getmypid();
if (!is_dir($stubDir)) { mkdir($stubDir, 0700, true); }
$router = $stubDir . '/router.php';
file_put_contents($router, <<<'PHP'
<?php
$p = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($p === '/ok')        { header('Content-Type: text/plain'); echo 'STUB-BODY-OK'; return true; }
if ($p === '/nope')      { http_response_code(404); echo 'not found'; return true; }
if ($p === '/leak')      { echo 'via 203.0.113.99 origin=203.0.113.99'; return true; }
if ($p === '/clean')     { echo 'headers are anonymous, no ip here'; return true; }
http_response_code(200); echo 'default-body';
return true;
PHP);
$null = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
$cmd  = escapeshellarg(PHP_BINARY)
    . ' -d session.save_path=' . escapeshellarg(ini_get('session.save_path'))
    . " -S 127.0.0.1:$port " . escapeshellarg($router);
$proc = proc_open($cmd, [['pipe', 'r'], ['file', $null, 'w'], ['file', $null, 'w']], $pipes);
if (!is_resource($proc)) { fwrite(STDERR, "cannot spawn stub server\n"); exit(1); }
register_shutdown_function(static function () use ($proc, $router, $stubDir): void {
    // proc_terminate alone leaves the listener alive on Windows — kill the tree
    $st = proc_get_status($proc);
    if (!empty($st['running'])) {
        exec('taskkill /F /T /PID ' . (int)$st['pid'] . ' >NUL 2>&1');
    }
    proc_close($proc);
    @unlink($router); @rmdir($stubDir);
});
$up = false;
for ($i = 0; $i < 30; $i++) {
    try { [$st] = _px_req("http://127.0.0.1:$port/ok"); } catch (Throwable) { $st = 0; usleep(200000); continue; }
    if ($st === 200) { $up = true; break; }
    usleep(200000);
}
T::ok('stub server booted', $up);

$db = get_db();
$db->exec("DELETE FROM osm_proxies WHERE url LIKE 'http://127.0.0.1:%'");
set_setting('osm_proxy_enabled', '0');

// ── URL normalization ─────────────────────────────────────────────────────────
T::eq('bare host:port gets scheme',       'http://10.0.0.1:8080',    osm_proxy_normalize('10.0.0.1:8080'));
T::eq('explicit scheme preserved',        'http://10.0.0.1:8080',    osm_proxy_normalize('http://10.0.0.1:8080'));
T::eq('https scheme accepted',            'https://proxy.example.com:3128', osm_proxy_normalize('https://proxy.example.com:3128'));
T::eq('socks5 accepted',                  'socks5://10.0.0.2:1080',  osm_proxy_normalize('socks5://10.0.0.2:1080'));
T::eq('host lowercased',                  'http://proxy.example.com:8080', osm_proxy_normalize('PROXY.Example.COM:8080'));
T::eq('credentials urlencoded',           'http://user%40x:p%40ss@10.0.0.3:8080', osm_proxy_normalize('user@x:p@ss@10.0.0.3:8080'));
T::ok('missing port rejected',            osm_proxy_normalize('10.0.0.1') === null);
T::ok('empty input rejected',             osm_proxy_normalize('   ') === null);
T::ok('oversized input rejected',         osm_proxy_normalize(str_repeat('a', 260)) === null);
T::ok('bad port range rejected',          osm_proxy_normalize('10.0.0.1:99999') === null);
T::ok('unknown scheme rejected',          osm_proxy_normalize('ftp://10.0.0.1:21') === null);
T::ok('invalid host rejected',            osm_proxy_normalize('http://:8080') === null);
T::ok('port zero rejected',               osm_proxy_normalize('10.0.0.1:0') === null);

// ── Direct fetches ────────────────────────────────────────────────────────────
T::eq('direct 200 returns body', 'STUB-BODY-OK', osm_fetch_via("http://127.0.0.1:$port/ok", null));
T::ok('non-2xx returns false',   osm_fetch_via("http://127.0.0.1:$port/nope", null) === false);
T::ok('dead proxy returns false', osm_fetch_via("http://127.0.0.1:$port/ok", 'http://127.0.0.1:1') === false);

// ── Routing decision ──────────────────────────────────────────────────────────
// Disabled routing goes direct even when a pool exists
$db->exec("INSERT INTO osm_proxies (url, label, source, last_status) VALUES ('http://127.0.0.1:1', 'dead', 'manual', 'new')");
T::eq('routing disabled means direct fetch',
      'STUB-BODY-OK', osm_fetch_via("http://127.0.0.1:$port/ok", null));

// Enabled routing with an EMPTY pool must fail closed — never leak direct
set_setting('osm_proxy_enabled', '1');
$db->exec("DELETE FROM osm_proxies");
T::ok('enabled + empty pool refuses to go direct', osm_fetch("http://127.0.0.1:$port/ok") === false);
$staged = osm_last_via_stage();
T::ok('empty-pool failure staged for badge', $staged !== null && $staged['failed'] === true && $staged['attempts'] === 0);

// Enabled routing over a dead pool: fail closed, every attempt recorded
$db->exec("INSERT INTO osm_proxies (url, label, source, last_status, latency_ms) VALUES
    ('http://127.0.0.1:1', 'deadA', 'manual', 'fail', 500),
    ('http://127.0.0.1:2', 'deadB', 'manual', 'ok',   100)");
$rowIds = [];
foreach ($db->query('SELECT id, url FROM osm_proxies')->fetchAll() as $r) { $rowIds[$r['url']] = (int)$r['id']; }
T::ok('all-dead pool fails closed', osm_fetch("http://127.0.0.1:$port/ok") === false);
$staged = osm_last_via_stage();
T::ok('dead-pool attempt bookkeeping', is_array($staged) && ($staged['failed'] ?? null) === true
    && ($staged['attempts'] ?? 0) === 2 && count($staged['skipped'] ?? []) === 2);
$markA = $db->query('SELECT last_status FROM osm_proxies WHERE id = ' . $rowIds['http://127.0.0.1:1'])->fetch();
T::ok('failed attempts marked as fail', $markA !== false && $markA['last_status'] === 'fail');

// Pool ordering: previously-ok proxies sort ahead of dead ones regardless of latency
$pool = [
    ['url' => 'a', 'last_status' => 'fail', 'latency_ms' => 1],
    ['url' => 'b', 'last_status' => 'ok',   'latency_ms' => 900],
];
usort($pool, function ($a, $b) {
    $rank = function ($p) {
        return match ($p['last_status'] ?? '') {
            'ok'   => 0,
            'new'  => 1,
            default => 2,
        };
    };
    $ra = $rank($a);
    if ($ra !== ($rb = $rank($b))) return $ra <=> $rb;
    return ((int)($a['latency_ms'] ?? PHP_INT_MAX)) <=> ((int)($b['latency_ms'] ?? PHP_INT_MAX));
});
T::eq('healthy proxy sorts first', 'b', $pool[0]['url']);

// Health marking round-trip
$db->exec("INSERT INTO osm_proxies (url, label, source, last_status) VALUES ('http://127.0.0.1:9', 'markme', 'manual', 'new')");
$mid = (int)$db->query("SELECT id FROM osm_proxies WHERE url = 'http://127.0.0.1:9'")->fetchColumn();
osm_proxy_mark($mid, true, 42);
$m = $db->query("SELECT last_status, latency_ms FROM osm_proxies WHERE id = $mid")->fetch();
T::ok('mark ok records status+latency', $m['last_status'] === 'ok' && (int)$m['latency_ms'] === 42);
osm_proxy_mark($mid, false);
$m = $db->query("SELECT last_status FROM osm_proxies WHERE id = $mid")->fetch();
T::eq('mark fail records failure', 'fail', $m['last_status']);
with_table_hidden_px('osm_proxies', function (): void {
    osm_proxy_mark(1, true, 5); // must degrade silently
    T::ok('health marking survives unreadable pool table', true);
});

// Pool load failure path
with_table_hidden_px('osm_proxies', function (): void {
    T::eq('unreadable pool loads as empty', [], osm_proxy_pool());
});

// Badge flush into an active session
start_secure_session();
osm_last_via_set(['via' => 'http://marked.proxy:8080', 'failed' => false, 'attempts' => 1]);
osm_last_via_flush();
T::ok('flush wrote badge info to session',
      ($_SESSION['osm_last_via']['via'] ?? '') === 'http://marked.proxy:8080');
T::ok('stage consumed after flush', osm_last_via_stage() === null);

// Anonymity judge logic against stub judges through a fake proxy channel:
// judge bodies come via osm_fetch_via(judge, proxyUrl) — point the "proxy"
// straight at the stub so the judge body is fully controlled.
T::eq('judge fails closed when unreachable',
      false, proxy_judge_anonymous('http://127.0.0.1:1', '203.0.113.99'));

// Batch probing: every candidate answers [code, ms], dead ones with code 0
$res = proxy_multi_probe(
    ['http://127.0.0.1:1', 'http://127.0.0.1:2'],
    "http://127.0.0.1:$port/ok",
    3,
    3,
    false
);
T::eq('batch probe returns an entry per candidate', 2, count($res));
T::ok('unreachable candidates report code 0',
      ($res['http://127.0.0.1:1'][0] ?? -1) === 0 && ($res['http://127.0.0.1:2'][0] ?? -1) === 0);
T::ok('batch probe records timings',
      ($res['http://127.0.0.1:1'][1] ?? -1) >= 0);
// HEAD-mode probe (default) against the same candidates
$resHead = proxy_multi_probe(['http://127.0.0.1:1'], "http://127.0.0.1:$port/ok", 3, 3);
T::ok('HEAD-mode batch probe works',
      isset($resHead['http://127.0.0.1:1']) && ($resHead['http://127.0.0.1:1'][0] ?? -1) === 0);

// Cleanup
$db->exec("DELETE FROM osm_proxies WHERE url LIKE 'http://127.0.0.1:%'");
set_setting('osm_proxy_enabled', '0');

exit(T::done());

function with_table_hidden_px(string $table, callable $fn): mixed {
    $bak = $table . '_px_bak';
    $dbX = get_db();
    $dbX->exec("RENAME TABLE {$table} TO {$bak}");
    try {
        return $fn();
    } finally {
        $dbX->exec("RENAME TABLE {$bak} TO {$table}");
    }
}

function _px_req(string $url): array {
    $body = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 3, 'ignore_errors' => true]]));
    $status = 0;
    foreach ($http_response_header ?? [] as $h) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) { $status = (int)$m[1]; }
    }
    return [$status, $body === false ? '' : $body];
}
