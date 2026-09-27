<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/includes/setup_check.php';

// ── Setup diagnostics + schema installer, in-process ────────────────────────
// The setup_check page is thin glue over this library (same checks, same
// installer); the page itself only runs over HTTP, so everything load-bearing
// is pinned here where pcov can see it.

// The probe asserts need the real schema: reload it like StateTransitionTest.
$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/schema_loader.php') . ' 2>&1';
exec($cmd, $loaderOut, $loaderCode);
T::eq('schema loader exits 0 (refactored onto schema_statements/apply)', 0, $loaderCode);

$db = get_db();
$teardown = t_teardown(static function () use ($db): void {
    $db->exec('DROP TABLE IF EXISTS sc_tmp');
});

// ── schema_statements: splitter strips comments, CREATE, USE ────────────────
$fixture = "-- a comment\nCREATE DATABASE IF NOT EXISTS deaddrops CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nUSE deaddrops;\nCREATE TABLE IF NOT EXISTS sc_tmp (id INT PRIMARY KEY);\n\n-- another comment\nINSERT INTO sc_tmp VALUES (1);";
$stmts = schema_statements($fixture);
T::eq('CREATE DATABASE + USE stripped', [
    'CREATE TABLE IF NOT EXISTS sc_tmp (id INT PRIMARY KEY)',
    'INSERT INTO sc_tmp VALUES (1)',
], array_values($stmts));
$kept = schema_statements($fixture, true);
T::ok('keepCreate retains CREATE DATABASE for privileged installs',
    str_starts_with($kept[0], 'CREATE DATABASE') && count($kept) === 3);

// ── schema_apply: success, then first-error short-circuit ───────────────────
$res = schema_apply($db, ['CREATE TABLE IF NOT EXISTS sc_tmp (id INT PRIMARY KEY)', 'INSERT INTO sc_tmp VALUES (1)']);
T::eq('apply success counts statements', 2, $res['applied']);
T::eq('apply success has no error', '', $res['error']);
T::eq('row landed', '1', (string)$db->query('SELECT COUNT(*) FROM sc_tmp')->fetchColumn());
$bad = schema_apply($db, ['INSERT INTO sc_tmp VALUES (2)', 'THIS IS NOT SQL', 'INSERT INTO sc_tmp VALUES (3)']);
T::eq('apply stops at first error', 1, $bad['applied']);
T::ok('apply reports the error', $bad['error'] !== '');
T::ok('apply names the failing statement', str_contains($bad['statement'], 'THIS IS NOT SQL'));
T::eq('later statements never ran', '0', (string)$db->query('SELECT COUNT(*) FROM sc_tmp WHERE id = 3')->fetchColumn());

// ── setup_db_probe against the live test database ───────────────────────────
$probe = setup_db_probe();
T::eq('probe connects', true, $probe['connected']);
T::eq('probe session zone is UTC where SET is honored', '+00:00', $probe['zone']);
T::eq('probe sees every managed table', [], array_values(array_diff(SETUP_TABLES, $probe['tables'])));
$nonInno = [];
foreach (SETUP_TABLES as $tbl) {
    if (($probe['engines'][$tbl] ?? null) !== 'INNODB') {
        $nonInno[] = $tbl;
    }
}
T::eq('probe sees InnoDB everywhere locally', [], $nonInno);
T::ok('owner_exists is a bool', is_bool($probe['owner_exists']));

$rows = setup_db_rows($probe);
T::eq('live probe first row is ok', 'ok', $rows[0]['status']);
$statuses = array_column($rows, 'status');
T::ok('live probe has no fail rows', !in_array('fail', $statuses, true));

$down = setup_db_rows(['connected' => false, 'error' => 'refused', 'pdo' => null,
    'zone' => null, 'tables' => [], 'engines' => [], 'owner_exists' => false]);
T::eq('down probe yields one fail row', 1, count($down));
T::eq('down probe row fails', 'fail', $down[0]['status']);
T::ok('down detail carries the error', str_contains($down[0]['detail'], 'refused'));

// ── setup_runtime_checks: shape + locally deterministic rows ────────────────
$rt = setup_runtime_checks();
$byId = [];
foreach ($rt as $r) {
    T::ok('row has id/label/status/detail: ' . $r['id'],
        isset($r['id'], $r['label'], $r['status'], $r['detail']));
    T::ok('row status is known: ' . $r['id'],
        in_array($r['status'], ['ok', 'warn', 'fail', 'info'], true));
    $byId[$r['id']] = $r;
}
T::eq('PHP row ok on 8.2+', 'ok', $byId['php']['status']);
T::eq('pdo_mysql ok wherever suites run', 'ok', $byId['ext_pdo_mysql']['status']);
T::eq('mbstring ok wherever suites run', 'ok', $byId['ext_mbstring']['status']);
T::eq('problem rows carry prose', true, (function () use ($rt): bool {
    foreach ($rt as $r) {
        if ($r['status'] === 'fail' || $r['status'] === 'warn') {
            return $r['detail'] !== '';
        }
    }
    return true; // nothing failing locally — vacuously true
})());

// ── setup_storage_checks: shape + AES key row ───────────────────────────────
$st = setup_storage_checks();
$stById = [];
foreach ($st as $r) {
    $stById[$r['id']] = $r;
}
T::eq('AES test key is valid hex', 'ok', $stById['aes_key']['status']);
T::ok('session row present', isset($stById['sessions']));
T::ok('dir rows present for every writable path',
    isset($stById['dir_logs'], $stById['dir_tiles'], $stById['dir_uploads']));

// ── setup_webserver_row: Apache honored, everything else warned ─────────────
T::eq('apache + htaccess is ok', 'ok', setup_webserver_row('Apache/2.4.58')['status']);
T::eq('nginx warns with the snippet note', 'warn', setup_webserver_row('nginx/1.24.0')['status']);
T::ok('nginx detail names the docs', str_contains(setup_webserver_row('nginx/1.24.0')['detail'], 'nginx'));
T::eq('unknown server warns', 'warn', setup_webserver_row('')['status']);

// ── session path helper: no-op where the configured path works ─────────────
$before = (string)@ini_get('session.save_path');
$eff = session_effective_path();
T::ok('effective path is non-empty', $eff !== '');
session_save_path_ensure();
T::eq('writable configured path is never touched', $before, (string)@ini_get('session.save_path'));

// ── maps_inline_budget: derived from the PHP limit, capped, floored ─────────
$keepLimit = (string)@ini_get('max_execution_time');
try {
    @ini_set('max_execution_time', '30');
    T::eq('30s limit yields 25s budget', 25, maps_inline_budget());
    @ini_set('max_execution_time', '7');
    T::eq('tiny limit floors at 5s', 5, maps_inline_budget());
    @ini_set('max_execution_time', '300');
    T::eq('generous limit still caps at 25s', 25, maps_inline_budget());
} finally {
    @ini_set('max_execution_time', $keepLimit);
}
T::eq('unlimited host keeps old behavior', 0, maps_inline_budget());

exit(T::done());
