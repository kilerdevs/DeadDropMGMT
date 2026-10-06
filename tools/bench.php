<?php
declare(strict_types=1);

// CLI only: benchmarks seed rows and touch the database — never over HTTP.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// ── Phase G benchmark harness (cliff detector, not a profiler) ──────────────
// Seeds 10k marker rows (5k order_events, 3k audit_log, 2k rate_limits — past
// BACKUP_CHUNK_ROWS=500 twenty times over) plus 40 × 128 KiB photo files in
// an isolated uploads tree, times the core six hot paths, and compares each
// against tests/bench-budgets.json. Budgets are deliberately generous
// (~10x observed): the gate catches perf cliffs, runner noise never fails it.
//
// The restore round-trips the just-created bundle, so the net DB effect is
// zero; marker rows, the bundle and the temp tree are deleted in cleanup.
//
// Usage:
//   php tools/bench.php [--budgets=path] [--json=out.json] [--summary=out.md]
//   php tools/bench.php --list   # print scenario ids, no DB writes

require_once dirname(__DIR__) . '/tests/bootstrap.php';

/** Scenario ids in run order. Keys must match tests/bench-budgets.json. */
function bench_scenarios(): array {
    return [
        'backup_create'       => 'snapshot 10k rows + 5 MiB photos to a bundle',
        'backup_verify'       => 're-checksum every row count and file hash',
        'backup_restore'      => 'transactional replay of the verified bundle',
        'diagnostics_collect' => 'seven-section live aggregation under load',
        'pmtiles_verify'      => 'structural verify of the 2 MiB zone fixture',
        'installer_min_build' => 'token minify + --check of tools/install.php',
    ];
}

function bench_usage(): void {
    fwrite(STDERR, "usage: php tools/bench.php [--budgets=path] [--json=out.json] [--summary=out.md] [--list]\n");
}

/** Multi-row INSERT in chunks; returns rows written. */
function bench_seed_rows(PDO $db, string $sql, array $rows, int $chunk = 500): int {
    $n = 0;
    foreach (array_chunk($rows, $chunk) as $batch) {
        $place = implode(',', array_fill(0, count($batch), '(' . implode(',', array_fill(0, count($batch[0]), '?')) . ')'));
        $flat = [];
        foreach ($batch as $row) {
            foreach ($row as $v) {
                $flat[] = $v;
            }
        }
        $db->prepare($sql . ' VALUES ' . $place)->execute($flat);
        $n += count($batch);
    }
    return $n;
}

function bench_rmtree(string $dir): void {
    if (!is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $file) {
        /** @var SplFileInfo $file */
        $file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
    }
    @rmdir($dir);
}

$budgetsPath = dirname(__DIR__) . '/tests/bench-budgets.json';
$jsonPath = null;
$summaryPath = null;
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--list') {
        foreach (bench_scenarios() as $id => $label) {
            echo $id . "\n";
        }
        exit(0);
    }
    if (str_starts_with($arg, '--budgets=')) {
        $budgetsPath = substr($arg, 10);
    } elseif (str_starts_with($arg, '--json=')) {
        $jsonPath = substr($arg, 7);
    } elseif (str_starts_with($arg, '--summary=')) {
        $summaryPath = substr($arg, 10);
    } else {
        bench_usage();
        exit(2);
    }
}

$budgetsRaw = @file_get_contents($budgetsPath);
$budgets = is_string($budgetsRaw) ? json_decode($budgetsRaw, true) : null;
if (!is_array($budgets)) {
    fwrite(STDERR, "bench: budgets file unreadable: $budgetsPath\n");
    exit(2);
}
foreach (bench_scenarios() as $id => $label) {
    if (!isset($budgets[$id]['max_s']) || !is_numeric($budgets[$id]['max_s'])) {
        fwrite(STDERR, "bench: no numeric budget for scenario '$id' in $budgetsPath\n");
        exit(2);
    }
}

// ── Seed fixtures ───────────────────────────────────────────────────────────
$db = get_db();
$benchRoot = sys_get_temp_dir() . '/ddmgmt-bench-' . getmypid();
@mkdir($benchRoot . '/uploads/bench', 0775, true);
$photoBytes = 0;
for ($i = 0; $i < 40; $i++) {
    $blob = random_bytes(131072);
    file_put_contents($benchRoot . '/uploads/bench/photo-' . $i . '.enc', $blob);
    $photoBytes += strlen($blob);
}
$evRows = [];
for ($i = 0; $i < 5000; $i++) {
    $evRows[] = [null, null, 'bench_probe', '198.51.100.' . ($i % 250 + 1)];
}
$auRows = [];
for ($i = 0; $i < 3000; $i++) {
    $auRows[] = ['bench', 'bench_probe', '198.51.100.' . ($i % 250 + 1)];
}
$rlRows = [];
$now = date('Y-m-d H:i:s');
for ($i = 0; $i < 2000; $i++) {
    $rlRows[] = ['198.51.100.' . ($i % 250 + 1), 'bench_' . intdiv($i, 250), 1, $now];
}
$dbRows = 0;
$dbRows += bench_seed_rows($db, 'INSERT INTO order_events (order_id, token_hmac, event_type, ip_address)', $evRows);
$dbRows += bench_seed_rows($db, 'INSERT INTO audit_log (username, action, ip_address)', $auRows);
$dbRows += bench_seed_rows($db, 'INSERT INTO rate_limits (ip_address, scope, count, window_start)', $rlRows);

$results = [];
$failures = [];
$bundlePath = null;
$bundleManifest = null;

$time = static function (callable $fn): array {
    $t0 = microtime(true);
    $out = $fn();
    return [$out, microtime(true) - $t0, memory_get_peak_usage(true)];
};

try {
    [$created, $dt, $peak] = $time(static fn() => backup_create($db, $benchRoot));
    if (!($created['ok'] ?? false)) {
        throw new RuntimeException('backup_create failed: ' . ($created['code'] ?? '?'));
    }
    $bundlePath = dirname(__DIR__) . '/backups/' . ($created['file'] ?? '');
    $results['backup_create'] = [
        'seconds' => $dt, 'peak_mb' => $peak / 1048576,
        'detail' => ($created['rows'] ?? 0) . ' rows, ' . ($created['files'] ?? 0) . ' files (' . ($created['format'] ?? '?') . ')',
    ];

    [$verified, $dt, $peak] = $time(static fn() => backup_verify($bundlePath));
    if (!($verified['ok'] ?? false) || !isset($verified['manifest']) || !is_array($verified['manifest'])) {
        throw new RuntimeException('backup_verify failed: ' . ($verified['code'] ?? '?'));
    }
    $bundleManifest = $verified['manifest'];
    $results['backup_verify'] = ['seconds' => $dt, 'peak_mb' => $peak / 1048576, 'detail' => 'strict manifest + sha256'];

    [$restored, $dt, $peak] = $time(static fn() => backup_restore($db, $bundlePath, $bundleManifest, $benchRoot));
    if (!($restored['ok'] ?? false)) {
        throw new RuntimeException('backup_restore failed: ' . ($restored['code'] ?? '?'));
    }
    $results['backup_restore'] = ['seconds' => $dt, 'peak_mb' => $peak / 1048576, 'detail' => 'verify-first single transaction'];

    [$diag, $dt, $peak] = $time(static fn() => diagnostics_collect());
    $sections = count(array_intersect_key($diag, array_flip(['system', 'jobs', 'logs', 'traffic', 'security', 'data', 'backups'])));
    if ($sections !== 7) {
        throw new RuntimeException('diagnostics_collect returned ' . $sections . '/7 sections');
    }
    $results['diagnostics_collect'] = ['seconds' => $dt, 'peak_mb' => $peak / 1048576, 'detail' => '7 sections under 10k-row load'];

    $fixture = dirname(__DIR__) . '/e2e/fixtures/micro.pmtiles';
    [$valid, $dt, $peak] = $time(static fn() => pmtiles_verify_path($fixture));
    if ($valid !== true) {
        throw new RuntimeException('pmtiles_verify_path rejected the fixture');
    }
    $results['pmtiles_verify'] = ['seconds' => $dt, 'peak_mb' => $peak / 1048576, 'detail' => round((int)@filesize($fixture) / 1048576, 1) . ' MiB fixture'];

    $builder = dirname(__DIR__) . '/tools/build_installer_min.php';
    [$code, $dt, $peak] = $time(static function () use ($builder): int {
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($builder) . ' --check 2>&1', $out, $code);
        return (int)$code;
    });
    if ($code !== 0) {
        throw new RuntimeException('installer min-build --check failed');
    }
    $results['installer_min_build'] = ['seconds' => $dt, 'peak_mb' => $peak / 1048576, 'detail' => 'token minify + compare (incl. PHP startup)'];
} catch (Throwable $e) {
    $failures[] = $e->getMessage();
} finally {
    // ── Cleanup: marker rows, bundle, temp tree — always ────────────────────
    $db->exec("DELETE FROM order_events WHERE event_type = 'bench_probe'");
    $db->exec("DELETE FROM audit_log WHERE action = 'bench_probe'");
    $db->exec("DELETE FROM rate_limits WHERE scope LIKE 'bench\\_%'");
    if (is_string($bundlePath) && str_contains($bundlePath, 'backup-')) {
        @unlink($bundlePath);
    }
    bench_rmtree($benchRoot);
    clearstatcache();
}

// ── Verdicts ────────────────────────────────────────────────────────────────
$ok = $failures === [];
foreach ($results as $id => $row) {
    $budget = (float)$budgets[$id]['max_s'];
    $pass = $row['seconds'] <= $budget;
    $results[$id]['budget_s'] = $budget;
    $results[$id]['pass'] = $pass;
    if (!$pass) {
        $ok = false;
        $failures[] = "$id took " . round($row['seconds'], 1) . "s over budget {$budget}s";
    }
}

printf("%-20s %10s %10s %6s  %s\n", 'scenario', 'seconds', 'budget', 'peak', 'detail');
foreach ($results as $id => $row) {
    printf(
        "%-20s %10.2f %10.0f %5.0fMB  %s %s\n",
        $id, $row['seconds'], $row['budget_s'], $row['peak_mb'],
        $row['pass'] ? 'PASS' : 'FAIL', $row['detail']
    );
}

$payload = [
    'generated_at' => time(),
    'php' => PHP_VERSION,
    'fixtures' => ['db_rows' => $dbRows, 'photo_files' => 40, 'photo_bytes' => $photoBytes],
    'scenarios' => $results,
    'ok' => $ok,
];
if (is_string($jsonPath)) {
    file_put_contents($jsonPath, (string)json_encode($payload, JSON_PRETTY_PRINT) . "\n");
}
if (is_string($summaryPath)) {
    $md = '## Benchmarks (' . gmdate('Y-m-d H:i', (int)$payload['generated_at']) . ' UTC, PHP ' . PHP_VERSION . ")\n\n";
    $md .= "| scenario | seconds | budget | peak | detail |\n|---|---|---|---|---|\n";
    foreach ($results as $id => $row) {
        $md .= sprintf(
            "| %s | %.2f | %.0f | %.0f MB | %s %s |\n",
            $id, $row['seconds'], $row['budget_s'], $row['peak_mb'],
            $row['pass'] ? 'PASS' : '**FAIL**', $row['detail']
        );
    }
    file_put_contents($summaryPath, $md);
}

foreach ($failures as $f) {
    fwrite(STDERR, "bench FAIL: $f\n");
}
exit($ok ? 0 : 1);
