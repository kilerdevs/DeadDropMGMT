<?php
declare(strict_types=1);

// BenchBudgetsTest — the Phase G cliff-detector gate only works if the
// budgets file covers exactly the harness scenarios. This pins that: every
// `bench.php --list` id has a positive numeric budget with a documented
// reason, and no budget is orphaned (a renamed scenario can't silently
// escape the gate). Fast and side-effect free (--list seeds nothing).

require_once __DIR__ . '/bootstrap.php';

$raw = @file_get_contents(__DIR__ . '/bench-budgets.json');
T::ok('budgets file parses', is_string($raw) && is_array(json_decode($raw, true)));
/** @var array<string,array{max_s?:mixed,why?:mixed}> $budgets */
$budgets = json_decode((string)$raw, true);

$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/tools/bench.php') . ' --list 2>&1';
exec($cmd, $out, $code);
T::eq('harness lists its scenarios', 0, $code);
$ids = array_values(array_filter(array_map('trim', $out)));

sort($ids);
$keys = array_keys($budgets);
sort($keys);
T::eq('budgets cover exactly the scenarios', $ids, $keys);
foreach ($budgets as $id => $b) {
    T::ok("budget $id is a positive number", isset($b['max_s']) && is_numeric($b['max_s']) && (float)$b['max_s'] > 0);
    T::ok("budget $id documents its rationale", isset($b['why']) && is_string($b['why']) && trim($b['why']) !== '');
}

exit(T::done());
