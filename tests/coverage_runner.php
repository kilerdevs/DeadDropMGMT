<?php
declare(strict_types=1);

// Coverage runner: executes every *Test.php inside ONE process with
// php-code-coverage collecting line data over includes/ (the security-critical
// library code). Dev-only — requires `composer install` first.
//
//   php tests/coverage_runner.php              # text summary to stdout
//   php tests/coverage_runner.php --html=out   # also write an HTML report

if (!file_exists(dirname(__DIR__) . '/vendor/autoload.php')) {
    fwrite(STDERR, "Run `composer install` first (dev-only dependency, see composer.json).\n");
    exit(1);
}

use SebastianBergmann\CodeCoverage\CodeCoverage;
use SebastianBergmann\CodeCoverage\Driver\Selector;
use SebastianBergmann\CodeCoverage\Filter;
use SebastianBergmann\CodeCoverage\Report\Html\Html as HtmlReport;
use SebastianBergmann\CodeCoverage\Report\Text as TextReport;

require_once dirname(__DIR__) . '/vendor/autoload.php';

define('T_INPROCESS', 1);
require_once __DIR__ . '/bootstrap.php';

$filter = new Filter();
// php-code-coverage 11.0.12 removed includeDirectory() — enumerate the
// library files explicitly. composer.json pins this exact version so the
// API cannot drift under us again (a silent minor bump broke this once).
$filter->includeFiles(glob(dirname(__DIR__) . '/includes/*.php') ?: []);

$makeCoverage = static fn(): CodeCoverage => new CodeCoverage(
    (new Selector())->forLineCoverage($filter),
    $filter
);

$files = glob(__DIR__ . '/*Test.php');
sort($files);

$totalPass = $totalFail = 0;
$coverages = [];
$suiteOutput = [];

foreach ($files as $file) {
    ob_start();
    echo "=== " . basename($file) . " ===\n";
    T::$pass = T::$fail = 0;
    T::$messages = [];
    $cc = $makeCoverage();
    $cc->start(basename($file));
    try {
        include $file;
        // a suite that returns instead of calling T::done() still exits via exit()
    } catch (TExitSignal $sig) {
        if ($sig->exitCode !== 0) {
            $totalFail++;
        }
    }
    $cc->stop();
    // Buffer and hold EVERY suite output: once anything flushes, PHP considers
    // headers sent and the next suite's session_start() fatals (15 suites of
    // banners eventually overflow the default output buffer). Everything is
    // printed after the last suite, when no session will start again.
    $suiteOutput[] = ob_get_clean();
    $totalPass += T::$pass;
    $totalFail += T::$fail;
    $coverages[] = $cc;
}

echo implode('', $suiteOutput);

// Merge per-suite collections into one report
/** @var CodeCoverage $merged */
$merged = array_shift($coverages);
foreach ($coverages as $cc) {
    $merged->merge($cc);
}

echo "\n" . str_repeat('=', 60) . "\n";
echo (new TextReport(70, 95, false, false))->process($merged, false);

if ($htmlDir = getopt('', ['html:'])['html'] ?? null) {
    (new HtmlReport())->process($merged, $htmlDir);
    echo "HTML report written to {$htmlDir}/\n";
}

// ── Coverage floors: an explicit answer to "did security quality regress?" ───
// The job fails when overall includes/ coverage drops below --min-overall,
// or when any security-critical file drops below --min-critical. Floors are
// printed even on success so drift stays visible.
$opts        = getopt('', ['html:', 'min-overall:', 'min-critical:']);
$minOverall  = isset($opts['min-overall'])  ? (float)$opts['min-overall']  : 0.0;
$minCritical = isset($opts['min-critical']) ? (float)$opts['min-critical'] : 0.0;

if ($minOverall > 0 || $minCritical > 0) {
    // Files where a coverage regression is a security event, not a stats blip.
    $critical = ['auth.php', 'crypto.php', 'db.php', 'order_state.php', 'totp.php', 'wipe.php'];

    $perFile = [];
    $sumExe  = 0;
    $sumRun  = 0;
    $walk = static function ($node) use (&$walk, &$perFile, &$sumExe, &$sumRun): void {
        foreach ($node->filesAndDirectories() as $child) {
            if ($child instanceof \SebastianBergmann\CodeCoverage\Node\Directory) {
                $walk($child);
                continue;
            }
            $exe = $child->numberOfExecutableLines();
            $run = $child->numberOfExecutedLines();
            $sumExe += $exe;
            $sumRun += $run;
            $perFile[basename($child->pathAsString())] = $exe > 0 ? ($run / $exe) * 100 : 100.0;
        }
    };
    $walk($merged->getReport());

    $overall = $sumExe > 0 ? ($sumRun / $sumExe) * 100 : 100.0;
    $fail    = false;

    if ($minOverall > 0) {
        printf("\nFloor check — overall includes/: %.2f%% (floor %.2f%%)\n", $overall, $minOverall);
        if ($overall < $minOverall) {
            fwrite(STDERR, sprintf(
                "COVERAGE FLOOR VIOLATION: overall %.2f%% is below the %.2f%% floor.\n" .
                "Add tests or lower the floor deliberately (and document why).\n",
                $overall, $minOverall
            ));
            $fail = true;
        }
    }

    if ($minCritical > 0) {
        echo "Floor check — security-critical files:\n";
        foreach ($critical as $f) {
            $pct = $perFile[$f] ?? 0.0;
            printf("  %-20s %6.2f%% (floor %.2f%%)\n", $f, $pct, $minCritical);
            if ($pct < $minCritical) {
                fwrite(STDERR, sprintf(
                    "COVERAGE FLOOR VIOLATION: %s at %.2f%% is below the %.2f%% floor.\n",
                    $f, $pct, $minCritical
                ));
                $fail = true;
            }
        }
    }

    if ($fail) {
        exit(2);
    }
}

exit($totalFail > 0 ? 1 : 0);
