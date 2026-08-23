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
$filter->includeDirectory(dirname(__DIR__) . '/includes');

$makeCoverage = static fn(): CodeCoverage => new CodeCoverage(
    (new Selector())->forLineCoverage($filter),
    $filter
);

$files = glob(__DIR__ . '/*Test.php');
sort($files);

$totalPass = $totalFail = 0;
$coverages = [];

foreach ($files as $file) {
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
    $totalPass += T::$pass;
    $totalFail += T::$fail;
    $coverages[] = $cc;
}

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

exit($totalFail > 0 ? 1 : 0);
