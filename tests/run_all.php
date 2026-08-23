<?php
declare(strict_types=1);

// Runs every *Test.php in its own PHP process (isolation for statics,
// sessions and settings caches), aggregates exit codes, exits non-zero
// if any file failed. CI entry point:  php tests/run_all.php

$files = glob(__DIR__ . '/*Test.php');
if (!$files) {
    fwrite(STDERR, "No test files found\n");
    exit(1);
}
sort($files);

$failed = [];
foreach ($files as $file) {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($file);
    $code = 0;
    echo "=== " . basename($file) . " ===\n";
    passthru($cmd, $code);
    if ($code !== 0) {
        $failed[] = basename($file);
    }
}

echo "\n" . count($files) . " suite(s), " . count($failed) . " failed";
if ($failed) {
    echo ': ' . implode(', ', $failed);
}
echo "\n";
exit($failed ? 1 : 0);
