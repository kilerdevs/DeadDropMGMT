<?php
declare(strict_types=1);

// ── Test bootstrap ────────────────────────────────────────────────────────────
// Every *Test.php requires this file first. It isolates the suite from any
// real installation by forcing a dedicated database name, installs an error
// handler that turns warnings/notices into failures, and provides the tiny
// assertion harness (T) — deliberately no PHPUnit, the app has zero deps.

error_reporting(E_ALL);

define('TEST_DB_NAME', getenv('DDMGMT_TEST_DB') ?: 'deaddrops_test');

// Point the app's secret-store env vars at the isolated test database before
// config.php is ever included. Host defaults to TCP loopback so the suite
// works identically on Windows/XAMPP and in CI containers.
if (getenv('DDMGMT_DB_HOST') === false) { putenv('DDMGMT_DB_HOST=127.0.0.1'); }
if (getenv('DDMGMT_DB_PORT') === false) { putenv('DDMGMT_DB_PORT=3306'); }
if (getenv('DDMGMT_DB_USER') === false) { putenv('DDMGMT_DB_USER=root'); }
putenv('DDMGMT_DB_NAME=' . TEST_DB_NAME);
if (getenv('DDMGMT_AES_KEY_HEX') === false) {
    putenv('DDMGMT_AES_KEY_HEX=3f9a1c77e263b7bf1918421d66cbe4e21e011feaac45eae2d1df50a7a28c653b');
}

// CLI processes may not have access to the web server's session dir
$session_dir = sys_get_temp_dir() . '/ddmgmt_test_sessions';
if (!is_dir($session_dir)) { mkdir($session_dir, 0700, true); }
ini_set('session.save_path', $session_dir);

final class T {
    public static int $pass = 0;
    public static int $fail = 0;
    /** @var array<int,string> */
    public static array $messages = [];

    public static function ok(string $name, bool $cond): void {
        if ($cond) { self::$pass++; return; }
        self::$fail++;
        self::$messages[] = "FAIL  $name";
    }

    public static function eq(string $name, mixed $expected, mixed $actual): void {
        if ($expected === $actual) { self::$pass++; return; }
        self::$fail++;
        self::$messages[] = sprintf(
            "FAIL  %s\n      expected: %s\n      actual:   %s",
            $name, var_export($expected, true), var_export($actual, true)
        );
    }

    public static function throws(string $name, callable $fn, string $class = Throwable::class): void {
        try {
            $fn();
            self::ok($name . ' (nothing thrown)', false);
        } catch (Throwable $e) {
            self::ok($name . ' [' . get_class($e) . ']', $e instanceof $class);
        }
    }

    // Prints the per-file summary and returns the process exit code.
    public static function done(): int {
        foreach (self::$messages as $m) { fwrite(STDERR, $m . PHP_EOL); }
        printf("%s: %d passed, %d failed\n", basename($GLOBALS['argv'][0]), self::$pass, self::$fail);
        return self::$fail > 0 ? 1 : 0;
    }
}

// Warnings/notices during tests are failures, not noise.
set_error_handler(static function (int $no, string $str, string $file, int $line): bool {
    throw new ErrorException($str, 0, $no, $file, $line);
});

// Surface fatals even though config.php sets display_errors=0.
register_shutdown_function(static function (): void {
    $e = error_get_last();
    if ($e !== null && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        fwrite(STDERR, sprintf("FATAL %s: %s in %s:%d\n",
            $e['type'], $e['message'], $e['file'], $e['line']));
        exit(255);
    }
});

require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/totp.php';
require_once dirname(__DIR__) . '/includes/cleanup.php';
