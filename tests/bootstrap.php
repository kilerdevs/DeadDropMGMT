<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

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

final class TExitSignal extends RuntimeException {
    public int $exitCode;
    public function __construct(int $exitCode) {
        $this->exitCode = $exitCode; // no property promotion: harness parses on PHP 8.2+
        parent::__construct('suite finished');
    }
}

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
    // Under the coverage runner (T_INPROCESS defined) a real exit() would kill
    // collection after the first suite, so it throws a signal instead.
    public static function done(): int {
        foreach (self::$messages as $m) { fwrite(STDERR, $m . PHP_EOL); }
        printf("%s: %d passed, %d failed\n", basename($GLOBALS['argv'][0]), self::$pass, self::$fail);
        $code = self::$fail > 0 ? 1 : 0;
        if (defined('T_INPROCESS')) {
            throw new TExitSignal($code);
        }
        return $code;
    }
}

// Warnings/notices during tests are failures, not noise — except where the
// code deliberately suppresses them with @, which we honour.
set_error_handler(static function (int $no, string $str, string $file, int $line): bool {
    if (!(error_reporting() & $no)) {
        return true; // @-suppressed — respect it
    }
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
require_once dirname(__DIR__) . '/includes/i18n.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/totp.php';
require_once dirname(__DIR__) . '/includes/analytics.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/order_state.php';
require_once dirname(__DIR__) . '/includes/wipe.php';
require_once dirname(__DIR__) . '/includes/proxy.php';
require_once dirname(__DIR__) . '/includes/maps.php';
require_once dirname(__DIR__) . '/includes/cleanup.php';
require_once dirname(__DIR__) . '/includes/version.php';

// No suite may ever start the detached proxy healer: it would run real
// discovery (list downloads, public-IP lookup, probes) against the network.
// ProxyHealTest installs its own capturing stand-in.
osm_proxy_heal_spawner(static fn(): bool => false);

// ── Order-token helpers (ADR-019) ─────────────────────────────────────────────
// The database never holds a token in the clear, so tests cannot INSERT or
// match one directly. These helpers keep the raw SQL in the suites readable.

/** [token_hmac, token_enc, token_iv] for an INSERT INTO orders (token_hmac, token_enc, token_iv, …). */
function tk(string $token): array {
    return array_values(token_columns($token));
}

/** Does a live row exist for this token? (looked up through the keyed index) */
function order_row_exists(PDO $db, string $token): bool {
    $st = $db->prepare('SELECT 1 FROM orders WHERE token_hmac = ? LIMIT 1');
    $st->execute([token_index($token)]);
    return (bool)$st->fetchColumn();
}

/** The order id for a token, or null. */
function order_id_for(PDO $db, string $token): ?int {
    $st = $db->prepare('SELECT id FROM orders WHERE token_hmac = ? LIMIT 1');
    $st->execute([token_index($token)]);
    $id = $st->fetchColumn();
    return $id === false ? null : (int)$id;
}

/** Delete the orders (and their events) for the given tokens. */
function purge_orders(PDO $db, array $tokens): void {
    $del  = $db->prepare('DELETE FROM orders WHERE token_hmac = ?');
    $delE = $db->prepare('DELETE FROM order_events WHERE token_hmac = ?');
    foreach ($tokens as $t) {
        $idx = token_index((string)$t);
        $del->execute([$idx]);
        $delE->execute([$idx]);
    }
}

/**
 * Delete every order whose token starts with $prefix. Tokens are stored
 * encrypted, so this opens each display copy — fine for a test database.
 */
function purge_orders_like(PDO $db, string $prefix): void {
    $hits = [];
    foreach ($db->query('SELECT id, token_hmac, token_enc, token_iv FROM orders')->fetchAll() as $r) {
        $plain = order_token_plain($r);
        if ($plain !== null && str_starts_with($plain, $prefix)) {
            $hits[] = $plain;
        }
    }
    purge_orders($db, $hits);
}

/** How many orders have a token starting with $prefix (opens each display copy). */
function orders_count_like(PDO $db, string $prefix): int {
    $n = 0;
    foreach ($db->query('SELECT token_enc, token_iv FROM orders')->fetchAll() as $r) {
        $plain = order_token_plain($r);
        if ($plain !== null && str_starts_with($plain, $prefix)) {
            $n++;
        }
    }
    return $n;
}

/** Number of event rows carrying this token's index. */
function event_count_for(PDO $db, string $token): int {
    $st = $db->prepare('SELECT COUNT(*) FROM order_events WHERE token_hmac = ?');
    $st->execute([token_index($token)]);
    return (int)$st->fetchColumn();
}
