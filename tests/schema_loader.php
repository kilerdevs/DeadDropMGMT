<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Loads setup.sql into the isolated test database (DDMGMT_DB_NAME, default
// deaddrops_test). setup.sql hardcodes "deaddrops", so the token is replaced
// with the target database name before execution. Idempotent — safe to rerun.
// Statement splitting and draining live in includes/setup_check.php (shared
// with the web installer); this loader only adds the test-database rewrite.

require_once __DIR__ . '/../includes/setup_check.php';

$name = getenv('DDMGMT_TEST_DB') ?: 'deaddrops_test';
$host = getenv('DDMGMT_DB_HOST') ?: '127.0.0.1';
$port = getenv('DDMGMT_DB_PORT') ?: '3306';
$user = getenv('DDMGMT_DB_USER') ?: 'root';
$pass = getenv('DDMGMT_DB_PASS') !== false ? getenv('DDMGMT_DB_PASS') : '';

$sql = file_get_contents(__DIR__ . '/../setup.sql');
if ($sql === false) {
    fwrite(STDERR, "Cannot read setup.sql\n");
    exit(1);
}
// Replace only the database NAME where it is one: CREATE DATABASE / USE.
// A blanket str_replace would also rewrite the word inside comments, labels,
// or future string literals.
$sql = preg_replace('/(CREATE DATABASE(?: IF NOT EXISTS)?\s+`?)deaddrops(`?(?:\s|;|$))/i', '$1' . $name . '$2', $sql);
$sql = preg_replace('/(^|\n)(\s*USE\s+`?)deaddrops(`?(?:\s|;|$))/i', '$1$2' . $name . '$3', $sql);

try {
    $pdo = new PDO("mysql:host=$host;port=$port;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        // setup.sql's PREPARE/EXECUTE guard blocks return result sets
        (defined('Pdo\\Mysql::ATTR_USE_BUFFERED_QUERY')
            ? constant('Pdo\\Mysql::ATTR_USE_BUFFERED_QUERY')
            : PDO::MYSQL_ATTR_USE_BUFFERED_QUERY) => true,
    ]);
} catch (PDOException $e) {
    fwrite(STDERR, "DB connect failed: {$e->getMessage()}\n");
    exit(1);
}

// Statements in setup.sql are ;-terminated with no DELIMITER blocks or
// semicolons inside string literals, so the shared plain split is safe.
$toRun = [];
foreach (schema_statements($sql, true) as $body) {
    // A least-privilege app user (e.g. the Docker stack's deaddrop) cannot run
    // CREATE DATABASE even with IF NOT EXISTS — skip it when the target
    // already exists; as root (fresh installs) it still runs normally.
    if (str_starts_with($body, 'CREATE DATABASE')) {
        $exists = $pdo->query(
            'SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ' . $pdo->quote($name)
        )->fetchColumn();
        if ((int)$exists > 0) {
            continue;
        }
    }
    $toRun[] = $body;
}
// The shared splitter strips USE (production connects with dbname already);
// the loader connects dbname-less so it can CREATE the database first, and
// therefore selects it explicitly here instead.
$pdo->exec('USE `' . str_replace('`', '``', $name) . '`');
$res = schema_apply($pdo, $toRun);if ($res['error'] !== '') {
    fwrite(STDERR, "Schema statement failed: {$res['error']}\n--\n{$res['statement']}\n--\n");
    exit(1);
}

echo "Schema loaded into `$name`\n";
