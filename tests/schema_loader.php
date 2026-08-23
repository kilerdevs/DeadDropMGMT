<?php
declare(strict_types=1);

// Loads setup.sql into the isolated test database (DDMGMT_DB_NAME, default
// deaddrops_test). setup.sql hardcodes "deaddrops", so the token is replaced
// with the target database name before execution. Idempotent — safe to rerun.

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
$sql = str_replace('deaddrops', $name, $sql);

try {
    $pdo = new PDO("mysql:host=$host;port=$port;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        // setup.sql's PREPARE/EXECUTE guard blocks return result sets
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
    ]);
} catch (PDOException $e) {
    fwrite(STDERR, "DB connect failed: {$e->getMessage()}\n");
    exit(1);
}

// Statements in setup.sql are ;-terminated with no DELIMITER blocks or
// semicolons inside string literals, so a plain split is safe.
foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
    // Drop comment-only fragments left over after splitting
    $body = implode("\n", array_filter(
        explode("\n", $stmt),
        static fn(string $l): bool => trim($l) !== '' && !str_starts_with(ltrim($l), '--')
    ));
    if ($body === '') {
        continue;
    }
    try {
        // query() + full result-set draining, because setup.sql's
        // PREPARE/EXECUTE guard blocks leave live unbuffered results behind
        $stmt = $pdo->query($body);
        if ($stmt instanceof PDOStatement) {
            while ($stmt->nextRowset()) { /* drain */ }
            $stmt->closeCursor();
        }
    } catch (PDOException $e) {
        fwrite(STDERR, "Schema statement failed: {$e->getMessage()}\n--\n$body\n--\n");
        exit(1);
    }
}

echo "Schema loaded into `$name`\n";
