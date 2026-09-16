<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

// Pure factory so the TLS option matrix (CA only vs client certs vs verify
// toggle) stays unit-testable without a live TLS-capable database.
function db_options(string $ca, string $cert, string $key, bool $verify): array {
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    // Optional TLS to the database (distributed deployments). Same-host
    // installs leave DB_SSL_CA empty and pay nothing. Certificate
    // verification is on by default and only explicitly disableable.
    if ($ca !== '') {
        $options[PDO::MYSQL_ATTR_SSL_CA] = $ca;
        if ($cert !== '') {
            $options[PDO::MYSQL_ATTR_SSL_CERT] = $cert;
        }
        if ($key !== '') {
            $options[PDO::MYSQL_ATTR_SSL_KEY] = $key;
        }
        if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = $verify;
        }
    }
    return $options;
}

// Separate connection step so the failure path is unit-testable without a
// live database (a refused TCP connect reproduces it exactly).
function db_connect(string $dsn, string $user, string $pass, array $options): PDO {
    $pdo = new PDO($dsn, $user, $pass, $options);
    $pdo->exec("SET time_zone = '+00:00'");
    return $pdo;
}

function get_db(): PDO {
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    try {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=%s',
            DB_HOST, DB_PORT, DB_NAME, DB_CHARSET
        );
        $options = db_options(DB_SSL_CA, DB_SSL_CERT, DB_SSL_KEY, DB_SSL_VERIFY);
        $pdo = db_connect($dsn, DB_USER, DB_PASS, $options);
    } catch (PDOException $e) {
        log_err('DB connection failed: ' . $e->getMessage());
        http_response_code(503);
        die('Service unavailable.');
    }
    return $pdo;
}
