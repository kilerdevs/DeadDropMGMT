<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

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
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        // Optional TLS to the database (distributed deployments). Same-host
        // installs leave DB_SSL_CA empty and pay nothing. Certificate
        // verification is on by default and only explicitly disableable.
        if (DB_SSL_CA !== '') {
            $options[PDO::MYSQL_ATTR_SSL_CA] = DB_SSL_CA;
            if (DB_SSL_CERT !== '') {
                $options[PDO::MYSQL_ATTR_SSL_CERT] = DB_SSL_CERT;
            }
            if (DB_SSL_KEY !== '') {
                $options[PDO::MYSQL_ATTR_SSL_KEY] = DB_SSL_KEY;
            }
            if (defined('PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT')) {
                $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = DB_SSL_VERIFY;
            }
        }
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        $pdo->exec("SET time_zone = '+00:00'");
    } catch (PDOException $e) {
        log_err('DB connection failed: ' . $e->getMessage());
        http_response_code(503);
        die('Service unavailable.');
    }
    return $pdo;
}
