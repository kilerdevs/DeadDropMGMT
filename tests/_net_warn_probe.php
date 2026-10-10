<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Child probe for RateLimitTest: with DDMGMT_TRUST_PROXY=1 and a public
// (untrusted) peer, get_client_ip() must answer the peer AND warn exactly
// once no matter how often it is asked. Prints JSON: {r1, r2, warns} where
// warns is the delta of proxy_headers_untrusted lines in the live log
// across the two calls. (A child process is required: the warn-once guard
// is per-process and the parent suite already tripped it. The delta makes
// the probe immune to other suites truncating or appending the live log.)
require_once __DIR__ . '/bootstrap.php';

$countWarns = static function (): int {
    $n = 0;
    foreach (file(APP_LOG_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        if (str_contains($line, 'proxy_headers_untrusted')) {
            $n++;
        }
    }
    return $n;
};

$_SERVER['REMOTE_ADDR'] = '203.0.113.99';
unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP']);
putenv('DDMGMT_TRUST_PROXY=1');
putenv('DDMGMT_TRUSTED_PROXIES');
putenv('DDMGMT_CLIENT_IP_HEADER');
$before = $countWarns();
$r1 = get_client_ip();
$r2 = get_client_ip();
$after = $countWarns();
echo json_encode(['r1' => $r1, 'r2' => $r2, 'warns' => $after - $before]);
