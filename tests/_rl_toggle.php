<?php
declare(strict_types=1);

// Probe spawned as a child process by RateLimitTest: flips the limiter
// kill switch in a fresh process (get_settings() caches per process),
// then reports rl_status() for the shared test IP/scope as JSON.
// Usage: php _rl_toggle.php <0|1>

require_once __DIR__ . '/bootstrap.php';

set_setting('rate_limit_enabled', $argv[1] ?? '1');
$_SERVER['REMOTE_ADDR'] = getenv('RL_TEST_IP') ?: '198.51.100.77';
echo json_encode(rl_status('test_public'));
