<?php
declare(strict_types=1);

// Child probe for RateLimitConcurrencyTest: spends exactly one attempt from
// the IP budget and reports the count + verdict that THE SINGLE TRANSITION
// produced. Fresh process = fresh settings cache, exactly like a real request.

require_once __DIR__ . '/bootstrap.php';

$_SERVER['REMOTE_ADDR'] = getenv('RL_TEST_IP') ?: '127.0.0.1';

$r = rl_hit('public');
echo json_encode(['count' => $r['count'], 'blocked' => $r['blocked']]);
exit(0);
