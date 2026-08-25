<?php
declare(strict_types=1);

// Child probe for StateRaceTest: performs ONE state transition named on the
// command line and reports the outcome as JSON. Fresh process = fresh
// everything, like an independent concurrent request.

require_once __DIR__ . '/bootstrap.php';

$mode = $argv[1] ?? '';
$arg  = $argv[2] ?? '';

switch ($mode) {
    case 'receive':
        $ok = order_receive_atomic($arg);
        break;
    case 'deliver':
        $ok = order_deliver_atomic((int)$arg, 24);
        break;
    case 'delete':
        $res = order_delete_atomic((int)$arg);
        $ok  = $res !== null;
        break;
    default:
        fwrite(STDERR, "unknown mode\n");
        exit(2);
}
echo json_encode(['ok' => $ok]);
