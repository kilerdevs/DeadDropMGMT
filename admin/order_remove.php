<?php
declare(strict_types=1);

// Legacy URL shim: the order_remove action moved behind the dispatcher
// (admin/dispatch.php), which owns the security envelope. Posted forms keep
// hitting this filename; method and body pass through untouched.
$_GET['action'] = 'order_remove';
require __DIR__ . '/dispatch.php';
