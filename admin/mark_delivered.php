<?php
declare(strict_types=1);

// Legacy URL shim: the mark_delivered action moved behind the dispatcher
// (admin/dispatch.php), which owns the security envelope. Posted forms keep
// hitting this filename; method and body pass through untouched.
$_GET['action'] = 'mark_delivered';
require __DIR__ . '/dispatch.php';
