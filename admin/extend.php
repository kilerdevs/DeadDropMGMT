<?php
declare(strict_types=1);

// Legacy URL shim: the extend action moved behind the dispatcher
// (admin/dispatch.php), which owns the security envelope. Posted forms keep
// hitting this filename; method and body pass through untouched.
$_GET['action'] = 'extend';
require __DIR__ . '/dispatch.php';
