<?php
declare(strict_types=1);

// Legacy URL shim: the set_lang action moved behind the dispatcher
// (admin/dispatch.php), which owns the security envelope. Fetch callers keep
// hitting this filename; method and body pass through untouched.
$_GET['action'] = 'set_lang';
require __DIR__ . '/dispatch.php';
