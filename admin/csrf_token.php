<?php
declare(strict_types=1);

// Legacy-style URL shim: the csrf_token action lives behind the dispatcher
// (admin/dispatch.php), which owns the security envelope.
$_GET['action'] = 'csrf_token';
require __DIR__ . '/dispatch.php';
