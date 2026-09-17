<?php
declare(strict_types=1);

// DeadDropMGMT service kernel — the single entry point for admin pages:
//
//     require_once dirname(__DIR__) . '/includes/kernel.php';
//
// The kernel loads config.php (deployment constants, error handling, logger)
// and every service module exactly once. Services stay plain PHP functions —
// the kernel is a loader, not a framework — and each service file keeps its
// own require_once guards, so loading services directly (tests, cron jobs,
// CLI scripts) keeps working unchanged. Centralizing the list here means an
// entry script never maintains its own require block again: adding a new
// service is one line in the manifest below, not a change to N pages.
//
// Shared handles (e.g. the PDO singleton in includes/db.php) stay where they
// are; if one ever needs centralizing, this file is where it moves.

if (defined('DDMGMT_KERNEL')) {
    return;
}
define('DDMGMT_KERNEL', true);

require_once dirname(__DIR__) . '/config.php';

// Service manifest. Load order mirrors the dependency direction (core
// first); every file is require_once-guarded, so the order is belt and
// braces rather than load-bearing.
foreach ([
    'logger',
    'db',
    'net',
    'settings',
    'i18n',
    'auth',
    'crypto',
    'totp',
    'audit',
    'analytics',
    'order_state',
    'proxy',
    'cleanup',
    'wipe',
] as $service) {
    require_once __DIR__ . '/' . $service . '.php';
}
