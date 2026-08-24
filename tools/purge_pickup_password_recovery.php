<?php
declare(strict_types=1);

// ── Purge recoverable pickup-password copies ──────────────────────────────────
// Older versions stored an AES-encrypted copy of every pickup password for
// admin display. Pickup credentials are now hash-only: shown once at order
// creation, replaceable (edit form) but never recoverable. This tool clears
// any leftover encrypted copies from the database.
//
// Idempotent and safe to re-run.
//
// Usage:  php tools/purge_pickup_password_recovery.php [--dry-run]

$options = getopt('', ['dry-run']);
$dry     = isset($options['dry-run']);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

$db = get_db();

$count = (int)$db->query(
    'SELECT COUNT(*) FROM orders WHERE pickup_password_enc IS NOT NULL OR pickup_password_iv IS NOT NULL'
)->fetchColumn();

if ($count === 0) {
    echo "Nothing to purge — no recoverable pickup-password copies present.\n";
    exit(0);
}

if ($dry) {
    echo "[dry-run] $count order(s) still carry a recoverable pickup-password copy.\n";
    exit(0);
}

$db->beginTransaction();
try {
    $db->exec('UPDATE orders SET pickup_password_enc = NULL, pickup_password_iv = NULL');
    $db->commit();
} catch (Exception $e) {
    if ($db->inTransaction()) {
        $db->rollBack();
    }
    fwrite(STDERR, 'Purge failed, nothing changed: ' . $e->getMessage() . "\n");
    exit(1);
}

printf("Done: %d order(s) purged. Pickup passwords are hash-only from here on.\n", $count);
