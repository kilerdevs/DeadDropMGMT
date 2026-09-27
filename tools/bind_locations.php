<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// ── One-time migration: bind stored locations to their order ──────────────────
// New and re-saved orders encrypt the location with the order's token_hmac as
// GCM associated data ("b1:" values, see includes/crypto.php): copied onto
// another row, such a value no longer opens. Rows written before that are
// unbound and still readable; this re-encrypts them bound, so no unbound
// location (which could be swapped between orders by someone with database
// write access) remains.
//
// Idempotent: bound rows are skipped. All-or-nothing: every row is read back
// under its binding before the transaction commits; any failure rolls back.
//
// Usage:  php tools/bind_locations.php [--dry-run]

$options = getopt('', ['dry-run']);
$dry     = isset($options['dry-run']);

require_once dirname(__DIR__) . '/includes/kernel.php';

if (!aes_key_valid()) {
    fwrite(STDERR, aes_key_problem() . "\n");
    exit(1);
}

$db = get_db();
$db->beginTransaction();
$bound   = 0;
$skipped = 0;
$failed  = 0;

// FOR UPDATE: no order may change (or appear, via next-key locks) mid-run.
$rows = $db->query(
    'SELECT id, token_hmac, location_encrypted AS enc, location_iv AS iv FROM orders FOR UPDATE'
)->fetchAll();
$upd = $db->prepare('UPDATE orders SET location_encrypted = ?, location_iv = ? WHERE id = ?');
$chk = $db->prepare('SELECT location_encrypted AS enc, location_iv AS iv FROM orders WHERE id = ?');

foreach ($rows as $row) {
    $enc = (string)$row['enc'];
    if ($enc === '' || str_starts_with($enc, LOCATION_BIND_PREFIX)) {
        $skipped++;
        continue;
    }
    $bind = (string)($row['token_hmac'] ?? '');
    if ($bind === '') {
        fwrite(STDERR, sprintf("FAIL orders#%d: no token_hmac to bind to — run tools/migrate_order_tokens.php first\n", $row['id']));
        $failed++;
        continue;
    }
    $plain = decrypt_location($enc, (string)$row['iv']);
    if ($plain === false) {
        fwrite(STDERR, sprintf("FAIL orders#%d: location does not decrypt with the current key\n", $row['id']));
        $failed++;
        continue;
    }
    if (!$dry) {
        $e = encrypt_location($plain, $bind);
        $upd->execute([$e['ciphertext'], $e['iv'], $row['id']]);
        $chk->execute([$row['id']]);
        $cur = $chk->fetch();
        if (!is_array($cur) || decrypt_location((string)$cur['enc'], (string)$cur['iv'], $bind) !== $plain) {
            fwrite(STDERR, sprintf("FAIL orders#%d: read-back verification failed\n", $row['id']));
            $failed++;
            continue;
        }
    }
    $bound++;
}

if ($failed > 0) {
    $db->rollBack();
    fwrite(STDERR, "\nABORTED: $failed row(s) failed — transaction rolled back, nothing changed.\n");
    exit(1);
}
if ($dry) {
    $db->rollBack();
    printf("[dry-run] %d row(s) would be bound (%d already bound)\n", $bound, $skipped);
    exit(0);
}
$db->commit();
printf("bound %d row(s) (%d already bound)\n", $bound, $skipped);
