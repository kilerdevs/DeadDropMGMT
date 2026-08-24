<?php
declare(strict_types=1);

// ── Legacy CBC → AES-256-GCM migration ────────────────────────────────────────
// Runtime code no longer decrypts AES-256-CBC rows (unauthenticated
// encryption is never accepted). Run this BEFORE deploying a version without
// the CBC fallback, or immediately after — until it completes, legacy rows
// are unreadable by the app.
//
// Converts every remaining CBC ciphertext (orders.location_encrypted,
// users.totp_secret_enc) to authenticated GCM inside one transaction:
// any row that fails to decrypt aborts the whole run with nothing changed.
//
// Usage:  php tools/migrate_cbc_to_gcm.php [--dry-run]
// Point DDMGMT_DB_* at your database (or let config.php provide them).

$options = getopt('', ['dry-run']);
$dry     = isset($options['dry-run']);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

// The ONLY place legacy CBC decryption still exists — migration code, not
// reachable from any HTTP path.
function legacy_cbc_decrypt(string $key, string $ciphertext_b64, string $iv_hex): string|false {
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) !== 32) {
        return false;
    }
    return openssl_decrypt($raw, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, hex2bin($iv_hex));
}

function gcm_encrypt_with(string $key, string $plaintext): array {
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct === false) {
        throw new RuntimeException('encryption failed');
    }
    return ['ciphertext' => base64_encode($ct . $tag), 'iv' => bin2hex($nonce)];
}

$key = hex2bin(AES_KEY_HEX);
if (strlen($key) !== 32) {
    fwrite(STDERR, "AES_KEY_HEX must be 32 bytes (64 hex chars)\n");
    exit(1);
}

$db      = get_db();
$db->beginTransaction();
$total   = 0;
$failed  = 0;

// [table, pk, enc column, iv column]
$targets = [
    ['orders', 'id', 'location_encrypted', 'location_iv'],
    ['users',  'id', 'totp_secret_enc',    'totp_secret_iv'],
];

foreach ($targets as [$table, $pk, $encCol, $ivCol]) {
    // A 32-hex-char IV marks pre-GCM CBC rows (GCM nonces are 24 hex chars).
    $stmt = $db->query(
        "SELECT $pk AS id, $encCol AS enc, $ivCol AS iv
         FROM $table
         WHERE $encCol IS NOT NULL AND $ivCol IS NOT NULL AND LENGTH($ivCol) = 32"
    );
    $upd = $db->prepare("UPDATE $table SET $encCol = ?, $ivCol = ? WHERE $pk = ?");
    $n   = 0;

    foreach ($stmt->fetchAll() as $row) {
        $plain = legacy_cbc_decrypt($key, $row['enc'], $row['iv']);
        if ($plain === false) {
            fwrite(STDERR, sprintf("FAIL %s#%d %s: cannot decrypt with current key\n", $table, $row['id'], $encCol));
            $failed++;
            continue;
        }
        if (!$dry) {
            $e = gcm_encrypt_with($key, $plain);
            $upd->execute([$e['ciphertext'], $e['iv'], $row['id']]);
        }
        $n++;
    }

    printf("%s %-28s %s row(s)\n", $dry ? '[dry-run]' : 'migrated', "$table.$encCol", $n);
    $total += $n;
}

if ($failed > 0) {
    $db->rollBack();
    fwrite(STDERR, "\nABORTED: $failed row(s) failed — transaction rolled back, nothing changed.\n");
    exit(1);
}
if ($dry) {
    printf("\nDry run OK — $total CBC row(s) convertible. Re-run without --dry-run to apply.\n");
    exit(0);
}
$db->commit();
printf("\nDone: $total row(s) converted to AES-256-GCM. The CBC fallback is gone from runtime code.\n");
