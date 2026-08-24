<?php
declare(strict_types=1);

// ── One-time migration: raw master key → HKDF purpose subkeys (ADR-016) ───────
// Older versions encrypted location data and TOTP secrets directly with the
// master key. The runtime now refuses raw-master rows and expects rows keyed
// with the per-purpose subkeys derived from the same master (HKDF-SHA256).
// Run this ONCE after deploying the new code — until it completes, existing
// orders and TOTP secrets are unreadable by the app (loudly, not silently).
//
// Idempotent: rows already under their purpose subkey are skipped, so a
// re-run never double-migrates. Any row that decrypts with NEITHER the
// purpose subkey NOR the raw master aborts the whole run — nothing changes.
//
// Usage:  php tools/separate_keys.php [--dry-run]
// Run tools/migrate_cbc_to_gcm.php FIRST if pre-GCM rows may exist.

$options = getopt('', ['dry-run']);
$dry     = isset($options['dry-run']);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/crypto.php';

$master = hex2bin(AES_KEY_HEX);
if (strlen($master) !== 32) {
    fwrite(STDERR, "AES_KEY_HEX must be 32 bytes (64 hex chars)\n");
    exit(1);
}

// Legacy decryption: GCM keyed with the RAW master — exists only here,
// unreachable from any HTTP path (same policy as legacy CBC).
function raw_master_decrypt(string $key, string $ciphertext_b64, string $iv_hex): string|false {
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) !== 24 || strlen($raw) < 16) {
        return false;
    }
    return openssl_decrypt(
        substr($raw, 0, -16), 'aes-256-gcm', $key,
        OPENSSL_RAW_DATA, hex2bin($iv_hex), substr($raw, -16)
    );
}

$db      = get_db();
$db->beginTransaction();
$total   = 0;
$skipped = 0;
$failed  = 0;

// [table, pk, enc column, iv column, purpose encryptor]
$targets = [
    ['orders', 'id', 'location_encrypted', 'location_iv', 'encrypt_location'],
    ['users',  'id', 'totp_secret_enc',    'totp_secret_iv', 'encrypt_secret'],
];

foreach ($targets as [$table, $pk, $encCol, $ivCol, $encryptFn]) {
    // NULL iv = row has nothing stored (nullable TOTP columns) — skip quietly.
    $stmt = $db->query(
        "SELECT $pk AS id, $encCol AS enc, $ivCol AS iv
         FROM $table WHERE $encCol IS NOT NULL AND $ivCol IS NOT NULL"
    );
    $upd = $db->prepare("UPDATE $table SET $encCol = ?, $ivCol = ? WHERE $pk = ?");
    $n   = 0;

    foreach ($stmt->fetchAll() as $row) {
        // Already under the purpose subkey? (idempotent re-run / fresh install)
        $plain = $encryptFn === 'encrypt_location'
            ? decrypt_location($row['enc'], $row['iv'])
            : decrypt_secret($row['enc'], $row['iv']);
        if ($plain !== false) {
            $skipped++;
            continue;
        }

        // Legacy raw-master row → re-encrypt under the purpose subkey.
        $legacy = raw_master_decrypt($master, $row['enc'], $row['iv']);
        if ($legacy === false) {
            fwrite(STDERR, sprintf(
                "FAIL %s#%d %s: decrypts with neither the purpose subkey nor the raw master key\n",
                $table, $row['id'], $encCol
            ));
            $failed++;
            continue;
        }

        if (!$dry) {
            $e   = $encryptFn($legacy);
            $upd->execute([$e['ciphertext'], $e['iv'], $row['id']]);
            // read-back sanity under the NEW subkey
            $chk = $db->prepare("SELECT $encCol AS enc, $ivCol AS iv FROM $table WHERE $pk = ?");
            $chk->execute([$row['id']]);
            $cur = $chk->fetch();
            $rt  = $encryptFn === 'encrypt_location'
                ? decrypt_location($cur['enc'], $cur['iv'])
                : decrypt_secret($cur['enc'], $cur['iv']);
            if ($rt !== $legacy) {
                fwrite(STDERR, sprintf("FAIL %s#%d %s: read-back verification failed\n", $table, $row['id'], $encCol));
                $failed++;
                continue;
            }
        }
        $n++;
    }
    printf("%s %-20s %s row(s) migrated (%d already current)\n", $dry ? '[dry-run]' : 'migrated', "$table.$encCol", $n, $skipped);
    $total   += $n;
    $skipped  = 0;
}

if ($failed > 0) {
    $db->rollBack();
    fwrite(STDERR, "\nABORTED: $failed row(s) failed — transaction rolled back, nothing changed.\n");
    exit(1);
}
if ($dry) {
    printf("\nDry run OK — $total row(s) convertible. Re-run without --dry-run to apply.\n");
    exit(0);
}
$db->commit();
printf("\nDone: $total row(s) now keyed with HKDF purpose subkeys. The raw master key is no longer used for encryption anywhere.\n");
