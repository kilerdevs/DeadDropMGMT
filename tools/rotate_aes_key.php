<?php
declare(strict_types=1);

// ── AES key rotation tool ─────────────────────────────────────────────────────
// Re-encrypts every encrypted column with a new key, verifying each row
// decrypts cleanly with the OLD key before rewriting anything.
//
// Usage:
//   php tools/rotate_aes_key.php --old=<64hex> --new=<64hex> [--dry-run]
//
// Both keys are explicit arguments on purpose — no ordering games with
// config/env. Point DDMGMT_DB_* at your database (or let them come from
// config.php). Wrap in a maintenance window: nothing should write while
// rotating. See README "Rotating the AES key".

$options = getopt('', ['old:', 'new:', 'dry-run']);
$old = strtolower(trim($options['old'] ?? ''));
$new = strtolower(trim($options['new'] ?? ''));
$dry = isset($options['dry-run']);

foreach (['--old' => $old, '--new' => $new] as $flag => $hex) {
    if (!preg_match('/^[0-9a-f]{64}$/', $hex)) {
        fwrite(STDERR, "$flag must be 64 hex chars (32 bytes)\n");
        exit(1);
    }
}
if ($old === $new) {
    fwrite(STDERR, "--old and --new are identical\n");
    exit(1);
}

$oldKey = hex2bin($old);
$newKey = hex2bin($new);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';

// Same wire format as includes/crypto.php, but keyed explicitly — the app's
// AES_KEY_HEX points at whichever key is currently deployed, not necessarily
// old or new during the migration window. Since ADR-016 key separation the
// runtime derives purpose subkeys via HKDF, so encryption targets the NEW
// master's subkey for the given purpose; decryption tries the OLD master's
// subkey first, then the raw OLD master (rows predating key separation).
function rot_hkdf(string $master, string $info): string {
    return hash_hkdf('sha256', $master, 32, $info, 'deaddrop-mgmt-hkdf-salt-v1');
}

function rot_decrypt(string $oldKey, ?string $info, string $ciphertext_b64, string $iv_hex): string|false {
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) % 2 !== 0) {
        return false;
    }
    $open = function (string $key) use ($raw, $iv_hex): string|false {
        if (strlen($iv_hex) === 24) { // GCM: nonce + appended tag
            if (strlen($raw) < 16) return false;
            return openssl_decrypt(substr($raw, 0, -16), 'aes-256-gcm', $key,
                OPENSSL_RAW_DATA, hex2bin($iv_hex), substr($raw, -16));
        }
        if (strlen($iv_hex) !== 32) return false; // legacy CBC
        return openssl_decrypt($raw, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, hex2bin($iv_hex));
    };
    if ($info !== null) {
        $plain = $open(rot_hkdf($oldKey, $info));
        if ($plain !== false) {
            return $plain;
        }
    }
    return $open($oldKey);
}

function rot_encrypt(string $newKey, ?string $info, string $plaintext): array {
    // null info = legacy column no longer read by the runtime; keep raw keying.
    $key  = $info !== null ? rot_hkdf($newKey, $info) : $newKey;
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct === false) throw new RuntimeException('encryption failed');
    return ['ciphertext' => base64_encode($ct . $tag), 'iv' => bin2hex($nonce)];
}

$db = get_db();
$db->beginTransaction();
$total = 0;
$fail  = 0;

// [table, pk, enc column, iv column, HKDF info, nullable-iv] — info strings
// match includes/crypto.php purpose subkeys; null means the column is legacy
// (unreadable by current runtime) and stays keyed with the raw master.
$targets = [
    ['orders', 'id', 'location_encrypted',  'location_iv',        'deaddrop:location-v1', false],
    ['orders', 'id', 'pickup_password_enc', 'pickup_password_iv',  null,                   true],
    ['users',  'id', 'totp_secret_enc',     'totp_secret_iv',      'deaddrop:totp-v1',     true],
];

foreach ($targets as [$table, $pk, $encCol, $ivCol, $info, $nullable]) {
    $stmt = $db->query("SELECT $pk AS id, $encCol AS enc, $ivCol AS iv FROM $table WHERE $encCol IS NOT NULL");
    $upd  = $db->prepare("UPDATE $table SET $encCol = ?, $ivCol = ? WHERE $pk = ?");
    $n = 0;

    foreach ($stmt->fetchAll() as $row) {
        if ($row['enc'] === null || ($nullable && $row['iv'] === null)) continue;
        $plain = rot_decrypt($oldKey, $info, $row['enc'], $row['iv']);
        if ($plain === false) {
            fwrite(STDERR, sprintf("FAIL %s#%d %s: cannot decrypt with OLD key — aborting\n", $table, $row['id'], $encCol));
            $fail++;
            continue;
        }
        if (!$dry) {
            $e = rot_encrypt($newKey, $info, $plain);
            $upd->execute([$e['ciphertext'], $e['iv'], $row['id']]);
            // read-back sanity: the row must now decrypt with the NEW key
            $chk = $db->prepare("SELECT $encCol AS enc, $ivCol AS iv FROM $table WHERE $pk = ?");
            $chk->execute([$row['id']]);
            $cur = $chk->fetch();
            if (rot_decrypt($newKey, $info, $cur['enc'], $cur['iv']) !== $plain) {
                fwrite(STDERR, sprintf("FAIL %s#%d %s: read-back verification failed\n", $table, $row['id'], $encCol));
                $fail++;
                continue;
            }
        }
        $n++;
    }
    printf("%s %-20s %s rows\n", $dry ? '[dry-run]' : 'rotated ', "$table.$encCol", $n);
    $total += $n;
}

if ($fail > 0) {
    $db->rollBack();
    fwrite(STDERR, "\nABORTED: $fail row(s) failed — transaction rolled back, nothing changed.\n");
    exit(1);
}
if ($dry) {
    printf("\nDry run OK — $total row(s) decryptable with OLD key. Re-run without --dry-run to apply.\n");
    exit(0);
}
$db->commit();
printf("\nDone: $total row(s) re-encrypted under the NEW master's purpose subkeys. Now:\n");
echo <<<EOT
  1. switch DDMGMT_AES_KEY_HEX to the NEW key everywhere and restart the app
  2. destroy every copy of the OLD key
  (the log-integrity chain verifies entries from both the old and new
   key generations, so app.log history stays verifiable)

EOT;
