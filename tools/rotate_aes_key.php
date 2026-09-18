<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

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

require_once dirname(__DIR__) . '/includes/kernel.php';

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

// Plaintext tokens still in the schema mean the ADR-019 migration has not run:
// there would be nothing to re-index them from, so refuse rather than half-rotate.
$legacyTokens = (int)$db->query(
    "SELECT COUNT(*) FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'order_token'
       AND TABLE_NAME IN ('orders', 'order_events', 'audit_log')"
)->fetchColumn();
if ($legacyTokens > 0) {
    fwrite(STDERR, "Plaintext order_token columns still exist — run tools/migrate_order_tokens.php first.\n");
    exit(1);
}

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

// ── Order tokens (ADR-019) ───────────────────────────────────────────────────
// token_hmac is keyed by a subkey of the MASTER key, so rotating the master
// changes every index. The only plaintext copy is orders.token_enc: each new
// index is computed from it. Event and audit rows carry the OLD index and are
// remapped through it; rows whose order no longer exists cannot be recomputed
// and lose their index (the order is gone — only the correlation is).
$oldIndexKey = rot_hkdf($oldKey, 'deaddrop:token-index-v1');
$newIndexKey = rot_hkdf($newKey, 'deaddrop:token-index-v1');
$tokenMap    = [];
$tokenCount  = 0;

foreach ($db->query('SELECT id, token_hmac, token_enc, token_iv FROM orders')->fetchAll() as $row) {
    if ($row['token_enc'] === null || $row['token_iv'] === null) {
        fwrite(STDERR, sprintf("FAIL orders#%d token_enc: order has no token copy — aborting\n", $row['id']));
        $fail++;
        continue;
    }
    $plain = rot_decrypt($oldKey, 'deaddrop:token-v1', $row['token_enc'], $row['token_iv']);
    if ($plain === false) {
        fwrite(STDERR, sprintf("FAIL orders#%d token_enc: cannot decrypt with OLD key — aborting\n", $row['id']));
        $fail++;
        continue;
    }
    if (!hash_equals((string)$row['token_hmac'], hash_hmac('sha256', strtolower($plain), $oldIndexKey))) {
        fwrite(STDERR, sprintf("FAIL orders#%d token_hmac: index does not match the token under the OLD key — aborting\n", $row['id']));
        $fail++;
        continue;
    }
    $tokenMap[(string)$row['token_hmac']] = [
        'id'   => (int)$row['id'],
        'hmac' => hash_hmac('sha256', strtolower($plain), $newIndexKey),
        'enc'  => $dry ? null : rot_encrypt($newKey, 'deaddrop:token-v1', $plain),
        'plain' => $plain,
    ];
    $tokenCount++;
}

if (!$dry && $fail === 0) {
    foreach (['order_events', 'audit_log'] as $t) {
        $db->exec("UPDATE $t x LEFT JOIN orders o ON o.token_hmac = x.token_hmac
                   SET x.token_hmac = NULL
                   WHERE x.token_hmac IS NOT NULL AND o.id IS NULL");
    }
    $remapEv = $db->prepare('UPDATE order_events SET token_hmac = ? WHERE token_hmac = ?');
    $remapAu = $db->prepare('UPDATE audit_log SET token_hmac = ? WHERE token_hmac = ?');
    $setOrd  = $db->prepare('UPDATE orders SET token_hmac = ?, token_enc = ?, token_iv = ? WHERE id = ?');
    foreach ($tokenMap as $oldHmac => $m) {
        $remapEv->execute([$m['hmac'], $oldHmac]);
        $remapAu->execute([$m['hmac'], $oldHmac]);
        $setOrd->execute([$m['hmac'], $m['enc']['ciphertext'], $m['enc']['iv'], $m['id']]);
        $chk = $db->prepare('SELECT token_hmac, token_enc, token_iv FROM orders WHERE id = ?');
        $chk->execute([$m['id']]);
        $cur = $chk->fetch();
        if (!is_array($cur) || $cur['token_hmac'] !== $m['hmac']
            || rot_decrypt($newKey, 'deaddrop:token-v1', $cur['token_enc'], $cur['token_iv']) !== $m['plain']) {
            fwrite(STDERR, sprintf("FAIL orders#%d token: read-back verification failed\n", $m['id']));
            $fail++;
        }
    }
}
printf("%s %-20s %s rows\n", $dry ? '[dry-run]' : 'rotated ', 'orders.token_enc+hmac', $tokenCount);
$total += $tokenCount;

if ($fail > 0) {
    $db->rollBack();
    fwrite(STDERR, "\nABORTED: $fail row(s) failed — transaction rolled back, nothing changed.\n");
    exit(1);
}
if ($dry) {
    // Nothing was written (all writes sit behind !$dry), but the outer
    // transaction is still open — roll back instead of exiting with it held.
    $db->rollBack();
    printf("\nDry run OK — $total row(s) decryptable with OLD key. Re-run without --dry-run to apply.\n");
    exit(0);
}
$db->commit();
printf("\nDone: $total row(s) re-encrypted under the NEW master's purpose subkeys. Now:\n");
echo <<<EOT
  1. switch DDMGMT_AES_KEY_HEX to the NEW key everywhere and restart the app
  2. destroy every copy of the OLD key
  (the log chain is HMAC-keyed with the master key: entries written under
   the OLD key will not verify under the new one, so verify the chain and
   archive logs/app.log BEFORE switching if you need that history proven)

EOT;
