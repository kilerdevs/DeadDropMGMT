<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── AES-256-GCM encrypt/decrypt, CBC refusal, passphrase generator ───────────

$plain = 'Spotkanie pod mostem, wejście od rzeki. 52.2297, 21.0122';

// Roundtrip
$enc = encrypt_location($plain);
T::eq('nonce is 24 hex chars (12 bytes)', 24, strlen($enc['iv']));
T::ok('roundtrip returns plaintext', decrypt_location($enc['ciphertext'], $enc['iv']) === $plain);

// Fresh nonce per call → different ciphertexts
$enc2 = encrypt_location($plain);
T::ok('nonces are unique per call', $enc['iv'] !== $enc2['iv']);
T::ok('ciphertexts differ across calls', $enc['ciphertext'] !== $enc2['ciphertext']);

// Tamper detection (GCM auth tag): flipped ciphertext bit, flipped tag bit
$raw  = base64_decode($enc['ciphertext']);
$bad  = $raw; $bad[3] = $bad[3] ^ "\x01";
T::ok('tampered ciphertext rejected', decrypt_location(base64_encode($bad), $enc['iv']) === false);
$bad2 = $raw; $last = strlen($bad2) - 1; $bad2[$last] = $bad2[$last] ^ "\x01";
T::ok('tampered auth tag rejected', decrypt_location(base64_encode($bad2), $enc['iv']) === false);

// Truncated payload / garbage inputs
T::ok('truncated tag rejected', decrypt_location(base64_encode(substr($raw, 0, -1)), $enc['iv']) === false);
T::ok('too-short payload rejected', decrypt_location(base64_encode('abc'), $enc['iv']) === false);
T::ok('invalid base64 rejected', decrypt_location('!!!not-base64!!!', $enc['iv']) === false);
T::ok('odd-length IV rejected', decrypt_location($enc['ciphertext'], 'abc') === false);
T::ok('unsupported IV length rejected', decrypt_location($enc['ciphertext'], str_repeat('ab', 15)) === false);

// Legacy CBC rows are REFUSED at runtime (ADR-003) — unauthenticated
// encryption is never accepted, migrate with tools/migrate_cbc_to_gcm.php.
$cbc_key = hex2bin(AES_KEY_HEX);
$cbc_iv  = random_bytes(16);
$cbc_ct  = openssl_encrypt($plain, 'aes-256-cbc', $cbc_key, OPENSSL_RAW_DATA, $cbc_iv);
T::ok('legacy CBC row REJECTED by runtime decrypt',
    decrypt_location(base64_encode($cbc_ct), bin2hex($cbc_iv)) === false);

// Wrong key: a sibling process encrypts with a different AES key; our runtime
// must refuse to decrypt it (authenticated encryption enforces the key).
$probe = static function (string $mode, string $payloadHex = '', string $ivHex = ''): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/_crypto_wrongkey.php')
         . ' ' . escapeshellarg($mode)
         . ' ' . escapeshellarg($payloadHex) . ' ' . escapeshellarg($ivHex);
    return json_decode(shell_exec($cmd) ?: '{}', true) ?: [];
};
$foreign = $probe('encrypt');
T::ok('wrong-key probe produced ciphertext', isset($foreign['ct'], $foreign['iv']));
if (isset($foreign['ct'], $foreign['iv'])) {
    T::ok('ciphertext from a foreign key is refused',
        decrypt_location($foreign['ct'], $foreign['iv']) === false);
}
$mine = ['ct' => $enc['ciphertext'], 'iv' => $enc['iv']];
$back = $probe('decrypt', bin2hex(base64_decode($mine['ct'])), $mine['iv']);
T::ok('foreign runtime cannot open our ciphertext', ($back['ok'] ?? true) === false);

// Structured location data (JSON inside AES)
$data = ['text' => 'Ławka przy ul. Długiej 5', 'lat' => 52.4082, 'lng' => 16.9335, 'instructions' => 'kod 1234'];
$sdata = encrypt_location_data($data);
$rt = decrypt_location_data($sdata['ciphertext'], $sdata['iv']);
T::ok('structured roundtrip', is_array($rt) && $rt['text'] === $data['text']
    && abs((float)$rt['lat'] - 52.4082) < 1e-9 && abs((float)$rt['lng'] - 16.9335) < 1e-9
    && $rt['instructions'] === 'kod 1234');

// Defaults merged for partial input
$p = encrypt_location_data(['text' => 'only text']);
$pr = decrypt_location_data($p['ciphertext'], $p['iv']);
T::ok('partial data gets defaults', $pr !== false
    && array_key_exists('lat', $pr) && array_key_exists('lng', $pr)
    && array_key_exists('instructions', $pr) && $pr['lat'] === null);

// Pre-schema plain strings still wrap into the schema (schema compat, not CBC)
$gcmOld = encrypt_location('ulica testowa 1');
$pold = decrypt_location_data($gcmOld['ciphertext'], $gcmOld['iv']);
T::ok('legacy plain string wrapped into schema',
    $pold !== false && $pold['text'] === 'ulica testowa 1' && $pold['lat'] === null);

// Password hashing
$h = hash_password('CorrectHorse1!');
T::ok('bcrypt cost 12 prefix', str_starts_with($h, '$2y$12$'));
T::ok('verify correct password', verify_password('CorrectHorse1!', $h));
T::ok('verify wrong password rejected', !verify_password('correcthorse1!', $h));

// Passphrase generator: 6 words + zero-padded 4-digit number + symbol
$seen = [];
for ($i = 0; $i < 300; $i++) {
    $pp = generate_passphrase();
    T::ok("passphrase format [$pp]",
        preg_match('/^(?:[A-Z][a-z]+){6}\d{4}[!@#$%&*+=?]$/', $pp) === 1
        && strlen($pp) >= 22 && strlen($pp) <= 55);
    if (!preg_match('/^(?:[A-Z][a-z]+){6}\d{4}[!@#$%&*+=?]$/', $pp)) { break; }
    $seen[$pp] = true;
}
T::ok('passphrases do not repeat in 300 draws', count($seen) >= 295);

// Entropy budget pinned in code: exactly 256 unique words →
// 6·log2(256) + log2(10000) + log2(10) ≈ 64.61 bits ≥ the promised 64.
$src = file_get_contents(dirname(__DIR__) . '/includes/crypto.php');
preg_match("/static \\\$words = \[(.*?)\];/s", $src, $m);
preg_match_all("/'([a-z]+)'/", $m[1], $w);
$list = $w[1];
T::eq('word list is exactly 256 words', 256, count($list));
T::eq('word list has no duplicates', 256, count(array_unique($list)));
$bits = 6 * log(count(array_unique($list)), 2) + log(10000, 2) + log(10, 2);
T::ok(sprintf('passphrase entropy %.2f bits >= 64', $bits), $bits >= 64.0);

// ── CBC → GCM migration tool, from a representative pre-migration state ──────
$db = get_db();
$db->exec("DELETE FROM orders WHERE order_token LIKE 'cbcmig%'");
$db->prepare(
    "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES ('cbcmigrate001', 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([base64_encode($cbc_ct), bin2hex($cbc_iv)]);
$migId = (int)$db->lastInsertId();

$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/migrate_cbc_to_gcm.php') . ' 2>&1');
$row = $db->prepare('SELECT location_encrypted AS enc, location_iv AS iv FROM orders WHERE id = ?');
$row->execute([$migId]);
$migRow = $row->fetch();
T::eq('migrated row now carries a GCM nonce', 24, strlen((string)$migRow['iv']));
T::ok('migrated row decrypts at runtime',
    decrypt_location($migRow['enc'], $migRow['iv']) === $plain);
T::ok('migration tool reports success', is_string($out) && str_contains($out, 'Done'));

// Second run is a clean no-op
$out2 = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/migrate_cbc_to_gcm.php') . ' 2>&1');
T::ok('re-run finds nothing left to migrate', is_string($out2) && str_contains($out2, '0 row(s)'));

// A corrupt legacy row aborts the whole migration transactionally
$db->exec("DELETE FROM orders WHERE order_token LIKE 'cbcmig%'");
$db->prepare(
    "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES ('cbcmigrate002', 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([base64_encode('corrupt-cbc-ciphertext-not-real'), bin2hex($cbc_iv)]);
$out3 = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/migrate_cbc_to_gcm.php') . ' 2>&1; echo EXIT:$?');
T::ok('undecryptable row aborts migration', is_string($out3) && str_contains($out3, 'ABORTED'));

$db->exec("DELETE FROM orders WHERE order_token LIKE 'cbcmig%'");

// ── HKDF key separation (ADR-016) ─────────────────────────────────────────────
// Every purpose derives its own subkey from the master; cross-purpose reuse
// must be cryptographically impossible, not just unlikely.

// A row encrypted under the RAW master (pre-separation legacy) is refused.
$rawCt = openssl_encrypt($plain, 'aes-256-gcm', hex2bin(AES_KEY_HEX), OPENSSL_RAW_DATA, $nonce = random_bytes(12), $tag);
T::ok('raw-master row REJECTED by runtime decrypt (run tools/separate_keys.php)',
    decrypt_location(base64_encode($rawCt . $tag), bin2hex($nonce)) === false);

// Purpose subkeys are mutually exclusive: a location blob is not a TOTP
// secret, a sealed payload is not a location blob.
$sec = encrypt_secret('TOTPSECRET123456');
T::ok('totp secret roundtrip', decrypt_secret($sec['ciphertext'], $sec['iv']) === 'TOTPSECRET123456');
T::ok('totp blob refused by location decrypt', decrypt_location($sec['ciphertext'], $sec['iv']) === false);
T::ok('location blob refused by totp decrypt', decrypt_secret($enc['ciphertext'], $enc['iv']) === false);

$sealed = seal_payload(['token' => 'PFTOKENDELIVER01']);
T::ok('sealed payload roundtrip', open_payload($sealed) === ['token' => 'PFTOKENDELIVER01']);
T::ok('sealed payload refused by location decrypt', decrypt_location($sealed['ct'], $sealed['iv']) === false);
$bad = $sealed; $bad['ct'] = base64_encode(substr(base64_decode($sealed['ct']), 0, -1));
T::ok('tampered sealed payload rejected wholesale', open_payload($bad) === false);

// Reveal capability is stable per (token, id) and bound to its own subkey.
T::eq('reveal capability deterministic', reveal_capability('TOK', 7), reveal_capability('TOK', 7));
T::ok('reveal capability differs per order', reveal_capability('TOK', 7) !== reveal_capability('TOK', 8));

// Log chain verifies across key generations: a legacy-keyed genesis entry
// followed by a derived-key entry is a valid chain; tampering is still caught.
$tmpLog = sys_get_temp_dir() . '/ddmgmt_chain_test.log';
$mkEntry = static function (array $rec, string $key): string {
    $payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $rec['hash'] = hash_hmac('sha256', $payload, $key);
    return json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
};
$e1 = $mkEntry(['ts' => 'x', 'level' => 'info', 'event' => 'legacy_gen', 'prev' => APP_LOG_GENESIS], _log_key_legacy());
$e2 = $mkEntry(['ts' => 'x', 'level' => 'info', 'event' => 'derived_gen', 'prev' => hash_hmac('sha256', json_encode(['ts' => 'x', 'level' => 'info', 'event' => 'legacy_gen', 'prev' => APP_LOG_GENESIS], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), _log_key_legacy())], _log_key());
file_put_contents($tmpLog, $e1 . "\n" . $e2 . "\n");
[$chainOk, , , $chainWhy] = verify_log_chain($tmpLog);
T::ok('log chain verifies across legacy + derived generations', $chainOk === true);
file_put_contents($tmpLog, str_replace('legacy_gen', 'tampered!', $e1) . "\n" . $e2 . "\n");
[$chainOk2, , , $chainWhy2] = verify_log_chain($tmpLog);
T::ok('tampered legacy-generation entry still detected', $chainOk2 === false && $chainWhy2 !== null);
unlink($tmpLog);

// ── separate_keys.php tool, from a representative pre-separation state ───────
$rawEnc = openssl_encrypt($plain, 'aes-256-gcm', hex2bin(AES_KEY_HEX), OPENSSL_RAW_DATA, $rawNonce = random_bytes(12), $rawTag);
$db->exec("DELETE FROM orders WHERE order_token LIKE 'keysep%'");
$db->prepare(
    "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES ('keysepmigrate1', 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([base64_encode($rawEnc . $rawTag), bin2hex($rawNonce)]);

$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/separate_keys.php') . ' 2>&1');
$row = $db->prepare('SELECT location_encrypted AS enc, location_iv AS iv FROM orders WHERE order_token = ?');
$row->execute(['keysepmigrate1']);
$sepRow = $row->fetch();
T::ok('separated row decrypts at runtime (purpose subkey)',
    decrypt_location($sepRow['enc'], $sepRow['iv']) === $plain);
T::ok('separation tool reports success', is_string($out) && str_contains($out, 'Done'));

// Idempotent: re-run skips rows already under their purpose subkey.
$out2 = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/separate_keys.php') . ' 2>&1');
T::ok('re-run migrates nothing new', is_string($out2) && str_contains($out2, '0 row(s) migrated'));

// A row decryptable by NEITHER key aborts transactionally.
$db->prepare(
    "INSERT INTO orders (order_token, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES ('keysepmigrate2', 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([base64_encode($rawEnc . $rawTag), bin2hex(random_bytes(12))]); // right ct, wrong nonce
$out3 = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/separate_keys.php') . ' 2>&1; echo EXIT:$?');
T::ok('undecryptable row aborts key separation', is_string($out3) && str_contains($out3, 'ABORTED'));

$db->exec("DELETE FROM orders WHERE order_token LIKE 'keysep%'");

exit(T::done());
