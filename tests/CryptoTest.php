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

// Password hashing: Argon2id where the build offers it (PASSWORD_ARGON2ID),
// bcrypt cost 12 where it does not. Old hashes keep verifying either way
// and are upgraded at the next successful login.
$h = hash_password('CorrectHorse1!');
$haveArgon = defined('PASSWORD_ARGON2ID');
T::eq('hash follows the platform policy', $haveArgon ? 'argon2id' : 'bcrypt', (string)(password_get_info($h)['algoName'] ?? ''));
T::ok('verify correct password', verify_password('CorrectHorse1!', $h));
T::ok('verify wrong password rejected', !verify_password('correcthorse1!', $h));
$legacyBcrypt = password_hash('CorrectHorse1!', PASSWORD_BCRYPT, ['cost' => 12]);
T::ok('legacy bcrypt still verifies under either policy', verify_password('CorrectHorse1!', $legacyBcrypt));
T::ok('fresh hash needs no upgrade', !hash_password_needs_upgrade($h));
T::eq('stale hash flagged exactly when argon2id is available',
    $haveArgon, hash_password_needs_upgrade($legacyBcrypt));
$cheapBcrypt = password_hash('CorrectHorse1!', PASSWORD_BCRYPT, ['cost' => 4]);
T::ok('cheap bcrypt always flagged', hash_password_needs_upgrade($cheapBcrypt));
$dummy = auth_dummy_hash();
T::ok('dummy burns (false) without throwing', password_verify('nope', $dummy) === false);
T::eq('dummy costs what real verifies cost', $haveArgon ? 'argon2id' : 'bcrypt',
    (string)(password_get_info($dummy)['algoName'] ?? ''));

// Order capability tokens: 16 chars over the full 62-symbol alphanumeric
// alphabet (16 × log2(62) ≈ 95.3 bits) — hex-only generation used to leave
// ~31 bits of the documented budget on the floor.
$talpha = [];
for ($i = 0; $i < 64; $i++) {
    $tok = generate_order_token();
    T::ok("order token format [$tok]",
        strlen($tok) === 16 && preg_match('/^[0-9A-Za-z]{16}$/', $tok) === 1);
    if (strlen($tok) !== 16 || preg_match('/^[0-9A-Za-z]{16}$/', $tok) !== 1) { break; }
    foreach (str_split($tok) as $ch) { $talpha[$ch] = true; }
}
T::ok('order tokens use the full alphabet, not hex-only', count($talpha) > 16);
T::ok('order tokens do not repeat in 64 draws',
    count(array_unique(array_map(static fn(): string => generate_order_token(), range(1, 64)))) > 60);

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
// The numeric suffix spans the full 0000–9999 range: a collapsed range
// (always 0000) would cost ~13 bits of the promised entropy.
$nums = [];
for ($i = 0; $i < 50; $i++) {
    $nums[] = (int)substr(generate_passphrase(), -5, 4);
}
T::ok('numeric suffix varies across draws', count(array_unique($nums)) > 1);
T::throws('location data rejects invalid UTF-8 with a loud error, not a TypeError',
    static fn() => encrypt_location_data(['text' => "\xff\xfe invalid"]), RuntimeException::class);

// Entropy budget pinned in code: exactly 256 unique words →
// 6·log2(256) + log2(10000) + log2(10) ≈ 64.61 bits ≥ the promised 64.
$src = file_get_contents(dirname(__DIR__) . '/includes/crypto.php');
preg_match("/static \\\$words = \[(.*?)\];/s", $src, $m);
preg_match_all("/'([a-z]+)'/", $m[1], $w);
$list = $w[1];
T::eq('word list is exactly 256 words', 256, count($list));
T::eq('word list has no duplicates', 256, count(array_unique($list)));
// Every dictionary word is reachable: a range starting at 1 would silently
// drop the first word (asserted over 1000 draws — 6000 picks across all six
// word slots — so a missing word fails deterministically, not statistically).
$wordsSeen = [];
for ($i = 0; $i < 1000; $i++) {
    $ppw = generate_passphrase();
    if (preg_match_all('/[A-Z][a-z]+/', $ppw, $wm)) {
        foreach ($wm[0] as $w) {
            $wordsSeen[strtolower($w)] = true;
        }
    }
}
T::ok('first dictionary word reachable', isset($wordsSeen[$list[0]]));
$bits = 6 * log(count(array_unique($list)), 2) + log(10000, 2) + log(10, 2);
T::ok(sprintf('passphrase entropy %.2f bits >= 64', $bits), $bits >= 64.0);

// ── CBC → GCM migration tool, from a representative pre-migration state ──────
$db = get_db();
purge_orders_like($db, 'cbcmig');
$db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, ?, 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([...tk('cbcmigrate001'), base64_encode($cbc_ct), bin2hex($cbc_iv)]);
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
purge_orders_like($db, 'cbcmig');
$db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, ?, 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([...tk('cbcmigrate002'), base64_encode('corrupt-cbc-ciphertext-not-real'), bin2hex($cbc_iv)]);
$out3 = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/migrate_cbc_to_gcm.php') . ' 2>&1; echo EXIT:$?');
T::ok('undecryptable row aborts migration', is_string($out3) && str_contains($out3, 'ABORTED'));

purge_orders_like($db, 'cbcmig');

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

// Flash messages have their own purpose subkey: sealed flashes and TOTP
// secrets cannot be swapped for one another (ADR-016).
$fl = encrypt_flash('Password: SeCr3t&Pass!');
T::ok('flash roundtrip', decrypt_flash($fl['ciphertext'], $fl['iv']) === 'Password: SeCr3t&Pass!');
T::ok('flash blob refused by totp decrypt', decrypt_secret($fl['ciphertext'], $fl['iv']) === false);
T::ok('totp blob refused by flash decrypt', decrypt_flash($sec['ciphertext'], $sec['iv']) === false);
T::ok('flash blob refused by location decrypt', decrypt_location($fl['ciphertext'], $fl['iv']) === false);
T::ok('flash decrypt rejects non-hex IV', decrypt_flash($fl['ciphertext'], str_repeat('g', 24)) === false);

$sealed = seal_payload(['token' => 'PFTOKENDELIVER01']);
T::ok('sealed payload roundtrip', open_payload($sealed) === ['token' => 'PFTOKENDELIVER01']);
T::ok('sealed payload refused by location decrypt', decrypt_location($sealed['ct'], $sealed['iv']) === false);
$bad = $sealed; $bad['ct'] = base64_encode(substr(base64_decode($sealed['ct']), 0, -1));
T::ok('tampered sealed payload rejected wholesale', open_payload($bad) === false);

// The key check the logger and CLI tools rely on, and the config's fallback
// that lets processes without the entrypoint's environment find the key.
T::ok('the test key is a valid master key', aes_key_valid());
T::ok('problem text points at the environment', str_contains(aes_key_problem(), 'DDMGMT_AES_KEY_HEX'));
$kf = sys_get_temp_dir() . '/ddmgmt_keyfile_' . getmypid();
file_put_contents($kf, str_repeat('ab', 32) . "\n");
T::eq('key file is read and trimmed', str_repeat('ab', 32), _key_from_file($kf));
file_put_contents($kf, 'short');
T::eq('malformed key file is ignored', '', _key_from_file($kf));
T::eq('missing key file is ignored', '', _key_from_file($kf . '.nope'));
@unlink($kf);


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
purge_orders_like($db, 'keysep');
$db->prepare(
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, ?, 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([...tk('keysepmigrate1'), base64_encode($rawEnc . $rawTag), bin2hex($rawNonce)]);

$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/separate_keys.php') . ' 2>&1');
$row = $db->prepare('SELECT location_encrypted AS enc, location_iv AS iv FROM orders WHERE token_hmac = ?');
$row->execute([token_index('keysepmigrate1')]);
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
    "INSERT INTO orders (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv,
                         status, delivered_at, expires_at)
     VALUES (?, ?, ?, 'x', ?, ?, 'delivered', NOW(), NOW() + INTERVAL 24 HOUR)"
)->execute([...tk('keysepmigrate2'), base64_encode($rawEnc . $rawTag), bin2hex(random_bytes(12))]); // right ct, wrong nonce
$out3 = shell_exec(escapeshellarg(PHP_BINARY) . ' ' .
    escapeshellarg(dirname(__DIR__) . '/tools/separate_keys.php') . ' 2>&1; echo EXIT:$?');
T::ok('undecryptable row aborts key separation', is_string($out3) && str_contains($out3, 'ABORTED'));

purge_orders_like($db, 'keysep');

// ── Coverage: photo/staging/notes/token helpers' reject paths ───────────────
// Staged-claim rejects junk without touching the disk.
T::ok('claim rejects non-staged rel', photo_staged_claim('nope.jpg', 1) === null);
T::ok('claim rejects order zero', photo_staged_claim('0/ab12cd34.jpg', 0) === null);
T::ok('claim fails closed on missing stage', photo_staged_claim('0/ab12cd34ef56.jpg', 999991) === null);
@rmdir(dirname(__DIR__) . '/uploads/999991');
// A file squatting where the order dir should be fails the claim closed
// (the mkdir fails) — no rename is attempted, nothing is served.
$squat = dirname(__DIR__) . '/uploads/29514';
file_put_contents($squat, 'squat');
T::ok('claim fails closed when order dir is blocked', photo_staged_claim('0/ab12cd34ef56.png', 29514) === null);
@unlink($squat);

$ptd = sys_get_temp_dir() . '/ddmgmt_cov_crypto';
if (!is_dir($ptd)) { mkdir($ptd, 0700, true); }

// Photo-at-rest decrypt rejects malformed envelopes, round-trips good ones.
file_put_contents($ptd . '/bad.json', 'not json{{{');
T::ok('decrypt rejects non-JSON envelope', photo_decrypt_to_temp($ptd . '/bad.json', $ptd . '/o1') === false);
file_put_contents($ptd . '/nokeys.json', json_encode(['v' => 1]));
T::ok('decrypt rejects keyless envelope', photo_decrypt_to_temp($ptd . '/nokeys.json', $ptd . '/o2') === false);
$good = encrypt_photo('cover-bytes');
file_put_contents($ptd . '/badct.json', json_encode(['ct' => '!!!notbase64!!!', 'iv' => $good['iv']]));
T::ok('decrypt rejects bad ciphertext', photo_decrypt_to_temp($ptd . '/badct.json', $ptd . '/o3') === false);
file_put_contents($ptd . '/good.json', json_encode(['ct' => $good['ciphertext'], 'iv' => $good['iv']]));
T::ok('decrypt round-trips sealed photo',
    photo_decrypt_to_temp($ptd . '/good.json', $ptd . '/o4') && file_get_contents($ptd . '/o4') === 'cover-bytes');

// order_notes_plain prefers the encrypted copy, falls back safely.
T::eq('notes prefers encrypted copy', 'enc-note', order_notes_plain(['notes' => 'legacy'], ['notes' => 'enc-note']));
T::eq('notes falls back to legacy column', 'legacy', order_notes_plain(['notes' => 'legacy'], false));
T::eq('notes empty when neither', '', order_notes_plain([], ['notes' => '']));

// Token display copy must belong to its row (swapped-in ciphertext refused).
$tok = bin2hex(random_bytes(16));
$te = encrypt_token($tok);
$cols = token_columns($tok);
T::ok('token copy opens for its own row',
    order_token_plain(['token_enc' => $te['ciphertext'], 'token_iv' => $te['iv'], 'token_hmac' => $cols['token_hmac']]) === $tok);
T::ok('token copy from another row is refused',
    order_token_plain(['token_enc' => $te['ciphertext'], 'token_iv' => $te['iv'], 'token_hmac' => $cols['token_hmac'] . 'x']) === null);

// Thumbnail writer refuses non-images without noise.
file_put_contents($ptd . '/note.txt', 'just text');
T::ok('thumb refuses non-image', _write_thumb($ptd . '/note.txt', $ptd . '/t1.jpg') === false);
file_put_contents($ptd . '/trunc.png',
    "\x89PNG\r\n\x1a\n\x00\x00\x00\x0DIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde");
T::ok('thumb refuses undecodable image', _write_thumb($ptd . '/trunc.png', $ptd . '/t2.jpg') === false);

// Upload pipeline rejects before GD ever decodes.
file_put_contents($ptd . '/tiny.jpg', "\xFF\xD8\xFF\xE0" . 'short');
$badEntry = ['name' => 'x.jpg', 'type' => 'image/jpeg', 'tmp_name' => $ptd . '/tiny.jpg',
    'error' => UPLOAD_ERR_OK, 'size' => 20];
T::ok('undecodable upload rejected', save_uploaded_photo($badEntry, 0) === false);

if (function_exists('imagecreatetruecolor')) {
    // Byte budget is enforced by shrinking, then giving up (never looping).
    $img = imagecreatetruecolor(8, 8);
    imagefill($img, 0, 0, imagecolorallocate($img, 200, 50, 50));
    imagejpeg($img, $ptd . '/small.jpg', 85);
    T::ok('impossible byte budget fails instead of looping forever',
        _compress_image($ptd . '/small.jpg', $ptd . '/small.out.jpg', 'image/jpeg', 50) === false);

    // Long-edge cap tames huge sources up front (2560 px).
    $big = imagecreatetruecolor(3000, 40);
    imagefill($big, 0, 0, imagecolorallocate($big, 10, 200, 90));
    imagejpeg($big, $ptd . '/wide.jpg', 80);
    T::ok('wide source is capped to 2560px',
        _compress_image($ptd . '/wide.jpg', $ptd . '/wide.out.jpg', 'image/jpeg', 12582912)
        && getimagesize($ptd . '/wide.out.jpg')[0] === 2560);

    // Alpha sources keep transparency through the long-edge downscale.
    $alpha = imagecreatetruecolor(2600, 100);
    imagealphablending($alpha, false);
    imagesavealpha($alpha, true);
    imagefill($alpha, 0, 0, imagecolorallocatealpha($alpha, 0, 0, 0, 127));
    imagepng($alpha, $ptd . '/alpha.png');
    $alpha = null; // PHP 8.5 deprecates imagedestroy(); GC frees the GdImage
    T::ok('alpha PNG downscales with transparency intact',
        _compress_image($ptd . '/alpha.png', $ptd . '/alpha.out.png', 'image/png', 12582912)
        && getimagesize($ptd . '/alpha.out.png')[0] === 2560);
    $alphaOut = imagecreatefrompng($ptd . '/alpha.out.png');
    $alphaPx = imagecolorat($alphaOut, 0, 0);
    T::ok('downscaled alpha stays transparent', (($alphaPx >> 24) & 127) === 127);
    $alphaOut = null;

    // Noisy semi-transparent PNG over a tight byte budget: the compressor
    // must resample (not just re-encode), and the resampled output keeps
    // its alpha channel instead of flattening to opaque.
    $noisy = imagecreatetruecolor(600, 600);
    imagealphablending($noisy, false);
    imagesavealpha($noisy, true);
    for ($ny = 0; $ny < 600; $ny += 10) {
        for ($nx = 0; $nx < 600; $nx += 10) {
            $c = imagecolorallocatealpha($noisy, ($nx * 7 + $ny * 13) % 256, ($nx * 3 + $ny) % 256, ($nx + $ny * 11) % 256, 64);
            imagefilledrectangle($noisy, $nx, $ny, $nx + 9, $ny + 9, $c);
        }
    }
    imagepng($noisy, $ptd . '/noisy.png');
    $noisy = null;
    T::ok('noisy alpha PNG shrinks to budget',
        _compress_image($ptd . '/noisy.png', $ptd . '/noisy.out.png', 'image/png', 60000) !== false);
    $noisyOut = imagecreatefrompng($ptd . '/noisy.out.png');
    $noisyPx = imagecolorat($noisyOut, 5, 5);
    T::ok('resampled output keeps its alpha', ((($noisyPx >> 24) & 127) > 0));
    $noisyOut = null;

    // The pixel ceiling multiplies width BY height: a tall 100x5000 strip is
    // half a megapixel (accepted), even though height alone squared is not.
    $tall = imagecreatetruecolor(100, 5000);
    imagefill($tall, 0, 0, imagecolorallocate($tall, 90, 10, 200));
    imagejpeg($tall, $ptd . '/tall.jpg', 80);
    $tall = null;
    $tallEntry = ['name' => 'tall.jpg', 'type' => 'image/jpeg', 'tmp_name' => $ptd . '/tall.jpg',
        'error' => UPLOAD_ERR_OK, 'size' => filesize($ptd . '/tall.jpg')];
    $tallRel = save_uploaded_photo($tallEntry, 0);
    T::ok('tall strip passes the pixel ceiling', $tallRel !== false);
    if (is_string($tallRel)) {
        @unlink(dirname(__DIR__) . '/uploads/' . $tallRel);
        @rmdir(dirname(__DIR__) . '/uploads/0');
    }

    // A file squatting where the order dir should be fails the upload closed.
    $ublock = dirname(__DIR__) . '/uploads/29515';
    file_put_contents($ublock, 'squat');
    $blockedEntry = ['name' => 'x.jpg', 'type' => 'image/jpeg', 'tmp_name' => $ptd . '/small.jpg',
        'error' => UPLOAD_ERR_OK, 'size' => filesize($ptd . '/small.jpg')];
    T::ok('upload fails closed when order dir is blocked',
        save_uploaded_photo($blockedEntry, 29515) === false);
    @unlink($ublock);
}

foreach (glob($ptd . '/*') ?: [] as $f) { @unlink($f); }
@rmdir($ptd);

exit(T::done());
