<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── AES-256-GCM encrypt/decrypt, legacy CBC fallback, passphrase generator ───

$plain = 'Spotkanie pod mostem, wejście od rzeki. 52.2297, 21.0122';

// Roundtrip
$enc = encrypt_location($plain);
T::eq('nonce is 24 hex chars (12 bytes)', 24, strlen($enc['iv']));
T::ok('roundtrip returns plaintext', decrypt_location($enc['ciphertext'], $enc['iv']) === $plain);

// Fresh nonce per call → different ciphertexts
$enc2 = encrypt_location($plain);
T::ok('nonces are unique per call', $enc['iv'] !== $enc2['iv']);
T::ok('ciphertexts differ across calls', $enc['ciphertext'] !== $enc2['ciphertext']);

// Tamper detection (GCM auth tag)
$raw  = base64_decode($enc['ciphertext']);
$raw[3] = $raw[3] ^ "\x01";
T::ok('tampered ciphertext rejected', decrypt_location(base64_encode($raw), $enc['iv']) === false);

// Truncated tag
T::ok('truncated tag rejected', decrypt_location(base64_encode(substr($raw, 0, -1)), $enc['iv']) === false);

// Garbage inputs
T::ok('invalid base64 rejected', decrypt_location('!!!not-base64!!!', $enc['iv']) === false);
T::ok('odd-length IV rejected', decrypt_location($enc['ciphertext'], 'abc') === false);
T::ok('unsupported IV length rejected', decrypt_location($enc['ciphertext'], str_repeat('ab', 15)) === false);

// Legacy CBC fallback (32-hex-char IV marks pre-GCM rows)
$cbc_key = hex2bin(AES_KEY_HEX);
$cbc_iv  = random_bytes(16);
$cbc_ct  = openssl_encrypt($plain, 'aes-256-cbc', $cbc_key, OPENSSL_RAW_DATA, $cbc_iv);
T::ok('legacy CBC row decrypts',
    decrypt_location(base64_encode($cbc_ct), bin2hex($cbc_iv)) === $plain);

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

// Legacy plain-string payload (pre-schema records)
$pc = openssl_encrypt('ulica testowa 1', 'aes-256-cbc', $cbc_key, OPENSSL_RAW_DATA, $cbc_iv);
$pold = decrypt_location_data(base64_encode($pc), bin2hex($cbc_iv));
T::ok('legacy plain string wrapped into schema',
    $pold !== false && $pold['text'] === 'ulica testowa 1' && $pold['lat'] === null);

// Password hashing
$h = hash_password('CorrectHorse1!');
T::ok('bcrypt cost 12 prefix', str_starts_with($h, '$2y$12$'));
T::ok('verify correct password', verify_password('CorrectHorse1!', $h));
T::ok('verify wrong password rejected', !verify_password('correcthorse1!', $h));

// Passphrase generator: 4 words + 2-digit number + symbol
$seen = [];
for ($i = 0; $i < 300; $i++) {
    $pp = generate_passphrase();
    T::ok("passphrase format [$pp]",
        preg_match('/^(?:[A-Z][a-z]+){4}\d{2}[!@#$%&*+=?]$/', $pp) === 1
        && strlen($pp) >= 15 && strlen($pp) <= 40);
    if (!preg_match('/^(?:[A-Z][a-z]+){4}\d{2}[!@#$%&*+=?]$/', $pp)) { break; }
    $seen[$pp] = true;
}
T::ok('passphrases do not repeat in 300 draws', count($seen) >= 295);

exit(T::done());
