<?php
declare(strict_types=1);

// Probe used by CryptoTest: runs with a DIFFERENT AES key (set via env before
// bootstrap loads config) to prove ciphertexts are bound to their key.
//   php _crypto_wrongkey.php encrypt
//   php _crypto_wrongkey.php decrypt <payloadHex> <ivHex>
$mode = $argv[1] ?? '';
putenv('DDMGMT_AES_KEY_HEX=' . str_repeat('5a', 32)); // ≠ the test-suite key

require_once __DIR__ . '/bootstrap.php';

if ($mode === 'encrypt') {
    $enc = encrypt_location('probe plaintext');
    echo json_encode(['ct' => $enc['ciphertext'], 'iv' => $enc['iv']]);
    exit(0);
}
if ($mode === 'decrypt') {
    $ct  = base64_encode(hex2bin($argv[2] ?? ''));
    $iv  = $argv[3] ?? '';
    $ok  = decrypt_location($ct, $iv);
    // A foreign key MUST fail; succeeding would be the vulnerability.
    echo json_encode(['ok' => $ok !== false]);
    exit(0);
}
echo '{}';
exit(1);
