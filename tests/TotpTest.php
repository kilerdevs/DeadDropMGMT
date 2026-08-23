<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Base32 (RFC 4648) and TOTP (RFC 6238, SHA1/6-digit/30s) ──────────────────

// RFC 4648 vectors
T::eq('base32 empty', '', base32_encode(''));
T::eq('base32 "f"', 'MY', base32_encode('f'));
T::eq('base32 "fo"', 'MZXQ', base32_encode('fo'));
T::eq('base32 "foo"', 'MZXW6', base32_encode('foo'));
T::eq('base32 "foobar"', 'MZXW6YTBOI', base32_encode('foobar'));

// Roundtrips incl. lowercase and separator stripping on decode
foreach (['', 'a', 'ab', 'abc', 'abcd', "\x00\xff\x7f secret!", random_bytes(37)] as $blob) {
    T::ok('base32 roundtrip [' . strlen($blob) . ' bytes]',
        base32_decode(base32_encode($blob)) === $blob);
}
T::eq('decode strips junk + lowercase', 'foobar', base32_decode('mzxw6-ytboi ===='));
T::eq('RFC vector decode', 'foobar', base32_decode('MZXW6YTBOI'));

// RFC 6238 SHA-1 test vectors (secret = ASCII "12345678901234567890"),
// truncated to the app's 6 digits.
$secret = base32_encode('12345678901234567890');
$rfc = [
    [59,          '287082'],
    [1111111109,  '081804'],
    [1234567890,  '005924'],
    [2000000000,  '279037'],
    [20000000000, '353130'],
];
foreach ($rfc as [$ts, $code]) {
    T::eq("RFC 6238 vector T=$ts", $code, totp_code($secret, $ts));
}

T::eq('generated secret decodes to 20 bytes', 20, strlen(base32_decode(totp_generate_secret())));

// Verification incl. clock-drift window (±1 step = ±30 s)
$now   = time();
$valid = totp_code($secret, $now);
T::ok('current code accepted', totp_verify($secret, $valid));
T::ok('previous step accepted within window', totp_verify($secret, totp_code($secret, $now - 30)));
T::ok('next step accepted within window', totp_verify($secret, totp_code($secret, $now + 30)));
T::ok('code 3 steps old rejected', !totp_verify($secret, totp_code($secret, $now - 90)));
T::ok('wrong code rejected', !totp_verify($secret, str_repeat('9', 5) . ($valid[5] === '9' ? '8' : '9')));
T::ok('non-numeric code rejected', !totp_verify($secret, 'abcdef'));
T::ok('empty code rejected', !totp_verify($secret, ''));
T::ok('short code rejected', !totp_verify($secret, substr($valid, 0, 5)));

// otpauth URI for QR enrollment
$uri = totp_uri($secret, 'user@example.com', 'DeadDrop');
T::ok('uri scheme+label', str_starts_with($uri, 'otpauth://totp/DeadDrop:user%40example.com'));
T::ok('uri carries secret', str_contains($uri, "secret=$secret"));
T::ok('uri pins algorithm params', str_contains($uri, 'issuer=DeadDrop')
    && str_contains($uri, 'algorithm=SHA1') && str_contains($uri, 'digits=6') && str_contains($uri, 'period=30'));

exit(T::done());
