<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

// ── RFC 4648 base32 (no padding) — the format TOTP secrets are shared in ──────

function base32_encode(string $data): string {
    if ($data === '') return ''; // str_split('') returned [''] before PHP 8.2
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($data) as $c) { $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT); }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $out  .= $alphabet[bindec($chunk)];
    }
    return $out;
}

function base32_decode(string $b32): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32  = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $b32));
    $bits = '';
    foreach (str_split($b32) as $c) {
        $pos = strpos($alphabet, $c);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) { $out .= chr(bindec($byte)); }
    }
    return $out;
}

// ── RFC 6238 TOTP (SHA1, 6 digits, 30s step) — the defaults every TOTP app
// assumes when you enter a secret manually ─────────────────────────────────

function totp_generate_secret(): string {
    return base32_encode(random_bytes(20)); // 160-bit secret
}

function totp_code(string $secret_b32, ?int $timestamp = null, int $period = 30, int $digits = 6): string {
    $raw = base32_decode($secret_b32);
    // Fail closed on weak secrets: an empty/undecodable/corrupt secret would
    // otherwise HMAC under the empty key — a publicly computable code, so a
    // row with a damaged secret becomes a 2FA bypass for anyone who computes
    // the empty-key TOTP offline. 10 bytes (80 bits) is the minimum the
    // enrollment path can ever produce (160-bit secrets).
    if (strlen($raw) < 10) {
        throw new InvalidArgumentException('TOTP secret too short.');
    }
    if ($period <= 0 || $digits < 6 || $digits > 8) {
        throw new InvalidArgumentException('Invalid TOTP parameters.');
    }
    $counter = intdiv($timestamp ?? time(), $period);
    $bin     = pack('N*', 0, $counter); // 8-byte big-endian counter
    $hash    = hash_hmac('sha1', $bin, $raw, true);
    $offset  = ord($hash[19]) & 0x0F;
    $part    = ((ord($hash[$offset]) & 0x7F) << 24)
             | ((ord($hash[$offset + 1]) & 0xFF) << 16)
             | ((ord($hash[$offset + 2]) & 0xFF) << 8)
             | (ord($hash[$offset + 3]) & 0xFF);
    return str_pad((string)($part % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

// Accepts the current step and one step either side to tolerate clock drift.
// Weak secrets and absurd windows reject as false (never as an exception or
// a hang): a huge $window would otherwise burn millions of HMACs per call.
function totp_verify(string $secret_b32, string $code, int $window = 1, int $period = 30): bool {
    $code = trim($code);
    if (!ctype_digit($code)) return false;
    if ($window < 0 || $window > 5 || $period <= 0) return false;
    for ($i = -$window; $i <= $window; $i++) {
        try {
            $expected = totp_code($secret_b32, time() + $i * $period, $period);
        } catch (InvalidArgumentException $e) {
            return false;
        }
        if (hash_equals($expected, $code)) {
            return true;
        }
    }
    return false;
}

function totp_uri(string $secret_b32, string $account, string $issuer): string {
    $label = rawurlencode($issuer) . ':' . rawurlencode($account);
    return 'otpauth://totp/' . $label
        . '?secret=' . $secret_b32
        . '&issuer=' . rawurlencode($issuer)
        . '&algorithm=SHA1&digits=6&period=30';
}
