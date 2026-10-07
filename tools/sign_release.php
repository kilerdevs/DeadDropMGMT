<?php
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Entry-point rule (KernelTest): every tools/*.php boots through the kernel
// and pulls no service directly. Signing needs no services (pure sodium),
// but it honors the rule anyway — one line, no exception mechanism.
require_once dirname(__DIR__) . '/includes/kernel.php';

// ── Release signing (Ed25519 detached signatures, libsodium) ────────────────
// The web installer (tools/install.php) downloads release zips over plain
// HTTPS from GitHub: TLS authenticates the TRANSPORT, but a compromised
// mirror, a pasted URL, or a swapped asset would still extract cleanly.
// Detached `<package>.sig` files authenticate the BYTES: the installer
// fetches the sibling .sig, verifies it against the release public key
// embedded in the installer itself (INST_RELEASE_PUB), and refuses to
// extract on mismatch — while an absent .sig (master.zip can never carry
// one) only warns and asks for explicit confirmation.
//
// The committed tools/release.pub is the trust anchor: rotating the key
// means committing a new .pub AND rebuilding the installer (the minified
// copy embeds it). The private key NEVER enters the repo — it lives in
// tools/release.key (gitignored: back it up offline) or in the
// DDMGMT_RELEASE_SIGN_KEY environment variable (base64 secret key, for CI).
//
// Usage:
//   php tools/sign_release.php --keygen <base>
//       Writes <base>.key (0600, base64 secret key) + <base>.pub (base64
//       public key). Refuses to overwrite either.
//   php tools/sign_release.php sign <file> [--key-file <keyfile>]
//       Writes <file>.sig (base64 detached signature). Key from --key-file
//       when given, else DDMGMT_RELEASE_SIGN_KEY (base64) — explicit beats
//       ambient.
//   php tools/sign_release.php verify <file> <sigfile> [--pubkey <pubfile>]
//       Exit 0 when the signature is valid, 1 when it is not. Default
//       pubkey is the committed tools/release.pub.
// Exit codes: 0 success/valid, 1 invalid signature or operational failure,
// 2 usage error.

function rs_sodium(): bool {
    return function_exists('sodium_crypto_sign_detached')
        && function_exists('sodium_crypto_sign_verify_detached')
        && function_exists('sodium_crypto_sign_keypair');
}

function rs_read_key(string $path): ?string {
    $raw = @file_get_contents($path);
    if (!is_string($raw)) {
        return null;
    }
    $bin = base64_decode(trim($raw), true);
    return is_string($bin) ? $bin : null;
}

function rs_main(array $argv): int {
    if (!rs_sodium()) {
        fwrite(STDERR, "libsodium unavailable in this PHP build — cannot sign.\n");
        return 1;
    }
    $cmd = $argv[1] ?? '';
    if ($cmd === '--keygen') {
        $base = $argv[2] ?? '';
        if ($base === '') {
            fwrite(STDERR, "usage: php tools/sign_release.php --keygen <base>\n");
            return 2;
        }
        if (is_file($base . '.key') || is_file($base . '.pub')) {
            fwrite(STDERR, "refusing to overwrite {$base}.key/{$base}.pub\n");
            return 1;
        }
        $kp = sodium_crypto_sign_keypair();
        $sk = sodium_crypto_sign_secretkey($kp);
        $pk = sodium_crypto_sign_publickey($kp);
        if (@file_put_contents($base . '.key', base64_encode($sk) . "\n") === false) {
            fwrite(STDERR, "cannot write {$base}.key\n");
            return 1;
        }
        @chmod($base . '.key', 0600);
        if (@file_put_contents($base . '.pub', base64_encode($pk) . "\n") === false) {
            @unlink($base . '.key');
            fwrite(STDERR, "cannot write {$base}.pub\n");
            return 1;
        }
        fwrite(STDOUT, "wrote {$base}.key (KEEP SECRET, gitignored) + {$base}.pub (commit this)\n");
        sodium_memzero($sk);
        return 0;
    }
    if ($cmd === 'sign') {
        $file = $argv[2] ?? '';
        $keyFile = null;
        foreach ($argv as $i => $a) {
            if ($a === '--key-file' && isset($argv[$i + 1])) {
                $keyFile = $argv[$i + 1];
            }
        }
        if ($file === '' || !is_file($file)) {
            fwrite(STDERR, "usage: php tools/sign_release.php sign <file> [--key-file <keyfile>]\n");
            return 2;
        }
        $sk = null;
        if ($keyFile !== null) {
            $raw = rs_read_key($keyFile);
            if ($raw === null) {
                fwrite(STDERR, "cannot read key from $keyFile\n");
                return 1;
            }
            // A .key file holds the 64-byte SECRET key; a .pub holds the
            // 32-byte public key — signing with a public key is refused.
            if (strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                fwrite(STDERR, "key in $keyFile is not a secret key\n");
                return 1;
            }
            $sk = $raw;
        } else {
            $env = getenv('DDMGMT_RELEASE_SIGN_KEY');
            if (!is_string($env) || $env === '') {
                fwrite(STDERR, "no key: set DDMGMT_RELEASE_SIGN_KEY or pass --key-file\n");
                return 1;
            }
            $raw = base64_decode(trim($env), true);
            if (!is_string($raw) || strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                fwrite(STDERR, "DDMGMT_RELEASE_SIGN_KEY is not a base64 secret key\n");
                return 1;
            }
            $sk = $raw;
        }
        $data = @file_get_contents($file);
        if (!is_string($data)) {
            fwrite(STDERR, "cannot read $file\n");
            return 1;
        }
        $sig = sodium_crypto_sign_detached($data, $sk);
        sodium_memzero($sk);
        sodium_memzero($data);
        if (@file_put_contents($file . '.sig', base64_encode($sig) . "\n") === false) {
            fwrite(STDERR, "cannot write {$file}.sig\n");
            return 1;
        }
        fwrite(STDOUT, "signed $file -> {$file}.sig (" . strlen($sig) . " bytes Ed25519)\n");
        return 0;
    }
    if ($cmd === 'verify') {
        $file = $argv[2] ?? '';
        $sigFile = $argv[3] ?? '';
        $pubFile = dirname(__DIR__) . '/tools/release.pub';
        foreach ($argv as $i => $a) {
            if ($a === '--pubkey' && isset($argv[$i + 1])) {
                $pubFile = $argv[$i + 1];
            }
        }
        if ($file === '' || $sigFile === '') {
            fwrite(STDERR, "usage: php tools/sign_release.php verify <file> <sigfile> [--pubkey <pubfile>]\n");
            return 2;
        }
        $data = @file_get_contents($file);
        // $sigFile is guaranteed non-empty by the usage guard above.
        $sigRaw = rs_read_key($sigFile);
        $pkRaw = rs_read_key($pubFile);
        if (!is_string($data) || $sigRaw === null || $pkRaw === null
            || strlen($sigRaw) !== SODIUM_CRYPTO_SIGN_BYTES
            || strlen($pkRaw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
        ) {
            fwrite(STDOUT, "INVALID ($file)\n");
            return 1;
        }
        $ok = sodium_crypto_sign_verify_detached($sigRaw, $data, $pkRaw);
        fwrite(STDOUT, ($ok ? 'VALID' : 'INVALID') . " ($file)\n");
        return $ok ? 0 : 1;
    }
    fwrite(STDERR, "usage: php tools/sign_release.php (--keygen <base> | sign <file> [--key-file F] | verify <file> <sigfile> [--pubkey F])\n");
    return 2;
}

exit(rs_main($argv));
