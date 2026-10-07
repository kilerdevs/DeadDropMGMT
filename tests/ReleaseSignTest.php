<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Release signing round-trip through the real tool ────────────────────────
// tools/sign_release.php is the only producer of installer-trusted
// signatures (Ed25519, libsodium): keygen → sign → verify must round-trip
// with an EPHEMERAL keypair (never the maintainer key), tampered bytes and
// wrong keys must verify INVALID, and malformed inputs must fail closed
// (exit 1, never a throw). The committed tools/release.pub anchor itself is
// pinned here too: the installer embeds it, so a rotation must update both.

$tmp = sys_get_temp_dir() . '/ddmgmt-sign-' . getmypid();
@mkdir($tmp, 0700, true);

$tool = static function (string ...$args): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/tools/sign_release.php');
    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }
    $out = [];
    $code = 0;
    exec($cmd . ' 2>&1', $out, $code);
    return [$code, implode("\n", $out)];
};

if (!extension_loaded('sodium')) {
    // Shared-host PHP without sodium cannot sign — the installer degrades
    // to the unsigned path there by design, so the suite skips loudly.
    T::ok('sodium missing here — signing untestable, installer degrades to unsigned', true);
    exit(T::done());
}

// Ephemeral identity (note: --keygen refuses to overwrite — fresh dir).
[$code] = $tool('--keygen', $tmp . '/eph');
T::eq('keygen exits 0', 0, $code);
T::ok('key written 0600-ish', is_file($tmp . '/eph.key'));
T::ok('pub written', is_file($tmp . '/eph.pub'));

file_put_contents($tmp . '/pkg.bin', "release-bytes-\0\xff" . random_bytes(64));
[$code] = $tool('sign', $tmp . '/pkg.bin', '--key-file', $tmp . '/eph.key');
T::eq('sign exits 0', 0, $code);
T::ok('sig written', is_file($tmp . '/pkg.bin.sig'));

[$code, $out] = $tool('verify', $tmp . '/pkg.bin', $tmp . '/pkg.bin.sig', '--pubkey', $tmp . '/eph.pub');
T::eq('round-trip verifies', 0, $code);
T::ok('round-trip says VALID', str_contains($out, 'VALID'));

// Tampered package: same sig, flipped byte.
$raw = (string)file_get_contents($tmp . '/pkg.bin');
$raw[0] = chr(ord($raw[0]) ^ 1);
file_put_contents($tmp . '/evil.bin', $raw);
[$code, $out] = $tool('verify', $tmp . '/evil.bin', $tmp . '/pkg.bin.sig', '--pubkey', $tmp . '/eph.pub');
T::eq('tampered bytes exit 1', 1, $code);
T::ok('tampered bytes say INVALID', str_contains($out, 'INVALID'));

// Wrong key: second identity's pubkey.
[$code] = $tool('--keygen', $tmp . '/other');
T::eq('second keygen exits 0', 0, $code);
[$code] = $tool('verify', $tmp . '/pkg.bin', $tmp . '/pkg.bin.sig', '--pubkey', $tmp . '/other.pub');
T::eq('wrong key exits 1', 1, $code);

// Malformed inputs fail closed, never throw.
file_put_contents($tmp . '/short.sig', base64_encode('tiny'));
[$code] = $tool('verify', $tmp . '/pkg.bin', $tmp . '/short.sig', '--pubkey', $tmp . '/eph.pub');
T::eq('short sig exits 1', 1, $code);
file_put_contents($tmp . '/notb64.sig', '!!!not-base64!!!');
[$code] = $tool('verify', $tmp . '/pkg.bin', $tmp . '/notb64.sig', '--pubkey', $tmp . '/eph.pub');
T::eq('non-base64 sig exits 1', 1, $code);
[$code] = $tool('verify', $tmp . '/nope.bin', $tmp . '/pkg.bin.sig', '--pubkey', $tmp . '/eph.pub');
T::eq('missing file exits 1', 1, $code);
[$code] = $tool('sign', $tmp . '/pkg.bin', '--key-file', $tmp . '/eph.pub');
T::eq('signing with a public key refused', 1, $code);
[$code] = $tool('--keygen', $tmp . '/eph');
T::eq('keygen refuses to overwrite', 1, $code);
[$code] = $tool('frobnicate');
T::eq('usage error exits 2', 2, $code);

// The committed trust anchor is a well-formed 32-byte Ed25519 public key —
// the installer embeds this exact value (INST_RELEASE_PUB), so a rotation
// must change both (the minified copy embeds it too — rebuilt by
// tools/build_installer_min.php, freshness-pinned by InstallerMinTest).
$anchor = trim((string)@file_get_contents(dirname(__DIR__) . '/tools/release.pub'));
$anchorBin = base64_decode($anchor, true);
T::ok('committed release.pub is 32-byte base64', is_string($anchorBin) && strlen($anchorBin) === 32);
foreach (['install.php', 'install.min.php'] as $inst) {
    $src = (string)@file_get_contents(dirname(__DIR__) . '/tools/' . $inst);
    $found = preg_match("/INST_RELEASE_PUB\\s*=\\s*'([^']+)'/", $src, $m) === 1 ? ($m[1] ?? '') : '';
    T::eq("installer $inst embeds the committed pubkey", $anchor, $found);
}

foreach (glob($tmp . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir($tmp);

exit(T::done());
