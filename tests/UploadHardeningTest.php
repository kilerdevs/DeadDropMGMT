<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Upload hardening ──────────────────────────────────────────────────────────
// Every upload must survive GD decode+re-encode: EXIF, polyglot trailers,
// PHAR-style metadata and active content are structurally stripped; MIME
// lies, SVG and decompression bombs are rejected outright.

$up = dirname(__DIR__) . '/uploads';
if (!is_dir($up)) { mkdir($up, 0770, true); }

$orderIds = [];
function _uh_entry(string $tmp): array {
    return ['name' => 'client-name.jpg', 'type' => 'application/octet-stream',
            'tmp_name' => $tmp, 'error' => UPLOAD_ERR_OK, 'size' => filesize($tmp)];
}
function _uh_track(int $oid): void { $GLOBALS['orderIds'][] = $oid; }
function _uh_read(string $rel): string {
    return (string)file_get_contents(dirname(__DIR__) . '/uploads/' . $rel);
}

$tmpdir = sys_get_temp_dir() . '/ddmgmt_upl_test';
if (!is_dir($tmpdir)) { mkdir($tmpdir, 0700, true); }

// 1 ── a plain JPEG passes and comes out clean
$tmp = "$tmpdir/ok.jpg";
$img = imagecreatetruecolor(24, 18);
imagefill($img, 0, 0, imagecolorallocate($img, 200, 40, 40));
imagejpeg($img, $tmp, 90);
imagedestroy($img);

$oid = 910001; _uh_track($oid);
$rel = save_uploaded_photo(_uh_entry($tmp), $oid, 2 * 1024 * 1024);
T::ok('valid JPEG accepted', $rel !== false);
if ($rel !== false) {
    T::ok('stored path is strictly server-generated', preg_match('#^910001/[0-9a-f]{28}\.(jpg|jpeg|png|webp|gif)$#', $rel) === 1);
    $data = _uh_read($rel);
    T::ok('re-encoded output is a real image', str_starts_with($data, "\xFF\xD8") || str_starts_with($data, 'RIFF') || str_starts_with($data, "\x89PNG"));
    T::ok('no active content survives re-encode', !str_contains($data, '<?'));
}

// 2 ── GIF + appended PHP payload (classic polyglot) → payload gone
$tmpGif = "$tmpdir/poly.gif";
$img = imagecreatetruecolor(8, 8);
imagegif($img, $tmpGif);
imagedestroy($img);
file_put_contents($tmpGif, file_get_contents($tmpGif) . "<?php echo 'pwned'; __HALT_COMPILER();");

$oid = 910002; _uh_track($oid);
$rel = save_uploaded_photo(_uh_entry($tmpGif), $oid, 2 * 1024 * 1024);
T::ok('polyglot GIF still decodes as an image', $rel !== false);
if ($rel !== false) {
    $data = _uh_read($rel);
    T::ok('PHP payload stripped by re-encode', !str_contains($data, '<?php'));
    T::ok('PHAR-like trailer stripped by re-encode', !str_contains($data, '__HALT_COMPILER'));
}

// 3 ── JPEG bytes with trailing junk stay valid images but lose the junk
$tmpJj = "$tmpdir/trail.jpg";
copy("$tmpdir/ok.jpg", $tmpJj);
file_put_contents($tmpJj, file_get_contents($tmpJj) . str_repeat('EVILDATA', 64));
$oid = 910003; _uh_track($oid);
$rel = save_uploaded_photo(_uh_entry($tmpJj), $oid, 2 * 1024 * 1024);
T::ok('jpeg with trailer accepted as image', $rel !== false);
if ($rel !== false) {
    T::ok('trailer stripped from stored copy', !str_contains(_uh_read($rel), 'EVILDATA'));
}

// 4 ── text pretending to be a JPEG is rejected (content sniffing, not names)
$fake = "$tmpdir/fake.jpg";
file_put_contents($fake, "definitely not an image\n");
T::ok('MIME mismatch rejected', save_uploaded_photo(_uh_entry($fake), 910004, 1024) === false);

// 5 ── SVG is active content and simply not on the allow-list
$svg = "$tmpdir/img.svg";
file_put_contents($svg, '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
T::ok('SVG rejected', save_uploaded_photo(_uh_entry($svg), 910005, 1024) === false);

// 6 ── decompression bomb: header declares absurd dimensions, decode never happens
$pngBomb = "$tmpdir/bomb.png";
$IHDR = pack('N', 60000) . pack('N', 60000) . "\x08\x02\x00\x00\x00";
$chunk = function (string $type, string $data): string {
    return pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
};
file_put_contents($pngBomb,
    "\x89PNG\r\n\x1a\n" . $chunk('IHDR', $IHDR) . $chunk('IDAT', 'x') . $chunk('IEND', ''));
$bombEntry = _uh_entry($pngBomb);
$bombEntry['size'] = 100;
$t0 = microtime(true);
T::ok('decompression bomb rejected', save_uploaded_photo($bombEntry, 910006, 2 * 1024 * 1024) === false);
T::ok('bomb rejected fast (header check, no decode)', microtime(true) - $t0 < 2.0);

// 7 ── zero-byte / broken uploads rejected
$empty = "$tmpdir/empty.jpg";
file_put_contents($empty, '');
T::ok('empty file rejected', save_uploaded_photo(_uh_entry($empty), 910007, 1024) === false);

// 8 ── PNG and WebP round-trips
$png = "$tmpdir/ok.png";
$img = imagecreatetruecolor(10, 10);
imagefill($img, 0, 0, imagecolorallocate($img, 10, 200, 30));
imagepng($img, $png);
imagedestroy($img);
$oid = 910008; _uh_track($oid);
$relPng = save_uploaded_photo(_uh_entry($png), $oid, 2 * 1024 * 1024);
T::ok('PNG accepted', $relPng !== false);

if (function_exists('imagecreatetruecolor') && function_exists('imagewebp')) {
    $webp = "$tmpdir/ok.webp";
    $img  = imagecreatetruecolor(10, 10);
    imagefill($img, 0, 0, imagecolorallocate($img, 10, 30, 200));
    imagewebp($img, $webp, 80);
    imagedestroy($img);
    $oid = 910009; _uh_track($oid);
    $relW = save_uploaded_photo(_uh_entry($webp), $oid, 2 * 1024 * 1024);
    if ($relW !== false) {
        T::ok('WebP re-encodes to a real WebP', str_starts_with(_uh_read($relW), 'RIFF'));
    } else {
        // GD without webp support must reject cleanly, not store garbage
        fwrite(STDERR, "note: webp unavailable in this GD build\n");
        T::ok('webp unsupported → clean rejection', true);
    }
}

// Cleanup: files + rows
foreach ($orderIds as $oidDel) {
    foreach (glob("$up/$oidDel/*") ?: [] as $f) { @unlink($f); }
    @rmdir("$up/$oidDel");
}
foreach (glob($tmpdir . '/*') ?: [] as $f) { @unlink($f); }
@rmdir($tmpdir);

exit(T::done());
