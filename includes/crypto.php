<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

// ── Key separation (HKDF, ADR-016) ────────────────────────────────────────────
// AES_KEY_HEX is a MASTER key and is never used for encryption directly.
// Every purpose derives its own 32-byte subkey via HKDF-SHA256 with a fixed
// public salt and a purpose-bound info string:
//
//   master ─┬─ location-v1    orders.location_encrypted
//           ├─ totp-v1        users.totp_secret_enc
//           ├─ reveal-v1      sealed session payloads
//           ├─ capability-v1  reveal capability MAC
//           └─ log-hmac-v1    app.log integrity chain
//
// Compromise or rotation of one subsystem's key no longer couples the others.
// The salt is public by design (RFC 5869): all secret material flows from the
// master key alone.

const HKDF_SALT = 'deaddrop-mgmt-hkdf-salt-v1';

function _master_key(): string {
    $key = hex2bin(AES_KEY_HEX);
    if (strlen($key) !== 32) {
        throw new RuntimeException('AES key must be 32 bytes (64 hex chars).');
    }
    return $key;
}

function _derived_key(string $info): string {
    static $cache = [];
    if (!isset($cache[$info])) {
        $cache[$info] = hash_hkdf('sha256', _master_key(), 32, $info, HKDF_SALT);
    }
    return $cache[$info];
}

function _location_key(): string    { return _derived_key('deaddrop:location-v1'); }
function _totp_key(): string        { return _derived_key('deaddrop:totp-v1'); }
function _reveal_key(): string      { return _derived_key('deaddrop:reveal-v1'); }
function _capability_key(): string  { return _derived_key('deaddrop:capability-v1'); }

// Proof that THIS session completed the pickup-password check for an order.
// The post-unlock redirect keeps only token + this MAC in the session and the
// reveal page re-decrypts from the DB — plaintext location data never rests
// in the session store. Derived subkey keeps it separate from the AES key.
function reveal_capability(string $token, int $order_id): string {
    return hash_hmac('sha256', $token . '|' . $order_id, _capability_key());
}

// ── Raw encrypt / decrypt ─────────────────────────────────────────────────────
// AES-256-GCM only (authenticated). Storage format: ciphertext column holds
// ciphertext||tag (base64), iv column holds the 12-byte nonce in hex.
// Legacy AES-256-CBC rows are NOT accepted at runtime — migrate them with
// tools/migrate_cbc_to_gcm.php before deploying this version. Rows encrypted
// under the raw master key (pre-key-separation) are likewise refused — run
// tools/separate_keys.php. Unauthenticated or legacy-keyed data is never used
// for new writes.

function encrypt_location(string $plaintext): array {
    $key   = _location_key();
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return [
        'ciphertext' => base64_encode($ct . $tag),
        'iv'         => bin2hex($nonce),
    ];
}

function decrypt_location(string $ciphertext_b64, string $iv_hex): string|false {
    $key = _location_key();
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) !== 24) { // GCM nonce is exactly 12 bytes
        return false;
    }
    if (strlen($raw) < 16) {
        return false;
    }
    $nonce = hex2bin($iv_hex);
    $ct    = substr($raw, 0, -16);
    $tag   = substr($raw, -16);
    return openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
}

// ── TOTP secrets (own subkey — a 2FA secret leak must not expose locations) ───

function encrypt_secret(string $plaintext): array {
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', _totp_key(), OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return ['ciphertext' => base64_encode($ct . $tag), 'iv' => bin2hex($nonce)];
}

function decrypt_secret(string $ciphertext_b64, string $iv_hex): string|false {
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) !== 24 || strlen($raw) < 16) {
        return false;
    }
    return openssl_decrypt(
        substr($raw, 0, -16), 'aes-256-gcm', _totp_key(),
        OPENSSL_RAW_DATA, hex2bin($iv_hex), substr($raw, -16)
    );
}

// ── Structured location data (JSON inside AES) ────────────────────────────────
// Schema: {"text":"...","lat":null,"lng":null,"instructions":""}

function encrypt_location_data(array $data): array {
    $defaults = ['text' => '', 'lat' => null, 'lng' => null, 'instructions' => ''];
    return encrypt_location(json_encode(array_merge($defaults, $data), JSON_UNESCAPED_UNICODE));
}

function decrypt_location_data(string $ciphertext_b64, string $iv_hex): array|false {
    $plain = decrypt_location($ciphertext_b64, $iv_hex);
    if ($plain === false) {
        return false;
    }
    $data = json_decode($plain, true);
    if (json_last_error() === JSON_ERROR_NONE && is_array($data)) {
        // Ensure all expected keys exist
        return array_merge(['text' => '', 'lat' => null, 'lng' => null, 'instructions' => ''], $data);
    }
    // Backwards-compatible: plain string from old records
    return ['text' => $plain, 'lat' => null, 'lng' => null, 'instructions' => ''];
}

// ── Sealed session payloads ───────────────────────────────────────────────────
// The post-unlock reveal lives in the PHP session between the unlock POST and
// the consuming GET. Sealing it with the AES key keeps the session store
// ciphertext-only: someone reading session files gets the same protection the
// database rows have, not plaintext locations.

function seal_payload(array $data): array {
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt(
        json_encode($data, JSON_UNESCAPED_UNICODE),
        'aes-256-gcm', _reveal_key(), OPENSSL_RAW_DATA, $nonce, $tag
    );
    if ($ct === false) {
        throw new RuntimeException('Sealing failed.');
    }
    return ['ct' => base64_encode($ct . $tag), 'iv' => bin2hex($nonce)];
}

function open_payload(array $sealed): array|false {
    if (!isset($sealed['ct'], $sealed['iv']) || strlen((string)$sealed['iv']) !== 24) {
        return false;
    }
    $raw = base64_decode((string)$sealed['ct'], true);
    if ($raw === false || strlen($raw) < 16) {
        return false;
    }
    $plain = openssl_decrypt(
        substr($raw, 0, -16), 'aes-256-gcm', _reveal_key(),
        OPENSSL_RAW_DATA, hex2bin($sealed['iv']), substr($raw, -16)
    );
    if ($plain === false) {
        return false;
    }
    $data = json_decode($plain, true);
    return is_array($data) ? $data : false;
}

// ── Password hashing ──────────────────────────────────────────────────────────

function hash_password(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verify_password(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

// ── Passphrase generator ──────────────────────────────────────────────────────
// Produces e.g. "StormRavenVaultMossFern4721!" — six capitalized words from a
// 256-word list (6 × log2(256) = 48 bits), plus a zero-padded 4-digit number
// (log2(10000) ≈ 13.29 bits) and one symbol from ten (≈ 3.32 bits):
// ≈ 64.61 bits of entropy while staying pronounceable and typeable.
// The IP + session rate limiters stretch online guessing far beyond that.

function generate_passphrase(): string {
    static $words = [
        'acorn','agent','album','amber','anchor','angle','anvil','apple',
        'apron','arch','arctic','armor','arrow','ash','aspen','atlas',
        'atom','auburn','axe','azure','badger','bamboo','banjo','barge',
        'basil','basin','basket','baton','bay','beacon','bear','beetle',
        'bell','bench','berry','birch','bishop','bison','blade','blaze',
        'bloom','bobcat','bolt','bone','bonfire','border','bottle','branch',
        'brass','breeze','brick','bridge','bronze','brook','broom','bubble',
        'bucket','buffalo','bulb','cabin','cable','cactus','camel','camera',
        'candle','canoe','canvas','canyon','cargo','carpet','cedar','chain',
        'chalk','chestnut','chimney','chisel','cider','cinder','cipher','clay',
        'cliff','cloak','cloud','clover','coal','cobra','code','coil',
        'comet','copper','coral','cougar','coyote','cradle','crane','crater',
        'creek','crescent','crest','cricket','crown','crumb','crush','crystal',
        'cypress','dagger','dahlia','dam','dawn','deer','delta','denim',
        'desert','dock','dolphin','domino','donkey','dove','dragon','drake',
        'dream','drift','drum','duck','dune','dusk','dust','eagle',
        'echo','ember','falcon','fern','ferret','fiddle','field','finch',
        'fjord','flame','flare','flax','flint','flock','flood','flute',
        'flux','fog','forest','forge','fox','frame','frost','funnel',
        'gadget','galaxy','gate','gazelle','gecko','gem','ghost','glacier',
        'glade','glass','glen','globe','gloom','glove','gnome','goat',
        'goblet','gold','gopher','gorge','graft','grain','granite','grave',
        'gravel','griffin','grove','guard','harbor','harvest','hawk','haze',
        'helm','heron','hickory','hollow','horn','hunter','iron','jade',
        'jaguar','kite','lance','lark','latch','lava','ledge','lens',
        'lever','light','lime','linden','link','lion','lock','lodge',
        'loom','lynx','maple','marsh','mast','mesa','mesh','mist',
        'moose','moss','mud','nail','night','oak','obsidian','orbit',
        'otter','peak','pebble','pike','pine','pivot','plane','plank',
        'plate','plinth','plow','pond','pool','port','prism','probe',
        'pulse','quartz','quill','radar','raven','reed','reef','resin',
        'ridge','rifle','ring','rivet','rook','rope','rose','route',
    ];
    $n   = count($words) - 1;
    $w1  = $words[random_int(0, $n)];
    $w2  = $words[random_int(0, $n)];
    $w3  = $words[random_int(0, $n)];
    $w4  = $words[random_int(0, $n)];
    $w5  = $words[random_int(0, $n)];
    $w6  = $words[random_int(0, $n)];
    $num = sprintf('%04d', random_int(0, 9999));
    $sym = ['!', '@', '#', '$', '%', '&', '*', '+', '=', '?'][random_int(0, 9)];
    return ucfirst($w1) . ucfirst($w2) . ucfirst($w3) . ucfirst($w4)
         . ucfirst($w5) . ucfirst($w6) . $num . $sym;
}

// ── Photo upload helper ───────────────────────────────────────────────────────

function save_uploaded_photo(array $file_entry, int $order_id, int $max_bytes = 12582912): string|false {
    if ($file_entry['error'] !== UPLOAD_ERR_OK) {
        return false;
    }

    // Hard ceiling: refuse files that are absurdly large (100 MB) even before GD
    if ($file_entry['size'] > 100 * 1024 * 1024) {
        return false;
    }

    $allowed_mime = ['image/jpeg' => 'jpg', 'image/png' => 'png',
                     'image/webp' => 'webp', 'image/gif' => 'gif'];

    // Trust the sniffed content type, never the client-supplied one. SVG and
    // everything else active is rejected by simply not being in the map.
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file_entry['tmp_name']);
    if (!isset($allowed_mime[$mime])) {
        return false;
    }

    // Decompression-bomb guard: read the header only, refuse absurd pixel
    // counts before GD ever decodes (a decoded 32-bit pixel buffer for the
    // cap below would still be ~200 MB, anything larger is hostile).
    $dim = @getimagesize($file_entry['tmp_name']);
    if ($dim === false || $dim[0] <= 0 || $dim[1] <= 0) {
        return false;
    }
    if ($dim[0] * (int)$dim[1] > 50_000_000) {
        return false;
    }

    $ext = $allowed_mime[$mime];
    $dir = dirname(__DIR__) . '/uploads/' . $order_id . '/';
    if (!is_dir($dir) && !mkdir($dir, 0750, true)) {
        return false;
    }

    // Filename is generated server-side from random bytes — client paths,
    // extensions and Unicode tricks never reach the filesystem.
    $filename = bin2hex(random_bytes(14)) . '.' . $ext;
    $dest     = $dir . $filename;

    // EVERY upload goes through decode + re-encode. This strips EXIF,
    // polyglot trailers, PHAR-ish metadata and any active-content payload:
    // what lands on disk is a freshly rendered raster image or nothing.
    if (!_compress_image($file_entry['tmp_name'], $dest, $mime, $max_bytes)) {
        return false;
    }

    return $order_id . '/' . $filename;
}

function _compress_image(string $src_path, string $dest_path, string $mime, int $max_bytes): bool {
    $loaders = [
        'image/jpeg' => 'imagecreatefromjpeg',
        'image/png'  => 'imagecreatefrompng',
        'image/webp' => 'imagecreatefromwebp',
        'image/gif'  => 'imagecreatefromgif',
    ];

    $load = $loaders[$mime] ?? null;
    if (!$load || !function_exists($load)) {
        return false;
    }

    $orig = @$load($src_path);
    if (!$orig) {
        return false;
    }

    $orig_w = imagesx($orig);
    $orig_h = imagesy($orig);
    $scale   = 1.0;
    $quality = 85; // start quality for JPEG/WebP

    for ($attempt = 0; $attempt < 10; $attempt++) {
        $w = max(1, (int)round($orig_w * $scale));
        $h = max(1, (int)round($orig_h * $scale));

        if ($w === $orig_w && $h === $orig_h && $scale >= 1.0) {
            $img = $orig;
        } else {
            $img = imagecreatetruecolor($w, $h);
            // Preserve transparency for PNG/GIF
            if ($mime === 'image/png' || $mime === 'image/gif') {
                imagealphablending($img, false);
                imagesavealpha($img, true);
                imagefill($img, 0, 0, imagecolorallocatealpha($img, 0, 0, 0, 127));
            }
            imagecopyresampled($img, $orig, 0, 0, 0, 0, $w, $h, $orig_w, $orig_h);
        }

        ob_start();
        switch ($mime) {
            case 'image/jpeg': imagejpeg($img, null, $quality); break;
            case 'image/png':  imagepng($img, null, 7);         break;
            case 'image/webp': imagewebp($img, null, $quality); break;
            case 'image/gif':  imagegif($img);                  break;
        }
        $data = ob_get_clean();

        if ($img !== $orig) {
            imagedestroy($img);
        }

        if (strlen($data) <= $max_bytes) {
            imagedestroy($orig);
            return (bool)file_put_contents($dest_path, $data);
        }

        // Reduce: lower quality first, then scale down
        if (in_array($mime, ['image/jpeg', 'image/webp'], true) && $quality > 50) {
            $quality -= 10;
        } else {
            $scale   -= 0.15;
            $quality  = 82; // reset quality for next scale step
        }

        if ($scale < 0.1) {
            break;
        }
    }

    imagedestroy($orig);
    return false;
}
