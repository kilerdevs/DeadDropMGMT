<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';

function _aes_key(): string {
    $key = hex2bin(AES_KEY_HEX);
    if (strlen($key) !== 32) {
        throw new RuntimeException('AES key must be 32 bytes (64 hex chars).');
    }
    return $key;
}

// ── Raw encrypt / decrypt ─────────────────────────────────────────────────────
// AES-256-GCM (authenticated). Storage format: ciphertext column holds
// ciphertext||tag (base64), iv column holds the 12-byte nonce in hex.
// Legacy AES-256-CBC rows are detected by IV length (32 hex chars vs 24)
// and still decrypt — they re-encrypt to GCM on next edit.

function encrypt_location(string $plaintext): array {
    $key   = _aes_key();
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
    $key = _aes_key();
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) % 2 !== 0) {
        return false;
    }

    if (strlen($iv_hex) === 24) { // GCM: 12-byte nonce, tag appended to ciphertext
        if (strlen($raw) < 16) {
            return false;
        }
        $nonce = hex2bin($iv_hex);
        $ct    = substr($raw, 0, -16);
        $tag   = substr($raw, -16);
        return openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    }

    // Legacy CBC fallback (16-byte IV)
    if (strlen($iv_hex) !== 32) {
        return false;
    }
    $iv = hex2bin($iv_hex);
    if (strlen($iv) !== 16) {
        return false;
    }
    return openssl_decrypt($raw, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
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

// ── Password hashing ──────────────────────────────────────────────────────────

function hash_password(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verify_password(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

// ── Passphrase generator ──────────────────────────────────────────────────────
// Produces e.g. "Storm·Raven·Vault·47!" — pronounceable, memorable, strong enough.
// 4 words from a 193-word list ≈ 34 bits, plus ~3.3 bits each from the number
// and the symbol — roughly 40 bits of entropy, which the IP rate limiter on
// pickup attempts stretches far beyond offline-attack relevance.

function generate_passphrase(): string {
    static $words = [
        'amber','anvil','arrow','atlas','axe','basin','beacon','bear','blade',
        'blaze','bolt','bone','bridge','brook','canyon','cedar','chain','chalk',
        'cinder','cipher','clay','cliff','cloud','coal','cobra','code','coil',
        'coral','crane','crater','creek','crest','crown','crush','crystal',
        'dagger','dawn','dusk','dust','eagle','echo','ember','falcon','fern',
        'field','flare','flint','flood','flux','fog','forge','frost','ghost',
        'glade','glass','glen','gloom','gold','graft','grain','granite','grave',
        'gravel','grove','guard','hawk','haze','helm','hollow','horn','hunter',
        'iron','jade','jaguar','kite','lance','lark','latch','lava','ledge',
        'lens','lever','light','lime','linden','link','lion','lock','lodge',
        'loom','lynx','maple','marsh','mast','mesa','mesh','mist','moose',
        'moss','mud','nail','night','oak','obsidian','orbit','otter','peak',
        'pebble','pike','pine','pivot','plane','plank','plate','plinth','plow',
        'pond','pool','port','prism','probe','pulse','quartz','quill','radar',
        'raven','reed','reef','resin','ridge','rifle','ring','rivet','rook',
        'rope','rose','route','rune','rust','sage','salt','sand','sap','shard',
        'shell','shield','shore','signal','silver','slate','smoke','snake',
        'snare','snow','soil','spark','spire','spoke','spur','staff','stag',
        'stake','stalk','star','steel','stem','stone','storm','strand','stream',
        'strike','stripe','stub','surge','swift','thorn','tide','timber','torch',
        'trace','track','trail','trap','tree','trench','tundra','vault','veil',
        'vine','violet','viper','volt','vortex','warden','wave','wedge','well',
        'wind','wolf','wood','wren','zinc',
    ];
    $n   = count($words) - 1;
    $w1  = $words[random_int(0, $n)];
    $w2  = $words[random_int(0, $n)];
    $w3  = $words[random_int(0, $n)];
    $w4  = $words[random_int(0, $n)];
    $num = random_int(10, 99);
    $sym = ['!', '@', '#', '$', '%', '&', '*', '+', '=', '?'][random_int(0, 9)];
    return ucfirst($w1) . ucfirst($w2) . ucfirst($w3) . ucfirst($w4) . $num . $sym;
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

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($file_entry['tmp_name']);
    if (!isset($allowed_mime[$mime])) {
        return false;
    }

    $ext  = $allowed_mime[$mime];
    $dir  = dirname(__DIR__) . '/uploads/' . $order_id . '/';
    if (!is_dir($dir) && !mkdir($dir, 0750, true)) {
        return false;
    }

    $filename = bin2hex(random_bytes(14)) . '.' . $ext;
    $dest     = $dir . $filename;

    // If within limit, store as-is
    if ($file_entry['size'] <= $max_bytes) {
        return move_uploaded_file($file_entry['tmp_name'], $dest)
            ? $order_id . '/' . $filename
            : false;
    }

    // File exceeds limit — compress via GD
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
