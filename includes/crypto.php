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
//           ├─ flash-v1       one-time messages parked in the session
//           ├─ token-index-v1 HMAC lookup index of order tokens (orders/events/audit)
//           ├─ token-v1       orders.token_enc (display copy of the order token)
//           ├─ photo-v1       encrypted photos at rest
//           └─ log-hmac-v1    app.log integrity chain
//
// Compromise or rotation of one subsystem's key no longer couples the others.
// The salt is public by design (RFC 5869): all secret material flows from the
// master key alone.
//
// ── Key rotation (ADR-019 extension) ─────────────────────────────────────────
// Multiple master keys are supported via DDMGMT_AES_KEY_HEX (current) and
// DDMGMT_AES_KEY_HEX_vN (previous versions). Each encrypted blob carries a
// version prefix (k1:, k2:, …) so decryption can find the right key. New
// writes always use the current key (no prefix = current). To rotate:
//   1. Add new key as DDMGMT_AES_KEY_HEX, move old to DDMGMT_AES_KEY_HEX_v1
//   2. Run migration tool (tools/rotate_keys.php) to re-encrypt all data
//   3. Remove old key after verification
// Migration tools handle legacy formats (pre-separation CBC, raw-key rows).

const HKDF_SALT = 'deaddrop-mgmt-hkdf-salt-v1';
const CURRENT_KEY_VERSION = 1;

// True when AES_KEY_HEX is a usable 64-hex-char master key. The placeholder in
// config.php.example, an empty string or a truncated value all answer false —
// callers (logger, CLI tools) can then say so instead of tripping over
// hex2bin() warnings or a TypeError on `false`.
function aes_key_valid(): bool {
    return defined('AES_KEY_HEX') && preg_match('/^[0-9a-fA-F]{64}$/', (string)AES_KEY_HEX) === 1;
}

// Operator-facing explanation for a missing/invalid key, with the fix that
// applies to the usual cause (a process that never saw the key).
function aes_key_problem(): string {
    return 'AES_KEY_HEX is not a valid 64-hex-char key. Set DDMGMT_AES_KEY_HEX in the environment '
        . '(a `docker exec` shell does not inherit it from the container entrypoint; on Docker installs '
        . 'the key is also read from /config/aes_key_hex when the variable is absent).';
}

// Returns array of [version => master_key_bytes], latest version first.
function _master_keys(): array {
    static $cache = null;
    if ($cache !== null) return $cache;
    $keys = [];
    // Current key (no version suffix)
    $current = defined('AES_KEY_HEX') ? (string)AES_KEY_HEX : '';
    if (preg_match('/^[0-9a-fA-F]{64}$/', $current) === 1) {
        $keys[CURRENT_KEY_VERSION] = hex2bin($current);
    }
    // Previous versions: AES_KEY_HEX_v1, AES_KEY_HEX_v2, …
    for ($v = CURRENT_KEY_VERSION + 1; $v <= 9; $v++) {
        $const = 'AES_KEY_HEX_v' . $v;
        if (!defined($const)) continue;
        $k = (string)constant($const);
        if (preg_match('/^[0-9a-fA-F]{64}$/', $k) === 1) {
            $keys[$v] = hex2bin($k);
        }
    }
    $cache = $keys;
    return $keys;
}

function _master_key(): string {
    $keys = _master_keys();
    if ($keys === []) {
        throw new RuntimeException('No valid AES_KEY_HEX configured. ' . aes_key_problem());
    }
    // Return current (version 1) key
    return $keys[CURRENT_KEY_VERSION];
}

function _derived_key(string $info): string {
    static $cache = [];
    if (!isset($cache[$info])) {
        $cache[$info] = hash_hkdf('sha256', _master_key(), 32, $info, HKDF_SALT);
    }
    return $cache[$info];
}

function _photo_key(): string { return _derived_key('deaddrop:photo-v1'); }

function _location_key(): string    { return _derived_key('deaddrop:location-v1'); }
function _totp_key(): string        { return _derived_key('deaddrop:totp-v1'); }
function _reveal_key(): string      { return _derived_key('deaddrop:reveal-v1'); }
function _flash_key(): string       { return _derived_key('deaddrop:flash-v1'); }
function _token_index_key(): string { return _derived_key('deaddrop:token-index-v1'); }
function _token_key(): string       { return _derived_key('deaddrop:token-v1'); }

// ── Raw encrypt / decrypt ─────────────────────────────────────────────────────
// AES-256-GCM only (authenticated). Storage format: ciphertext column holds
// ciphertext||tag (base64), iv column holds the 12-byte nonce in hex.
// Legacy AES-256-CBC rows are NOT accepted at runtime — migrate them with
// tools/migrate_cbc_to_gcm.php before deploying this version. Rows encrypted
// under the raw master key (pre-key-separation) are likewise refused — run
// tools/separate_keys.php. Unauthenticated or legacy-keyed data is never used
// for new writes.

// Row binding (AAD). A location ciphertext written with $bind (the order's
// token_hmac) authenticates that binding too: copied onto another order's
// row it no longer opens, so someone able to WRITE the database cannot make
// one recipient's reveal show another drop. Bound values carry the "b1:"
// prefix (base64 never contains ':'); a stripped prefix fails the tag, so
// there is no downgrade. Unprefixed values are pre-binding rows, still read
// until re-saved or re-bound (tools/bind_locations.php).
const LOCATION_BIND_PREFIX = 'b1:';

function _location_aad(string $bind): string {
    return 'deaddrop:location|' . $bind;
}

function encrypt_location(string $plaintext, ?string $bind = null): array {
    $key   = _location_key();
    $nonce = random_bytes(12);
    $tag   = '';
    $aad   = ($bind !== null && $bind !== '') ? _location_aad($bind) : '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    if ($ct === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return [
        'ciphertext' => ($aad !== '' ? LOCATION_BIND_PREFIX : '') . base64_encode($ct . $tag),
        'iv'         => bin2hex($nonce),
    ];
}

function decrypt_location(string $ciphertext_b64, string $iv_hex, ?string $bind = null): string|false {
    $key = _location_key();
    $aad = '';
    if (str_starts_with($ciphertext_b64, LOCATION_BIND_PREFIX)) {
        if ($bind === null || $bind === '') {
            return false; // a bound value never opens without its row identity
        }
        $ciphertext_b64 = substr($ciphertext_b64, strlen(LOCATION_BIND_PREFIX));
        $aad = _location_aad($bind);
    }
    $raw = base64_decode($ciphertext_b64, true);
    // Length 24 alone does not imply valid hex: hex2bin() answers false on
    // non-hex input and openssl_decrypt() would TypeError instead of failing
    // closed — a corrupt/planted row must reject, not 500.
    if ($raw === false || strlen($iv_hex) !== 24 || !ctype_xdigit($iv_hex)) {
        return false;
    }
    if (strlen($raw) < 16) {
        return false;
    }
    $nonce = hex2bin($iv_hex);
    $ct    = substr($raw, 0, -16);
    $tag   = substr($raw, -16);
    return openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
}

// ── TOTP secrets (own subkey — a 2FA secret leak must not expose locations) ───

function _seal_gcm(string $key, string $plaintext): array {
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
    if ($ct === false) {
        throw new RuntimeException('Encryption failed.');
    }
    return ['ciphertext' => base64_encode($ct . $tag), 'iv' => bin2hex($nonce)];
}

function _open_gcm(string $key, string $ciphertext_b64, string $iv_hex): string|false {
    $raw = base64_decode($ciphertext_b64, true);
    if ($raw === false || strlen($iv_hex) !== 24 || !ctype_xdigit($iv_hex) || strlen($raw) < 16) {
        return false;
    }
    return openssl_decrypt(
        substr($raw, 0, -16), 'aes-256-gcm', $key,
        OPENSSL_RAW_DATA, hex2bin($iv_hex), substr($raw, -16)
    );
}

function encrypt_secret(string $plaintext): array {
    return _seal_gcm(_totp_key(), $plaintext);
}

function decrypt_secret(string $ciphertext_b64, string $iv_hex): string|false {
    return _open_gcm(_totp_key(), $ciphertext_b64, $iv_hex);
}

// ── One-time session messages (own subkey — a flash is not a TOTP secret) ─────
// Generated passwords and enrollment secrets cross a redirect inside the
// session. They are sealed under flash-v1, not the TOTP subkey, so the two
// purposes stay cryptographically separate (ADR-016). Sessions are transient:
// a blob sealed by an earlier build simply fails to open and the message is
// lost once — nothing to migrate.

function encrypt_flash(string $plaintext): array {
    return _seal_gcm(_flash_key(), $plaintext);
}

function decrypt_flash(string $ciphertext_b64, string $iv_hex): string|false {
    return _open_gcm(_flash_key(), $ciphertext_b64, $iv_hex);
}

// ── Photo encryption (own subkey — a photo leak must not expose locations/TOTP) ──
// Photos are encrypted at rest with AES-256-GCM. The encrypted format:
//   ciphertext_b64 = base64(ciphertext || tag)
//   iv_hex = 12-byte nonce in hex
// Storage: files on disk are encrypted; served via photo_serve() which
// streams decrypted content. Thumbnails are also encrypted.

function encrypt_photo(string $plaintext): array {
    return _seal_gcm(_photo_key(), $plaintext);
}

function decrypt_photo(string $ciphertext_b64, string $iv_hex): string|false {
    return _open_gcm(_photo_key(), $ciphertext_b64, $iv_hex);
}

// Encrypt a photo file on disk (overwrites the file with encrypted version)
function photo_encrypt_file(string $path): bool {
    $data = @file_get_contents($path);
    if ($data === false) return false;
    $enc = encrypt_photo($data);
    $meta = json_encode(['v' => CURRENT_KEY_VERSION, 'ct' => $enc['ciphertext'], 'iv' => $enc['iv']]);
    if (@file_put_contents($path, $meta) === false) return false;
    return true;
}

// Decrypt a photo file to a temporary path for serving
function photo_decrypt_to_temp(string $encrypted_path, string $tmp_path): bool {
    $meta = @json_decode(@file_get_contents($encrypted_path), true);
    if (!is_array($meta) || !isset($meta['ct'], $meta['iv'])) return false;
    $data = decrypt_photo($meta['ct'], $meta['iv']);
    if ($data === false) return false;
    return @file_put_contents($tmp_path, $data) !== false;
}

// Serve a photo (encrypted at rest) via streaming response
function photo_serve(string $rel, bool $thumbnail = false): void {
    $base = dirname(__DIR__) . '/uploads/';
    $path = $base . ($thumbnail ? photo_thumb_rel($rel) : $rel);
    if (!is_file($path)) { http_response_code(404); exit; }
    // For now, decrypt to temp and serve (could stream-decrypt for large files)
    $tmp = sys_get_temp_dir() . '/photo_serve_' . bin2hex(random_bytes(8));
    if (!photo_decrypt_to_temp($path, $tmp)) { http_response_code(500); exit; }
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($tmp));
    header('Cache-Control: private, max-age=3600');
    readfile($tmp);
    @unlink($tmp);
    exit;
}

// ── Order tokens (HMAC-indexed lookup, ADR-019) ───────────────────────────────
// The database never holds an order token in the clear. Lookups go through a
// keyed index — HMAC-SHA256 under its own subkey — so a DB reader holding a
// dump cannot enumerate live capability URLs, and the token still finds its
// row with one indexed equality match. The admin panel needs to DISPLAY the
// token again later, so orders also carry an AES-GCM copy under a second
// subkey; events and the audit trail keep only the index.
//
// The index is computed over the LOWER-CASED token: the column this replaces
// compared case-insensitively (utf8mb4_unicode_ci), and a recipient typing a
// code from a note must not fail on caps lock.

function token_index(string $token): string {
    return hash_hmac('sha256', strtolower($token), _token_index_key());
}

function encrypt_token(string $token): array {
    return _seal_gcm(_token_key(), $token);
}

function decrypt_token(string $ciphertext_b64, string $iv_hex): string|false {
    return _open_gcm(_token_key(), $ciphertext_b64, $iv_hex);
}

/**
 * The three orders columns that stand in for the token.
 * @return array{token_hmac:string, token_enc:string, token_iv:string}
 */
function token_columns(string $token): array {
    $e = encrypt_token($token);
    return ['token_hmac' => token_index($token), 'token_enc' => $e['ciphertext'], 'token_iv' => $e['iv']];
}

/** Index for an optional token: null and '' mean "no token" and stay NULL. */
function token_index_or_null(?string $token): ?string {
    return ($token === null || $token === '') ? null : token_index($token);
}

/** Display copy of a row's token, or null when it cannot be opened. */
function order_token_plain(array $row): ?string {
    $ct = $row['token_enc'] ?? null;
    $iv = $row['token_iv'] ?? null;
    if (!is_string($ct) || !is_string($iv) || $ct === '' || $iv === '') {
        return null;
    }
    try {
        $plain = decrypt_token($ct, $iv);
    } catch (Throwable $e) {
        return null; // unusable key: the caller shows a placeholder
    }
    if (!is_string($plain)) {
        return null;
    }
    // The copy must belong to THIS row: token_enc swapped in from another
    // order (database write access) would otherwise show the admin the wrong
    // delivery link. The index is keyed, so the check cannot be forged.
    $idx = $row['token_hmac'] ?? null;
    if (is_string($idx) && $idx !== '' && !hash_equals($idx, token_index($plain))) {
        return null;
    }
    return $plain;
}

/**
 * What the admin panel shows for a token: the readable copy when there is one,
 * otherwise "#" plus the first 8 hex of the index — enough to tell two rows of
 * the same (deleted, or unreadable) order apart without revealing anything.
 */
function token_label(?string $plain, ?string $index): string {
    if ($plain !== null && $plain !== '') {
        return $plain;
    }
    return ($index !== null && $index !== '') ? '#' . substr($index, 0, 8) : '—';
}

// ── Structured location data (JSON inside AES) ────────────────────────────────
// Schema: {"text":"...","lat":null,"lng":null,"instructions":"","notes":""}

function encrypt_location_data(array $data, ?string $bind = null): array {
    $defaults = ['text' => '', 'lat' => null, 'lng' => null, 'instructions' => ''];
    // json_encode() answers false on invalid UTF-8 — passing that into
    // encrypt_location(string) would TypeError instead of failing loudly.
    $json = json_encode(array_merge($defaults, $data), JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        throw new RuntimeException('Location data is not valid UTF-8.');
    }
    return encrypt_location($json, $bind);
}

// $bind: the row's token_hmac (see encrypt_location) — required to open a
// bound value, ignored for pre-binding ones.
function decrypt_location_data(string $ciphertext_b64, string $iv_hex, ?string $bind = null): array|false {
    $plain = decrypt_location($ciphertext_b64, $iv_hex, $bind);
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

// Order notes live inside the encrypted location blob ('notes'). Rows
// written before that keep them in the plaintext orders.notes column until
// their next save — read either, encrypted copy first.
function order_notes_plain(array $order, array|false $loc): string {
    if (is_array($loc) && isset($loc['notes']) && is_string($loc['notes']) && $loc['notes'] !== '') {
        return $loc['notes'];
    }
    return (string)($order['notes'] ?? '');
}

// ── Sealed session payloads ───────────────────────────────────────────────────
// The post-unlock reveal lives in the PHP session between the unlock POST and
// the consuming GET. Sealing it with the AES key keeps the session store
// ciphertext-only: someone reading session files gets the same protection the
// database rows have, not plaintext locations.

function seal_payload(array $data): array {
    $nonce = random_bytes(12);
    $tag   = '';
    $json  = json_encode($data, JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        throw new RuntimeException('Sealing failed: payload is not valid UTF-8.');
    }
    $ct    = openssl_encrypt(
        $json,
        'aes-256-gcm', _reveal_key(), OPENSSL_RAW_DATA, $nonce, $tag
    );
    if ($ct === false) {
        throw new RuntimeException('Sealing failed.');
    }
    return ['ct' => base64_encode($ct . $tag), 'iv' => bin2hex($nonce)];
}

function open_payload(array $sealed): array|false {
    if (!isset($sealed['ct'], $sealed['iv']) || strlen((string)$sealed['iv']) !== 24
        || !ctype_xdigit((string)$sealed['iv'])) {
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

// ── Order capability tokens ───────────────────────────────────────────────────
// 16 chars over [0-9a-zA-Z] (62 symbols). Lookups are case-INSENSITIVE
// (token_index() lower-cases, so a recipient's caps lock never fails), which
// means a guesser only has to cover 36 symbols per position: the effective
// budget is 16 × log2(36) ≈ 82.7 bits, not the 95.3 the raw alphabet
// suggests — still far beyond any online or offline search. Hex-only
// generation would have left 64 bits.
// Validators accept ctype_alnum (index.php, receive.php), so previously
// issued hex tokens keep working: they are a subset of this alphabet.
function generate_order_token(int $len = 16): string {
    static $alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $out = '';
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, 61)];
    }
    return $out;
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

// Record a photo saved by save_uploaded_photo(). The file is already on disk
// (public under an unguessable name): when the row cannot be written — the
// order vanished meanwhile, a transaction is rolling back — the file goes too,
// instead of lingering unreferenced where no cleanup ever looks.
function store_order_photo(PDO $db, int $order_id, string $rel): void {
    try {
        $db->prepare('INSERT INTO order_photos (order_id, filename) VALUES (?, ?)')->execute([$order_id, $rel]);
    } catch (Throwable $e) {
        discard_order_photo_file($rel);
        throw $e;
    }
}

function discard_order_photo_file(string $rel): void {
    if (preg_match('#^\d+/[0-9a-f]+\.(jpg|jpeg|png|webp|gif)$#i', $rel) === 1) {
        overwrite_and_unlink(dirname(__DIR__) . '/uploads/' . $rel);
    }
    $thumb = photo_thumb_rel($rel);
    if ($thumb !== null) {
        overwrite_and_unlink(dirname(__DIR__) . '/uploads/' . $thumb);
    }
}

// Grid thumbnail derived from the full-size photo: same directory, same
// random stem, _thumb suffix, always JPEG. Deterministic so every delete
// path finds it with no schema change (order_photos keeps one row).
function photo_thumb_rel(string $rel): ?string {
    if (preg_match('#^(\d+/)([0-9a-f]+)\.(jpg|jpeg|png|webp|gif)$#i', $rel, $m) !== 1) {
        return null;
    }
    return $m[1] . $m[2] . '_thumb.jpg';
}

// Claim a staged upload (uploads/0/<hex>.<ext>, written before the order row
// exists) for its order: renames the photo and its thumbnail into
// uploads/<id>/ and answers the final rel. Null when the stage is missing
// or the move fails — the caller treats it like a rejected upload, and the
// hourly staging sweep reaps the leftover (never referenced, never served).
function photo_staged_claim(string $rel, int $order_id): ?string {
    if ($order_id <= 0 || preg_match('#^0/([0-9a-f]+)\.(jpg|jpeg|png|webp|gif)$#i', $rel, $m) !== 1) {
        return null;
    }
    $base = dirname(__DIR__) . '/uploads/';
    $dir = $base . $order_id . '/';
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        return null;
    }
    if (!@rename($base . $rel, $dir . $m[1] . '.' . $m[2])) {
        return null;
    }
    $thumb = '0/' . $m[1] . '_thumb.jpg';
    if (is_file($base . $thumb)) {
        @rename($base . $thumb, $dir . $m[1] . '_thumb.jpg');
    }
    return $order_id . '/' . $m[1] . '.' . $m[2];
}

// Grid <img> source: the thumbnail when it exists, the full file otherwise
// (pre-thumbnail rows, or a thumb that failed to write, keep working).
function photo_grid_src(string $rel): string {
    $thumb = photo_thumb_rel($rel);
    if ($thumb !== null && is_file(dirname(__DIR__) . '/uploads/' . $thumb)) {
        return $thumb;
    }
    return $rel;
}

// Small static JPEG for the 140 px grid: longest edge 400 px, quality 75.
// Decodes the re-encoded artifact (never the raw upload); transparency is
// flattened onto white. Best-effort — the grid falls back to the full file.
function _write_thumb(string $src, string $dest): bool {
    $loaders = [
        'image/jpeg' => 'imagecreatefromjpeg',
        'image/png'  => 'imagecreatefrompng',
        'image/webp' => 'imagecreatefromwebp',
        'image/gif'  => 'imagecreatefromgif',
    ];
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($src);
    $load = $loaders[$mime] ?? null;
    if (!$load || !function_exists($load)) {
        return false;
    }
    $orig = @$load($src);
    if (!$orig) {
        return false;
    }
    $w = imagesx($orig);
    $h = imagesy($orig);
    $s = min(1.0, 400 / max(1, max($w, $h)));
    $tw = max(1, (int)round($w * $s));
    $th = max(1, (int)round($h * $s));
    $img = imagecreatetruecolor($tw, $th);
    imagefill($img, 0, 0, imagecolorallocate($img, 255, 255, 255));
    imagecopyresampled($img, $orig, 0, 0, 0, 0, $tw, $th, $w, $h);
    $orig = null; // PHP 8.5 deprecates imagedestroy(); GC frees the GdImage
    $ok = imagejpeg($img, $dest, 75);
    $img = null;
    return (bool)$ok;
}

function save_uploaded_photo(array $file_entry, int $order_id, int $max_bytes = 12582912): string|false {
    if ($file_entry['error'] !== UPLOAD_ERR_OK) {
        return false;
    }

    // Hard ceiling: refuse files that are absurdly large (100 MB) even before GD.
    // Ground truth is the on-disk size, not $_FILES['size'] (client-influenced
    // metadata and hand-built arrays must not be able to skip the early reject
    // and push a huge file into GD decode before the 12 MB re-encode cap).
    $actual_size = is_file($file_entry['tmp_name'] ?? '')
        ? (@filesize($file_entry['tmp_name']) ?: PHP_INT_MAX)
        : PHP_INT_MAX;
    if ($actual_size > 100 * 1024 * 1024 || (int)($file_entry['size'] ?? 0) > 100 * 1024 * 1024) {
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
    // counts before GD ever decodes. 16 MP (4096x4096) is the ceiling: a
    // decoded 32-bit buffer is already 64 MB, and GD holds several copies
    // during resample — anything larger risks OOM on a 256 MB PHP limit
    // while adding nothing to a re-encode capped at 12 MB.
    $dim = @getimagesize($file_entry['tmp_name']);
    if ($dim === false || $dim[0] <= 0 || $dim[1] <= 0) {
        return false;
    }
    if ($dim[0] * (int)$dim[1] > 16_777_216) {
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

    // Re-sniff what actually landed on disk. GD re-encodes everything, but
    // malformed input has historically produced surprising output — verify
    // the artifact is still a member of the allowed image map before handing
    // out its path.
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $out_mime = $finfo->file($dest);
    if ($out_mime === false || !isset($allowed_mime[$out_mime])) {
        if (!@unlink($dest)) {
            log_err('Upload rejected but artifact survived: ' . $dest);
        }
        return false;
    }
    // If GD rendered into a different format than sniffed on input, rename
    // so the extension never lies about the bytes inside.
    if ($out_mime !== $mime) {
        $renamed = $dir . bin2hex(random_bytes(14)) . '.' . $allowed_mime[$out_mime];
        if (!@rename($dest, $renamed)) {
            if (!@unlink($dest)) {
                log_err('Upload rename failed and artifact survived: ' . $dest);
            }
            return false;
        }
        $dest = $renamed;
    }

    // Grid thumbnail from the verified artifact (never the raw upload).
    $thumbRel = photo_thumb_rel($order_id . '/' . basename($dest));
    if ($thumbRel !== null && !_write_thumb($dest, $dir . basename($thumbRel))) {
        log_err('Thumbnail write failed for: ' . $dest);
    }

    // Encrypt both the main photo and thumbnail at rest
    photo_encrypt_file($dest);
    if ($thumbRel !== null) {
        photo_encrypt_file($dir . basename($thumbRel));
    }

    return $order_id . '/' . basename($dest);
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
    // Cap the longest edge up front: a 16 MP source re-encoded up to 10
    // times at full resolution is pure CPU burn — the grid shows 140 px and
    // the lightbox rarely benefits past 2560 px.
    $cap = 2560 / max(1, max($orig_w, $orig_h));
    if ($cap < 1.0) {
        $cw = max(1, (int)round($orig_w * $cap));
        $ch = max(1, (int)round($orig_h * $cap));
        $small = imagecreatetruecolor($cw, $ch);
        if ($mime === 'image/png' || $mime === 'image/gif') {
            imagealphablending($small, false);
            imagesavealpha($small, true);
            imagefill($small, 0, 0, imagecolorallocatealpha($small, 0, 0, 0, 127));
        }
        imagecopyresampled($small, $orig, 0, 0, 0, 0, $cw, $ch, $orig_w, $orig_h);
        $orig = $small;
        $orig_w = $cw;
        $orig_h = $ch;
    }
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
            $img = null; // PHP 8.5 deprecates imagedestroy(); GC frees the GdImage
        }

        if (strlen($data) <= $max_bytes) {
            $orig = null; // PHP 8.5 deprecates imagedestroy(); GC frees the GdImage
            return (bool)file_put_contents($dest_path, $data);
        }

        // Reduce: lower quality first, then scale down — estimated from the
        // size ratio instead of fixed 0.15 steps, so 1-2 encodes land the
        // budget instead of up to 10 full-resolution ones.
        if (in_array($mime, ['image/jpeg', 'image/webp'], true) && $quality > 50) {
            $quality -= 10;
        } else {
            $size = max(1, strlen($data));
            $scale *= sqrt($max_bytes / $size) * 0.95;
            $quality  = 82; // reset quality for next scale step
        }

        if ($scale < 0.1) {
            break;
        }
    }

    $orig = null; // PHP 8.5 deprecates imagedestroy(); GC frees the GdImage
    return false;
}
