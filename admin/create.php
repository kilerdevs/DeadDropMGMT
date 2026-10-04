<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

set_security_headers(true);
start_secure_session();
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/new_order.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['flash']    = t('admin.common.invalid_csrf');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/new_order.php');
    exit;
}

$location     = trim(post_string('location'));
$password     = post_string('pickup_password');
$notes        = trim(post_string('notes'));
$instructions = trim(post_string('instructions'));
$raw_lat      = $_POST['lat'] ?? '';
$raw_lng      = $_POST['lng'] ?? '';


// Auto-generate password if empty
$generated_password = false;
if ($password === '') {
    $password           = generate_passphrase();
    $generated_password = true;
} elseif (strlen($password) < 8) {
    $_SESSION['flash']    = t('admin.new_order.flash.password_short');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/new_order.php#new-order');
    exit;
} elseif (!password_length_ok($password)) {
    $_SESSION['flash']    = t('admin.common.password_too_long');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/new_order.php#new-order');
    exit;
}

// Validate coordinates
$lat = null;
$lng = null;
if ($raw_lat !== '' && $raw_lng !== '' && is_numeric($raw_lat) && is_numeric($raw_lng)) {
    $lat = round((float)$raw_lat, 7);
    $lng = round((float)$raw_lng, 7);
    if ($lat < -90 || $lat > 90 || $lng < -180 || $lng > 180) {
        $lat = null;
        $lng = null;
    }
}

// Judged on the VALIDATED pin: a junk lat= used to satisfy this check and
// create an order with no location at all.
if ($location === '' && $instructions === '' && $lat === null) {
    $_SESSION['flash']    = t('admin.new_order.flash.missing_location');
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/new_order.php#new-order');
    exit;
}

try {
    $token   = generate_order_token();
    // The token itself is never stored: a keyed index for lookups plus an
    // encrypted copy for the admin views (ADR-019). The location is bound to
    // that index, so it only ever opens as THIS order's location.
    $tokCols = token_columns($token);
    $enc     = encrypt_location_data([
        'text'         => $location,
        'lat'          => $lat,
        'lng'          => $lng,
        'instructions' => $instructions,
        // Notes are drop hints the recipient sees after unlocking — as
        // sensitive as the location, so they ride in the same ciphertext.
        'notes'        => $notes,
    ], $tokCols['token_hmac']);
    // Hash only — the pickup password is shown ONCE in the flash message and
    // never stored recoverably. Lost credentials are replaced, not recovered.
    $pw_hash = hash_password($password);

    $db   = get_db();
    // Photos are processed BEFORE the transaction opens: GD decode+re-encode
    // is the slow part and must not hold the order row lock. Files stage
    // under uploads/0/ (no order 0 ever exists) and move into place after
    // the INSERT; a failed insert discards them, crash leftovers are swept
    // hourly — the transaction below stays a short row write.
    //
    // Register shutdown handler to clean staged uploads on fatal errors
    // (OOM, timeout, etc.) that bypass the catch block. The handler runs
    // after the script dies and removes any files still in uploads/0/
    // that belong to this request (identified by a request-specific prefix).
    $staged_prefix = '0/' . bin2hex(random_bytes(8)) . '_';
    $staged_for_cleanup = [];
    register_shutdown_function(static function (array $staged, string $prefix): void {
        if (!empty($staged)) {
            foreach ($staged as $rel) {
                @unlink(dirname(__DIR__, 2) . '/uploads/' . $rel);
                // Thumbnail path for prefixed filenames: the prefixed name
                // already includes the prefix, so we derive the thumb name
                // directly instead of using photo_thumb_rel() which expects
                // the unprefixed pattern.
                $thumb = dirname(__DIR__, 2) . '/uploads/' . $prefix . pathinfo($rel, PATHINFO_FILENAME) . '_thumb.jpg';
                if (is_file($thumb)) @unlink($thumb);
            }
        }
        // Also clean any orphaned files in uploads/0/ with our prefix
        $base = dirname(__DIR__, 2) . '/uploads/0/';
        if (is_dir($base)) {
            foreach (glob($base . $prefix . '*') as $f) {
                @unlink($f);
                $t = $base . pathinfo($f, PATHINFO_FILENAME) . '_thumb.jpg';
                if (is_file($t)) @unlink($t);
            }
        }
    }, [$staged_for_cleanup, $staged_prefix]);

    $photo_errors = [];
    $count = 0;
    $limit = max_photos_per_order();
    $files = ['name' => []];
    $staged = [];
    if (isset($_FILES['photos']['name']) && is_array($_FILES['photos']['name']) && !empty($_FILES['photos']['name'][0])) {
        $files = $_FILES['photos'];
        $count = count($files['name']);
        for ($i = 0; $i < $count && $i < $limit; $i++) {
            $entry = [
                'name'     => $files['name'][$i],
                'type'     => $files['type'][$i],
                'tmp_name' => $files['tmp_name'][$i],
                'error'    => $files['error'][$i],
                'size'     => $files['size'][$i],
            ];
            $rel = save_uploaded_photo($entry, 0, max_photo_bytes());
            if ($rel === false) {
                // Raw name: t() escapes params at the sink (see orders.php) —
                // pre-escaping here would double-escape it in the flash.
                $photo_errors[] = (string)$files['name'][$i];
            } else {
                // Rename staged file to include our request-specific prefix
                $base = dirname(__DIR__, 2) . '/uploads/';
                $prefixed = $staged_prefix . basename($rel);
                if (@rename($base . $rel, $base . $prefixed)) {
                    // Also rename thumbnail if it exists
                    $thumb = photo_thumb_rel($rel);
                    if ($thumb !== null && is_file($base . $thumb)) {
                        $thumbPrefixed = $staged_prefix . basename($thumb);
                        @rename($base . $thumb, $base . $thumbPrefixed);
                    }
                    $staged_for_cleanup[] = $prefixed;
                    $staged[] = $prefixed; // Use prefixed name for claim
                } else {
                    $staged_for_cleanup[] = $rel;
                    $staged[] = $rel;
                }
            }
        }
    }

    // Order row and photo rows commit together or not at all: a photo-row
    // failure used to report "create failed" for an order that existed (its
    // generated password never shown). Files saved for a rolled-back order
    // are removed below.
    $db->beginTransaction();
    $stmt = $db->prepare(
        'INSERT INTO orders
         (token_hmac, token_enc, token_iv, pickup_password_hash, location_encrypted, location_iv, notes, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([
        ...array_values($tokCols),
        $pw_hash,
        $enc['ciphertext'],
        $enc['iv'],
        null, // orders.notes is legacy plaintext storage — never written now
        // Config-based fallback owner has user_id 0 with no users row, and
        // the FK rejects 0 — so NULL is load-bearing here, not a lost trail:
        // audit() below records the actor's username + IP in audit_log.
        current_user_id() ?: null,
    ]);

    $order_id = (int)$db->lastInsertId();
    audit('order_create', $order_id, $token);

    // Handle staged uploads: claim each into the order directory (instant
    // renames), then record the row. A failed claim reports like a rejected
    // upload — the file stays staged for the hourly sweep.
    $saved = [];
    foreach ($staged as $stagedRel) {
        // Strip our request-specific prefix before claiming
        $claimRel = $stagedRel;
        if (str_starts_with($stagedRel, $staged_prefix)) {
            $claimRel = substr($stagedRel, strlen($staged_prefix));
        }
        $final = photo_staged_claim($claimRel, $order_id);
        if ($final === null) {
            $photo_errors[] = basename($stagedRel);
            continue;
        }
        $saved[] = $final;
        store_order_photo($db, $order_id, $final);
    }
    $db->commit();

    $msg = $generated_password
        ? t('admin.new_order.flash.created_with_pw', ['token' => $token, 'password' => $password])
        : t('admin.new_order.flash.created', ['token' => $token]);
    if ($count > $limit) {
        // Skipped names join the same error list: the flash names every file
        // that was not saved, whether rejected or over the cap.
        for ($i = $limit; $i < $count; $i++) {
            $photo_errors[] = (string)$files['name'][$i];
        }
    }
    if (!empty($photo_errors)) {
        $msg .= ' | ' . t('admin.new_order.flash.upload_errors', ['files' => implode(', ', $photo_errors)]);
    }
    // A generated pickup password rides in this message: seal it at rest.
    flash_set($msg, true, $generated_password);
} catch (Throwable $e) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    // Both claimed files and files still staged under uploads/0/ die with
    // the failed create (anything missed is swept hourly, never referenced).
    foreach (array_merge($saved ?? [], $staged ?? [], $staged_for_cleanup ?? []) as $rel) {
        discard_order_photo_file($rel);
    }
    log_err('Create order error: ' . $e->getMessage());
    $_SESSION['flash']    = t('admin.new_order.flash.create_failed');
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
