<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/crypto.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';

set_security_headers(true);
start_secure_session();
require_admin();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /admin/new_order.php');
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    $_SESSION['flash']    = 'Nieprawidłowy token CSRF.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/new_order.php');
    exit;
}

$location     = trim($_POST['location']     ?? '');
$password     = (string)($_POST['pickup_password'] ?? '');
$notes        = trim($_POST['notes']        ?? '');
$instructions = trim($_POST['instructions'] ?? '');
$raw_lat      = $_POST['lat'] ?? '';
$raw_lng      = $_POST['lng'] ?? '';

if ($location === '' && $instructions === '' && $raw_lat === '') {
    $_SESSION['flash']    = 'Podaj opis lokalizacji lub ustaw pinezkę na mapie.';
    $_SESSION['flash_ok'] = false;
    header('Location: /admin/new_order.php#new-order');
    exit;
}

// Auto-generate password if empty
$generated_password = false;
if ($password === '') {
    $password           = generate_passphrase();
    $generated_password = true;
} elseif (strlen($password) < 4) {
    $_SESSION['flash']    = 'Hasło odbioru musi mieć co najmniej 4 znaki.';
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

try {
    $token   = bin2hex(random_bytes(8));
    $enc     = encrypt_location_data([
        'text'         => $location,
        'lat'          => $lat,
        'lng'          => $lng,
        'instructions' => $instructions,
    ]);
    $pw_hash    = hash_password($password);
    $pw_enc_raw = encrypt_location($password); // AES copy for admin display

    $db   = get_db();
    $stmt = $db->prepare(
        'INSERT INTO orders
         (order_token, pickup_password_hash, pickup_password_enc, pickup_password_iv,
          location_encrypted, location_iv, notes, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([
        $token,
        $pw_hash,
        $pw_enc_raw['ciphertext'],
        $pw_enc_raw['iv'],
        $enc['ciphertext'],
        $enc['iv'],
        $notes !== '' ? $notes : null,
        current_user_id() ?: null,
    ]);

    $order_id = (int)$db->lastInsertId();
    audit('order_create', $order_id, $token);

    // Handle photo uploads
    $photo_errors = [];
    if (!empty($_FILES['photos']['name'][0])) {
        $files = $_FILES['photos'];
        $count = count($files['name']);
        for ($i = 0; $i < $count; $i++) {
            $entry = [
                'name'     => $files['name'][$i],
                'type'     => $files['type'][$i],
                'tmp_name' => $files['tmp_name'][$i],
                'error'    => $files['error'][$i],
                'size'     => $files['size'][$i],
            ];
            $rel = save_uploaded_photo($entry, $order_id, max_photo_bytes());
            if ($rel === false) {
                $photo_errors[] = htmlspecialchars($files['name'][$i], ENT_QUOTES, 'UTF-8');
            } else {
                $db->prepare('INSERT INTO order_photos (order_id, filename) VALUES (?, ?)')
                   ->execute([$order_id, $rel]);
            }
        }
    }

    $msg = 'Zamówienie utworzone. Token: ' . $token
         . ($generated_password ? ' | Hasło: ' . $password : '');
    if (!empty($photo_errors)) {
        $msg .= ' | Błąd przesyłania: ' . implode(', ', $photo_errors);
    }
    $_SESSION['flash']    = $msg;
    $_SESSION['flash_ok'] = true;
} catch (Exception $e) {
    log_err('Create order error: ' . $e->getMessage());
    $_SESSION['flash']    = 'Nie udało się utworzyć zamówienia. Sprawdź log błędów.';
    $_SESSION['flash_ok'] = false;
}

header('Location: /admin/orders.php');
exit;
