<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

header('Content-Type: application/json');
start_secure_session();
require_owner();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo json_encode(['error' => 'CSRF']);
    exit;
}

$key   = $_POST['key']   ?? '';
$value = $_POST['value'] ?? '';

$numeric  = ['order_ttl_hours','rate_limit_max','rate_limit_window_min','admin_session_hours','max_photo_mb'];
$floats   = ['admin_session_hours','max_photo_mb']; // stored as float strings
$booleans = ['allow_status_lookup','require_delivered_reveal','analytics_enabled','show_error_log','rate_limit_enabled','compliance_note_enabled','osm_proxy_enabled'];
$limits   = [
    'order_ttl_hours'       => [12,  72],
    'rate_limit_max'        => [3,   10],
    'rate_limit_window_min' => [5,   60],
    'admin_session_hours'   => [0.5,  5],
    'max_photo_mb'          => [0.1,  5],
];
$allowed  = array_merge(['site_name','extend_hours_options','default_lang'], $numeric, $booleans);

if (!in_array($key, $allowed, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid key']);
    exit;
}

if (in_array($key, $booleans, true)) {
    $value = $value === '1' ? '1' : '0';
} elseif (in_array($key, $numeric, true)) {
    $n = in_array($key, $floats) ? round((float)$value, 2) : (int)$value;
    [$min, $max] = $limits[$key];
    if ($n < $min || $n > $max) {
        http_response_code(422);
        echo json_encode(['error' => t('admin.settings.js.range_error', ['min' => (string)$min, 'max' => (string)$max])]);
        exit;
    }
    $value = (string)$n;
} elseif ($key === 'extend_hours_options') {
    $value = trim($value);
    foreach (explode(',', $value) as $part) {
        $n = (int)trim($part);
        if ($n <= 0) {
            http_response_code(422);
            echo json_encode(['error' => t('admin.settings.js.extend_hours_error')]);
            exit;
        }
    }
} elseif ($key === 'site_name') {
    $value = trim($value);
    if ($value === '') {
        $value = 'MGT'; // fall back to default when cleared
    }
} elseif ($key === 'default_lang') {
    if (!in_array($value, i18n_supported_langs(), true)) {
        http_response_code(422);
        echo json_encode(['error' => 'Invalid language']);
        exit;
    }
} else {
    $value = trim($value);
}

try {
    set_setting($key, $value);
    audit('setting_change', null, null, "{$key}={$value}");
    echo json_encode(['ok' => true]);
} catch (Exception $e) {
    log_err('Setting auto-save: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Save failed']);
}
exit;
