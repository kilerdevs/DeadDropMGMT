<?php
declare(strict_types=1);

// Handler for the save_setting dispatch route. Runs INSIDE the dispatcher
// envelope (JSON headers, session, owner auth, POST, CSRF) — direct
// requests are refused.
if (!defined('DDMGMT_DISPATCH') || DDMGMT_DISPATCH !== 'save_setting') {
    http_response_code(404);
    exit;
}

$key   = $_POST['key']   ?? '';
$value = $_POST['value'] ?? '';

$numeric  = ['order_ttl_hours','rate_limit_max','rate_limit_window_min','admin_session_hours','max_photo_mb'];
$floats   = ['admin_session_hours','max_photo_mb']; // stored as float strings
$booleans = ['allow_status_lookup','analytics_enabled','show_error_log','rate_limit_enabled','compliance_note_enabled','osm_proxy_enabled'];
$limits   = [
    'order_ttl_hours'       => [12,  72],
    'rate_limit_max'        => [3,   10],
    'rate_limit_window_min' => [5,   60],
    'admin_session_hours'   => [0.5,  5],
    'max_photo_mb'          => [0.1,  5],
];
$allowed  = array_merge(['site_name','extend_hours_options','default_lang','map_provider'], $numeric, $booleans);

if (!in_array($key, $allowed, true)) {
    json_out(['error' => 'Invalid key'], 400);
}

if (in_array($key, $booleans, true)) {
    $value = $value === '1' ? '1' : '0';
} elseif (in_array($key, $numeric, true)) {
    $n = in_array($key, $floats) ? round((float)$value, 2) : (int)$value;
    [$min, $max] = $limits[$key];
    if ($n < $min || $n > $max) {
        json_out(['error' => t('admin.settings.js.range_error', ['min' => (string)$min, 'max' => (string)$max])], 422);
    }
    $value = (string)$n;
} elseif ($key === 'extend_hours_options') {
    $value = trim($value);
    foreach (explode(',', $value) as $part) {
        // Strict digits + the same 1–720 range extend.php enforces: (int)
        // casts silently accepted "24abc" → 24 and unbounded millions that
        // render as dead +99999999h buttons.
        $p = trim($part);
        if (!preg_match('/^\d+$/', $p) || (int)$p < 1 || (int)$p > 720) {
            json_out(['error' => t('admin.settings.js.extend_hours_error')], 422);
        }
    }
} elseif ($key === 'site_name') {
    $value = trim($value);
    if ($value === '') {
        $value = 'MGT'; // fall back to default when cleared
    }
} else {
    // Enum selects: default_lang validates against the language list,
    // map_provider against the provider allowlist. Anything else here is
    // a programming error (every allowed key must be handled above).
    if ($key === 'map_provider') {
        if ($value !== MAP_PROVIDER_OSM && $value !== MAP_PROVIDER_SELFHOSTED) {
            json_out(['error' => 'Invalid map provider'], 422);
        }
    } elseif (!in_array($value, i18n_supported_langs(), true)) {
        json_out(['error' => 'Invalid language'], 422);
    }
}

try {
    set_setting($key, $value);
    audit('setting_change', null, null, "{$key}={$value}");
    json_out(['ok' => true]);
} catch (Exception $e) {
    log_err('Setting auto-save: ' . $e->getMessage());
    json_out(['error' => 'Save failed'], 500);
}
