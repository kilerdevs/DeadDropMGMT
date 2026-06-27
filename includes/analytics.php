<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/settings.php';

function get_client_ip(): string {
    $candidates = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR',
    ];
    foreach ($candidates as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

function log_event(
    string  $event_type,
    ?int    $order_id  = null,
    ?string $token     = null
): void {
    if (!analytics_enabled()) {
        return;
    }
    try {
        get_db()->prepare(
            'INSERT INTO order_events
             (order_id, order_token, event_type, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?)'
        )->execute([
            $order_id,
            $token,
            $event_type,
            get_client_ip(),
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
        ]);
    } catch (Exception $e) {
        log_err('Event log failed: ' . $e->getMessage());
    }
}
