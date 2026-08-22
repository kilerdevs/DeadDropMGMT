<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/settings.php';

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
