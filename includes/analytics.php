<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/crypto.php';

function log_event(
    string  $event_type,
    ?int    $order_id  = null,
    ?string $token     = null,
    bool    $anonymous = false
): void {
    // The toggle gates tracking: attributable rows (token index, IP, user
    // agent). An anonymous terminal row (a flow's last event after the order
    // and its history were wiped: no token, no IP, no user agent) is a bare
    // counter, not tracking — it records even while analytics is off, so
    // switching analytics off never silently drops the receipt trail.
    if (!$anonymous && !analytics_enabled()) {
        return;
    }
    try {
        get_db()->prepare(
            'INSERT INTO order_events
             (order_id, token_hmac, event_type, ip_address, user_agent)
             VALUES (?, ?, ?, ?, ?)'
        )->execute([
            $order_id,
            // Anonymous rows (a flow's terminal event after the order and its
            // history were deleted) keep only the fact and the time: no token
            // index, IP or user agent may outlive the wipe.
            $anonymous ? null : token_index_or_null($token),
            $event_type,
            $anonymous ? '' : get_client_ip(),
            $anonymous ? null : substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
        ]);
    } catch (Exception $e) {
        log_err('Event log failed: ' . $e->getMessage());
    }
}
