<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';

// Records an admin write action. Best-effort — never blocks the caller.
function audit(string $action, ?int $order_id = null, ?string $order_token = null, string $detail = ''): void {
    try {
        get_db()->prepare(
            'INSERT INTO audit_log (user_id, username, action, order_id, order_token, detail, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            current_user_id() ?: null,
            current_user_name() ?: 'system',
            $action,
            $order_id,
            $order_token,
            $detail !== '' ? substr($detail, 0, 255) : null,
            get_client_ip(),
        ]);
    } catch (Exception $e) {
        log_err('Audit log failed: ' . $e->getMessage());
    }
}
