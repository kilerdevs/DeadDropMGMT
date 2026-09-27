<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/crypto.php';

// Records an admin write action. Best-effort — never blocks the caller.
function audit(string $action, ?int $order_id = null, ?string $order_token = null, string $detail = ''): void {
    try {
        get_db()->prepare(
            'INSERT INTO audit_log (user_id, username, action, order_id, token_hmac, detail, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        )->execute([
            current_user_id() ?: null,
            current_user_name() ?: 'system',
            $action,
            $order_id,
            // Only the keyed index is stored, never the token (ADR-019). A value
            // that is not token-shaped (a placeholder, an unreadable copy) is
            // dropped rather than indexed as if it were one.
            preg_match('/^[0-9A-Za-z]{16}$/', (string)$order_token) === 1 ? token_index($order_token) : null,
            // mb_strcut: a byte cut through a multibyte character would make the
            // INSERT fail on invalid UTF-8 and silently drop the whole audit row.
            $detail !== '' ? mb_strcut($detail, 0, 255, 'UTF-8') : null,
            get_client_ip(),
        ]);
    } catch (Exception $e) {
        log_err('Audit log failed: ' . $e->getMessage());
    }
}
