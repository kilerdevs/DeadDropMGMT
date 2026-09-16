<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/proxy.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

header('Content-Type: application/json');
start_secure_session();
require_owner();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(['error' => 'Method not allowed'], 405);
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    json_out(['error' => 'CSRF'], 403);
}

$action = $_POST['action'] ?? '';

switch ($action) {

    // ── Add one proxy manually ────────────────────────────────────────────────
    case 'add': {
        $url = osm_proxy_normalize((string)($_POST['url'] ?? ''));
        if ($url === null) {
            json_out(['error' => t('admin.proxies.flash.invalid_url')], 422);
        }
        try {
            $db = get_db();
            $dup = $db->prepare('SELECT id FROM osm_proxies WHERE url = ? LIMIT 1');
            $dup->execute([$url]);
            if ($dup->fetch()) {
                json_out(['error' => t('admin.proxies.flash.duplicate')], 409);
            }
            $db->prepare('INSERT INTO osm_proxies (url, source) VALUES (?, "manual")')->execute([$url]);
            audit('proxy_add', null, null, $url);
            json_out(['ok' => true]);
        } catch (Exception $e) {
            log_err('Proxy add: ' . $e->getMessage());
            json_out(['error' => t('admin.proxies.flash.save_failed')], 500);
        }
    }

    // ── Remove one proxy ─────────────────────────────────────────────────────
    case 'delete': {
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0) {
            json_out(['error' => t('admin.common.invalid_request')], 422);
        }
        try {
            $stmt = get_db()->prepare('DELETE FROM osm_proxies WHERE id = ?');
            $stmt->execute([$id]);
            audit('proxy_delete', null, null, "id={$id}");
            json_out(['ok' => true]);
        } catch (Exception $e) {
            log_err('Proxy delete: ' . $e->getMessage());
            json_out(['error' => t('admin.proxies.flash.save_failed')], 500);
        }
    }

    // ── Auto-discover anonymity-focused proxies and store the working ones ───
    case 'discover': {
        // Probing dozens of public proxies takes a while; lift the usual cap.
        @set_time_limit(180);
        try {
            $found = proxy_discover();
            $db = get_db();
            $ins = $db->prepare(
                'INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
                 VALUES (?, ?, "ok", ?, NOW())
                 ON DUPLICATE KEY UPDATE last_status = "ok", latency_ms = VALUES(latency_ms), last_checked = NOW()'
            );
            $added = 0;
            foreach ($found as $px) {
                $ins->execute([$px['url'], (string)$px['source'], $px['latency_ms']]);
                if ($ins->rowCount() === 1) $added++; // 2 = updated existing row
            }
            audit('proxy_discover', null, null, 'working=' . count($found));
            json_out([
                'ok'      => true,
                'added'   => $added,
                'working' => count($found),
            ]);
        } catch (Exception $e) {
            log_err('Proxy discover: ' . $e->getMessage());
            json_out(['error' => t('admin.proxies.flash.discover_failed')], 500);
        }
    }
}

json_out(['error' => t('admin.common.invalid_request')], 400);
