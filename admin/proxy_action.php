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
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo json_encode(['error' => 'CSRF']);
    exit;
}

$action = $_POST['action'] ?? '';

switch ($action) {

    // ── Add one proxy manually ────────────────────────────────────────────────
    case 'add': {
        $url = osm_proxy_normalize((string)($_POST['url'] ?? ''));
        if ($url === null) {
            http_response_code(422);
            echo json_encode(['error' => t('admin.proxies.flash.invalid_url')]);
            exit;
        }
        try {
            $db = get_db();
            $dup = $db->prepare('SELECT id FROM osm_proxies WHERE url = ? LIMIT 1');
            $dup->execute([$url]);
            if ($dup->fetch()) {
                http_response_code(409);
                echo json_encode(['error' => t('admin.proxies.flash.duplicate')]);
                exit;
            }
            $db->prepare('INSERT INTO osm_proxies (url, source) VALUES (?, "manual")')->execute([$url]);
            audit('proxy_add', null, null, $url);
            echo json_encode(['ok' => true]);
        } catch (Exception $e) {
            log_err('Proxy add: ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => t('admin.proxies.flash.save_failed')]);
        }
        exit;
    }

    // ── Remove one proxy ─────────────────────────────────────────────────────
    case 'delete': {
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0) {
            http_response_code(422);
            echo json_encode(['error' => t('admin.common.invalid_request')]);
            exit;
        }
        try {
            $stmt = get_db()->prepare('DELETE FROM osm_proxies WHERE id = ?');
            $stmt->execute([$id]);
            audit('proxy_delete', null, null, "id={$id}");
            echo json_encode(['ok' => true]);
        } catch (Exception $e) {
            log_err('Proxy delete: ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => t('admin.proxies.flash.save_failed')]);
        }
        exit;
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
                 VALUES (?, "discovered", "ok", ?, NOW())
                 ON DUPLICATE KEY UPDATE last_status = "ok", latency_ms = VALUES(latency_ms), last_checked = NOW()'
            );
            $added = 0;
            foreach ($found as $px) {
                $ins->execute([$px['url'], $px['latency_ms']]);
                if ($ins->rowCount() === 1) $added++; // 2 = updated existing row
            }
            audit('proxy_discover', null, null, 'working=' . count($found));
            echo json_encode([
                'ok'      => true,
                'added'   => $added,
                'working' => count($found),
            ]);
        } catch (Exception $e) {
            log_err('Proxy discover: ' . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => t('admin.proxies.flash.discover_failed')]);
        }
        exit;
    }
}

http_response_code(400);
echo json_encode(['error' => t('admin.common.invalid_request')]);
exit;
