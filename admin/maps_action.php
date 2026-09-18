<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

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

    // ── Queue one zone ──────────────────────────────────────────────────────
    // Sizing (exact bytes) happens in the worker, not here: a dry-run pulls
    // megabytes and takes seconds-to-minutes, which no POST should wait for.
    // The row lands as queued; the worker sizes it, then either downloads or
    // fails it with the reason (disk short, no proxy, …).
    case 'add': {
        $f = static fn(string $k): ?float => is_numeric($_POST[$k] ?? null)
            ? (float)$_POST[$k] : null;
        $minLon = $f('min_lon');
        $minLat = $f('min_lat');
        $maxLon = $f('max_lon');
        $maxLat = $f('max_lat');
        if ($minLon === null || $minLat === null || $maxLon === null || $maxLat === null) {
            json_out(['error' => t('admin.maps.flash.bad_bbox')], 422);
        }
        $maxzoom = (int)($_POST['maxzoom'] ?? 14);
        $viaProxy = ($_POST['via_proxy'] ?? '1') === '1';
        [$id, $err] = maps_zone_add(
            (string)($_POST['name'] ?? ''), $minLon, $minLat, $maxLon, $maxLat,
            $maxzoom, $viaProxy
        );
        if ($id === null) {
            json_out(['error' => maps_zone_error_text($err)], 422);
        }
        $kicked = maps_kick_worker();
        audit('maps_zone_queue', null, null, "id={$id}");
        json_out(['ok' => true, 'id' => $id, 'kicked' => $kicked]);
    }

    // ── Delete a zone (row + files) ─────────────────────────────────────────
    case 'delete': {
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0 || !maps_zone_delete($id)) {
            json_out(['error' => t('admin.common.invalid_request')], 422);
        }
        json_out(['ok' => true]);
    }

    // ── Re-queue a failed zone ──────────────────────────────────────────────
    case 'retry': {
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0 || !maps_zone_retry($id)) {
            json_out(['error' => t('admin.common.invalid_request')], 422);
        }
        $kicked = maps_kick_worker();
        json_out(['ok' => true, 'kicked' => $kicked]);
    }

    // ── Live queue state for the progress poll ──────────────────────────────
    case 'status': {
        $zones = [];
        foreach (maps_zone_list() as $z) {
            $zones[] = [
                'id'             => (int)$z['id'],
                'name'           => (string)$z['name'],
                'status'         => (string)$z['status'],
                'maxzoom'        => (int)$z['maxzoom'],
                'min_lon'        => (float)$z['min_lon'],
                'min_lat'        => (float)$z['min_lat'],
                'max_lon'        => (float)$z['max_lon'],
                'max_lat'        => (float)$z['max_lat'],
                'via_proxy'      => ((int)$z['via_proxy']) === 1,
                'bytes_expected' => $z['bytes_expected'] !== null ? (int)$z['bytes_expected'] : null,
                'bytes_done'     => (int)$z['bytes_done'],
                'speed_bps'      => $z['speed_bps'] !== null ? (int)$z['speed_bps'] : null,
                'eta_secs'       => $z['eta_secs'] !== null ? (int)$z['eta_secs'] : null,
                'error'          => maps_zone_error_text($z['error'] !== null ? (string)$z['error'] : null),
            ];
        }
        json_out([
            'ok'        => true,
            'zones'     => $zones,
            'disk_free' => maps_disk_free(),
        ]);
    }
}

json_out(['error' => t('admin.common.invalid_request')], 400);
