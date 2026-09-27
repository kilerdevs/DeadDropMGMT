<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
start_secure_session();
require_owner();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(['error' => 'Method not allowed'], 405);
}

if (!verify_csrf($_POST['csrf_token'] ?? '')) {
    json_out(['error' => 'CSRF'], 403);
}

$action = $_POST['action'] ?? '';

// Long worker calls (poll slice, inline finish) must not hold the session
// lock: the status poll fires every 3 s, and every other admin request from
// this owner — tiles included — would queue behind the download. Closing
// first persists verify_csrf()'s rotation and frees the lock; re-opening
// afterwards lets json_out() mint the next token into a live session.
// Reads of $_SESSION (audit, guards) above already ran; maps_* use no
// session state at all.
$withoutSessionLock = static function (callable $fn): void {
    session_write_close();
    try {
        $fn();
    } finally {
        start_secure_session();
    }
};

switch ($action) {

    // ── Queue one zone ──────────────────────────────────────────────────────
    // Sizing (exact bytes) happens in the worker, not here: a dry-run pulls
    // megabytes and takes seconds-to-minutes, which no POST should wait for.
    // The row lands as queued; the worker sizes it, then either downloads or
    // fails it with the reason (disk short, no proxy, …). PHP-engine hosts
    // have no worker to kick, so the POST finishes the zone inline instead
    // (maps_php_inline is a no-op everywhere else).
    case 'add': {
        if (!maps_downloads_supported()) {
            json_out(['error' => t('admin.maps.flash.unsupported')], 422);
        }
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
            post_string('name'), $minLon, $minLat, $maxLon, $maxLat,
            $maxzoom, $viaProxy
        );
        if ($id === null) {
            json_out(['error' => maps_zone_error_text($err)], 422);
        }
        $kicked = maps_kick_worker();
        audit('maps_zone_queue', null, null, "id={$id}");
        // No detached worker can exist on PHP-engine hosts: finish inline.
        $withoutSessionLock(static function () use ($id): void { maps_php_inline($id); });
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
        if (!maps_downloads_supported()) {
            json_out(['error' => t('admin.maps.flash.unsupported')], 422);
        }
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0 || !maps_zone_retry($id)) {
            json_out(['error' => t('admin.common.invalid_request')], 422);
        }
        $kicked = maps_kick_worker();
        audit('maps_zone_retry', null, null, "id={$id}");
        $withoutSessionLock(static function () use ($id): void { maps_php_inline($id); });
        json_out(['ok' => true, 'kicked' => $kicked]);
    }

    // ── Re-queue a ready/failed zone on a new planet build ──────────────────
    // Same reset as retry; the worker re-sizes against the fresh build and
    // republishes atomically, so the old file serves until the new one lands.
    case 'refresh': {
        if (!maps_downloads_supported()) {
            json_out(['error' => t('admin.maps.flash.unsupported')], 422);
        }
        $id = (int)($_POST['id'] ?? 0);
        if ($id <= 0 || !maps_zone_refresh($id)) {
            json_out(['error' => t('admin.common.invalid_request')], 422);
        }
        $kicked = maps_kick_worker();
        audit('maps_zone_refresh', null, null, "id={$id}");
        $withoutSessionLock(static function () use ($id): void { maps_php_inline($id); });
        json_out(['ok' => true, 'kicked' => $kicked]);
    }

    // ── Live queue state for the progress poll ──────────────────────────────
    case 'status': {
        // PHP-engine hosts donate a short slice per poll so the queue moves
        // with no cron, no detach and no hanging POST (rows re-read below).
        $withoutSessionLock(static function (): void { maps_php_poll_slice(); });
        $zones = [];
        foreach (maps_zone_list() as $z) {
            $zones[] = [
                'id'             => (int)$z['id'],
                'name'           => (string)$z['name'],
                'status'         => (string)$z['status'],
                'stale'          => maps_zone_is_stale($z),
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
