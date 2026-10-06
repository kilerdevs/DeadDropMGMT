<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Manual zone-file upload: verify-before-publish ───────────────────────────
// maps_zone_import_file() takes a file already staged at the zone's .part
// path (admin/maps_action.php moved it there with move_uploaded_file) and
// either publishes it atomically or refuses with a translated reason,
// leaving the zone row untouched.

$db = get_db();
T::ok('upload supported on this host', maps_upload_supported());
@mkdir(maps_tiles_dir(), 0775, true);

$fixture = dirname(__DIR__) . '/e2e/fixtures/micro.pmtiles';
T::ok('pmtiles fixture exists', is_file($fixture));
// Fixture coverage (Warsaw): zones under test must sit inside it.
$fh = pmtiles_parse_header((string)@file_get_contents($fixture, false, null, 0, PMTILES_HEADER_LEN));
T::ok('fixture header parses', $fh !== null);

// ── Happy path: failed zone, covering file → ready ──────────────────────────
[$id, $addErr] = maps_zone_add('P3 Upload Zone', 20.96, 52.21, 21.09, 52.27, 14, false);
T::ok('zone queued (' . $addErr . ')', $id !== null && $id > 0);
$db->prepare("UPDATE map_zones SET status = 'failed', error = 'code:download_failed|seed' WHERE id = ?")->execute([$id]);
[, , $part, $final] = maps_zone_workspace((int)$id);
T::ok('staging copy lands', copy($fixture, $part));
T::eq('valid file publishes', null, maps_zone_import_file((int)$id));
$row = maps_zone_get((int)$id);
T::eq('zone ready', 'ready', $row['status'] ?? null);
T::eq('error cleared', null, $row['error']);
T::eq('freshness unknown, not fresh', null, $row['build_key']);
T::ok('published file verifies', pmtiles_verify_path($final));
T::eq('row bytes match the file', (int)@filesize($final), (int)($row['bytes_done'] ?? -1));
T::ok('staging file consumed', !is_file($part));

// ── Ready rows accept a replacement (manual refresh) ───────────────────────
T::ok('re-staging lands', copy($fixture, $part));
T::eq('replacement publishes', null, maps_zone_import_file((int)$id));
T::eq('zone still ready', 'ready', (maps_zone_get((int)$id)['status'] ?? null));
T::ok('published file still verifies', pmtiles_verify_path($final));

// ── Wrong area: header bbox must cover the zone ────────────────────────────
[$mid, ] = maps_zone_add('P3 Far Zone', 2.20, 48.80, 2.50, 48.90, 14, false);
$db->prepare("UPDATE map_zones SET status = 'failed', error = 'code:download_failed|seed' WHERE id = ?")->execute([$mid]);
[, , $mpart, $mfinal] = maps_zone_workspace((int)$mid);
T::ok('foreign staging lands', copy($fixture, $mpart));
T::eq('foreign file refused', t('admin.maps.flash.upload_mismatch'), maps_zone_import_file((int)$mid));
$mrow = maps_zone_get((int)$mid);
T::eq('row untouched by refusal', 'failed', $mrow['status'] ?? null);
T::eq('old error kept', 'code:download_failed|seed', $mrow['error'] ?? null);
T::ok('staging cleaned on refusal', !is_file($mpart));
T::ok('nothing published on refusal', !is_file($mfinal));

// ── Garbage bytes are not an archive ───────────────────────────────────────
[$gid, ] = maps_zone_add('P3 Garbage Zone', 20.96, 52.21, 21.09, 52.27, 14, false);
$db->prepare("UPDATE map_zones SET status = 'failed', error = 'code:sizing_failed|seed' WHERE id = ?")->execute([$gid]);
[, , $gpart, $gfinal] = maps_zone_workspace((int)$gid);
file_put_contents($gpart, 'NOT-A-PMTILES-FILE');
T::eq('garbage refused', t('admin.maps.flash.upload_invalid'), maps_zone_import_file((int)$gid));
T::eq('row untouched by garbage', 'failed', (maps_zone_get((int)$gid)['status'] ?? null));
T::ok('garbage staging cleaned', !is_file($gpart));
T::ok('nothing published from garbage', !is_file($gfinal));

// ── Rows a worker may own refuse without touching their staging ────────────
[$aid, ] = maps_zone_add('P3 Active Zone', 20.96, 52.21, 21.09, 52.27, 14, false);
[, , $apart] = maps_zone_workspace((int)$aid);
file_put_contents($apart, 'maybe-a-live-worker-part');
T::eq('in-flight row refuses', t('admin.maps.flash.upload_active'), maps_zone_import_file((int)$aid));
T::ok('foreign staging never deleted for active rows', is_file($apart));
@unlink($apart);
T::eq('unknown zone refused', t('admin.common.invalid_request'), maps_zone_import_file(2147000000));
T::eq('bad id refused', t('admin.common.invalid_request'), maps_zone_import_file(0));

// ── Cleanup ────────────────────────────────────────────────────────────────
foreach ([$id, $mid, $gid, $aid] as $zid) {
    T::ok("zone $zid deleted", maps_zone_delete((int)$zid));
}
T::ok('published file gone with its zone', !is_file($final));

exit(T::done());
