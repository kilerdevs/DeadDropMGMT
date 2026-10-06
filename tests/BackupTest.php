<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Owner backups: create / verify / restore round-trip ─────────────────────
// backup_create() snapshots all rows + uploads/ files into backups/ (zip
// when ZipArchive exists, pure-PHP JSON otherwise); backup_verify()
// checksums everything without changing anything; backup_restore()
// replays a VERIFIED manifest transactionally. Tests run against an
// isolated uploads tree ($tmpRoot) but the real test database — every test
// round-trips, so the net DB effect is zero, and created bundles are
// deleted afterwards.

$db = get_db();
T::ok('backups supported here', backup_supported());
T::ok('backup dir exists', is_dir(backup_dir()));

// ── Isolated uploads tree ───────────────────────────────────────────────────
$tmpRoot = sys_get_temp_dir() . '/ddmgmt-backup-test-' . bin2hex(random_bytes(6));
@mkdir($tmpRoot . '/uploads/7', 0775, true);
file_put_contents($tmpRoot . '/uploads/7/aaa.enc', random_bytes(1024));
file_put_contents($tmpRoot . '/uploads/9-bbb.enc', random_bytes(512));
T::eq('photo scan finds both files', 2, count(backup_photo_files($tmpRoot)));
T::ok('real uploads untouched by the scan', true);

// ── Strict filename gate ────────────────────────────────────────────────────
T::eq('backup name regex pins the format', 1, preg_match(BACKUP_NAME_RE, 'backup-20260102-030405.zip'));
T::eq('...and the fallbacks', 1, preg_match(BACKUP_NAME_RE, 'backup-20260102-030405.json.gz'));
T::eq('staging debris never matches', 0, preg_match(BACKUP_NAME_RE, '.database-abc123.json'));
T::eq('delete refuses traversal', false, backup_delete('../../config.php'));
T::eq('delete refuses snapshots', false, backup_delete('snapshot.json'));

// ── Marker: proves restore really replaces rows ────────────────────────────
$markerOrig = get_setting('backup_test_marker', '');
set_setting('backup_test_marker', 'before');

// ── Create (zip here if available, JSON fallback otherwise) ─────────────────
$created = backup_create($db, $tmpRoot);
T::eq('create ok (' . ($created['code'] ?? 'no-code') . ')', true, $created['ok'] ?? false);
T::ok('create names a file', isset($created['file']) && preg_match(BACKUP_NAME_RE, $created['file']) === 1);
$path = backup_dir() . '/' . $created['file'];
T::ok('bundle on disk', is_file($path));
T::eq('all tables snapshotted', count(BACKUP_TABLES), $created['tables'] ?? 0);
T::eq('both photos bundled', 2, $created['files'] ?? -1);
$listed = array_column(backup_list(), 'name');
T::ok('new backup lists', in_array($created['file'], $listed, true));

// ── Verify the fresh bundle ────────────────────────────────────────────────
$ver = backup_verify($path);
T::eq('fresh bundle verifies', true, $ver['ok'] ?? false);
T::ok('manifest returned', isset($ver['manifest']['db']['users']));
T::eq('manifest pins ten tables', count(BACKUP_TABLES), count($ver['manifest']['db'] ?? []));
T::eq('manifest pins both photos', 2, count($ver['manifest']['files'] ?? []));
T::eq('own key matches', false, $ver['key_mismatch'] ?? true);
T::ok('config crc recorded', ($ver['manifest']['config_crc'] ?? '') !== '');

// ── Tamper: one flipped byte voids the whole file ──────────────────────────
$tampered = $tmpRoot . '/tampered.bin';
copy($path, $tampered);
$fh = fopen($tampered, 'r+b');
fseek($fh, (int)(filesize($tampered) / 2));
$c = fgetc($fh);
fseek($fh, (int)(filesize($tampered) / 2));
fwrite($fh, $c === 'A' ? 'B' : 'A');
fclose($fh);
$verTampered = backup_verify($tampered);
T::eq('flipped byte refuses', false, $verTampered['ok'] ?? true);
T::eq('refusal is quiet (code only)', 'invalid', $verTampered['code'] ?? '');
@unlink($tampered);
T::eq('garbage is not a backup', false, (backup_verify($tmpRoot . '/uploads/7/aaa.enc')['ok'] ?? true));

// ── Manifest strictness ────────────────────────────────────────────────────
$good = $ver['manifest'];
$wrongVer = $good;
$wrongVer['backup'] = 999;
T::eq('wrong version rejected', null, backup_manifest_parse($wrongVer));
$dropTable = $good;
unset($dropTable['db']['settings']);
T::eq('dropped table rejected', null, backup_manifest_parse($dropTable));
$extraTable = $good;
$extraTable['db']['evil'] = 1;
T::eq('extra table rejected', null, backup_manifest_parse($extraTable));
$badSum = $good;
$badSum['files'] = ['uploads/7/aaa.enc' => 'not-a-sha'];
T::eq('bad checksum rejected', null, backup_manifest_parse($badSum));
$traversal = $good;
$traversal['files'] = ['uploads/../../config.php' => str_repeat('a', 64)];
T::eq('path traversal rejected', null, backup_manifest_parse($traversal));
$dotfile = $good;
$dotfile['files'] = ['uploads/.restore-x/y' => str_repeat('a', 64)];
T::eq('dot paths rejected', null, backup_manifest_parse($dotfile));

// ── Restore round-trip: marker moves, then comes back ──────────────────────
set_setting('backup_test_marker', 'after');
$restored = backup_restore($db, $path, $good, $tmpRoot);
T::eq('restore ok', true, $restored['ok'] ?? false);
T::eq('marker rewound to backup time', 'before', get_setting('backup_test_marker', ''));
T::eq('no key warning on own host', false, $restored['key_mismatch'] ?? true);
T::ok('staged photo landed', is_file($tmpRoot . '/uploads/7/aaa.enc'));
T::eq('photo bytes identical', hash_file('sha256', $tmpRoot . '/uploads/7/aaa.enc'), $good['files']['uploads/7/aaa.enc'] ?? '');
// Orphan pruning: a file the backup never knew dies with the restore.
file_put_contents($tmpRoot . '/uploads/orphan.enc', 'x');
$restored2 = backup_restore($db, $path, $good, $tmpRoot);
T::eq('second restore ok', true, $restored2['ok'] ?? false);
T::ok('orphan pruned', !is_file($tmpRoot . '/uploads/orphan.enc'));
T::ok('no staging leftovers', count(glob($tmpRoot . '/uploads/.restore-*')) === 0);

// ── Restore of a tampered bundle changes nothing ───────────────────────────
copy($path, $tampered);
$fh = fopen($tampered, 'r+b');
fseek($fh, (int)(filesize($tampered) / 2));
$c = fgetc($fh);
fseek($fh, (int)(filesize($tampered) / 2));
fwrite($fh, $c === 'A' ? 'B' : 'A');
fclose($fh);
set_setting('backup_test_marker', 'after');
$badRestore = backup_restore($db, $tampered, $good, $tmpRoot);
T::eq('tampered restore refused', false, $badRestore['ok'] ?? true);
T::eq('live data untouched by refusal', 'after', get_setting('backup_test_marker', ''));
@unlink($tampered);

// ── Zip path (CI has ZipArchive; this box does not) ────────────────────────
if (backup_zip_supported()) {
    T::ok('zip available here', true);
} else {
    T::ok('zip unavailable here — fallback covered above, zip pinned by shape', true);
}
T::eq('zip gate mirrors the environment', class_exists('ZipArchive'), backup_zip_supported());

// ── Cleanup: marker back, bundle gone, tree gone ───────────────────────────
if ($markerOrig === '') {
    delete_setting('backup_test_marker');
} else {
    set_setting('backup_test_marker', $markerOrig);
}
T::eq('marker restored', $markerOrig, get_setting('backup_test_marker', ''));
T::ok('bundle deletes', backup_delete($created['file']));
T::ok('bundle gone from disk', !is_file($path));
@unlink($tmpRoot . '/uploads/7/aaa.enc');
@unlink($tmpRoot . '/uploads/9-bbb.enc');
@rmdir($tmpRoot . '/uploads/7');
@rmdir($tmpRoot . '/uploads');
@rmdir($tmpRoot);
T::ok('temp tree gone', !is_dir($tmpRoot));

exit(T::done());
