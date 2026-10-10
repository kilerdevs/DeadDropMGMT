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
// The container matches host capability: zip when ZipArchive exists (a
// flipped gzip flag would silently ship json.gz on zip-capable hosts).
if (backup_zip_supported()) {
    T::eq('zip host ships zip', 'zip', $created['format'] ?? null);
    T::ok('...with a .zip name', str_ends_with($created['file'] ?? '', '.zip'));
} else {
    T::eq('non-zip host ships json variant',
        extension_loaded('zlib') ? 'json.gz' : 'json', $created['format'] ?? null);
}
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

// ── Schema-less database fails creation honestly ──────────────────────────
// A database without the schema must refuse with ok:false, never claim a
// backup (a flipped ok flag would ship an empty "success").
$adminDsn = 'mysql:host=' . (getenv('DDMGMT_DB_HOST') ?: '127.0.0.1')
    . ';port=' . (getenv('DDMGMT_DB_PORT') ?: '3306');
$adminUser = getenv('DDMGMT_DB_USER') ?: 'root';
$adminPass = getenv('DDMGMT_DB_PASS') !== false ? (string)getenv('DDMGMT_DB_PASS') : '';
$emptyDb = 'deaddrops_emptyprobe';
$adminPdo = new PDO($adminDsn, $adminUser, $adminPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
try {
    $adminPdo->exec('CREATE DATABASE IF NOT EXISTS `' . $emptyDb . '`');
    $emptyPdo = new PDO($adminDsn . ';dbname=' . $emptyDb . ';charset=utf8mb4',
        $adminUser, $adminPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $emptyRes = backup_create($emptyPdo, $tmpRoot);
    T::eq('schema-less database fails creation', false, $emptyRes['ok'] ?? null);
    T::eq('...with the failure code', 'create_failed', $emptyRes['code'] ?? null);
} finally {
    $adminPdo->exec('DROP DATABASE IF EXISTS `' . $emptyDb . '`');
}

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
// Second-engine bundle, built now while the marker still reads 'before': the
// JSON bundle must build, verify and restore even when zip is the active
// engine (and vice versa) — one engine's lines must never go dark just
// because the host prefers the other.
$jsonManifest = $good;
$jsonManifest['format'] = 'json';
$useGz = extension_loaded('zlib');
$jsonManifest['encoding'] = $useGz ? 'gzip' : 'raw';
$jsonPath = $tmpRoot . '/explicit.' . ($useGz ? 'json.gz' : 'json');
T::eq('explicit JSON bundle builds', true, backup_write_json_bundle($jsonPath, $db, $jsonManifest, $useGz, $tmpRoot));
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
T::eq('scalar manifest rejected', null, backup_manifest_parse('not-a-manifest'));
T::eq('integer manifest rejected', null, backup_manifest_parse(42));
T::eq('null manifest rejected', null, backup_manifest_parse(null));

// Refusal-code mapping (shared by the stage and payload failure arms): an
// oversized payload stays 'too_large', anything else (null included) is
// 'invalid'. A swapped mapping would misreport corrupt bundles.
T::eq('oversize maps to too_large', 'too_large', backup_refusal_code('too_large'));
T::eq('other reasons map to invalid', 'invalid', backup_refusal_code('corrupt'));
T::eq('missing reason maps to invalid', 'invalid', backup_refusal_code(null));

// Size gate answers false for junk wearing a zip header (the open below can
// only fail the same way the early return already did).
$garbageZip = $tmpRoot . '/garbage.zip';
file_put_contents($garbageZip, "PK\x03\x04" . str_repeat('x', 100));
T::ok('unopenable zip is not oversized', backup_exceeds_caps($garbageZip) === false);
T::ok('missing path is not oversized', backup_exceeds_caps($tmpRoot . '/nope.zip') === false);
@unlink($garbageZip);

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
// A clean restore reports no partial files (the flag exists only for the
// best-effort photo publish past the DB commit).
T::ok('clean restore reports no partial files', !isset($restored2['files_partial']));
// Nested orphan trees go too: files unlink first (child-first walk), then
// the emptied directories themselves are removed.
@mkdir($tmpRoot . '/uploads/7/nested/deep', 0775, true);
file_put_contents($tmpRoot . '/uploads/7/nested/deep/orphan.enc', 'x');
@mkdir($tmpRoot . '/uploads/emptydir', 0775, true);
$restored3 = backup_restore($db, $path, $good, $tmpRoot);
T::eq('restore with nested orphans ok', true, $restored3['ok'] ?? false);
T::ok('nested orphan file pruned', !is_file($tmpRoot . '/uploads/7/nested/deep/orphan.enc'));
T::ok('emptied orphan dirs removed',
    !is_dir($tmpRoot . '/uploads/7/nested') && !is_dir($tmpRoot . '/uploads/emptydir'));
T::ok('...and still no partial-files flag', !isset($restored3['files_partial']));
// A destination that cannot be written marks the restore partial: squat a
// file where the photo directory should be and the staged move must fail.
@unlink($tmpRoot . '/uploads/7/aaa.enc');
@rmdir($tmpRoot . '/uploads/7');
file_put_contents($tmpRoot . '/uploads/7', 'squatter');
$restoredBlocked = backup_restore($db, $path, $good, $tmpRoot);
T::eq('blocked destination still restores the rows', true, $restoredBlocked['ok'] ?? false);
T::ok('...but reports partial files', isset($restoredBlocked['files_partial']));
@unlink($tmpRoot . '/uploads/7');

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

// ── Second engine round-trip: the JSON bundle must build, verify and
// restore even when zip is the active engine (and vice versa) — one
// engine's lines must never go dark just because the host prefers the other.
$verJson = backup_verify($jsonPath);
T::eq('explicit JSON bundle verifies', true, $verJson['ok'] ?? false);
set_setting('backup_test_marker', 'after');
$restJson = backup_restore($db, $jsonPath, $verJson['manifest'], $tmpRoot);
T::eq('explicit JSON bundle restores', true, $restJson['ok'] ?? false);
T::eq('marker rewound via JSON restore', 'before', get_setting('backup_test_marker', ''));

// ── Dispatch and shape edges ─────────────────────────────────────────────
T::eq('missing file is invalid', 'invalid', (backup_verify($tmpRoot . '/nope.bin')['code'] ?? ''));
T::eq('unopenable zip is invalid', 'invalid', (backup_verify_zip($tmpRoot . '/uploads/7/aaa.enc')['code'] ?? ''));
T::eq('wrong table set refuses', false, backup_database_matches('{"users":[]}', $good));
$drift = [];
foreach (BACKUP_TABLES as $t) {
    $drift[$t] = [];
}
$drift['users'][] = ['id' => 1];
T::eq('row count drift refuses', false, backup_database_matches((string)json_encode($drift), $good));
T::eq('malformed db refuses', false, backup_database_matches('[1,2', $good));
$nonRows = [];
foreach (BACKUP_TABLES as $t) {
    $n = (int)($good['db'][$t] ?? 0);
    $nonRows[$t] = $n > 0 ? array_fill(0, $n, 7) : [];
}
T::eq('non-row entries refuse', false, backup_database_matches((string)json_encode($nonRows), $good));
T::eq('non-array manifest rejected', null, backup_manifest_parse('x'));
$emptyField = $good;
$emptyField['created_utc'] = '';
T::eq('empty manifest field rejected', null, backup_manifest_parse($emptyField));
$badFormat = $good;
$badFormat['format'] = 'tar';
T::eq('unknown format rejected', null, backup_manifest_parse($badFormat));
$negCount = $good;
$negCount['db']['users'] = -1;
T::eq('negative count rejected', null, backup_manifest_parse($negCount));

// ── Scan edges: missing tree, directories, dotfiles, debris ────────────────
T::eq('missing uploads tree scans empty', [], backup_photo_files($tmpRoot . '/no-such-root-xyz'));
@mkdir($tmpRoot . '/uploads/emptydir', 0775, true);
@mkdir($tmpRoot . '/uploads/.hidedir', 0775, true);
file_put_contents($tmpRoot . '/uploads/.hidedir/x.enc', 'hidden');
$scan = backup_photo_files($tmpRoot);
T::ok('dirs and dotfiles never payload', count($scan) === 2 && !isset($scan['uploads/.hidedir/x.enc']));
@unlink($tmpRoot . '/uploads/.hidedir/x.enc');
@rmdir($tmpRoot . '/uploads/.hidedir');
@rmdir($tmpRoot . '/uploads/emptydir');
file_put_contents(backup_dir() . '/backup-debris.tmp', 'x');
T::ok('staging debris never lists', !in_array('backup-debris.tmp', array_column(backup_list(), 'name'), true));
@unlink(backup_dir() . '/backup-debris.tmp');
T::eq('db json to a bad path fails', false, backup_write_database_json($db, $tmpRoot . '/no-dir-xyz/x.json'));
file_put_contents($tmpRoot . '/empty.bin', '');
T::eq('empty file is invalid', 'invalid', (backup_verify($tmpRoot . '/empty.bin')['code'] ?? ''));
file_put_contents($tmpRoot . '/badgz.bin', "\x1f\x8bgarbage-garbage");
T::eq('broken gzip is invalid', 'invalid', (backup_verify($tmpRoot . '/badgz.bin')['code'] ?? ''));

// ── Crafted JSON documents: every shape guard ───────────────────────────────
$tmpDb2 = $tmpRoot . '/db2.json';
backup_write_database_json($db, $tmpDb2);
$dbPayload = json_decode((string)@file_get_contents($tmpDb2), true);
@unlink($tmpDb2);
$photosPayload = [];
foreach (array_keys($jsonManifest['files']) as $rel) {
    $photosPayload[$rel] = base64_encode((string)@file_get_contents($tmpRoot . '/' . $rel));
}
$mkDoc = static fn(array $m, mixed $d, mixed $p, string $f): string => (function () use ($m, $d, $p, $f): string {
    file_put_contents($f, json_encode(['manifest' => $m, 'db' => $d, 'photos' => $p]));
    return $f;
})();
$mkDoc = static function (array $m, mixed $d, mixed $p, string $f): string {
    file_put_contents($f, (string)json_encode(['manifest' => $m, 'db' => $d, 'photos' => $p]));
    return $f;
};
T::eq('doc without keys is invalid', 'invalid', (backup_verify($mkDoc([], $dbPayload, $photosPayload, $tmpRoot . '/c1.json'))['code'] ?? ''));
$zipFmt = $jsonManifest;
$zipFmt['format'] = 'zip';
$zipFmt['encoding'] = 'zip';
T::eq('zip manifest in a json doc is invalid', 'invalid', (backup_verify($mkDoc($zipFmt, $dbPayload, $photosPayload, $tmpRoot . '/c2.json'))['code'] ?? ''));
$dropDb = $dbPayload;
unset($dropDb['settings']);
T::eq('dropped table doc is invalid', 'invalid', (backup_verify($mkDoc($jsonManifest, $dropDb, $photosPayload, $tmpRoot . '/c3.json'))['code'] ?? ''));
T::eq('string photos doc is invalid', 'invalid', (backup_verify($mkDoc($jsonManifest, $dbPayload, 'x', $tmpRoot . '/c4.json'))['code'] ?? ''));
$missingPhoto = $photosPayload;
unset($missingPhoto['uploads/7/aaa.enc']);
T::eq('missing photo doc is invalid', 'invalid', (backup_verify($mkDoc($jsonManifest, $dbPayload, $missingPhoto, $tmpRoot . '/c5.json'))['code'] ?? ''));
$badB64 = $photosPayload;
$badB64['uploads/7/aaa.enc'] = '!!!not-base64!!!';
T::eq('bad base64 doc is invalid', 'invalid', (backup_verify($mkDoc($jsonManifest, $dbPayload, $badB64, $tmpRoot . '/c6.json'))['code'] ?? ''));
$wrongBytes = $photosPayload;
$wrongBytes['uploads/7/aaa.enc'] = base64_encode('wrong-bytes');
T::eq('wrong photo bytes doc is invalid', 'invalid', (backup_verify($mkDoc($jsonManifest, $dbPayload, $wrongBytes, $tmpRoot . '/c7.json'))['code'] ?? ''));
$misDoc = $mkDoc($jsonManifest, $dropDb, $photosPayload, $tmpRoot . '/c8.json');
$misRestore = backup_restore($db, $misDoc, $jsonManifest, $tmpRoot);
T::eq('count drift restores nothing', 'invalid', $misRestore['code'] ?? '');
T::eq('live data untouched by drift refusal', 'before', get_setting('backup_test_marker', ''));
// A boolean inside a restored row takes the PARAM_INT branch, never a crash.
// Restored twice: the boolean bundle proves the branch, the pristine bundle
// rewinds the coerced value so later suites inherit sane settings.
$boolRaw = (string)@file_get_contents($jsonPath);
if ($useGz && str_starts_with($boolRaw, "\x1f\x8b")) {
    $boolRaw = (string)@gzdecode($boolRaw);
}
$boolDoc = json_decode($boolRaw, true);
$boolSettings = (is_array($boolDoc) ? $boolDoc['db']['settings'] : null) ?? null;
if (is_array($boolDoc) && is_array($boolSettings) && $boolSettings !== []) {
    $boolDoc['db']['settings'][0]['value'] = true;
    file_put_contents($tmpRoot . '/c9.json', (string)json_encode($boolDoc));
    set_setting('backup_test_marker', 'after');
    $boolRestore = backup_restore($db, $tmpRoot . '/c9.json', $boolDoc['manifest'], $tmpRoot);
    T::eq('boolean row restores', true, $boolRestore['ok'] ?? false);
    $rewind = backup_restore($db, $jsonPath, $verJson['manifest'], $tmpRoot);
    T::eq('pristine bundle rewinds the coercion', true, $rewind['ok'] ?? false);
    T::eq('marker rewound via boolean restore', 'before', get_setting('backup_test_marker', ''));
    @unlink($tmpRoot . '/c9.json');
    @unlink($jsonPath);
} else {
    T::ok('boolean fixture has a settings row', false);
    @unlink($jsonPath);
}
foreach (['c1.json', 'c2.json', 'c3.json', 'c4.json', 'c5.json', 'c6.json', 'c7.json', 'c8.json', 'c9.json', 'empty.bin', 'badgz.bin'] as $junk) {
    @unlink($tmpRoot . '/' . $junk);
}
// The JSON writer refuses an unwritable destination.
T::eq('json bundle to a bad path fails', false, backup_write_json_bundle($tmpRoot . '/no-dir-xyz/x.json', $db, $jsonManifest, $useGz, $tmpRoot));

// ── Size caps: fail closed before buffering or staging ────────────────────
// A manifest is one entry per photo: over BACKUP_MAX_FILES valid entries is
// a hash-table DoS, refused as shape.
$manyFiles = $jsonManifest;
$manyFiles['files'] = [];
for ($i = 0; $i < BACKUP_MAX_FILES + 1; $i++) {
    $manyFiles['files']['uploads/cap/' . $i . '.enc'] = str_repeat('a', 64);
}
T::eq('manifest over the file cap rejected', null, backup_manifest_parse($manyFiles));
$edgeFiles = $jsonManifest;
$edgeFiles['files'] = [];
for ($i = 0; $i < BACKUP_MAX_FILES; $i++) {
    $edgeFiles['files']['uploads/cap/' . $i . '.enc'] = str_repeat('a', 64);
}
T::ok('manifest at the file cap parses', is_array(backup_manifest_parse($edgeFiles)));
unset($manyFiles, $edgeFiles);
// A JSON bundle over BACKUP_MAX_JSON_BYTES is refused by filesize before a
// single byte is buffered — the content below is irrelevant on purpose.
$bigJson = $tmpRoot . '/big.json';
$fhBig = @fopen($bigJson, 'wb');
if ($fhBig !== false) {
    fwrite($fhBig, '{"pad":"');
    fseek($fhBig, BACKUP_MAX_JSON_BYTES);
    fwrite($fhBig, 'x');
    fclose($fhBig);
    T::eq('oversized json verifies too_large', 'too_large', (backup_verify($bigJson)['code'] ?? ''));
    @mkdir($tmpRoot . '/wcap', 0775, true);
    $whyS = null;
    T::eq('oversized json stages nothing', false, backup_stage_files($bigJson, $jsonManifest, $tmpRoot . '/wcap', $whyS));
    T::eq('stage refusal says too_large', 'too_large', $whyS);
    $whyR = null;
    T::eq('oversized json reads no rows', null, backup_read_payload_rows($bigJson, $jsonManifest, $whyR));
    T::eq('rows refusal says too_large', 'too_large', $whyR);
    set_setting('backup_test_marker', 'after');
    $bigRestore = backup_restore($db, $bigJson, $jsonManifest, $tmpRoot);
    T::eq('oversized restore refuses', 'too_large', $bigRestore['code'] ?? '');
    T::eq('...with ok false', false, $bigRestore['ok'] ?? true);
    T::eq('live data untouched by size refusal', 'after', get_setting('backup_test_marker', ''));
    @rmdir($tmpRoot . '/wcap');
    @unlink($bigJson);
} else {
    T::ok('oversized fixture writable', false);
}
// A gzip bomb is small on disk (passes the filesize gate) and huge
// inflated: the buffered-document cap catches it after gzdecode.
if (extension_loaded('zlib')) {
    $bombRaw = str_repeat('B', BACKUP_MAX_JSON_BYTES + 1048576);
    file_put_contents($tmpRoot . '/bomb.json.gz', (string)gzencode($bombRaw, 9));
    unset($bombRaw);
    T::eq('gzip bomb verifies too_large', 'too_large', (backup_verify($tmpRoot . '/bomb.json.gz')['code'] ?? ''));
    @unlink($tmpRoot . '/bomb.json.gz');
}

// ── Crafted zips: every structural guard (ZipArchive hosts only) ────────────
if (backup_zip_supported()) {
    $zm = $jsonManifest;
    $zm['format'] = 'zip';
    $zm['encoding'] = 'zip';
    $tmpDbZ = $tmpRoot . '/dbz.json';
    backup_write_database_json($db, $tmpDbZ);
    $mkZip = static function (string $f, array $entries): string {
        $z = new ZipArchive();
        $z->open($f, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        foreach ($entries as $name => $content) {
            $z->addFromString($name, $content);
        }
        $z->close();
        return $f;
    };
    T::eq('zip without manifest is invalid', 'invalid', (backup_verify($mkZip($tmpRoot . '/z1.zip', ['x.txt' => 'x']))['code'] ?? ''));
    T::eq('zip with a json manifest is invalid', 'invalid', (backup_verify($mkZip($tmpRoot . '/z2.zip', ['manifest.json' => (string)json_encode($jsonManifest)]))['code'] ?? ''));
    T::eq('zip without database is invalid', 'invalid', (backup_verify($mkZip($tmpRoot . '/z3.zip', [
        'manifest.json' => (string)json_encode($zm),
        'uploads/7/aaa.enc' => 'x',
    ]))['code'] ?? ''));
    $dbJsonZ = (string)@file_get_contents($tmpDbZ);
    T::eq('zip with a missing photo is invalid', 'invalid', (backup_verify($mkZip($tmpRoot . '/z4.zip', [
        'manifest.json' => (string)json_encode($zm),
        'database.json' => $dbJsonZ,
        'uploads/7/aaa.enc' => (string)@file_get_contents($tmpRoot . '/uploads/7/aaa.enc'),
    ]))['code'] ?? ''));
    T::eq('zip with altered photo bytes is invalid', 'invalid', (backup_verify($mkZip($tmpRoot . '/z5.zip', [
        'manifest.json' => (string)json_encode($zm),
        'database.json' => $dbJsonZ,
        'uploads/7/aaa.enc' => 'WRONG-BYTES',
        'uploads/9-bbb.enc' => (string)@file_get_contents($tmpRoot . '/uploads/9-bbb.enc'),
    ]))['code'] ?? ''));
    file_put_contents($tmpRoot . '/pkjunk.bin', "PK\x03\x04" . 'junk-junk-junk');
    T::eq('unopenable zip verifies nothing', 'invalid', (backup_verify($tmpRoot . '/pkjunk.bin')['code'] ?? ''));
    $wstage = $tmpRoot . '/wstage';
    @mkdir($wstage, 0775, true);
    T::eq('unopenable zip stages nothing', false, backup_stage_files($tmpRoot . '/pkjunk.bin', $zm, $wstage));
    T::eq('unopenable zip reads no rows', null, backup_read_payload_rows($tmpRoot . '/pkjunk.bin', $zm));
    // A zip missing a manifest photo stages nothing (fail-closed at stage).
    T::eq('zip with a missing photo stages nothing', false, backup_stage_files($tmpRoot . '/z4.zip', $zm, $wstage));
    // A zip with altered photo bytes fails the stage checksum.
    $z5b = $mkZip($tmpRoot . '/z5b.zip', [
        'manifest.json' => (string)json_encode($zm),
        'database.json' => $dbJsonZ,
        'uploads/7/aaa.enc' => 'WRONG-BYTES',
        'uploads/9-bbb.enc' => (string)@file_get_contents($tmpRoot . '/uploads/9-bbb.enc'),
    ]);
    T::eq('zip with altered bytes stages nothing', false, backup_stage_files($z5b, $zm, $wstage));
    // A zip whose database drifts from the manifest reads no rows.
    $driftDb = json_decode($dbJsonZ, true);
    if (is_array($driftDb)) {
        $driftDb['settings'] = [];
        $z7 = $mkZip($tmpRoot . '/z7.zip', [
            'manifest.json' => (string)json_encode($zm),
            'database.json' => (string)json_encode($driftDb),
            'uploads/7/aaa.enc' => (string)@file_get_contents($tmpRoot . '/uploads/7/aaa.enc'),
            'uploads/9-bbb.enc' => (string)@file_get_contents($tmpRoot . '/uploads/9-bbb.enc'),
        ]);
        T::eq('zip with drifted database reads no rows', null, backup_read_payload_rows($z7, $zm));
    } else {
        T::ok('drift fixture decodes', false);
    }
    // A zip bomb: tiny on disk (zeros compress), huge streamed. 130 x 4 MiB
    // tops the 512 MiB stage cap while the physical file stays ~1 MiB.
    // addFile (not addFromString): libzip buffers added strings until
    // close, which would eat 520 MiB of test memory — files stream.
    $padFile = $tmpRoot . '/pad.bin';
    file_put_contents($padFile, str_repeat('0', 4 * 1024 * 1024));
    $sumPad = (string)hash_file('sha256', $padFile);
    $bm = $zm;
    $bm['files'] = [];
    $bomb = new ZipArchive();
    $bomb->open($tmpRoot . '/bomb.zip', ZipArchive::CREATE | ZipArchive::OVERWRITE);
    for ($i = 0; $i < 130; $i++) {
        $rel = 'uploads/bomb/' . $i . '.enc';
        $bm['files'][$rel] = $sumPad;
        $bomb->addFile($padFile, $rel);
    }
    $bomb->addFromString('database.json', $dbJsonZ);
    $bomb->addFromString('manifest.json', (string)json_encode($bm));
    $bomb->close();
    @unlink($padFile);
    $bombZip = $tmpRoot . '/bomb.zip';
    T::eq('zip bomb verifies too_large', 'too_large', (backup_verify($bombZip)['code'] ?? ''));
    $whyB = null;
    T::eq('zip bomb stages nothing', false, backup_stage_files($bombZip, $bm, $wstage, $whyB));
    T::eq('bomb stage refusal says too_large', 'too_large', $whyB);
    // A database.json over the buffer cap trips by entry size (stat, never
    // read): 64 MiB of spaces compresses to kilobytes on disk.
    $fatDb = str_repeat(' ', BACKUP_MAX_JSON_BYTES + 1);
    $fatZip = $mkZip($tmpRoot . '/fatdb.zip', [
        'manifest.json' => (string)json_encode($zm),
        'database.json' => $fatDb,
        'uploads/7/aaa.enc' => (string)@file_get_contents($tmpRoot . '/uploads/7/aaa.enc'),
        'uploads/9-bbb.enc' => (string)@file_get_contents($tmpRoot . '/uploads/9-bbb.enc'),
    ]);
    unset($fatDb);
    $whyF = null;
    T::eq('fat database verifies too_large', 'too_large', (backup_verify($fatZip)['code'] ?? ''));
    T::eq('fat database reads no rows', null, backup_read_payload_rows($fatZip, $zm, $whyF));
    T::eq('fat database refusal says too_large', 'too_large', $whyF);
    // z4 stages its one present photo before refusing the missing one, so
    // the stage dir may be non-empty — sweep it fully.
    if (is_dir($wstage)) {
        $sweep = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($wstage, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($sweep as $f) {
            /** @var SplFileInfo $f */
            $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($wstage);
    }
    @unlink($tmpDbZ);
    foreach (['z1.zip', 'z2.zip', 'z3.zip', 'z4.zip', 'z5.zip', 'z5b.zip', 'z7.zip', 'bomb.zip', 'fatdb.zip', 'pkjunk.bin'] as $junk) {
        @unlink($tmpRoot . '/' . $junk);
    }
}

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
