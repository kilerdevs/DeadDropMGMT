<?php
declare(strict_types=1);

// Owner backups: a complete, portable snapshot of everything that cannot be
// re-downloaded — all database rows plus the encrypted photo files under
// uploads/ — with a checksum manifest, verified before any restore.
//
// Two on-disk formats, chosen at creation time:
//
//   backup-<UTC>.zip      ZipArchive: manifest.json + database.json + uploads/…
//   backup-<UTC>.json.gz  pure PHP fallback (zlib): manifest, rows and
//   backup-<UTC>.json     base64 photos in one JSON document
//
// The zip path is preferred (photos ride as files, nothing is base64'd) but
// ZipArchive is a warn-level capability, not a guaranteed one — restricted
// hosts fall back to the JSON bundle with zero extensions beyond PDO. Both
// formats verify identically: strict manifest shape, sha256 over every
// payload entry, exact table-set match, row counts.
//
// Restore is verify-then-apply and fail-closed: a checksum mismatch, an
// unknown table, or a count drift refuses the whole file and changes
// nothing. The database half applies inside ONE transaction (DELETE + INSERT
// — never TRUNCATE, which is DDL and would implicit-commit on MySQL),
// foreign-key checks off for the load and back on before commit. Photo files
// cannot join the transaction, so they stage to uploads/.restore-*/ first,
// verify there, and only then move into place; a file-phase failure after
// the DB commit reports files_partial instead of pretending all is well.
//
// What is NOT in a backup, deliberately: tiles/ and data/ (zone files
// re-download or re-upload), logs/, cache/, config.php secrets. The manifest
// does carry two fingerprints — key_fp (sha256 over the AES master-key set,
// so a restore under a rotated key warns that photos will not decrypt until
// the original key is back) and config_crc (crc32 of config.php, so a move
// to a different host is diagnosable) — neither of which leaks key material.

const BACKUP_VERSION = 1;
// Parents before children; the restore loads with FK checks off anyway, but
// the canonical order keeps dumps and diffs readable.
const BACKUP_TABLES = [
    'users',
    'settings',
    'osm_proxies',
    'map_zones',
    'orders',
    'order_photos',
    'order_events',
    'rate_limits',
    'audit_log',
    'log_checkpoints',
];
const BACKUP_NAME_RE = '/^backup-\d{8}-\d{6}\.(zip|json\.gz|json)$/';
const BACKUP_CHUNK_ROWS = 500;
// Size caps: verify/stage/read buffer or stream attacker-shaped input, and a
// crafted bundle that passes checksums could otherwise exhaust memory (one
// fully-buffered JSON document) or disk (staged photos). The caps fail
// closed with code 'too_large': this host cannot safely hold that bundle —
// re-create it as zip (which streams) or restore it on a bigger host. The
// numbers: 20k photos is two orders above any real uploads/; 64 MiB is the
// largest single JSON document json_decode may hold under a 128M
// memory_limit; 512 MiB staged photos matches the 512 MB body ceiling the
// Docker profiles already assume.
const BACKUP_MAX_FILES = 20000;
const BACKUP_MAX_JSON_BYTES = 67108864;
const BACKUP_MAX_STAGE_BYTES = 536870912;

/** Where finished backups live. Web-denied on all four server profiles. */
function backup_dir(): string {
    return dirname(__DIR__) . '/backups';
}

function backup_uploads_dir(?string $root = null): string {
    return ($root ?? dirname(__DIR__)) . '/uploads';
}

/** Creatable + writable is all a backup needs — no exec, no extensions. */
function backup_supported(): bool {
    $dir = backup_dir();
    if (!is_dir($dir) && !@mkdir($dir, 0775, true)) {
        return false;
    }
    return host_dir_writable($dir);
}

function backup_zip_supported(): bool {
    return class_exists('ZipArchive');
}

/** Newest first. Strict names only — staging debris never lists. */
function backup_list(): array {
    $out = [];
    foreach (glob_list(backup_dir() . '/backup-*') as $path) {
        $name = basename($path);
        if (!is_file($path) || preg_match(BACKUP_NAME_RE, $name) !== 1) {
            continue;
        }
        $format = str_ends_with($name, '.zip') ? 'zip'
            : (str_ends_with($name, '.json.gz') ? 'json.gz' : 'json');
        $out[] = [
            'name' => $name, 'format' => $format,
            'size' => (int)@filesize($path), 'mtime' => (int)@filemtime($path),
        ];
    }
    usort($out, static fn(array $a, array $b): int => $b['mtime'] <=> $a['mtime']);
    return $out;
}

/** sha256 over the master-key SET (current + previous versions): a different
 *  key anywhere in the rotation chain fingerprints differently, but the
 *  fingerprint itself decrypts nothing. */
function backup_key_fingerprint(): string {
    $raw = '';
    foreach (_master_keys() as $ver => $bytes) {
        $raw .= $ver . ':' . $bytes . ';';
    }
    return hash('sha256', $raw);
}

/** crc32 of config.php — drift detection for host moves, not secrets. */
function backup_config_crc(): string {
    $raw = @file_get_contents(dirname(__DIR__) . '/config.php');
    return is_string($raw) ? sprintf('%u', crc32($raw)) : '0';
}

/** Chunked row reads: flat memory even for a long audit_log, and the shared
 *  PDO handle keeps its buffered-query mode untouched. */
function backup_read_table_chunk(PDO $db, string $table, int $offset, int $limit): array {
    $stmt = $db->prepare('SELECT * FROM `' . $table . '` LIMIT ' . $limit . ' OFFSET ' . $offset);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function backup_table_count(PDO $db, string $table): int {
    return (int)$db->query('SELECT COUNT(*) FROM `' . $table . '`')->fetchColumn();
}

/** Every encrypted photo file under uploads/, as app-relative paths with
 *  sha256. Dot-directories (staging, pseudo-cron locks) are never payload. */
function backup_photo_files(?string $root = null): array {
    $base = backup_uploads_dir($root);
    $files = [];
    if (!is_dir($base)) {
        return $files;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($it as $file) {
        /** @var SplFileInfo $file */
        if (!$file->isFile()) {
            continue;
        }
        $rel = substr($file->getPathname(), strlen($base) + 1);
        $rel = str_replace(DIRECTORY_SEPARATOR, '/', $rel);
        if ($rel === '' || str_starts_with($rel, '.')) {
            continue;
        }
        $sum = @hash_file('sha256', $file->getPathname());
        if (!is_string($sum)) {
            continue;
        }
        $files['uploads/' . $rel] = $sum;
    }
    ksort($files);
    return $files;
}

/**
 * Create a backup. Streams everything (chunked reads, addFile, gz streaming)
 * so a large uploads/ never sits in memory.
 *
 * @return array{ok:bool,file?:string,format?:string,tables?:int,rows?:int,files?:int,code?:string}
 */
function backup_create(PDO $db, ?string $root = null): array {
    $dir = backup_dir();
    if (!backup_supported()) {
        return ['ok' => false, 'code' => 'unsupported'];
    }
    $stamp = gmdate('Ymd-His');
    $useZip = backup_zip_supported();
    $useGz = !$useZip && extension_loaded('zlib');
    $ext = $useZip ? 'zip' : ($useGz ? 'json.gz' : 'json');
    $name = 'backup-' . $stamp . '.' . $ext;
    for ($i = 1; $i < 100 && is_file($dir . '/' . $name); $i++) {
        $name = 'backup-' . $stamp . '-' . $i . '.' . $ext;
    }
    $dest = $dir . '/' . $name;
    if (is_file($dest)) {
        return ['ok' => false, 'code' => 'create_failed'];
    }

    try {
        $counts = [];
        foreach (BACKUP_TABLES as $table) {
            $counts[$table] = backup_table_count($db, $table);
        }
        $photos = backup_photo_files($root);
        $manifest = [
            'backup' => BACKUP_VERSION,
            'created_utc' => gmdate('Y-m-d H:i:s'),
            'app' => DDMGMT_BUNDLED_VERSION,
            'format' => $useZip ? 'zip' : 'json',
            'encoding' => $useZip ? 'zip' : ($useGz ? 'gzip' : 'raw'),
            'key_fp' => backup_key_fingerprint(),
            'config_crc' => backup_config_crc(),
            'db' => $counts,
            'files' => $photos,
        ];
        $rows = array_sum($counts);

        if ($useZip) {
            $zip = new ZipArchive();
            if ($zip->open($dest, ZipArchive::CREATE | ZipArchive::EXCL) !== true) {
                return ['ok' => false, 'code' => 'create_failed'];
            }
            $tmpDb = $dir . '/.database-' . bin2hex(random_bytes(8)) . '.json';
            $ok = backup_write_database_json($db, $tmpDb);
            if (!$ok || !$zip->addFile($tmpDb, 'database.json')) {
                @unlink($tmpDb);
                $zip->close();
                @unlink($dest);
                return ['ok' => false, 'code' => 'create_failed'];
            }
            $base = backup_uploads_dir($root);
            foreach (array_keys($photos) as $rel) {
                $src = $base . '/' . substr($rel, strlen('uploads/'));
                if (!is_file($src) || !$zip->addFile($src, $rel)) {
                    // A photo that vanished mid-backup invalidates the
                    // manifest — abort rather than ship a half bundle.
                    @unlink($tmpDb);
                    $zip->close();
                    @unlink($dest);
                    return ['ok' => false, 'code' => 'create_failed'];
                }
            }
            $zip->addFromString('manifest.json', (string)json_encode($manifest));
            $zip->close();
            @unlink($tmpDb);
        } else {
            if (!backup_write_json_bundle($dest, $db, $manifest, $useGz, $root)) {
                @unlink($dest);
                return ['ok' => false, 'code' => 'create_failed'];
            }
        }
    } catch (Throwable $e) {
        log_err('backup create failed: ' . $e->getMessage());
        @unlink($dest);
        return ['ok' => false, 'code' => 'create_failed'];
    }
    @chmod($dest, 0600);
    return [
        'ok' => true, 'file' => $name, 'format' => $ext,
        'tables' => count($counts), 'rows' => $rows, 'files' => count($photos),
    ];
}

/** Stream {table:[rows]} to a temp file, chunked. Shared by both formats. */
function backup_write_database_json(PDO $db, string $path): bool {
    $fh = @fopen($path, 'wb');
    if ($fh === false) {
        return false;
    }
    $first = true;
    fwrite($fh, '{');
    foreach (BACKUP_TABLES as $table) {
        fwrite($fh, ($first ? '' : ',') . json_encode($table) . ':[');
        $first = false;
        $offset = 0;
        $rowFirst = true;
        for (;;) {
            $rows = backup_read_table_chunk($db, $table, $offset, BACKUP_CHUNK_ROWS);
            if ($rows === []) {
                break;
            }
            foreach ($rows as $row) {
                $json = json_encode($row);
                if (!is_string($json)) {
                    fclose($fh);
                    return false;
                }
                fwrite($fh, ($rowFirst ? '' : ',') . $json);
                $rowFirst = false;
            }
            $offset += count($rows);
            if (count($rows) < BACKUP_CHUNK_ROWS) {
                break;
            }
        }
        fwrite($fh, ']');
    }
    fwrite($fh, '}');
    return fclose($fh);
}

/** Fallback bundle: manifest + rows + base64 photos in one JSON document,
 *  gzipped when zlib exists. Base64 runs on 3-byte-multiple chunks so the
 *  stream never holds a whole photo. */
function backup_write_json_bundle(string $dest, PDO $db, array $manifest, bool $useGz, ?string $root): bool {
    $tmpDb = backup_dir() . '/.database-' . bin2hex(random_bytes(8)) . '.json';
    if (!backup_write_database_json($db, $tmpDb)) {
        @unlink($tmpDb);
        return false;
    }
    $write = $useGz ? @gzopen($dest, 'wb9') : @fopen($dest, 'wb');
    if ($write === false) {
        @unlink($tmpDb);
        return false;
    }
    $put = static function (string $s) use ($write, $useGz): void {
        if ($useGz) {
            gzwrite($write, $s);
        } else {
            fwrite($write, $s);
        }
    };
    $close = static function () use ($write, $useGz): bool {
        return $useGz ? gzclose($write) : fclose($write);
    };
    $put('{"manifest":' . (string)json_encode($manifest) . ',"db":');
    $dbJson = @file_get_contents($tmpDb);
    @unlink($tmpDb);
    if (!is_string($dbJson)) {
        $close();
        return false;
    }
    $put($dbJson . ',"photos":{');
    $base = backup_uploads_dir($root);
    $first = true;
    foreach (array_keys($manifest['files']) as $rel) {
        $src = $base . '/' . substr($rel, strlen('uploads/'));
        $fh = @fopen($src, 'rb');
        if ($fh === false) {
            $close();
            return false;
        }
        $put(($first ? '' : ',') . json_encode($rel) . ':"');
        $first = false;
        while (!feof($fh)) {
            $chunk = fread($fh, 8190); // 2730 * 3: base64-safe splits
            if ($chunk === false || ($chunk === '' && !feof($fh))) {
                fclose($fh);
                $close();
                return false;
            }
            if ($chunk !== '') {
                $put(base64_encode($chunk));
            }
        }
        fclose($fh);
        $put('"');
    }
    $put('}}');
    return $close();
}

/** Strict manifest shape check. Anything off-spec is not a backup. */
function backup_manifest_parse(mixed $raw): ?array {
    if (!is_array($raw)) {
        return null;
    }
    if (($raw['backup'] ?? null) !== BACKUP_VERSION) {
        return null;
    }
    foreach (['created_utc', 'app', 'format', 'encoding', 'key_fp', 'config_crc'] as $k) {
        if (!is_string($raw[$k] ?? null) || ($raw[$k] ?? '') === '') {
            return null;
        }
    }
    if (!in_array($raw['format'], ['zip', 'json'], true)
        || !in_array($raw['encoding'], ['zip', 'gzip', 'raw'], true)
    ) {
        return null;
    }
    if (!is_array($raw['db'] ?? null) || !is_array($raw['files'] ?? null)) {
        return null;
    }
    // Exact table set: a backup from a different schema version refuses
    // rather than half-restoring.
    $tables = array_keys($raw['db']);
    sort($tables);
    $want = BACKUP_TABLES;
    sort($want);
    if ($tables !== $want) {
        return null;
    }
    foreach ($raw['db'] as $count) {
        if (!is_int($count) || $count < 0) {
            return null;
        }
    }
    foreach ($raw['files'] as $rel => $sum) {
        if (!is_string($rel) || !is_string($sum)
            || preg_match('#^uploads/[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$#', $rel) !== 1
            || str_contains($rel, '..')
            || preg_match('/^[0-9a-f]{64}$/', $sum) !== 1
        ) {
            return null;
        }
    }
    // A manifest is small by construction (one entry per photo): tens of
    // thousands of entries is not a backup, it is a hash-table DoS against
    // every loop below. Refused as shape, reported as 'invalid'.
    if (count($raw['files']) > BACKUP_MAX_FILES) {
        return null;
    }
    return $raw;
}

/** True when a JSON bundle is too big to buffer: checked by filesize BEFORE
 *  any byte is read, so the check itself costs no memory. A missing size is
 *  not "too large" — downstream verify fails it as 'invalid' instead. */
function backup_json_too_large(string $path): bool {
    $size = @filesize($path);
    return $size !== false && $size > BACKUP_MAX_JSON_BYTES;
}

/** True when a bundle cannot be safely held by this host: JSON by filesize,
 *  zip by its database.json entry size (stat, not read). Used by verify and
 *  restore BEFORE anything is buffered or staged, so both answer 'too_large'
 *  without touching memory or disk. */
function backup_exceeds_caps(string $path): bool {
    if (!is_file($path)) {
        return false;
    }
    $head = (string)@file_get_contents($path, false, null, 0, 4);
    if (str_starts_with($head, "PK\x03\x04")) {
        if (!backup_zip_supported()) {
            return false;
        }
        $zip = new ZipArchive();
        if ($zip->open($path) !== true) {
            return false;
        }
        $st = $zip->statName('database.json');
        $zip->close();
        // Missing is not oversized: a bundle without database.json is a
        // shape refusal ('invalid') downstream, not a size one.
        return $st !== false && (int)($st['size'] ?? 0) > BACKUP_MAX_JSON_BYTES;
    }
    return backup_json_too_large($path);
}

/**
 * Verify a backup file without changing anything. Recomputes every sha256,
 * rechecks row counts, flags a rotated key as a non-fatal warning.
 *
 * @return array{ok:bool,manifest?:array,key_mismatch?:bool,code?:string}
 */
function backup_verify(string $path): array {
    if (!is_file($path)) {
        return ['ok' => false, 'code' => 'invalid'];
    }
    if (backup_exceeds_caps($path)) {
        return ['ok' => false, 'code' => 'too_large'];
    }
    try {
        $head = (string)@file_get_contents($path, false, null, 0, 4);
        if (str_starts_with($head, "PK\x03\x04")) {
            return backup_verify_zip($path);
        }
        if ($head !== '' && ($head[0] === '{' || $head[0] === "\x1f")) {
            return backup_verify_json($path);
        }
    } catch (Throwable $e) {
        log_err('backup verify failed: ' . $e->getMessage());
    }
    return ['ok' => false, 'code' => 'invalid'];
}

function backup_verify_zip(string $path): array {
    if (!backup_zip_supported()) {
        return ['ok' => false, 'code' => 'invalid'];
    }
    $zip = new ZipArchive();
    if ($zip->open($path) !== true) {
        return ['ok' => false, 'code' => 'invalid'];
    }
    $rawManifest = $zip->getFromName('manifest.json');
    if (!is_string($rawManifest)) {
        $zip->close();
        return ['ok' => false, 'code' => 'invalid'];
    }
    $manifest = backup_manifest_parse(json_decode($rawManifest, true));
    if ($manifest === null || $manifest['format'] !== 'zip') {
        $zip->close();
        return ['ok' => false, 'code' => 'invalid'];
    }
    $rawDb = $zip->getFromName('database.json');
    if (!is_string($rawDb) || !backup_database_matches($rawDb, $manifest)) {
        $zip->close();
        return ['ok' => false, 'code' => 'invalid'];
    }
    $total = 0;
    foreach ($manifest['files'] as $rel => $sum) {
        $stream = $zip->getStream($rel);
        if ($stream === false) {
            $zip->close();
            return ['ok' => false, 'code' => 'invalid'];
        }
        $ctx = hash_init('sha256');
        while (!feof($stream)) {
            $chunk = fread($stream, 65536);
            if ($chunk === false) {
                fclose($stream);
                $zip->close();
                return ['ok' => false, 'code' => 'invalid'];
            }
            hash_update($ctx, $chunk);
            // Cumulative cap: a zip bomb (tiny on disk, huge streamed)
            // trips here instead of filling the disk at stage time.
            $total += strlen($chunk);
            if ($total > BACKUP_MAX_STAGE_BYTES) {
                fclose($stream);
                $zip->close();
                return ['ok' => false, 'code' => 'too_large'];
            }
        }
        fclose($stream);
        if (hash_final($ctx) !== $sum) {
            $zip->close();
            return ['ok' => false, 'code' => 'invalid'];
        }
    }
    $zip->close();
    return ['ok' => true, 'manifest' => $manifest, 'key_mismatch' => $manifest['key_fp'] !== backup_key_fingerprint()];
}

/** database.json must hold exactly the manifest's tables and counts. */
function backup_database_matches(string $rawDb, array $manifest): bool {
    $db = json_decode($rawDb, true);
    if (!is_array($db)) {
        return false;
    }
    $tables = array_keys($db);
    sort($tables);
    $want = BACKUP_TABLES;
    sort($want);
    if ($tables !== $want) {
        return false;
    }
    foreach ($db as $table => $rows) {
        if (!is_array($rows) || count($rows) !== (int)$manifest['db'][$table]) {
            return false;
        }
        foreach ($rows as $row) {
            if (!is_array($row)) {
                return false;
            }
        }
    }
    return true;
}

function backup_verify_json(string $path): array {
    $raw = (string)@file_get_contents($path);
    if ($raw === '') {
        return ['ok' => false, 'code' => 'invalid'];
    }
    if (str_starts_with($raw, "\x1f\x8b")) {
        if (!extension_loaded('zlib')) {
            return ['ok' => false, 'code' => 'invalid'];
        }
        $raw = (string)@gzdecode($raw);
        if ($raw === '') {
            return ['ok' => false, 'code' => 'invalid'];
        }
        // A gzip bomb is small on disk (passes the filesize gate) and huge
        // inflated: cap the buffered document, not just the file.
        if (strlen($raw) > BACKUP_MAX_JSON_BYTES) {
            return ['ok' => false, 'code' => 'too_large'];
        }
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !isset($doc['manifest'], $doc['db'], $doc['photos'])) {
        return ['ok' => false, 'code' => 'invalid'];
    }
    $manifest = backup_manifest_parse($doc['manifest']);
    if ($manifest === null || $manifest['format'] !== 'json') {
        return ['ok' => false, 'code' => 'invalid'];
    }
    if (!backup_database_matches((string)json_encode($doc['db']), $manifest)) {
        return ['ok' => false, 'code' => 'invalid'];
    }
    if (!is_array($doc['photos'])) {
        return ['ok' => false, 'code' => 'invalid'];
    }
    foreach ($manifest['files'] as $rel => $sum) {
        $b64 = $doc['photos'][$rel] ?? null;
        if (!is_string($b64)) {
            return ['ok' => false, 'code' => 'invalid'];
        }
        $bin = base64_decode($b64, true);
        if (!is_string($bin) || hash('sha256', $bin) !== $sum) {
            return ['ok' => false, 'code' => 'invalid'];
        }
    }
    return ['ok' => true, 'manifest' => $manifest, 'key_mismatch' => $manifest['key_fp'] !== backup_key_fingerprint()];
}

/**
 * Restore a VERIFIED backup (pass backup_verify() output's manifest). The
 * caller re-verifies cheaply by reusing the same manifest — the file is
 * re-read entry by entry, so a swap between verify and restore still fails.
 *
 * @return array{ok:bool,code?:string,key_mismatch?:bool,files_partial?:bool}
 */
function backup_restore(PDO $db, string $path, array $manifest, ?string $root = null): array {
    // Size first: an oversized bundle is refused before a stage directory
    // or a transaction exists, so the refusal touches neither disk nor DB.
    if (backup_exceeds_caps($path)) {
        return ['ok' => false, 'code' => 'too_large'];
    }
    // Files stage first: every payload byte is checksummed in staging before
    // the database transaction opens, so a corrupt photo fails with the live
    // data untouched.
    $stage = backup_uploads_dir($root) . '/.restore-' . bin2hex(random_bytes(8));
    if (!@mkdir($stage, 0775, true)) {
        return ['ok' => false, 'code' => 'restore_failed'];
    }
    $cleanup = static function () use ($stage): void {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($stage, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            /** @var SplFileInfo $f */
            $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($stage);
    };
    try {
        $why = null;
        $staged = backup_stage_files($path, $manifest, $stage, $why);
        if (!$staged) {
            $cleanup();
            return ['ok' => false, 'code' => $why === 'too_large' ? 'too_large' : 'invalid'];
        }
        $rows = backup_read_payload_rows($path, $manifest, $why);
        if ($rows === null) {
            $cleanup();
            return ['ok' => false, 'code' => $why === 'too_large' ? 'too_large' : 'invalid'];
        }
        // The database half: one transaction, DELETE (never TRUNCATE — DDL
        // would implicit-commit on MySQL and split the restore in two).
        $db->beginTransaction();
        try {
            $db->exec('SET FOREIGN_KEY_CHECKS=0');
            foreach (BACKUP_TABLES as $table) {
                $db->exec('DELETE FROM `' . $table . '`');
                $chunks = array_chunk($rows[$table], BACKUP_CHUNK_ROWS);
                foreach ($chunks as $chunk) {
                    if ($chunk === []) {
                        continue;
                    }
                    $cols = array_keys($chunk[0]);
                    $place = '(' . implode(',', array_fill(0, count($cols), '?')) . ')';
                    $stmt = $db->prepare(
                        'INSERT INTO `' . $table . '` (`' . implode('`,`', $cols) . '`) VALUES '
                        . implode(',', array_fill(0, count($chunk), $place))
                    );
                    $n = 1;
                    foreach ($chunk as $row) {
                        foreach ($cols as $col) {
                            $val = $row[$col] ?? null;
                            if ($val === null) {
                                $stmt->bindValue($n, null, PDO::PARAM_NULL);
                            } elseif (is_int($val)) {
                                $stmt->bindValue($n, $val, PDO::PARAM_INT);
                            } elseif (is_bool($val)) {
                                $stmt->bindValue($n, $val ? 1 : 0, PDO::PARAM_INT);
                            } else {
                                $stmt->bindValue($n, (string)$val, PDO::PARAM_STR);
                            }
                            $n++;
                        }
                    }
                    $stmt->execute();
                }
            }
            $db->exec('SET FOREIGN_KEY_CHECKS=1');
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $e;
        }
        // Publish the staged photos over uploads/: new files move in,
        // orphans (in uploads/ but in no backup) are deleted. Past the DB
        // commit, so failures here report instead of rolling back.
        $filesPartial = !backup_publish_staged($stage, $manifest, $root);
        $cleanup();
    } catch (Throwable $e) {
        log_err('backup restore failed: ' . $e->getMessage());
        $cleanup();
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        return ['ok' => false, 'code' => 'restore_failed'];
    }
    $out = ['ok' => true, 'key_mismatch' => $manifest['key_fp'] !== backup_key_fingerprint()];
    if ($filesPartial) {
        $out['files_partial'] = true;
    }
    // Rows were replaced behind every cache's back — the next read in this
    // process must come from the database, not the pre-restore snapshot.
    if (function_exists('settings_invalidate')) {
        settings_invalidate();
    }
    return $out;
}

/** Copy every manifest file into staging, checksumming on arrival. $why
 *  carries the refusal reason ('too_large' vs silent false) so the caller
 *  can answer the right code without re-streaming the bundle. */
function backup_stage_files(string $path, array $manifest, string $stage, ?string &$why = null): bool {
    $isZip = str_starts_with((string)@file_get_contents($path, false, null, 0, 4), "PK\x03\x04");
    if ($isZip) {
        if (!backup_zip_supported()) {
            return false;
        }
        $zip = new ZipArchive();
        if ($zip->open($path) !== true) {
            return false;
        }
        $total = 0;
        foreach ($manifest['files'] as $rel => $sum) {
            $stream = $zip->getStream($rel);
            if ($stream === false) {
                $zip->close();
                return false;
            }
            $dst = $stage . '/' . substr($rel, strlen('uploads/'));
            $dstDir = dirname($dst);
            if (!is_dir($dstDir) && !@mkdir($dstDir, 0775, true)) {
                fclose($stream);
                $zip->close();
                return false;
            }
            $out = @fopen($dst, 'wb');
            if ($out === false) {
                fclose($stream);
                $zip->close();
                return false;
            }
            $ctx = hash_init('sha256');
            while (!feof($stream)) {
                $chunk = fread($stream, 65536);
                if ($chunk === false) {
                    fclose($stream);
                    fclose($out);
                    $zip->close();
                    return false;
                }
                hash_update($ctx, $chunk);
                fwrite($out, $chunk);
                // Cumulative cap: staged bytes are real disk. A bundle that
                // verified small per-entry but streams huge dies here, with
                // the stage swept by the caller.
                $total += strlen($chunk);
                if ($total > BACKUP_MAX_STAGE_BYTES) {
                    fclose($stream);
                    fclose($out);
                    $zip->close();
                    $why = 'too_large';
                    return false;
                }
            }
            fclose($stream);
            fclose($out);
            if (hash_final($ctx) !== $sum) {
                $zip->close();
                return false;
            }
        }
        $zip->close();
        return true;
    }
    // JSON bundle: decode from the document.
    if (backup_json_too_large($path)) {
        $why = 'too_large';
        return false;
    }
    $raw = (string)@file_get_contents($path);
    if (str_starts_with($raw, "\x1f\x8b")) {
        if (!extension_loaded('zlib')) {
            return false;
        }
        $raw = (string)@gzdecode($raw);
        if (strlen($raw) > BACKUP_MAX_JSON_BYTES) {
            $why = 'too_large';
            return false;
        }
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !is_array($doc['photos'] ?? null)) {
        return false;
    }
    foreach ($manifest['files'] as $rel => $sum) {
        $b64 = $doc['photos'][$rel] ?? null;
        if (!is_string($b64)) {
            return false;
        }
        $bin = base64_decode($b64, true);
        if (!is_string($bin) || hash('sha256', $bin) !== $sum) {
            return false;
        }
        $dst = $stage . '/' . substr($rel, strlen('uploads/'));
        $dstDir = dirname($dst);
        if (!is_dir($dstDir) && !@mkdir($dstDir, 0775, true)) {
            return false;
        }
        if (@file_put_contents($dst, $bin) !== strlen($bin)) {
            return false;
        }
    }
    return true;
}

/** Re-read the row payload (fail-closed: counts must still match). $why
 *  carries 'too_large' the same way backup_stage_files() does. */
function backup_read_payload_rows(string $path, array $manifest, ?string &$why = null): ?array {
    $isZip = str_starts_with((string)@file_get_contents($path, false, null, 0, 4), "PK\x03\x04");
    if ($isZip) {
        if (!backup_zip_supported()) {
            return null;
        }
        $zip = new ZipArchive();
        if ($zip->open($path) !== true) {
            return null;
        }
        // database.json buffers fully below: gate its entry size by stat,
        // not by reading it. (Restore already pre-checked via
        // backup_exceeds_caps(); this guards direct callers too.)
        $st = $zip->statName('database.json');
        if ($st !== false && (int)($st['size'] ?? 0) > BACKUP_MAX_JSON_BYTES) {
            $zip->close();
            $why = 'too_large';
            return null;
        }
        $rawDb = $zip->getFromName('database.json');
        $zip->close();
        if (!is_string($rawDb) || !backup_database_matches($rawDb, $manifest)) {
            return null;
        }
        /** @var array $rows */
        $rows = json_decode($rawDb, true);
        return $rows;
    }
    if (backup_json_too_large($path)) {
        $why = 'too_large';
        return null;
    }
    $raw = (string)@file_get_contents($path);
    if (str_starts_with($raw, "\x1f\x8b")) {
        if (!extension_loaded('zlib')) {
            return null;
        }
        $raw = (string)@gzdecode($raw);
        if (strlen($raw) > BACKUP_MAX_JSON_BYTES) {
            $why = 'too_large';
            return null;
        }
    }
    $doc = json_decode($raw, true);
    if (!is_array($doc) || !is_array($doc['db'] ?? null)) {
        return null;
    }
    if (!backup_database_matches((string)json_encode($doc['db']), $manifest)) {
        return null;
    }
    return $doc['db'];
}

/** Move staged files into uploads/, deleting orphans. Best-effort past the
 *  DB commit: returns false when anything did not land, never throws. */
function backup_publish_staged(string $stage, array $manifest, ?string $root): bool {
    $base = backup_uploads_dir($root);
    $ok = true;
    foreach (array_keys($manifest['files']) as $rel) {
        $relPath = substr($rel, strlen('uploads/'));
        $src = $stage . '/' . $relPath;
        $dst = $base . '/' . $relPath;
        $dstDir = dirname($dst);
        if (!is_dir($dstDir) && !@mkdir($dstDir, 0775, true)) {
            $ok = false;
            continue;
        }
        if (!@rename($src, $dst)) {
            $ok = false;
        }
    }
    // Orphans: files the backup does not know. They belonged to deleted
    // orders — or to nobody at all — and a restore means "become the
    // backup", so they go. Dotfiles and directories are never touched.
    $want = [];
    foreach (array_keys($manifest['files']) as $rel) {
        $want[substr($rel, strlen('uploads/'))] = true;
    }
    if (is_dir($base)) {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $file) {
            /** @var SplFileInfo $file */
            $relPath = substr($file->getPathname(), strlen($base) + 1);
            $relPath = str_replace(DIRECTORY_SEPARATOR, '/', $relPath);
            if ($relPath === '' || str_starts_with($relPath, '.')) {
                continue;
            }
            if ($file->isDir()) {
                @rmdir($file->getPathname()); // only removes emptied dirs
                continue;
            }
            if (!isset($want[$relPath]) && !@unlink($file->getPathname())) {
                $ok = false;
            }
        }
    }
    return $ok;
}

/** Delete a finished backup. Strict names only — nothing else in backups/
 *  is reachable through here. */
function backup_delete(string $name): bool {
    if (preg_match(BACKUP_NAME_RE, $name) !== 1) {
        return false;
    }
    $path = backup_dir() . '/' . $name;
    return is_file($path) && @unlink($path);
}
