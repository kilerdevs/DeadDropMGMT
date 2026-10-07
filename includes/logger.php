<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';

// ── Structured application log with tamper-evident chain ──────────────────────
// Every entry is one JSON line in logs/app.log:
//   {ts, level, event, msg, ip, user, req, ...ctx, prev, seq, hash}
// "prev" holds the previous entry's hash; "seq" is a global monotonic
// sequence number (continues across rotation); "hash" is HMAC-SHA256 over
// the whole record (key derived from AES_KEY_HEX with domain separation).
// Editing, reordering, or deleting any historical line breaks every
// subsequent hash, so tampering is detectable via verify_log_chain().
// Pure tail DELETION leaves a shorter chain that still verifies — that half
// is covered by truncation checkpoints (log_checkpoints table, written by
// the hourly cleanup pass) compared in verify_log_continuity(). Rotation
// keeps one generation (app.log.1) and starts a fresh file, but numbering
// does not restart (the first entry continues the rotated tip's seq).

if (!defined('APP_LOG_PATH')) {
    define('APP_LOG_PATH', dirname(__DIR__) . '/logs/app.log');
}

const APP_LOG_MAX_BYTES   = 5 * 1024 * 1024;
const APP_LOG_GENESIS     = '0000000000000000000000000000000000000000000000000000000000000000';

// Log-integrity subkey: HKDF-derived from the master key with the same public
// salt includes/crypto.php uses (ADR-016 key separation) — a leaked log-chain
// key neither helps decrypt locations nor vice versa. Legacy entries written
// before key separation used HMAC keyed with the raw hex string; verification
// still accepts them until the log rotates out (see verify_log_chain).
// The master key text the chain key derives from. Test seam (see
// maps_cli_runner): a suite installs a bogus value to exercise the "key
// unusable" arms in-process — the constant itself cannot change — and clears
// it again ($clear) so nothing leaks into later files.
function _log_key_hex(?string $override = null, bool $clear = false): string {
    static $forced = null;
    if ($clear) {
        $forced = null;
    } elseif ($override !== null) {
        $forced = $override;
    }
    return $forced ?? (defined('AES_KEY_HEX') ? (string)AES_KEY_HEX : '');
}

// (self-contained on purpose: config.php loads this file before crypto.php)
function _log_key(): string {
    static $cache = [];
    $hex = _log_key_hex();
    if (!isset($cache[$hex])) {
        $master = preg_match('/^[0-9a-fA-F]{64}$/', $hex) === 1 ? hex2bin($hex) : false;
        if ($master === false) {
            throw new RuntimeException('Log integrity key unavailable: AES_KEY_HEX is not a valid 64-hex-char key.');
        }
        $cache[$hex] = hash_hkdf('sha256', $master, 32, 'deaddrop:log-hmac-v1', 'deaddrop-mgmt-hkdf-salt-v1');
    }
    return $cache[$hex];
}

function _log_key_legacy(): string {
    return hash_hmac('sha256', 'deaddrop-log-integrity-v1', AES_KEY_HEX, true);
}

function _log_req_id(): string {
    static $req = null;
    if ($req === null) {
        $req = bin2hex(random_bytes(4));
    }
    return $req;
}

// Read the tip of the log: [hash, seq] of the last complete JSON line.
// Caller holds LOCK_EX (writers) or LOCK_SH (read-only peeks). Scans
// backwards in growing windows: a single entry larger than one window must
// not anchor the next write to the second-to-last hash (which would
// permanently alarm the chain on the following verify). Garbage lines inside
// the view are still skipped (tolerance is test-pinned); only a possibly
// window-truncated TAIL line triggers a wider re-read. Empty file →
// [GENESIS, 0]; content without any parseable entry → ['', 0] (the writer
// refuses to append — anchoring to nothing would fork the chain).
// Records predating sequence numbers report seq 0; the writer counts.
/**
 * @param resource $fh
 * @return array{0:string,1:int}
 */
function _log_tail_tip($fh): array {
    fseek($fh, 0, SEEK_END);
    $size = ftell($fh);
    if ($size === 0) {
        return [APP_LOG_GENESIS, 0];
    }
    $window = 8192;
    while (true) {
        $cover_all = $window >= $size;
        $tail_len  = (int)($cover_all ? $size : $window);
        fseek($fh, -$tail_len, SEEK_END);
        $tail  = fread($fh, $tail_len);
        $lines = explode("\n", rtrim($tail));
        $last  = count($lines) - 1;
        for ($i = $last; $i >= 0; $i--) {
            $line = trim($lines[$i]);
            if ($line === '') {
                continue;
            }
            $rec = json_decode($line, true);
            if (is_array($rec) && isset($rec['hash']) && is_string($rec['hash'])) {
                return [$rec['hash'], (int)($rec['seq'] ?? 0)];
            }
            // Unparseable tail line with unseen file above it: the entry is
            // cut by the window edge, not garbage — widen and retry instead
            // of anchoring to an older hash.
            if ($i === $last && !$cover_all) {
                break;
            }
        }
        if ($cover_all) {
            break;
        }
        $window *= 8;
    }
    // File has content but no parseable last entry — treat as broken start
    return ['', 0];
}

/** @param resource $fh */
function _log_last_hash($fh): string {
    return _log_tail_tip($fh)[0];
}

// Count entries (non-blank lines) from the start. Runs only when the tip
// predates sequence numbers — at most once per legacy generation, since
// every new write lands sequenced and tips carry seq from then on.
/** @param resource $fh */
function _log_count_entries($fh): int {
    rewind($fh);
    $n = 0;
    while (($line = fgets($fh)) !== false) {
        if (trim($line) !== '') {
            $n++;
        }
    }
    return $n;
}

// Tip [hash, seq] of the rotated generation, or [GENESIS, 0] when there is
// none to continue (missing, unreadable or unparseable).
/** @return array{0:string,1:int} */
function _log_rot_tip(string $rotPath): array {
    if (!is_file($rotPath)) {
        return [APP_LOG_GENESIS, 0];
    }
    $fh = @fopen($rotPath, 'r');
    if ($fh === false) {
        return [APP_LOG_GENESIS, 0];
    }
    flock($fh, LOCK_SH);
    try {
        $tip = _log_tail_tip($fh);
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
    return $tip[0] === '' ? [APP_LOG_GENESIS, 0] : $tip;
}

// Tip seq of the rotated generation, or 0 when there is none to continue.
function _log_rot_tip_seq(string $rotPath): int {
    return _log_rot_tip($rotPath)[1];
}

// Pure seq rule, unit-testable without handles: sequenced tip → +1; legacy
// tip → the position after it; fresh file → continue the rotated
// generation, or start at 1 when there is nothing to continue.
function _log_compute_seq(string $tipHash, int $tipSeq, int $entryCount, int $rotSeq): int {
    if ($tipSeq > 0) {
        return $tipSeq + 1;
    }
    if ($tipHash !== '' && $tipHash !== APP_LOG_GENESIS) {
        return $entryCount + 1;
    }
    return $rotSeq > 0 ? $rotSeq + 1 : 1;
}

function _log_rotate_if_needed(string $path): void {
    clearstatcache(true, $path);
    if (is_file($path) && filesize($path) >= APP_LOG_MAX_BYTES) {
        $old = $path . '.1';
        if (is_file($old)) {
            overwrite_and_unlink($old);
        }
        @rename($path, $old);
    }
}

/** @param array<string,mixed> $ctx */
function app_log(string $level, string $event, array $ctx = []): bool {
    // No usable key, no chain: refuse BEFORE touching the file (an empty
    // app.log used to appear, and hex2bin() warnings flooded error.log on
    // every call). Say so once per process — it is a configuration fault.
    try {
        _log_key();
    } catch (Throwable $e) {
        static $keyWarned = false;
        if (!$keyWarned) {
            $keyWarned = true;
            error_log('Structured log disabled: ' . $e->getMessage());
        }
        return false;
    }
    $path = APP_LOG_PATH;
    $dir  = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }

    // Everything lock-free happens first: the critical section below is
    // rotate + tip + append only, held as briefly as possible.
    $user = null;
    if (isset($_SESSION['user_name']) && is_string($_SESSION['user_name'])) {
        $user = $_SESSION['user_name'];
    }

    $base = [
        'ts'    => gmdate('Y-m-d\TH:i:s.v\Z'),
        'level' => $level,
        'event' => $event,
        'msg'   => isset($ctx['msg']) ? $ctx['msg'] : '',
        // TCP peer on purpose, NOT get_client_ip(): the logger resolving the
        // client IP would call log_warn() on untrusted peers, which calls
        // back into app_log() — a call cycle held together only by a static
        // once-guard. The authoritative client IP belongs in audit_log /
        // order_events (written explicitly by the flows); this field says
        // who actually connected.
        'ip'    => ($_SERVER['REMOTE_ADDR'] ?? null),
        'user'  => $user,
        'req'   => PHP_SAPI === 'cli' ? 'cli' : _log_req_id(),
    ];
    unset($ctx['msg']);
    foreach ($ctx as $k => $v) {
        // array_key_exists, not isset: under CLI 'ip' is null and anonymous
        // requests carry 'user' null — isset(null) would let a context value
        // forge those fields. Base record always wins.
        if (!array_key_exists($k, $base)) {
            $base[$k] = $v;
        }
    }

    // ONE lock across rotate AND append (the sidecar): the old shape opened
    // and locked two files per write (sidecar for the rotation check, then
    // the log itself) and left a window where another process could rotate
    // between the check and the append. Lock order is fixed everywhere
    // (sidecar, then file — nothing ever takes them in reverse), so nesting
    // cannot deadlock.
    $lock = @fopen($path . '.lock', 'c');
    if ($lock === false) {
        return false;
    }
    flock($lock, LOCK_EX);
    try {
        // Serialize rotation AND writing: rotating outside the lock let two
        // processes at the 5 MiB boundary both rename (the second deleting
        // the first's .1 generation outright) or append post-rotation
        // entries to the renamed .1 file.
        _log_rotate_if_needed($path);
        $fh = @fopen($path, 'c+');
        if ($fh === false) {
            return false;
        }
        flock($fh, LOCK_EX);
        try {
            [$prev, $tipSeq] = _log_tail_tip($fh);
            if ($prev === '') {
                return false;
            }
            // A fresh generation links to the rotated one's tip (hash AND seq), so
            // the chain runs across files: deleting app.log.1, or renaming app.log
            // to fake a rotation and then editing it, breaks verification instead of
            // restarting a clean chain at GENESIS.
            $fresh = $prev === APP_LOG_GENESIS && $tipSeq === 0;
            $rot = $fresh ? _log_rot_tip($path . '.1') : [APP_LOG_GENESIS, 0];
            $rec = $base;
            $rec['prev'] = $fresh ? $rot[0] : $prev;
            // Seq inputs stay lazy (ternaries): the full count runs only for legacy
            // tips, the rotation peek only for a fresh file — the common sequenced
            // path pays just the tail scan above.
            $rec['seq'] = _log_compute_seq(
                $prev,
                $tipSeq,
                $tipSeq > 0 ? 0 : _log_count_entries($fh),
                $rot[1]
            );

            $payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($payload === false) {
                // Non-UTF8 context — drop the offending context rather than lose the entry
                foreach ($rec as $k => $v) {
                    if (!in_array($k, ['ts', 'level', 'event', 'msg', 'ip', 'user', 'req', 'prev', 'seq'], true)) {
                        unset($rec[$k]);
                    }
                }
                // Identical flags to the stored line AND the verifier (unescaped +
                // substitute): hashing the default-flags encoding here while the
                // line below is written unescaped made every non-ASCII base field
                // (Polish msgs, names) verify as "hash mismatch" — a false tamper
                // alarm on a perfectly honest entry.
                $payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
                if ($payload === false) {
                    return false;
                }
            }
            $rec['hash'] = hash_hmac('sha256', $payload, _log_key());

            $line = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($line === false) {
                // Unencodable even with substitution (e.g. INF/NAN floats in ctx) —
                // refuse loudly instead of appending a blank line the verifier
                // would silently skip, losing the entry without a trace.
                return false;
            }
            fwrite($fh, $line . "\n");
            fflush($fh);
            return true;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function log_err(string $message): void {
    app_log('error', 'php_error', ['msg' => $message]);
}

/** @param array<string,mixed> $ctx */
function log_warn(string $event, array $ctx = []): void {
    app_log('warn', $event, $ctx);
}

/** @param array<string,mixed> $ctx */
function log_info(string $event, array $ctx = []): void {
    app_log('info', $event, $ctx);
}

// glob() answers false — not [] — when the directory is missing or
// unreadable, and count(false) is a TypeError on PHP 8+. Every directory
// listing in the codebase goes through here so the next sweep/delete/probe
// cannot reintroduce that crash by reaching for glob() directly.
/** @return list<string> */
function glob_list(string $pattern, int $flags = 0): array {
    $hits = glob($pattern, $flags);
    return $hits === false ? [] : $hits;
}

// ── Viewer helpers (Settings → structured log) ──────────────────────────────
// One line of human-readable text for a structured entry: the event, its
// message, then every extra context field as key=value. The chain fields
// (prev/hash/seq), the timestamp and the level are shown in their own
// columns or not at all. Everything is untrusted text — the caller escapes.
/** @param array<string,mixed> $rec */
function log_entry_summary(array $rec): string {
    $skip = ['ts' => 1, 'level' => 1, 'event' => 1, 'msg' => 1, 'req' => 1, 'prev' => 1, 'seq' => 1, 'hash' => 1];
    $parts = [];
    foreach (['event', 'msg'] as $k) {
        if (isset($rec[$k]) && is_scalar($rec[$k]) && (string)$rec[$k] !== '') {
            $parts[] = (string)$rec[$k];
        }
    }
    foreach ($rec as $k => $v) {
        if (isset($skip[$k]) || $v === null || $v === '') {
            continue;
        }
        $val = is_scalar($v) ? (string)$v : (string)json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $parts[] = $k . '=' . mb_strimwidth($val, 0, 80, '…', 'UTF-8');
    }
    return mb_strimwidth(implode('  ', $parts), 0, 400, '…', 'UTF-8');
}

// The newest $limit entries of the structured log, newest first, for the
// Settings viewer — the same file the integrity check covers. Lines that are
// not valid JSON records are shown raw rather than hidden. Backward block
// scan: the file caps at 5 MiB but only the tail is ever shown, so the last
// $limit lines plus an exact total are collected without file()ing the
// whole thing (which kept ~10 MB decoded).
/** @return array{total:int,entries:list<array{seq:?int,ts:string,level:string,text:string}>} */
function log_recent_entries(int $limit = 200, ?string $path = null): array {
    $path = $path ?? APP_LOG_PATH;
    $limit = max(1, $limit);
    clearstatcache(true, $path);
    $size = @filesize($path);
    if ($size === false || $size === 0 || !is_file($path)) {
        return ['total' => 0, 'entries' => []];
    }
    $fh = @fopen($path, 'r');
    if ($fh === false) {
        return ['total' => 0, 'entries' => []];
    }
    $total = 0;
    $kept = []; // newest-first raw lines, at most $limit non-empty ones
    $carry = ''; // partial first line, completed by the earlier block
    $pos = $size;
    while ($pos > 0) {
        $n = (int)min(65536, $pos);
        $pos -= $n;
        fseek($fh, $pos);
        $block = (string)fread($fh, $n);
        $parts = explode("\n", $block . $carry);
        // Every part except [0] ends at a newline inside this window, so it
        // is a complete line; [0] continues into the earlier window (unless
        // this was the first block, i.e. the start of the file).
        for ($i = count($parts) - 1; $i >= 1; $i--) {
            if ($parts[$i] === '') {
                continue; // FILE_SKIP_EMPTY_LINES parity for the total
            }
            $total++;
            if (count($kept) < $limit) {
                $kept[] = $parts[$i];
            }
        }
        $carry = $parts[0];
        if ($pos === 0 && $carry !== '') {
            $total++;
            if (count($kept) < $limit) {
                $kept[] = $carry;
            }
        }
    }
    fclose($fh);
    $out = [];
    foreach ($kept as $line) {
        $rec = json_decode($line, true);
        if (!is_array($rec)) {
            $out[] = ['seq' => null, 'ts' => '', 'level' => 'raw', 'text' => mb_strimwidth($line, 0, 400, '…', 'UTF-8')];
            continue;
        }
        $ts = is_string($rec['ts'] ?? null) ? str_replace(['T', 'Z'], [' ', ''], substr($rec['ts'], 0, 19)) : '';
        $lvl = is_string($rec['level'] ?? null) && preg_match('/^[a-z]{3,10}$/', $rec['level']) === 1 ? $rec['level'] : 'info';
        $out[] = [
            'seq'   => isset($rec['seq']) && is_int($rec['seq']) ? $rec['seq'] : null,
            'ts'    => $ts,
            'level' => $lvl,
            'text'  => log_entry_summary($rec),
        ];
    }
    return ['total' => $total, 'entries' => $out];
}

// ── Plain error log (PHP's error_log target) ─────────────────────────────────
// Not chained and never rotated by PHP itself: a noisy host (one warning per
// connection) grows it without bound, and Settings used to file() the whole
// thing into memory. Viewers read only the tail; the hourly cleanup trims it.

/**
 * Last $maxLines lines within the last $maxBytes.
 * @return array{0:list<string>,1:bool} [lines oldest-first, cut]
 */
function log_tail_lines(string $path, int $maxBytes = 262144, int $maxLines = 500): array {
    clearstatcache(true, $path); // a stale cached size (PHP 8.2) would read an appended log as empty
    $size = @filesize($path);
    if ($size === false || $size === 0) {
        return [[], false];
    }
    $fh = @fopen($path, 'r');
    if ($fh === false) {
        return [[], false];
    }
    $start = max(0, $size - $maxBytes);
    fseek($fh, $start);
    $data = (string)stream_get_contents($fh);
    fclose($fh);
    $lines = preg_split('/\r?\n/', $data) ?: [];
    if ($start > 0) {
        array_shift($lines); // first line is cut mid-way
    }
    $lines = array_values(array_filter($lines, static fn(string $l): bool => trim($l) !== ''));
    $cut = $start > 0 || count($lines) > $maxLines;
    return [array_slice($lines, -$maxLines), $cut];
}

// Keep error.log bounded: past $max bytes only the newest $keep bytes stay
// (cut at a line boundary). Best-effort, never throws.
function error_log_trim(?string $path = null, int $max = 5242880, int $keep = 1048576): bool {
    $path ??= defined('ERROR_LOG_PATH') ? ERROR_LOG_PATH : '';
    if ($path === '' || !is_file($path) || is_link($path)) {
        return false;
    }
    clearstatcache(true, $path);
    $size = (int)@filesize($path);
    if ($size <= $max) {
        return false;
    }
    $fh = @fopen($path, 'r+');
    if ($fh === false) {
        return false;
    }
    try {
        flock($fh, LOCK_EX);
        fseek($fh, -$keep, SEEK_END);
        $tail = (string)stream_get_contents($fh);
        $nl = strpos($tail, "\n");
        $tail = $nl === false ? '' : substr($tail, $nl + 1);
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, $tail);
        fflush($fh);
        flock($fh, LOCK_UN);
    } finally {
        fclose($fh);
    }
    return true;
}

// ── Chain verification ────────────────────────────────────────────────────────
// Returns [valid(bool), checked(int), broken_line(int|null), reason(string|null)]
// broken_line is the 1-based file line of the first bad entry.
/** @return array{0:bool,1:int,2:?int,3:?string} */
function verify_log_chain(?string $path = null): array {
    $path = $path ?? APP_LOG_PATH;
    $rot = $path . '.1';
    if (!is_file($path) && !is_file($rot)) {
        return [true, 0, null, null];
    }
    try {
        _log_key();
    } catch (Throwable) {
        return [false, 0, null, 'log key unavailable (AES_KEY_HEX invalid)'];
    }
    // The rotated generation is verified too: its first entry anchors to a
    // generation that no longer exists (accepted as-is), everything after
    // must chain. The live file must then continue from its tip.
    $checked = 0;
    $prev = null;
    if (is_file($rot)) {
        [$ok, $n, $broken, $reason, $tip] = _verify_log_file($rot, null);
        if (!$ok) {
            return [false, $n, $broken, basename($rot) . ': ' . $reason];
        }
        $checked = $n;
        $prev = $tip;
    }
    if (!is_file($path)) {
        return [true, $checked, null, null];
    }
    [$ok, $n, $broken, $reason] = _verify_log_file($path, $prev ?? APP_LOG_GENESIS, $prev !== null);
    if (!$ok) {
        return [false, $checked + $n, $broken, $reason];
    }
    return [true, $checked + $n, null, null];
}

// One file of the chain. $prev: the hash the first entry must link to, or
// null to accept whatever it names (the oldest surviving generation).
// $legacyGenesis: a live file written before cross-file linking starts at
// GENESIS even though a rotated generation exists — still accepted.
// Returns [valid, checked, broken_line, reason, tip_hash].
/** @return array{0:bool,1:int,2:?int,3:?string,4:?string} */
function _verify_log_file(string $path, ?string $prev, bool $legacyGenesis = false): array {
    $fh = @fopen($path, 'r');
    if ($fh === false) {
        return [false, 0, null, 'unreadable', null];
    }
    // Shared lock: a concurrent rotation must not move the file mid-read.
    flock($fh, LOCK_SH);
    $n = 0;
    try {
        while (($line = fgets($fh)) !== false) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $n++;
            $rec = json_decode($line, true);
            // A non-string 'hash' (planted/corrupt line) must fail verification,
            // not TypeError inside hash_equals() and 500 the integrity page.
            if (!is_array($rec) || !isset($rec['hash'], $rec['prev']) || !is_string($rec['hash']) || !is_string($rec['prev'])) {
                return [false, $n, $n, 'malformed entry', null];
            }
            if ($n === 1 && $prev === null) {
                $prev = $rec['prev'];
            } elseif ($n === 1 && $legacyGenesis && hash_equals(APP_LOG_GENESIS, $rec['prev'])) {
                $prev = APP_LOG_GENESIS;
            }
            if (!hash_equals((string)$prev, $rec['prev'])) {
                return [false, $n, $n, $n === 1 && $prev === APP_LOG_GENESIS
                    ? 'previous log generation missing (app.log.1 deleted?)'
                    : 'broken chain linkage', null];
            }
            $expected = $rec['hash'];
            unset($rec['hash']);
            $payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            // Entries may predate key separation (legacy raw-key HMAC) — accept
            // either subkey so history stays verifiable across the transition.
            $calc = hash_hmac('sha256', (string)$payload, _log_key());
            if (!hash_equals($expected, $calc)) {
                $calc = hash_hmac('sha256', (string)$payload, _log_key_legacy());
            }
            if (!hash_equals($expected, $calc)) {
                return [false, $n, $n, 'hash mismatch (entry modified or forged)', null];
            }
            $prev = $expected;
        }
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
    return [true, $n, null, null, $prev];
}

// ── Truncation checkpoints ────────────────────────────────────────────────────
// A hash chain detects modification, not pure tail deletion: lopping entries
// off the end leaves a shorter chain that still verifies. The hourly cleanup
// pass therefore anchors the current tip (hash + seq) in the database — a
// separate trust domain from the log files (db-data vs app-logs volume) —
// and verify_log_continuity() compares the live log against the newest
// anchor. An anchor must predate the attack to catch it: deletions inside
// the checkpoint interval (about an hour) are the documented residual blind
// spot, same as with any polling anchor.

function log_checkpoint_write(): void {
    try {
        $tip = _log_checkpoint_tip(APP_LOG_PATH);
        if ($tip === null) {
            return; // nothing anchorable (missing/empty/broken log)
        }
        [$hash, $seq] = $tip;
        $db = get_db();
        $db->prepare('INSERT INTO log_checkpoints (tip_hash, tip_seq) VALUES (?, ?)')
           ->execute([$hash, $seq]);
        $db->exec('DELETE FROM log_checkpoints WHERE created_at < NOW() - INTERVAL 30 DAY');
    } catch (Throwable $e) {
        // Best-effort: a missing table (pre-migration install) or a down DB
        // must never break cleanup — continuity then reports 'none'.
    }
}

// Readable tip for anchoring: [hash, seq], or null when there is nothing
// worth anchoring (missing/empty file, unreadable handle, broken tail,
// genesis-only file). Factored out so every no-anchor branch is directly
// testable on scratch paths.
/** @return ?array{0:string,1:int} */
function _log_checkpoint_tip(string $path): ?array {
    if (!is_file($path) || filesize($path) === 0) {
        return null;
    }
    $fh = @fopen($path, 'r');
    if ($fh === false) {
        return null;
    }
    flock($fh, LOCK_SH);
    try {
        [$hash, $seq] = _log_tail_tip($fh);
    } finally {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
    if ($hash === '' || $hash === APP_LOG_GENESIS) {
        return null;
    }
    return [$hash, $seq];
}

// Compare the live log (current generation plus the rotated one) against
// the newest checkpoint. Chain validity stays verify_log_chain()'s job;
// this answers only "is anything missing since the anchor":
//   extends   — tip continues past the anchor (healthy)
//   truncated — surviving history ends before the anchor (tail deleted, or
//               the file swapped for an older copy)
//   rotated   — anchor aged out by legitimate rotation (oldest surviving
//               entry is newer than the anchor)
//   none      — no anchor yet (fresh install / table missing)
//   error     — checkpoint store unreadable for another reason
/** @return array{status:string,detail:string,checkpoint_seq?:int,checkpoint_at?:string,entries?:int,tip_seq?:?int} */
function verify_log_continuity(?string $path = null): array {
    $path = $path ?? APP_LOG_PATH;
    try {
        $db = get_db();
        $cp = $db->query(
            'SELECT tip_hash, tip_seq, created_at FROM log_checkpoints ORDER BY id DESC LIMIT 1'
        )->fetch();
    } catch (Throwable $e) {
        $missing = $e instanceof PDOException && (string)$e->getCode() === '42S02';
        $msg = strtolower($e->getMessage());
        if ($missing || str_contains($msg, "doesn't exist") || str_contains($msg, 'no such table')) {
            return ['status' => 'none', 'detail' => 'no checkpoint table yet'];
        }
        return ['status' => 'error', 'detail' => 'checkpoint store unavailable'];
    }
    if (!$cp) {
        return ['status' => 'none', 'detail' => 'no checkpoint written yet'];
    }
    // Single streaming pass over both generations: only min/max seq, the
    // entry count and the anchor match are retained — the old version kept
    // every [seq, hash] pair of both files in memory and effectively read
    // the same bytes a second time after verify_log_chain().
    $cHash = trim((string)$cp['tip_hash']);
    $cSeq = (int)$cp['tip_seq'];
    $found = false;
    $rewritten = false;
    $count = 0;
    $minSeq = null;
    $maxSeq = null;
    foreach ([$path . '.1', $path] as $f) {
        if (!is_file($f)) {
            continue;
        }
        $fh = @fopen($f, 'r');
        if ($fh === false) {
            continue;
        }
        while (($line = fgets($fh)) !== false) {
            $rec = json_decode(trim($line), true);
            if (!is_array($rec) || !isset($rec['hash']) || !is_string($rec['hash'])) {
                continue;
            }
            $s = isset($rec['seq']) ? (int)$rec['seq'] : null;
            if ($s !== null) {
                $minSeq = $minSeq === null ? $s : min($minSeq, $s);
                $maxSeq = $maxSeq === null ? $s : max($maxSeq, $s);
            }
            if (!$found && hash_equals($cHash, $rec['hash'])) {
                $found = true;
            } elseif ($found && $s !== null && $s < $cSeq) {
                // File order is append order, so a lower seq past the anchor
                // means the history was rewritten, not extended.
                $rewritten = true;
            }
            $count++;
        }
        fclose($fh);
    }
    $base = [
        'checkpoint_seq' => $cSeq,
        'checkpoint_at'  => (string)($cp['created_at'] ?? ''),
        'entries'        => $count,
    ];
    $base['tip_seq'] = $maxSeq;
    if ($found) {
        if ($rewritten) {
            return ['status' => 'truncated', 'detail' => 'history rewritten after the anchor'] + $base;
        }
        if ($maxSeq !== null && $maxSeq < $cSeq) {
            return ['status' => 'truncated', 'detail' => 'tip predates the anchor'] + $base;
        }
        return ['status' => 'extends', 'detail' => 'tip continues past the anchor'] + $base;
    }
    if ($minSeq !== null && $minSeq > $cSeq) {
        return ['status' => 'rotated', 'detail' => 'anchor aged out by rotation'] + $base;
    }
    return ['status' => 'truncated', 'detail' => 'history ends before the anchor'] + $base;
}
