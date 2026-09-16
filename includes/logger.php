<?php
declare(strict_types=1);

// ── Structured application log with tamper-evident chain ──────────────────────
// Every entry is one JSON line in logs/app.log:
//   {ts, level, event, msg, ip, user, req, ...ctx, prev, hash}
// "prev" holds the previous entry's hash; "hash" is HMAC-SHA256 over the whole
// record (key derived from AES_KEY_HEX with domain separation). Editing or
// deleting any historical line breaks every subsequent hash, so tampering is
// detectable via verify_log_chain(). Rotation keeps one generation (app.log.1)
// and starts a fresh genesis chain.

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
function _log_key(): string {
    return hash_hkdf('sha256', hex2bin(AES_KEY_HEX), 32, 'deaddrop:log-hmac-v1', 'deaddrop-mgmt-hkdf-salt-v1');
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

// Read the trailing hash of the last complete JSON line. Caller holds LOCK_EX.
// Scans backwards in growing windows: a single entry larger than one window
// must not anchor the next write to the second-to-last hash (which would
// permanently alarm the chain on the following verify). Garbage lines inside
// the view are still skipped (tolerance is test-pinned); only a possibly
// window-truncated TAIL line triggers a wider re-read.
function _log_last_hash($fh): string {
    fseek($fh, 0, SEEK_END);
    $size = ftell($fh);
    if ($size === 0) {
        return APP_LOG_GENESIS;
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
                return $rec['hash'];
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
    return '';
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

function app_log(string $level, string $event, array $ctx = []): bool {
    $path = APP_LOG_PATH;
    $dir  = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }

    // Serialize rotation AND writing on a sidecar lock: rotating outside the
    // lock let two processes at the 5 MiB boundary both rename (the second
    // deleting the first's .1 generation outright) or append post-rotation
    // entries to the renamed .1 file.
    $lock = @fopen($path . '.lock', 'c');
    if ($lock === false) {
        return false;
    }
    flock($lock, LOCK_EX);
    try {
        _log_rotate_if_needed($path);
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }

    $user = null;
    if (isset($_SESSION['user_name']) && is_string($_SESSION['user_name'])) {
        $user = $_SESSION['user_name'];
    }

    $rec = [
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
        if (!array_key_exists($k, $rec)) {
            $rec[$k] = $v;
        }
    }

    $fh = @fopen($path, 'c+');
    if ($fh === false) {
        return false;
    }
    flock($fh, LOCK_EX);
    $prev = _log_last_hash($fh);
    if ($prev === '') {
        flock($fh, LOCK_UN);
        fclose($fh);
        return false;
    }
    $rec['prev'] = $prev;

    $payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($payload === false) {
        // Non-UTF8 context — drop the offending context rather than lose the entry
        foreach ($rec as $k => $v) {
            if (!in_array($k, ['ts', 'level', 'event', 'msg', 'ip', 'user', 'req', 'prev'], true)) {
                unset($rec[$k]);
            }
        }
        $payload = json_encode($rec, JSON_INVALID_UTF8_SUBSTITUTE);
        if ($payload === false) {
            flock($fh, LOCK_UN);
            fclose($fh);
            return false;
        }
    }
    $rec['hash'] = hash_hmac('sha256', $payload, _log_key());

    $line = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    fwrite($fh, $line . "\n");
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return true;
}

function log_err(string $message): void {
    app_log('error', 'php_error', ['msg' => $message]);
}

function log_warn(string $event, array $ctx = []): void {
    app_log('warn', $event, $ctx);
}

function log_info(string $event, array $ctx = []): void {
    app_log('info', $event, $ctx);
}

// glob() answers false — not [] — when the directory is missing or
// unreadable, and count(false) is a TypeError on PHP 8+. Every directory
// listing in the codebase goes through here so the next sweep/delete/probe
// cannot reintroduce that crash by reaching for glob() directly.
function glob_list(string $pattern, int $flags = 0): array {
    $hits = glob($pattern, $flags);
    return $hits === false ? [] : $hits;
}

// ── Chain verification ────────────────────────────────────────────────────────
// Returns [valid(bool), checked(int), broken_line(int|null), reason(string|null)]
// broken_line is the 1-based file line of the first bad entry.

function verify_log_chain(?string $path = null): array {
    $path = $path ?? APP_LOG_PATH;
    if (!is_file($path)) {
        return [true, 0, null, null];
    }
    $fh = fopen($path, 'r');
    if ($fh === false) {
        return [false, 0, null, 'unreadable'];
    }
    // Shared lock: a concurrent rotation must not move the file mid-read.
    flock($fh, LOCK_SH);
    $prev      = APP_LOG_GENESIS;
    $n         = 0;
    while (($line = fgets($fh)) !== false) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $n++;
        $rec = json_decode($line, true);
        // A non-string 'hash' (planted/corrupt line) must fail verification,
        // not TypeError inside hash_equals() and 500 the integrity page.
        if (!is_array($rec) || !isset($rec['hash'], $rec['prev']) || !is_string($rec['hash'])) {
            flock($fh, LOCK_UN);
            fclose($fh);
            return [false, $n, $n, 'malformed entry'];
        }
        if (!hash_equals($prev, (string)$rec['prev'])) {
            flock($fh, LOCK_UN);
            fclose($fh);
            return [false, $n, $n, 'broken chain linkage'];
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
            flock($fh, LOCK_UN);
            fclose($fh);
            return [false, $n, $n, 'hash mismatch (entry modified or forged)'];
        }
        $prev = $expected;
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return [true, $n, null, null];
}
