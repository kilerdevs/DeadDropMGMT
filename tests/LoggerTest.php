<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Tamper-evident log chain + audit + event log ─────────────────────────────
// Chain-integrity cases run against PRIVATE chain files built with the exact
// record format app_log() uses — the shared live log is written by several
// processes (CLI suites AND spawned test servers), so verifying it here would
// be a race, not a test.

$db = get_db();

/** Build one chain record exactly like app_log() does: prev first, then
 *  HMAC over the JSON of everything-but-hash. */
function mk_chain_rec(string $prev, array $rec): array {
    $rec['prev'] = $prev;
    unset($rec['hash']);
    $payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $rec['hash'] = hash_hmac('sha256', (string)$payload, _log_key());
    return $rec;
}

function write_chain(string $path, array $records): void {
    $out = '';
    foreach ($records as $r) { $out .= json_encode($r, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n"; }
    file_put_contents($path, $out);
}

$tmpDir = sys_get_temp_dir() . '/ddmgmt_chain_' . getmypid();
if (!is_dir($tmpDir)) { mkdir($tmpDir, 0700, true); }
$genesis = APP_LOG_GENESIS;

$r1 = mk_chain_rec($genesis,      ['ts' => '2026-08-26T00:00:01.000Z', 'level' => 'error', 'event' => 'php_error', 'msg' => 'entry one']);
$r2 = mk_chain_rec($r1['hash'],   ['ts' => '2026-08-26T00:00:02.000Z', 'level' => 'warn',  'event' => 't_warn',     'msg' => 'entry two']);
$r3 = mk_chain_rec($r2['hash'],   ['ts' => '2026-08-26T00:00:03.000Z', 'level' => 'info',  'event' => 't_info',     'msg' => 'entry three']);

// Missing file: vacuously valid, nothing checked
T::eq('missing log is vacuously valid',
      [true, 0, null, null], verify_log_chain(sys_get_temp_dir() . '/ddmgmt_no_such_log.log'));

// A well-formed three-entry chain verifies completely
$p = $tmpDir . '/good.log';
write_chain($p, [$r1, $r2, $r3]);
T::eq('well-formed chain verifies', [true, 3, null, null], verify_log_chain($p));

// Empty file: zero entries, still valid (genesis)
file_put_contents($p, '');
T::eq('empty log verifies trivially', [true, 0, null, null], verify_log_chain($p));

// Malformed line breaks the chain at that line
write_chain($p, [$r1, $r2, $r3]);
file_put_contents($p, "not json at all\n", FILE_APPEND);
[$valid, , $broken, $reason] = verify_log_chain($p);
T::ok('malformed entry detected', $valid === false && str_contains((string)$reason, 'malformed'));

// Removing a middle entry breaks linkage
write_chain($p, [$r1, $r2, $r3]);
$lines = file($p);
unset($lines[1]);
file_put_contents($p, implode('', $lines));

// A non-string 'hash' field (planted/corrupt line) fails verification —
// never TypeErrors inside hash_equals() and 500s the integrity page.
// (Separate scratch file: $p below must still hold the middle-removed chain.)
$badHash = $r1; $badHash['hash'] = 12345;
$badPath = $tmpDir . '/badhash.log';
write_chain($badPath, [$badHash]);
[$valid] = verify_log_chain($badPath);
T::ok('non-string hash fails closed, no TypeError', $valid === false);

// A single entry larger than the tail window: the writer must anchor on ITS
// hash, not the second-to-last one (which permanently alarms the chain).
$bigRec = mk_chain_rec($genesis, ['ts' => '2026-08-26T00:00:04.000Z', 'level' => 'info', 'event' => 't_big', 'msg' => str_repeat('y', 9000)]);
$big = $tmpDir . '/big.log';
write_chain($big, [$bigRec]);
$fhBig = fopen($big, 'c+');
T::eq('tail scan anchors past an 8 KiB entry', $bigRec['hash'], _log_last_hash($fhBig));
fclose($fhBig);
T::eq('chain with oversized entry verifies', [true, 1, null, null], verify_log_chain($big));
[$valid, , , $reason] = verify_log_chain($p);
T::ok('removed entry breaks chain linkage', $valid === false && $reason === 'broken chain linkage');

// Editing an entry in place fails the HMAC (well-formed record, wrong digest)
write_chain($p, [$r1, $r2, $r3]);
$lines = file($p);
$rec = json_decode($lines[2], true);
$rec['msg'] = 'forged message';
$rec['hash'] = str_repeat('0', 64);
$lines[2] = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
file_put_contents($p, implode('', $lines));
[$valid, , , $reason] = verify_log_chain($p);
T::ok('forged entry detected by hash mismatch', $valid === false && str_contains((string)$reason, 'hash mismatch'));

// Blank lines are skipped, not treated as corruption — in both directions:
// verification walks past them, and the tail scan anchors past a blank line
// sitting between an entry and trailing garbage.
write_chain($p, [$r1, $r2, $r3]);
file_put_contents($p, "\n", FILE_APPEND);
T::eq('blank line inside chain verifies', [true, 3, null, null], verify_log_chain($p));
file_put_contents($p, "\nbroken-tail\n", FILE_APPEND);
$fh = fopen($p, 'c+');
T::eq('tail scan skips blank and garbage to last hash', $r3['hash'], _log_last_hash($fh));
fclose($fh);

// Request id is stable within the process (and 8 hex chars)
T::eq('request id stable per process', _log_req_id(), _log_req_id());
T::ok('request id is 8 hex chars', (bool)preg_match('/^[0-9a-f]{8}$/', _log_req_id()));

// log_info writes through like its siblings (void return — verify the entry)
log_info('logger_test_info_evt', ['msg' => 'info smoke']);
$liveLines = file(APP_LOG_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
T::ok('log_info entry lands in the live log',
      str_contains((string)end($liveLines), 'logger_test_info_evt'));

// The log's ip field is the TCP peer, never a proxy header: resolving the
// client IP here would re-enter get_client_ip() -> log_warn() -> app_log().
$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.5';
putenv('DDMGMT_TRUST_PROXY=1');
app_log('info', 'logger_test_peer_ip', ['msg' => 'peer, not header']);
putenv('DDMGMT_TRUST_PROXY');
unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['REMOTE_ADDR']);
$liveLines = file(APP_LOG_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
$lastRec = json_decode((string)end($liveLines), true);
T::eq('log ip is the TCP peer even behind a trusted proxy',
      '198.51.100.99', is_array($lastRec) ? ($lastRec['ip'] ?? null) : null);

// Legacy-key entries (pre key-separation history) still verify
write_chain($p, [$r1, $r2]);
$rec = ['ts' => '2026-08-26T00:00:03.000Z', 'level' => 'info', 'event' => 't_info', 'msg' => 'entry three'];
$rec['prev'] = $r2['hash'];
$payload = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
$rec['hash'] = hash_hmac('sha256', $payload, _log_key_legacy());
write_chain($p, [$r1, $r2, $rec]);
[$valid] = verify_log_chain($p);
T::ok('legacy-HMAC entry still verifies', $valid === true);

@unlink($p);

// Rotation: oversized log moves to .1, destroying any previous generation
$rot = $tmpDir . '/rot.log';
file_put_contents($rot, str_repeat('x', (int)APP_LOG_MAX_BYTES + 1));
file_put_contents($rot . '.1', 'previous generation');
_log_rotate_if_needed($rot);
T::ok('oversized log rotated away', !is_file($rot));
T::ok('old generation replaced', is_file($rot . '.1') && filesize($rot . '.1') > APP_LOG_MAX_BYTES - 10);
@unlink($rot . '.1');
// Under size → untouched
file_put_contents($rot, 'tiny');
_log_rotate_if_needed($rot);
T::ok('small log not rotated', is_file($rot) && !is_file($rot . '.1'));
@unlink($rot);
@rmdir($tmpDir);

// Live writer END-TO-END: three real appends must form a verifiable chain.
// This exact sequence caught the ftell-at-zero bug where every entry anchored
// to GENESIS and each write overwrote the file from byte zero.
$live = APP_LOG_PATH;
file_put_contents($live, '');
T::ok('app_log writes through the chain writer',
      app_log('info', 'logger_test_e1', ['msg' => 'one']) === true);
$_SESSION['user_name'] = 't_log_user';
T::ok('app_log succeeds with a session identity',
      app_log('warn', 'logger_test_e2', ['msg' => 'two']) === true);
unset($_SESSION['user_name']);
T::ok('app_log succeeds anonymous again',
      app_log('error', 'logger_test_e3', ['msg' => 'three']) === true);
T::eq('three live appends form a verifiable chain',
      [true, 3, null, null], verify_log_chain($live));

// Non-UTF8 context payloads must not lose the entry: the offending context
// key is dropped and the record is re-encoded with substitution
T::ok('app_log survives non-UTF8 context',
      app_log('info', 'logger_test_binary', ['junk' => "\xB1\x31", 'msg' => 'binary ctx']) === true);

// Garbage at the tail is TOLERATED: the writer anchors on the last parseable
// entry, so one broken line must not orphan the rest of the log
$live = APP_LOG_PATH;
$keep = file_get_contents($live);
file_put_contents($live, $keep . "garbage-not-json\n");
T::ok('writer anchors past a corrupt tail line',
      app_log('info', 'logger_test_tolerant', ['msg' => 'after garbage']) === true);

// With NO parseable anchor anywhere there is nothing to chain onto — refuse
file_put_contents($live, "total-garbage\n");
T::ok('writer refuses without any chain anchor',
      app_log('info', 'logger_test_refused', ['msg' => 'never written']) === false);
file_put_contents($live, $keep); // restore for later suites
T::ok('writer recovers after repair',
      app_log('info', 'logger_test_recovered', ['msg' => 'again']) === true);

// ── Audit trail ───────────────────────────────────────────────────────────────
$_SESSION = [];
start_secure_session();
$_SESSION['user_id'] = 4242;
$_SESSION['user_role'] = 'owner';
$_SESSION['user_name'] = 't_audit_user';

$db->exec("DELETE FROM audit_log WHERE username = 't_audit_user'");
audit('t_audit_action', 7, 'AUDITTOKEN000001', str_repeat('d', 300));
$row = $db->query("SELECT * FROM audit_log WHERE username = 't_audit_user' AND action = 't_audit_action'")->fetch();
T::ok('audit row written with actor identity', $row !== false && (int)$row['user_id'] === 4242);
T::ok('audit detail truncated to 255', strlen((string)($row['detail'] ?? '')) <= 255);

with_table_hidden_lg('audit_log', function (): void {
    audit('t_audit_fail'); // must degrade to a log entry, never throw
});
T::ok('failed audit leaves no phantom row',
      $db->query("SELECT 1 FROM audit_log WHERE action = 't_audit_fail'")->fetch() === false);

// ── Event log ────────────────────────────────────────────────────────────────
set_setting('analytics_enabled', '0');
log_event('t_disabled_event'); // early return, no insert, no error
T::ok('disabled analytics writes nothing',
      $db->query("SELECT 1 FROM order_events WHERE event_type = 't_disabled_event'")->fetch() === false);

set_setting('analytics_enabled', '1');
$_SERVER['HTTP_USER_AGENT'] = 'LoggerTest/1.0';
log_event('t_enabled_event', null, 'EVTTOKEN00000001');
$ev = $db->query("SELECT * FROM order_events WHERE event_type = 't_enabled_event' ORDER BY id DESC LIMIT 1")->fetch();
T::ok('event row carries token and UA', $ev !== false && $ev['order_token'] === 'EVTTOKEN00000001');
T::ok('event UA recorded', ($ev['user_agent'] ?? '') === 'LoggerTest/1.0');

with_table_hidden_lg('order_events', function (): void {
    log_event('t_event_fail');
});
T::ok('failed event leaves no phantom row',
      $db->query("SELECT 1 FROM order_events WHERE event_type = 't_event_fail'")->fetch() === false);

exit(T::done());

// Local helper (suites are separate files; a shared helper file would be
// nicer once a third suite needs table-hiding).
function with_table_hidden_lg(string $table, callable $fn): mixed {
    $bak = $table . '_lg_bak';
    $dbX = get_db();
    $dbX->exec("RENAME TABLE {$table} TO {$bak}");
    try {
        return $fn();
    } finally {
        $dbX->exec("RENAME TABLE {$bak} TO {$table}");
    }
}
