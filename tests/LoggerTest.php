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

// Non-ASCII base fields must VERIFY after the substitution fallback: the
// hash used to be computed over default-flags encoding while the stored
// line was unescaped, so a Polish msg false-alarmed as "hash mismatch".
T::ok('app_log survives non-UTF8 context with non-ASCII msg',
      app_log('info', 'logger_test_binary_pl', ['junk' => "\xB1\x31", 'msg' => 'Zażółć gęślą jaźń']) === true);
T::eq('fallback entry with non-ASCII msg verifies clean',
      [true, 5, null, null], verify_log_chain($live));

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

// ── Sequence numbers ────────────────────────────────────────────────────────
T::eq('sequenced tip increments', 8, _log_compute_seq('abc', 7, 0, 0));
T::eq('legacy tip takes position after count', 6, _log_compute_seq('abc', 0, 5, 0));
T::eq('fresh file continues rotation', 11, _log_compute_seq(APP_LOG_GENESIS, 0, 0, 10));
T::eq('fresh file without rotation starts at 1', 1, _log_compute_seq(APP_LOG_GENESIS, 0, 0, 0));

$seqDir = $tmpDir . '/seq';
mkdir($seqDir, 0700, true);
$leg = $seqDir . '/legacy.log';
write_chain($leg, [$r1, $r2]); // r1/r2 predate seqs
$fhL = fopen($leg, 'c+');
[$lh, $ls] = _log_tail_tip($fhL);
fclose($fhL);
T::eq('legacy tip hash read', $r2['hash'], $lh);
T::eq('legacy tip seq zero', 0, $ls);
$fhC = fopen($leg, 'r');
T::eq('legacy entries counted', 2, _log_count_entries($fhC));
fclose($fhC);

$sA = mk_chain_rec($genesis, ['ts' => '2026-08-26T00:00:05.000Z', 'level' => 'info', 'event' => 't_seq', 'msg' => 's', 'seq' => 41]);
$seqP = $seqDir . '/seq.log';
write_chain($seqP, [$sA]);
$fhS = fopen($seqP, 'c+');
T::eq('sequenced tip read', [$sA['hash'], 41], _log_tail_tip($fhS));
fclose($fhS);
$emptyP = $seqDir . '/empty.log';
file_put_contents($emptyP, '');
$fhE = fopen($emptyP, 'c+');
T::eq('empty tip is genesis', [APP_LOG_GENESIS, 0], _log_tail_tip($fhE));
fclose($fhE);
file_put_contents($emptyP, "zzz\n");
$fhG = fopen($emptyP, 'c+');
T::eq('garbage-only tip empty', ['', 0], _log_tail_tip($fhG));
fclose($fhG);
$rotP = $seqDir . '/app.log.1';
write_chain($rotP, [$sA]);
T::eq('rotation tip continued', 41, _log_rot_tip_seq($rotP));
T::eq('missing rotation reads zero', 0, _log_rot_tip_seq($seqDir . '/nope.1'));

// ── Truncation continuity ───────────────────────────────────────────────────
// Pure tail deletion leaves a shorter chain that still verifies — the
// checkpoint comparison must catch what verify_log_chain() cannot.
$db->exec('DELETE FROM log_checkpoints');
$mkS = static function (string $prev, int $seq, string $msg): array {
    return mk_chain_rec($prev, ['ts' => '2026-08-26T00:00:0' . $seq . '.000Z', 'level' => 'info',
        'event' => 't_cont', 'msg' => $msg, 'seq' => $seq]);
};
$c1 = $mkS($genesis, 1, 'one');
$c2 = $mkS($c1['hash'], 2, 'two');
$c3 = $mkS($c2['hash'], 3, 'three');
$c4 = $mkS($c3['hash'], 4, 'four');
$c5 = $mkS($c4['hash'], 5, 'five');
$cp = $tmpDir . '/cont.log';
write_chain($cp, [$c1, $c2, $c3, $c4]);
T::eq('no anchor yet', 'none', verify_log_continuity($cp)['status']);
$db->prepare('INSERT INTO log_checkpoints (tip_hash, tip_seq) VALUES (?, ?)')->execute([$c4['hash'], 4]);
T::eq('tip at anchor extends', 'extends', verify_log_continuity($cp)['status']);
write_chain($cp, [$c1, $c2, $c3, $c4, $c5]);
T::eq('tip past anchor extends', 'extends', verify_log_continuity($cp)['status']);
// Lop the last two lines: shorter chain, still internally valid.
$lines = file($cp);
file_put_contents($cp, implode('', array_slice($lines, 0, 2)));
[$vAfterCut] = verify_log_chain($cp);
$r = verify_log_continuity($cp);
T::ok('cut chain still verifies (the gap being closed)', $vAfterCut === true);
T::eq('deleted tail reports truncated', 'truncated', $r['status']);
// Anchor older than all surviving history: legitimate rotation, not an attack.
$old = $tmpDir . '/old.log';
$o1 = $mkS($genesis, 10, 'ten');
$o2 = $mkS($o1['hash'], 11, 'eleven');
write_chain($old, [$o1, $o2]);
$db->exec('DELETE FROM log_checkpoints');
$db->prepare('INSERT INTO log_checkpoints (tip_hash, tip_seq) VALUES (?, ?)')->execute([$c4['hash'], 4]);
T::eq('aged-out anchor reports rotated', 'rotated', verify_log_continuity($old)['status']);
// Checkpoint write-through anchors the live tip (best-effort, never throws).
// Table cleared first: the assertion must see THIS write's row, not a
// leftover anchor (a stale row would also let a neutered writer pass).
$db->exec('DELETE FROM log_checkpoints');
log_info('logger_test_checkpoint_probe', ['msg' => 'anchor me']);
log_checkpoint_write();
$row = $db->query('SELECT tip_hash, tip_seq FROM log_checkpoints ORDER BY id DESC LIMIT 1')->fetch();
T::ok('checkpoint anchors the live tip',
    $row !== false && preg_match('/^[0-9a-f]{64}$/', (string)$row['tip_hash']) === 1 && (int)$row['tip_seq'] >= 1);

// Failure containment: hidden table degrades to silence ('none' later),
// never to an exception out of cleanup or verification.
$db->exec('RENAME TABLE log_checkpoints TO log_checkpoints_lg_bak');
try {
    log_checkpoint_write();
    T::ok('checkpoint write survives missing table', true);
    T::eq('continuity without store reports none',
        'none', verify_log_continuity($cp)['status']);
    // A broken VIEW throws a non-missing-table error (HY000): that surfaces
    // as 'error', distinct from the pre-migration 'none'. The view must be
    // created valid and broken afterwards — MariaDB rejects invalid views
    // at CREATE time.
    $db->exec('CREATE VIEW log_checkpoints AS SELECT * FROM log_checkpoints_lg_bak');
    $db->exec('RENAME TABLE log_checkpoints_lg_bak TO log_checkpoints_lg_bak2');
    T::eq('continuity reports store errors distinctly',
        'error', verify_log_continuity($cp)['status']);
} finally {
    try {
        $db->exec('DROP VIEW IF EXISTS log_checkpoints');
    } catch (Throwable) {
    }
    foreach (['log_checkpoints_lg_bak2', 'log_checkpoints_lg_bak'] as $bak) {
        try {
            $db->exec("RENAME TABLE `$bak` TO log_checkpoints");
        } catch (Throwable) {
        }
    }
}
T::ok('checkpoints table restored after failure probe',
    $db->query("SHOW TABLES LIKE 'log_checkpoints'")->fetch() !== false);

// Rewound history: the anchor is present but the tip predates it (an older
// copy swapped in). A correctly chained later entry with a lower seq proves
// the file does not extend past the anchor.
$s6rew = mk_chain_rec($c4['hash'], ['ts' => '2026-08-26T00:00:06.000Z', 'level' => 'info',
    'event' => 't_cont', 'msg' => 'rewound', 'seq' => 2]);
write_chain($cp, [$c1, $c2, $c3, $c4, $s6rew]);
$db->prepare('INSERT INTO log_checkpoints (tip_hash, tip_seq) VALUES (?, ?)')->execute([$c4['hash'], 4]);
T::eq('rewound tip reports truncated', 'truncated', verify_log_continuity($cp)['status']);
$db->exec('DELETE FROM log_checkpoints');

// Anchor-tip reader, every no-anchor branch on scratch paths.
T::ok('tip reader rejects missing file', _log_checkpoint_tip($tmpDir . '/no-such.log') === null);
$tipEmpty = $tmpDir . '/tip-empty.log';
file_put_contents($tipEmpty, '');
T::ok('tip reader rejects empty file', _log_checkpoint_tip($tipEmpty) === null);
$tipGarbage = $tmpDir . '/tip-garbage.log';
file_put_contents($tipGarbage, "not json\n");
T::ok('tip reader rejects broken tail', _log_checkpoint_tip($tipGarbage) === null);
$tipGood = $tmpDir . '/tip-good.log';
$g1 = mk_chain_rec($genesis, ['ts' => '2026-08-26T00:00:07.000Z', 'level' => 'info',
    'event' => 't_tip', 'msg' => 'g', 'seq' => 9]);
write_chain($tipGood, [$g1]);
T::eq('tip reader returns hash and seq', [$g1['hash'], 9], _log_checkpoint_tip($tipGood));
$db->exec('DELETE FROM log_checkpoints');

// ── Rotation racing an in-progress append ───────────────────────────────────
// Deterministic replay of the interleaving: A reads the tip under lock, B
// rotates underneath, A completes into the renamed inode, B starts fresh.
// Both generations must verify — the late entry lands in the old file with
// intact linkage (misplaced, never corrupted).
$ra = $tmpDir . '/race.log';
write_chain($ra, [$c1, $c2]);
$fhA = fopen($ra, 'c+');
flock($fhA, LOCK_EX);
[$tipH] = _log_tail_tip($fhA); // A computed prev before the rotation
if (!@rename($ra, $ra . '.1')) {
    // Windows cannot rename an open file — nothing to replay here.
    flock($fhA, LOCK_UN);
    fclose($fhA);
    T::ok('race replay skipped (open-file rename unsupported)', true);
} else {
    $late = mk_chain_rec($tipH, ['ts' => '2026-08-26T00:00:09.000Z', 'level' => 'info',
        'event' => 't_race', 'msg' => 'late', 'seq' => 3]);
    fwrite($fhA, json_encode($late, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
    fflush($fhA);
    flock($fhA, LOCK_UN);
    fclose($fhA);
    $fresh = mk_chain_rec(APP_LOG_GENESIS, ['ts' => '2026-08-26T00:00:10.000Z', 'level' => 'info',
        'event' => 't_fresh', 'msg' => 'new', 'seq' => 4]);
    write_chain($ra, [$fresh]); // B starts the new generation continuing the seq
    T::eq('old generation valid after raced append', [true, 3, null, null], verify_log_chain($ra . '.1'));
    T::eq('new generation valid', [true, 1, null, null], verify_log_chain($ra));
}

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
