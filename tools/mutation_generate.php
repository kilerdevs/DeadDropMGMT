<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

// Entry-point rule (KernelTest): every tools/*.php boots through the kernel.
require_once dirname(__DIR__) . '/includes/kernel.php';

// ── Generated mutation testing (report-only) ─────────────────────────────────
// mutation_probe.php asks a hand-picked question per guard ("does a test fail
// if THIS check dies?"). This script asks the same question THOUSANDS of
// times, mechanically: it tokenizes includes/*.php, applies small
// semantics-weakening edits at every eligible site, and runs the mapped fast
// suites against each one. A mutant the suites kill is a guarded line; a
// SURVIVED mutant is either a test gap (write the assertion) or an
// equivalent mutant (the edit changed nothing observable — the proven ones
// live in $mg_equiv below, report as EQUIVALENT, and stay out of MSI).
//
// Why generated AND curated coexist: the curated 18 are the merge gate
// (--min-msi=100, every killer deterministic) because a human vetted each
// one as meaningful. The generated set always contains equivalents, so it
// can never gate — it is a scheduled sweeper (nightly, sharded, artifacts)
// plus a PR sampler (--budget/--seed). Curated says "the important guards
// hold"; generated says "here is everything the suites cannot see".
//
// Operator safety: every operator only WEAKENS existing tokens — flips a
// comparison, deletes a `!`, zeroes a literal, removes a `return <expr>`,
// forces an `if` false. No operator introduces I/O, so a mutant cannot
// unlink/overwrite/exfiltrate anything the unmutated code could not already
// reach; and mutants run in a throwaway tree copy (same pattern as the probe),
// never the checkout. `php -l` screens each mutant before any suite runs —
// parse errors are BROKEN (excluded from MSI), not kills. The shared test
// database resets the same way: order tables truncate before the baselines
// and every mutant, so a suite killed mid-run cannot poison later verdicts.
//
// The copy is MINIMAL by design (no uploads/tiles payloads, no logs), so a
// suite that needs a runtime control file would die on the missing file and
// every mutant in that file would "kill" — false data, stable and silent
// (this exact failure once made tiles/.htaccess look like 6 kills). Two
// defenses: the copy seeds runtime control files (.htaccess), and every run
// executes a BASELINE — each mapped suite once against the pristine copy.
// A red baseline is a harness error (exit 2), never a kill: it means the
// copy diverged or the DB is down, and no mutant verdict from that run can
// be trusted.
//
// Suite mapping: each includes/ file names its fast deterministic killers,
// cheapest first — the runner short-circuits on the first killing suite, so
// ordering by measured suite time (≈0.1s Csrf … ≈5.5s FailClosed on the dev
// box; see the map below) is a real cost control at thousands-scale. Slow,
// timing-sensitive, or HTTP-driven suites (ProxyClient, ProxyTransport,
// PublicFlow, TokenIndex, php -S suites, race/concurrency, Verify2fa, bench)
// are NEVER killers here: a timeout-flaky killer would cry wolf nightly.
// A file with no fast killer gets status UNTESTABLE — itself a signal to
// write one, not a gap in the tool.
//
// Usage:
//   php tools/mutation_generate.php --list                     enumerate only
//   php tools/mutation_generate.php --budget=50 --seed=123     PR sampler
//   php tools/mutation_generate.php --shard=0/8 --report=s0.json   nightly shard
//   php tools/mutation_generate.php --only=auto-auth-42-cmp-neg-1 rerun one
//   php tools/mutation_generate.php --merge=all.json s0.json s1.json ...
//   --files=auth.php,crypto.php limits scope. --min-msi=N gates (nightly and
//   PR runs omit it — report-only by design). Exit 0 report, 1 gate failed,
//   2 harness error.

$root = dirname(__DIR__);

// File => fast killer suites, cheapest first (short-circuit on first kill).
// Timings measured 2026-10-07 on the dev box; reorder if they drift.
/** @var array<string,list<string>> $mg_suites */
$mg_suites = [
    'auth.php'         => ['CsrfTest', 'RateLimitTest', 'AuthTest', 'FailClosedTest'],
    'crypto.php'       => ['UploadHardeningTest', 'CryptoTest', 'PhotoCapTest'],
    'cleanup.php'      => ['CleanupTest'],
    'order_state.php'  => ['CleanupTest', 'StateTransitionTest'],
    'logger.php'       => ['LoggerTest'],
    'analytics.php'    => ['LoggerTest'], // analytics counter asserts live in LoggerTest
    'audit.php'        => ['LoggerTest'], // audit() token-index/degrade asserts live in LoggerTest
    'i18n.php'         => ['I18nTest'],
    'backup.php'       => ['BackupTest'],
    'net.php'          => ['FuzzParsersTest', 'RateLimitTest'],
    'proxy.php'        => ['ProxyTest', 'FuzzParsersTest'],
    'pmtiles.php'      => ['PmtilesTest', 'FuzzParsersTest'],
    'maps.php'         => ['MapsUploadTest', 'MapsTest'],
    'diagnostics.php'  => ['DiagnosticsTest'],
    'totp.php'         => ['TotpTest', 'TotpReplayTest'],
    'settings.php'     => ['SettingsTest'],
    'capabilities.php' => ['CapabilitiesTest'],
    'host.php'         => ['HostTest'],
    'version.php'      => ['VersionTest'],
    'wipe.php'         => ['PanicTest'],
    'db.php'           => ['FailClosedTest'],
    // setup_check.php's fast killer (SetupCheckTest) pins the probe flags and
    // the pure row builders in seconds; CapabilitiesTest behind it loads
    // the file, so parse-level breakage surfaces too.
    'setup_check.php'  => ['SetupCheckTest', 'CapabilitiesTest'],
    'kernel.php'       => ['KernelTest'],
];

$mg_suite_timeout = 90; // per-suite wall clock; a mutant that hangs a suite
                        // (e.g. a skipped loop break) is TIMEOUT, counted
                        // killed — the suite did not pass.

// ── Equivalent-mutant suppression ─────────────────────────────────────────
// A site lands here only with PROOF no test can distinguish the edit —
// either the surrounding code already subsumes the guard (removing it cannot
// change any observable), or reaching the branch needs an environment no
// hermetic suite can build (fault-injected I/O, tree-permission surgery).
// Each entry names file + line + operator + the reason; the sampler reports
// them as EQUIVALENT (visible for audit) and excludes them from MSI, so the
// score measures coverable guards instead of punishing defensive code.
// --only bypasses this list: naming an ID explicitly always runs it, which
// is how each entry below was proven (it SURVIVES even targeted runs).
/** @var array<string,array<int,array<string,string>>> $mg_equiv file => line => op => reason */
$mg_equiv = [
    // The session-ini verification only logs: forcing the check needs locked
    // ini settings no hermetic suite can build, and the return value never
    // changes either way.
    'auth.php' => [92 => ['if-false' => 'log-only arm needs locked ini']],
    // order_token_plain() feeds every guard-false input into decrypt_token()
    // (typed string params: non-strings throw TypeError, '' decrypts to
    // false) and both land on the same `return null` arms below — the guard
    // only skips work, it never changes the answer.
    // The compressor's scale floor is hit with probability zero (exact float
    // equality after sqrt steps) and both arms converge next iteration.
    // decrypt_location()'s short-payload arm converges downstream too: with
    // a guard-passing IV, substr() on a <16 B payload is safe and
    // openssl_decrypt() answers false either way (verified empirically —
    // proven: survives even targeted runs).
    'crypto.php' => [319 => ['if-false' => 'guard subsumed by typed decrypt + null arms'],
                     869 => ['cmp-bound' => 'scale-floor edge hit with probability zero'],
                     157 => ['if-false' => 'short-payload arm converges via openssl false']],
    // log_tail_lines() normalizes both arms identically: an empty file reads
    // as '' (filtered to [] with cut=false), a missing file fails fopen —
    // the early return only skips work (LoggerTest 'empty file' passes both
    // ways by construction).
    // The non-UTF8 scrub keeps every key a strict check would: array keys
    // are int|string, and under PHP 8 neither loosely matches a non-numeric
    // field name without strictly matching it — strict and loose agree on
    // all possible keys.
    // The tail reader's empty/missing guard converges downstream too: a
    // missing file fails fopen, an empty one filters to the same pair.
    'logger.php' => [461 => ['if-false' => 'redundant guard, downstream normalizes identically'],
                     296 => ['bool-lit' => 'strict/loose agree on all array-key types'],
                     462 => ['return-del' => 'same convergence as the guard above']],
    // map_zones rows arrive via PDO FETCH_ASSOC: fetchAll() elements are
    // always arrays, so the non-array arm is unreachable without changing
    // the fetch mode.
    'diagnostics.php' => [323 => ['if-false' => 'PDO fetchAll elements always arrays'],
    // Same proof for the proxy-pool loop two dozen lines down: only the
    // tracked maximum is stored, and a tied maximum writes the same number.
                          340 => ['if-false' => 'PDO fetchAll elements always arrays'],
    // `>` vs `>=` on the running maximum is unobservable: a tie writes the
    // identical value it would have kept.
                          349 => ['cmp-bound' => 'max-tracking tie writes the same value']],
    // fread() failing on a ZipArchive entry stream has no in-process
    // injection point (the stream comes from getStream(), not a path) — the
    // branch is defensive against OS-level I/O faults only.
    // The restore's inner catch rolls back before rethrowing, but the OUTER
    // catch rolls back any still-open transaction too — killing the inner
    // rollback changes no observable (same rows, same return, same logs).
    // Defense in depth stays; it just cannot fail a test by design.
    // The stage-reader's empty/false arms need read faults no in-process
    // fixture produces (regular files return '' only at EOF, where both arms
    // already agree).
    // The tmp-name entropy only matters under concurrent creates; sequential
    // runs reuse the name safely either way.
    // The oversized-gzip refusal converges through the truthy caller: $why
    // is already 'too_large' before the deleted return, so the restore
    // answers identically (proven: survives even targeted runs).
    'backup.php' => [512 => ['return-del' => 'I/O-fault branch, not inducible in-process'],
                     700 => ['if-false' => 'inner rollback subsumed by outer catch'],
                     344 => ['if-false' => 'read-fault arms need I/O faults'],
                     219 => ['int-lit' => 'tmp-name entropy needs concurrency'],
                     810 => ['return-del' => 'oversized refusal converges via truthy caller']],
    // verify_path()'s minimum-size guard is subsumed by the layout check
    // below it: any file under 128 B fails `rootOff + lens === size` (127 +
    // non-negatives can never equal fewer than 128), so both arms agree on
    // every input including missing files.
    // covering_count()'s early-exit edge needs a cumulative total of EXACTLY
    // the cap at an intermediate zoom with more tiles after — contrived
    // coordinates no real bbox hits (the over-cap refusal itself is pinned
    // by PmtilesTest's ceiling test).
    // fetch_due()'s null-body arm needs a live origin: without one the loop
    // never produces a span to classify.
    // The plan-phase miss arm needs a fetchable archive (all misses fail
    // identically on refused hosts).
    'pmtiles.php' => [841 => ['if-false' => 'size guard subsumed by layout consistency check'],
                      166 => ['cmp-bound' => 'exact-cap hit needs contrived coordinates'],
                      648 => ['cmp-neg' => 'null-body arm needs a live origin'],
                      412 => ['if-false' => 'plan-phase miss needs a fetchable archive']],
    // The pool-walk success arm needs a LIVE proxy to observe: with only
    // dead/refused proxies both arms return the same false. Covered
    // behaviourally by ProxyClientTest (HTTP-driven, excluded as a killer
    // by design — see the suite map).
    // The chunked-reader deadline check is enforced again inside
    // proxy_read_until ($deadline passes through): dropping the explicit
    // check only delays the identical EOF/timeout outcome.
    // The direct-TLS forward flag needs a live TLS peer to observe; the
    // loopback suites cover it behaviourally (ProxyTransportTest).
    // The public-IP fetch needs clearnet: its failure arms converge to null
    // either way, and success needs two real parties.
    // List-fetch verdict mapping needs live list hosts (no seam); the
    // empty-body arm is covered behaviourally by discovery suites.
    // The heal-lock's missing-'at' fallback differs by a single second
    // (time()-1 vs time()-0 against a 900 s window) — no deterministic
    // observation can straddle it.
    // The dialing opener's greet-index needs a live listener for multi-round
    // handshakes (single-process stubs deadlock); the same check in the
    // connected-socket twin is pinned by ProxyTest's socket-pair tests.
    // The default fetch cap only matters for a successful default-cap fetch,
    // which needs a live proxy like the 1069 arm above.
    // The winner badge (failed=false on success) needs a live proxy to
    // observe; the failure badge is pinned by ProxyTest's dead-pool asserts.
    // The tunnel-TLS failure arm needs a live TLS peer (success and failure
    // converge to null on refused hosts either way).
    // The round-2 gate needs live judges; without them discovery never gets
    // far enough to diverge.
    // The curl-less result mapping needs a live origin (refused hosts fail
    // both arms identically).
    // The heal-lock's DB-fault catch converges through the single truthy
    // caller (needs a faulted connection to observe — proven: survives
    // even targeted runs).
    // The redirect method-rewrite glue needs a live redirect chain (loopback
    // servers cannot speak HTTP single-process); the predicate's literal
    // table is pinned by ProxyTest instead.
    // The CONNECT auth-header glue needs a live tunnel for the same reason;
    // the predicate is pinned by ProxyTest instead.
    'proxy.php' => [1069 => ['if-false' => 'success arm needs a live proxy to observe'],
                    726 => ['if-false' => 'deadline enforced again downstream'],
                    495 => ['bool-lit' => 'direct-TLS flag needs a live TLS peer'],
                    1342 => ['if-false' => 'public-IP fetch needs clearnet'],
                    1468 => ['logic' => 'list verdicts need live list hosts'],
                    1941 => ['int-lit' => 'missing-at fallback differs by one second'],
                    553 => ['int-lit' => 'dialing opener needs a live listener'],
                    1060 => ['int-lit' => 'default cap needs a successful fetch'],
                    1114 => ['bool-lit' => 'winner badge needs a live proxy'],
                    // The non-array label arm converges to the same empty
                    // string through the implode below it.
                    1253 => ['return-del' => 'non-array arm converges via implode'],
                    1829 => ['not-del' => 'tunnel-TLS arms need a live TLS peer'],
                    1589 => ['if-false' => 'round-2 gate needs live judges'],
                    1415 => ['if-false' => 'curl-less mapping needs a live origin'],
                    1981 => ['return-del' => 'lock-catch refusal converges via truthy caller'],
                    2056 => ['int-lit' => 'heal time budget needs a slow pass to observe'],
                    1735 => ['bool-lit' => 'mass-dial blocking flag needs live dial targets'],
                    693 => ['if-false' => 'rewrite glue needs a live redirect chain'],
                    1803 => ['if-false' => 'auth-header glue needs a live tunnel']],
    // Pseudo-cron may only run under a web SAPI: fast suites always run as
    // CLI, where the SAPI arm decides alone and the flag default is dead.
    'cleanup.php' => [204 => ['bool-lit' => 'SAPI-gated, fast suites always CLI']],
    // maps_zone_refresh(0) reaches the same refusal through rowCount: no
    // AUTO_INCREMENT id is <= 0, so the guarded UPDATE matches nothing and
    // the row-count check returns false either way.
    // The steward dice with chance exactly 1.0 rolls random_int(1, 1), which
    // always passes — both arms run the steward; only an unobservable CSPRNG
    // call differs.
    // A 206 to a fresh request in the curl-less transport only differs with
    // a Range origin behind them — curl builds never reach the arm.
    // Plan-building with swapped bbox corners needs a fetchable archive to
    // diverge (both arms fail identically on refused hosts).
    // The build-list parser needs a live list host; without one both arms
    // refuse identically.
    // A 0/1-byte upload converges to the same refusal downstream (disk and
    // header checks refuse what the size guard would have).
    // The magic/version fast-reject converges through the structural verify
    // right below it: every input taking the early arm fails the full pass
    // with the same reason string and the same staging unlink (proven:
    // survives even targeted runs).
    // The disk-full arm needs a full disk to observe (no hermetic suite can
    // fill one — proven: survives even targeted runs).
    'maps.php' => [1266 => ['if-false' => 'id guard subsumed by rowCount check'],
                   1592 => ['cmp-bound' => 'chance-1.0 dice always passes'],
                   1026 => ['cmp-bound' => 'fresh-206 arm needs a Range origin'],
                   1777 => ['int-lit' => 'swapped plan args need a fetchable archive'],
                   1061 => ['return-del' => 'build-list parse needs a live list host'],
                   1325 => ['logic' => 'tiny upload converges to the same refusal'],
                   1335 => ['return-del' => 'magic-guard refusal subsumed by structural verify'],
                   1794 => ['if-false' => 'disk-full arm needs a full disk']],
    // Session language lookup: the supported list holds no numeric strings,
    // and under PHP 8 a session value loosely matches one only by strictly
    // matching it — same proof as the logger scrub above.
    'i18n.php' => [53 => ['bool-lit' => 'strict/loose agree on all session values']],
    // The multihop warning is observability only: firing it on single hops
    // (or never) changes no return value, and the once-per-process latch
    // makes even the warning order-dependent.
    'net.php' => [165 => ['int-lit' => 'warn-once noise, return value identical'],
                  168 => ['bool-lit' => 'warn-once noise, return value identical']],
];

/** @param array<string,mixed> $m */
function mg_is_equiv(array $m): ?string {
    global $mg_equiv;
    return $mg_equiv[basename($m['file'])][$m['line']][$m['op']] ?? null;
}

// ── CLI ─────────────────────────────────────────────────────────────────────
$args = array_slice($argv ?? [], 1);
// --merge is pre-scanned so report files may follow it in any position:
// --merge=out.json s0.json s1.json (it never runs mutants).
foreach ($args as $ai => $a) {
    if (!str_starts_with($a, '--merge=')) continue;
    $out = substr($a, 8);
    $merged = ['tool' => 'mutation_generate', 'merged' => [], 'mutants' => []];
    foreach (array_slice($args, $ai + 1) as $f) {
        $j = json_decode((string)@file_get_contents($f), true);
        if (!is_array($j) || !isset($j['mutants']) || !is_array($j['mutants'])) {
            fwrite(STDERR, "merge: unreadable report $f\n");
            exit(2);
        }
        $merged['merged'][] = $f;
        foreach ($j['mutants'] as $mu) $merged['mutants'][] = $mu;
    }
    mg_print_summary($merged['mutants'], (int)($merged['mutants'][0]['seed'] ?? 0));
    file_put_contents($out, json_encode($merged, JSON_PRETTY_PRINT) . "\n");
    echo 'merged ' . count($merged['mutants']) . " mutants -> $out\n";
    exit(0);
}
$opt = ['seed' => 20261007, 'budget' => null, 'shard' => null, 'only' => null,
        'list' => false, 'report' => null, 'min-msi' => null, 'files' => null];
foreach ($args as $a) {
    if ($a === '--list') { $opt['list'] = true; continue; }
    if (preg_match('/^--seed=(\d+)$/', $a, $m) === 1) { $opt['seed'] = (int)$m[1]; continue; }
    if (preg_match('/^--budget=(\d+)$/', $a, $m) === 1) { $opt['budget'] = (int)$m[1]; continue; }
    if (preg_match('/^--shard=(\d+)\/(\d+)$/', $a, $m) === 1) { $opt['shard'] = [(int)$m[1], (int)$m[2]]; continue; }
    if (str_starts_with($a, '--only=')) { $opt['only'] = explode(',', substr($a, 7)); continue; }
    if (str_starts_with($a, '--report=')) { $opt['report'] = substr($a, 9); continue; }
    if (preg_match('/^--min-msi=(\d+(?:\.\d+)?)$/', $a, $m) === 1) { $opt['min-msi'] = (float)$m[1]; continue; }
    if (str_starts_with($a, '--files=')) { $opt['files'] = explode(',', substr($a, 8)); continue; }
    fwrite(STDERR, "unknown arg: $a\n");
    exit(2);
}

// ── Token helpers ───────────────────────────────────────────────────────────
// token_get_all mixes [id, text, line] arrays with single-char strings.
// Normalize once: every entry is [id|null, text, line].
/**
 * @return list<array{int|null,string,int}>
 */
function mg_tokenize(string $src): array {
    $out = [];
    $line = 1;
    foreach (token_get_all($src) as $t) {
        if (is_array($t)) {
            $out[] = [$t[0], $t[1], $t[2]];
            $line = $t[2] + substr_count($t[1], "\n");
        } else {
            $out[] = [null, $t, $line];
            $line += substr_count($t, "\n");
        }
    }
    return $out;
}

/** @param array{int|null,string,int} $tok */
function mg_is_ws(array $tok): bool {
    return $tok[0] === T_WHITESPACE || $tok[0] === T_COMMENT || $tok[0] === T_DOC_COMMENT;
}

/**
 * Next non-trivia token index at/after $i, or null.
 * @param list<array{int|null,string,int}> $toks
 */
function mg_next(array $toks, int $i): ?int {
    $n = count($toks);
    while ($i < $n && mg_is_ws($toks[$i])) $i++;
    return $i < $n ? $i : null;
}

/**
 * Match the closer for the opener at $i ('('/'['/'{').
 * Interpolation blocks ("{$...}", "${...}") are skipped as balanced units
 * rather than depth-counted: their T_CURLY_OPEN has no literal '{' twin,
 * so counting it would phantom-inflate the depth and land the match in the
 * wrong place (or return null for a well-formed span).
 * @param list<array{int|null,string,int}> $toks
 */
function mg_match(array $toks, int $i): ?int {
    $open = $toks[$i][1];
    $pairs = ['(' => ')', '[' => ']', '{' => '}'];
    if (!isset($pairs[$open])) return null;
    $want = $pairs[$open];
    $depth = 0;
    $n = count($toks);
    for ($j = $i; $j < $n; $j++) {
        [$id, $tx] = $toks[$j];
        if ($tx === $open) {
            $depth++;
            continue;
        }
        if ($id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) {
            $d = 1;
            $j++;
            while ($j < $n && $d > 0) {
                if ($toks[$j][0] === T_CURLY_OPEN || $toks[$j][0] === T_DOLLAR_OPEN_CURLY_BRACES) $d++;
                elseif ($toks[$j][1] === '}') $d--;
                $j++;
            }
            $j--; // the for-step moves back onto the token after '}'
            continue;
        }
        if ($tx === $want) {
            $depth--;
            if ($depth === 0) return $j;
        }
    }
    return null;
}

/**
 * Token-index ranges to skip: declare(...) spans (strict_types=1 must never
 * be "mutated" — that is churn, not a guard).
 * @param list<array{int|null,string,int}> $toks
 * @return list<array{int,int}>
 */
function mg_skip_ranges(array $toks): array {
    $ranges = [];
    $n = count($toks);
    for ($i = 0; $i < $n; $i++) {
        if ($toks[$i][0] !== T_DECLARE) continue;
        $j = mg_next($toks, $i + 1);
        if ($j === null || $toks[$j][1] !== '(') continue;
        $depth = 0;
        for ($k = $j; $k < $n; $k++) {
            if ($toks[$k][1] === '(') $depth++;
            elseif ($toks[$k][1] === ')') {
                $depth--;
                if ($depth === 0) { $ranges[] = [$i, $k]; break; }
            } elseif ($toks[$k][1] === ';' && $depth === 0) {
                $ranges[] = [$i, $k]; break;
            }
        }
    }
    return $ranges;
}

/** @param list<array{int,int}> $ranges */
function mg_skipped(array $ranges, int $i): bool {
    foreach ($ranges as [$a, $b]) {
        if ($i >= $a && $i <= $b) return true;
    }
    return false;
}

/** Rebuild source, replacing span [$a,$b] with $new (or deleting when null). */
function mg_rebuild(array $toks, int $a, int $b, ?string $new): string {
    $out = '';
    $n = count($toks);
    for ($i = 0; $i < $n; $i++) {
        if ($i === $a) {
            if ($new !== null) $out .= $new;
            $i = $b;
            continue;
        }
        $out .= $toks[$i][1];
    }
    return $out;
}

function mg_same_case(string $template, string $word): string {
    if ($template === strtoupper($template)) return strtoupper($word);
    if ($template === ucfirst(strtolower($template))) return ucfirst($word);
    return $word;
}

// ── Enumeration ─────────────────────────────────────────────────────────────
// One mutant = one token-site edit. Deterministic order: sorted files, token
// order — shard math (index % N) is stable for a given tree.
/**
 * @return list<array{id:string,file:string,line:int,op:string,a:int,b:int,new:?string,orig:string,desc:string}>
 */
function mg_enumerate(string $file, string $src): array {
    $toks = mg_tokenize($src);
    $skip = mg_skip_ranges($toks);
    $n = count($toks);
    $base = basename($file, '.php');
    $out = [];
    $seq = 0;
    $add = static function (int $line, string $op, int $a, int $b, ?string $new, string $orig, string $desc) use (&$out, &$seq, $base, $file): void {
        $seq++;
        $out[] = ['id' => "auto-{$base}-{$line}-{$op}-{$seq}", 'file' => $file,
                  'line' => $line, 'op' => $op, 'a' => $a, 'b' => $b,
                  'new' => $new, 'orig' => $orig, 'desc' => $desc];
    };
    for ($i = 0; $i < $n; $i++) {
        if (mg_skipped($skip, $i)) continue;
        [$id, $tx, $ln] = $toks[$i];
        if ($id === T_IS_EQUAL) { $add($ln, 'cmp-neg', $i, $i, '!=', '==', 'equality negated'); continue; }
        if ($id === T_IS_NOT_EQUAL) { $add($ln, 'cmp-neg', $i, $i, '==', '!=', 'inequality negated'); continue; }
        if ($id === T_IS_IDENTICAL) { $add($ln, 'cmp-neg', $i, $i, '!==', '===', 'identity negated'); continue; }
        if ($id === T_IS_NOT_IDENTICAL) { $add($ln, 'cmp-neg', $i, $i, '===', '!==', 'non-identity negated'); continue; }
        if ($id === null && $tx === '<') { $add($ln, 'cmp-bound', $i, $i, '<=', '<', 'bound loosened'); continue; }
        if ($id === null && $tx === '>') { $add($ln, 'cmp-bound', $i, $i, '>=', '>', 'bound loosened'); continue; }
        if ($id === T_IS_SMALLER_OR_EQUAL) { $add($ln, 'cmp-bound', $i, $i, '<', '<=', 'bound tightened'); continue; }
        if ($id === T_IS_GREATER_OR_EQUAL) { $add($ln, 'cmp-bound', $i, $i, '>', '>=', 'bound tightened'); continue; }
        if ($id === T_BOOLEAN_AND) { $add($ln, 'logic', $i, $i, '||', '&&', 'conjunction weakened to disjunction'); continue; }
        if ($id === T_BOOLEAN_OR) { $add($ln, 'logic', $i, $i, '&&', '||', 'disjunction strengthened to conjunction'); continue; }
        if ($id === T_LOGICAL_AND) { $add($ln, 'logic', $i, $i, mg_same_case($tx, 'or'), $tx, 'and weakened to or'); continue; }
        if ($id === T_LOGICAL_OR) { $add($ln, 'logic', $i, $i, mg_same_case($tx, 'and'), $tx, 'or strengthened to and'); continue; }
        if ($id === null && $tx === '!') { $add($ln, 'not-del', $i, $i, '', '!', 'negation removed'); continue; }
        if ($id === T_STRING && in_array(strtolower($tx), ['true', 'false'], true)) {
            $to = strtolower($tx) === 'true' ? 'false' : 'true';
            $add($ln, 'bool-lit', $i, $i, mg_same_case($tx, $to), $tx, 'boolean flipped');
            continue;
        }
        if ($id === T_LNUMBER) {
            $to = intval($tx, 0) === 0 ? '1' : '0';
            $add($ln, 'int-lit', $i, $i, $to, $tx, 'integer zeroed/one-d');
            continue;
        }
        if ($id === T_RETURN) {
            // Delete `return <expr>;` — the function silently yields null.
            // Depth-tracked so nested calls/closures/arrays do not end the
            // span early; abort past a close tag or EOF (never delete those).
            // `return null;` is never enumerated: deleting it yields null
            // anyway, so the mutant is equivalent by construction.
            $depth = 0;
            $j = $i + 1;
            $bare = true;
            $end = null;
            while ($j < $n) {
                [$jid, $jtx] = $toks[$j];
                if ($jid === T_CLOSE_TAG || $jid === T_HALT_COMPILER) break;
                if ($jtx === '(' || $jtx === '[' || $jtx === '{' || $jid === T_CURLY_OPEN || $jid === T_DOLLAR_OPEN_CURLY_BRACES) $depth++;
                elseif ($jtx === ')' || $jtx === ']' || $jtx === '}') $depth--;
                elseif ($jtx === ';' && $depth === 0) { $end = $j; break; }
                if (!mg_is_ws($toks[$j]) && $jtx !== ';') $bare = false;
                $j++;
            }
            if ($end !== null && !$bare) {
                $words = [];
                for ($k = $i + 1; $k < $end; $k++) {
                    if (!mg_is_ws($toks[$k])) $words[] = strtolower($toks[$k][1]);
                }
                if ($words !== ['null']) {
                    $add($ln, 'return-del', $i, $end, '', 'return …;', 'valued return deleted (yields null)');
                }
            }
            continue;
        }
        if ($id === T_IF || $id === T_ELSEIF) {
            // Force the branch dead: `if (C)` -> `if (false && (C))`. Guards
            // that matter must kill this; surviving intentional-false arms
            // (e.g. feature flags) are the expected equivalents.
            $j = mg_next($toks, $i + 1);
            if ($j === null || $toks[$j][1] !== '(') continue;
            $close = mg_match($toks, $j);
            if ($close === null) continue;
            $kw = $toks[$i][1]; // 'if' or 'elseif', verbatim
            $inner = '';
            for ($k = $j + 1; $k < $close; $k++) $inner .= $toks[$k][1];
            // Rebuild keeps the original `if (` prefix (spacing/comments)
            // and only wraps the condition.
            $prefix = '';
            for ($k = $i; $k <= $j; $k++) $prefix .= $toks[$k][1];
            $add($ln, 'if-false', $j + 1, $close - 1, 'false && (' . $inner . ')',
                 $kw . ' (…)', 'branch forced dead');
            continue;
        }
    }
    return $out;
}

// ── Seeded shuffle (xorshift32, same family as the fuzz suite's PRNG) ───────
function mg_shuffle(array $list, int $seed): array {
    $st = ($seed & 0xffffffff) !== 0 ? ($seed & 0xffffffff) : 1;
    $rand = static function (int $bound) use (&$st): int {
        $st ^= ($st << 13) & 0xffffffff;
        $st ^= ($st >> 17);
        $st ^= ($st << 5) & 0xffffffff;
        $st &= 0xffffffff;
        return $bound > 0 ? $st % $bound : 0;
    };
    for ($i = count($list) - 1; $i > 0; $i--) {
        $j = $rand($i + 1);
        [$list[$i], $list[$j]] = [$list[$j], $list[$i]];
    }
    return $list;
}

// ── Throwaway tree (same pattern as the probe) ──────────────────────────────
function mg_copy_tree(string $from, string $to, array $skipTop, bool $top = true): bool {
    if (!is_dir($to) && !@mkdir($to, 0700, true)) return false;
    foreach (scandir($from) ?: [] as $e) {
        if ($e === '.' || $e === '..' || ($top && in_array($e, $skipTop, true))) continue;
        $s = $from . '/' . $e;
        $d = $to . '/' . $e;
        if (is_link($s)) continue;
        if (is_dir($s)) {
            if (!mg_copy_tree($s, $d, $skipTop, false)) return false;
        } elseif (!@copy($s, $d)) return false;
    }
    return true;
}

function mg_rm_tree(string $p): void {
    if (is_link($p) || is_file($p)) { @unlink($p); return; }
    if (!is_dir($p)) return;
    foreach (scandir($p) ?: [] as $e) {
        if ($e !== '.' && $e !== '..') mg_rm_tree($p . '/' . $e);
    }
    @rmdir($p);
}

// The suites share one test database, and a suite killed mid-run leaves its
// seeded rows behind for the NEXT mutant's suites to trip on (whole-table
// scans like the backup/crypto migration tools read every row, whatever its
// prefix; zone listings see every row). Files are restored per mutant; rows
// are reset here instead: the seeded tables truncate before the baselines
// and every mutant, so each verdict observes only what its own suites
// seeded. Settings, users and audit rows stay — suites snapshot those
// themselves (or DELETE-first their own keys).
function mg_db_reset(): void {
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DDMGMT_DB_HOST') ?: '127.0.0.1';
        $port = getenv('DDMGMT_DB_PORT') ?: '3306';
        $user = getenv('DDMGMT_DB_USER') ?: 'root';
        $pass = getenv('DDMGMT_DB_PASS') !== false ? (string)getenv('DDMGMT_DB_PASS') : '';
        $name = getenv('DDMGMT_TEST_DB') ?: 'deaddrops_test';
        try {
            $pdo = new PDO("mysql:host=$host;port=$port;dbname=$name;charset=utf8mb4", $user, $pass,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        } catch (PDOException $e) {
            fwrite(STDERR, 'harness error: cannot reset test database: ' . $e->getMessage() . "\n");
            exit(2);
        }
    }
    try {
        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        foreach (['order_events', 'order_photos', 'orders', 'map_zones', 'osm_proxies'] as $t) {
            $pdo->exec("TRUNCATE `$t`");
        }
        $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
    } catch (PDOException $e) {
        fwrite(STDERR, 'harness error: cannot truncate test tables: ' . $e->getMessage() . "\n");
        exit(2);
    }
}

// Run one suite inside the copy, bounded. Returns [status, seconds, tail].
// status is 'pass', 'fail', or 'timeout'.
function mg_run_suite(string $copy, string $suite, int $timeout): array {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($copy . '/tests/' . $suite . '.php') . ' 2>&1';
    $t0 = microtime(true);
    $des = [0 => ['pipe', 'r'], 1 => ['pipe', 'w']];
    $p = @proc_open($cmd, $des, $pipes, $copy);
    if (!is_resource($p)) return ['error', 0.0, 'proc_open failed'];
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    $out = '';
    $timedOut = false;
    while (true) {
        $out .= stream_get_contents($pipes[1]) ?: '';
        $st = proc_get_status($p);
        if (!$st['running']) {
            $code = $st['exitcode'];
            break;
        }
        if (microtime(true) - $t0 > $timeout) {
            $timedOut = true;
            @proc_terminate($p);
            // Reap: the terminate needs a moment; poll briefly, then close.
            for ($w = 0; $w < 20; $w++) {
                $st = proc_get_status($p);
                if (!$st['running']) break;
                usleep(50000);
            }
            $out .= stream_get_contents($pipes[1]) ?: '';
            $code = -1;
            break;
        }
        usleep(50000);
    }
    fclose($pipes[1]);
    @proc_close($p);
    $dt = microtime(true) - $t0;
    $lines = array_values(array_filter(explode("\n", trim($out)), static fn($l) => trim($l) !== ''));
    $tail = implode("\n", array_slice($lines, -15));
    if ($timedOut) return ['timeout', round($dt, 1), $tail];
    return [$code === 0 ? 'pass' : 'fail', round($dt, 1), $tail];
}

/** @param list<array<string,mixed>> $mutants */
function mg_print_summary(array $mutants, int $seed): void {
    $k = $s = $b = $t = $u = $e = 0;
    foreach ($mutants as $m) {
        match ($m['status'] ?? '') {
            'KILLED' => $k++, 'SURVIVED' => $s++, 'BROKEN' => $b++,
            'TIMEOUT' => $t++, 'EQUIVALENT' => $e++, default => $u++,
        };
    }
    $msi = ($k + $s + $t) > 0 ? round(100 * ($k + $t) / ($k + $s + $t), 1) : 0.0;
    echo 'Generated mutation: ' . ($k + $t) . '/' . ($k + $s + $t)
        . " killed (MSI {$msi}%), $b broken, $u untestable, $e equivalent, seed $seed\n";
    foreach ($mutants as $m) {
        $st = $m['status'] ?? '?';
        if ($st === 'KILLED' || $st === 'TIMEOUT') {
            echo "  $st   {$m['id']} [{$m['file']}:{$m['line']}] {$m['desc']} ({$m['secs']}s)\n";
        }
    }
    foreach ($mutants as $m) {
        if (($m['status'] ?? '') === 'SURVIVED') {
            echo "  SURVIVED {$m['id']} [{$m['file']}:{$m['line']}] {$m['desc']}\n";
        }
    }
    foreach ($mutants as $m) {
        if (($m['status'] ?? '') === 'UNTESTABLE') {
            echo "  UNTESTABLE {$m['id']} [{$m['file']}:{$m['line']}] {$m['desc']}\n";
        }
    }
    foreach ($mutants as $m) {
        if (($m['status'] ?? '') === 'EQUIVALENT') {
            echo "  EQUIVALENT {$m['id']} [{$m['file']}:{$m['line']}] {$m['desc']} ({$m['output']})\n";
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────────────
$scope = $opt['files'] ?? array_keys($mg_suites);
$files = [];
foreach ($scope as $f) {
    $f = basename(trim((string)$f));
    if ($f === '' || substr($f, -4) !== '.php') { fwrite(STDERR, "bad --files entry: $f\n"); exit(2); }
    if (!is_file($root . '/includes/' . $f)) { fwrite(STDERR, "unknown file: $f\n"); exit(2); }
    $files[] = $f;
}
sort($files);

$all = [];
foreach ($files as $f) {
    $src = (string)@file_get_contents($root . '/includes/' . $f);
    foreach (mg_enumerate('includes/' . $f, $src) as $m) $all[] = $m;
}
// Stable shard math: enumeration order is file-sorted + token order.
if ($opt['shard'] !== null) {
    // \d+ cannot be negative, so only k >= n is rejectable (a $k < 0 arm
    // here would be dead code, not validation).
    [$k, $n] = [(int)$opt['shard'][0], max(1, (int)$opt['shard'][1])];
    if ($k >= $n) { fwrite(STDERR, "bad --shard\n"); exit(2); }
    $all = array_values(array_filter($all, static fn($m, $i) => $i % $n === $k, ARRAY_FILTER_USE_BOTH));
}
if ($opt['only'] !== null) {
    $want = array_flip($opt['only']);
    $all = array_values(array_filter($all, static fn($m) => isset($want[$m['id']])));
    if ($all === []) { fwrite(STDERR, "no mutants match --only\n"); exit(2); }
}
$all = mg_shuffle($all, $opt['seed']);
// Equivalents are partitioned AFTER the shuffle (enumeration order, IDs and
// shard math stay stable) but BEFORE the budget slice, so --budget always
// buys runnable mutants and the suppressed sites cost no suite time. An
// explicit --only bypasses suppression: naming a mutant means run it.
$equiv = [];
if ($opt['only'] === null) {
    $kept = [];
    foreach ($all as $m) {
        $why = mg_is_equiv($m);
        if ($why !== null) {
            $m['status'] = 'EQUIVALENT';
            $m['output'] = $why;
            $m['seed'] = $opt['seed'];
            $m['suites'] = $mg_suites[basename($m['file'])] ?? [];
            $equiv[] = $m;
        } else {
            $kept[] = $m;
        }
    }
    $all = $kept;
}
if ($opt['budget'] !== null) $all = array_slice($all, 0, max(0, $opt['budget']));

echo 'enumerated ' . count($all) . " mutant(s), seed {$opt['seed']}\n";

if ($opt['list']) {
    $byFile = [];
    $byOp = [];
    foreach ($all as $m) {
        $byFile[$m['file']] = ($byFile[$m['file']] ?? 0) + 1;
        $byOp[$m['op']] = ($byOp[$m['op']] ?? 0) + 1;
    }
    ksort($byFile);
    ksort($byOp);
    foreach ($byFile as $f => $c) echo "  $f: $c\n";
    echo 'operators: ';
    $parts = [];
    foreach ($byOp as $op => $c) $parts[] = "$op=$c";
    echo implode(', ', $parts) . "\n";
    exit(0);
}

$copy = sys_get_temp_dir() . '/ddmgmt-genmut-' . getmypid() . '-' . bin2hex(random_bytes(4));
$skipTop = ['.git', 'node_modules', 'vendor', 'uploads', 'tiles', 'cache', 'logs', 'backups', 'data',
            'test-results', 'playwright-report', 'coverage-html'];
// DDMGMT_MUTANT_KEEP=1 leaves the throwaway tree behind for post-mortem
// (which file the mutant touched, the copy's log with the real exception).
// Otherwise it is always removed, even on Ctrl-C (shutdown function).
$keep = getenv('DDMGMT_MUTANT_KEEP') === '1';
register_shutdown_function(static function () use ($copy, $keep): void {
    if (!$keep) mg_rm_tree($copy);
});
if ($keep) echo "throwaway tree kept at: $copy\n";
if (!mg_copy_tree($root, $copy, $skipTop)) {
    fwrite(STDERR, "cannot copy tree to $copy\n");
    exit(2);
}
foreach (['logs', 'uploads', 'tiles', 'cache/osm_tiles', 'cache/sessions', 'data/maps', 'backups'] as $d) {
    @mkdir($copy . '/' . $d, 0700, true);
}
// Runtime control files the suites read (deny rules, not payloads): without
// tiles/.htaccess every KernelTest mutant "killed" on the missing file.
foreach (['logs/.htaccess', 'uploads/.htaccess', 'tiles/.htaccess', 'cache/.htaccess', 'data/.htaccess', 'backups/.htaccess'] as $f) {
    if (is_file($root . '/' . $f)) @copy($root . '/' . $f, $copy . '/' . $f);
}

// ── Baseline: every mapped suite must pass on the PRISTINE copy ────────────
// A red baseline means the copy diverged (or the DB is down) — mutant
// verdicts from such a run would be fiction, so this is a harness error,
// not a kill.
$baselineSuites = [];
foreach ($all as $m) {
    foreach ($mg_suites[basename($m['file'])] ?? [] as $s) $baselineSuites[$s] = true;
}
mg_db_reset();
foreach (array_keys($baselineSuites) as $suite) {
    [$st, $dt, $tail] = mg_run_suite($copy, $suite, $mg_suite_timeout);
    echo "  baseline $suite: $st ({$dt}s)\n";
    if ($st !== 'pass') {
        fwrite(STDERR, "harness error: baseline $suite does not pass on the pristine copy ($st):\n$tail\n");
        exit(2);
    }
}

$results = [];
foreach ($all as $m) {
    $row = ['id' => $m['id'], 'file' => $m['file'], 'line' => $m['line'], 'op' => $m['op'],
            'orig' => $m['orig'], 'desc' => $m['desc'], 'seed' => $opt['seed'],
            'suites' => $mg_suites[basename($m['file'])] ?? []];
    if ($row['suites'] === []) {
        $row += ['status' => 'UNTESTABLE', 'secs' => 0.0, 'output' => 'no fast killer suite mapped'];
        $results[] = $row;
        continue;
    }
    $toks = mg_tokenize((string)@file_get_contents($copy . '/' . $m['file']));
    $mutated = mg_rebuild($toks, $m['a'], $m['b'], $m['new']);
    // Screen with php -l before any suite sees it: parse errors are BROKEN.
    $lint = $copy . '/.mutant-lint.php';
    file_put_contents($lint, $mutated);
    $lintOut = [];
    $lintCode = 0;
    exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($lint) . ' 2>&1', $lintOut, $lintCode);
    @unlink($lint);
    if ($lintCode !== 0) {
        $row += ['status' => 'BROKEN', 'secs' => 0.0, 'output' => implode("\n", array_slice($lintOut, 0, 3))];
        $results[] = $row;
        continue;
    }
    $path = $copy . '/' . $m['file'];
    $orig = (string)@file_get_contents($path);
    file_put_contents($path, $mutated);
    mg_db_reset();
    $status = 'SURVIVED';
    $secs = 0.0;
    $note = '';
    $evidence = '';
    foreach ($row['suites'] as $suite) {
        [$st, $dt, $tail] = mg_run_suite($copy, $suite, $mg_suite_timeout);
        $secs = round($secs + $dt, 1);
        if ($st === 'timeout') { $status = 'TIMEOUT'; $note = "$suite hung (>${mg_suite_timeout}s)"; break; }
        if ($st === 'error') {
            file_put_contents($path, $orig);
            fwrite(STDERR, "harness error running $suite\n");
            exit(2);
        }
        // Killed verdicts carry the failing assertion lines: without them a
        // nightly report is triage-blind (which assert died, and why).
        if ($st === 'fail') { $status = 'KILLED'; $note = "$suite failed in {$dt}s"; $evidence = $tail; break; }
    }
    file_put_contents($path, $orig);
    // One-line snippet of the mutated line for the report.
    $snip = '';
    $ln = 1;
    foreach (explode("\n", $mutated) as $line) {
        if ($ln === $m['line']) { $snip = trim($line); break; }
        $ln++;
    }
    $row += ['status' => $status, 'secs' => $secs, 'output' => $note, 'snippet' => $snip];
    if ($evidence !== '') $row['output'] .= "\n" . $evidence;
    $results[] = $row;
    echo "  {$status} {$m['id']} [{$m['file']}:{$m['line']}] {$m['desc']}" . ($note !== '' ? " ($note)" : '') . "\n";
}

mg_print_summary(array_merge($results, $equiv), $opt['seed']);
if ($opt['report'] !== null) {
    file_put_contents($opt['report'], json_encode(
        ['tool' => 'mutation_generate', 'seed' => $opt['seed'], 'mutants' => array_merge($results, $equiv)],
        JSON_PRETTY_PRINT) . "\n");
    echo 'report -> ' . $opt['report'] . "\n";
}
if ($opt['min-msi'] !== null) {
    $k = $s = $t = 0;
    foreach ($results as $m) {
        match ($m['status']) { 'KILLED' => $k++, 'SURVIVED' => $s++, 'TIMEOUT' => $t++, default => null };
    }
    $msi = ($k + $s + $t) > 0 ? 100 * ($k + $t) / ($k + $s + $t) : 0.0;
    if ($msi < $opt['min-msi']) {
        fwrite(STDERR, "generated MSI {$msi}% below {$opt['min-msi']}% gate\n");
        exit(1);
    }
}
exit(0);
