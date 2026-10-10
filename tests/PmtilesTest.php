<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── PMTiles v3 pure-PHP engine: format core ────────────────────────────────
// No network, no DB: varints, Hilbert ids, directory codec round-trip, and a
// read of the real CLI-built zone archive (proves byte-compatibility with
// go-pmtiles output, including the +1 offset bias and zero-compression).

foreach ([0, 1, 127, 128, 300, 16384, 2097151, 2065704, 2 ** 40] as $v) {
    $enc = pmtiles_vint_encode($v);
    $pos = 0;
    T::ok("vint round-trip $v", pmtiles_vint_decode($enc, $pos) === $v && $pos === strlen($enc));
}
$pos = 0;
T::ok('vint truncation fails closed', pmtiles_vint_decode("\x80", $pos) === null);

// Ground truth from the CLI-built archive (tiles/zone_44_*): root tile ids
// 0, 4, 18, 75, 302 — tile 4 is z1 x1/y0 (the Warsaw tile at that zoom).
T::eq('hilbert z0 tile', 0, pmtiles_tile_id(0, 0, 0));
T::eq('hilbert z1 (1,0)', 4, pmtiles_tile_id(1, 1, 0));
T::eq('level offsets', [0, 1, 5, 21, 85],
    [pmtiles_level_offset(0), pmtiles_level_offset(1), pmtiles_level_offset(2),
     pmtiles_level_offset(3), pmtiles_level_offset(4)]);
$h21 = pmtiles_hilbert_id(2, 2, 1);
T::ok('hilbert z2 in grid range', $h21 >= 0 && $h21 < 16);
$ids = pmtiles_covering_ids(20.9, 52.1, 21.2, 52.4, 1);
T::ok('covering holds z0 + Warsaw z1 tile', in_array(0, $ids, true) && in_array(4, $ids, true));
$sorted = $ids;
sort($sorted, SORT_NUMERIC);
T::ok('covering ascending deduplicated', $ids === $sorted && count($ids) === count(array_unique($ids)));
// OOM guard: a continent at high zoom trips the covering ceiling instead of
// building a quarter-million-entry plan.
T::ok('covering count trips the ceiling',
    pmtiles_covering_count(-180.0, -85.0, 180.0, 85.0, 14) > PMTILES_COVERING_MAX);

// Directory codec round-trip, contiguous (zero-compressed) and gapped offsets.
$entries = [
    ['id' => 0, 'len' => 100, 'off' => 0],
    ['id' => 4, 'len' => 50, 'off' => 100],
    ['id' => 18, 'len' => 70, 'off' => 150],
    ['id' => 302, 'len' => 33, 'off' => 900],
];
$dec = pmtiles_parse_dir(pmtiles_dir_encode($entries), PMTILES_COMP_GZIP);
T::ok('dir round-trip decodes', $dec !== null && count($dec ?? []) === 4);
if (is_array($dec)) {
    foreach ($entries as $i => $e) {
        T::eq("dir entry $i", ['id' => $e['id'], 'run' => 1, 'len' => $e['len'], 'off' => $e['off']], $dec[$i]);
    }
    T::eq('find hit', $dec[2], pmtiles_find_entry($dec, 18));
    T::ok('find miss', pmtiles_find_entry($dec, 19) === null);
}
T::ok('dir rejects bad compression', pmtiles_parse_dir('xx', 0) === null);
T::ok('dir rejects truncation', pmtiles_parse_dir("\x05\x00", PMTILES_COMP_NONE) === null);

// Real CLI-built archive: parse, resolve, gunzip, verify. Uses the committed
// e2e fixture (a documented `pmtiles extract` product, SHA-256 pinned in
// e2e/fixtures/README.md) — never tiles/zone_*.pmtiles: the orphan sweep
// deletes zone files no row claims once they age past an hour, so a stray
// download there is not a stable fixture.
$fixture = dirname(__DIR__) . '/e2e/fixtures/micro.pmtiles';
T::ok('the CLI-built fixture exists for the compat read', is_file($fixture));
if (is_file($fixture)) {
    $raw = (string)file_get_contents($fixture);
    $hdr = pmtiles_parse_header(substr($raw, 0, 127));
    T::ok('real header parses', $hdr !== null && $hdr['tileType'] === PMTILES_TYPE_MVT);
    if ($hdr !== null) {
        $root = pmtiles_parse_dir(
            substr($raw, $hdr['rootOff'], $hdr['rootLen']), $hdr['intComp']);
        T::eq('real root entry count', $hdr['nEntries'], $root === null ? -1 : count($root));
        if ($root !== null) {
            $e4 = pmtiles_find_entry($root, 4);
            T::ok('real tile resolves', $e4 !== null && ($e4['run'] ?? 0) === 1 && ($e4['len'] ?? 0) > 0);
            if ($e4 !== null) {
                $tile = substr($raw, $hdr['tileOff'] + $e4['off'], $e4['len']);
                T::ok('real tile is gzip MVT', substr($tile, 0, 2) === "\x1f\x8b"
                    && is_string(@gzdecode($tile)));
            }
        }
        T::ok('real archive verifies', pmtiles_verify_path($fixture));
    }
}

// Assembler in isolation: fake tiles through plan → file → verify → bytes.
$tmp = sys_get_temp_dir() . '/ddmgmt_pmtiles_' . getmypid();
@mkdir($tmp, 0700, true);
$tileA = (string)gzencode('TILE-A');
$tileB = (string)gzencode('TILE-BBBBB');
$tileC = (string)gzencode('TILE-C');
file_put_contents($tmp . '/data.tiles', $tileA . $tileB . $tileC);
$plan = [
    'url' => 'http://127.0.0.1/x', 'proxy' => null,
    'bbox' => [20.0, 52.0, 21.0, 53.0], 'maxzoom' => 2,
    'tileType' => PMTILES_TYPE_MVT, 'tileComp' => PMTILES_COMP_GZIP,
    'outMaxZoom' => 2, 'meta' => base64_encode('{"name":"t"}'),
    'entries' => [
        [pmtiles_tile_id(1, 1, 0), 0, strlen($tileA)],
        [pmtiles_tile_id(1, 0, 0), strlen($tileA), strlen($tileB)],
        [0, strlen($tileA) + strlen($tileB), strlen($tileC)],
    ],
    'spans' => [[0, strlen($tileA) + strlen($tileB) + strlen($tileC)]],
    'expected' => 1,
];
$dest = $tmp . '/out.pmtiles';
T::ok('assemble writes', pmtiles_assemble($plan, $tmp . '/data.tiles', $dest) === $dest);
T::ok('assembled archive verifies', pmtiles_verify_path($dest));
if (is_file($dest)) {
    $raw = (string)file_get_contents($dest);
    $hdr = pmtiles_parse_header(substr($raw, 0, 127));
    $okHdr = $hdr !== null && $hdr['maxZoom'] === 2 && $hdr['nEntries'] === 3
        && $hdr['minZoom'] === 0
        && abs($hdr['minLon'] - 20.0) < 1e-6 && abs($hdr['maxLat'] - 53.0) < 1e-6;
    T::ok('assembled header carries plan', $okHdr);
    if ($hdr !== null) {
        $root = pmtiles_parse_dir(substr($raw, $hdr['rootOff'], $hdr['rootLen']), $hdr['intComp']);
        $hit = $root !== null ? pmtiles_find_entry($root, pmtiles_tile_id(1, 0, 0)) : null;
        $bytes = ($root !== null && $hit !== null)
            ? substr($raw, $hdr['tileOff'] + $hit['off'], $hit['len']) : null;
        T::ok('assembled tile bytes exact', $bytes === $tileB);
    }
}
@unlink($dest);
@unlink($tmp . '/data.tiles');
@rmdir($tmp);

// ── Verification refuses corrupt archives ───────────────────────────────────
$tmp3 = sys_get_temp_dir() . '/ddmgmt_pmtiles3_' . getmypid();
@mkdir($tmp3, 0700, true);
file_put_contents($tmp3 . '/garbage.pmtiles', str_repeat('x', 200));
T::ok('garbage fails verify', !pmtiles_verify_path($tmp3 . '/garbage.pmtiles'));
file_put_contents($tmp3 . '/short.pmtiles', "\x00");
T::ok('truncated fails verify', !pmtiles_verify_path($tmp3 . '/short.pmtiles'));
T::ok('missing fails verify', !pmtiles_verify_path($tmp3 . '/nope.pmtiles'));
// A valid archive with a corrupted first tile fails the magic check.
$tileA2 = (string)gzencode('A');
$tileB2 = (string)gzencode('B');
file_put_contents($tmp3 . '/d.tiles', $tileA2 . $tileB2);
$miniPlan = [
    'url' => 'http://127.0.0.1/x', 'proxy' => null,
    'bbox' => [0.0, 0.0, 1.0, 1.0], 'maxzoom' => 1,
    'tileType' => PMTILES_TYPE_MVT, 'tileComp' => PMTILES_COMP_GZIP,
    'outMaxZoom' => 1, 'meta' => base64_encode('{}'),
    'entries' => [[0, 0, strlen($tileA2)], [1, strlen($tileA2), strlen($tileB2)]],
    'spans' => [[0, strlen($tileA2) + strlen($tileB2)]],
    'expected' => 10,
];
$mini = $tmp3 . '/mini.pmtiles';
T::ok('mini assembles', pmtiles_assemble($miniPlan, $tmp3 . '/d.tiles', $mini) === $mini);
T::ok('mini verifies', pmtiles_verify_path($mini));
$corrupt = (string)file_get_contents($mini);
$hdrMini = pmtiles_parse_header(substr($corrupt, 0, 127));
if ($hdrMini !== null) {
    $corrupt[$hdrMini['tileOff']] = "\x00";
    file_put_contents($tmp3 . '/corrupt.pmtiles', $corrupt);
    T::ok('bad tile magic fails verify', !pmtiles_verify_path($tmp3 . '/corrupt.pmtiles'));
    // Truncated mid-tiles fails the section-length check.
    file_put_contents($tmp3 . '/cut.pmtiles', substr($corrupt, 0, $hdrMini['tileOff'] + 5));
    T::ok('cut archive fails verify', !pmtiles_verify_path($tmp3 . '/cut.pmtiles'));
}
foreach (glob($tmp3 . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir($tmp3);

// ── Assembler folds duplicate source tiles into run-length entries ────────
$tmp4 = sys_get_temp_dir() . '/ddmgmt_pmtiles4_' . getmypid();
@mkdir($tmp4, 0700, true);
$dupA = (string)gzencode('DUP');
$dupOther = (string)gzencode('OTHER');
file_put_contents($tmp4 . '/r.tiles', $dupA . $dupOther);
$runPlan = [
    'url' => 'http://127.0.0.1/x', 'proxy' => null,
    'bbox' => [0.0, 0.0, 1.0, 1.0], 'maxzoom' => 1,
    'tileType' => PMTILES_TYPE_MVT, 'tileComp' => PMTILES_COMP_GZIP,
    'outMaxZoom' => 1, 'meta' => base64_encode('{}'),
    // ids 5+6 share one source copy; id 7 has its own
    'entries' => [[5, 0, strlen($dupA)], [6, 0, strlen($dupA)], [7, strlen($dupA), strlen($dupOther)]],
    'spans' => [[0, strlen($dupA) + strlen($dupOther)]],
    'expected' => 10,
];
$runOut = $tmp4 . '/run.pmtiles';
T::ok('duplicate tiles assemble', pmtiles_assemble($runPlan, $tmp4 . '/r.tiles', $runOut) === $runOut);
T::ok('run archive verifies', pmtiles_verify_path($runOut));
$runRaw = (string)file_get_contents($runOut);
$runHdr = pmtiles_parse_header(substr($runRaw, 0, 127));
T::ok('run header parses', $runHdr !== null);
if ($runHdr !== null) {
    $runRoot = pmtiles_parse_dir(substr($runRaw, $runHdr['rootOff'], $runHdr['rootLen']), $runHdr['intComp']);
    T::eq('duplicates fold to two directory rows', 2, $runRoot === null ? -1 : count($runRoot));
    if (is_array($runRoot) && count($runRoot) === 2) {
        T::eq('folded row is a run of 2', 2, $runRoot[0]['run']);
        T::eq('mid-run tile resolves to the shared copy', $runRoot[0],
            pmtiles_lookup_id($runRoot, static fn(): ?array => null, 6));
        T::eq('addressed count covers every tile', 3, $runHdr['nAddr']);
    }
    // One stored copy: file holds dupA once, not twice.
    T::eq('shared bytes stored once', 127 + $runHdr['rootLen'] + strlen('{}') + strlen($dupA) + strlen($dupOther),
        filesize($runOut));
}
foreach (glob($tmp4 . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir($tmp4);

// ── Zero-length directory entries are refused at verify ───────────────────
// A loosened bound would accept a tile that occupies no bytes.
$tmp5 = sys_get_temp_dir() . '/ddmgmt_pmtiles5_' . getmypid();
@mkdir($tmp5, 0700, true);
$tileE1 = (string)gzencode('E1');
$tileE3 = (string)gzencode('E3');
file_put_contents($tmp5 . '/e.tiles', $tileE1 . $tileE3);
$emptyEntryPlan = [
    'url' => 'http://127.0.0.1/x', 'proxy' => null,
    'bbox' => [0.0, 0.0, 1.0, 1.0], 'maxzoom' => 1,
    'tileType' => PMTILES_TYPE_MVT, 'tileComp' => PMTILES_COMP_GZIP,
    'outMaxZoom' => 1, 'meta' => base64_encode('{}'),
    // id 1 occupies no bytes; id 2's real gzip bytes sit exactly where id 1
    // points, so only the entry-bounds check can refuse it (the magic probe
    // reads valid gzip either way).
    'entries' => [[0, 0, strlen($tileE1)], [1, strlen($tileE1), 0], [2, strlen($tileE1), strlen($tileE3)]],
    'spans' => [[0, strlen($tileE1) + strlen($tileE3)]],
    'expected' => 10,
];
$emptyArch = $tmp5 . '/empty-entry.pmtiles';
T::ok('zero-length entry assembles', pmtiles_assemble($emptyEntryPlan, $tmp5 . '/e.tiles', $emptyArch) === $emptyArch);
T::ok('zero-length entry fails verify', !pmtiles_verify_path($emptyArch));

// ── Span search misses below the first span ─────────────────────────────────
// A source offset below every span resolves to null (no tile there); the
// binary search must still terminate — a hi bound that never shrinks loops
// forever here instead.
$gapPlan = $emptyEntryPlan;
$gapPlan['entries'] = [[0, 0, 1]];
$gapPlan['spans'] = [[10, 14], [30, 34]];
file_put_contents($tmp5 . '/g.tiles', str_repeat('G', 34));
T::eq('below-span source resolves to null', null, pmtiles_assemble($gapPlan, $tmp5 . '/g.tiles', $tmp5 . '/gap.pmtiles'));
foreach (glob($tmp5 . '/*') ?: [] as $f) {
    @unlink($f);
}
@rmdir($tmp5);

// ── Plan validation fails closed on untrusted sidecar bytes ────────────────
$good = [
    'url' => 'http://127.0.0.1/x', 'proxy' => null,
    'bbox' => [20.0, 52.0, 21.0, 53.0], 'maxzoom' => 2,
    'tileType' => 1, 'tileComp' => 2, 'outMaxZoom' => 2,
    'meta' => base64_encode('{}'),
    'entries' => [[4, 0, 10]], 'spans' => [[0, 10]], 'expected' => 999,
];
T::ok('good plan validates', pmtiles_plan_validate($good) !== null);
$badPlans = [
    'not an array' => 'junk',
    'empty url' => array_merge($good, ['url' => '']),
    'bad proxy' => array_merge($good, ['proxy' => 42]),
    'short bbox' => array_merge($good, ['bbox' => [1.0, 2.0]]),
    'string bbox' => array_merge($good, ['bbox' => ['a', 'b', 'c', 'd']]),
    'string maxzoom' => array_merge($good, ['maxzoom' => '2']),
    'zoom out of range' => array_merge($good, ['maxzoom' => 99]),
    'no expected' => array_merge($good, ['expected' => 0]),
    'no meta' => array_merge($good, ['meta' => null]),
    'no entries' => array_merge($good, ['entries' => []]),
    'ragged entry' => array_merge($good, ['entries' => [[4, 0]]]),
    'negative entry' => array_merge($good, ['entries' => [[4, -1, 10]]]),
    'empty entry' => array_merge($good, ['entries' => [[4, 0, 0]]]),
    'no spans' => array_merge($good, ['spans' => []]),
    'inverted span' => array_merge($good, ['spans' => [[10, 5]]]),
    'string span' => array_merge($good, ['spans' => [['a', 'b']]]),
];
foreach ($badPlans as $name => $p) {
    T::ok("plan rejects: $name", pmtiles_plan_validate($p) === null);
}
T::ok('plan load rejects garbage file', pmtiles_plan_load($good['url']) === null);

// ── Assembler refuses unlocatable entries ───────────────────────────────────
$tmp2 = sys_get_temp_dir() . '/ddmgmt_pmtiles2_' . getmypid();
@mkdir($tmp2, 0700, true);
file_put_contents($tmp2 . '/d.tiles', '0123456789');
$badPlan = $good;
$badPlan['entries'] = [[4, 0, 5], [5, 999999, 5]]; // second past every span
$badPlan['spans'] = [[0, 10]];
T::ok('assemble null on missing span', pmtiles_assemble($badPlan, $tmp2 . '/d.tiles', $tmp2 . '/o.pmtiles') === null);
T::ok('nothing published on failure', !is_file($tmp2 . '/o.pmtiles'));
@unlink($tmp2 . '/d.tiles');
@rmdir($tmp2);

// ── Range client argument guards (no network touched) ───────────────────────
T::eq('zero length short-circuits', ['', ''], pmtiles_http_range('http://127.0.0.1:9/x', 0, 0, null));
[$body, $err] = pmtiles_http_range('http://127.0.0.1:9/x', -1, 10, null);
T::ok('negative offset fails', $body === null && $err !== '');
T::eq('refused host fails as data, never throws',
    [null, 'request failed'], pmtiles_range_stream('http://127.0.0.1:9/x', 0, 10, null, 5));

// ── Range body classification (pure — the transports only fetch) ──────────
T::eq('exact 206 carries the body', ['0123456789', ''], pmtiles_classify_range(206, '0123456789', 0, 10));
T::eq('short 206 names itself', [null, 'short range body'], pmtiles_classify_range(206, '01234', 0, 10));
T::eq('200 to offset 0 keeps the head', ['01234', ''], pmtiles_classify_range(200, '0123456789EXTRA', 0, 5));
T::eq('short 200 names itself', [null, 'short body'], pmtiles_classify_range(200, '01', 0, 5));
T::eq('200 past offset 0 is not a range', [null, 'HTTP 200'], pmtiles_classify_range(200, '0123456789', 100, 10));
T::eq('other statuses name themselves', [null, 'HTTP 404'], pmtiles_classify_range(404, 'nope', 0, 10));

// ── Root-directory size gate (exact boundary — the spec fits header + root
// in the first 16 KiB, so the cap itself is still a legal archive) ───────
T::ok('zero root length rejected', !pmtiles_root_len_ok(0));
T::ok('unit root length accepted', pmtiles_root_len_ok(1));
T::ok('cap itself accepted', pmtiles_root_len_ok(PMTILES_ROOT_MAX));
T::ok('past the cap rejected', !pmtiles_root_len_ok(PMTILES_ROOT_MAX + 1));

// ── Leaf sidecar round-trip (span cap guards the decode, not honest data) ─
$leavesTmp = sys_get_temp_dir() . '/ddmgmt_leaves_' . getmypid() . '.json';
T::ok('leaves save', pmtiles_leaves_save($leavesTmp, 'http://example.com/p.pmtiles', ['0:10' => '0123456789']));
$loaded = pmtiles_leaves_load($leavesTmp);
T::eq('leaves load keeps the url', 'http://example.com/p.pmtiles', $loaded['url'] ?? null);
T::eq('honest leaves survive the cap', ['0:10' => '0123456789'], $loaded['leaves'] ?? null);
@unlink($leavesTmp);
T::eq('missing sidecar loads empty', ['url' => '', 'leaves' => []],
    pmtiles_leaves_load(sys_get_temp_dir() . '/ddmgmt_no_such_leaves.json'));

// ── Fetch accounting starts at zero: an empty plan is already done ────────
$emptyPlan = ['url' => 'http://127.0.0.1:9/p.pmtiles', 'proxy' => null, 'bbox' => [0.0, 0.0, 1.0, 1.0],
    'maxzoom' => 0, 'tileType' => 1, 'tileComp' => 2, 'outMaxZoom' => 0, 'meta' => '{}',
    'entries' => [], 'spans' => [], 'expected' => 0];
$fetchTmp = sys_get_temp_dir() . '/ddmgmt_fetch_' . getmypid() . '.tiles';
@unlink($fetchTmp);
T::eq('empty plan fetches nothing', ['done', '', 0], pmtiles_fetch_due($emptyPlan, $fetchTmp, 5));
@unlink($fetchTmp);

// ── Plan validation rejects non-integer span bounds ───────────────────────
$spanPlan = ['url' => 'http://example.com/p.pmtiles', 'proxy' => null, 'bbox' => [0.0, 0.0, 1.0, 1.0],
    'maxzoom' => 5, 'tileType' => 1, 'tileComp' => 2, 'outMaxZoom' => 5, 'meta' => '{}',
    'entries' => [[7, 0, 10]], 'spans' => [[0, 10]], 'expected' => 10];
T::ok('well-formed plan validates', pmtiles_plan_validate($spanPlan) !== null);
$floatSpan = $spanPlan;
$floatSpan['spans'] = [[0, 10.5]];
T::ok('float span bound rejected', pmtiles_plan_validate($floatSpan) === null);
$backSpan = $spanPlan;
$backSpan['spans'] = [[10, 10]];
T::ok('empty span rejected', pmtiles_plan_validate($backSpan) === null);

// ── Proxy usability matrix ──────────────────────────────────────────────────
T::ok('direct always usable', pmtiles_proxy_usable(null));
T::ok('http proxy usable', pmtiles_proxy_usable('http://127.0.0.1:8080'));
T::ok('https proxy usable', pmtiles_proxy_usable('https://127.0.0.1:8080'));
T::ok('socks usable curl-less', pmtiles_proxy_usable('socks5://127.0.0.1:1080'));
T::ok('socks5h usable curl-less', pmtiles_proxy_usable('socks5h://127.0.0.1:1080'));
T::ok('garbage proxy unusable', !pmtiles_proxy_usable('bogus://x'));

// ── Range lookup through leaf levels ─────────────────────────────────────────
$leaf = [
    ['id' => 10, 'run' => 1, 'len' => 5, 'off' => 100],
    ['id' => 11, 'run' => 1, 'len' => 5, 'off' => 105],
];
$mixedRoot = [
    ['id' => 5, 'run' => 1, 'len' => 5, 'off' => 50],
    ['id' => 10, 'run' => 0, 'len' => 20, 'off' => 200],
    ['id' => 25, 'run' => 1, 'len' => 5, 'off' => 300],
];
$fetch = static fn(int $off, int $len): ?array => ($off === 200 && $len === 20) ? $leaf : null;
T::eq('lookup data hit', $mixedRoot[0], pmtiles_lookup_id($mixedRoot, $fetch, 5));
T::ok('lookup below data misses', pmtiles_lookup_id($mixedRoot, $fetch, 7) === null);
T::eq('lookup leaf start descends', $leaf[0], pmtiles_lookup_id($mixedRoot, $fetch, 10));
T::eq('lookup in leaf range descends', $leaf[1], pmtiles_lookup_id($mixedRoot, $fetch, 11));
T::ok('lookup hole in leaf misses', pmtiles_lookup_id($mixedRoot, $fetch, 12) === null);
T::ok('lookup past leaf misses', pmtiles_lookup_id($mixedRoot, $fetch, 24) === null);
T::eq('lookup later data hit', $mixedRoot[2], pmtiles_lookup_id($mixedRoot, $fetch, 25));
T::ok('lookup past end misses', pmtiles_lookup_id($mixedRoot, $fetch, 99) === null);
T::ok('lookup before start misses', pmtiles_lookup_id($mixedRoot, $fetch, 4) === null);
T::ok('lookup corrupt leaf fails', pmtiles_lookup_id($mixedRoot, static fn(): ?array => null, 11) === null);
// Run-length entries (identical tiles, e.g. open sea) cover id..id+run-1:
// every tile inside the run must resolve, not just the first id.
$runRoot = [
    ['id' => 5, 'run' => 3, 'len' => 5, 'off' => 50],
];
T::eq('lookup run first id hits', $runRoot[0], pmtiles_lookup_id($runRoot, $fetch, 5));
T::eq('lookup inside run hits', $runRoot[0], pmtiles_lookup_id($runRoot, $fetch, 6));
T::eq('lookup run last id hits', $runRoot[0], pmtiles_lookup_id($runRoot, $fetch, 7));
T::ok('lookup past run misses', pmtiles_lookup_id($runRoot, $fetch, 8) === null);

// Hostile-upstream bounds: an absurd entry count or a gzip bomb fails
// closed instead of exhausting memory.
T::ok('directory claiming too many entries fails closed',
      pmtiles_parse_dir(pmtiles_vint_encode(PMTILES_DIR_ENTRIES_MAX + 1), PMTILES_COMP_NONE) === null);
$bomb = gzencode(str_repeat("\0", PMTILES_DIR_INFLATED_MAX + 1), 9);
T::ok('gzip bomb directory fails closed', pmtiles_parse_dir((string)$bomb, PMTILES_COMP_GZIP) === null);
unset($bomb);

// A directory whose offset section is truncated fails closed: the missing
// vint is corruption, not a zero offset (a weakened arm would file entries
// at negative offsets and poison the span map).
$truncEntries = [
    ['id' => 0, 'len' => 10, 'off' => 100],
    ['id' => 4, 'len' => 20, 'off' => 110],
];
$truncInflated = @gzdecode(pmtiles_dir_encode($truncEntries));
$truncCut = is_string($truncInflated) ? gzencode(substr($truncInflated, 0, -1), 9) : false;
T::ok('directory with truncated offsets fails closed',
    $truncCut !== false && pmtiles_parse_dir($truncCut, PMTILES_COMP_GZIP) === null);

// ── Single-tile archive over a local stub: planner sizing contract ────────
// A hand-built one-entry archive (header + gzip root + tile bytes) served
// by php -S, whose static handler honors Range natively.
$arcTile = 'TILEBYTES!';
$arcLen = strlen($arcTile);
$arcRootRaw = pmtiles_dir_encode([['id' => 0, 'run' => 1, 'len' => $arcLen, 'off' => 0]]);
$arcTileOff = PMTILES_HEADER_LEN + strlen($arcRootRaw);
$arcHdr = PMTILES_MAGIC . chr(PMTILES_VERSION)
    . pmtiles_u64le(PMTILES_HEADER_LEN) . pmtiles_u64le(strlen($arcRootRaw))
    . pmtiles_u64le($arcTileOff) . pmtiles_u64le(0)
    . pmtiles_u64le(0) . pmtiles_u64le(0)
    . pmtiles_u64le($arcTileOff) . pmtiles_u64le($arcLen)
    . pmtiles_u64le(1) . pmtiles_u64le(1) . pmtiles_u64le($arcLen)
    . chr(1) . chr(PMTILES_COMP_GZIP) . chr(1) . chr(PMTILES_TYPE_MVT)
    . chr(0) . chr(0)
    . pmtiles_i32le(-1800000000) . pmtiles_i32le(-850000000)
    . pmtiles_i32le(1800000000) . pmtiles_i32le(850000000)
    . chr(0) . pmtiles_i32le(0) . pmtiles_i32le(0);
$arcDir = sys_get_temp_dir() . '/ddmgmt-arc-' . getmypid();
@mkdir($arcDir);
file_put_contents($arcDir . '/one.pmtiles', $arcHdr . $arcRootRaw . $arcTile);
// php -S ignores Range for static files, so a tiny router answers slices
// with 206 itself (same pattern as MapsPhpTest's planet stub).
$arcRouter = $arcDir . '/router.php';
file_put_contents($arcRouter, <<<'PHP'
<?php
$p = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($p === '/one.pmtiles') {
    $body = (string)file_get_contents(__DIR__ . '/one.pmtiles');
    $range = $_SERVER['HTTP_RANGE'] ?? '';
    if (preg_match('/bytes=(\d+)-(\d*)/', $range, $m)) {
        $start = (int)$m[1];
        $end = $m[2] === '' ? strlen($body) - 1 : min((int)$m[2], strlen($body) - 1);
        if ($start >= strlen($body)) {
            http_response_code(416);
            return true;
        }
        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . strlen($body));
        header('Content-Length: ' . ($end - $start + 1));
        echo substr($body, $start, $end - $start + 1);
        return true;
    }
    header('Content-Length: ' . strlen($body));
    echo $body;
    return true;
}
http_response_code(404);
echo 'not found';
return true;
PHP);
T::eq('hand-built header is exactly 127 bytes', PMTILES_HEADER_LEN, strlen($arcHdr));
$arcPort = 0;
$arcProc = null;
$arcNull = DIRECTORY_SEPARATOR === '\\' ? 'NUL' : '/dev/null';
for ($t = 0; $t < 10 && $arcPort === 0; $t++) {
    $cand = 27437 + ((getmypid() + $t * 131) % 200);
    $probeSock = @fsockopen('127.0.0.1', $cand, $errno, $errstr, 0.2);
    if (is_resource($probeSock)) {
        fclose($probeSock);
        continue;
    }
    $try = proc_open(t_exec_cmd(escapeshellarg(PHP_BINARY) . " -S 127.0.0.1:$cand " . escapeshellarg($arcRouter)),
        [['pipe', 'r'], ['file', $arcNull, 'w'], ['file', $arcNull, 'w']], $pipes);
    if (!is_resource($try)) {
        continue;
    }
    $ready = false;
    for ($i = 0; $i < 15; $i++) {
        $ctx = stream_context_create(['http' => ['timeout' => 2]]);
        $got = @file_get_contents("http://127.0.0.1:$cand/one.pmtiles", false, $ctx, 0, 8);
        if ($got === PMTILES_MAGIC . chr(PMTILES_VERSION)) {
            $ready = true;
            break;
        }
        usleep(50000);
    }
    if ($ready) {
        $arcPort = $cand;
        $arcProc = $try;
    } else {
        if (!empty(proc_get_status($try)['running'])) {
            if (DIRECTORY_SEPARATOR === '\\') {
                exec('taskkill /F /T /PID ' . (int)proc_get_status($try)['pid'] . ' >NUL 2>&1');
            } else {
                proc_terminate($try);
            }
        }
        proc_close($try);
    }
}
if ($arcPort === 0) {
    T::ok('stub server unavailable here — planner sizing skipped', true);
} else {
    register_shutdown_function(static function () use ($arcProc, $arcDir): void {
        if (is_resource($arcProc) && !empty(proc_get_status($arcProc)['running'])) {
            if (DIRECTORY_SEPARATOR === '\\') {
                exec('taskkill /F /T /PID ' . (int)proc_get_status($arcProc)['pid'] . ' >NUL 2>&1');
            } else {
                proc_terminate($arcProc);
            }
        }
        if (is_resource($arcProc)) {
            proc_close($arcProc);
        }
        @unlink($arcDir . '/router.php');
        @unlink($arcDir . '/one.pmtiles');
        @rmdir($arcDir);
    });
    $arcUrl = "http://127.0.0.1:$arcPort/one.pmtiles";
    [$arcPlan, $arcErr] = pmtiles_build_plan($arcUrl, null, -180.0, -85.0, 180.0, 85.0, 0);
    T::eq('single-tile plan builds', '', $arcErr);
    T::ok('...with a plan', $arcPlan !== null);
    if (is_array($arcPlan)) {
        // Sizing is exact: header + 8 bytes per entry + the fixed directory
        // allowance + metadata + tile bytes (a moved constant here would
        // under-reserve the disk and wedge mid-extract).
        $arcData = 0;
        foreach ($arcPlan['entries'] as $en) {
            $arcData += $en[2];
        }
        T::eq('plan sizing is exact',
            PMTILES_HEADER_LEN + count($arcPlan['entries']) * 8 + 256
                + strlen((string)base64_decode((string)$arcPlan['meta'])) + $arcData,
            $arcPlan['expected'] ?? null);
        // An expired deadline aborts the walk before the first entry, never
        // after resolving it (a weakened check would fetch on a dead budget).
        [$tPlan, $tErr] = pmtiles_build_plan($arcUrl, null, -180.0, -85.0, 180.0, 85.0, 0,
            60, [], microtime(true) - 1.0);
        T::eq('expired deadline times out', 'sizing timed out', $tErr);
        T::ok('...with no plan', $tPlan === null);
    }
}

exit(T::done());
