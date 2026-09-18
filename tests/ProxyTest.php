<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

// ── Proxy anonymity gate ──────────────────────────────────────────────────────
// proxy_filter_anonymity() is the single decision point that decides which
// working proxies may carry OSM traffic. It used to be inline in the discovery
// routine, where an array-vs-false comparison made the whole anonymity round
// silently never run (found by PHPStan, not by tests — this suite exists so
// the next such bug needs two mistakes, not zero).

// Shape helpers matching the discovery routine's data structures.
$mkWorking = static fn(string $url, int $ms = 100): array => [
    ['url' => $url, 'latency_ms' => $ms, 'source' => 'test'],
];
// candidates: url => ['rated' => bool, 'source' => string]
$cRated   = static fn(): array => ['rated' => true,  'source' => 'curated'];
$cUnrated = static fn(): array => ['rated' => false, 'source' => 'public-list'];

$httpUnrated = 'http://unrated.example:8080';
$httpRated   = 'http://rated.example:8080';
$httpsUnrated = 'https://unrated.example:8443';

// 1 ── Rated proxies always pass, regardless of judge outcomes.
$working  = $mkWorking($httpRated);
$cands    = [$httpRated => $cRated()];
T::eq('rated HTTP proxy kept (judge reachable, anonymous)', 1,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpRated => false])));

// 2 ── HTTPS proxies are opaque to the filter chain — kept even unrated+unjudged.
$working  = $mkWorking($httpsUnrated);
$cands    = [$httpsUnrated => $cUnrated()];
T::eq('unrated HTTPS proxy kept without judging', 1,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [])));

// 3 ── Unrated HTTP: kept only when the judge says anonymous.
$working = $mkWorking($httpUnrated);
$cands   = [$httpUnrated => $cUnrated()];
T::eq('unrated HTTP proxy judged anonymous → kept', 1,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpUnrated => true])));
T::eq('unrated HTTP proxy judged leaking → dropped', 0,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpUnrated => false])));
T::eq('unrated HTTP proxy never judged → dropped', 0,
    count(proxy_filter_anonymity($working, $cands, '203.0.113.9', [])));
// Fail-closed default: a working entry with NO candidate record at all
// (missing key, not rated:false) and no judge verdict must be dropped.
// (With a positive verdict it is kept per the judged-anonymous row above.)
T::eq('proxy missing from candidates, unjustified → dropped', 0,
    count(proxy_filter_anonymity($working, [], '203.0.113.9', [])));

// 4 ── Judge unreachable (no public IP): EVERY unrated HTTP proxy is dropped —
// fail closed is the whole point of the round. Rated and HTTPS survive.
$working = array_merge(
    $mkWorking($httpUnrated),
    $mkWorking($httpRated),
    $mkWorking($httpsUnrated)
);
$cands = [
    $httpUnrated  => $cUnrated(),
    $httpRated    => $cRated(),
    $httpsUnrated => $cUnrated(),
];
$kept = proxy_filter_anonymity($working, $cands, null, []);
T::eq('no public IP: unrated HTTP dropped, everything else kept', 2, count($kept));
T::ok('survivors are exactly rated + https',
    !in_array($httpUnrated, array_column($kept, 'url'), true));

// 5 ── Mixed pool keeps order-independent correctness and latency sort input.
$working = array_merge(
    $mkWorking($httpUnrated, 50),
    $mkWorking($httpsUnrated, 30),
    $mkWorking($httpRated, 40)
);
$cands = [
    $httpUnrated  => $cUnrated(),
    $httpsUnrated => $cUnrated(),
    $httpRated    => $cRated(),
];
$kept = proxy_filter_anonymity($working, $cands, '203.0.113.9', [$httpUnrated => true]);
T::eq('mixed pool: all three survive with positive verdicts', 3, count($kept));
$kept = proxy_filter_anonymity($working, $cands, '203.0.113.9', []);
T::eq('mixed pool: only rated + https survive without verdicts', 2, count($kept));

// ── Reverse-geocode place labels (lat/lng hidden from owners by policy) ───
T::eq('country + state join', 'Poland, Masovian Voivodeship',
    osm_place_label(['country' => 'Poland', 'state' => 'Masovian Voivodeship', 'city' => 'Warsaw']));
T::eq('country alone when no state', 'Poland', osm_place_label(['country' => 'Poland']));
T::eq('state alone when no country', 'Mazowieckie', osm_place_label(['state' => 'Mazowieckie']));
T::eq('nothing known is empty', '', osm_place_label(['city' => 'Nowhere']));
T::eq('non-array is empty', '', osm_place_label(null));
T::eq('blank parts ignored', 'Poland', osm_place_label(['country' => ' Poland ', 'state' => '  ']));

// Reverse URL builder (pure half of the lookup — the fetch itself must never
// run in unit suites).
T::eq('valid point builds the reverse URL',
    'https://nominatim.openstreetmap.org/reverse?lat=52.2297&lon=21.0122&format=json&accept-language=en',
    osm_reverse_url(52.2297, 21.0122));
T::eq('latitude out of range is null', null, osm_reverse_url(91.0, 21.0));
T::eq('longitude out of range is null', null, osm_reverse_url(52.0, 181.0));
T::eq('non-finite is null', null, osm_reverse_url(NAN, 21.0));
T::ok('lookup rejects geography without network', osm_reverse_lookup(91.0, 21.0) === null);

// Reverse answer decoding (pure — no network in any arm).
T::eq('parse keeps the address', ['country' => 'Poland', 'state' => 'X'],
    osm_reverse_parse('{"address":{"country":"Poland","state":"X"}}'));
T::eq('parse without address is null', null, osm_reverse_parse('{"error":"nope"}'));
T::eq('parse garbage is null', null, osm_reverse_parse('not json'));

// Fail-closed lookup: routing enabled with an empty pool answers null
// without touching the network (covers the fetch-failed arm). Pool and
// setting restored below — later suites inherit sanity.
$db = get_db();
$prevProxies = $db->query('SELECT url, source, last_status, latency_ms, last_checked FROM osm_proxies')->fetchAll();
$prevRouting = get_setting('osm_proxy_enabled', '0');
set_setting('osm_proxy_enabled', '1');
$db->prepare('DELETE FROM osm_proxies')->execute();
T::ok('lookup fails closed on empty pool', osm_reverse_lookup(52.2297, 21.0122) === null);
$db->prepare('DELETE FROM osm_proxies')->execute();
$pxIns = $db->prepare(
    'INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
     VALUES (?, ?, ?, ?, ?)'
);
foreach ($prevProxies as $px) {
    $pxIns->execute([$px['url'], $px['source'], $px['last_status'], $px['latency_ms'], $px['last_checked']]);
}
set_setting('osm_proxy_enabled', $prevRouting);

exit(T::done());
