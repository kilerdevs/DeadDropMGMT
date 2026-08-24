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

exit(T::done());
