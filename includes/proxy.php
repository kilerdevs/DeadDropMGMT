<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/settings.php';

// ── Outbound proxy pool for OpenStreetMap requests ────────────────────────────
// The admin panel's tile/geocode proxies normally talk to OSM from the
// server's own IP. Owners who want to keep even that metadata away from
// OSM can maintain a pool of HTTP(S) proxies here and enable routing.
//
// Design notes:
// - Fail-closed: when routing is enabled but every proxy fails, the request
//   fails (HTTP 502 to the admin browser) instead of silently leaking the
//   server's real IP to OSM.
// - Proxy health is tracked per URL so dead entries are visible in settings.
// - Discovery pulls candidate lists from Proxifly's free-proxy-list (GitHub,
//   MIT-licensed, regularly refreshed) — see proxy_discover().

function osm_proxy_pool(): array {
    try {
        $stmt = get_db()->query(
            'SELECT id, url, label, source, last_status, latency_ms, last_checked
             FROM osm_proxies ORDER BY created_at ASC'
        );
        return $stmt->fetchAll();
    } catch (Exception $e) {
        log_err('Proxy pool load: ' . $e->getMessage());
        return [];
    }
}

// Normalize user input into a proxy URL cURL accepts (http://host:port).
// Accepts "host:port", "http://host:port", "https://host:port" and optional
// "user:pass@" credentials. Returns null when the input is not usable.
function osm_proxy_normalize(string $raw): ?string {
    $raw = trim($raw);
    if ($raw === '' || strlen($raw) > 255) return null;
    if (!str_contains($raw, '://')) {
        $raw = 'http://' . $raw;
    }
    $p = parse_url($raw);
    if (!$p || empty($p['host']) || empty($p['port'])) return null;
    if (!filter_var($p['host'], FILTER_VALIDATE_IP) && !filter_var($p['host'], FILTER_VALIDATE_DOMAIN)) return null;
    $port = filter_var($p['port'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
    if ($port === false) return null;
    if (!in_array($p['scheme'] ?? 'http', ['http', 'https', 'socks4', 'socks5'], true)) return null;

    $url = $p['scheme'] . '://';
    if (!empty($p['user'])) {
        $url .= rawurlencode($p['user']);
        if (isset($p['pass'])) $url .= ':' . rawurlencode($p['pass']);
        $url .= '@';
    }
    $url .= strtolower($p['host']) . ':' . $port;
    return $url;
}

// One GET through a specific proxy (or direct when $proxy is null).
// Returns body on HTTP 200, false otherwise. Never throws.
function osm_fetch_via(string $url, ?string $proxy, int $timeout = 5): string|false {
    if (!function_exists('curl_init')) {
        // No cURL on this host — fall back to direct stream fetch only.
        if ($proxy !== null) return false;
        $ctx = stream_context_create(['http' => [
            'method'  => 'GET',
            'header'  => "User-Agent: DeadDropMGMT/1.0\r\n",
            'timeout' => $timeout,
            'ignore_errors' => false,
        ]]);
        return @file_get_contents($url, false, $ctx);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    if ($proxy !== null) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }

    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    return ($code >= 200 && $code < 300 && is_string($body)) ? $body : false;
}

function osm_proxy_mark(int $id, bool $ok, ?int $latency_ms = null): void {
    try {
        get_db()->prepare(
            'UPDATE osm_proxies
             SET last_status = ?, latency_ms = ?, last_checked = NOW()
             WHERE id = ?'
        )->execute([$ok ? 'ok' : 'fail', $latency_ms, $id]);
    } catch (Exception $e) {
        log_err('Proxy mark: ' . $e->getMessage());
    }
}

// Fetch an OSM resource honouring the osm_proxy_enabled setting. Tries each
// pool member fastest-first; gives up (returns false) if all fail while
// routing is enabled — that is the point of fail-closed.
//
// Session note: this function never touches $_SESSION directly. The caller
// is expected to session_write_close() before invoking it (so a slow proxy
// chain doesn't lock out every other admin page) and then call
// osm_last_via_flush() afterwards, which re-opens the session just long
// enough to record what happened for the admin badge.
//
// Bail-outs between attempts: an overall wall-clock budget (a big pool
// must not churn for minutes) and a client-disconnect check, so a user who
// navigated away stops generating further proxy attempts.
function osm_fetch(string $url): string|false {
    if (!osm_proxy_enabled()) {
        return osm_fetch_via($url, null);
    }

    $pool = osm_proxy_pool();
    if (!$pool) {
        osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => 0, 'skipped' => []]);
        return false; // enabled with an empty pool would mean going direct = leak
    }

    // Try the fastest known-good proxy first: working ones ordered by last
    // measured latency, then untested, then previously-dead as last resort.
    // Each attempt gets 3 seconds before moving on to the next candidate.
    usort($pool, function ($a, $b) {
        $rank = function ($p) {
            return match ($p['last_status'] ?? '') {
                'ok'   => 0,
                'new'  => 1,
                default => 2,
            };
        };
        $ra = $rank($a);
        if ($ra !== ($rb = $rank($b))) return $ra <=> $rb;
        return ((int)($a['latency_ms'] ?? PHP_INT_MAX)) <=> ((int)($b['latency_ms'] ?? PHP_INT_MAX));
    });

    $deadline = microtime(true) + 20.0; // whole-request budget across all attempts
    $attempts = 0;
    $skipped  = []; // proxies that timed out / failed before the winner
    foreach ($pool as $px) {
        if (microtime(true) >= $deadline || connection_aborted()) {
            break; // budget exhausted or client gone — stop burning the pool
        }
        $attempts++;
        $t0     = microtime(true);
        $result = osm_fetch_via($url, $px['url'], 3);
        $ms     = (int)round((microtime(true) - $t0) * 1000);
        osm_proxy_mark((int)$px['id'], $result !== false, $ms);
        if ($result !== false) {
            osm_last_via_set([
                'via'        => $px['url'],
                'latency_ms' => $ms,
                'failed'     => false,
                'attempts'   => $attempts,
                'skipped'    => $skipped,
            ]);
            return $result;
        }
        $skipped[] = $px['url'];
    }
    osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => $attempts, 'skipped' => $skipped]);
    return false;
}

// Shared storage for the staged badge info of the current request.
function osm_last_via_stage(?array $info = null): ?array {
    static $staged = null;
    if ($info !== null) {
        $staged = $info;
    }
    return $staged;
}

// Stash badge info for the current request; flushed to the session later by
// osm_last_via_flush() once the caller has released the session lock.
function osm_last_via_set(array $info): void {
    osm_last_via_stage($info);
}

// Write the staged badge info to the session. Safe to call even when the
// session was closed (or never started) — it re-opens the session briefly,
// writes, and closes again so locks are held only for milliseconds.
function osm_last_via_flush(): void {
    $staged = osm_last_via_stage();
    if ($staged === null) return;
    osm_last_via_stage(null); // consume
    if (session_status() !== PHP_SESSION_ACTIVE && !headers_sent()) {
        session_start();
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['osm_last_via'] = $staged;
        session_write_close();
    }
}

// ── Discovery ────────────────────────────────────────────────────────────────

// Sources of candidate proxies — all free, community-maintained, fetched
// from GitHub raw. 'rated' marks sources whose HTTP entries carry a real
// anonymity rating (anonymous/elite); HTTP entries from unrated sources are
// only accepted after passing a live anonymity check (see proxy_discover).
// SOCKS proxies are header-anonymous by protocol and always qualify.
const PROXY_DISCOVERY_SOURCES = [
    // rated JSON with anonymity metadata
    ['name' => 'proxifly',   'url' => 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json', 'type' => 'proxifly', 'rated' => true],
    // hourly pre-checked plain lists
    ['name' => 'monosans',   'url' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',    'type' => 'plain', 'proto' => 'http',   'rated' => false],
    ['name' => 'monosans',   'url' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt',  'type' => 'plain', 'proto' => 'socks4', 'rated' => true],
    ['name' => 'monosans',   'url' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',  'type' => 'plain', 'proto' => 'socks5', 'rated' => true],
    // high-volume lists
    ['name' => 'thespeedx',  'url' => 'https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/http.txt',   'type' => 'plain', 'proto' => 'http',   'rated' => false],
    ['name' => 'thespeedx',  'url' => 'https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/socks4.txt', 'type' => 'plain', 'proto' => 'socks4', 'rated' => true],
    ['name' => 'thespeedx',  'url' => 'https://raw.githubusercontent.com/TheSpeedX/PROXY-LIST/master/socks5.txt', 'type' => 'plain', 'proto' => 'socks5', 'rated' => true],
    // curated, regularly refreshed
    ['name' => 'roosterkid', 'url' => 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',  'type' => 'plain', 'proto' => 'http',   'rated' => false],
    ['name' => 'roosterkid', 'url' => 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt', 'type' => 'plain', 'proto' => 'socks5', 'rated' => true],
];

// Header-echo judge used to verify that an HTTP proxy does not leak our IP
// via Via / X-Forwarded-For style headers. Plain HTTP on purpose — it must
// work through proxies that lack CONNECT support.
const PROXY_ANONYMITY_JUDGES = [
    'http://httpbin.org/get',
    'http://azenv.net/',
];

// Learn this server's public IP so the judge response can be scanned for it.
function proxy_public_ip(): ?string {
    foreach (['https://api.ipify.org?format=text', 'http://httpbin.org/ip'] as $url) {
        $raw = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => 8]]));
        if ($raw === false) continue;
        if (preg_match('/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/', $raw, $m)) {
            return $m[1];
        }
    }
    return null;
}

// Run one anonymity judge through a proxy. Returns true when the judge's
// response does not contain our IP in any echoed header or origin field.
function proxy_judge_anonymous(string $pxUrl, string $ourIp, int $timeout_s = 6): bool {
    foreach (PROXY_ANONYMITY_JUDGES as $judge) {
        $body = osm_fetch_via($judge, $pxUrl, $timeout_s);
        if ($body === false) continue; // judge unreachable through this proxy — try next judge
        if (str_contains($body, $ourIp)) {
            return false; // our IP leaked into the request as seen by the target
        }
        return true;
    }
    return false; // could not verify — maximum security means reject
}

// Pull candidates from public sources, then probe them in parallel against a
// real OSM tile URL. Returns [['url' => ..., 'latency_ms' => ...], ...],
// sorted fastest first.
//
// Acceptance is security-first:
//   1. must answer an HTTPS OSM tile (proves CONNECT/socks tunneling works),
//   2. must be under 3000 ms — slower proxies are useless for a map UI,
//   3. HTTP proxies without a source anonymity rating must additionally pass
//      a live judge check proving our IP stays out of the request headers;
//      SOCKS is header-anonymous by protocol and rated lists are trusted.
function proxy_discover(int $max_test = 400, int $timeout_s = 4): array {
    $candidates = []; // url => ['rated' => bool, 'source' => list name]

    foreach (PROXY_DISCOVERY_SOURCES as $src) {
        $raw = @file_get_contents($src['url'], false, stream_context_create([
            'http' => ['timeout' => 10],
        ]));
        if ($raw === false) continue;

        $record = function (string $norm) use ($src, &$candidates): void {
            // first source wins, but a rated listing outranks an unrated one
            if (!isset($candidates[$norm])) {
                $candidates[$norm] = ['rated' => $src['rated'], 'source' => $src['name']];
            } elseif ($src['rated'] && !$candidates[$norm]['rated']) {
                $candidates[$norm]['rated'] = true;
                $candidates[$norm]['source'] = $src['name'];
            }
        };

        if ($src['type'] === 'proxifly') {
            $list = json_decode($raw, true);
            if (!is_array($list)) continue;
            foreach ($list as $entry) {
                if (!is_array($entry)) continue;
                $proto = strtolower((string)($entry['protocol'] ?? ''));
                if ($proto === '') continue;
                $anon = strtolower((string)($entry['anonymity'] ?? ''));
                if (!str_starts_with($proto, 'socks')
                    && !in_array($anon, ['anonymous', 'elite'], true)) {
                    continue;
                }
                $ip   = (string)($entry['ip'] ?? '');
                $port = (string)($entry['port'] ?? '');
                if ($ip === '' || $port === '') continue;
                $norm = osm_proxy_normalize("$proto://$ip:$port");
                if ($norm !== null) $record($norm);
            }
        } else {
            foreach (preg_split('/\r?\n/', trim($raw)) ?: [] as $line) {
                // plain lists are one ip:port per line, but tolerate stray
                // annotations by extracting the first ip:port on the line
                if (!preg_match('/\b(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})\b/', $line, $m)) continue;
                $norm = osm_proxy_normalize($src['proto'] . '://' . $m[1]);
                if ($norm !== null) $record($norm);
            }
        }
    }

    if (!$candidates) return [];
    $all = array_keys($candidates);
    shuffle($all); // lists are ordered; random slice spreads the load
    $toTest = array_slice($all, 0, $max_test);

    // Round 1: functional + latency probe against a real OSM tile.
    $probeUrl = 'https://a.tile.openstreetmap.org/13/4051/2749.png';
    $results  = proxy_multi_probe($toTest, $probeUrl, $timeout_s, $timeout_s);

    $working = [];
    foreach ($results as $pxUrl => [$code, $ms]) {
        if ($code >= 200 && $code < 300 && $ms < 3000) {
            $working[$pxUrl] = [
                'url'        => $pxUrl,
                'latency_ms' => $ms,
                'source'     => $candidates[$pxUrl]['source'],
            ];
        }
    }
    if (!$working) return [];

    // Round 2: live anonymity verification for unrated HTTP proxies.
    $unrated = array_values(array_filter($working, fn($p) => $candidates[$p['url']]['rated'] === false
        && str_starts_with($p['url'], 'http://')));
    if ($unrated) {
        $ourIp = proxy_public_ip();
        if ($ourIp === null) {
            // Cannot verify anonymity — maximum security means drop them all.
            $working = array_values(array_filter($working, fn($p) => $candidates[$p['url']]['rated'] !== false
                || !str_starts_with($p['url'], 'http://')));
        } else {
            $judged = [];
            foreach (array_chunk($unrated, 50) as $chunk) {
                $urls     = array_column($chunk, 'url');
                $judgeRes = proxy_multi_probe($urls, PROXY_ANONYMITY_JUDGES[0], $timeout_s, $timeout_s, false);
                foreach ($urls as $pxUrl) {
                    [$code, ] = $judgeRes[$pxUrl] ?? [0, 0];
                    $judged[$pxUrl] = $code >= 200 && $code < 300 && proxy_judge_anonymous($pxUrl, $ourIp);
                }
            }
            $working = array_values(array_filter($working, fn($p) =>
                $candidates[$p['url']]['rated'] !== false
                || !str_starts_with($p['url'], 'http://')
                || ($judged[$p['url']] ?? false)));
        }
    }

    usort($working, fn($a, $b) => $a['latency_ms'] <=> $b['latency_ms']);
    return $working;
}

// Run a batch of GETs through different proxies in parallel.
// Returns [proxyUrl => [httpCode, totalMs]]. $head controls HEAD vs GET.
function proxy_multi_probe(array $proxies, string $url, int $timeout_s, int $connect_s, bool $head = true): array {
    $mh = curl_multi_init();
    /** @var CurlHandle[] $handles */
    $handles = [];
    foreach ($proxies as $pxUrl) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROXY          => $pxUrl,
            CURLOPT_TIMEOUT        => $timeout_s,
            CURLOPT_CONNECTTIMEOUT => $connect_s,
            CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
            CURLOPT_NOBODY         => $head,
        ]);
        curl_multi_add_handle($mh, $ch);
        $handles[$pxUrl] = $ch;
    }

    do {
        $status = curl_multi_exec($mh, $active);
        if ($active) {
            curl_multi_select($mh, 0.2);
        }
    } while ($active && $status === CURLM_OK);

    $out = [];
    foreach ($handles as $pxUrl => $ch) {
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $ms   = (int)round((float)curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
        $out[$pxUrl] = [$code, $ms];
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);
    return $out;
}
