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
// Returns body on HTTP 200, false otherwise. Never throws. $maxBytes caps
// the response body on BOTH transports: curl aborts progressively via
// MAXFILESIZE, the stream fallback reads at most max+1 bytes and rejects
// over-long bodies — a reusable fetcher with no ceiling is a memory-DoS
// waiting for the next endpoint, proxy, or data source.
function osm_fetch_via(string $url, ?string $proxy, int $timeout = 5, int $maxBytes = 2097152): string|false {
    if (!function_exists('curl_init')) {
        // No cURL on this host — fall back to direct stream fetch only.
        if ($proxy !== null) return false;
        $ctx = stream_context_create(['http' => [
            'method'  => 'GET',
            'header'  => "User-Agent: DeadDropMGMT/1.0\r\n",
            'timeout' => $timeout,
            'ignore_errors' => false,
        ]]);
        $body = @file_get_contents($url, false, $ctx, 0, $maxBytes + 1);
        if (!is_string($body) || strlen($body) > $maxBytes) {
            return false;
        }
        return $body;
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_MAXFILESIZE    => $maxBytes,
        CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    if ($proxy !== null) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }

    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    unset($ch); // PHP 8.5 deprecates curl_close(); the handle frees on scope exit

    if ($code < 200 || $code >= 300 || !is_string($body) || strlen($body) > $maxBytes) {
        return false;
    }
    return $body;
}

// ── Tile cache upkeep ───────────────────────────────────────────────────────
// cache/osm_tiles/<z>/<x>/<y>.png is filled by tile_proxy.php on demand. Aged
// entries and everything beyond the byte cap are dropped (oldest first) by
// the hourly cleanup, so the cache cannot grow without bound however many
// distinct tiles an admin (or a runaway script) requests. Returns the number
// of files removed; never throws.
function osm_tile_cache_prune(?string $dir = null, int $maxBytes = 268435456, int $ttl = 604800): int {
    $dir = $dir ?? dirname(__DIR__) . '/cache/osm_tiles';
    if (!is_dir($dir)) {
        return 0;
    }
    $removed = 0;
    try {
        $files = [];
        $total = 0;
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        $now = time();
        foreach ($it as $f) {
            if ($f->isDir()) {
                @rmdir($f->getPathname()); // only succeeds when empty
                continue;
            }
            if ($f->isLink() || !$f->isFile()) {
                @unlink($f->getPathname());
                continue;
            }
            if (($now - $f->getMTime()) >= $ttl) {
                if (@unlink($f->getPathname())) {
                    $removed++;
                }
                continue;
            }
            $files[] = [$f->getMTime(), $f->getSize(), $f->getPathname()];
            $total += $f->getSize();
        }
        if ($total > $maxBytes) {
            usort($files, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
            foreach ($files as [, $size, $path]) {
                if ($total <= $maxBytes) {
                    break;
                }
                if (@unlink($path)) {
                    $total -= $size;
                    $removed++;
                }
            }
        }
    } catch (Throwable $e) {
        log_err('Tile cache prune: ' . $e->getMessage());
    }
    return $removed;
}

// A real PNG starts with the fixed 8-byte signature. Anything else that came
// back from a (possibly hostile, public) pool proxy is not a tile.
function osm_is_png(string $data): bool {
    return str_starts_with($data, "\x89PNG\r\n\x1a\n");
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

// ── Stale-pool revalidation ─────────────────────────────────────────────────
// A manually added proxy is only format-checked at insert, and a stored one
// is only re-probed when live traffic happens to exercise it. Entries nobody
// exercises — routing disabled, or an earlier pool member always winning —
// keep their stale 'ok'/'new' forever, including typo'd-but-well-formed
// URLs. The cleanup passes re-probe the stalest few so the settings page
// never shows a healthy pool that is actually dead.
//
// Bounded: at most $max entries per pass, oldest-unchecked first, one
// parallel probe round with short timeouts. Never throws; an empty pool is
// one cheap SELECT, no network.
function osm_proxy_revalidate_stale(int $max = 3, int $stale_days = 7, ?string $probe_url = null): array {
    if (!function_exists('curl_init')) return [];
    try {
        $db = get_db();
        $stmt = $db->prepare(
            'SELECT id, url FROM osm_proxies
             WHERE last_checked IS NULL OR last_checked < DATE_SUB(NOW(), INTERVAL ? DAY)
             ORDER BY last_checked IS NOT NULL, last_checked ASC
             LIMIT ' . max(1, $max)
        );
        $stmt->execute([$stale_days]);
        $due = $stmt->fetchAll();
        if (!$due) return [];
        $urls = [];
        foreach ($due as $row) {
            $urls[(int)$row['id']] = (string)$row['url'];
        }
        $probe = $probe_url ?? 'https://a.tile.openstreetmap.org/13/4051/2749.png';
        $res = proxy_multi_probe(array_values($urls), $probe, 3, 2);
        $out = [];
        foreach ($urls as $id => $url) {
            [$code, $ms] = $res[$url] ?? [0, 0];
            $ok = $code >= 200 && $code < 300;
            osm_proxy_mark($id, $ok, $ms);
            $out[$url] = $ok;
        }
        return $out;
    } catch (Throwable $e) {
        log_err('Proxy revalidate: ' . $e->getMessage());
        return [];
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
function osm_fetch(string $url, int $maxBytes = 2097152): string|false {
    if (!osm_proxy_enabled()) {
        return osm_fetch_via($url, null, 5, $maxBytes);
    }

    $pool = osm_proxy_pool();
    if (!$pool) {
        osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => 0, 'skipped' => []]);
        osm_proxy_heal_kick(); // first run / emptied pool: discover one in the background
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
        $result = osm_fetch_via($url, $px['url'], 3, $maxBytes);
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
            if ($skipped) {
                osm_proxy_heal_kick(); // members ahead of the winner just failed
            }
            return $result;
        }
        $skipped[] = $px['url'];
    }
    osm_last_via_set(['via' => null, 'failed' => true, 'attempts' => $attempts, 'skipped' => $skipped]);
    if ($skipped) {
        osm_proxy_heal_kick();
    }
    return false;
}

// Reverse-geocode one point through Nominatim (same proxy routing as the
// forward search — never direct when routing is enabled). Returns the raw
// address array or null. Callers display osm_place_label(), never raw
// coordinates: owner-facing surfaces hide lat/lng by policy.
/** @return ?array<string,mixed> */
function osm_reverse_lookup(float $lat, float $lng): ?array {
    $url = osm_reverse_url($lat, $lng);
    if ($url === null) {
        return null;
    }
    $data = osm_fetch($url, 65536);
    if ($data === false) {
        return null;
    }
    return osm_reverse_parse($data);
}

// Decode one Nominatim reverse answer to its address array (pure half of
// the lookup — garbage in answers null, never a partial address).
/** @return ?array<string,mixed> */
function osm_reverse_parse(string $data): ?array {
    $j = json_decode($data, true);
    if (!is_array($j)) {
        return null;
    }
    $addr = $j['address'] ?? null;
    return is_array($addr) ? $addr : null;
}

// Nominatim reverse URL for a point, or null outside geography (pure —
// the network half of osm_reverse_lookup stays thin and untested by unit
// suites, which must never reach tile hosts).
function osm_reverse_url(float $lat, float $lng): ?string {
    if (!is_finite($lat) || !is_finite($lng) || $lat < -90.0 || $lat > 90.0 || $lng < -180.0 || $lng > 180.0) {
        return null;
    }
    // Fixed-point, never (string)$float: tiny values would print as "1.0E-5",
    // which Nominatim rejects.
    return 'https://nominatim.openstreetmap.org/reverse?lat=' . sprintf('%.7F', $lat)
        . '&lon=' . sprintf('%.7F', $lng) . '&format=json&accept-language=en';
}

// Human label for a Nominatim address: "Country, State". Either half may be
// absent (sea points, nameless hamlets) — what's there is what's shown.
// Nothing known renders '' and the caller falls back to a generic
// placed/draft text instead of coordinates.
function osm_place_label(mixed $addr): string {
    if (!is_array($addr)) {
        return '';
    }
    $parts = [];
    foreach (['country', 'state'] as $k) {
        $v = trim((string)($addr[$k] ?? ''));
        if ($v !== '') {
            $parts[] = $v;
        }
    }
    return implode(', ', $parts);
}

// Shared storage for the staged badge info of the current request.
// func_num_args() distinguishes an explicit osm_last_via_stage(null)
// ("consume") from a parameterless read — the previous !== null check made
// the consume call a silent no-op, so stale badge info survived the flush.
function osm_last_via_stage(?array $info = null): ?array {
    static $staged = null;
    if (func_num_args() > 0) {
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
// Privacy trade-off, stated openly: this makes a DIRECT clearnet connection
// to ipify/httpbin, disclosing the server IP to exactly those two parties.
// That is the price of verifying the pool hides it from everyone else (OSM);
// the call happens only on owner-initiated discovery, never per request.
function proxy_public_ip(): ?string {
    foreach (['https://api.ipify.org?format=text', 'http://httpbin.org/ip'] as $url) {
        // An IP is bytes, not megabytes: cap the read like every other fetch.
        // Through the shared fetcher so it works via cURL where
        // allow_url_fopen is off (common on shared hosting).
        $raw = osm_fetch_via($url, null, 8, 4096);
        if (!is_string($raw)) {
            continue;
        }
        if (preg_match('/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/', $raw, $m)) {
            return $m[1];
        }
    }
    return null;
}

// Run one anonymity judge through a proxy. Returns true only when EVERY
// reachable judge's response is clean: a leaking proxy may be visible to
// just one judge (different judges echo different fields), so the first
// clean answer must not accept the proxy. Unreachable judges are skipped;
// when none are reachable the answer is false (could not verify — maximum
// security means reject). $judges override exists for tests.
function proxy_judge_anonymous(string $pxUrl, string $ourIp, int $timeout_s = 6, ?array $judges = null): bool {
    $seen = false;
    foreach ($judges ?? PROXY_ANONYMITY_JUDGES as $judge) {
        $body = osm_fetch_via($judge, $pxUrl, $timeout_s);
        if ($body === false) continue; // judge unreachable through this proxy — try next judge
        $seen = true;
        if (str_contains($body, $ourIp)) {
            return false; // our IP leaked into the request as seen by the target
        }
    }
    return $seen;
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
//
// $budget_s is for hosts that run this inside a page visit (no exec, no CLI,
// a wall-clock limit of ~30 s): list downloads get at most 60% of it, the
// anonymity round only runs while time is left, and unrated HTTP proxies that
// could not be judged in time are dropped — the same fail-closed rule as when
// the judge is unreachable. Null = the unbounded CLI/button behaviour.
function proxy_discover(int $max_test = 400, int $timeout_s = 4, ?float $budget_s = null): array {
    // No cURL on this host: every probe below needs it. proxy_multi_probe()
    // would fatal with an Error that callers only catch as Exception.
    if (!function_exists('curl_init')) return [];
    $started   = microtime(true);
    $remaining = static fn(): float => $budget_s === null ? INF : $budget_s - (microtime(true) - $started);
    $candidates = []; // url => ['rated' => bool, 'source' => list name]

    foreach (PROXY_DISCOVERY_SOURCES as $i => $src) {
        // Stop collecting once the download share of the budget is spent: what
        // is in hand gets probed instead of starting another slow download.
        if ($budget_s !== null && $i > 0 && $remaining() < $budget_s * 0.4) {
            break;
        }
        $fetchTimeout = $budget_s === null ? 10 : max(2, min(6, (int)floor($remaining() - $budget_s * 0.4)));
        // Third-party list bodies are the largest untrusted input on this
        // path — same 2 MiB ceiling as the shared fetcher (cURL where
        // available, so allow_url_fopen is not required).
        $raw = osm_fetch_via($src['url'], null, $fetchTimeout, 2097152);
        if (!is_string($raw)) {
            continue;
        }

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
    if ($budget_s !== null) {
        $unrated = array_slice($unrated, 0, 10); // all a budgeted run can afford to judge
    }
    $judged = [];
    if ($unrated && $remaining() > 8.0) {
        $ourIp = proxy_public_ip();
        if ($ourIp !== null) {
            foreach (array_chunk($unrated, 50) as $chunk) {
                $urls     = array_column($chunk, 'url');
                $judgeRes = proxy_multi_probe($urls, PROXY_ANONYMITY_JUDGES[0], $timeout_s, $timeout_s, false);
                foreach ($urls as $pxUrl) {
                    if ($remaining() < 4.0) {
                        $judged[$pxUrl] = false; // out of time: unproven means rejected
                        continue;
                    }
                    [$code, ] = $judgeRes[$pxUrl] ?? [0, 0];
                    $judged[$pxUrl] = $code >= 200 && $code < 300 && proxy_judge_anonymous($pxUrl, $ourIp);
                }
            }
        }
    }
    $working = proxy_filter_anonymity($working, $candidates, $ourIp ?? null, $judged);

    usort($working, fn($a, $b) => $a['latency_ms'] <=> $b['latency_ms']);
    return $working;
}

// ── Anonymity gate (pure — see ProxyTest) ─────────────────────────────────────
// The single decision point for which working proxies may serve OSM traffic:
//   rated proxies (from a curated list)        → keep
//   HTTPS proxies (content opaque to filters)  → keep
//   unrated HTTP proxies, judge reachable      → keep only if judged anonymous
//   unrated HTTP proxies, judge unreachable    → DROP ALL (fail closed — when
//     we cannot learn our own IP we cannot prove a proxy hides it)
// This function is where the "array === false" bug lived: the entire anonymity
// round silently never ran. ProxyTest pins the decision table.
function proxy_filter_anonymity(array $working, array $candidates, ?string $our_ip, array $judged): array {
    return array_values(array_filter($working, static fn(array $p): bool =>
        ($candidates[$p['url']]['rated'] ?? false) !== false
        || !str_starts_with($p['url'], 'http://')
        || ($our_ip !== null && ($judged[$p['url']] ?? false))
    ));
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
        unset($ch); // PHP 8.5 deprecates curl_close(); removal + scope exit frees it
    }
    curl_multi_close($mh);
    return $out;
}

// ── Self-healing pool ─────────────────────────────────────────────────────────
// Public proxies die constantly. A pool entry that failed is confirmed dead
// by a fresh probe, deleted, and replaced by a newly discovered one chosen by
// exactly the criteria of the Auto-discover button (proxy_discover(): answers
// an HTTPS OSM tile in under 3 s, anonymity gate for unrated HTTP proxies).
//
// Safety rules:
//   - Only while routing is enabled, and only entries that discovery itself
//     could have added: `manual` entries are the owner's own choice (maybe
//     their own server) and are never deleted automatically.
//   - The same job seeds the pool: routing is on by default and an empty pool
//     fails closed, so on the first run (or after the pool was emptied) it
//     runs discovery and stores everything the Auto-discover button would.
//   - DDMGMT_PROXY_HEAL=0 turns all of it off (replacement and seeding) for
//     deployments that must never start discovery on their own.
//   - Replace, never just delete: nothing is removed until discovery has
//     produced a replacement, so a network outage (where every proxy "fails"
//     and discovery finds nothing) cannot wipe the pool, and the pool never
//     shrinks — at most min(dead, fresh) entries are swapped.
//   - Discovery is heavy and makes the same outbound calls as the button
//     (list downloads, the public-IP lookup, up to 400 probes), so it runs
//     in a detached CLI job (cron/proxy_heal.php), never inside a request,
//     under a lock and a cooldown.
const OSM_PROXY_HEAL_COOLDOWN    = 600;  // seconds between discovery runs
const OSM_PROXY_HEAL_INLINE_BUDGET = 22.0; // wall-clock seconds of an inline pass (shared hosts stop scripts at ~30 s)
const OSM_PROXY_SEED_MAX_FAILURES = 3;   // empty-pool discoveries in a row before routing is switched off
const OSM_PROXY_HEAL_LOCK_STALL  = 900;  // a lock older than this is dead
const OSM_PROXY_HEAL_PROBE_URL   = 'https://a.tile.openstreetmap.org/13/4051/2749.png';

// Automatic discovery (replacement and first-run seeding) can be switched off
// for the whole deployment; disabling routing in Settings also stops it.
function osm_proxy_heal_allowed(): bool {
    return host_flag('DDMGMT_PROXY_HEAL', true);
}

function osm_proxy_pool_empty(): bool {
    return (int)get_db()->query('SELECT COUNT(*) FROM osm_proxies')->fetchColumn() === 0;
}

// Failed entries the healer may replace, longest-dead first.
/** @return list<array{id:int,url:string}> */
function osm_proxy_replaceable_dead(): array {
    $rows = get_db()->query(
        "SELECT id, url FROM osm_proxies
         WHERE last_status = 'fail' AND source <> 'manual'
         ORDER BY last_checked IS NULL DESC, last_checked ASC, id ASC"
    )->fetchAll();
    return array_map(static fn(array $r): array => ['id' => (int)$r['id'], 'url' => (string)$r['url']], $rows);
}

// One healer at a time: compare-and-swap on a settings row (same scheme as
// the map worker lock — no new table). A lock older than the stall window
// belongs to a dead process and is stealable.
function osm_proxy_heal_lock(): bool {
    $mine = json_encode(['by' => php_uname('n') . ':' . getmypid(), 'at' => time()]);
    try {
        $db = get_db();
        $st = $db->query("SELECT value FROM settings WHERE key_name = 'proxy_heal_lock' LIMIT 1");
        $raw = $st === false ? false : $st->fetchColumn();
        if ($raw === false) {
            $win = $db->prepare("INSERT IGNORE INTO settings (key_name, value, label) VALUES ('proxy_heal_lock', ?, '')");
            $win->execute([$mine]);
        } else {
            $raw = (string)$raw;
            if ($raw !== '') {
                $held = json_decode($raw, true);
                if (is_array($held) && (time() - (int)($held['at'] ?? 0)) < OSM_PROXY_HEAL_LOCK_STALL) {
                    return false;
                }
            }
            $win = $db->prepare("UPDATE settings SET value = ? WHERE key_name = 'proxy_heal_lock' AND value = ?");
            $win->execute([$mine, $raw]);
        }
        return $win->rowCount() === 1;
    } catch (Throwable $e) {
        log_err('Proxy heal lock: ' . $e->getMessage());
        return false;
    }
}

function osm_proxy_heal_unlock(): void {
    try {
        get_db()->exec("DELETE FROM settings WHERE key_name = 'proxy_heal_lock'");
    } catch (Throwable) {
    }
}

// Test seam: production spawns the detached CLI; a suite installs a stand-in
// (or a no-op) so no real process — and no real network — is ever started.
function osm_proxy_heal_spawner(?callable $set = null, bool $reset = false): ?callable {
    static $spawner = null;
    if ($reset) {
        $spawner = null;
    } elseif ($set !== null) {
        $spawner = $set;
    }
    return $spawner;
}

// Is there heal work that is allowed right now? Routing on and possible,
// automatic discovery not disabled, the cooldown passed, and either a
// replaceable dead entry or an empty pool. $throttle (the pseudo-cron slot,
// which asks on every request) also remembers "nothing to do" for one
// cooldown so a healthy pool costs a single query per interval.
function osm_proxy_heal_pending(bool $throttle = false): bool {
    if (!osm_proxy_heal_allowed() || !osm_proxy_enabled()) return false;
    $since = (int)get_setting('proxy_heal_last', '0');
    if ($throttle) {
        $since = max($since, (int)get_setting('proxy_heal_checked', '0'));
    }
    if ((time() - $since) < OSM_PROXY_HEAL_COOLDOWN) return false;
    if (osm_proxy_replaceable_dead() !== [] || osm_proxy_pool_empty()) return true;
    if ($throttle) {
        set_setting('proxy_heal_checked', (string)time());
    }
    return false;
}

// The pseudo-cron's proxy slot (runs after the response). Where a detached
// job can be started, start one; where it cannot — shared hosting without
// exec or CLI PHP — run a time-budgeted pass right here. Never throws.
// ($discover / $probe: test seams, as in osm_proxy_heal().)
function osm_proxy_heal_pseudo_cron(?callable $discover = null, ?callable $probe = null): void {
    try {
        if (!osm_proxy_heal_pending(true)) return;
        if (osm_proxy_heal_spawner() !== null || host_can_detach()) {
            osm_proxy_heal_kick();
            return;
        }
        @set_time_limit(60);
        osm_proxy_heal($discover, $probe, false, OSM_PROXY_HEAL_INLINE_BUDGET);
    } catch (Throwable $e) {
        log_err('Proxy heal slot: ' . $e->getMessage());
    }
}

// Routing is on by default, but a host that can never build a pool (outbound
// connections blocked, every list unreachable, a wall-clock limit too short to
// finish a pass) would answer 502 on every map view forever. After a few
// empty-pool discoveries in a row, switch routing off — loudly: audit +
// warning + a notice in Settings — so OSM requests go direct and the owner
// decides. Re-enabling the toggle clears the notice.
//
// The attempt is counted BEFORE discovery starts: a host that kills the script
// mid-pass never reaches any "it failed" code, and must still run out of tries.
// Returns false when the tries were already used up (routing was just switched
// off instead of trying again).
function osm_proxy_seed_attempt(): bool {
    $n = (int)get_setting('proxy_seed_failures', '0');
    if ($n >= OSM_PROXY_SEED_MAX_FAILURES) {
        osm_proxy_auto_off('no working proxy could be found from this host');
        return false;
    }
    set_setting('proxy_seed_failures', (string)($n + 1));
    return true;
}

// After an attempt that produced nothing: was that the last try?
function osm_proxy_seed_failed(): void {
    if ((int)get_setting('proxy_seed_failures', '0') >= OSM_PROXY_SEED_MAX_FAILURES) {
        osm_proxy_auto_off('no working proxy could be found from this host');
    }
}

function osm_proxy_auto_off(string $reason): void {
    set_setting('osm_proxy_enabled', '0');
    set_setting('osm_proxy_auto_off', (string)json_encode(['at' => time(), 'reason' => $reason]));
    delete_setting('proxy_seed_failures');
    audit('proxy_auto_off', null, null, $reason);
    log_warn('proxy_auto_off', ['msg' => 'OSM proxy routing switched off automatically: ' . $reason]);
}

/** @return ?array{at:int,reason:string} */
function osm_proxy_auto_off_state(): ?array {
    $raw = get_setting('osm_proxy_auto_off', '');
    if ($raw === '') return null;
    $d = json_decode($raw, true);
    return is_array($d) ? ['at' => (int)($d['at'] ?? 0), 'reason' => (string)($d['reason'] ?? '')] : null;
}

function osm_proxy_auto_off_clear(): void {
    delete_setting('osm_proxy_auto_off', 'proxy_seed_failures');
}

// Start a detached heal job when one is warranted: routing on, a replaceable
// dead entry exists (or the pool is empty and needs seeding), and the
// cooldown has passed. Cheap when nothing is due
// (one setting read plus one SELECT), never throws, never blocks. Returns
// whether a job was started.
function osm_proxy_heal_kick(): bool {
    try {
        $spawn = osm_proxy_heal_spawner();
        // No way to detach here (no exec / CLI PHP): the pseudo-cron slot runs
        // the pass inline instead — and must not find the cooldown burnt.
        if ($spawn === null && !host_can_detach()) return false;
        if (!osm_proxy_heal_pending()) return false;
        // Stamp before spawning: concurrent requests must not each start a job.
        set_setting('proxy_heal_last', (string)time());
        if ($spawn !== null) {
            return (bool)$spawn();
        }
        $cli = host_php_cli();
        if ($cli === null) return false;
        @exec(escapeshellarg($cli) . ' ' . escapeshellarg(dirname(__DIR__) . '/cron/proxy_heal.php') . ' > /dev/null 2>&1 &');
        return true;
    } catch (Throwable $e) {
        log_err('Proxy heal kick: ' . $e->getMessage());
        return false;
    }
}

// Replace confirmed-dead pool entries with freshly discovered ones. $discover
// and $probe exist for tests (default: proxy_discover / proxy_multi_probe).
// $honorCooldown: see the note in the body. $budget: wall-clock seconds for
// the inline pass on hosts that cannot run a detached job (see
// proxy_discover()); null = unbounded (CLI job, cron, the button).
// Blocking and network-heavy — call from CLI only.
/** @return array{skipped:?string,dead:int,recovered:int,replaced:int,seeded:int} */
function osm_proxy_heal(?callable $discover = null, ?callable $probe = null, bool $honorCooldown = false, ?float $budget = null): array {
    $out = ['skipped' => null, 'dead' => 0, 'recovered' => 0, 'replaced' => 0, 'seeded' => 0];
    if (!osm_proxy_heal_allowed()) { $out['skipped'] = 'disabled by DDMGMT_PROXY_HEAL'; return $out; }
    if (!osm_proxy_enabled()) { $out['skipped'] = 'routing disabled'; return $out; }
    if (!function_exists('curl_init')) { $out['skipped'] = 'no cURL'; return $out; }
    // Scheduled callers (the cleanup cron) honour the cooldown so they cannot
    // run discovery back-to-back with a job a live request just started; a job
    // started BY the kick has stamped the cooldown itself and must not honour it.
    if ($honorCooldown && (time() - (int)get_setting('proxy_heal_last', '0')) < OSM_PROXY_HEAL_COOLDOWN) {
        $out['skipped'] = 'cooldown';
        return $out;
    }
    if (!osm_proxy_heal_lock()) { $out['skipped'] = 'another heal is running'; return $out; }
    $db = get_db();
    try {
        set_setting('proxy_heal_last', (string)time());

        // First run (or a pool that was emptied): nothing to replace, so seed
        // it with what the Auto-discover button would store. Routing is on and
        // an empty pool fails closed, so waiting for the owner would leave the
        // maps dead until they found the button.
        if (osm_proxy_pool_empty()) {
            if (!osm_proxy_seed_attempt()) { $out['skipped'] = 'routing switched off'; return $out; }
            $found = ($discover ?? static fn(): array => proxy_discover(
                $budget !== null ? 120 : 400, $budget !== null ? 3 : 4, $budget
            ))();
            if ($found === []) {
                $out['skipped'] = 'no proxies found';
                osm_proxy_seed_failed();
                return $out;
            }
            delete_setting('proxy_seed_failures');
            $seed = $db->prepare(
                'INSERT IGNORE INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
                 VALUES (?, ?, "ok", ?, NOW())'
            );
            foreach ($found as $px) {
                $seed->execute([$px['url'], (string)($px['source'] ?? 'discovered'), $px['latency_ms'] ?? null]);
                $out['seeded'] += $seed->rowCount();
            }
            if ($out['seeded'] > 0) {
                audit('proxy_seed', null, null, 'added=' . $out['seeded']);
                log_info('proxy_seeded', ['msg' => "first-run discovery added {$out['seeded']} proxies", 'added' => $out['seeded']]);
            }
            return $out;
        }

        $dead = osm_proxy_replaceable_dead();
        if ($dead === []) { $out['skipped'] = 'nothing to replace'; return $out; }

        // Confirm before deleting: a slow answer or a one-off OSM hiccup marks
        // a good proxy 'fail'. Probe them once more, the way the stale
        // revalidation does, and keep whoever answers now.
        $probeFn = $probe ?? static fn(array $urls): array
            => proxy_multi_probe($urls, OSM_PROXY_HEAL_PROBE_URL, 4, 4);
        $res = $probeFn(array_column($dead, 'url'));
        $confirmed = [];
        foreach ($dead as $row) {
            [$code, $ms] = $res[$row['url']] ?? [0, 0];
            if ($code >= 200 && $code < 300) {
                osm_proxy_mark($row['id'], true, (int)$ms);
                $out['recovered']++;
            } else {
                $confirmed[] = $row;
            }
        }
        $out['dead'] = count($confirmed);
        if ($confirmed === []) { $out['skipped'] = 'all recovered'; return $out; }

        // Same criteria as the Auto-discover button, fastest first.
        $found = ($discover ?? static fn(): array => proxy_discover(
            $budget !== null ? 120 : 400, $budget !== null ? 3 : 4, $budget
        ))();
        $have = array_flip($db->query('SELECT url FROM osm_proxies')->fetchAll(PDO::FETCH_COLUMN));
        $fresh = array_values(array_filter(
            $found,
            static fn(array $p): bool => !isset($have[$p['url']])
        ));
        $n = min(count($confirmed), count($fresh));
        if ($n === 0) { $out['skipped'] = 'no replacement found'; return $out; }

        $del = $db->prepare("DELETE FROM osm_proxies WHERE id = ? AND last_status = 'fail' AND source <> 'manual'");
        $ins = $db->prepare(
            'INSERT INTO osm_proxies (url, source, last_status, latency_ms, last_checked)
             VALUES (?, ?, "ok", ?, NOW())'
        );
        $db->beginTransaction();
        try {
            $swapped = 0;
            foreach (array_slice($confirmed, 0, $n) as $row) {
                $del->execute([$row['id']]);
                if ($del->rowCount() !== 1) continue; // recovered or removed meanwhile
                $px = $fresh[$swapped];
                $ins->execute([$px['url'], (string)($px['source'] ?? 'discovered'), $px['latency_ms'] ?? null]);
                $swapped++;
            }
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            throw $e;
        }
        $out['replaced'] = $swapped;
        if ($swapped > 0) {
            audit('proxy_replace', null, null, "replaced={$swapped} dead={$out['dead']}");
            log_info('proxy_replaced', ['msg' => "replaced {$swapped} of {$out['dead']} dead proxies", 'replaced' => $swapped, 'dead' => $out['dead']]);
        }
        return $out;
    } catch (Throwable $e) {
        log_err('Proxy heal: ' . $e->getMessage());
        $out['skipped'] = 'error';
        return $out;
    } finally {
        osm_proxy_heal_unlock();
    }
}
