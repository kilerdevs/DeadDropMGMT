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
// pool member in random order; gives up (returns false) if all fail while
// routing is enabled — that is the point of fail-closed.
// Records which proxy served the request in the session so the admin UI
// can show it (see admin/osm_monit.php).
function osm_fetch(string $url): string|false {
    if (!osm_proxy_enabled()) {
        return osm_fetch_via($url, null);
    }

    $pool = osm_proxy_pool();
    if (!$pool) {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['osm_last_via'] = ['via' => null, 'failed' => true];
        }
        return false; // enabled with an empty pool would mean going direct = leak
    }

    shuffle($pool);
    foreach ($pool as $px) {
        $t0     = microtime(true);
        $result = osm_fetch_via($url, $px['url']);
        $ms     = (int)round((microtime(true) - $t0) * 1000);
        osm_proxy_mark((int)$px['id'], $result !== false, $ms);
        if ($result !== false) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                $_SESSION['osm_last_via'] = ['via' => $px['url'], 'latency_ms' => $ms, 'failed' => false];
            }
            return $result;
        }
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['osm_last_via'] = ['via' => null, 'failed' => true];
    }
    return false;
}

// ── Discovery ────────────────────────────────────────────────────────────────

// Sources of candidate proxies. Proxifly ships structured JSON with
// anonymity ratings; monosans publishes hourly pre-checked lists (plain
// ip:port). Both are free and community-maintained.
const PROXY_DISCOVERY_SOURCES = [
    'proxifly'      => 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json',
    'monosans_http' => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'monosans_s5'   => 'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
];

// Pull candidates from public sources, then probe them in parallel against a
// real OSM tile URL. Returns [['url' => ..., 'latency_ms' => ...], ...] for
// proxies that actually answered.
//
// Why probe against HTTPS: our real targets (tiles, Nominatim) are
// HTTPS-only, which requires HTTP proxies to support CONNECT tunneling —
// most free plain-HTTP proxies don't, so a proxy that only speaks plain
// HTTP is useless here no matter how alive it looks. SOCKS proxies tunnel
// arbitrary TCP natively and never inject HTTP headers (anonymity by
// design), so they are probed the same way.
function proxy_discover(int $max_test = 300, int $timeout_s = 4): array {
    $candidates = [];

    foreach (PROXY_DISCOVERY_SOURCES as $srcUrl) {
        $raw = @file_get_contents($srcUrl, false, stream_context_create([
            'http' => ['timeout' => 10],
        ]));
        if ($raw === false) continue;

        if (str_contains($srcUrl, 'data.json')) {
            // Proxifly JSON — anonymity-rated
            $list = json_decode($raw, true);
            if (!is_array($list)) continue;
            foreach ($list as $entry) {
                if (!is_array($entry)) continue;
                $proto = strtolower((string)($entry['protocol'] ?? ''));
                if ($proto === '') continue;
                $anon = strtolower((string)($entry['anonymity'] ?? ''));
                // HTTP proxies must be anonymity-rated (no transparent ones);
                // SOCKS is header-anonymous by protocol, so rating is moot.
                if (str_starts_with($proto, 'socks')) {
                    // keep
                } elseif (!in_array($anon, ['anonymous', 'elite'], true)) {
                    continue;
                }
                $ip   = (string)($entry['ip'] ?? '');
                $port = (string)($entry['port'] ?? '');
                if ($ip === '' || $port === '') continue;
                $norm = osm_proxy_normalize("$proto://$ip:$port");
                if ($norm !== null) $candidates[$norm] = true;
            }
        } else {
            // monosans plain lists — one ip:port per line
            foreach (preg_split('/\r?\n/', trim($raw)) ?: [] as $line) {
                $line = trim(explode(';', trim($line))[0]);
                if ($line === '' || !str_contains($line, ':')) continue;
                $scheme = str_contains($srcUrl, 'socks5') ? 'socks5' : 'http';
                $norm   = osm_proxy_normalize("$scheme://$line");
                if ($norm !== null) $candidates[$norm] = true;
            }
        }
    }

    if (!$candidates) return [];
    $candidates = array_keys($candidates);
    shuffle($candidates); // lists are ordered; random slice spreads the load
    $toTest = array_slice($candidates, 0, $max_test);

    // Probe against a real OSM tile so we know the proxy works for this use.
    $probeUrl = 'https://a.tile.openstreetmap.org/13/4051/2749.png';
    $mh = curl_multi_init();
    /** @var CurlHandle[] $handles */
    $handles = [];
    foreach ($toTest as $pxUrl) {
        $ch = curl_init($probeUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_PROXY          => $pxUrl,
            CURLOPT_TIMEOUT        => $timeout_s,
            CURLOPT_CONNECTTIMEOUT => $timeout_s,
            CURLOPT_USERAGENT      => 'DeadDropMGMT/1.0',
            CURLOPT_NOBODY         => true,
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

    $working = [];
    foreach ($handles as $pxUrl => $ch) {
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $ms   = (int)round((float)curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
        if ($code >= 200 && $code < 300) {
            $working[] = ['url' => $pxUrl, 'latency_ms' => $ms];
        }
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);

    return $working;
}
