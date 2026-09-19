<?php
/**
 * Dead Drop proxy pool healer — CLI worker (and detached background job).
 *
 * Replaces failed pool proxies with freshly discovered ones, using exactly
 * the criteria of Settings → OSM proxy pool → Auto-discover. Started
 * detached when a live request sees a pool member fail (osm_fetch), and once
 * an hour from the cleanup slot; safe to run from system cron as well:
 *
 * Cron example (hourly):
 *     php /path/to/cron/proxy_heal.php
 *
 * Does nothing unless proxy routing is enabled and a discovered (non-manual)
 * entry is marked failed and still fails a fresh probe. Nothing is deleted
 * until a replacement exists. Never invoked from a page visit inline.
 */
declare(strict_types=1);

// CLI only: this script must never be runnable over HTTP, whatever the
// web server happens to serve.
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

define('BASE_DIR', dirname(__DIR__));
require_once BASE_DIR . '/includes/kernel.php';

@set_time_limit(300);

$r = osm_proxy_heal();
echo '[' . date('Y-m-d H:i:s') . '] proxy heal: '
    . ($r['skipped'] !== null
        ? "skipped ({$r['skipped']})"
        : "replaced {$r['replaced']} of {$r['dead']} dead")
    . ($r['recovered'] > 0 ? ", {$r['recovered']} recovered" : '')
    . "\n";
exit($r['skipped'] === 'error' ? 1 : 0);
