<?php
declare(strict_types=1);

// Operational metrics collector for the owner diagnostics page.
//
// Read-only by construction: every section aggregates counts, sizes and
// timestamps from existing tables and log files. Nothing here writes,
// rotates, purges or repairs — so a diagnostics load can never change the
// state it reports on. Each section is fail-soft on its own: one
// unreadable source (restricted information_schema, missing log dir)
// marks just its section unavailable instead of failing the page.

const DIAGNOSTICS_LOG_TAIL_LINES = 500;
// Capped disk walk for uploads/ usage: bounded work on huge trees, and the
// page says so instead of silently reporting a partial sum as exact.
const DIAGNOSTICS_DU_MAX_FILES = 5000;
// Heartbeat staleness: the pseudo-cron slots run hourly, so silence past
// two intervals means the worker is not reaching them.
const DIAGNOSTICS_HEARTBEAT_STALE_S = 7200;

/**
 * Full snapshot: seven sections plus the collection timestamp.
 * @return array{generated_at:int,system:array<string,mixed>,jobs:array<string,mixed>,logs:array<string,mixed>,traffic:array<string,mixed>,security:array<string,mixed>,data:array<string,mixed>,backups:array<string,mixed>}
 */
function diagnostics_collect(): array {
    return [
        'generated_at' => time(),
        'system'       => _diag_try('diagnostics_system'),
        'jobs'         => _diag_try('diagnostics_jobs'),
        'logs'         => _diag_try('diagnostics_logs'),
        'traffic'      => _diag_try('diagnostics_traffic'),
        'security'     => _diag_try('diagnostics_security'),
        'data'         => _diag_try('diagnostics_data'),
        'backups'      => _diag_try('diagnostics_backups'),
    ];
}

/**
 * Run one section collector; a throwing source degrades, never fails.
 * @return array<string,mixed>
 */
function _diag_try(string $fn): array {
    try {
        $out = $fn();
        $out['ok'] = true;
        return $out;
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => 'unavailable'];
    }
}

// ── Formatting (page + JSON share the raw numbers; these are display) ───────

/** 1536 → "1.5 KiB"; null (unknown) stays visibly unknown, never "0 B". */
function diagnostics_bytes(?int $bytes): string {
    if ($bytes === null || $bytes < 0) {
        return '—';
    }
    $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    $v = (float)$bytes;
    $u = 0;
    while ($v >= 1024.0 && $u < count($units) - 1) {
        $v /= 1024.0;
        $u++;
    }
    return ($u === 0 ? (string)(int)$v : sprintf('%.1f', $v)) . ' ' . $units[$u];
}

/** Unix timestamp → "3m ago" / "2d ago"; 0 or future → "never". */
function diagnostics_age(int $ts, ?int $now = null): string {
    $now ??= time();
    $d = $now - $ts;
    if ($ts <= 0 || $d < 0) {
        return 'never';
    }
    if ($d < 60) {
        return $d . 's ago';
    }
    if ($d < 3600) {
        return (int)($d / 60) . 'm ago';
    }
    if ($d < 86400) {
        return (int)($d / 3600) . 'h ago';
    }
    return (int)($d / 86400) . 'd ago';
}

// ── System ───────────────────────────────────────────────────────────────────

/** @return array{php:string,sapi:string,memory_limit:string|false,opcache:?array<string,mixed>,disks:array<string,array{free:?int,total:?int}>,db_version:?string,db_size:?int} */
function diagnostics_system(): array {
    $root = dirname(__DIR__);
    $disks = [];
    foreach (['root' => '', 'tiles' => '/tiles', 'uploads' => '/uploads', 'backups' => '/backups'] as $label => $sub) {
        $p = $root . $sub;
        $free = @disk_free_space($p);
        $total = @disk_total_space($p);
        $disks[$label] = [
            'free'  => is_float($free) ? (int)$free : null,
            'total' => is_float($total) ? (int)$total : null,
        ];
    }
    // DB size needs information_schema; locked-down grants deny it — that is
    // a missing cell, not a page failure.
    $dbSize = null;
    $dbVersion = null;
    try {
        $db = get_db();
        $dbVersion = (string)$db->query('SELECT VERSION()')->fetchColumn();
        $dbSize = (int)$db->query(
            'SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()'
        )->fetchColumn();
    } catch (Throwable) {
    }
    $opcache = null;
    if (function_exists('opcache_get_status')) {
        $st = @opcache_get_status(false);
        if (is_array($st)) {
            $opcache = [
                'enabled'   => true,
                'hit_rate'  => isset($st['opcache_statistics']['opcache_hit_rate'])
                    ? round((float)$st['opcache_statistics']['opcache_hit_rate'], 1) : null,
                'used_mb'   => isset($st['memory_usage']['used_memory'])
                    ? round((float)$st['memory_usage']['used_memory'] / 1048576, 1) : null,
            ];
        }
    }
    return [
        'php'          => PHP_VERSION,
        'sapi'         => PHP_SAPI,
        'memory_limit' => ini_get('memory_limit'),
        'opcache'      => $opcache,
        'disks'        => $disks,
        'db_version'   => $dbVersion,
        'db_size'      => $dbSize,
    ];
}

// ── Jobs (heartbeats the operator currently cannot see anywhere) ─────────────

/** @return array{pseudo_cron:bool,heartbeats:array<string,array{label:string,at:?int,age_s:?int,stale:bool}>,maps_worker_lock:?array{by:string,at:int,age_s:int},maps_engine:?string} */
function diagnostics_jobs(): array {
    $now = time();
    $beats = [];
    foreach (['last_cleanup' => 'cleanup', 'maps_steward_at' => 'maps steward', 'proxy_heal_last' => 'proxy heal'] as $key => $label) {
        $at = (int)get_setting($key, '0');
        $beats[$key] = [
            'label' => $label, 'at' => $at > 0 ? $at : null,
            'age_s' => $at > 0 ? $now - $at : null,
            // Never-run on a fresh install is expected, not alarming.
            'stale' => $at > 0 && ($now - $at) > DIAGNOSTICS_HEARTBEAT_STALE_S,
        ];
    }
    // The maps download worker lock: holder + age, so a wedged worker (lock
    // held for hours, no progress) is visible instead of silent.
    $lock = null;
    $raw = get_setting('maps_worker_lock', '');
    if ($raw !== '') {
        $dec = json_decode($raw, true);
        if (is_array($dec) && isset($dec['at'])) {
            $lock = [
                'by'    => is_string($dec['by'] ?? null) ? (string)$dec['by'] : '?',
                'at'    => (int)$dec['at'],
                'age_s' => $now - (int)$dec['at'],
            ];
        }
    }
    return [
        'pseudo_cron' => pseudo_cron_enabled(),
        'heartbeats'  => $beats,
        'maps_worker_lock' => $lock,
        'maps_engine' => function_exists('maps_engine') ? maps_engine() : null,
    ];
}

// ── Log health (sizes + tip + checkpoint age; continuity stays manual) ───────

/** @return array{files:array<string,array{size:?int,mtime:?int}>,tip:?array{seq:?int,ts:?string},checkpoint:?array{tip_seq:int,at:?int}} */
function diagnostics_logs(): array {
    $root = dirname(__DIR__);
    $files = [];
    $paths = ['app.log' => $root . '/logs/app.log', 'app.log.1' => $root . '/logs/app.log.1'];
    if (defined('ERROR_LOG_PATH')) {
        $paths['error.log'] = ERROR_LOG_PATH;
    }
    foreach ($paths as $label => $p) {
        $files[$label] = [
            'size'  => is_file($p) ? (int)@filesize($p) : null,
            'mtime' => is_file($p) ? (int)@filemtime($p) : null,
        ];
    }
    // Chain tip: the newest entry's seq anchors "how much log exists".
    // log_recent_entries() returns ['total'=>…,'entries'=>[…]] — the tuple
    // shape, not a bare list (a past revision read $recent[0] and the tip
    // silently stayed null).
    $tip = null;
    $recent = log_recent_entries(1);
    $newest = $recent['entries'][0] ?? null;
    if (is_array($newest)) {
        $tip = ['seq' => $newest['seq'] ?? null, 'ts' => $newest['ts'] ?? null];
    }
    $checkpoint = null;
    try {
        $row = get_db()->query(
            'SELECT tip_seq, created_at FROM log_checkpoints ORDER BY id DESC LIMIT 1'
        )->fetch();
        if (is_array($row)) {
            $at = is_string($row['created_at'] ?? null) ? strtotime((string)$row['created_at']) : false;
            $checkpoint = ['tip_seq' => (int)($row['tip_seq'] ?? 0), 'at' => $at === false ? null : (int)$at];
        }
    } catch (Throwable) {
    }
    return ['files' => $files, 'tip' => $tip, 'checkpoint' => $checkpoint];
}

// ── Traffic (true 24h counts from order_events + recent app-log histogram) ───

/** @return array{events_24h_by_type:array<string,int>,top_ips_24h:list<array{ip:string,events:int}>,log_levels:array<string,int>,log_top_events:array<string,int>,log_sampled_lines:int} */
function diagnostics_traffic(): array {
    $since = date('Y-m-d H:i:s', time() - 86400);
    $byType = [];
    $topIps = [];
    try {
        $db = get_db();
        $st = $db->prepare('SELECT event_type, COUNT(*) AS n FROM order_events WHERE created_at >= ? GROUP BY event_type ORDER BY n DESC');
        $st->execute([$since]);
        foreach ($st->fetchAll() as $r) {
            $byType[(string)$r['event_type']] = (int)$r['n'];
        }
        $st = $db->prepare('SELECT ip_address, COUNT(*) AS n FROM order_events WHERE created_at >= ? GROUP BY ip_address ORDER BY n DESC LIMIT 10');
        $st->execute([$since]);
        foreach ($st->fetchAll() as $r) {
            $topIps[] = ['ip' => (string)$r['ip_address'], 'events' => (int)$r['n']];
        }
    } catch (Throwable) {
    }
    // App-log histogram over the capped tail: labeled by sample size so a
    // busy host's "last 500 lines" is never mistaken for a full day.
    // log_tail_lines() returns [lines oldest-first, cut] — iterate the lines,
    // not the tuple (a past revision decoded the tuple itself and the
    // histogram silently stayed empty).
    $levels = [];
    $events = [];
    $sampled = 0;
    [$tailLines] = log_tail_lines(APP_LOG_PATH, 262144, DIAGNOSTICS_LOG_TAIL_LINES);
    foreach ($tailLines as $line) {
        $dec = json_decode($line, true);
        if (!is_array($dec)) {
            continue;
        }
        $sampled++;
        $lv = is_string($dec['level'] ?? null) ? (string)$dec['level'] : '?';
        $levels[$lv] = ($levels[$lv] ?? 0) + 1;
        $ev = is_string($dec['event'] ?? null) ? (string)$dec['event'] : '?';
        $events[$ev] = ($events[$ev] ?? 0) + 1;
    }
    arsort($events);
    return [
        'events_24h_by_type' => $byType,
        'top_ips_24h'        => $topIps,
        'log_levels'         => $levels,
        'log_top_events'     => array_slice($events, 0, 10, true),
        'log_sampled_lines'  => $sampled,
    ];
}

// ── Security (live rate-limit pressure + audit mix; IPs owner-visible) ───────

/** @return array{top_blocked:list<array{ip:string,scope:string,count:int,window_start:?int}>,audit_24h_by_action:array<string,int>,audit_24h_total:int} */
function diagnostics_security(): array {
    $blocked = [];
    $auditMix = [];
    try {
        $db = get_db();
        // rate_limits rows exist only while a window is hot — an empty table
        // means "nobody is being throttled right now", which is itself info.
        $rows = $db->query(
            'SELECT ip_address, scope, count, window_start FROM rate_limits ORDER BY count DESC LIMIT 10'
        )->fetchAll();
        foreach ($rows as $r) {
            $at = is_string($r['window_start'] ?? null) ? strtotime((string)$r['window_start']) : false;
            $blocked[] = [
                'ip' => (string)$r['ip_address'], 'scope' => (string)$r['scope'],
                'count' => (int)$r['count'], 'window_start' => $at === false ? null : (int)$at,
            ];
        }
        $since = date('Y-m-d H:i:s', time() - 86400);
        $st = $db->prepare('SELECT action, COUNT(*) AS n FROM audit_log WHERE created_at >= ? GROUP BY action ORDER BY n DESC LIMIT 10');
        $st->execute([$since]);
        foreach ($st->fetchAll() as $r) {
            $auditMix[(string)$r['action']] = (int)$r['n'];
        }
        $st = $db->prepare('SELECT COUNT(*) FROM audit_log WHERE created_at >= ?');
        $st->execute([$since]);
        $auditTotal = (int)$st->fetchColumn();
    } catch (Throwable) {
        $auditTotal = 0;
    }
    return ['top_blocked' => $blocked, 'audit_24h_by_action' => $auditMix, 'audit_24h_total' => $auditTotal];
}

// ── Data (queue depth, photo store, zone progress, pool staleness) ───────────

/** @return array{orders_by_status:array<string,int>,orders_expiring_24h:int,photos:int,uploads:array<string,mixed>,zones:list<array{name:string,status:string,pct:?float,speed_bps:?int,eta_secs:?int,error:string}>,proxy_pool:array{total:int,by_status:array<string,int>,stalest_check_s:?int}} */
function diagnostics_data(): array {
    $orders = [];
    $expiringSoon = 0;
    $photos = 0;
    try {
        $db = get_db();
        foreach ($db->query('SELECT status, COUNT(*) AS n FROM orders GROUP BY status')->fetchAll() as $r) {
            $orders[(string)$r['status']] = (int)$r['n'];
        }
        $st = $db->prepare("SELECT COUNT(*) FROM orders WHERE status = 'preparing' AND expires_at IS NOT NULL AND expires_at < ?");
        $st->execute([date('Y-m-d H:i:s', time() + 86400)]);
        $expiringSoon = (int)$st->fetchColumn();
        $photos = (int)$db->query('SELECT COUNT(*) FROM order_photos')->fetchColumn();
    } catch (Throwable) {
    }
    $uploads = _diag_dir_usage(dirname(__DIR__) . '/uploads');
    $zones = [];
    foreach (maps_zone_list() as $z) {
        if (!is_array($z)) {
            continue;
        }
        $exp = (int)($z['bytes_expected'] ?? 0);
        $done = (int)($z['bytes_done'] ?? 0);
        $zones[] = [
            'name' => (string)($z['name'] ?? '?'),
            'status' => (string)($z['status'] ?? '?'),
            'pct' => $exp > 0 ? round($done / $exp * 100, 1) : null,
            'speed_bps' => isset($z['speed_bps']) ? (int)$z['speed_bps'] : null,
            'eta_secs' => isset($z['eta_secs']) ? (int)$z['eta_secs'] : null,
            'error' => (string)($z['error'] ?? ''),
        ];
    }
    $pool = ['total' => 0, 'by_status' => [], 'stalest_check_s' => null];
    $now = time();
    foreach (osm_proxy_pool() as $p) {
        if (!is_array($p)) {
            continue;
        }
        $pool['total']++;
        $s = (string)($p['last_status'] ?? '?');
        $pool['by_status'][$s] = ($pool['by_status'][$s] ?? 0) + 1;
        $lc = is_string($p['last_checked'] ?? null) ? strtotime((string)$p['last_checked']) : false;
        if ($lc !== false) {
            $age = $now - (int)$lc;
            if ($pool['stalest_check_s'] === null || $age > $pool['stalest_check_s']) {
                $pool['stalest_check_s'] = $age;
            }
        }
    }
    return [
        'orders_by_status' => $orders, 'orders_expiring_24h' => $expiringSoon,
        'photos' => $photos, 'uploads' => $uploads,
        'zones' => $zones, 'proxy_pool' => $pool,
    ];
}

/**
 * Bounded recursive size walk; flags truncation instead of lying.
 * @return array{ok:true,bytes:int,files:int,truncated:bool}|array{ok:false,error:string}
 */
function _diag_dir_usage(string $dir): array {
    $bytes = 0;
    $files = 0;
    $truncated = false;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $f) {
            if ($files >= DIAGNOSTICS_DU_MAX_FILES) {
                $truncated = true;
                break;
            }
            if ($f->isFile()) {
                $files++;
                $bytes += $f->getSize();
            }
        }
    } catch (Throwable) {
        return ['ok' => false, 'error' => 'unavailable'];
    }
    return ['ok' => true, 'bytes' => $bytes, 'files' => $files, 'truncated' => $truncated];
}

// ── Backups (freshness is the metric: a backup system with no recent bundle ─
// ── is how dead hosts happen) ───────────────────────────────────────────────

/** @return array{count:int,total_bytes:int,latest:?array{name:string,format:string,size:int,mtime:int},zip_supported:bool} */
function diagnostics_backups(): array {
    $list = backup_list();
    $latest = $list[0] ?? null;
    $total = 0;
    foreach ($list as $b) {
        $total += (int)($b['size'] ?? 0);
    }
    return [
        'count' => count($list),
        'total_bytes' => $total,
        'latest' => $latest !== null ? [
            'name' => (string)$latest['name'], 'format' => (string)$latest['format'],
            'size' => (int)$latest['size'], 'mtime' => (int)$latest['mtime'],
        ] : null,
        'zip_supported' => backup_zip_supported(),
    ];
}
