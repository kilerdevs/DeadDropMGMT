<?php
declare(strict_types=1);
require_once __DIR__ . '/capabilities.php';

// First-run / restricted-host diagnostics and schema installer.
//
// Cheap shared hosting fails in ways the app otherwise answers with a bare
// 503 or a stuck queue: revoked SET/LOCK privileges, unwritable default
// session or log paths, a missing AES key, no CREATE DATABASE privilege.
// The checks below name each of those (and every runtime capability the
// proxy/maps engines need) so admin/setup_check.php renders them instead of
// leaving the owner guessing. Pure functions over the live host — the page
// is thin glue, and everything here is unit-testable without HTTP.

// Every table setup.sql manages. The schema check counts these; the engine
// check insists on InnoDB for all of them (transactions and row locks the
// rate limiter and order state depend on are MyISAM no-ops).
const SETUP_TABLES = [
    'users', 'orders', 'order_photos', 'osm_proxies', 'map_zones',
    'order_events', 'rate_limits', 'audit_log', 'settings', 'log_checkpoints',
];

// One diagnostic row: literal machine-readable id + label, a status, and a
// detail that is empty when everything is fine (only problems get prose,
// which is why the lang-key count stays small).
/** @return array{id:string,label:string,status:string,detail:string} */
function setup_row(string $id, string $label, string $status, string $detail = ''): array {
    return ['id' => $id, 'label' => $label, 'status' => $status, 'detail' => $detail];
}

// ── Runtime: PHP, extensions, functions ─────────────────────────────────────

// PHP version, required extensions, transports, and process control — no DB
// needed. Every row is one capability_definitions() entry evaluated with the
// live host probes, so the installer, this page and the hosting doctor name
// the same fallbacks (admin.cap.<id>). Quantitative infos (max_time) stay
// bespoke below: they are measurements, not capabilities.
function setup_runtime_checks(): array {
    $eval = [];
    foreach (capabilities_evaluate(capabilities_live_env()) as $row) {
        $eval[$row['id']] = $row;
    }
    $out = [];
    foreach (['php', 'pdo_mysql', 'mbstring', 'zlib', 'openssl', 'curl', 'tls',
              'zip', 'exec', 'proc_open', 'jobs', 'env', 'set_time_limit'] as $id) {
        $row = $eval[$id];
        $status = capabilities_consumer_status($row);
        $label = $row['label'];
        $params = [];
        if ($id === 'php') {
            $label .= ' ' . PHP_VERSION;
            $params = ['v' => PHP_VERSION];
        } elseif (str_starts_with($id, 'pdo_') || in_array($id, ['mbstring', 'zlib', 'openssl', 'curl'], true)) {
            $label .= ' ' . (string)phpversion($id === 'curl' ? 'curl' : $id);
        } elseif ($id === 'zip' && $row['state'] === 'limited') {
            $label .= ' via unzip binary';
            $params = ['bin' => $row['note']];
        }
        $detail = $status === 'ok' ? '' : t($row['fallback'], $params);
        // Row ids are the historic ones (ext_<name> for extensions, bare
        // capability name otherwise) — tests and the doctor rely on them.
        $rowId = ($id === 'php' || in_array($id, ['tls', 'zip', 'exec', 'proc_open', 'jobs', 'env', 'set_time_limit'], true))
            ? $id : 'ext_' . $id;
        $out[] = setup_row($rowId, $label, $status, $detail);
    }
    $out[] = sprintf('max_execution_time=%s', (string)@ini_get('max_execution_time')) === 'max_execution_time='
        ? setup_row('max_time', 'max_execution_time', 'info')
        : setup_row('max_time', 'max_execution_time=' . (string)@ini_get('max_execution_time'), 'info');
    return $out;
}

// ── Storage: writable dirs, sessions, AES key, webserver ───────────────────

// Directories the app writes at runtime. Check-only: never mkdir here, so a
// permissions problem is reported, not masked.
function setup_storage_checks(): array {
    $root = dirname(__DIR__);
    $out = [];
    foreach ([
        'logs' => $root . '/logs',
        'cache/osm_tiles' => $root . '/cache/osm_tiles',
        'tiles' => $root . '/tiles',
        'data/maps' => $root . '/data/maps',
        'uploads' => $root . '/uploads',
    ] as $label => $dir) {
        $out[] = is_writable($dir)
            ? setup_row('dir_' . $label, $label, 'ok')
            : setup_row('dir_' . $label, $label, 'fail', t('admin.setupcheck.dir_ro', ['dir' => $label]));
    }
    // Session path (#11's probe, shared with auth.php): the default is only
    // replaced where it is actually unusable, and this row says which won.
    $sp = session_effective_path();
    $out[] = (is_dir($sp) && is_writable($sp))
        ? setup_row('sessions', 'sessions: ' . $sp, 'ok')
        : setup_row('sessions', 'sessions', 'fail', t('admin.setupcheck.dir_ro', ['dir' => $sp]));
    $out[] = preg_match('/^[0-9a-fA-F]{64}$/', AES_KEY_HEX) === 1
        ? setup_row('aes_key', 'AES-256-GCM key', 'ok')
        : setup_row('aes_key', 'AES key', 'fail', t('admin.setupcheck.key_bad'));
    $out[] = setup_webserver_row($_SERVER['SERVER_SOFTWARE'] ?? '');
    // The compose files' published fallbacks: fine while the database has no
    // exposed port, but anyone reading this repo knows them.
    // constant(): the value is deployment data, not the template's literal.
    $dbPass = defined('DB_PASS') ? (string)constant('DB_PASS') : '';
    if (in_array($dbPass, ['deaddrop-db', 'deaddrop-root'], true)) {
        $out[] = setup_row('db_pass', 'database password', 'warn', t('admin.setupcheck.db_default_pass'));
    }
    return $out;
}

// .htaccess protects includes/, logs/, setup.sql and friends — but only on
// Apache. Anywhere else the owner must apply the nginx snippet (docs/).
// The root file's directory rules need mod_rewrite, so every private folder
// also carries its own deny file; a missing one is reported by name.
const SETUP_DENY_FILES = ['includes/.htaccess', 'logs/.htaccess', 'tools/.htaccess', 'cron/.htaccess',
    'data/.htaccess', 'cache/.htaccess', 'backups/.htaccess'];
function setup_webserver_row(string $software, ?string $root = null): array {
    $root ??= dirname(__DIR__);
    if (is_file($root . '/.htaccess') && stripos($software, 'apache') !== false) {
        $missing = array_values(array_filter(SETUP_DENY_FILES, static fn(string $f): bool => !is_file($root . '/' . $f)));
        return $missing === []
            ? setup_row('htaccess', '.htaccess', 'ok')
            : setup_row('htaccess', '.htaccess', 'warn', t('admin.setupcheck.deny_missing', ['files' => implode(', ', $missing)]));
    }
    if (stripos($software, 'apache') !== false) {
        return setup_row('htaccess', '.htaccess', 'warn', t('admin.setupcheck.dir_ro', ['dir' => '.htaccess']));
    }
    return setup_row('htaccess', $software !== '' ? $software : 'web server', 'warn', t('admin.setupcheck.not_apache'));
}

// ── Database: connect probe (never dies), schema, engines, zone ────────────

// Connect with the configured constants but WITHOUT get_db()'s 503: a setup
// page that dies on a bad DB_NAME cannot diagnose a bad DB_NAME.
function setup_db_probe(): array {
    try {
        $pdo = db_connect(
            sprintf('mysql:host=%s;port=%s;dbname=%s;charset=%s', DB_HOST, DB_PORT, DB_NAME, DB_CHARSET),
            DB_USER, DB_PASS, db_options(DB_SSL_CA, DB_SSL_CERT, DB_SSL_KEY, DB_SSL_VERIFY)
        );
    } catch (PDOException $e) {
        return ['connected' => false, 'error' => $e->getMessage(), 'pdo' => null,
                'zone' => null, 'tables' => [], 'engines' => [], 'owner_exists' => false,
                'owner_known' => false, 'grants' => null];
    }
    $zone = null;
    try {
        $zone = $pdo->query('SELECT @@session.time_zone')->fetchColumn();
    } catch (Throwable) {
    }
    $tables = [];
    $engines = [];
    $tablesRead = false;
    try {
        $rows = $pdo->query(
            'SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()'
        )->fetchAll();
        foreach ($rows as $r) {
            $tables[] = $r['TABLE_NAME'];
            $engines[$r['TABLE_NAME']] = strtoupper((string)$r['ENGINE']);
        }
        $tablesRead = true;
    } catch (Throwable) {
    }
    // owner_known: the answer is positively established — the count ran, or
    // the users table verifiably does not exist yet (fresh install). A failed
    // query is NOT "no owner": the page would go public on an installed app.
    $owner = false;
    $known = $tablesRead && !in_array('users', $tables, true);
    try {
        $owner = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'owner'")->fetchColumn() > 0;
        $known = true;
    } catch (Throwable) {
    }
    // Read-only privilege census for the forced-name panel case: SHOW GRANTS
    // reveals only the caller's own privileges, and a failed call (revoked
    // SHOW, proxied frontend) conservatively reads as restricted — the
    // no-CREATE path works either way, so the row informs, never blocks.
    $grants = null;
    try {
        $g = $pdo->query('SHOW GRANTS');
        if ($g instanceof PDOStatement) {
            $grants = implode("\n", array_map('strval', $g->fetchAll(PDO::FETCH_COLUMN)));
        }
    } catch (Throwable) {
    }
    return ['connected' => true, 'error' => '', 'pdo' => $pdo,
            'zone' => is_string($zone) ? $zone : null, 'tables' => $tables,
            'engines' => $engines, 'owner_exists' => $owner, 'owner_known' => $known,
            'grants' => $grants];
}

// Rows for the Database section from a probe above.
function setup_db_rows(array $probe): array {
    if (!$probe['connected']) {
        return [setup_row('db', 'database', 'fail', t('admin.setupcheck.db_down', ['error' => $probe['error']]))];
    }
    $out = [setup_row('db', 'database ' . DB_NAME, 'ok')];
    $zone = $probe['zone'];
    if ($zone !== null && $zone !== '+00:00') {
        // #1's fallback in action: the app runs, but DB-side NOW() windows
        // skew against PHP's UTC. Loud here, not fatal anywhere.
        $out[] = setup_row('db_zone', 'session time_zone=' . $zone, 'warn', t('admin.setupcheck.db_zone', ['zone' => $zone]));
    }
    $missing = array_values(array_diff(SETUP_TABLES, $probe['tables']));
    if ($missing !== []) {
        $out[] = setup_row('schema', 'schema', 'fail', t('admin.setupcheck.schema_missing', [
            'n' => (string)count($missing), 'm' => (string)count(SETUP_TABLES),
        ]));
    } else {
        $out[] = setup_row('schema', count(SETUP_TABLES) . '/' . count(SETUP_TABLES) . ' tables', 'ok');
    }
    $wrong = [];
    foreach (SETUP_TABLES as $tbl) {
        $eng = $probe['engines'][$tbl] ?? null; // stored upper-cased by the probe
        if ($eng !== null && $eng !== 'INNODB') {
            $wrong[] = $tbl . ':' . $eng;
        }
    }
    if ($wrong !== []) {
        $out[] = setup_row('engines', 'table engines', 'fail', t('admin.setupcheck.engines', ['tables' => implode(', ', $wrong)]));
    }
    // Forced-name panel accounts (user_xxx, no CREATE DATABASE) are normal:
    // the schema applies into the existing database either way, so this row
    // names the situation and its non-action instead of failing it.
    $dc = capability_row('db_create', ['grants' => $probe['grants'] ?? null]);
    if ($dc !== null) {
        $dcStatus = capabilities_consumer_status($dc);
        $out[] = setup_row('db_create', $dc['label'], $dcStatus,
            $dcStatus === 'ok' ? '' : t($dc['fallback']));
    }
    return $out;
}

// ── Schema installer ────────────────────────────────────────────────────────
// setup.sql targets a privileged one-shot import (CREATE DATABASE + USE). A
// panel user has neither privilege nor the hardcoded name — so the installer
// connects to the configured DB_NAME (already created in the panel) and
// applies every statement EXCEPT those two lines. Same splitter the test
// loader uses; statements are ;-terminated with no DELIMITER blocks or
// semicolons inside string literals, so a plain split is safe.

/** @return list<string> executable statement bodies.
 * CREATE DATABASE is privileged-install only ($keepCreate); USE is always
 * stripped — the connection already targets the right database, and replaying
 * setup.sql's hardcoded name would switch away from panel-prefixed ones. */
function schema_statements(string $sql, bool $keepCreate = false): array {
    $out = [];
    foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
        $body = implode("\n", array_filter(
            explode("\n", $stmt),
            static fn(string $l): bool => trim($l) !== '' && !str_starts_with(ltrim($l), '--')
        ));
        if ($body === '' || preg_match('/^USE\s+/i', $body) === 1) {
            continue;
        }
        if (str_starts_with($body, 'CREATE DATABASE') && !$keepCreate) {
            continue;
        }
        $out[] = $body;
    }
    return $out;
}

// Runs the statements with full result-set draining (setup.sql's
// PREPARE/EXECUTE guard blocks leave live results behind otherwise).
/** @return array{applied:int,error:string,statement:string} error empty on success */
function schema_apply(PDO $pdo, array $statements): array {
    $applied = 0;
    foreach ($statements as $body) {
        try {
            $st = $pdo->query($body);
            if ($st instanceof PDOStatement) {
                while ($st->nextRowset()) { /* drain */ }
                $st->closeCursor();
            }
            $applied++;
        } catch (PDOException $e) {
            return ['applied' => $applied, 'error' => $e->getMessage(), 'statement' => $body];
        }
    }
    return ['applied' => $applied, 'error' => '', 'statement' => ''];
}
