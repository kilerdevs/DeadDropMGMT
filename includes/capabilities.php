<?php
declare(strict_types=1);

// ── Host capability registry: one source of truth ────────────────────────────
// Free shared hosting fails in specific, repeatable ways (no cURL, no exec,
// no zip, no cron, no env vars, forced user_xxx database names, a disabled
// set_time_limit) — and every one of those has an exact automatic fallback
// except the ones that don't (TLS, the database driver). Three different
// surfaces used to probe them independently and drift apart: the standalone
// web installer (tools/install.php, which can never load the kernel —
// KernelTest pins that), the setup check (includes/setup_check.php), and the
// Settings hosting panel (includes/host.php). This file is the contract they
// all evaluate:
//
//   capability_definitions() — the full table: id, technical label, probe
//       key, whether a missing capability BLOCKS the install (required),
//       the warn/info severity a degraded-but-working capability renders
//       with (soft), and the lang key of the sentence that names the exact
//       fallback (admin.cap.<id>).
//   capabilities_evaluate($env) — pure function of an explicit probe-result
//       map (no live detection inside, no side effects), so every hostile
//       host in the request is a unit test with an injected $env.
//   capabilities_consumer_status($row) — the ok/fail/warn/info word the
//       installer and the setup check render for an evaluated row.
//   capabilities_grants_allow_create($grants) — conservative SHOW GRANTS
//       parse (read-only input): only an explicit global CREATE privilege
//       answers true; anything unclear assumes a restricted panel account,
//       which is the safe direction because the no-CREATE path always works.
//
// Deliberate non-goals: quantitative rows (disk free, upload caps, memory,
// max_execution_time) are measurements, not capabilities, and stay with their
// current owners. And there is NO insecure fallback anywhere in this table:
// a missing TLS transport is `required` (blocked), never "limited" —
// plain-HTTP fallback is not offered, on purpose.

// Canonical evaluated states: ok (present), limited (absent or degraded but
// the automatic fallback covers it), missing (absent with no fallback).
// Consumers map missing via `required`: required → fail/blocked, else soft.

/** @return list<array{id:string,label:string,probe:string,required:bool,soft:string,fallback:string}> */
function capability_definitions(): array {
    return [
        ['id' => 'php', 'label' => 'PHP', 'probe' => 'php', 'required' => true, 'soft' => 'warn',
            'fallback' => 'admin.cap.php'],
        ['id' => 'pdo_mysql', 'label' => 'pdo_mysql', 'probe' => 'pdo_mysql', 'required' => true, 'soft' => 'warn',
            'fallback' => 'admin.cap.pdo_mysql'],
        ['id' => 'mbstring', 'label' => 'mbstring', 'probe' => 'mbstring', 'required' => true, 'soft' => 'warn',
            'fallback' => 'admin.cap.mbstring'],
        ['id' => 'zlib', 'label' => 'zlib', 'probe' => 'zlib', 'required' => false, 'soft' => 'warn',
            'fallback' => 'admin.cap.zlib'],
        ['id' => 'openssl', 'label' => 'openssl', 'probe' => 'openssl', 'required' => false, 'soft' => 'warn',
            'fallback' => 'admin.cap.openssl'],
        ['id' => 'curl', 'label' => 'cURL', 'probe' => 'curl', 'required' => false, 'soft' => 'info',
            'fallback' => 'admin.cap.curl'],
        ['id' => 'tls', 'label' => 'HTTPS transport', 'probe' => 'tls', 'required' => true, 'soft' => 'warn',
            'fallback' => 'admin.cap.tls'],
        ['id' => 'zip', 'label' => 'ZipArchive / unzip', 'probe' => 'zip', 'required' => true, 'soft' => 'warn',
            'fallback' => 'admin.cap.zip'],
        ['id' => 'exec', 'label' => 'exec', 'probe' => 'exec', 'required' => false, 'soft' => 'info',
            'fallback' => 'admin.cap.exec'],
        ['id' => 'proc_open', 'label' => 'proc_open', 'probe' => 'proc_open', 'required' => false, 'soft' => 'info',
            'fallback' => 'admin.cap.proc_open'],
        ['id' => 'jobs', 'label' => 'background jobs', 'probe' => 'jobs', 'required' => false, 'soft' => 'warn',
            'fallback' => 'admin.cap.jobs'],
        ['id' => 'env', 'label' => 'env vars (DDMGMT_*)', 'probe' => 'env', 'required' => false, 'soft' => 'info',
            'fallback' => 'admin.cap.env'],
        ['id' => 'db_create', 'label' => 'CREATE DATABASE privilege', 'probe' => 'db_create', 'required' => false, 'soft' => 'info',
            'fallback' => 'admin.cap.db_create'],
        ['id' => 'set_time_limit', 'label' => 'set_time_limit', 'probe' => 'set_time_limit', 'required' => false, 'soft' => 'warn',
            'fallback' => 'admin.cap.set_time_limit'],
        ['id' => 'dirs', 'label' => 'writable dirs', 'probe' => 'dirs', 'required' => true, 'soft' => 'warn',
            'fallback' => 'admin.cap.dirs'],
        ['id' => 'sessions', 'label' => 'session path', 'probe' => 'sessions', 'required' => false, 'soft' => 'warn',
            'fallback' => 'admin.cap.sessions'],
        ['id' => 'htaccess', 'label' => '.htaccess / webserver', 'probe' => 'htaccess', 'required' => false, 'soft' => 'warn',
            'fallback' => 'admin.cap.htaccess'],
    ];
}

// Probe-result map keys (every key optional; absent keys take the safe
// default documented per probe — callers that cannot measure something pass
// nothing and get the conservative answer):
//   php_version: string (default PHP_VERSION) | ext: array<string,bool>
//   curl, sockets, zip_ext, exec, proc_open, set_time_limit: bool
//   unzip_bin: ?string path | detach, putenv_ok: bool | grants: ?string
//   dirs: array<string,bool> label => writable | session_path: string,
//   session_writable: bool | server_sw: string, htaccess_ok: bool
//
/**
 * @param array{php_version?:string,ext?:array<string,bool>,curl?:bool,sockets?:bool,zip_ext?:bool,unzip_bin?:?string,exec?:bool,proc_open?:bool,detach?:bool,putenv_ok?:bool,grants?:?string,dirs?:array<string,bool>,session_path?:string,session_writable?:bool,server_sw?:string,htaccess_ok?:bool,set_time_limit?:bool} $env
 * @return list<array{id:string,label:string,state:string,required:bool,soft:string,fallback:string,note:string}>
 */
function capabilities_evaluate(array $env): array {
    $ext = $env['ext'] ?? [];
    $ex = static fn(string $e): bool => (bool)($ext[$e] ?? false);
    $curl = (bool)($env['curl'] ?? false);
    $out = [];
    foreach (capability_definitions() as $def) {
        $state = 'ok';
        $soft = $def['soft'];
        $note = '';
        switch ($def['probe']) {
            case 'php':
                $state = version_compare((string)($env['php_version'] ?? PHP_VERSION), '8.2.0', '>=') ? 'ok' : 'missing';
                break;
            case 'pdo_mysql':
            case 'mbstring':
            case 'zlib':
                $state = $ex($def['probe']) ? 'ok' : ($def['required'] ? 'missing' : 'limited');
                break;
            case 'openssl':
                if ($ex('openssl')) {
                    $state = 'ok';
                } else {
                    // Missing openssl only matters where cURL is also absent
                    // (the socket engine needs it for HTTPS); with cURL the
                    // row is purely informational.
                    $state = 'limited';
                    $soft = $curl ? 'info' : 'warn';
                }
                break;
            case 'curl':
                $state = $curl ? 'ok' : 'limited';
                break;
            case 'tls':
                $sockets = (bool)($env['sockets'] ?? false);
                $state = ($curl || ($sockets && $ex('openssl'))) ? 'ok' : 'missing';
                break;
            case 'zip':
                if ((bool)($env['zip_ext'] ?? false)) {
                    $state = 'ok';
                } elseif (is_string($env['unzip_bin'] ?? null) && ($env['unzip_bin'] ?? '') !== '') {
                    $state = 'limited';
                    $note = (string)$env['unzip_bin'];
                } else {
                    $state = 'missing';
                }
                break;
            case 'exec':
            case 'proc_open':
            case 'set_time_limit':
                $state = (bool)($env[$def['probe']] ?? false) ? 'ok' : 'limited';
                break;
            case 'jobs':
                $state = (bool)($env['detach'] ?? false) ? 'ok' : 'limited';
                break;
            case 'env':
                $state = (bool)($env['putenv_ok'] ?? false) ? 'ok' : 'limited';
                break;
            case 'db_create':
                $state = capabilities_grants_allow_create(
                    array_key_exists('grants', $env) ? $env['grants'] : null
                ) ? 'ok' : 'limited';
                break;
            case 'dirs':
                $dirs = $env['dirs'] ?? [];
                $bad = [];
                foreach ($dirs as $label => $writable) {
                    if (!$writable) {
                        $bad[] = (string)$label;
                    }
                }
                if ($bad !== []) {
                    $state = 'missing';
                    $note = implode(', ', $bad);
                }
                break;
            case 'sessions':
                $state = (bool)($env['session_writable'] ?? false) ? 'ok' : 'limited';
                $note = (string)($env['session_path'] ?? '');
                break;
            case 'htaccess':
                $sw = (string)($env['server_sw'] ?? '');
                $state = (stripos($sw, 'apache') !== false && (bool)($env['htaccess_ok'] ?? false)) ? 'ok' : 'limited';
                $note = $sw !== '' ? $sw : 'web server';
                break;
        }
        $out[] = ['id' => $def['id'], 'label' => $def['label'], 'state' => $state,
                  'required' => $def['required'], 'soft' => $soft,
                  'fallback' => $def['fallback'], 'note' => $note];
    }
    return $out;
}

// Locate the Info-ZIP `unzip` binary through whichever process function the
// host still allows (same rule as the installer's ix_unzip_bin, which mirrors
// this standalone-file-incompatible helper): only proc_open/exec qualify —
// shell_exec reports no exit code, and a silent half-extract is worse than a
// clear error. Pure builtins, no side effects; null when nothing can run it.
// NEVER throws.
function capabilities_find_unzip(): ?string {
    $canRun = false;
    foreach (['proc_open', 'exec'] as $fn) {
        if (!function_exists($fn)) {
            continue;
        }
        $disabled = array_map('trim', explode(',', (string)(function_exists('ini_get') ? @ini_get('disable_functions') : '')));
        if (!in_array($fn, $disabled, true)) {
            $canRun = true;
            break;
        }
    }
    if (!$canRun) {
        return null;
    }
    $path = function_exists('getenv') ? (string)@getenv('PATH') : '';
    if ($path !== '') {
        $exe = 'unzip' . (DIRECTORY_SEPARATOR === '\\' ? '.exe' : '');
        foreach (explode(PATH_SEPARATOR, $path) as $d) {
            $c = rtrim($d, '/\\') . DIRECTORY_SEPARATOR . $exe;
            if ($c !== $exe && is_file($c)) {
                return $c;
            }
        }
    }
    foreach (['/usr/bin/unzip', '/bin/unzip', '/usr/local/bin/unzip'] as $c) {
        if (is_file($c)) {
            return $c;
        }
    }
    return null;
}

// One evaluated row by id (unknown ids answer null). Convenience over
// capabilities_evaluate() for consumers that own the rest of their table
// (the setup schema section, the installer's dbtest step).
/**
 * @param array{php_version?:string,ext?:array<string,bool>,curl?:bool,sockets?:bool,zip_ext?:bool,unzip_bin?:?string,exec?:bool,proc_open?:bool,detach?:bool,putenv_ok?:bool,grants?:?string,dirs?:array<string,bool>,session_path?:string,session_writable?:bool,server_sw?:string,htaccess_ok?:bool,set_time_limit?:bool} $env
 * @return ?array{id:string,label:string,state:string,required:bool,soft:string,fallback:string,note:string}
 */
function capability_row(string $id, array $env): ?array {
    foreach (capabilities_evaluate($env) as $row) {
        if ($row['id'] === $id) {
            return $row;
        }
    }
    return null;
}

// Installer / setup-check word for an evaluated row: ok stays ok, a covered
// degradation renders with its soft severity, and only a required capability
// with no fallback renders fail.
/**
 * @param array{id:string,label:string,state:string,required:bool,soft:string,fallback:string,note:string} $row
 */
function capabilities_consumer_status(array $row): string {
    if ($row['state'] === 'ok') {
        return 'ok';
    }
    if ($row['state'] === 'limited') {
        return $row['soft'];
    }
    return $row['required'] ? 'fail' : $row['soft'];
}

// Conservative SHOW GRANTS parse: true only on an explicit global CREATE
// privilege (ALL PRIVILEGES, or GRANT ... CREATE ... ON *.*). Anything else
// — a scoped grant, a failed SHOW GRANTS (null), an unparsable line —
// answers false, i.e. "assume a restricted panel account": the safe
// direction, because the no-CREATE path (apply into the existing database,
// CREATE DATABASE skipped) always works. NEVER throws.
function capabilities_grants_allow_create(mixed $grants): bool {
    if (!is_string($grants) || $grants === '') {
        return false;
    }
    foreach (explode("\n", strtoupper($grants)) as $line) {
        $line = trim($line);
        if (!str_starts_with($line, 'GRANT')) {
            continue;
        }
        if (str_contains($line, 'ALL PRIVILEGES')) {
            return true;
        }
        // GRANT SELECT, ..., CREATE, ... ON *.* TO ... — the ON *.* scope
        // is what makes it a database-creation privilege rather than e.g.
        // CREATE VIEW inside one schema.
        if (preg_match('/\bCREATE\b/', $line) === 1 && str_contains($line, 'ON *.*')) {
            return true;
        }
    }
    return false;
}
