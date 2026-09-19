<?php
declare(strict_types=1);

// ── Build provenance (Settings → Version, owners only) ───────────────────────
// The Docker image carries no .git, so the build host records what it builds
// (tools/build_info.sh: `git describe` against the v* release tags, commit,
// branch, commit subject) and the Dockerfiles store the JSON outside the
// docroot. This file only reads and interprets it — it never runs git and
// never reaches the network.
//
// A build is a RELEASE when it sits exactly on a v* tag with a clean tree.
// Anything else — commits after the last tag (a build from dev), a dirty
// tree, or a build with no tag to compare against — is a BETA. A build with
// no provenance file at all is "unknown": no claim either way.
//
// Everything in the file is treated as untrusted text (validated here,
// escaped at output): it is written at build time, but a corrupt or edited
// file must not be able to inject markup or an oversized string.

const DDMGMT_BUILD_INFO_FILE = '/usr/local/share/ddmgmt-build.json';

/**
 * Interpret one provenance document. Pure — no I/O.
 *
 * @return array{known:bool,release:bool,beta:bool,version:?string,ahead:int,commit:?string,subject:?string,branch:?string,dirty:bool}
 */
function build_info_parse(string $json): array {
    $none = [
        'known' => false, 'release' => false, 'beta' => false, 'version' => null,
        'ahead' => 0, 'commit' => null, 'subject' => null, 'branch' => null, 'dirty' => false,
    ];
    $d = json_decode($json, true, 4);
    if (!is_array($d)) {
        return $none;
    }

    $version = null;
    $ahead   = 0;
    $describe = is_string($d['describe'] ?? null) ? $d['describe'] : '';
    // `git describe --long`: v1.5.0-8-g610eff7 (8 commits after v1.5.0).
    if (preg_match('/^v(\d{1,4}\.\d{1,4}\.\d{1,4})-(\d{1,6})-g[0-9a-f]{4,40}$/', $describe, $m) === 1) {
        $version = $m[1];
        $ahead   = (int)$m[2];
    }

    $commit = is_string($d['commit'] ?? null) && preg_match('/^[0-9a-f]{7,40}$/', $d['commit']) === 1
        ? substr($d['commit'], 0, 7) : null;
    $branch = is_string($d['branch'] ?? null) && preg_match('/^[A-Za-z0-9._\/-]{1,64}$/', $d['branch']) === 1
        ? $d['branch'] : null;
    $subject = null;
    if (is_string($d['subject'] ?? null)) {
        $s = trim((string)preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $d['subject']));
        $subject = $s === '' ? null : mb_substr($s, 0, 100, 'UTF-8');
    }
    $dirty = ($d['dirty'] ?? false) === true;

    if ($version === null && $commit === null) {
        return $none; // nothing usable in the file
    }
    $release = $version !== null && $ahead === 0 && !$dirty;
    return [
        'known' => true, 'release' => $release, 'beta' => !$release, 'version' => $version,
        'ahead' => $ahead, 'commit' => $commit, 'subject' => $subject, 'branch' => $branch,
        'dirty' => $dirty,
    ];
}

/** Provenance of the running build (read once per request). */
function build_info(): array {
    static $info = null;
    if ($info === null) {
        $path = getenv('DDMGMT_BUILD_INFO_FILE') ?: DDMGMT_BUILD_INFO_FILE;
        $raw = is_file($path) && is_readable($path) ? @file_get_contents($path, false, null, 0, 4096) : false;
        $info = build_info_parse(is_string($raw) ? $raw : '');
    }
    return $info;
}
