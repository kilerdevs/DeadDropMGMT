<?php
declare(strict_types=1);

// ── Build provenance (Settings → Version, owners only) ───────────────────────
// The Docker image carries no .git, so the build host records what it builds
// (tools/build_info.sh: `git describe` against the v* release tags, commit,
// branch — never the commit message) and the Dockerfiles store the JSON outside the
// docroot. This file only reads and interprets it — it never runs git and
// never reaches the network.
//
// A build is a RELEASE when it sits exactly on a v* tag with a clean tree.
// Anything else — commits after the last tag (a build from dev), a dirty
// tree, or a build with no tag to compare against — is a BETA. A build with
// no provenance file at all falls back to DDMGMT_BUNDLED_VERSION below
// (still BETA — a checkout cannot certify a release), so Settings names a
// version instead of "unknown build" even where .git did not survive.
//
// Everything in the file is treated as untrusted text (validated here,
// escaped at output): it is written at build time, but a corrupt or edited
// file must not be able to inject markup or an oversized string.

const DDMGMT_BUILD_INFO_FILE = '/usr/local/share/ddmgmt-build.json';

// Version baked into the shipped code. Bump on every release, in the same
// commit as the CHANGELOG cut — it is the fallback Settings shows when no
// build-info.json exists (plain `docker build` without build args, a git
// checkout with no tags, or a release zip: none of them carry .git, so
// `git describe` cannot run where the app runs). A checkout can never prove
// it sits exactly on a tag with a clean tree, so the bundled line always
// renders as BETA — it names the version, it does not certify the release.
const DDMGMT_BUNDLED_VERSION = '1.6.2';

/**
 * Interpret one provenance document. Pure — no I/O.
 *
 * @return array{known:bool,release:bool,beta:bool,version:?string,ahead:int,commit:?string,branch:?string,dirty:bool}
 */
function build_info_parse(string $json): array {
    $none = [
        'known' => false, 'release' => false, 'beta' => false, 'version' => null,
        'ahead' => 0, 'commit' => null, 'branch' => null, 'dirty' => false,
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
    $dirty = ($d['dirty'] ?? false) === true;

    if ($version === null && $commit === null) {
        return $none; // nothing usable in the file
    }
    $release = $version !== null && $ahead === 0 && !$dirty;
    return [
        'known' => true, 'release' => $release, 'beta' => !$release, 'version' => $version,
        'ahead' => $ahead, 'commit' => $commit, 'branch' => $branch,
        'dirty' => $dirty,
    ];
}

/**
 * Provenance of the running build (read once per request).
 * @return array{known:bool,release:bool,beta:bool,version:?string,ahead:int,commit:?string,branch:?string,dirty:bool}
 */
function build_info(): array {
    static $info = null;
    if ($info === null) {
        // Docker image, then a build-info.json next to the app (non-Docker
        // installs: `tools/build_info.sh --write`, or shipped with a release).
        $raw = false;
        foreach ([getenv('DDMGMT_BUILD_INFO_FILE') ?: DDMGMT_BUILD_INFO_FILE, dirname(__DIR__) . '/build-info.json'] as $path) {
            if (is_file($path) && is_readable($path)) {
                $raw = @file_get_contents($path, false, null, 0, 4096);
                if (is_string($raw)) {
                    break;
                }
            }
        }
        if (is_string($raw)) {
            $info = build_info_parse($raw);
        } elseif (preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/', DDMGMT_BUNDLED_VERSION) === 1) {
            // No provenance file at all: name the bundled version instead of
            // "unknown build". Always BETA (see the const) — known version,
            // no commit/branch to show.
            $info = [
                'known' => true, 'release' => false, 'beta' => true, 'version' => DDMGMT_BUNDLED_VERSION,
                'ahead' => 0, 'commit' => null, 'branch' => null, 'dirty' => false,
            ];
        } else {
            $info = build_info_parse('');
        }
    }
    return $info;
}

/**
 * Cache-buster for first-party static files: the file's mtime, so a deploy
 * (or any edit) changes the <script>/<link> URL and browsers fetch the new
 * copy instead of serving a stale cached one (an admin once got new CSS
 * with old admin.js after an update). 0 when unreadable — the URL still
 * works, it just doesn't bust.
 */
function asset_ver(string $path): int {
    if (!str_starts_with($path, '/') || str_contains($path, '..')) {
        return 0;
    }
    $t = @filemtime(dirname(__DIR__) . $path);
    return $t === false ? 0 : (int)$t;
}

function admin_css_ver(): int {
    return asset_ver('/admin/style.css');
}
