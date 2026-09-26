<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/includes/kernel.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

// ── POST handlers — all use PRG to prevent resubmission on back/refresh ──────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $_SESSION['flash']    = t('admin.common.invalid_csrf');
        $_SESSION['flash_ok'] = false;
    } elseif (($_POST['action'] ?? '') === 'clear_analytics') {
        try {
            get_db()->exec('TRUNCATE TABLE order_events');
            audit('analytics_clear');
            $_SESSION['flash']    = t('admin.settings.flash.analytics_cleared');
            $_SESSION['flash_ok'] = true;
        } catch (Exception $e) {
            log_err('Clear analytics: ' . $e->getMessage());
            $_SESSION['flash']    = t('admin.settings.flash.analytics_clear_failed');
            $_SESSION['flash_ok'] = false;
        }
    } elseif (($_POST['action'] ?? '') === 'clear_log') {
        file_put_contents(ERROR_LOG_PATH, '');
        audit('errorlog_clear');
        $_SESSION['flash']    = t('admin.settings.flash.log_cleared');
        $_SESSION['flash_ok'] = true;
    }
    header('Location: /admin/settings.php');
    exit;
}

// ── Read flash from session (set by PRG above) ────────────────────────────────
$success = '';
$error   = '';
[$flashMsg, $flashOk] = flash_take();
if ($flashMsg !== '') {
    if ($flashOk) {
        $success = $flashMsg;
    } else {
        $error = $flashMsg;
    }
}

// Load settings with labels
try {
    $rows = get_db()->query('SELECT key_name, value, label FROM settings')->fetchAll();
    $s    = [];
    foreach ($rows as $r) { $s[$r['key_name']] = $r; }
} catch (Exception $e) {
    $s = [];
}

$csrf = generate_csrf();

// Analytics stats for the warning label
try {
    $analytics_events = (int)get_db()->query("SELECT COUNT(*) FROM order_events WHERE event_type NOT LIKE 'admin_%'")->fetchColumn();
    $analytics_orders = (int)get_db()->query('SELECT COUNT(DISTINCT token_hmac) FROM order_events WHERE token_hmac IS NOT NULL')->fetchColumn();
} catch (Exception $e) {
    $analytics_events = 0;
    $analytics_orders = 0;
}

$proxy_pool = osm_proxy_pool();

$groups = [
    'service' => [
        'site_name'    => ['type' => 'text', 'placeholder' => 'MGT'],
        'default_lang' => ['type' => 'select', 'options' => i18n_lang_names()],
    ],
    'orders' => [
        'order_ttl_hours'      => ['type' => 'slider', 'min' => 12,  'max' => 72,  'step' => 1,   'default' => '24',  'format' => 'h'],
        'extend_hours_options' => ['type' => 'text',   'placeholder' => '24,48,72', 'unit' => t('admin.settings.unit.comma_separated')],
    ],
    'security' => [
        'rate_limit_enabled'    => ['type' => 'toggle'],
        'rate_limit_max'        => ['type' => 'slider', 'min' => 3,   'max' => 10,  'step' => 1,   'default' => '5',   'format' => 'count'],
        'rate_limit_window_min' => ['type' => 'slider', 'min' => 5,   'max' => 60,  'step' => 5,   'default' => '15',  'format' => 'min'],
        'admin_session_hours'   => ['type' => 'slider', 'min' => 0.5, 'max' => 5,   'step' => 0.5, 'default' => '4',   'format' => 'session'],
    ],
    'uploads' => [
        'max_photo_mb' => ['type' => 'slider', 'min' => 0.1, 'max' => 5, 'step' => 0.1, 'default' => '2', 'format' => 'mb'],
    ],
    'behavior' => [
        'allow_status_lookup'      => ['type' => 'toggle'],
        'compliance_note_enabled'  => ['type' => 'toggle'],
    ],
    'analytics' => [
        'analytics_enabled' => ['type' => 'toggle'],
    ],
    'diagnostics' => [
        'show_error_log' => ['type' => 'toggle'],
    ],
    'maps' => [
        'map_provider' => ['type' => 'select', 'options' => [
            MAP_PROVIDER_OSM        => t('admin.maps.provider.osm'),
            MAP_PROVIDER_SELFHOSTED => t('admin.maps.provider.selfhosted'),
        ]],
    ],
];

function s_val(array $s, string $key): string {
    return $s[$key]['value'] ?? '';
}
function s_label(array $s, string $key): string {
    $tkey = "admin.settings.label.{$key}";
    $translated = t($tkey);
    return $translated !== $tkey ? $translated : ($s[$key]['label'] ?? $key);
}
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(current_lang(), ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<meta name="darkreader-lock">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — <?= t('admin.settings.title') ?></title><link rel="stylesheet" href="/admin/style.css">
<link rel="stylesheet" href="/admin/vendor/leaflet/leaflet.css">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
</head>
<body>
<div class="shell">

    <?php $_active = 'settings'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading"><?= t('admin.settings.title') ?></div>

        <?php if ($error):   ?><div class="flash"><?= $error ?></div><?php endif; ?>
        <?php if ($success): ?><div class="flash ok"><?= $success ?></div><?php endif; ?>
        <!-- Flash mirrors t()-built session values; raw echo (see orders.php). -->

        <?php $bi = build_info(); ?>
        <!-- Build provenance: owners only (this page is require_owner()). -->
        <div class="version-strip" id="version-strip">
            <span class="version-label"><?= htmlspecialchars(t('admin.settings.version_label'), ENT_QUOTES, 'UTF-8') ?></span>
            <?php if (!$bi['known']): ?>
            <span class="version-muted"><?= htmlspecialchars(t('admin.settings.version_unknown'), ENT_QUOTES, 'UTF-8') ?></span>
            <?php else: ?>
            <span class="version-value"><?= $bi['version'] !== null
                ? 'v' . htmlspecialchars($bi['version'], ENT_QUOTES, 'UTF-8') . ($bi['ahead'] > 0 ? '+' . (int)$bi['ahead'] : '')
                : '&mdash;' ?></span>
            <?php if ($bi['beta']): ?>
            <span class="beta-badge" title="<?= htmlspecialchars(t('admin.settings.version_beta_hint'), ENT_QUOTES, 'UTF-8') ?>">BETA</span>
            <span class="version-commit"><?php
                // One line: hash, branch, and (when the tree was modified) a note.
                $parts = [];
                if ($bi['commit'] !== null) { $parts[] = '<code>' . htmlspecialchars($bi['commit'], ENT_QUOTES, 'UTF-8') . '</code>'; }
                if ($bi['branch'] !== null) { $parts[] = '<span class="version-muted">' . htmlspecialchars($bi['branch'], ENT_QUOTES, 'UTF-8') . '</span>'; }
                if ($bi['dirty']) { $parts[] = '<span class="version-muted">' . htmlspecialchars(t('admin.settings.version_dirty'), ENT_QUOTES, 'UTF-8') . '</span>'; }
                echo implode(' <span class="version-muted">&middot;</span> ', $parts);
            ?></span>
            <?php endif; ?>
            <?php endif; ?>
        </div>

        <div class="form-panel settings-panel">
            <div autocomplete="off">

                <?php foreach ($groups as $group_slug => $fields): ?>
                <div class="settings-group">
                    <div class="settings-group-label"><?= htmlspecialchars(t("admin.settings.group.{$group_slug}"), ENT_QUOTES, 'UTF-8') ?></div>

                    <?php
                    // Collect toggles vs regular fields
                    $toggles = array_filter($fields, fn($m) => $m['type'] === 'toggle');
                    $inputs  = array_filter($fields, fn($m) => $m['type'] !== 'toggle');
                    ?>

                    <?php foreach ($inputs as $key => $meta): ?>
                    <div class="form-group">
                        <label for="s_<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars(s_label($s, $key), ENT_QUOTES, 'UTF-8') ?>
                            <?php if (!empty($meta['unit'])): ?>
                            <span class="hint"><?= htmlspecialchars($meta['unit'], ENT_QUOTES, 'UTF-8') ?></span>
                            <?php endif; ?>
                        </label>
                        <?php if ($meta['type'] === 'slider'): ?>
                        <div class="slider-row">
                            <input type="range"
                                   id="s_<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                                   name="<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                                   min="<?= $meta['min'] ?>"
                                   max="<?= $meta['max'] ?>"
                                   step="<?= $meta['step'] ?>"
                                   data-format="<?= htmlspecialchars($meta['format'], ENT_QUOTES, 'UTF-8') ?>"
                                   value="<?= htmlspecialchars(s_val($s, $key) ?: ($meta['default'] ?? (string)$meta['min']), ENT_QUOTES, 'UTF-8') ?>">
                            <span class="slider-val"></span>
                        </div>
                        <?php elseif ($meta['type'] === 'select'): ?>
                        <select id="s_<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                                name="<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                                class="settings-select-save">
                            <?php foreach ($meta['options'] as $optval => $optlabel): ?>
                            <option value="<?= htmlspecialchars($optval, ENT_QUOTES, 'UTF-8') ?>" <?= s_val($s, $key) === $optval ? 'selected' : '' ?>><?= htmlspecialchars($optlabel, ENT_QUOTES, 'UTF-8') ?></option>
                            <?php endforeach; ?>
                        </select>
                        <?php else: ?>
                        <input
                            type="<?= $meta['type'] === 'number' ? 'number' : 'text' ?>"
                            id="s_<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                            name="<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                            value="<?= htmlspecialchars(s_val($s, $key), ENT_QUOTES, 'UTF-8') ?>"
                            placeholder="<?= htmlspecialchars($meta['placeholder'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                        <?php endif; ?>
                    </div>
                    <?php endforeach; ?>

                    <?php foreach ($toggles as $key => $meta): ?>
                    <?php $on = s_val($s, $key) === '1'; ?>
                    <div class="sw-row">
                        <span class="sw-row-label"><?= htmlspecialchars(s_label($s, $key), ENT_QUOTES, 'UTF-8') ?></span>
                        <label class="sw">
                            <input type="checkbox"
                                   name="<?= htmlspecialchars($key, ENT_QUOTES, 'UTF-8') ?>"
                                   value="1"
                                   <?= $on ? 'checked' : '' ?>>
                            <span class="sw-track"><span class="sw-thumb"></span></span>
                            <span class="sw-state"><?= $on ? t('admin.settings.on') : t('admin.settings.off') ?></span>
                        </label>
                    </div>
                    <?php if ($key === 'analytics_enabled'): ?>
                    <div class="settings-warning">
                        <?= t('admin.settings.analytics_warning') ?>
                        <?php if ($analytics_events > 0): ?>
                        <?= t('admin.settings.analytics_current', [
                            'n'      => number_format($analytics_events),
                            'word'   => tn('admin.settings.event_word', $analytics_events),
                            'orders' => number_format($analytics_orders),
                        ]) ?>
                        <?php endif; ?>
                    </div>
                    <?php if ($analytics_events > 0): ?>
                    <form method="POST" action="/admin/settings.php"
                          data-confirm="<?= htmlspecialchars(t('admin.settings.clear_analytics_confirm'), ENT_QUOTES, 'UTF-8') ?>">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                        <input type="hidden" name="action" value="clear_analytics">
                        <button type="submit" class="action-btn action-btn--danger"><?= t('admin.settings.clear_analytics_button') ?></button>
                    </form>
                    <?php endif; ?>
                    <?php endif; ?>
                    <?php endforeach; ?>

                </div>
                <?php endforeach; ?>

                <!-- ── OSM proxy pool ─────────────────────────────────────── -->
                <div class="settings-group">
                    <div class="settings-group-label"><?= htmlspecialchars(t('admin.proxies.section'), ENT_QUOTES, 'UTF-8') ?></div>

                    <?php $pxOn = osm_proxy_enabled(); ?>
                    <div class="sw-row">
                        <span class="sw-row-label"><?= htmlspecialchars(t('admin.settings.label.osm_proxy_enabled'), ENT_QUOTES, 'UTF-8') ?></span>
                        <label class="sw">
                            <input type="checkbox"
                                   name="osm_proxy_enabled"
                                   value="1"
                                   <?= $pxOn ? 'checked' : '' ?>>
                            <span class="sw-track"><span class="sw-thumb"></span></span>
                            <span class="sw-state"><?= $pxOn ? t('admin.settings.on') : t('admin.settings.off') ?></span>
                        </label>
                    </div>
                    <?php if ($pxOn && !$proxy_pool): ?>
                    <div class="settings-warning"><?= t('admin.proxies.enabled_empty') ?></div>
                    <?php endif; ?>
                    <?php if (!host_has_curl()): ?>
                    <div class="settings-warning"><?= t('admin.proxies.no_curl') ?></div>
                    <?php elseif (!$pxOn && osm_proxy_auto_off_state() !== null): ?>
                    <div class="settings-warning"><?= t('admin.proxies.auto_off') ?></div>
                    <?php endif; ?>

                    <div class="proxies-hint"><?= t('admin.proxies.hint') ?></div>

                    <?php if (!$proxy_pool): ?>
                    <div class="log-empty"><?= t('admin.proxies.empty') ?></div>
                    <?php else: ?>
                    <table class="proxies-table">
                        <thead>
                        <tr>
                            <th><?= t('admin.proxies.th.proxy') ?></th>
                            <th><?= t('admin.proxies.th.source') ?></th>
                            <th><?= t('admin.proxies.th.status') ?></th>
                            <th><?= t('admin.proxies.th.latency') ?></th>
                            <th></th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($proxy_pool as $px): ?>
                        <tr data-id="<?= (int)$px['id'] ?>">
                            <td class="px-url"><?= htmlspecialchars($px['url'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><?= htmlspecialchars($px['source'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td><span class="px-status px-status--<?= htmlspecialchars($px['last_status'], ENT_QUOTES, 'UTF-8') ?>"><?= t('admin.proxies.status.' . $px['last_status']) ?></span></td>
                            <td><?= $px['latency_ms'] !== null ? (int)$px['latency_ms'] . ' ms' : '&mdash;' ?></td>
                            <td class="px-actions"><button type="button" class="action-btn action-btn--danger px-del"><?= t('admin.proxies.delete_button') ?></button></td>
                        </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>

                    <div class="proxies-toolbar">
                        <input type="text" id="px-url" autocomplete="off"
                               placeholder="<?= htmlspecialchars(t('admin.proxies.add_placeholder'), ENT_QUOTES, 'UTF-8') ?>"
                               aria-label="<?= htmlspecialchars(t('admin.proxies.add_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
                        <button type="button" id="px-add" class="action-btn"><?= t('admin.proxies.add_button') ?></button>
                        <button type="button" id="px-discover" class="action-btn"><?= t('admin.proxies.discover_button') ?></button>
                    </div>
                </div>

                <!-- ── Self-hosted map zones ───────────────────────────────── -->
                <?php $map_zones = maps_zone_list(); ?>
                <div class="settings-group">
                    <div class="settings-group-label"><?= htmlspecialchars(t('admin.maps.zones_section'), ENT_QUOTES, 'UTF-8') ?></div>
                    <div class="proxies-hint"><?= t('admin.maps.zones_hint') ?></div>
                    <?php $zones_ok = maps_downloads_supported(); ?>
                    <?php if (!$zones_ok): ?>
                    <div class="settings-warning" id="maps-unsupported"><?= t('admin.maps.flash.unsupported') ?></div>
                    <?php endif; ?>
                    <div class="maps-disk" id="maps-disk">
                        <?= htmlspecialchars(t('admin.maps.disk_free', ['x' => maps_fmt_bytes(maps_disk_free())]), ENT_QUOTES, 'UTF-8') ?>
                    </div>

                    <?php if (!$map_zones): ?>
                    <div class="log-empty" id="maps-empty"><?= t('admin.maps.no_zones_yet') ?></div>
                    <?php endif; ?>
                    <table class="proxies-table maps-table" id="maps-table" <?= $map_zones ? '' : 'hidden' ?>>
                        <thead>
                        <tr>
                            <th><?= t('admin.maps.th.zone') ?></th>
                            <th><?= t('admin.maps.th.detail') ?></th>
                            <th><?= t('admin.maps.th.status') ?></th>
                            <th><?= t('admin.maps.th.size') ?></th>
                            <th><?= t('admin.maps.th.speed') ?></th>
                            <th><?= t('admin.maps.th.eta') ?></th>
                            <th><?= t('admin.maps.th.via') ?></th>
                            <th></th>
                        </tr>
                        </thead>
                        <tbody id="maps-tbody">
                        <?php foreach ($map_zones as $mz): ?>
                        <tr class="mz-c<?= maps_zone_color_index((int)$mz['id']) ?>"
                            data-status="<?= htmlspecialchars((string)$mz['status'], ENT_QUOTES, 'UTF-8') ?>"
                            data-id="<?= (int)$mz['id'] ?>"
                            data-min-lon="<?= htmlspecialchars((string)$mz['min_lon'], ENT_QUOTES, 'UTF-8') ?>"
                            data-min-lat="<?= htmlspecialchars((string)$mz['min_lat'], ENT_QUOTES, 'UTF-8') ?>"
                            data-max-lon="<?= htmlspecialchars((string)$mz['max_lon'], ENT_QUOTES, 'UTF-8') ?>"
                            data-max-lat="<?= htmlspecialchars((string)$mz['max_lat'], ENT_QUOTES, 'UTF-8') ?>">
                            <td class="px-url" data-label="<?= htmlspecialchars(t('admin.maps.th.zone'), ENT_QUOTES, 'UTF-8') ?>"><span class="mz-swatch" aria-hidden="true"></span><?= htmlspecialchars((string)$mz['name'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td data-label="<?= htmlspecialchars(t('admin.maps.th.detail'), ENT_QUOTES, 'UTF-8') ?>">z<?= (int)$mz['maxzoom'] ?></td>
                            <td class="mz-status" data-label="<?= htmlspecialchars(t('admin.maps.th.status'), ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars(t('admin.maps.status.' . $mz['status']), ENT_QUOTES, 'UTF-8') ?><?php if (maps_zone_is_stale($mz)): ?> — <?= htmlspecialchars(t('admin.maps.stale_badge'), ENT_QUOTES, 'UTF-8') ?><?php endif; ?></td>
                            <td class="mz-size" data-label="<?= htmlspecialchars(t('admin.maps.th.size'), ENT_QUOTES, 'UTF-8') ?>"></td>
                            <td class="mz-speed" data-label="<?= htmlspecialchars(t('admin.maps.th.speed'), ENT_QUOTES, 'UTF-8') ?>"></td>
                            <td class="mz-eta" data-label="<?= htmlspecialchars(t('admin.maps.th.eta'), ENT_QUOTES, 'UTF-8') ?>"></td>
                            <td data-label="<?= htmlspecialchars(t('admin.maps.th.via'), ENT_QUOTES, 'UTF-8') ?>"><?= ((int)$mz['via_proxy'] === 1) ? t('admin.maps.via.proxy') : t('admin.maps.via.direct') ?></td>
                            <td class="px-actions"></td>
                        </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>

                    <div class="form-group" style="margin-top:18px">
                        <div class="field-label"><?= t('admin.maps.add_title') ?></div>
                        <div class="maps-add-grid">
                            <label><?= htmlspecialchars(t('admin.maps.name_label'), ENT_QUOTES, 'UTF-8') ?>
                                <input type="text" id="mz-name" maxlength="64" autocomplete="off">
                                <span class="mz-field-error" id="mz-name-error" role="alert" hidden></span></label>
                            <label><?= htmlspecialchars(t('admin.maps.maxzoom_label'), ENT_QUOTES, 'UTF-8') ?>
                                <select id="mz-maxzoom">
                                    <option value="14"><?= t('admin.maps.z14') ?></option>
                                    <option value="15"><?= t('admin.maps.z15') ?></option>
                                </select></label>
                            <!-- The rectangle is drawn on the map below; these carry it to the queue button. -->
                            <input type="hidden" id="mz-min-lon">
                            <input type="hidden" id="mz-min-lat">
                            <input type="hidden" id="mz-max-lon">
                            <input type="hidden" id="mz-max-lat">
                        </div>
                        <div class="field-label" style="margin-top:12px"><?= htmlspecialchars(t('admin.maps.editor_title'), ENT_QUOTES, 'UTF-8') ?></div>
                        <div class="proxies-hint"><?= t('admin.maps.editor_hint') ?></div>
                        <div class="maps-search-row">
                            <input type="text" id="mz-search" maxlength="200" autocomplete="off"
                                placeholder="<?= htmlspecialchars(t('admin.maps.search_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
                            <button type="button" id="mz-find" class="action-btn"><?= t('admin.maps.search_button') ?></button>
                            <button type="button" id="mz-draw" class="action-btn"><?= t('admin.maps.draw_button') ?></button>
                            <button type="button" id="mz-clear" class="action-btn"><?= t('admin.maps.clear_button') ?></button>
                        </div>
                        <div id="mz-map" class="maps-editor-map"></div>
                        <?php if (osm_proxy_enabled()) { require __DIR__ . '/osm_monit.php'; } ?>
                        <div class="maps-overlap" id="mz-overlap" hidden></div>
                        <div class="maps-overlap" id="mz-placelabel" hidden></div>
                        <fieldset class="maps-route">
                            <legend><?= t('admin.maps.route_legend') ?></legend>
                            <label><input type="radio" name="mz-via" value="1" <?= osm_proxy_enabled() ? 'checked' : '' ?>>
                                <?= htmlspecialchars(t('admin.maps.via_proxy_yes'), ENT_QUOTES, 'UTF-8') ?></label>
                            <label><input type="radio" name="mz-via" value="0" <?= osm_proxy_enabled() ? '' : 'checked' ?>>
                                <?= htmlspecialchars(t('admin.maps.via_proxy_no'), ENT_QUOTES, 'UTF-8') ?></label>
                        </fieldset>
                        <button type="button" id="mz-add" class="action-btn"<?= $zones_ok ? '' : ' disabled' ?>><?= t('admin.maps.queue_button') ?></button>
                    </div>
                </div>

            </div>
        </div>

        <!-- ── Hosting capabilities ─────────────────────────────────────── -->
        <div class="divider"></div>
        <div class="section-label"><?= t('admin.host.section') ?></div>
        <div class="host-list" id="host-list">
            <?php foreach (host_capabilities() as $c): ?>
            <?php
                $hintKey = 'admin.host.' . $c['id'] . '.' . $c['status'];
                $hint    = t($hintKey, ['n' => $c['note'], 'dirs' => $c['note']]);
            ?>
            <div class="host-row host-row--<?= $c['status'] ?>" data-cap="<?= $c['id'] ?>">
                <span class="host-label"><?= t('admin.host.' . $c['id'] . '.label') ?></span>
                <span class="host-status"><?= t('admin.host.' . $c['status']) ?></span>
                <?php if ($hint !== $hintKey): ?><span class="host-hint"><?= $hint ?></span><?php endif; ?>
            </div>
            <?php endforeach; ?>
        </div>

        <!-- ── Log viewer ────────────────────────────────────────────────── -->
        <?php if (get_setting('show_error_log', '0') === '1'): ?>
        <?php
        // Structured log: the hash-chained file "Verify integrity" checks. It
        // is shown first and in full sense — verifying entries nobody can see
        // is what made the old panel (raw PHP error file only) look empty.
        $app_view  = log_recent_entries(200);
        $app_shown = count($app_view['entries']);

        $log_all   = [];
        $log_total = 0;
        if (is_file(ERROR_LOG_PATH) && filesize(ERROR_LOG_PATH) > 0) {
            $log_all   = file(ERROR_LOG_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $log_total = count($log_all);
        }
        $log_lines = array_reverse($log_all); // newest first, file line numbers preserved
        ?>
        <div class="divider"></div>
        <div class="section-label"><?= htmlspecialchars(t('admin.settings.app_log_section'), ENT_QUOTES, 'UTF-8') ?></div>
        <div class="log-toolbar">
            <span class="td-muted"><?= tn('admin.settings.log_line', $app_view['total'], ['n' => number_format($app_view['total'])]) ?><?php if ($app_view['total'] > $app_shown): ?> &middot; <?= htmlspecialchars(t('admin.settings.log_showing_latest', ['n' => $app_shown]), ENT_QUOTES, 'UTF-8') ?><?php endif; ?></span>
            <div class="log-toolbar-actions">
                <?php if ($app_view['total'] > 0): ?>
                <a class="action-btn" href="/admin/download_log.php?file=app"><?= t('admin.settings.download_jsonl_button') ?></a>
                <?php endif; ?>
                <button type="button" class="action-btn" id="verify-log-btn"><?= t('admin.settings.verify_log_button') ?></button>
                <span id="verify-log-result" class="td-muted"></span>
            </div>
        </div>
        <?php if ($app_shown === 0): ?>
        <div class="log-empty"><?= t('admin.settings.log_empty') ?></div>
        <?php else: ?>
        <div class="log-view" id="app-log-view">
            <?php foreach ($app_view['entries'] as $e): ?>
            <div class="log-line log-line--<?= htmlspecialchars($e['level'], ENT_QUOTES, 'UTF-8') ?>">
                <span class="log-num"><?= $e['seq'] !== null ? (int)$e['seq'] : '' ?></span><span class="log-ts"><?= htmlspecialchars($e['ts'], ENT_QUOTES, 'UTF-8') ?></span><span class="log-lvl"><?= htmlspecialchars(strtoupper($e['level']), ENT_QUOTES, 'UTF-8') ?></span><span class="log-text"><?= htmlspecialchars($e['text'], ENT_QUOTES, 'UTF-8') ?></span>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <div class="section-label"><?= t('admin.settings.error_log_section') ?></div>
        <div class="log-toolbar">
            <span class="td-muted"><?= tn('admin.settings.log_line', $log_total, ['n' => number_format($log_total)]) ?></span>
            <div class="log-toolbar-actions">
                <?php if ($log_total > 0): ?>
                <a class="action-btn" href="/admin/download_log.php"><?= t('admin.settings.download_log_button') ?></a>
                <?php endif; ?>
                <form method="POST" action="/admin/settings.php">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="clear_log">
                    <button class="action-btn action-btn--danger"><?= t('admin.settings.clear_log_button') ?></button>
                </form>
            </div>
        </div>
        <?php if (empty($log_lines)): ?>
        <div class="log-empty"><?= t('admin.settings.log_empty') ?></div>
        <?php else: ?>
        <div class="log-view">
            <?php foreach ($log_lines as $i => $line): ?>
            <div class="log-line">
                <span class="log-num"><?= $log_total - $i ?></span><?= htmlspecialchars($line, ENT_QUOTES, 'UTF-8') ?>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <?php endif; ?>

    </main>
</div>

<script src="/admin/pin-label.js"></script>
<script src="/admin/vendor/leaflet/leaflet.js"></script>
<script nonce="<?= htmlspecialchars($csp_nonce, ENT_QUOTES, 'UTF-8') ?>">
(function () {
    var I = <?= json_encode([
        'empty_field'       => t('admin.settings.js.empty_field'),
        'range_error'       => t('admin.settings.js.range_error'),
        'extend_hours_error' => t('admin.settings.js.extend_hours_error'),
        'saved'             => t('admin.edit.js.saved'),
        'save_error'        => t('admin.edit.js.save_error'),
        'connection_error'  => t('admin.edit.js.connection_error'),
        'on'                => t('admin.settings.on'),
        'off'               => t('admin.settings.off'),
        'enable_analytics_line1'    => t('admin.settings.enable_analytics_confirm_line1'),
        'enable_analytics_line2'    => t('admin.settings.enable_analytics_confirm_line2'),
        'enable_analytics_question' => t('admin.settings.enable_analytics_confirm_question'),
        'px_added'          => t('admin.proxies.js.added'),
        'px_discovering'    => t('admin.proxies.js.discovering'),
        'px_discovered'     => t('admin.proxies.js.discovered'),
        'px_none_working'   => t('admin.proxies.js.none_working'),
        'log_verify_ok'     => t('admin.settings.log_verify_ok'),
        'log_verify_fail'   => t('admin.settings.log_verify_fail'),
        'log_verify_empty'  => t('admin.settings.log_verify_empty'),
        'mz_queued_kicked'  => t('admin.maps.queued_kicked'),
        'mz_queued_cron'    => t('admin.maps.queued_cron'),
        'mz_confirm_delete' => t('admin.maps.confirm_delete'),
        'mz_request_failed' => t('admin.maps.js.request_failed'),
        'mz_retry'          => t('admin.maps.retry_button'),
        'mz_refresh'        => t('admin.maps.refresh_button'),
        'mz_stale'          => t('admin.maps.stale_badge'),
        'mz_delete'         => t('admin.maps.delete_button'),
        'mz_no_zones'       => t('admin.maps.no_zones_yet'),
        'mz_disk_free'      => t('admin.maps.disk_free'),
        'mz_overlap_warn'   => t('admin.maps.js.overlap_warning'),
        'mz_geo_not_found'  => t('admin.maps.js.geocode_not_found'),
        'mz_geo_error'      => t('admin.maps.js.geocode_error'),
        'mz_draw'           => t('admin.maps.draw_button'),
        'mz_draw_first'     => t('admin.maps.editor_title'),
        'mz_name_required'  => t('admin.maps.err.bad_name'),
        'mz_drawing'        => t('admin.maps.drawing_button'),
        'mz_s_queued'      => t('admin.maps.status.queued'),
        'mz_s_sizing'      => t('admin.maps.status.sizing'),
        'mz_s_downloading' => t('admin.maps.status.downloading'),
        'mz_s_ready'       => t('admin.maps.status.ready'),
        'mz_s_failed'      => t('admin.maps.status.failed'),
        'mz_via_proxy'  => t('admin.maps.via.proxy'),
        'mz_via_direct' => t('admin.maps.via.direct'),
    ]) ?>;

    // Zone colours: one palette for the map layers here and the CSS swatches.
    var MZ_PALETTE = <?= json_encode(MAPS_ZONE_COLORS) ?>;

    // Confirm destructive form submissions
    document.addEventListener('submit', function (e) {
        var msg = e.target.dataset.confirm;
        if (msg && !window.confirm(msg)) e.preventDefault();
    });

    var csrf       = document.querySelector('meta[name="csrf-token"]').content;
    var timers     = {};
    var popupTimer = null;

    // Validation limits (mirrors server-side save_setting.php $limits)
    var limits = {
        order_ttl_hours:       [12,  72],
        rate_limit_max:        [3,   10],
        rate_limit_window_min: [5,   60],
        admin_session_hours:   [0.5,  5],
        max_photo_mb:          [0.1,  5],
    };

    // ── Popup ─────────────────────────────────────────────────────────────────
    var popup = document.createElement('div');
    popup.id = 'save-popup';
    popup.className = 'save-popup';
    document.body.appendChild(popup);

    function showPopup(msg, isError) {
        popup.textContent = msg;
        popup.className = 'save-popup' + (isError ? ' error' : '') + ' visible';
        clearTimeout(popupTimer);
        // Long messages stay up long enough to be read (about 55 ms a character).
        var ms = Math.min(9000, Math.max(isError ? 3000 : 1400, String(msg).length * 55));
        popupTimer = setTimeout(function () {
            popup.classList.remove('visible');
        }, ms);
    }

    // ── Token-safe POSTs ──────────────────────────────────────────────────────
    // The server rotates the CSRF token on every verified request, and this
    // page fires several kinds (autosaves, the zone status poll, proxy and zone
    // actions). Two in flight at once means one is rejected — and a late reply
    // can even put a stale token back. So every POST goes through ONE queue
    // (a single token-consuming request at a time), takes the token from the
    // reply, and if the server still refuses it (403), fetches the live token
    // and tries once more.
    var postQueue = Promise.resolve();
    function postForm(url, fd) {
        function send(token) {
            fd.set('csrf_token', token);
            return fetch(url, { method: 'POST', body: fd }).then(function (r) {
                return r.json().then(function (j) {
                    if (j && j.csrf) csrf = j.csrf;
                    return { r: r, j: j };
                });
            });
        }
        function run() {
            return send(csrf).then(function (res) {
                if (res.r.status === 403 && window.ddmgmtFreshCsrf) {
                    return window.ddmgmtFreshCsrf().then(send);
                }
                return res;
            });
        }
        var p = postQueue.then(run, run);
        postQueue = p.catch(function () {});
        return p;
    }

    // ── Slider value formatter ────────────────────────────────────────────────
    function fmtSlider(inp) {
        var v = parseFloat(inp.value);
        switch (inp.dataset.format) {
            case 'mb':      return v.toFixed(1) + ' MB';
            case 'min':     return v + ' min';
            case 'h':       return v + 'h';
            case 'session': return v < 1 ? Math.round(v * 60) + ' min' : v + ' h';
            default:        return String(v);
        }
    }

    // ── Sliders: update display live, save on release ─────────────────────────
    document.querySelectorAll('input[type="range"]').forEach(function (inp) {
        var disp = inp.parentElement.querySelector('.slider-val');
        function refresh() { if (disp) disp.textContent = fmtSlider(inp); }
        refresh();
        inp.addEventListener('input', refresh);
        inp.addEventListener('change', function () { saveSetting(inp.name, inp.value); });
    });

    // ── Validation ────────────────────────────────────────────────────────────
    function validate(key, value) {
        value = value.trim();
        if (value === '' && key !== 'extend_hours_options' && key !== 'site_name') return I.empty_field;
        if (limits[key]) {
            var n = parseInt(value, 10);
            if (isNaN(n) || n < limits[key][0] || n > limits[key][1]) {
                return I.range_error.replace('{min}', limits[key][0]).replace('{max}', limits[key][1]);
            }
        }
        if (key === 'extend_hours_options') {
            var parts = value.split(',');
            for (var i = 0; i < parts.length; i++) {
                var n = parseInt(parts[i].trim(), 10);
                if (isNaN(n) || n <= 0) return I.extend_hours_error;
            }
        }
        return null;
    }

    // ── Save ──────────────────────────────────────────────────────────────────
    function saveSetting(key, value) {
        var err = validate(key, value);
        if (err) { showPopup(err, true); return; }

        var fd = new FormData();
        fd.append('key', key);
        fd.append('value', value);
        postForm('/admin/save_setting.php', fd)
            .then(function (res) { return res.j; })
            .then(function (d) {
                if (d.ok) {
                    showPopup('✓ ' + I.saved, false);
                    setTimeout(function () { location.reload(); }, 600);
                } else {
                    showPopup(d.error || I.save_error, true);
                }
            })
            .catch(function () { showPopup(I.connection_error, true); });
    }

    // ── Toggles: save immediately ─────────────────────────────────────────────
    document.querySelectorAll('.sw input[type="checkbox"]').forEach(function (cb) {
        cb.addEventListener('change', function () {
            if (cb.name === 'analytics_enabled' && cb.checked) {
                var msg = I.enable_analytics_line1 + '\n\n' + I.enable_analytics_line2 + '\n\n' + I.enable_analytics_question;
                if (!window.confirm(msg)) { cb.checked = false; return; }
            }
            var state = cb.closest('.sw').querySelector('.sw-state');
            if (state) state.textContent = cb.checked ? I.on : I.off;
            saveSetting(cb.name, cb.checked ? '1' : '0');
        });
    });

    // ── Select: save immediately ────────────────────────────────────────────
    document.querySelectorAll('.settings-select-save').forEach(function (sel) {
        sel.addEventListener('change', function () { saveSetting(sel.name, sel.value); });
    });

    // ── Text / number: save on blur OR after 3s of inactivity ────────────────
    document.querySelectorAll('input[type="text"], input[type="number"]').forEach(function (inp) {
        if (!inp.name) return;

        inp.addEventListener('input', function () {
            clearTimeout(timers[inp.name]);
            timers[inp.name] = setTimeout(function () {
                saveSetting(inp.name, inp.value);
            }, 3000);
        });

        inp.addEventListener('blur', function () {
            clearTimeout(timers[inp.name]);
            saveSetting(inp.name, inp.value);
        });
    });

    // ── OSM proxy pool management ─────────────────────────────────────────────
    var pxUrl  = document.getElementById('px-url');
    var pxAdd  = document.getElementById('px-add');
    var pxDisc = document.getElementById('px-discover');

    function pxPost(action, extra) {
        var fd = new FormData();
        fd.append('action', action);
        if (extra) Object.keys(extra).forEach(function (k) { fd.append(k, extra[k]); });
        return postForm('/admin/proxy_action.php', fd)
            .then(function (res) { return { ok: res.r.ok, j: res.j }; })
            .catch(function () { return { ok: false, j: { error: I.connection_error } }; });
    }

    if (pxAdd && pxUrl) {
        pxAdd.addEventListener('click', function () {
            pxAdd.disabled = true;
            pxPost('add', { url: pxUrl.value }).then(function (res) {
                pxAdd.disabled = false;
                if (res.ok && res.j.ok) { showPopup(I.px_added, false); setTimeout(function () { location.reload(); }, 600); }
                else showPopup(res.j.error || I.save_error, true);
            });
        });
    }

    if (pxDisc) {
        pxDisc.addEventListener('click', function () {
            pxDisc.disabled = true;
            var orig = pxDisc.textContent;
            pxDisc.textContent = I.px_discovering;
            // Discovery probes dozens of proxies — this legitimately takes a while.
            pxPost('discover').then(function (res) {
                pxDisc.disabled = false;
                pxDisc.textContent = orig;
                if (res.ok && res.j.ok) {
                    showPopup(res.j.working > 0
                        ? I.px_discovered.replace('{n}', res.j.added)
                        : I.px_none_working, res.j.working === 0);
                    if (res.j.working > 0) setTimeout(function () { location.reload(); }, 1200);
                } else {
                    showPopup(res.j.error || I.save_error, true);
                }
            });
        });
    }

    document.querySelectorAll('.px-del').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var tr = btn.closest('tr');
            btn.disabled = true;
            pxPost('delete', { id: tr.dataset.id }).then(function (res) {
                if (res.ok && res.j.ok) { tr.remove(); }
                else { btn.disabled = false; showPopup(res.j.error || I.save_error, true); }
            });
        });
    });
    // ── Self-hosted map zones ───────────────────────────────────────────────
    var mzTable = document.getElementById('maps-table');
    var mzBody  = document.getElementById('maps-tbody');
    var mzEmpty = document.getElementById('maps-empty');
    var mzDisk  = document.getElementById('maps-disk');
    var mzAdd   = document.getElementById('mz-add');

    function mzPost(action, extra) {
        var fd = new FormData();
        fd.append('action', action);
        if (extra) Object.keys(extra).forEach(function (k) { fd.append(k, extra[k]); });
        return postForm('/admin/maps_action.php', fd)
            .then(function (res) { return { ok: res.r.ok, j: res.j }; })
            .catch(function () { return { ok: false, j: { error: I.mz_request_failed } }; });
    }

    function mzFmtBytes(n) {
        if (n === null || n === undefined) return '—';
        if (n < 1024) return n + ' B';
        var units = ['KiB', 'MiB', 'GiB', 'TiB'];
        var e = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
        return (n / Math.pow(1024, e)).toFixed(1) + ' ' + units[e - 1];
    }

    function mzFmtDur(s) {
        if (s === null || s === undefined) return '—';
        s = Math.max(0, Math.round(s));
        var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
        if (h > 0) return h + 'h' + String(m).padStart(2, '0') + 'm';
        if (m > 0) return m + 'm' + String(s % 60).padStart(2, '0') + 's';
        return s + 's';
    }

    function mzStatusLabel(st) {
        return { queued: I.mz_s_queued, sizing: I.mz_s_sizing,
                 downloading: I.mz_s_downloading, ready: I.mz_s_ready,
                 failed: I.mz_s_failed }[st] || st;
    }

    // Row cells carry their column title (shown as a small prefix by the card
    // layout in style.css); read from the header so the strings stay in one place.
    var mzLabels = mzTable
        ? Array.prototype.map.call(mzTable.querySelectorAll('thead th'), function (th) { return th.textContent; })
        : [];

    function mzRender(zones, diskFree) {
        if (mzDisk) mzDisk.textContent = I.mz_disk_free.replace('{x}', mzFmtBytes(diskFree));
        if (!mzBody) return;
        mzBody.innerHTML = '';
        var active = false;
        zones.forEach(function (z) {
            if (z.status === 'queued' || z.status === 'sizing' || z.status === 'downloading') active = true;
            var tr = document.createElement('tr');
            tr.className = 'mz-c' + (z.id % MZ_PALETTE.length);
            tr.dataset.status = z.status;
            tr.dataset.id = z.id;
            tr.dataset.minLon = z.min_lon;
            tr.dataset.minLat = z.min_lat;
            tr.dataset.maxLon = z.max_lon;
            tr.dataset.maxLat = z.max_lat;
            var size, speed, eta, actions;
            if (z.status === 'ready' && z.bytes_expected !== null) {
                size = mzFmtBytes(z.bytes_done || z.bytes_expected);
            } else if (z.bytes_expected !== null) {
                var pct = Math.floor(100 * z.bytes_done / Math.max(1, z.bytes_expected));
                size = mzFmtBytes(z.bytes_done) + ' / ' + mzFmtBytes(z.bytes_expected) + ' (' + pct + '%)';
            } else {
                size = z.status === 'sizing' ? I.mz_s_sizing : '';
            }
            // Unknown speed/ETA leave the cell empty: the card layout hides
            // empty cells instead of printing a dash-filled column.
            speed = z.speed_bps !== null ? mzFmtBytes(z.speed_bps) + '/s' : '';
            eta = z.eta_secs !== null ? mzFmtDur(z.eta_secs) : '';
            var status = mzStatusLabel(z.status);
            if (z.status === 'failed' && z.error) status += ' — ' + z.error;
            if (z.stale) status += ' — ' + I.mz_stale;
            actions = z.status === 'failed'
                ? '<button type="button" class="action-btn mz-retry">' + I.mz_retry + '</button> '
                : '';
            if (z.status === 'ready' && z.stale) {
                actions += '<button type="button" class="action-btn mz-refresh">' + I.mz_refresh + '</button> ';
            }
            actions += '<button type="button" class="action-btn action-btn--danger mz-del">' + I.mz_delete + '</button>';
            tr.innerHTML = '<td class="px-url"></td><td>z' + z.maxzoom + '</td>'
                + '<td class="mz-status"></td><td class="mz-size"></td>'
                + '<td class="mz-speed"></td><td class="mz-eta"></td>'
                + '<td>' + (z.via_proxy ? I.mz_via_proxy : I.mz_via_direct) + '</td>'
                + '<td class="px-actions">' + actions + '</td>';
            mzLabels.forEach(function (label, i) {
                if (label && tr.children[i]) tr.children[i].dataset.label = label;
            });
            // Zone name behind its colour swatch (same colour as on the map).
            var sw = document.createElement('span');
            sw.className = 'mz-swatch';
            sw.setAttribute('aria-hidden', 'true');
            tr.children[0].textContent = '';
            tr.children[0].appendChild(sw);
            tr.children[0].appendChild(document.createTextNode(z.name));
            tr.children[2].textContent = status;
            tr.children[3].textContent = size;
            tr.children[4].textContent = speed;
            tr.children[5].textContent = eta;
            mzBody.appendChild(tr);
        });
        if (mzTable) mzTable.hidden = zones.length === 0;
        if (mzEmpty) mzEmpty.hidden = zones.length !== 0;
        // Re-rendered rows carry fresh bboxes — re-check a live draft.
        // (Function declaration, hoisted: safe while the editor block below
        // has not executed yet — it no-ops on an empty draft.)
        if (typeof mzRefreshOverlap === 'function') mzRefreshOverlap();
        if (typeof mzSyncZoneLayers === 'function') mzSyncZoneLayers();
        return active;
    }

    function mzPoll() {
        mzPost('status').then(function (res) {
            if (!(res.ok && res.j.ok)) return;
            if (!mzRender(res.j.zones, res.j.disk_free)) {
                clearInterval(mzTimer);
                mzTimer = null;
            }
        });
    }
    var mzTimer = null;

    if (mzBody) {
        // Row buttons are re-rendered by the poll — delegate once.
        mzBody.addEventListener('click', function (e) {
            var btn = e.target.closest('button');
            if (!btn) return;
            var tr = btn.closest('tr');
            if (btn.classList.contains('mz-del')) {
                if (!window.confirm(I.mz_confirm_delete)) return;
                btn.disabled = true;
                mzPost('delete', { id: tr.dataset.id }).then(function (res) {
                    if (res.ok && res.j.ok) { tr.remove(); mzPoll(); }
                    else { btn.disabled = false; showPopup(res.j.error || I.save_error, true); }
                });
            } else if (btn.classList.contains('mz-retry')) {
                btn.disabled = true;
                mzPost('retry', { id: tr.dataset.id }).then(function (res) {
                    if (res.ok && res.j.ok) { mzPoll(); }
                    else { btn.disabled = false; showPopup(res.j.error || I.save_error, true); }
                });
            } else if (btn.classList.contains('mz-refresh')) {
                btn.disabled = true;
                mzPost('refresh', { id: tr.dataset.id }).then(function (res) {
                    if (res.ok && res.j.ok) { mzPoll(); }
                    else { btn.disabled = false; showPopup(res.j.error || I.save_error, true); }
                });
            }
        });
        // Start live for the server-rendered rows; keep polling while active.
        mzPoll();
        if (!mzTimer) mzTimer = setInterval(function () { if (!mzTimer) return; mzPoll(); }, 3000);
    }

    if (mzAdd) {
        mzAdd.addEventListener('click', function () {
            var via = document.querySelector('input[name="mz-via"]:checked');
            var bbox = {
                min_lon: document.getElementById('mz-min-lon').value,
                min_lat: document.getElementById('mz-min-lat').value,
                max_lon: document.getElementById('mz-max-lon').value,
                max_lat: document.getElementById('mz-max-lat').value,
            };
            // The rectangle exists only once drawn on the map: nothing drawn
            // means telling the admin to draw, not a server "must be numbers".
            if (Object.keys(bbox).some(function (k) { return String(bbox[k]).trim() === ''; })) {
                showPopup(I.mz_draw_first, true);
                return;
            }
            // The name field sits far above the map and this button. Check it HERE
            // and take the admin to it — scrolled into view, focused, marked, with
            // the reason written next to it — instead of a toast that names a field
            // nobody can see and vanishes in seconds.
            var mzNameEl = document.getElementById('mz-name');
            var zoneName = mzNameEl.value.trim();
            if (zoneName === '' || zoneName.length > 64) {
                mzNameProblem(I.mz_name_required);
                return;
            }
            mzNameProblem('');
            mzAdd.disabled = true;
            mzPost('add', {
                name: zoneName,
                min_lon: bbox.min_lon,
                min_lat: bbox.min_lat,
                max_lon: bbox.max_lon,
                max_lat: bbox.max_lat,
                maxzoom: document.getElementById('mz-maxzoom').value,
                via_proxy: via ? via.value : '1',
            }).then(function (res) {
                mzAdd.disabled = false;
                if (res.ok && res.j.ok) {
                    showPopup(res.j.kicked ? I.mz_queued_kicked : I.mz_queued_cron, false);
                    setTimeout(function () { location.reload(); }, 1200);
                } else {
                    showPopup(res.j.error || I.save_error, true);
                }
            });
        });
        document.getElementById('mz-name').addEventListener('input', function () { mzNameProblem(''); });
    }
    // Mark / unmark the zone-name field. With a message it also scrolls the field
    // into view and focuses it (so typing starts right there).
    function mzNameProblem(msg) {
        var el = document.getElementById('mz-name');
        var out = document.getElementById('mz-name-error');
        if (!el || !out) return;
        out.textContent = msg;
        out.hidden = msg === '';
        el.classList.toggle('mz-invalid', msg !== '');
        el.setAttribute('aria-invalid', msg !== '' ? 'true' : 'false');
        if (msg !== '') {
            el.scrollIntoView({ block: 'center', behavior: 'smooth' });
            el.focus({ preventScroll: true });
        }
    }
    // ── Zone rectangle editor (OSM canvas, tiles via tile_proxy.php only) ────────────
    // Leaflet core has no editable rectangles, so this is hand-rolled: a
    // draft rectangle with four draggable corner handles. Dragging the body
    // moves it, corners resize against the opposite corner. Every change
    // syncs the hidden bbox inputs above (the queue button reads those, so the
    // editor needs no separate submit path) and re-checks overlap against
    // the server-rendered rows (warning only — the worker happily stores
    // shared tiles twice, the admin just deserves to know).
    var mzMapEl = document.getElementById('mz-map');
    if (mzMapEl && typeof L !== 'undefined') {
        var mzMap = L.map('mz-map').setView([52.23, 21.01], 10);
        L.tileLayer('/admin/tile_proxy.php?z={z}&x={x}&y={y}', {
            maxZoom: 18, attribution: '© OpenStreetMap contributors',
        }).addTo(mzMap);
        var mzDraft = null;   // L.rectangle, the editable draft (or null)
        var mzHandles = [];   // corner circleMarkers for the draft
        var mzDrawing = false;
        var mzDrawBtn = document.getElementById('mz-draw');
        var mzClearBtn = document.getElementById('mz-clear');
        var mzOverlap = document.getElementById('mz-overlap');
        var mzFields = {
            min_lon: document.getElementById('mz-min-lon'),
            min_lat: document.getElementById('mz-min-lat'),
            max_lon: document.getElementById('mz-max-lon'),
            max_lat: document.getElementById('mz-max-lat'),
        };

        function mzNum(v) {
            var n = parseFloat(String(v).replace(',', '.'));
            return isNaN(n) ? null : n;
        }
        function mzRound(v) { return Math.round(v * 1e5) / 1e5; }

        function mzExistingZones() {
            var out = [];
            document.querySelectorAll('#maps-tbody tr[data-id]').forEach(function (tr) {
                var b = {
                    min_lon: mzNum(tr.dataset.minLon), min_lat: mzNum(tr.dataset.minLat),
                    max_lon: mzNum(tr.dataset.maxLon), max_lat: mzNum(tr.dataset.maxLat),
                    name: tr.children[0] ? tr.children[0].textContent.trim() : '',
                    id: parseInt(tr.dataset.id || '0', 10),
                    status: tr.dataset.status || '',
                };
                if (b.min_lon !== null && b.min_lat !== null && b.max_lon !== null && b.max_lat !== null) {
                    out.push(b);
                }
            });
            return out;
        }
        // Same fraction as maps_overlap_frac(): overlap area over $b's area.
        function mzOverlapFrac(a, b) {
            var w = Math.max(0, Math.min(a.max_lon, b.max_lon) - Math.max(a.min_lon, b.min_lon));
            var h = Math.max(0, Math.min(a.max_lat, b.max_lat) - Math.max(a.min_lat, b.min_lat));
            var area = Math.max(0, (b.max_lon - b.min_lon) * (b.max_lat - b.min_lat));
            if (area <= 0) return 0;
            return Math.min(1, (w * h) / area);
        }
        // Existing zones as read-only context rectangles, each in its own colour
        // (the swatch colour in the list) and carrying its name as a permanent
        // centred label. Ready zones are solid; zones still downloading or
        // failed are dashed and lighter. The status poll re-renders the table
        // rows, so the layers follow: they are rebuilt whenever the set of
        // zones (id, name, box, status) changes and left alone otherwise.
        var mzZoneLayers = [];
        var mzZoneSig = null;
        function mzSyncZoneLayers() {
            var zones = mzExistingZones();
            var sig = JSON.stringify(zones);
            if (sig === mzZoneSig) return;
            mzZoneSig = sig;
            mzZoneLayers.forEach(function (l) { mzMap.removeLayer(l); });
            mzZoneLayers = zones.map(function (b) {
                var color = MZ_PALETTE[b.id % MZ_PALETTE.length];
                var ready = b.status === 'ready';
                var r = L.rectangle([[b.min_lat, b.min_lon], [b.max_lat, b.max_lon]], {
                    color: color, weight: 2, interactive: false,
                    dashArray: ready ? null : '6 4',
                    fillColor: color, fillOpacity: ready ? 0.16 : 0.05,
                }).addTo(mzMap);
                if (b.name) {
                    // The label's frame takes the zone colour once it is on the map.
                    r.on('tooltipopen', function (e) {
                        var el = e.tooltip.getElement();
                        if (el) el.style.borderColor = color;
                    });
                    r.bindTooltip(b.name, { permanent: true, direction: 'center', className: 'mz-zone-label' });
                }
                return r;
            });
        }
        mzSyncZoneLayers();

        function mzReadDraft() {
            if (!mzDraft) return null;
            var b = mzDraft.getBounds();
            return { min_lon: mzRound(b.getWest()), min_lat: mzRound(b.getSouth()),
                     max_lon: mzRound(b.getEast()), max_lat: mzRound(b.getNorth()) };
        }
        function mzRefreshOverlap() {
            if (!mzOverlap) return;
            var d = mzReadDraft();
            if (!d) { mzOverlap.hidden = true; return; }
            var worst = 0;
            mzExistingZones().forEach(function (z) {
                worst = Math.max(worst, mzOverlapFrac(d, z), mzOverlapFrac(z, d));
            });
            if (worst > 0) {
                mzOverlap.textContent = I.mz_overlap_warn.replace('{n}', Math.round(worst * 100));
                mzOverlap.hidden = false;
            } else {
                mzOverlap.hidden = true;
            }
        }
        function mzSyncInputs() {
            var d = mzReadDraft();
            if (!d) return;
            mzFields.min_lon.value = d.min_lon;
            mzFields.min_lat.value = d.min_lat;
            mzFields.max_lon.value = d.max_lon;
            mzFields.max_lat.value = d.max_lat;
            mzRefreshOverlap();
            mzRefreshPlace(d);
        }
        // Human area label for the draft ("Country, State" of its center —
        // raw coordinates stay out of the UI by policy). Debounced: drags
        // fire syncs continuously, the lookup only on pause.
        var mzPlaceTimer = null;
        var mzPlaceLabel = document.getElementById('mz-placelabel');
        function mzRefreshPlace(d) {
            if (!mzPlaceLabel || typeof ddmgmtPinLabel !== 'function') return;
            if (mzPlaceTimer) clearTimeout(mzPlaceTimer);
            mzPlaceTimer = setTimeout(function () {
                ddmgmtPinLabel((d.min_lat + d.max_lat) / 2, (d.min_lon + d.max_lon) / 2)
                    .then(function (res) {
                        if (!res.current) return;
                        if (res.label) {
                            mzPlaceLabel.textContent = res.label;
                            mzPlaceLabel.hidden = false;
                        } else {
                            mzPlaceLabel.hidden = true;
                        }
                    });
            }, 400);
        }
        function mzClearHandles() {
            mzHandles.forEach(function (h) { mzMap.removeLayer(h); });
            mzHandles = [];
        }
        function mzClearDraft() {
            if (mzDraft) { mzMap.removeLayer(mzDraft); mzDraft = null; }
            mzClearHandles();
            // The fields are invisible: a stale rectangle must never be
            // queueable after Clear (a fresh draft re-syncs them right away).
            Object.keys(mzFields).forEach(function (k) { mzFields[k].value = ''; });
            if (mzOverlap) mzOverlap.hidden = true;
            if (mzPlaceLabel) mzPlaceLabel.hidden = true;
        }
        // Pointer tracking shared by drawing, corner resize and body move.
        // Pointer Events cover mouse, touch and pen with one code path —
        // Leaflet only synthesises mouse events for taps, so a finger drag
        // never reached the old mousemove handlers and nothing could be drawn
        // on a phone. Listeners sit on the document so the gesture survives
        // the finger leaving the (small) map, and map panning is suspended
        // for its duration.
        function mzTrack(ev, onMove, onEnd) {
            var id = ev.pointerId;
            mzMap.dragging.disable();
            function finish(e, cancelled) {
                document.removeEventListener('pointermove', move);
                document.removeEventListener('pointerup', up);
                document.removeEventListener('pointercancel', cancel);
                onEnd(mzMap.mouseEventToLatLng(e), cancelled);
                if (!mzDrawing) mzMap.dragging.enable();
            }
            function move(e) { if (e.pointerId === id) onMove(mzMap.mouseEventToLatLng(e)); }
            function up(e) { if (e.pointerId === id) finish(e, false); }
            function cancel(e) { if (e.pointerId === id) finish(e, true); }
            document.addEventListener('pointermove', move);
            document.addEventListener('pointerup', up);
            document.addEventListener('pointercancel', cancel);
        }
        function mzPrimary(e) {
            return e.isPrimary && !(e.pointerType === 'mouse' && e.button !== 0);
        }
        // The four corner circles always sit on the four corners of the
        // draft, whichever one the finger is dragging (they are identical).
        function mzPlaceHandles() {
            if (!mzDraft) return;
            var b = mzDraft.getBounds();
            var pos = { sw: b.getSouthWest(), nw: b.getNorthWest(),
                        ne: b.getNorthEast(), se: b.getSouthEast() };
            mzHandles.forEach(function (h) { h.setLatLng(pos[h.mzCorner]); });
        }
        function mzAddHandles() {
            mzClearHandles();
            if (!mzDraft) return;
            var b = mzDraft.getBounds();
            // Fingertip-sized on touch screens, precise on a mouse.
            var radius = window.matchMedia && window.matchMedia('(pointer: coarse)').matches ? 14 : 8;
            [['sw', b.getSouthWest()], ['nw', b.getNorthWest()],
             ['ne', b.getNorthEast()], ['se', b.getSouthEast()]].forEach(function (pair) {
                var h = L.circleMarker(pair[1], {
                    radius: radius, color: '#1a73e8', fillColor: '#fff',
                    fillOpacity: 1, weight: 3,
                }).addTo(mzMap);
                h.mzCorner = pair[0];
                var el = h.getElement();
                if (el) {
                    el.style.touchAction = 'none';
                    el.addEventListener('pointerdown', function (e) {
                        if (mzDrawing || !mzDraft || !mzPrimary(e)) return;
                        e.preventDefault();
                        e.stopPropagation();
                        // Resize against the corner opposite the one grabbed;
                        // fixed for the whole gesture so dragging past it flips
                        // the rectangle instead of collapsing it.
                        var bb = mzDraft.getBounds();
                        var opp = { sw: bb.getNorthEast(), nw: bb.getSouthEast(),
                                    ne: bb.getSouthWest(), se: bb.getNorthWest() }[h.mzCorner];
                        mzTrack(e, function (ll) {
                            mzDraft.setBounds([opp, ll]);
                            mzPlaceHandles();
                            mzSyncInputs();
                        }, function () { mzSyncInputs(); });
                    });
                }
                mzHandles.push(h);
            });
        }
        function mzSetDraft(bounds) {
            mzClearDraft();
            mzDraft = L.rectangle(bounds, { color: '#1a73e8', weight: 2 }).addTo(mzMap);
            mzAddHandles();
            var body = mzDraft.getElement();
            if (body) {
                body.style.touchAction = 'none';
                // Move the whole rectangle; corners have their own handlers.
                body.addEventListener('pointerdown', function (e) {
                    if (mzDrawing || !mzDraft || !mzPrimary(e)) return;
                    e.preventDefault();
                    e.stopPropagation();
                    var start = mzMap.mouseEventToLatLng(e), orig = mzDraft.getBounds();
                    mzTrack(e, function (ll) {
                        var dLat = ll.lat - start.lat, dLng = ll.lng - start.lng;
                        mzDraft.setBounds([
                            [orig.getSouth() + dLat, orig.getWest() + dLng],
                            [orig.getNorth() + dLat, orig.getEast() + dLng],
                        ]);
                        mzPlaceHandles();
                    }, function () { mzSyncInputs(); });
                });
            }
            mzSyncInputs();
        }

        function mzSetDrawing(on) {
            mzDrawing = on;
            if (mzDrawBtn) {
                mzDrawBtn.textContent = on ? I.mz_drawing : I.mz_draw;
                mzDrawBtn.classList.toggle('action-btn--active', on);
            }
            mzMapEl.style.cursor = on ? 'crosshair' : '';
            // Draw mode owns the gesture: no panning, and touch-action off so
            // the browser does not scroll the page under the finger.
            mzMapEl.classList.toggle('mz-drawing', on);
            if (on) mzMap.dragging.disable(); else mzMap.dragging.enable();
        }
        if (mzDrawBtn) {
            mzDrawBtn.addEventListener('click', function () { mzSetDrawing(!mzDrawing); });
        }
        if (mzClearBtn) {
            mzClearBtn.addEventListener('click', function () {
                mzSetDrawing(false);
                mzClearDraft();
            });
        }
        mzMapEl.addEventListener('pointerdown', function (e) {
            if (!mzDrawing || !mzPrimary(e)) return;
            if (e.target.closest && e.target.closest('.leaflet-control')) return;
            e.preventDefault();
            var start = mzMap.mouseEventToLatLng(e);
            var temp = L.rectangle([start, start], { color: '#1a73e8', weight: 2, dashArray: '4 4' }).addTo(mzMap);
            mzTrack(e, function (ll) { temp.setBounds([start, ll]); }, function (end, cancelled) {
                mzMap.removeLayer(temp);
                mzSetDrawing(false);
                if (cancelled) return;
                if (Math.abs(end.lat - start.lat) < 1e-7 || Math.abs(end.lng - start.lng) < 1e-7) return;
                mzSetDraft([start, end]);
            });
        });
        // The hidden inputs stay the source of truth for queueing — setting a
        // valid bbox and firing change (what the e2e specs do) redraws the draft.
        ['min_lon', 'min_lat', 'max_lon', 'max_lat'].forEach(function (k) {
            var inp = mzFields[k];
            if (!inp) return;
            inp.addEventListener('change', function () {
                var b = { min_lon: mzNum(mzFields.min_lon.value), min_lat: mzNum(mzFields.min_lat.value),
                          max_lon: mzNum(mzFields.max_lon.value), max_lat: mzNum(mzFields.max_lat.value) };
                if (b.min_lon === null || b.min_lat === null || b.max_lon === null || b.max_lat === null) return;
                if (!(b.min_lon < b.max_lon && b.min_lat < b.max_lat)) return;
                if (Math.abs(b.min_lon) > 180 || Math.abs(b.max_lon) > 180) return;
                if (Math.abs(b.min_lat) > 90 || Math.abs(b.max_lat) > 90) return;
                mzSetDraft([[b.min_lat, b.min_lon], [b.max_lat, b.max_lon]]);
            });
        });
        // Place search rides the existing proxied Nominatim path (no key, no
        // direct third-party contact from the browser).
        var mzSearch = document.getElementById('mz-search');
        var mzFind = document.getElementById('mz-find');
        function mzSearchPlace() {
            if (!mzSearch || !mzSearch.value.trim()) return;
            fetch('/admin/geocode_proxy.php?q=' + encodeURIComponent(mzSearch.value.trim()))
                .then(function (r) { return r.json(); })
                .then(function (j) {
                    var hit = Array.isArray(j) ? j[0] : null;
                    if (hit && hit.lat !== undefined && hit.lon !== undefined) {
                        mzMap.setView([parseFloat(hit.lat), parseFloat(hit.lon)], Math.max(mzMap.getZoom(), 12));
                    } else {
                        showPopup(I.mz_geo_not_found, true);
                    }
                })
                .catch(function () { showPopup(I.mz_geo_error, true); });
        }
        if (mzFind) mzFind.addEventListener('click', mzSearchPlace);
        if (mzSearch) mzSearch.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); mzSearchPlace(); }
        });
        // Pre-draw the bbox if the inputs already hold one (e.g. after a
        // failed queue attempt keeps the values).
        (function () {
            var b = { min_lon: mzNum(mzFields.min_lon.value), min_lat: mzNum(mzFields.min_lat.value),
                      max_lon: mzNum(mzFields.max_lon.value), max_lat: mzNum(mzFields.max_lat.value) };
            if (b.min_lon !== null && b.min_lat !== null && b.max_lon !== null && b.max_lat !== null
                && b.min_lon < b.max_lon && b.min_lat < b.max_lat) {
                mzSetDraft([[b.min_lat, b.min_lon], [b.max_lat, b.max_lon]]);
            }
        })();
    }
    // ── Log integrity verification ─────────────────────────────────────────────
    var vBtn    = document.getElementById('verify-log-btn');
    var vResult = document.getElementById('verify-log-result');
    if (vBtn && vResult) {
        vBtn.addEventListener('click', function () {
            vBtn.disabled = true;
            vResult.textContent = '…';
            var fd = new FormData();
            fd.append('csrf_token', csrf);
            fetch('/admin/log_verify.php', { method: 'POST', body: fd })
                .then(function (r) { return r.json(); })
                .then(function (j) {
                    if (j.csrf) csrf = j.csrf;
                    if (j.valid && !j.checked) {
                        // Nothing chained yet: "intact — 0 verified" read as a pass
                        // on the error log above, which this check never covers.
                        vResult.textContent = I.log_verify_empty;
                    } else if (j.valid) {
                        vResult.textContent = I.log_verify_ok.replace('{n}', j.checked);
                    } else {
                        vResult.textContent = (I.log_verify_fail
                            .replace('{n}', j.broken_line || '?')
                            .replace('{r}', j.reason || '')) + ' (' + j.checked + ')';
                    }
                })
                .catch(function () { vResult.textContent = I.connection_error; })
                .finally(function () { vBtn.disabled = false; });
        });
    }
})();
</script>
<script src="/admin/admin.js"></script>
</body>
</html>
