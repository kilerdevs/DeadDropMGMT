<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/i18n.php';

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
if (isset($_SESSION['flash'])) {
    if ($_SESSION['flash_ok'] ?? false) {
        $success = $_SESSION['flash'];
    } else {
        $error = $_SESSION['flash'];
    }
    unset($_SESSION['flash'], $_SESSION['flash_ok']);
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
    $analytics_orders = (int)get_db()->query("SELECT COUNT(DISTINCT order_token) FROM order_events WHERE order_token IS NOT NULL")->fetchColumn();
} catch (Exception $e) {
    $analytics_events = 0;
    $analytics_orders = 0;
}

require_once dirname(__DIR__) . '/includes/proxy.php';
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
        'require_delivered_reveal' => ['type' => 'toggle'],
        'compliance_note_enabled'  => ['type' => 'toggle'],
    ],
    'analytics' => [
        'analytics_enabled' => ['type' => 'toggle'],
    ],
    'diagnostics' => [
        'show_error_log' => ['type' => 'toggle'],
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
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
</head>
<body>
<div class="shell">

    <?php $_active = 'settings'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
    <?php require __DIR__ . '/totp_banner.php'; ?>
        <div class="page-heading"><?= t('admin.settings.title') ?></div>

        <?php if ($error):   ?><div class="flash"><?= htmlspecialchars($error,   ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <?php if ($success): ?><div class="flash ok"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

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

            </div>
        </div>

        <!-- ── Error log viewer ──────────────────────────────────────────── -->
        <?php if (get_setting('show_error_log', '0') === '1'): ?>
        <?php
        $log_all   = [];
        $log_total = 0;
        if (is_file(ERROR_LOG_PATH) && filesize(ERROR_LOG_PATH) > 0) {
            $log_all   = file(ERROR_LOG_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $log_total = count($log_all);
        }
        $log_lines = array_reverse($log_all); // newest first, file line numbers preserved
        ?>
        <div class="divider"></div>
        <div class="section-label"><?= t('admin.settings.error_log_section') ?></div>
        <div class="log-toolbar">
            <span class="td-muted"><?= tn('admin.settings.log_line', $log_total, ['n' => number_format($log_total)]) ?></span>
            <div class="log-toolbar-actions">
                <?php if ($log_total > 0): ?>
                <a class="action-btn" href="/admin/download_log.php"><?= t('admin.settings.download_log_button') ?></a>
                <?php if (is_file(APP_LOG_PATH)): ?>
                <a class="action-btn" href="/admin/download_log.php?file=app"><?= t('admin.settings.download_jsonl_button') ?></a>
                <?php endif; ?>
                <?php endif; ?>
                <button type="button" class="action-btn" id="verify-log-btn"><?= t('admin.settings.verify_log_button') ?></button>
                <span id="verify-log-result" class="td-muted"></span>
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
    ]) ?>;

    // Confirm destructive form submissions
    document.addEventListener('submit', function (e) {
        var msg = e.target.dataset.confirm;
        if (msg && !window.confirm(msg)) e.preventDefault();
    });

    var csrf       = document.querySelector('meta[name="csrf-token"]').content;
    var timers     = {};
    var popupTimer = null;

    // Validation limits (mirrors server-side)
    var limits = {
        order_ttl_hours:       [1,  720],
        rate_limit_max:        [1,  100],
        rate_limit_window_min: [1, 1440],
        admin_session_hours:   [1,   72],
        max_photo_mb:          [1,  100],
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
        popupTimer = setTimeout(function () {
            popup.classList.remove('visible');
        }, isError ? 3000 : 1400);
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
        fd.append('csrf_token', csrf);
        fd.append('key', key);
        fd.append('value', value);
        fetch('/admin/save_setting.php', { method: 'POST', body: fd })
            .then(function (r) { return r.json(); })
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
        fd.append('csrf_token', csrf);
        fd.append('action', action);
        if (extra) Object.keys(extra).forEach(function (k) { fd.append(k, extra[k]); });
        return fetch('/admin/proxy_action.php', { method: 'POST', body: fd })
            .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
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
                    if (j.valid) {
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
