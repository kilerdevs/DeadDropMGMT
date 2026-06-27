<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/settings.php';

start_secure_session();
require_owner();
$csp_nonce = set_security_headers(true);

// ── POST handlers — all use PRG to prevent resubmission on back/refresh ──────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf($_POST['csrf_token'] ?? '')) {
        $_SESSION['flash']    = 'Nieprawidłowy token CSRF.';
        $_SESSION['flash_ok'] = false;
    } elseif (($_POST['action'] ?? '') === 'clear_analytics') {
        try {
            get_db()->exec('TRUNCATE TABLE order_events');
            $_SESSION['flash']    = 'Dane analityczne zostały usunięte.';
            $_SESSION['flash_ok'] = true;
        } catch (Exception $e) {
            log_err('Clear analytics: ' . $e->getMessage());
            $_SESSION['flash']    = 'Błąd podczas usuwania danych analitycznych.';
            $_SESSION['flash_ok'] = false;
        }
    } elseif (($_POST['action'] ?? '') === 'clear_log') {
        file_put_contents(ERROR_LOG_PATH, '');
        $_SESSION['flash']    = 'Log błędów wyczyszczony.';
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

$groups = [
    'Serwis' => [
        'site_name' => ['type' => 'text', 'placeholder' => 'MGT'],
    ],
    'Zamówienia' => [
        'order_ttl_hours'      => ['type' => 'slider', 'min' => 12,  'max' => 72,  'step' => 1,   'default' => '24',  'format' => 'h'],
        'extend_hours_options' => ['type' => 'text',   'placeholder' => '24,48,72', 'unit' => 'oddzielone przecinkiem'],
    ],
    'Bezpieczeństwo' => [
        'rate_limit_max'        => ['type' => 'slider', 'min' => 3,   'max' => 10,  'step' => 1,   'default' => '5',   'format' => 'count'],
        'rate_limit_window_min' => ['type' => 'slider', 'min' => 5,   'max' => 60,  'step' => 5,   'default' => '15',  'format' => 'min'],
        'admin_session_hours'   => ['type' => 'slider', 'min' => 0.5, 'max' => 5,   'step' => 0.5, 'default' => '4',   'format' => 'session'],
    ],
    'Przesyłanie plików' => [
        'max_photo_mb' => ['type' => 'slider', 'min' => 0.1, 'max' => 5, 'step' => 0.1, 'default' => '2', 'format' => 'mb'],
    ],
    'Zachowanie serwisu' => [
        'allow_status_lookup'      => ['type' => 'toggle'],
        'require_delivered_reveal' => ['type' => 'toggle'],
    ],
    'Analityka' => [
        'analytics_enabled' => ['type' => 'toggle'],
    ],
    'Diagnostyka' => [
        'show_error_log' => ['type' => 'toggle'],
    ],
];

function s_val(array $s, string $key): string {
    return $s[$key]['value'] ?? '';
}
function s_label(array $s, string $key): string {
    return $s[$key]['label'] ?? $key;
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — Ustawienia</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="/admin/style.css">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
</head>
<body>
<div class="shell">

    <?php $_active = 'settings'; require __DIR__ . '/sidebar.php'; ?>

    <main class="main">
        <div class="page-heading">Ustawienia</div>

        <?php if ($error):   ?><div class="flash"><?= htmlspecialchars($error,   ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>
        <?php if ($success): ?><div class="flash ok"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div><?php endif; ?>

        <div class="form-panel settings-panel">
            <div autocomplete="off">

                <?php foreach ($groups as $group_name => $fields): ?>
                <div class="settings-group">
                    <div class="settings-group-label"><?= htmlspecialchars($group_name, ENT_QUOTES, 'UTF-8') ?></div>

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
                            <span class="sw-state"><?= $on ? 'Włączone' : 'Wyłączone' ?></span>
                        </label>
                    </div>
                    <?php if ($key === 'analytics_enabled'): ?>
                    <div class="settings-warning">
                        Analityka przechowuje dodatkowe dane aktywności użytkowników: adresy IP, znaczniki czasu, tokeny zamówień oraz typ zdarzenia.
                        Na podstawie tych danych można oszacować <strong>całkowitą liczbę zamówień</strong> od początku działania systemu.
                        <?php if ($analytics_events > 0): ?>
                        Aktualnie w bazie: <strong><?= number_format($analytics_events) ?></strong> <?= $analytics_events === 1 ? 'zdarzenie' : 'zdarzeń' ?> dotyczących <strong><?= number_format($analytics_orders) ?></strong> zamówień.
                        <?php endif; ?>
                    </div>
                    <?php if ($analytics_events > 0): ?>
                    <form method="POST" action="/admin/settings.php"
                          data-confirm="Usunąć wszystkie dane analityczne? Tej operacji nie można cofnąć.">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                        <input type="hidden" name="action" value="clear_analytics">
                        <button type="submit" class="action-btn action-btn--danger">Usuń dane analityczne</button>
                    </form>
                    <?php endif; ?>
                    <?php endif; ?>
                    <?php endforeach; ?>

                </div>
                <?php endforeach; ?>

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
        <div class="section-label">Log błędów</div>
        <div class="log-toolbar">
            <span class="td-muted"><?= number_format($log_total) ?> <?= $log_total === 1 ? 'wiersz' : 'wierszy' ?></span>
            <div class="log-toolbar-actions">
                <?php if ($log_total > 0): ?>
                <a class="action-btn" href="/admin/download_log.php">Pobierz log</a>
                <?php endif; ?>
                <form method="POST" action="/admin/settings.php">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="action" value="clear_log">
                    <button class="action-btn action-btn--danger">Wyczyść log</button>
                </form>
            </div>
        </div>
        <?php if (empty($log_lines)): ?>
        <div class="log-empty">Log jest pusty.</div>
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
        if (value === '' && key !== 'extend_hours_options' && key !== 'site_name') return 'Pole nie może być puste.';
        if (limits[key]) {
            var n = parseInt(value, 10);
            if (isNaN(n) || n < limits[key][0] || n > limits[key][1]) {
                return 'Wartość musi być między ' + limits[key][0] + ' a ' + limits[key][1] + '.';
            }
        }
        if (key === 'extend_hours_options') {
            var parts = value.split(',');
            for (var i = 0; i < parts.length; i++) {
                var n = parseInt(parts[i].trim(), 10);
                if (isNaN(n) || n <= 0) return 'Wpisz liczby całkowite dodatnie oddzielone przecinkami.';
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
                    showPopup('✓ Zapisano', false);
                    setTimeout(function () { location.reload(); }, 600);
                } else {
                    showPopup(d.error || 'Błąd zapisu.', true);
                }
            })
            .catch(function () { showPopup('Błąd połączenia.', true); });
    }

    // ── Toggles: save immediately ─────────────────────────────────────────────
    document.querySelectorAll('.sw input[type="checkbox"]').forEach(function (cb) {
        cb.addEventListener('change', function () {
            var state = cb.closest('.sw').querySelector('.sw-state');
            if (state) state.textContent = cb.checked ? 'Włączone' : 'Wyłączone';
            saveSetting(cb.name, cb.checked ? '1' : '0');
        });
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
})();
</script>
<script src="/admin/admin.js"></script>
</body>
</html>
