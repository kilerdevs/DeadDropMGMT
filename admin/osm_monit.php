<?php
// Small status badge for pages that load OSM resources through
// admin/tile_proxy.php / admin/geocode_proxy.php. Polls osm_status.php
// and shows which pool proxy served the last request — visible only
// while OSM proxy routing is enabled.
require_once dirname(__DIR__) . '/includes/i18n.php';
?>
<div class="osm-monit" id="osm-monit" hidden>
    <span class="osm-monit-dot"></span>
    <span id="osm-monit-text"></span>
</div>
<script nonce="<?= htmlspecialchars($csp_nonce ?? '', ENT_QUOTES, 'UTF-8') ?>">
(function () {
    var el  = document.getElementById('osm-monit');
    var txt = document.getElementById('osm-monit-text');
    if (!el || !txt) return;
    var L = <?= json_encode([
        'via'      => t('admin.osm_monit.via'),
        'failed'   => t('admin.osm_monit.failed'),
        'failover' => t('admin.osm_monit.failover'),
    ]) ?>;
    var timer = null;

    function render(d) {
        // Routing off -> badge off entirely; poll slowly so a re-enable
        // is picked up without hammering the endpoint.
        if (!d.enabled) {
            el.hidden = true;
            return 30000;
        }
        el.hidden = false;
        el.classList.toggle('osm-monit--fail', !!d.failed && !d.via);
        if (d.via) {
            var s = L.via + ' ' + d.via + (d.latency ? ' (' + d.latency + ' ms)' : '');
            if (d.attempts > 1) {
                s += ' \u00b7 ' + L.failover.replace('{n}', d.attempts - 1)
                    + (d.skipped && d.skipped.length ? ': ' + d.skipped.join(', ') : '');
            }
            txt.textContent = s;
        } else if (d.failed) {
            txt.textContent = L.failed;
        } else {
            txt.textContent = L.via + ' \u2026';
        }
        return 5000;
    }

    function tick() {
        fetch('/admin/osm_status.php')
            .then(function (r) { return r.json(); })
            .then(function (d) {
                var interval = render(d) || 5000;
                clearInterval(timer);
                timer = setInterval(tick, interval);
            })
            .catch(function () {});
    }
    tick();
    timer = setInterval(tick, 5000);
})();
</script>
