<?php
// Small status caption for pages that load OSM resources through
// admin/tile_proxy.php / admin/geocode_proxy.php. Polls osm_status.php
// and shows which pool proxy served the last request — visible only
// while OSM proxy routing is enabled. Include it DIRECTLY UNDER the map it
// describes. It lives in the page flow (never an overlay), so even a long
// failover message pushes content down instead of covering it.
require_once dirname(__DIR__) . '/includes/i18n.php';
?>
<div class="osm-monit" id="osm-monit" hidden>
    <span class="osm-monit-dot"></span>
    <span class="osm-monit-body">
        <span id="osm-monit-text"></span>
        <span class="osm-monit-detail" id="osm-monit-detail" hidden></span>
    </span>
</div>
<script nonce="<?= htmlspecialchars($csp_nonce ?? '', ENT_QUOTES, 'UTF-8') ?>">
(function () {
    var el  = document.getElementById('osm-monit');
    var txt = document.getElementById('osm-monit-text');
    var det = document.getElementById('osm-monit-detail');
    if (!el || !txt || !det) return;
    var L = <?= json_encode([
        'via'      => t('admin.osm_monit.via'),
        'failed'   => t('admin.osm_monit.failed'),
        'failover' => t('admin.osm_monit.failover'),
    ]) ?>;
    var timer = null;
    function schedule(ms) {
        if (timer) clearTimeout(timer);
        timer = setTimeout(tick, ms);
    }

    function render(d) {
        // Routing off -> badge off entirely; poll slowly so a re-enable
        // is picked up without hammering the endpoint.
        if (!d.enabled) {
            el.hidden = true;
            return 30000;
        }
        el.hidden = false;
        el.classList.toggle('osm-monit--fail', !!d.failed && !d.via);
        det.hidden = true;
        det.textContent = '';
        if (d.via) {
            txt.textContent = L.via + ' ' + d.via + (d.latency ? ' (' + d.latency + ' ms)' : '');
            if (d.attempts > 1) {
                // Failover: what was skipped goes on a second, muted line, capped
                // so a pool full of dead proxies cannot grow the strip unbounded.
                var sk = d.skipped || [];
                det.textContent = L.failover.replace('{n}', d.attempts - 1)
                    + (sk.length ? ': ' + sk.slice(0, 3).join(', ') + (sk.length > 3 ? ' +' + (sk.length - 3) : '') : '');
                det.hidden = false;
            }
        } else if (d.failed) {
            txt.textContent = L.failed;
        } else {
            txt.textContent = L.via + ' \u2026';
        }
        return 5000;
    }

    function tick() {
        // Chained, never overlapping: the next round waits for this answer.
        // Hidden tabs pause (an open map tab must not keep the admin logged
        // in forever by refreshing login_time every 5 s).
        if (document.hidden) { schedule(5000); return; }
        fetch('/admin/osm_status.php')
            .then(function (r) { return r.json(); })
            .then(function (d) {
                schedule(render(d) || 5000);
            })
            .catch(function () { schedule(5000); });
    }
    tick();
    document.addEventListener('visibilitychange', function () {
        if (!document.hidden) tick();
    });
})();
</script>
