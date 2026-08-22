(function () {
    'use strict';

    // ── Order expiry countdown ────────────────────────────────────────────────
    var el = document.getElementById('expiry-countdown');
    if (el) {
        var expires = parseInt(el.dataset.expires, 10);
        var tick = function () {
            var remaining = expires - Math.floor(Date.now() / 1000);
            if (remaining <= 0) {
                el.textContent = window.I18N ? window.I18N.order_expired : 'Order expired.';
                el.className = 'expiry-timer expired';
                return;
            }
            var h = Math.floor(remaining / 3600);
            var m = Math.floor((remaining % 3600) / 60);
            var s = remaining % 60;
            var parts = [];
            if (h > 0) parts.push(h + 'h');
            parts.push((m < 10 && h > 0 ? '0' : '') + m + 'm');
            parts.push((s < 10 ? '0' : '') + s + 's');
            el.textContent = parts.join(' ');
            el.className = 'expiry-timer' + (remaining < 3600 ? ' urgent' : remaining < 21600 ? ' warning' : '');
        };
        tick();
        setInterval(tick, 1000);
    }

    // ── Post-receive redirect countdown ──────────────────────────────────────
    var rcd = document.getElementById('redirect-countdown');
    if (rcd) {
        var secs = parseInt(rcd.dataset.secs, 10);
        var ri = setInterval(function () {
            secs--;
            rcd.textContent = secs;
            if (secs <= 0) {
                clearInterval(ri);
                window.location.href = '/';
            }
        }, 1000);
    }
})();
