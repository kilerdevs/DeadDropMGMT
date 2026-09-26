(function () {
    'use strict';

    var i18n = window.I18N || {};

    // ── Live countdown for expiry-timer cells ─────────────────────────────────
    function tickAdmin() {
        document.querySelectorAll('.expiry-timer[data-expires]').forEach(function (el) {
            var exp = parseInt(el.dataset.expires, 10);
            var rem = exp - Math.floor(Date.now() / 1000);
            if (rem <= 0) {
                el.textContent = i18n.expired || 'Expired';
                el.className = 'expiry-timer urgent';
                return;
            }
            var h = Math.floor(rem / 3600);
            var m = Math.floor((rem % 3600) / 60);
            var s = rem % 60;
            var parts = [];
            if (h > 0) parts.push(h + 'h');
            parts.push((m < 10 && h > 0 ? '0' : '') + m + 'm');
            parts.push((s < 10 ? '0' : '') + s + 's');
            el.textContent = parts.join(' ');
            el.className = 'expiry-timer' + (rem < 3600 ? ' urgent' : rem < 21600 ? ' warning' : '');
        });
    }
    if (document.querySelector('.expiry-timer[data-expires]')) {
        tickAdmin();
        setInterval(tickAdmin, 1000);
    }

    // ── Confirm before form submit ────────────────────────────────────────────
    document.addEventListener('submit', function (e) {
        var msg = e.target.dataset.confirm;
        if (msg && !window.confirm(msg)) {
            e.preventDefault();
        }
    });

    // ── Live CSRF token for every POST form ───────────────────────────────────
    // The server rotates the session token each time a request verifies it, so
    // the copy rendered into a form goes stale whenever anything else on the
    // page (an autosave, a poll) ran first — the next submit would then die
    // with "invalid CSRF" (or, for logout, silently do nothing). Ask the server
    // for the live token right before the form goes out. Registered after the
    // confirm handler above: a cancelled confirm has already prevented default.
    function freshCsrf() {
        return fetch('/admin/csrf_token.php', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
            .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('token')); })
            .then(function (j) { return j && j.csrf ? j.csrf : Promise.reject(new Error('token')); });
    }
    window.ddmgmtFreshCsrf = freshCsrf;
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (e.defaultPrevented || !form || form.dataset.csrfFresh === '1') return;
        if (String(form.method).toLowerCase() !== 'post') return;
        var input = form.querySelector('input[name="csrf_token"]');
        if (!input) return;
        e.preventDefault();
        var submitter = e.submitter || null;
        freshCsrf().then(function (t) { input.value = t; }, function () { /* keep the rendered one */ })
            .then(function () {
                form.dataset.csrfFresh = '1';
                try {
                    if (form.requestSubmit) { form.requestSubmit(submitter); } else { form.submit(); }
                } finally {
                    delete form.dataset.csrfFresh;
                }
            });
    });

    // ── Copy order info to clipboard ──────────────────────────────────────────
    document.querySelectorAll('[data-copy]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var token = btn.dataset.token || '';
            var code  = btn.dataset.code  || i18n.copy_no_password || '(none)';
            var url   = window.location.protocol + '//' + window.location.host + '/?token=' + token;
            var text  = (i18n.copy_link_label || 'Delivery link: ') + url + '\n' + (i18n.copy_password_label || 'Pickup password: ') + code + '\n\n' + (i18n.copy_warning || '');

            function showOk() {
                var orig = btn.textContent;
                btn.textContent = i18n.copied || 'Copied ✓';
                setTimeout(function () { btn.textContent = orig; }, 2000);
            }

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(showOk).catch(fallback);
            } else {
                fallback();
            }

            function fallback() {
                var el = document.createElement('textarea');
                el.value = text;
                // Stylesheet class, not el.style: style-src has no
                // 'unsafe-inline', so inline style writes are blocked.
                el.className = 'copy-scratch';
                document.body.appendChild(el);
                el.focus();
                el.select();
                try { document.execCommand('copy'); } catch (e) {}
                document.body.removeChild(el);
                showOk();
            }
        });
    });

    // ── Mobile sidebar toggle ─────────────────────────────────────────────────
    // Elements are injected into <body> (NOT inside .shell) so they never
    // participate in the flex layout and cause no desktop rendering artifacts.
    var _stSidebar = document.getElementById('sidebar');
    if (_stSidebar) {
        var _stBtn = document.createElement('button');
        _stBtn.className = 'sidebar-toggle';
        _stBtn.setAttribute('aria-label', i18n.menu_aria || 'Menu');
        _stBtn.innerHTML = '&#9776;';

        var _stBackdrop = document.createElement('div');
        _stBackdrop.className = 'sidebar-backdrop';

        document.body.appendChild(_stBtn);
        document.body.appendChild(_stBackdrop);

        _stBtn.addEventListener('click', function () {
            _stSidebar.classList.add('sidebar-open');
            _stBackdrop.classList.add('sidebar-open');
            // The [hidden] rule beats the mobile display rule, and unlike
            // _stBtn.style it is not blocked by style-src.
            _stBtn.hidden = true;
        });
        _stBackdrop.addEventListener('click', function () {
            _stSidebar.classList.remove('sidebar-open');
            _stBackdrop.classList.remove('sidebar-open');
            _stBtn.hidden = false;
        });
    }
})();
