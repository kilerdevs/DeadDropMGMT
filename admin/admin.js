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
                el.style.cssText = 'position:fixed;opacity:0;top:0;left:0;';
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
            _stBtn.style.display = 'none';
        });
        _stBackdrop.addEventListener('click', function () {
            _stSidebar.classList.remove('sidebar-open');
            _stBackdrop.classList.remove('sidebar-open');
            _stBtn.style.display = '';
        });
    }
})();
