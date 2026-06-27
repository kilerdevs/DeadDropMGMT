(function () {
    'use strict';

    var photos = Array.from(document.querySelectorAll('.photo-item img'));
    if (!photos.length) return;

    // ── Build lightbox DOM ────────────────────────────────────────────────────
    var lb = document.createElement('div');
    lb.id = 'lightbox';
    lb.innerHTML =
        '<div class="lb-backdrop"></div>' +
        '<button class="lb-close" aria-label="Zamknij">&times;</button>' +
        '<button class="lb-prev" aria-label="Poprzednie">&#8249;</button>' +
        '<div class="lb-stage">' +
            '<img class="lb-img" src="" alt="">' +
            '<div class="lb-caption"></div>' +
            '<div class="lb-counter"></div>' +
        '</div>' +
        '<button class="lb-next" aria-label="Następne">&#8250;</button>';
    document.body.appendChild(lb);

    var lbImg     = lb.querySelector('.lb-img');
    var lbCaption = lb.querySelector('.lb-caption');
    var lbCounter = lb.querySelector('.lb-counter');
    var lbPrev    = lb.querySelector('.lb-prev');
    var lbNext    = lb.querySelector('.lb-next');
    var current   = 0;

    function show(index) {
        current = (index + photos.length) % photos.length;
        var img = photos[current];
        lbImg.src = img.src;
        lbImg.alt = img.alt;
        lbCaption.textContent = img.alt || '';
        lbCounter.textContent = (current + 1) + ' / ' + photos.length;
        lbPrev.style.display = photos.length > 1 ? '' : 'none';
        lbNext.style.display = photos.length > 1 ? '' : 'none';
        lb.classList.add('active');
        document.body.classList.add('lb-open');
    }

    function hide() {
        lb.classList.remove('active');
        document.body.classList.remove('lb-open');
        lbImg.src = '';
    }

    // Click photos to open
    photos.forEach(function (img, i) {
        img.style.cursor = 'zoom-in';
        img.addEventListener('click', function () { show(i); });
    });

    lb.querySelector('.lb-close').addEventListener('click', hide);
    lb.querySelector('.lb-backdrop').addEventListener('click', hide);
    lbPrev.addEventListener('click', function (e) { e.stopPropagation(); show(current - 1); });
    lbNext.addEventListener('click', function (e) { e.stopPropagation(); show(current + 1); });

    // Keyboard
    document.addEventListener('keydown', function (e) {
        if (!lb.classList.contains('active')) return;
        if (e.key === 'Escape')      { hide(); }
        if (e.key === 'ArrowLeft')   { show(current - 1); }
        if (e.key === 'ArrowRight')  { show(current + 1); }
    });

    // Touch swipe
    var touchX = 0;
    lb.addEventListener('touchstart', function (e) {
        touchX = e.touches[0].clientX;
    }, { passive: true });
    lb.addEventListener('touchend', function (e) {
        var diff = touchX - e.changedTouches[0].clientX;
        if (Math.abs(diff) > 50) { show(current + (diff > 0 ? 1 : -1)); }
    }, { passive: true });
})();
