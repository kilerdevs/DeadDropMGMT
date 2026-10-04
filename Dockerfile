# DeadDropMGMT — PHP 8.5 / Apache with exactly the extensions the app touches.
# Config is rendered from config.php.example at first boot (see docker/entrypoint.sh);
# secrets arrive via DDMGMT_* environment variables, never baked into the image.

# Pinned by digest (Dependabot bumps it): a re-pushed tag cannot swap the base
# under a rebuild without a reviewed diff.
FROM php:8.5-apache@sha256:70d80539dcacae817d9a1320518b95c86bb9568835ef3a7a024d57a4898c90e4

# gd needs freetype/jpeg/png/webp system libs, zip needs libzip; everything
# else (openssl, fileinfo, session, json) ships enabled in the base image
# already. ZipArchive is required by the web installer to unpack releases.
# APT_BUST (CI: day, e.g. 2026-W40-7) re-dates this layer daily so apt-get
# upgrade tracks fresh Debian packages instead of serving stale cached
# layers (a mid-week DSA failed the Grype gate with a layer no code change
# could refresh).
ARG APT_BUST=none
RUN echo "apt cache day: $APT_BUST" \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        libwebp-dev \
        libzip-dev \
 && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
 && docker-php-ext-install -j"$(nproc)" gd pdo_mysql zip \
 # The -dev packages stay only for the compile above: mark what the built
 # extensions actually link, then purge the headers (30-60 MB and fewer
 # packages for Grype/Syft). dpkg-query keeps this robust across Debian
 # suites (t64 renames and all) — unknown names simply match nothing.
 && _rtlibs="$(dpkg-query -W -f='${Package}\n' 'libfreetype6*' 'libjpeg62-turbo*' 'libpng16*' 'libwebp*' 'libzip*' 2>/dev/null)" \
 && { [ -z "$_rtlibs" ] || apt-mark manual $_rtlibs; } \
 && apt-get purge -y --auto-remove \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        libwebp-dev \
        libzip-dev \
 && a2enmod rewrite headers \
 && rm -rf /var/lib/apt/lists/*

# AllowOverride All so the shipped .htaccess rules (routing, blocking includes/,
# config.php, logs/) take effect.
COPY docker/apache.conf /etc/apache2/conf-available/zz-deaddrop.conf
RUN a2enconf zz-deaddrop

COPY . /var/www/html
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/php-ddmgmt.ini /usr/local/etc/php/conf.d/zz-ddmgmt-runtime.ini
RUN chmod +x /usr/local/bin/entrypoint.sh \
 # pristine config template outside the docroot for first-boot rendering
 && cp /var/www/html/config.php.example /usr/local/share/config.php.template \
 # writable runtime dirs; real content comes from volumes at runtime
 && mkdir -p /var/www/html/logs /var/www/html/uploads /var/www/html/cache/osm_tiles /var/www/html/data/maps /var/www/html/tiles /config \
 && chown -R www-data:www-data /var/www/html/logs /var/www/html/uploads /var/www/html/cache /var/www/html/data /var/www/html/tiles /config \
 # the base image leaves the docroot itself www-data-owned and world-writable
 # (1777): only the runtime directories above need to be writable, never the
 # docroot root — www-data could otherwise drop a *.php there or replace the
 # root-owned config.php (both only need write access to the directory)
 && chown root:root /var/www/html && chmod 755 /var/www/html

# Build provenance for Settings → Version (owners only). Produced on the
# build host by tools/build_info.sh and passed through the compose files as
# DDMGMT_BUILD_INFO; empty (a plain `docker build`) just shows "unknown build".
# Kept outside the docroot: nothing here is ever served.
ARG DDMGMT_BUILD_INFO=""
RUN if [ -n "$DDMGMT_BUILD_INFO" ]; then \
        printf '%s' "$DDMGMT_BUILD_INFO" | base64 -d > /usr/local/share/ddmgmt-build.json || rm -f /usr/local/share/ddmgmt-build.json; \
    fi

WORKDIR /var/www/html
# Real health signal: Apache + PHP + config rendering all working — a plain
# HTTP GET of the public page must return something HTML-shaped. curl/wget
# are not in the image; PHP itself does the probing.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD php -r 'exit(str_contains((string)@file_get_contents("http://127.0.0.1/healthz.php"), "ok") ? 0 : 1);'
ENTRYPOINT ["entrypoint.sh"]
CMD ["apache2-foreground"]
