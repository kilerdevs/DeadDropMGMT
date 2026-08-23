# DeadDropMGMT — PHP 8.3 / Apache with exactly the extensions the app touches.
# Config is rendered from config.php.example at first boot (see docker/entrypoint.sh);
# secrets arrive via DDMGMT_* environment variables, never baked into the image.

FROM php:8.3-apache

# gd needs freetype/jpeg/png system libs; everything else (openssl, fileinfo,
# session, json) ships enabled in the base image already.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" gd pdo_mysql \
 && a2enmod rewrite headers \
 && rm -rf /var/lib/apt/lists/*

# AllowOverride All so the shipped .htaccess rules (routing, blocking includes/,
# config.php, logs/) take effect.
COPY docker/apache.conf /etc/apache2/conf-available/deaddrop.conf
RUN a2enconf deaddrop

COPY . /var/www/html
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 # pristine config template outside the docroot for first-boot rendering
 && cp /var/www/html/config.php.example /usr/local/share/config.php.template \
 # writable runtime dirs; real content comes from volumes at runtime
 && mkdir -p /var/www/html/logs /var/www/html/uploads /var/www/html/cache/osm_tiles /config \
 && chown -R www-data:www-data /var/www/html/logs /var/www/html/uploads /var/www/html/cache /config

WORKDIR /var/www/html
ENTRYPOINT ["entrypoint.sh"]
CMD ["apache2-foreground"]
