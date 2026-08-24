-- Dead Drop Management — complete database setup.
-- One file, safe to run on ANY starting state: a brand-new empty database,
-- an existing install from any earlier version, or even a fully up-to-date
-- database (running it again is a harmless no-op). Every statement is
-- idempotent, and every ALTER is guarded through information_schema +
-- PREPARE — a portable pattern that works identically on MySQL 8.0+ and
-- MariaDB (neither engine supports IF NOT EXISTS on ADD COLUMN reliably,
-- MySQL not at all).
--
--   mysql -u root -p < setup.sql

CREATE DATABASE IF NOT EXISTS deaddrops
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE deaddrops;

-- ── Users ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id               INT           AUTO_INCREMENT PRIMARY KEY,
    username         VARCHAR(64)   NOT NULL UNIQUE,
    password_hash    VARCHAR(255)  NOT NULL,
    role             ENUM('owner','courier') NOT NULL DEFAULT 'courier',
    totp_secret_enc  TEXT                   DEFAULT NULL,
    totp_secret_iv   CHAR(32)               DEFAULT NULL,
    totp_enabled     TINYINT(1)    NOT NULL DEFAULT 0,
    enrollment_hash  CHAR(64)               DEFAULT NULL,
    enrollment_expires DATETIME             DEFAULT NULL,
    lang             CHAR(2)       NOT NULL DEFAULT 'en',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Installs from before 2FA / per-account language / enrollment secrets
-- existed won't have these columns yet. One guarded ALTER per column —
-- MySQL has no ADD COLUMN IF NOT EXISTS, so existence is checked by hand.
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_secret_enc');
SET @s = IF(@c = 0, 'ALTER TABLE users ADD COLUMN totp_secret_enc TEXT DEFAULT NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_secret_iv');
SET @s = IF(@c = 0, 'ALTER TABLE users ADD COLUMN totp_secret_iv CHAR(32) DEFAULT NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_enabled');
SET @s = IF(@c = 0, 'ALTER TABLE users ADD COLUMN totp_enabled TINYINT(1) NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'lang');
SET @s = IF(@c = 0, 'ALTER TABLE users ADD COLUMN lang CHAR(2) NOT NULL DEFAULT ''en''', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'enrollment_hash');
SET @s = IF(@c = 0, 'ALTER TABLE users ADD COLUMN enrollment_hash CHAR(64) DEFAULT NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'enrollment_expires');
SET @s = IF(@c = 0, 'ALTER TABLE users ADD COLUMN enrollment_expires DATETIME DEFAULT NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- ── Orders ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS orders (
    id                   INT           AUTO_INCREMENT PRIMARY KEY,
    created_by           INT                    DEFAULT NULL,
    order_token          CHAR(16)      NOT NULL UNIQUE,
    pickup_password_hash VARCHAR(255)  NOT NULL,
    -- Deprecated: legacy installs may still carry the recoverable AES copy
    -- of the pickup password. New code never writes it — run
    -- tools/purge_pickup_password_recovery.php to clear leftover values.
    pickup_password_enc  TEXT                   DEFAULT NULL,
    pickup_password_iv   CHAR(32)               DEFAULT NULL,
    location_encrypted   TEXT          NOT NULL,
    location_iv          CHAR(32)      NOT NULL,
    status               ENUM('preparing','delivered') NOT NULL DEFAULT 'preparing',
    created_at           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at         DATETIME               DEFAULT NULL,
    expires_at           DATETIME               DEFAULT NULL,
    notes                TEXT                   DEFAULT NULL,

    INDEX idx_token      (order_token),
    INDEX idx_status     (status),
    INDEX idx_created    (created_at),
    INDEX idx_expires    (expires_at),
    INDEX idx_created_by (created_by),
    CONSTRAINT fk_orders_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Installs from before the multi-user system won't have created_by yet.
SET @c = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'created_by');
SET @s = IF(@c = 0, 'ALTER TABLE orders ADD COLUMN created_by INT DEFAULT NULL AFTER id', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

SET @c = (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND INDEX_NAME = 'idx_created_by');
SET @s = IF(@c = 0, 'ALTER TABLE orders ADD INDEX idx_created_by (created_by)', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;

-- Neither engine has "ADD CONSTRAINT IF NOT EXISTS" for foreign keys, so
-- guard it by hand — only add fk_orders_created_by if it isn't already there.
SET @fk_exists = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'orders'
      AND CONSTRAINT_NAME = 'fk_orders_created_by'
);
SET @fk_sql = IF(@fk_exists = 0,
    'ALTER TABLE orders ADD CONSTRAINT fk_orders_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL',
    'SELECT 1'
);
PREPARE fk_stmt FROM @fk_sql;
EXECUTE fk_stmt;
DEALLOCATE PREPARE fk_stmt;

-- ── Orders: DB-enforced state machine ─────────────────────────────────────────
-- preparing = nothing delivered yet (no timestamps), delivered = both
-- timestamps present. Application code uses conditional UPDATE/DELETE plus
-- affected-row checks — this CHECK is the last line of defense against
-- impossible states from any path.
--
-- Legacy rows that violate the invariant are normalized first so the ALTER
-- never fails mid-upgrade:
UPDATE orders
   SET delivered_at = COALESCE(delivered_at, created_at)
 WHERE status = 'delivered' AND delivered_at IS NULL;
UPDATE orders
   SET expires_at = COALESCE(expires_at, DATE_ADD(COALESCE(delivered_at, created_at), INTERVAL 24 HOUR))
 WHERE status = 'delivered' AND expires_at IS NULL;

SET @chk_exists = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'orders'
      AND CONSTRAINT_TYPE = 'CHECK'
      AND CONSTRAINT_NAME = 'chk_orders_state'
);
SET @chk_sql = IF(@chk_exists = 0,
    'ALTER TABLE orders ADD CONSTRAINT chk_orders_state CHECK (
        (status = ''preparing'' AND delivered_at IS NULL)
     OR (status = ''delivered'' AND delivered_at IS NOT NULL))',
    'SELECT 1'
);
PREPARE chk_stmt FROM @chk_sql;
EXECUTE chk_stmt;
DEALLOCATE PREPARE chk_stmt;

-- ── Order photos ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS order_photos (
    id          INT           AUTO_INCREMENT PRIMARY KEY,
    order_id    INT           NOT NULL,
    filename    VARCHAR(320)  NOT NULL,
    caption     TEXT                   DEFAULT NULL,
    sort_order  TINYINT       NOT NULL DEFAULT 0,
    uploaded_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    INDEX idx_order_id (order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── OSM proxy pool ────────────────────────────────────────────────────────────
-- Optional outbound proxies for the admin panel's OpenStreetMap requests
-- (tile_proxy.php / geocode_proxy.php). Empty table = direct connection.

CREATE TABLE IF NOT EXISTS osm_proxies (
    id           INT          AUTO_INCREMENT PRIMARY KEY,
    url          VARCHAR(255) NOT NULL,
    label        VARCHAR(128) NOT NULL DEFAULT '',
    source       VARCHAR(64)  NOT NULL DEFAULT 'manual',
    last_status  VARCHAR(16)  NOT NULL DEFAULT 'new',
    latency_ms   INT                   DEFAULT NULL,
    last_checked DATETIME              DEFAULT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_url (url)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Older installs created source as VARCHAR(16) ('manual'/'discovered' only);
-- widen it so discovery can record the actual list a proxy came from.
SET @src_len = (
    SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'osm_proxies'
      AND COLUMN_NAME  = 'source'
);
SET @src_sql = IF(@src_len IS NOT NULL AND @src_len < 64,
    'ALTER TABLE osm_proxies MODIFY source VARCHAR(64) NOT NULL DEFAULT ''manual''',
    'SELECT 1'
);
PREPARE src_stmt FROM @src_sql;
EXECUTE src_stmt;
DEALLOCATE PREPARE src_stmt;

-- ── Event log ─────────────────────────────────────────────────────────────────
-- event_type is VARCHAR (not ENUM) for forward compatibility.

CREATE TABLE IF NOT EXISTS order_events (
    id           INT           AUTO_INCREMENT PRIMARY KEY,
    order_id     INT                    DEFAULT NULL,
    order_token  CHAR(16)               DEFAULT NULL,
    event_type   VARCHAR(32)   NOT NULL,
    ip_address   VARCHAR(45)   NOT NULL,
    user_agent   TEXT                   DEFAULT NULL,
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_order_id   (order_id),
    INDEX idx_event_type (event_type),
    INDEX idx_ip         (ip_address(20)),
    INDEX idx_created    (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Rate limiting (IP-based, DB-backed) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS rate_limits (
    ip_address   VARCHAR(45) NOT NULL,
    scope        VARCHAR(32) NOT NULL,
    count        INT         NOT NULL DEFAULT 0,
    window_start DATETIME    NOT NULL,
    PRIMARY KEY (ip_address, scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Audit log (admin write actions) ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    id          INT           AUTO_INCREMENT PRIMARY KEY,
    user_id     INT                    DEFAULT NULL,
    username    VARCHAR(64)   NOT NULL,
    action      VARCHAR(64)   NOT NULL,
    order_id    INT                    DEFAULT NULL,
    order_token CHAR(16)               DEFAULT NULL,
    detail      VARCHAR(255)           DEFAULT NULL,
    ip_address  VARCHAR(45)   NOT NULL,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_created (created_at),
    INDEX idx_user     (user_id),
    INDEX idx_action   (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── Settings ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS settings (
    key_name   VARCHAR(64)  NOT NULL PRIMARY KEY,
    value      TEXT         NOT NULL,
    label      VARCHAR(128) NOT NULL DEFAULT '',
    updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO settings (key_name, value, label) VALUES
    ('site_name',               'MGT',     'Nazwa serwisu'),
    ('default_lang',            'en',      'Domyślny język strony publicznej'),
    ('order_ttl_hours',         '24',      'Czas życia zamówienia od dostarczenia (godziny)'),
    ('extend_hours_options',    '24,48,72','Opcje przedłużenia (godziny, rozdzielone przecinkiem)'),
    ('rate_limit_enabled',      '1',       'Włącz limitowanie prób wg adresu IP'),
    ('rate_limit_max',          '10',      'Maks. nieudanych prób przed blokadą'),
    ('rate_limit_window_min',   '15',      'Okno blokady (minuty)'),
    ('admin_session_hours',     '4',       'Czas sesji admina (godziny)'),
    ('max_photo_mb',            '12',      'Maks. rozmiar zdjęcia (MB)'),
    ('allow_status_lookup',     '1',       'Zezwól na sprawdzenie statusu bez hasła'),
    ('require_delivered_reveal','1',       'Ukryj lokalizację gdy W PRZYGOTOWANIU'),
    ('analytics_enabled',       '1',       'Włącz analitykę'),
    ('compliance_note_enabled', '0',       'Pokaż notę o zgodności na stronach publicznych'),
    ('osm_proxy_enabled',       '0',       'Przekieruj ruch OSM przez serwery proxy'),
    ('show_error_log',          '0',       'Pokaż log błędów w ustawieniach'),
    ('last_cleanup',            '0',       '')
ON DUPLICATE KEY UPDATE label = VALUES(label);
