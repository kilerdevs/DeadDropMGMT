-- Dead Drop Management — complete database setup.
-- One file, safe to run on ANY starting state: a brand-new empty database,
-- an existing install from any earlier version, or even a fully up-to-date
-- database (running it again is a harmless no-op). Every statement is
-- idempotent (IF NOT EXISTS / ON DUPLICATE KEY / a guarded check for the
-- one foreign key MariaDB doesn't support IF NOT EXISTS on).
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
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Installs from before 2FA existed won't have these columns yet.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT       DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS totp_secret_iv  CHAR(32)   DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS totp_enabled    TINYINT(1) NOT NULL DEFAULT 0;

-- ── Orders ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS orders (
    id                   INT           AUTO_INCREMENT PRIMARY KEY,
    created_by           INT                    DEFAULT NULL,
    order_token          CHAR(16)      NOT NULL UNIQUE,
    pickup_password_hash VARCHAR(255)  NOT NULL,
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
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS created_by INT DEFAULT NULL AFTER id,
    ADD INDEX  IF NOT EXISTS idx_created_by (created_by);

-- MariaDB has no "ADD CONSTRAINT IF NOT EXISTS" for foreign keys, so guard
-- it by hand — only add fk_orders_created_by if it isn't already there.
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
    ('show_error_log',          '0',       'Pokaż log błędów w ustawieniach'),
    ('last_cleanup',            '0',       '')
ON DUPLICATE KEY UPDATE label = VALUES(label);
