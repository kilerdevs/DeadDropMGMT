-- setup_v10.sql — migration adding 2FA, IP-based rate limiting, and the admin audit log.
-- ONLY run this on existing pre-v10 installations.
-- Fresh installs should use setup.sql instead (already includes all of this).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT       DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS totp_secret_iv  CHAR(32)    DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS totp_enabled    TINYINT(1)  NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS rate_limits (
    ip_address   VARCHAR(45) NOT NULL,
    scope        VARCHAR(32) NOT NULL,
    count        INT         NOT NULL DEFAULT 0,
    window_start DATETIME    NOT NULL,
    PRIMARY KEY (ip_address, scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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

INSERT INTO settings (key_name, value, label) VALUES
    ('rate_limit_enabled', '1', 'Włącz limitowanie prób wg adresu IP')
ON DUPLICATE KEY UPDATE key_name = key_name;
