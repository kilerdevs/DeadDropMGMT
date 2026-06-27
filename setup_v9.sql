-- setup_v9.sql — migration for installs created before the multi-user system.
-- ONLY run this on existing pre-v9 installations.
-- Fresh installs should use setup.sql instead (already includes all of this).

CREATE TABLE IF NOT EXISTS users (
    id            INT           AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)   NOT NULL UNIQUE,
    password_hash VARCHAR(255)  NOT NULL,
    role          ENUM('owner','courier') NOT NULL DEFAULT 'courier',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS created_by INT DEFAULT NULL AFTER id,
    ADD INDEX  IF NOT EXISTS idx_created_by (created_by);

ALTER TABLE orders
    ADD CONSTRAINT fk_orders_created_by
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;

INSERT INTO settings (key_name, value, label) VALUES
    ('last_cleanup', '0', '')
ON DUPLICATE KEY UPDATE key_name = key_name;
