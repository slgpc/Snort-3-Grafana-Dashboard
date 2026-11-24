-- Snort 3 alerts -> MariaDB (10.5+). Колонки совпадают с snort_alerts в HeavyDB
-- и с JSON-полями json_binding.h, поэтому один и тот же JSONL грузится в обе БД.
-- Время хранится в UTC (format_ts в json_binding.h использует gmtime) - Grafana ждёт именно UTC.

CREATE DATABASE IF NOT EXISTS snort CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE snort;

CREATE TABLE IF NOT EXISTS snort_alerts (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_time     DATETIME(6)  NOT NULL,
    src_ip         VARCHAR(45)  NOT NULL DEFAULT '',
    dst_ip         VARCHAR(45)  NOT NULL DEFAULT '',
    src_port       INT UNSIGNED NOT NULL DEFAULT 0,
    dst_port       INT UNSIGNED NOT NULL DEFAULT 0,
    protocol       SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    priority       TINYINT UNSIGNED  NOT NULL DEFAULT 0,
    generator_id   INT UNSIGNED NOT NULL DEFAULT 0,
    sig_id         INT UNSIGNED NOT NULL DEFAULT 0,
    sig_revision   INT UNSIGNED NOT NULL DEFAULT 0,
    classification VARCHAR(128) NOT NULL DEFAULT '',
    action         VARCHAR(32)  NOT NULL DEFAULT '',
    pkt_len        INT UNSIGNED NOT NULL DEFAULT 0,
    ttl            SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    iface          VARCHAR(32)  NOT NULL DEFAULT '',
    rule_msg       VARCHAR(512) NOT NULL DEFAULT '',
    flow_id        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    raw_json       JSON NULL,
    PRIMARY KEY (id),
    -- идемпотентная догрузка: повторная вставка той же строки игнорируется
    UNIQUE KEY uq_alert (alert_time, flow_id, sig_id, src_port, dst_port),
    KEY ix_sig   (sig_id, generator_id, alert_time),
    KEY ix_src   (src_ip, alert_time),
    KEY ix_dst   (dst_ip, alert_time),
    KEY ix_flow  (flow_id)
) ENGINE=InnoDB ROW_FORMAT=DYNAMIC;

-- Пользователь только для чтения - для источника данных Grafana
-- CREATE USER 'grafana_ro'@'%' IDENTIFIED BY 'CHANGE_ME';
-- GRANT SELECT ON snort.* TO 'grafana_ro'@'%';

-- Ретенция (по желанию): хранить 90 дней
-- SET GLOBAL event_scheduler = ON;
-- CREATE EVENT IF NOT EXISTS ev_snort_retention ON SCHEDULE EVERY 1 DAY
--   DO DELETE FROM snort.snort_alerts WHERE alert_time < UTC_TIMESTAMP() - INTERVAL 90 DAY LIMIT 100000;
