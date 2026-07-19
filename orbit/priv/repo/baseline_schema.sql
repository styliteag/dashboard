-- Baseline schema (MariaDB) captured from the Alembic head at orbit cutover.
-- Idempotent (CREATE TABLE IF NOT EXISTS, and NO 'DROP TABLE'): a no-op on an
-- existing DB, a full create on an empty one. mariadb-dump emits DROP TABLE by
-- default -- the dump recipe passes --skip-add-drop-table for exactly this
-- reason. A DROP here would delete production data on the first orbit boot. Tables are emitted in FK-dependency order (parents
-- first) so creation succeeds regardless of connection/transaction behaviour;
-- the FK-check guard is belt-and-suspenders. Regenerate via 'just orbit-dump-baseline'.
SET FOREIGN_KEY_CHECKS = 0;
CREATE TABLE IF NOT EXISTS `groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(64) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `password_version` int(11) NOT NULL DEFAULT 1,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `role` varchar(16) NOT NULL DEFAULT 'view_only',
  `totp_secret_enc` blob DEFAULT NULL,
  `totp_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `is_bootstrap` tinyint(1) NOT NULL DEFAULT 0,
  `disabled` tinyint(1) NOT NULL DEFAULT 0,
  `is_superadmin` tinyint(1) NOT NULL DEFAULT 0,
  `last_login_ip` varchar(45) DEFAULT NULL,
  `last_login_country` varchar(2) DEFAULT NULL,
  `last_login_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `api_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  `key_hash` varchar(64) NOT NULL,
  `prefix` varchar(20) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_used_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `revealable` tinyint(1) NOT NULL DEFAULT 0,
  `key_enc` blob DEFAULT NULL,
  `purpose` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key_hash` (`key_hash`),
  KEY `ix_api_keys_key_hash` (`key_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `access_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ts` datetime NOT NULL,
  `user_id` bigint(20) DEFAULT NULL,
  `ip` varchar(45) NOT NULL,
  `method` varchar(8) NOT NULL,
  `path` varchar(255) NOT NULL,
  `status` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_access_events_ts` (`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `access_stats` (
  `bucket` datetime NOT NULL,
  `principal_type` varchar(8) NOT NULL,
  `principal_key` varchar(32) NOT NULL,
  `count` bigint(20) NOT NULL DEFAULT 0,
  `last_ip` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`bucket`,`principal_type`,`principal_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `app_settings` (
  `key` varchar(64) NOT NULL,
  `value` text NOT NULL,
  `is_secret` tinyint(1) NOT NULL DEFAULT 0,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `geoip_config` (
  `id` int(11) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `countries` text NOT NULL,
  `whitelist` text NOT NULL,
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `updated_by` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `geoip_denial_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ts` datetime NOT NULL,
  `ip` varchar(45) NOT NULL,
  `country` varchar(4) DEFAULT NULL,
  `path` varchar(255) NOT NULL,
  `reason` varchar(32) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_geoip_denial_events_ts` (`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `geoip_denial_stats` (
  `bucket` date NOT NULL,
  `reason` varchar(32) NOT NULL,
  `country` varchar(4) NOT NULL,
  `count` bigint(20) NOT NULL DEFAULT 0,
  PRIMARY KEY (`bucket`,`reason`,`country`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `instances` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  `base_url` varchar(512) NOT NULL,
  `api_key_enc` blob NOT NULL,
  `api_secret_enc` blob NOT NULL,
  `ca_bundle` text DEFAULT NULL,
  `ssl_verify` tinyint(1) NOT NULL DEFAULT 1,
  `agent_token` varchar(128) DEFAULT NULL,
  `agent_last_seen` datetime DEFAULT NULL,
  `location` varchar(255) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `tags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`tags`)),
  `last_success_at` datetime DEFAULT NULL,
  `last_error_at` datetime DEFAULT NULL,
  `last_error_message` text DEFAULT NULL,
  `deleted_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `name_active_key` varchar(128) GENERATED ALWAYS AS (case when `deleted_at` is null then `name` end) STORED,
  `transport` varchar(16) NOT NULL DEFAULT 'direct',
  `device_type` varchar(32) NOT NULL DEFAULT 'opnsense',
  `status_snapshot` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`status_snapshot`)),
  `gui_login_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `slug` varchar(63) NOT NULL,
  `ssh_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `ssh_port` int(11) NOT NULL DEFAULT 9922,
  `ssh_user` varchar(64) NOT NULL DEFAULT 'root',
  `ssh_key_enc` blob DEFAULT NULL,
  `ssh_host_key` text DEFAULT NULL,
  `poll_interval_seconds` int(11) DEFAULT NULL,
  `push_interval_seconds` int(11) DEFAULT NULL,
  `ping_url` varchar(512) DEFAULT NULL,
  `maintenance` tinyint(1) NOT NULL DEFAULT 0,
  `firmware_locked` tinyint(1) NOT NULL DEFAULT 0,
  `group_id` int(11) NOT NULL,
  `shell_enabled` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_instances_slug` (`slug`),
  UNIQUE KEY `agent_token` (`agent_token`),
  UNIQUE KEY `uq_instances_name_active` (`name_active_key`),
  KEY `ix_instances_group_id` (`group_id`),
  CONSTRAINT `fk_instances_group_id_groups` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `apikey_groups` (
  `apikey_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`apikey_id`,`group_id`),
  KEY `group_id` (`group_id`),
  CONSTRAINT `apikey_groups_ibfk_1` FOREIGN KEY (`apikey_id`) REFERENCES `api_keys` (`id`) ON DELETE CASCADE,
  CONSTRAINT `apikey_groups_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `ts` datetime NOT NULL DEFAULT current_timestamp(),
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(64) NOT NULL,
  `target_type` varchar(64) DEFAULT NULL,
  `target_id` varchar(128) DEFAULT NULL,
  `request_id` varchar(64) DEFAULT NULL,
  `result` varchar(16) NOT NULL,
  `detail` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`detail`)),
  `source_ip` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `ix_audit_log_ts` (`ts`),
  KEY `ix_audit_log_action` (`action`),
  CONSTRAINT `audit_log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `auth_sessions` (
  `sid` varchar(32) NOT NULL,
  `user_id` int(11) NOT NULL,
  `ip` varchar(45) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `last_seen_at` datetime NOT NULL,
  `ended_at` datetime DEFAULT NULL,
  `end_reason` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`sid`),
  KEY `ix_auth_sessions_user_id` (`user_id`),
  KEY `ix_auth_sessions_last_seen_at` (`last_seen_at`),
  CONSTRAINT `fk_auth_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `check_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `ts` datetime NOT NULL DEFAULT current_timestamp(),
  `check_key` varchar(128) NOT NULL,
  `old_state` int(11) NOT NULL,
  `new_state` int(11) NOT NULL,
  `summary` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `ix_check_event_lookup` (`instance_id`,`ts`),
  KEY `ix_check_events_ts` (`ts`),
  CONSTRAINT `check_events_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `config_backups` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `collected_at` datetime NOT NULL DEFAULT current_timestamp(),
  `sha256` varchar(64) NOT NULL,
  `bytes` int(11) NOT NULL DEFAULT 0,
  `source` varchar(16) NOT NULL DEFAULT 'agent',
  `content_enc` mediumblob NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_config_backup_lookup` (`instance_id`,`collected_at`),
  CONSTRAINT `config_backups_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `connectivity_monitors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `source` varchar(64) NOT NULL DEFAULT '',
  `destination` varchar(253) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `ping_count` int(11) NOT NULL DEFAULT 3,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_connectivity_monitor` (`instance_id`,`name`),
  KEY `ix_connectivity_monitors_instance_id` (`instance_id`),
  CONSTRAINT `connectivity_monitors_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `enrollment_codes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code_hash` varchar(64) NOT NULL,
  `instance_id` int(11) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `code_hash` (`code_hash`),
  KEY `instance_id` (`instance_id`),
  KEY `ix_enrollment_codes_code_hash` (`code_hash`),
  CONSTRAINT `enrollment_codes_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `entity_comments` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `kind` varchar(32) NOT NULL,
  `entity_key` varchar(255) NOT NULL DEFAULT '',
  `comment` text NOT NULL,
  `updated_by` varchar(64) NOT NULL DEFAULT '',
  `updated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_entity_comment` (`instance_id`,`kind`,`entity_key`),
  CONSTRAINT `entity_comments_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `group_channels` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `channel` varchar(16) NOT NULL,
  `config_enc` blob NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_group_channel` (`group_id`,`channel`),
  CONSTRAINT `group_channels_ibfk_1` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `ipsec_ping_monitors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `tunnel_id` varchar(128) NOT NULL,
  `child_name` varchar(128) NOT NULL DEFAULT '',
  `local_ts` varchar(255) NOT NULL DEFAULT '',
  `remote_ts` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) NOT NULL DEFAULT '',
  `source` varchar(64) NOT NULL DEFAULT '',
  `destination` varchar(64) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `ping_count` int(11) NOT NULL DEFAULT 3,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ipsec_ping_monitor` (`instance_id`,`tunnel_id`,`local_ts`,`remote_ts`),
  KEY `ix_ipsec_ping_monitors_instance_id` (`instance_id`),
  CONSTRAINT `ipsec_ping_monitors_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `ipsec_tunnel_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `tunnel_id` varchar(128) NOT NULL,
  `child_name` varchar(128) NOT NULL DEFAULT '',
  `ts` datetime NOT NULL DEFAULT current_timestamp(),
  `event_type` varchar(32) NOT NULL,
  `old_value` varchar(255) NOT NULL DEFAULT '',
  `new_value` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `ix_ipsec_event_lookup` (`instance_id`,`tunnel_id`,`ts`),
  KEY `ix_ipsec_events_ts` (`ts`),
  CONSTRAINT `ipsec_tunnel_events_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `log_events` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `log_name` varchar(64) NOT NULL,
  `severity` int(11) NOT NULL,
  `program` varchar(64) NOT NULL DEFAULT '',
  `pattern` varchar(200) NOT NULL,
  `sample` text NOT NULL,
  `count` int(11) NOT NULL DEFAULT 1,
  `last_ts` varchar(40) NOT NULL DEFAULT '',
  `updated_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `ix_log_event_lookup` (`instance_id`,`log_name`),
  KEY `ix_log_event_severity` (`severity`),
  CONSTRAINT `log_events_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `logfiles` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `instance_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `collected_at` datetime NOT NULL DEFAULT current_timestamp(),
  `bytes` int(11) NOT NULL DEFAULT 0,
  `content` mediumtext NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_logfile_lookup` (`instance_id`,`name`,`collected_at`),
  CONSTRAINT `logfiles_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `metrics` (
  `instance_id` int(11) NOT NULL,
  `ts` datetime NOT NULL,
  `metric` varchar(128) NOT NULL,
  `value` double NOT NULL,
  PRIMARY KEY (`instance_id`,`ts`,`metric`),
  KEY `ix_metrics_ts` (`ts`),
  CONSTRAINT `metrics_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `selection_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `consumer` varchar(32) NOT NULL,
  `instance_id` int(11) DEFAULT NULL,
  `selector` varchar(255) NOT NULL,
  `mode` varchar(8) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_selection_rule` (`consumer`,`instance_id`,`selector`),
  KEY `ix_selection_rules_consumer` (`consumer`),
  KEY `ix_selection_rules_instance_id` (`instance_id`),
  CONSTRAINT `selection_rules_ibfk_1` FOREIGN KEY (`instance_id`) REFERENCES `instances` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `user_groups` (
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`user_id`,`group_id`),
  KEY `group_id` (`group_id`),
  CONSTRAINT `user_groups_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_groups_ibfk_2` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
CREATE TABLE IF NOT EXISTS `webauthn_credentials` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `credential_id` varchar(255) NOT NULL,
  `public_key` blob NOT NULL,
  `sign_count` bigint(20) NOT NULL DEFAULT 0,
  `name` varchar(128) DEFAULT NULL,
  `transports` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `last_used_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `credential_id` (`credential_id`),
  KEY `ix_webauthn_credentials_user_id` (`user_id`),
  CONSTRAINT `webauthn_credentials_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
SET FOREIGN_KEY_CHECKS = 1;
