-- Adminer 4.7.6 MySQL dump

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

SET NAMES utf8mb4;

DROP TABLE IF EXISTS `antispam_control`;
CREATE TABLE `antispam_control` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'unikátní identifikátor',
  `publicKey` varchar(255) COLLATE utf8mb4_czech_ci NOT NULL COMMENT 'veřejná část API klíč',
  `privateKey` varchar(255) COLLATE utf8mb4_czech_ci NOT NULL COMMENT 'soukromá část API klíče',
  `origins` text COLLATE utf8mb4_czech_ci DEFAULT NULL COMMENT 'origins ze kterých můžou dané klíče komunikovat',
  `points` float NOT NULL COMMENT 'body daného hotnotitele',
  PRIMARY KEY (`id`),
  UNIQUE KEY `publicKey` (`publicKey`),
  UNIQUE KEY `privateKey` (`privateKey`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_czech_ci COMMENT='řídící tabulka k antispamu';

INSERT INTO `antispam_control` (`id`, `publicKey`, `privateKey`, `origins`, `points`) VALUES
(1,	'8gUBgEitsLCXar2vq3bm',	't42d91X29sdRE083zFlg',	'[\"aaa.org\",\"iiic.dev\",\"generator.localhost\"]',	0);

DROP TABLE IF EXISTS `antispam_items`;
CREATE TABLE `antispam_items` (
  `antispam_results_id` int(11) NOT NULL COMMENT 'vazba na výsledek',
  `antispam_control_id` int(11) NOT NULL COMMENT 'vazba na klíče',
  `datetime` datetime NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE current_timestamp() COMMENT 'datum a čas potvrzení výsledku',
  `result` smallint(1) DEFAULT NULL COMMENT 'výsledek manuálního zhodnocení',
  UNIQUE KEY `antispam_results_id_antispam_control_id` (`antispam_results_id`,`antispam_control_id`),
  KEY `antispam_control_id` (`antispam_control_id`),
  CONSTRAINT `antispam_items_ibfk_1` FOREIGN KEY (`antispam_results_id`) REFERENCES `antispam_results` (`id`),
  CONSTRAINT `antispam_items_ibfk_2` FOREIGN KEY (`antispam_control_id`) REFERENCES `antispam_control` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_czech_ci;

INSERT INTO `antispam_items` (`antispam_results_id`, `antispam_control_id`, `datetime`, `result`) VALUES
(47,	1,	'0000-00-00 00:00:00',	NULL),
(48,	1,	'0000-00-00 00:00:00',	NULL),
(49,	1,	'0000-00-00 00:00:00',	NULL);

DROP TABLE IF EXISTS `antispam_results`;
CREATE TABLE `antispam_results` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT 'identifikátor záznamu',
  `hash` varchar(64) COLLATE utf8_czech_ci NOT NULL COMMENT 'sha256 hash vloženého řetězce',
  `type` enum('url','email','text','hundredth') COLLATE utf8_czech_ci NOT NULL COMMENT 'typ hashovaných dat',
  `probability` float DEFAULT NULL COMMENT 'pravděpodobnost že jde o spamový hash',
  PRIMARY KEY (`id`),
  UNIQUE KEY `hash_type` (`hash`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_czech_ci;

INSERT INTO `antispam_results` (`id`, `hash`, `type`, `probability`) VALUES
(47,	'224275fec1d825fe6d278fa659beccd6be606e2d4be26c3b1d328d35df67f095',	'url',	NULL),
(48,	'36b05c08fe8eca933bc41be4d9cb1d1f500fd32c6359ec5e791224a4e7fd7384',	'email',	NULL),
(49,	'b594aa763e5e932c20269641034477bd342cc331c29a3b9c9d48c3e347431bb8',	'text',	NULL);

-- 2021-01-01 15:34:45
