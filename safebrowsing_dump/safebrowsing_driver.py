from safebrowsing_database import *
from safebrowsing_parse_dump import * 

DUMP_FILENAME = "fullHashes_2019-10-05.json.gz"

# Reference: https://apiharmony-open.mybluemix.net/public/apis/google_safe_browsing#post_v4_fullHashes:find
create_table_cmds = r"""

CREATE TABLE IF NOT EXISTS threat_platforms (
    threat_platform text PRIMARY KEY
    );

INSERT OR IGNORE INTO threat_platforms VALUES ("PLATFORM_TYPE_UNSPECIFIED");
INSERT OR IGNORE INTO threat_platforms VALUES ("WINDOWS");
INSERT OR IGNORE INTO threat_platforms VALUES ("LINUX");
INSERT OR IGNORE INTO threat_platforms VALUES ("ANDROID");
INSERT OR IGNORE INTO threat_platforms VALUES ("OSX");
INSERT OR IGNORE INTO threat_platforms VALUES ("IOS");
INSERT OR IGNORE INTO threat_platforms VALUES ("ANY_PLATFORM");
INSERT OR IGNORE INTO threat_platforms VALUES ("ALL_PLATFORMS");
INSERT OR IGNORE INTO threat_platforms VALUES ("CHROME");


CREATE TABLE IF NOT EXISTS threat_entry_types (
    threat_entry_type text PRIMARY KEY
    );

INSERT OR IGNORE INTO threat_entry_types VALUES ("THREAT_ENTRY_TYPE_UNSPECIFIED");
INSERT OR IGNORE INTO threat_entry_types VALUES ("URL");
INSERT OR IGNORE INTO threat_entry_types VALUES ("EXECUTABLE");
INSERT OR IGNORE INTO threat_entry_types VALUES ("IP_RANGE");


CREATE TABLE IF NOT EXISTS threat_types (
    threat_type text PRIMARY KEY
    );

INSERT OR IGNORE INTO threat_types VALUES ("THREAT_TYPE_UNSPECIFIED");
INSERT OR IGNORE INTO threat_types VALUES ("MALWARE");
INSERT OR IGNORE INTO threat_types VALUES ("SOCIAL_ENGINEERING");
INSERT OR IGNORE INTO threat_types VALUES ("UNWANTED_SOFTWARE");
INSERT OR IGNORE INTO threat_types VALUES ("POTENTIALLY_HARMFUL_APPLICATION");


CREATE TABLE IF NOT EXISTS threat_entry (
    threat_hash text PRIMARY KEY
    );

CREATE TABLE IF NOT EXISTS threat_records(
	threat_hash text REFERENCES threat_hash,
	threat_type text REFERENCES threat_type,
	threat_entry_type text REFERENCES threat_entry_type,
	threat_platform text REFERENCES threat_platform,
	record_date text
	);
"""

conn = db_connection("test.db")

# Create tables
execute_cmds(conn, create_table_cmds)

# Parse Dump File && Store to DB
parse_dump_and_store(DUMP_FILENAME,conn)

conn.commit()
conn.close()