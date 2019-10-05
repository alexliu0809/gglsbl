import sqlite3
from sqlite3 import Error

def db_connection(db_name):
    """ 
    create a database connection to a SQLite database 
    if there is no database, it will be created.
    """

    try:
        conn = sqlite3.connect(db_name)
    except Error as e:
        print(e)
        return None
    
    return conn

def insert_into_threat_entry(conn, entry_hash):
    # Get cursor
    cmd = 'INSERT OR IGNORE INTO threat_entry VALUES ("{}")'.format(entry_hash)
    execute_cmd(conn, cmd)

def insert_into_threat_records(conn, record_values):
    cmd = 'INSERT INTO threat_records VALUES ({})'.format(",".join(record_values))
    execute_cmd(conn, cmd)

def execute_cmds(conn, cmds):
	""" Create table if not exsit """
	
	# Get cursor
	c = conn.cursor()
	c.executescript(cmds)

	# add commit if multiple connections

def execute_cmd(conn, cmd):
	c = conn.cursor()
	c.execute(cmd)

	# add commit if multiple connections





