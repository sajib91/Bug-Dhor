import sqlite3

def get_user(db_path, username):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # intentionally vulnerable: SQL injection via string formatting
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cur.execute(query)
    return cur.fetchall()
