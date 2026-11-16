import sqlite3

def get_user(db_path, username):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # parameterized query (safe)
    query = "SELECT * FROM users WHERE name = ?"
    cur.execute(query, (username,))
    return cur.fetchall()
