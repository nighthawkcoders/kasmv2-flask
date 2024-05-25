import os
import sqlite3

db_file = os.path.join("volumes", "users.sqlite")

try:
    conn = sqlite3.connect(db_file)

    cursor = conn.cursor()

    sql_query = """CREATE TABLE user (
            id INTEGER PRIMARY KEY, 
            Name TEXT NOT NULL,
            GitHubID TEXT NOT NULL,
            Password TEXT NOT NULL,
            Classes TEXT[],  -- Array of strings
            KasmServerNeeded BOOLEAN
    )"""

    cursor.execute(sql_query)

    conn.commit()

    cursor.close()
    conn.close()

    print("Database file created successfully at:", db_file)

except Exception as e:
    print("An error occurred:", e)
