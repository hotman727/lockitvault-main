import sqlite3
import os

def check_database_schema(db_path):
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the sessions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions';")
        table_exists = cursor.fetchone()

        if not table_exists:
            print("The 'sessions' table does not exist in the database.")
            return

        # Retrieve and display the schema of the sessions table
        print("\nSchema of the 'sessions' table:")
        cursor.execute("PRAGMA table_info(sessions);")
        schema = cursor.fetchall()
        for column in schema:
            print(f"Column: {column[1]}, Type: {column[2]}")

        # Display a sample of data from the sessions table
        print("\nSample data from the 'sessions' table:")
        cursor.execute("SELECT * FROM sessions LIMIT 5;")
        rows = cursor.fetchall()
        for row in rows:
            print(row)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
    finally:
        if conn:
            conn.close()

# Path to your SQLite database file
db_path = "instance/site.db"  # Replace with the actual path to your database file

check_database_schema(db_path)

