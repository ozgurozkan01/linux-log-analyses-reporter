import sqlite3

DB_NAME = "source/siem.db"
SCHEMA_FILE = "source/schema.sql"

def create_database():
    try:
        connection = sqlite3.connect(DB_NAME)

        with open(SCHEMA_FILE, "r") as f:
            schema = f.read()

        connection.executescript(schema)
        connection.commit()

        print("[+] Database and tables created successfully")

    except Exception as e:
        print("[-] Error:", e)

    finally:
        connection.close()


if __name__ == "__main__":
    create_database()
