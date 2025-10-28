import sqlite3
import bcrypt
import os

# --- Configuration ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.path.join(BASE_DIR, "voting_system.db")  # or "voting.db" as per your setup

# --- Connect to DB ---
conn = sqlite3.connect(DB_FILE)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# --- Fetch all admin entries ---
cur.execute("SELECT id, role, password_hash FROM admins")
admins = cur.fetchall()

for admin in admins:
    admin_id = admin['id']
    role = admin['role']
    pw = admin['password_hash']

    # If password already hashed (starts with bcrypt prefix), skip
    if pw.startswith("$2b$") or pw.startswith("$2a$"):
        print(f"{role} already hashed, skipping...")
        continue

    # Hash plain password
    hashed_pw = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    # Update DB
    cur.execute("UPDATE admins SET password_hash=? WHERE id=?", (hashed_pw, admin_id))
    print(f"{role} password hashed and updated.")

conn.commit()
conn.close()
print("All admin passwords are now hashed successfully.")
