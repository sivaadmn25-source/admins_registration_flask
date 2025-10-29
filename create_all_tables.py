import os
import psycopg2 
from psycopg2 import OperationalError
from dotenv import load_dotenv

# --- LOAD ENVIRONMENT VARIABLES ---
load_dotenv()
 
DB_NAME = os.getenv("DB_NAME") or os.getenv("PG_DBNAME")
DB_USER = os.getenv("DB_USER") or os.getenv("PG_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD") or os.getenv("PG_PASSWORD")
DB_HOST = os.getenv("DB_HOST") or os.getenv("PG_HOST")
DB_PORT = os.getenv("DB_PORT") or os.getenv("PG_PORT")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")

conn = None
cursor = None

try:
    DB_URL = os.getenv("DATABASE_URL")
    print("🔍 DATABASE_URL =", os.getenv("DATABASE_URL"))

    # --- Connect ---
    if os.getenv("DB_HOST"):
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            sslmode=DB_SSLMODE,
            keepalives=0
        )
        print("✅ Connected using IPv4-compatible Supabase pooler.")
    elif DB_URL:
        conn = psycopg2.connect(DB_URL, sslmode="require", keepalives=0)
        print("✅ Connected using DATABASE_URL.")
    else:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            sslmode="require",
            keepalives=0
        )
        print("✅ Connected using PG_* environment variables.")

    cursor = conn.cursor()

    # --- DROP EXISTING TABLES ---
    tables_to_drop = [
        "votes",
        "households",
        "settings",
        "voting_schedule",
        "home_data",
        "admins",
        "new_admins",
        "registration_requests"
    ]

    for table in tables_to_drop:
        cursor.execute(f"DROP TABLE IF EXISTS {table} CASCADE;")
        print(f"Dropped table {table} if it existed.")

    # --- CREATE TABLES ---
    cursor.execute('''CREATE TABLE IF NOT EXISTS public.new_admins (
        society_name text NOT NULL,
        role text NOT NULL,
        mobile_number text,
        email text NOT NULL,
        password_hash text,
        invite_token text NOT NULL,
        invited_at timestamp DEFAULT CURRENT_TIMESTAMP,
        invite_end_at timestamp DEFAULT CURRENT_TIMESTAMP,
        responded boolean DEFAULT false,
        responded_at timestamp,
        max_voters integer DEFAULT 2,
        housing_type text DEFAULT 'xyz',
        review_status text DEFAULT 'new_invitation',
        is_towerwise boolean DEFAULT false,
        vote_per_house boolean DEFAULT false,
        CONSTRAINT new_admins_pkey PRIMARY KEY (society_name),
        CONSTRAINT new_admins_email_key UNIQUE (email),
        CONSTRAINT new_admins_mobile_number_check CHECK (mobile_number ~ '^[0-9]{10}$')
    );''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS public.admins (
        id SERIAL PRIMARY KEY,
        society_name text NOT NULL,
        role text NOT NULL,
        password_hash text NOT NULL,
        max_voters integer DEFAULT 2,
        housing_type text DEFAULT 'xyz',
        reset_token varchar(100),
        reset_token_expiry timestamp with time zone,
        email varchar(255),
        vote_per_house boolean DEFAULT false,
        CONSTRAINT admins_society_name_role_key UNIQUE (society_name, role)
    );''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS home_data (
        society_name TEXT PRIMARY KEY,
        data TEXT
    );''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS households (
        id SERIAL PRIMARY KEY,
        society_name TEXT NOT NULL,
        tower TEXT NOT NULL,
        flat TEXT NOT NULL,
        is_vote_allowed INTEGER DEFAULT 1,
        is_admin_blocked INTEGER DEFAULT 0,
        voted_in_cycle INTEGER DEFAULT 0,
        is_contestant INTEGER DEFAULT 0,
        contestant_name TEXT,
        contestant_symbol TEXT,
        secret_code TEXT,
        reset_code TEXT,
        face_recognition_image TEXT,
        mobile_number TEXT,
        contestant_photo_b64 TEXT,
        max_votes_allowed integer DEFAULT 1,
        votes_cast integer DEFAULT 0,
        voted_at TIMESTAMP WITH TIME ZONE NULL,
        UNIQUE(society_name, tower, flat)
    );''')

    cursor.execute('''CREATE TABLE registration_requests (
        id SERIAL PRIMARY KEY,
        society_name VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL,
        mobile_number VARCHAR(20) NOT NULL,
        submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(20) DEFAULT 'pending'
    );''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS votes (
        id SERIAL PRIMARY KEY,
        society_name TEXT NOT NULL,
        tower TEXT NOT NULL,
        contestant_name TEXT NOT NULL,
        vote_count INTEGER DEFAULT 0,
        is_archived INTEGER DEFAULT 0,
        UNIQUE(society_name, tower, contestant_name, is_archived)
    );''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
        society_name TEXT PRIMARY KEY,
        max_candidates_selection INTEGER DEFAULT 1,
        max_voters INTEGER DEFAULT 2,
        voted_count INTEGER DEFAULT 0,
        is_towerwise BOOLEAN DEFAULT FALSE,
        housing_type TEXT DEFAULT 'xyz',
        vote_per_house boolean DEFAULT false
    );''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS public.voting_schedule (
        society_name text NOT NULL,
        start_time TIMESTAMP WITH TIME ZONE,
        end_time TIMESTAMP WITH TIME ZONE,
        CONSTRAINT voting_schedule_pkey PRIMARY KEY (society_name)
    );''')
 
    conn.commit()
    print("✅ Database setup complete with all default societies and admins (plain text passwords).")

except OperationalError as e:
    print(f"Error: Could not connect to the database - {e}")
finally:
    if cursor:
        cursor.close()
    if conn:
        conn.close()
        print("Connection closed.")
