"""
reset_db.py — Drop all tables and recreate the database schema from scratch.
Creates an admin user with a random password (printed once) that must be
changed on first login. Set PCAP_DEFAULT_ADMIN_PASSWORD to choose it explicitly.

Usage:
    python reset_db.py [--yes]

The --yes flag skips the confirmation prompt (useful for CI/automated setups).
"""
import sys
import os

# ---- confirmation ----
auto_yes = '--yes' in sys.argv
if not auto_yes:
    answer = input(
        "WARNING: This will DROP all tables and delete all data.\n"
        "Continue? (yes/no): "
    ).strip().lower()
    if answer != 'yes':
        print("Aborted.")
        sys.exit(0)

import psycopg2
import psycopg2.extras
from werkzeug.security import generate_password_hash

DATABASE_URL = os.environ.get(
    'DATABASE_URL',
    'postgresql://pcap_user:pcap_pass@localhost:5432/pcap_analyzer'
)

print(f"Connecting to: {DATABASE_URL}")

conn = psycopg2.connect(DATABASE_URL)
conn.autocommit = False
cur = conn.cursor()

print("Dropping all tables...")
cur.execute("""
    DO $$
    DECLARE
        r RECORD;
    BEGIN
        -- Drop all tables in the public schema (including partitioned children)
        FOR r IN (
            SELECT tablename FROM pg_tables
            WHERE schemaname = 'public'
        ) LOOP
            EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
        END LOOP;
    END $$;
""")
conn.commit()
print("All tables dropped.")

# Re-initialize schema via database.py
import database as db
print("Re-initializing schema...")
# init_database() is called on import, but tables were just dropped so we
# need to call it explicitly again.
db.init_database()
print("Schema initialized.")

# Create the admin user. The password is taken from PCAP_DEFAULT_ADMIN_PASSWORD
# if set, otherwise a strong random one is generated and printed exactly once.
# must_change_password is True so a leaked console log alone is not a standing
# credential.
import secrets

admin_password = os.environ.get('PCAP_DEFAULT_ADMIN_PASSWORD')
generated = False
if not admin_password:
    admin_password = secrets.token_urlsafe(16)
    generated = True

try:
    uid = db.create_user(
        username='admin',
        password_hash=generate_password_hash(admin_password),
        role='admin',
        enabled=True,
        must_change_password=True,
    )
    print("=" * 56)
    print(f"Admin user created (id={uid}): username=admin")
    if generated:
        print(f"Generated password (change on first login): {admin_password}")
    else:
        print("Password: taken from PCAP_DEFAULT_ADMIN_PASSWORD")
    print("=" * 56)
except Exception as e:
    print(f"Failed to create admin user: {e}")

print("\nDone. You can now start the application.")
