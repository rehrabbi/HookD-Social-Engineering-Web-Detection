"""
Local database layer for HookD (SQLite).

This replaces the previous Supabase (cloud) backend with a single local
SQLite file so the app works completely offline -- no internet required.

The database file lives next to this script as 'hookd.db'. It is created
automatically on first run, and seeded with a demo account + sample scans
so the History page looks populated during a presentation.

Demo login (created by seed_demo_data):
    email:    demo@hookd.com
    password: demo123
"""

import os
import hashlib
import hmac
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta

# --- DB LOCATION (single local file, no server, no internet) ---
# Defaults to ./hookd.db, but can be overridden with the DATABASE_PATH env var.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DATABASE_PATH") or os.path.join(BASE_DIR, "hookd.db")

# --- PASSWORD HASHING (pure standard library, PBKDF2-HMAC-SHA256) ---
_PBKDF2_ITERATIONS = 200_000


def generate_password_hash(password):
    """Return a salted PBKDF2 hash string: 'pbkdf2_sha256$iter$salt$hash'."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def check_password_hash(stored, password):
    """Verify a password against a hash produced by generate_password_hash."""
    try:
        algorithm, iterations, salt, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), int(iterations)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def get_connection():
    """Open a connection that returns rows as dict-like objects."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # access columns by name, like Supabase
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def _now_iso():
    """ISO timestamp the front-end JS (new Date(...)) can parse reliably."""
    return datetime.now().isoformat()


# ---------------------------------------------------------------------------
# SCHEMA
# ---------------------------------------------------------------------------
def init_db():
    """Create tables if they don't already exist."""
    conn = get_connection()
    cur = conn.cursor()

    # 'users' merges Supabase's auth + 'profiles' table into one local table.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name    TEXT,
            last_name     TEXT,
            display_name  TEXT,
            created_at    TEXT NOT NULL
        );
        """
    )

    # 'history' mirrors the old Supabase 'history' table exactly so the
    # templates need no changes.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id             TEXT PRIMARY KEY,
            user_id        TEXT NOT NULL,
            history_name   TEXT,
            content        TEXT,
            content_type   TEXT,
            result         TEXT,
            result_details TEXT,
            created_at     TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        """
    )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# AUTHENTICATION (replaces supabase.auth)
# ---------------------------------------------------------------------------
def register_user(email, password, first_name, last_name):
    """
    Create a new local account with a hashed password.

    Returns: the new user's id (str).
    Raises:  ValueError if the email is already registered.
    """
    email = (email or "").strip().lower()
    display_name = f"{first_name} {last_name}".strip()
    user_id = str(uuid.uuid4())

    conn = get_connection()
    try:
        conn.execute(
            """
            INSERT INTO users
                (id, email, password_hash, first_name, last_name, display_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                email,
                generate_password_hash(password),
                first_name,
                last_name,
                display_name,
                _now_iso(),
            ),
        )
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        raise ValueError("An account with this email already exists.")
    finally:
        conn.close()


def authenticate_user(email, password):
    """
    Verify a login. Returns the user row as a dict on success, else None.
    """
    email = (email or "").strip().lower()
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if row and check_password_hash(row["password_hash"], password):
        return dict(row)
    return None


def ensure_guest_user(user_id="local-guest", email="guest@localhost",
                      display_name="Guest"):
    """
    Make sure a fixed guest account exists. Used by DEV_MODE so that scans
    performed without a real login still satisfy the history foreign key.
    """
    try:
        conn = get_connection()
        exists = conn.execute(
            "SELECT id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not exists:
            conn.execute(
                """
                INSERT INTO users
                    (id, email, password_hash, first_name, last_name,
                     display_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, email, generate_password_hash(uuid.uuid4().hex),
                 "Guest", "", display_name, _now_iso()),
            )
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error ensuring guest user: {e}")


# ---------------------------------------------------------------------------
# PROFILES
# ---------------------------------------------------------------------------
def create_user_profile(user_id, first_name, last_name, display_name):
    """
    Kept for API compatibility. With local auth the profile is already
    created in register_user(); this just backfills/updates the names.
    """
    conn = get_connection()
    conn.execute(
        """
        UPDATE users
           SET first_name = ?, last_name = ?, display_name = ?
         WHERE id = ?
        """,
        (first_name, last_name, display_name, user_id),
    )
    conn.commit()
    conn.close()


def get_user_profile(user_id):
    """Return the profile dict (incl. email) for a user, or None."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def update_user_profile(user_id, first_name, last_name):
    """Update editable profile fields. Returns True on success."""
    display_name = f"{first_name} {last_name}".strip()
    try:
        conn = get_connection()
        conn.execute(
            """
            UPDATE users
               SET first_name = ?, last_name = ?, display_name = ?
             WHERE id = ?
            """,
            (first_name, last_name, display_name, user_id),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating profile: {e}")
        return False


def verify_user_password(user_id, password):
    """Return True if the given password matches the user's current one."""
    conn = get_connection()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return bool(row) and check_password_hash(row["password_hash"], password)


def change_user_password(user_id, new_password):
    """Set a new (hashed) password for the user. Returns True on success."""
    try:
        conn = get_connection()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error changing password: {e}")
        return False


# ---------------------------------------------------------------------------
# SCAN HISTORY
# ---------------------------------------------------------------------------
def log_scan(scan_type, result, sender, content, user_id):
    """Save a scan result to the local 'history' table."""
    try:
        details_string = (
            f"Score: {result['confidence']}% - Risk Score: {result['confidence']}%"
        )
        conn = get_connection()
        conn.execute(
            """
            INSERT INTO history
                (id, user_id, history_name, content, content_type,
                 result, result_details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                user_id,
                sender,
                content,
                scan_type,
                result["label"],
                details_string,
                _now_iso(),
            ),
        )
        conn.commit()
        conn.close()
        print("Scan logged to history.")
    except Exception as e:
        print(f"Error logging scan: {e}")


def get_scan_history(user_id):
    """Fetch the last 50 scans for a user, newest first."""
    try:
        conn = get_connection()
        rows = conn.execute(
            """
            SELECT * FROM history
             WHERE user_id = ?
             ORDER BY created_at DESC
             LIMIT 50
            """,
            (user_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error fetching history: {e}")
        return []


def delete_scan_log(log_id, user_id):
    """Delete one scan, but only if it belongs to this user."""
    try:
        conn = get_connection()
        conn.execute(
            "DELETE FROM history WHERE id = ? AND user_id = ?",
            (log_id, user_id),
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error deleting log: {e}")
        return False


def clear_scan_history(user_id):
    """Delete ALL scans for a user. Returns the number of rows removed."""
    try:
        conn = get_connection()
        cur = conn.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
        conn.commit()
        deleted = cur.rowcount
        conn.close()
        return deleted
    except Exception as e:
        print(f"Error clearing history: {e}")
        return 0


# ---------------------------------------------------------------------------
# DEMO SEED DATA (so History isn't empty during the presentation)
# ---------------------------------------------------------------------------
def seed_demo_data():
    """
    Create a demo account + a handful of realistic sample scans, but only
    if the demo account doesn't already exist. Safe to call on every start.
    """
    demo_email = "demo@hookd.com"

    conn = get_connection()
    exists = conn.execute(
        "SELECT id FROM users WHERE email = ?", (demo_email,)
    ).fetchone()
    conn.close()
    if exists:
        return  # already seeded

    user_id = register_user(demo_email, "demo123", "Demo", "User")

    sample_scans = [
        # (scan_type, sender, content, label, confidence, age_minutes)
        ("text", "security@paypa1-alerts.com",
         "Your account has been LIMITED. Verify your identity within 24 hours "
         "or it will be permanently suspended: http://paypa1-secure-login.com",
         "Phishing", 96, 5),
        ("url", "http://amaz0n-account-verify.net",
         "http://amaz0n-account-verify.net", "Unsafe", 91, 90),
        ("text", "hr@yourcompany.com",
         "Hi team, please find the updated holiday schedule attached. "
         "Let me know if you have any questions. Thanks!",
         "Safe", 98, 240),
        ("image", "Image_OCR",
         "URGENT: We detected a login from a new device. Confirm it was you "
         "by entering your password here to avoid lockout.",
         "Caution", 74, 1440),
        ("url", "https://www.google.com",
         "https://www.google.com", "Safe", 99, 2880),
    ]

    conn = get_connection()
    for scan_type, sender, content, label, confidence, age_min in sample_scans:
        created = (datetime.now() - timedelta(minutes=age_min)).isoformat()
        details = f"Score: {confidence}% - Risk Score: {confidence}%"
        conn.execute(
            """
            INSERT INTO history
                (id, user_id, history_name, content, content_type,
                 result, result_details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), user_id, sender, content, scan_type,
             label, details, created),
        )
    conn.commit()
    conn.close()
    print(f"Seeded demo account ({demo_email} / demo123) with sample scans.")
