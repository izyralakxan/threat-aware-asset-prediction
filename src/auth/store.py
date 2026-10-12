"""
User, ownership and audit storage (SQLite, data/auth/auth.db).

users         accounts, role, team, password hash, TOTP secret, lockout state
asset_owners  which team owns which asset (per lab), and the team's email
audit_log     append-only, hash-chained record of security-relevant actions:
              each entry stores the SHA-256 of the previous entry, so any
              edit or deletion breaks the chain and is detected by verify_audit
"""

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

# Overridable for tests, so a test run never touches the real accounts
AUTH_DB = Path(os.environ.get("THREATAWARE_AUTH_DB", "data/auth/auth.db"))

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL,
    team TEXT,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    totp_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    last_totp_counter INTEGER,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS asset_owners (
    lab TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    team TEXT NOT NULL,
    team_email TEXT,
    PRIMARY KEY (lab, asset_id)
);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sent_at TEXT NOT NULL,
    sender TEXT NOT NULL,
    lab TEXT,
    asset_id TEXT NOT NULL,
    hostname TEXT,
    team TEXT,
    recipients TEXT NOT NULL,
    subject TEXT NOT NULL,
    actions INTEGER,
    exploited INTEGER,
    delivery TEXT NOT NULL,
    message_file TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    outcome TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""


def now():
    return datetime.now(timezone.utc).replace(microsecond=0)


@contextmanager
def connect(db=AUTH_DB):
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ==============================
# Users
# ==============================

def get_user(username, db=AUTH_DB):
    with connect(db) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", [username]).fetchone()
    return dict(row) if row else None


def list_users(db=AUTH_DB):
    with connect(db) as conn:
        return pd.read_sql("SELECT username, display_name, email, role, team, mfa_enabled, "
                           "must_change_password, failed_attempts, locked_until, active, "
                           "created_at, last_login FROM users ORDER BY role, username", conn)


def create_user(username, display_name, role, password_hash, email="", team="", db=AUTH_DB):
    with connect(db) as conn:
        conn.execute(
            "INSERT INTO users (username, display_name, email, role, team, password_hash, "
            "must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            [username, display_name, email, role, team, password_hash, now().isoformat()])


def update_user(username, db=AUTH_DB, **fields):
    if not fields:
        return
    assignments = ", ".join(f"{key} = ?" for key in fields)
    with connect(db) as conn:
        conn.execute(f"UPDATE users SET {assignments} WHERE username = ?",
                     [*fields.values(), username])


def is_locked(user):
    return bool(user["locked_until"]) and datetime.fromisoformat(user["locked_until"]) > now()


def record_failure(user, db=AUTH_DB):
    """Count a failed login; lock the account after MAX_FAILED_LOGINS."""
    failures = user["failed_attempts"] + 1
    locked = (now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat() \
        if failures >= MAX_FAILED_LOGINS else None
    update_user(user["username"], db, failed_attempts=failures if not locked else 0,
                locked_until=locked)
    return locked is not None


def record_success(username, db=AUTH_DB):
    update_user(username, db, failed_attempts=0, locked_until=None, last_login=now().isoformat())


# ==============================
# Asset ownership
# ==============================

def set_owner(lab, asset_id, team, team_email="", db=AUTH_DB):
    with connect(db) as conn:
        conn.execute("INSERT OR REPLACE INTO asset_owners VALUES (?, ?, ?, ?)",
                     [lab, asset_id, team, team_email])


def owners(lab=None, db=AUTH_DB):
    with connect(db) as conn:
        query = "SELECT * FROM asset_owners" + (" WHERE lab = ?" if lab else "")
        return pd.read_sql(query, conn, params=[lab] if lab else None)


def team_assets(lab, team, db=AUTH_DB):
    frame = owners(lab, db)
    return set(frame.loc[frame["team"] == team, "asset_id"])


def set_team_email(lab, asset_id, team_email, db=AUTH_DB):
    with connect(db) as conn:
        conn.execute("UPDATE asset_owners SET team_email = ? WHERE lab = ? AND asset_id = ?",
                     [team_email, lab, asset_id])


# ==============================
# Notifications sent to owning teams
# ==============================

def add_notification(record, db=AUTH_DB):
    with connect(db) as conn:
        conn.execute(
            "INSERT INTO notifications (sent_at, sender, lab, asset_id, hostname, team, recipients, "
            "subject, actions, exploited, delivery, message_file) "
            "VALUES (:sent_at, :sender, :lab, :asset_id, :hostname, :team, :recipients, :subject, "
            ":actions, :exploited, :delivery, :message_file)",
            {"sent_at": now().isoformat(), **record})


def list_notifications(lab=None, db=AUTH_DB):
    with connect(db) as conn:
        query = "SELECT * FROM notifications" + (" WHERE lab = ?" if lab else "") + " ORDER BY id DESC"
        return pd.read_sql(query, conn, params=[lab] if lab else None)


# ==============================
# Audit log (hash chain)
# ==============================

def _entry_hash(entry, prev_hash):
    payload = json.dumps({k: entry[k] for k in ["at", "username", "role", "action", "detail", "outcome"]},
                         sort_keys=True)
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


def audit(action, username=None, role=None, detail="", outcome="success", db=AUTH_DB):
    with connect(db) as conn:
        last = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = last["entry_hash"] if last else "0" * 64
        entry = {"at": now().isoformat(), "username": username, "role": role,
                 "action": action, "detail": detail, "outcome": outcome}
        conn.execute(
            "INSERT INTO audit_log (at, username, role, action, detail, outcome, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [*entry.values(), prev_hash, _entry_hash(entry, prev_hash)])


def read_audit(limit=500, db=AUTH_DB):
    with connect(db) as conn:
        return pd.read_sql("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", conn, params=[limit])


def verify_audit(db=AUTH_DB):
    """(intact, first broken entry id or None) by re-computing every hash."""
    with connect(db) as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
    prev = "0" * 64
    for row in rows:
        if row["prev_hash"] != prev or _entry_hash(row, prev) != row["entry_hash"]:
            return False, row["id"]
        prev = row["entry_hash"]
    return True, None
