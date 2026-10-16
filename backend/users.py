"""
users.py — User accounts with self-registration + admin approval.

Lifecycle:  register -> pending -> (admin) approve -> active
                                 -> (admin) reject  -> rejected
            active <-> disabled (admin)

* Passwords are stored as PBKDF2-HMAC-SHA256 hashes (per-user salt, 240k iterations).
* Self-registered users can only *request* analyst/viewer; the admin decides the final role.
* Demo accounts (admin / analyst / viewer) are seeded once as active users.
"""
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

DB_FILE: Optional[Path] = None

ROLES = ("admin", "analyst", "viewer")
REQUESTABLE_ROLES = ("analyst", "viewer")
STATUSES = ("pending", "active", "rejected", "disabled")

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,120}\.[a-z]{2,24}$", re.I)
PBKDF2_ITERATIONS = 240_000

DEMO_USERS = [
    ("admin", "Admin User", "admin@dnsleak.local", "admin123", "admin"),
    ("analyst", "Sara Analyst", "analyst@dnsleak.local", "analyst123", "analyst"),
    ("viewer", "Guest Viewer", "viewer@dnsleak.local", "viewer123", "viewer"),
]


# ----------------------------------------------------------------- password hashing
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(8))  # equalises timing for unknown users


# ----------------------------------------------------------------- DB
def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_FILE), timeout=8)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def init(db_file: Path):
    global DB_FILE
    DB_FILE = db_file
    conn = _conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            requested_role TEXT,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at DATETIME DEFAULT (datetime('now', 'localtime')),
            reviewed_by TEXT,
            reviewed_at DATETIME,
            review_note TEXT,
            last_login DATETIME
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)")
    for username, name, email, pw, role in DEMO_USERS:
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if not exists:
            conn.execute(
                """INSERT INTO users (username, name, email, password_hash, role, requested_role, status, reviewed_by, reviewed_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'active', 'system', datetime('now','localtime'))""",
                (username, name, email, hash_password(pw), role, role),
            )
    conn.commit()
    conn.close()


def _public(r: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": r["id"],
        "username": r["username"],
        "name": r["name"],
        "email": r["email"],
        "role": r["role"],
        "requested_role": r["requested_role"],
        "reason": r["reason"],
        "status": r["status"],
        "created_at": str(r["created_at"] or ""),
        "reviewed_by": r["reviewed_by"],
        "reviewed_at": str(r["reviewed_at"] or "") or None,
        "review_note": r["review_note"],
        "last_login": str(r["last_login"] or "") or None,
    }


def get_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = _conn()
    r = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return _public(r) if r else None


def get_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    conn = _conn()
    r = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return _public(r) if r else None


# ----------------------------------------------------------------- rate limiting (per IP, in-memory)
_hits: Dict[str, deque] = defaultdict(deque)


def rate_limit(key: str, max_hits: int, window_sec: int):
    now = time.time()
    q = _hits[key]
    while q and q[0] < now - window_sec:
        q.popleft()
    if len(q) >= max_hits:
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait a few minutes and try again.")
    q.append(now)


# ----------------------------------------------------------------- auth
def authenticate(username: str, password: str) -> Dict[str, Any]:
    """Returns the active user or raises HTTPException with a user-friendly message."""
    uname = (username or "").strip().lower()[:64]
    conn = _conn()
    r = conn.execute("SELECT * FROM users WHERE username = ?", (uname,)).fetchone()
    if not r:
        verify_password(password or "", _DUMMY_HASH)
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not verify_password(password or "", r["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    status = r["status"]
    if status == "pending":
        conn.close()
        raise HTTPException(status_code=403, detail="Your account is awaiting administrator approval.")
    if status == "rejected":
        conn.close()
        raise HTTPException(status_code=403, detail="Your registration request was declined by an administrator.")
    if status == "disabled":
        conn.close()
        raise HTTPException(status_code=403, detail="This account has been disabled. Contact an administrator.")

    conn.execute("UPDATE users SET last_login = datetime('now','localtime') WHERE id = ?", (r["id"],))
    conn.commit()
    conn.close()
    return _public(r)


def active_identity(username: str) -> Optional[Dict[str, Any]]:
    """Current role/status from DB — so disabling or changing a role takes effect immediately."""
    try:
        conn = _conn()
        r = conn.execute("SELECT username, name, role, status FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
    except Exception:
        return None
    if not r or r["status"] != "active":
        return None
    return {"username": r["username"], "name": r["name"], "role": r["role"]}


# ----------------------------------------------------------------- registration
def register(username: str, name: str, email: str, password: str, requested_role: str, reason: str = "") -> Dict[str, Any]:
    username = (username or "").strip().lower()
    name = (name or "").strip()
    email = (email or "").strip().lower()
    reason = (reason or "").strip()[:300]

    if not USERNAME_RE.match(username):
        raise HTTPException(400, "Username must be 3–32 characters: lowercase letters, numbers, dot, dash or underscore.")
    if not (2 <= len(name) <= 64):
        raise HTTPException(400, "Full name must be between 2 and 64 characters.")
    if email and (len(email) > 190 or not EMAIL_RE.match(email)):
        raise HTTPException(400, "Please enter a valid email address.")
    if not (8 <= len(password or "") <= 128):
        raise HTTPException(400, "Password must be 8–128 characters.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise HTTPException(400, "Password must contain at least one letter and one number.")
    if password.lower() == username:
        raise HTTPException(400, "Password must not be the same as the username.")
    if requested_role not in REQUESTABLE_ROLES:
        raise HTTPException(400, "You can request the Analyst or Viewer role.")

    conn = _conn()
    try:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise HTTPException(409, "This username is already taken.")
        if email and conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(409, "An account with this email already exists.")
        cur = conn.execute(
            """INSERT INTO users (username, name, email, password_hash, role, requested_role, reason, status)
               VALUES (?, ?, ?, ?, 'viewer', ?, ?, 'pending')""",
            (username, name, email or None, hash_password(password), requested_role, reason or None),
        )
        conn.commit()
        uid = cur.lastrowid
    finally:
        conn.close()
    return get_by_id(uid)


# ----------------------------------------------------------------- admin management
def list_users(status: Optional[str] = None) -> Dict[str, Any]:
    conn = _conn()
    if status and status in STATUSES:
        rows = conn.execute("SELECT * FROM users WHERE status = ? ORDER BY id DESC", (status,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, id DESC"
        ).fetchall()
    counts = {s: 0 for s in STATUSES}
    for s, n in conn.execute("SELECT status, COUNT(*) FROM users GROUP BY status").fetchall():
        counts[s] = n
    conn.close()
    return {"items": [_public(r) for r in rows], "counts": counts}


def pending_count() -> int:
    conn = _conn()
    n = conn.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'").fetchone()[0]
    conn.close()
    return n


def _require(user_id: int) -> Dict[str, Any]:
    u = get_by_id(user_id)
    if not u:
        raise HTTPException(404, "User not found")
    return u


def _active_admin_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'").fetchone()[0]


def review(user_id: int, approve: bool, reviewer: str, role: Optional[str] = None, note: str = "") -> Dict[str, Any]:
    u = _require(user_id)
    if u["status"] not in ("pending", "rejected"):
        raise HTTPException(400, f"Account is already {u['status']}.")
    if approve:
        final_role = role or u["requested_role"] or "viewer"
        if final_role not in ROLES:
            raise HTTPException(400, "Invalid role")
        new_status = "active"
    else:
        final_role = u["role"]
        new_status = "rejected"
    conn = _conn()
    conn.execute(
        """UPDATE users SET status = ?, role = ?, reviewed_by = ?, reviewed_at = datetime('now','localtime'), review_note = ?
           WHERE id = ?""",
        (new_status, final_role, reviewer, (note or "")[:300] or None, user_id),
    )
    conn.commit()
    conn.close()
    return get_by_id(user_id)


def update(user_id: int, actor: str, role: Optional[str] = None, status: Optional[str] = None) -> Dict[str, Any]:
    u = _require(user_id)
    if role is not None and role not in ROLES:
        raise HTTPException(400, "Invalid role")
    if status is not None and status not in ("active", "disabled"):
        raise HTTPException(400, "Status can only be set to active or disabled")
    if u["status"] in ("pending", "rejected") and status == "active":
        raise HTTPException(400, "Use approve for pending accounts")

    conn = _conn()
    try:
        losing_admin = u["role"] == "admin" and u["status"] == "active" and (
            (role is not None and role != "admin") or status == "disabled"
        )
        if u["username"] == actor and losing_admin:
            raise HTTPException(400, "You cannot remove your own administrator access.")
        if losing_admin and _active_admin_count(conn) <= 1:
            raise HTTPException(400, "At least one active administrator must remain.")
        if role is not None:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if status is not None:
            conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
        conn.commit()
    finally:
        conn.close()
    return get_by_id(user_id)


def delete(user_id: int, actor: str) -> Dict[str, Any]:
    u = _require(user_id)
    if u["username"] == actor:
        raise HTTPException(400, "You cannot delete your own account.")
    conn = _conn()
    try:
        if u["role"] == "admin" and u["status"] == "active" and _active_admin_count(conn) <= 1:
            raise HTTPException(400, "At least one active administrator must remain.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
    return u
