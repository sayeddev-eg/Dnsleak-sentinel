"""
audit.py — Authentication tokens + Audit Log for DNSLeak Sentinel.

* Signed session tokens (HMAC-SHA256, stdlib only) so the backend — not the client —
  decides who performed an action.
* `audit_log` table recording every meaningful action (logins, PCAP uploads,
  analyses, simulations, deletions, exports, page views) with user, role, IP and time.
* Admin-only querying / deletion helpers.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Header, HTTPException, Request

DB_FILE: Optional[Path] = None
TOKEN_TTL_SECONDS = 12 * 60 * 60  # 12h session

# Client-originated events are restricted to this whitelist (category per action)
CLIENT_EVENTS = {
    "page.view": "navigation",
    "alerts.export": "export",
    "audit.export": "export",
    "report.download": "export",
    "devices.export": "export",
}

MAX_TARGET_LEN = 300
MAX_DETAILS_LEN = 4000


# ----------------------------------------------------------------- secret / tokens
def _load_secret() -> bytes:
    env = os.environ.get("SENTINEL_SECRET")
    if env:
        return env.encode()
    f = Path(__file__).with_name(".sentinel_secret")
    try:
        if f.exists():
            s = f.read_bytes().strip()
            if len(s) >= 32:
                return s
        s = secrets.token_hex(32).encode()
        f.write_bytes(s)
        return s
    except OSError:
        # read-only FS (some cloud hosts): tokens valid until restart
        return secrets.token_hex(32).encode()


_SECRET = _load_secret()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "name": user.get("name", user["username"]),
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64d(body))
        if int(payload.get("exp", 0)) < time.time():
            return None
        if not isinstance(payload.get("sub"), str) or payload.get("role") not in ("admin", "analyst", "viewer"):
            return None
        return {"username": payload["sub"], "role": payload["role"], "name": payload.get("name", payload["sub"])}
    except Exception:
        return None


# Optional hook: username -> current identity (or None if account no longer active).
# Set by main.py to users.active_identity so role changes / disabling apply instantly.
IDENTITY_RESOLVER = None


# ----------------------------------------------------------------- FastAPI dependencies
def current_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """Returns the verified user or None (anonymous)."""
    if authorization and authorization.lower().startswith("bearer "):
        ident = verify_token(authorization[7:].strip())
        if ident and IDENTITY_RESOLVER:
            return IDENTITY_RESOLVER(ident["username"])
        return ident
    return None


def require_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    u = current_user(authorization)
    if not u:
        raise HTTPException(status_code=401, detail="Authentication required or session expired")
    return u


def require_admin(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    u = require_user(authorization)
    if u["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return u


def require_operator(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """admin or analyst"""
    u = require_user(authorization)
    if u["role"] not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst or administrator privileges required")
    return u


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "unknown")[:64]


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
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            username TEXT NOT NULL DEFAULT 'anonymous',
            role TEXT DEFAULT 'guest',
            category TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT DEFAULT '{}',
            status TEXT DEFAULT 'success',
            ip TEXT,
            user_agent TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit_log(category)")

    # Link DNS records to the action/user that produced them
    cols = {r["name"] for r in c.execute("PRAGMA table_info(queries_log)").fetchall()}
    if cols:
        if "audit_id" not in cols:
            c.execute("ALTER TABLE queries_log ADD COLUMN audit_id INTEGER")
        if "source" not in cols:
            c.execute("ALTER TABLE queries_log ADD COLUMN source TEXT")
        if "username" not in cols:
            c.execute("ALTER TABLE queries_log ADD COLUMN username TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_queries_audit ON queries_log(audit_id)")
    conn.commit()
    conn.close()


def log(
    category: str,
    action: str,
    user: Optional[Dict[str, Any]] = None,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    status: str = "success",
    request: Optional[Request] = None,
    username: Optional[str] = None,
) -> Optional[int]:
    """Writes one audit entry and returns its id. Never raises."""
    try:
        details_json = json.dumps(details or {}, ensure_ascii=False, default=str)
        if len(details_json) > MAX_DETAILS_LEN:
            details_json = json.dumps({"truncated": True, "preview": details_json[:MAX_DETAILS_LEN - 100]})
        conn = _conn()
        cur = conn.execute(
            """INSERT INTO audit_log (username, role, category, action, target, details, status, ip, user_agent)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                (user or {}).get("username") or username or "anonymous",
                (user or {}).get("role") or "guest",
                category[:40],
                action[:60],
                (target or "")[:MAX_TARGET_LEN],
                details_json,
                status[:20],
                client_ip(request) if request else None,
                (request.headers.get("user-agent", "")[:250] if request else None),
            ),
        )
        conn.commit()
        rid = cur.lastrowid
        conn.close()
        return rid
    except Exception as e:
        print(f"[!] audit log error: {e}")
        return None


def update(audit_id: Optional[int], details: Dict[str, Any], status: str = "success"):
    if not audit_id:
        return
    try:
        conn = _conn()
        conn.execute(
            "UPDATE audit_log SET details = ?, status = ? WHERE id = ?",
            (json.dumps(details, ensure_ascii=False, default=str)[:MAX_DETAILS_LEN], status, audit_id),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] audit update error: {e}")


# ----------------------------------------------------------------- queries
def _where(filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
    clauses, params = [], []
    if filters.get("q"):
        like = f"%{str(filters['q'])[:100]}%"
        clauses.append("(action LIKE ? OR target LIKE ? OR details LIKE ? OR username LIKE ? OR ip LIKE ?)")
        params += [like] * 5
    if filters.get("username"):
        clauses.append("username = ?")
        params.append(str(filters["username"])[:64])
    if filters.get("category"):
        clauses.append("category = ?")
        params.append(str(filters["category"])[:40])
    if filters.get("status"):
        clauses.append("status = ?")
        params.append(str(filters["status"])[:20])
    if filters.get("date_from"):
        clauses.append("timestamp >= ?")
        params.append(str(filters["date_from"])[:10])
    if filters.get("date_to"):
        clauses.append("timestamp < date(?, '+1 day')")
        params.append(str(filters["date_to"])[:10])
    if filters.get("hide_nav"):
        clauses.append("category != 'navigation'")
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def _row(r: sqlite3.Row) -> Dict[str, Any]:
    try:
        details = json.loads(r["details"] or "{}")
    except Exception:
        details = {"raw": r["details"]}
    return {
        "id": r["id"],
        "timestamp": str(r["timestamp"]),
        "username": r["username"],
        "role": r["role"],
        "category": r["category"],
        "action": r["action"],
        "target": r["target"],
        "details": details,
        "status": r["status"],
        "ip": r["ip"],
        "user_agent": r["user_agent"],
    }


def search(filters: Dict[str, Any], limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    where, params = _where(filters)
    conn = _conn()
    total = conn.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ? OFFSET ?", params + [limit, offset]
    ).fetchall()

    stats = {
        "total": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        "today": conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE date(timestamp) = date('now','localtime')"
        ).fetchone()[0],
        "uploads": conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'pcap.upload'").fetchone()[0],
        "failed_logins": conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'auth.login' AND status = 'failed'"
        ).fetchone()[0],
        "users": [r[0] for r in conn.execute("SELECT DISTINCT username FROM audit_log ORDER BY username").fetchall()],
        "categories": [r[0] for r in conn.execute("SELECT DISTINCT category FROM audit_log ORDER BY category").fetchall()],
    }
    conn.close()
    return {"items": [_row(r) for r in rows], "total": total, "stats": stats}


def get(audit_id: int, query_limit: int = 500) -> Optional[Dict[str, Any]]:
    conn = _conn()
    r = conn.execute("SELECT * FROM audit_log WHERE id = ?", (audit_id,)).fetchone()
    if not r:
        conn.close()
        return None
    item = _row(r)
    q = conn.execute(
        """SELECT id, timestamp, src_ip, domain, qtype, probability, level FROM queries_log
           WHERE audit_id = ? ORDER BY id LIMIT ?""",
        (audit_id, query_limit),
    ).fetchall()
    item["linked_query_count"] = conn.execute(
        "SELECT COUNT(*) FROM queries_log WHERE audit_id = ?", (audit_id,)
    ).fetchone()[0]
    item["linked_queries"] = [
        {
            "id": x["id"], "timestamp": str(x["timestamp"]), "src_ip": x["src_ip"], "domain": x["domain"],
            "qtype": x["qtype"], "risk": round((x["probability"] or 0) * 100, 1), "level": x["level"],
        }
        for x in q
    ]
    conn.close()
    return item


def delete_ids(ids: List[int], cascade: bool) -> Dict[str, int]:
    ids = [int(i) for i in ids][:5000]
    if not ids:
        return {"audit_deleted": 0, "queries_deleted": 0}
    marks = ",".join("?" * len(ids))
    conn = _conn()
    q_deleted = 0
    if cascade:
        q_deleted = conn.execute(f"DELETE FROM queries_log WHERE audit_id IN ({marks})", ids).rowcount
    a_deleted = conn.execute(f"DELETE FROM audit_log WHERE id IN ({marks})", ids).rowcount
    conn.commit()
    conn.close()
    return {"audit_deleted": a_deleted, "queries_deleted": q_deleted}


def purge(filters: Dict[str, Any], cascade: bool) -> Dict[str, int]:
    where, params = _where(filters)
    conn = _conn()
    ids = [r[0] for r in conn.execute(f"SELECT id FROM audit_log{where}", params).fetchall()]
    conn.close()
    total = {"audit_deleted": 0, "queries_deleted": 0}
    for i in range(0, len(ids), 900):  # SQLite variable limit
        part = delete_ids(ids[i:i + 900], cascade)
        total["audit_deleted"] += part["audit_deleted"]
        total["queries_deleted"] += part["queries_deleted"]
    return total
