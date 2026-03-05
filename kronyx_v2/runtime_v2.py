import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse


DB_PATH = os.environ.get("KRONYX_DB", os.path.join(os.path.dirname(__file__), "kronyx.db"))
SECRET_PATH = os.environ.get("KRONYX_SECRET", os.path.join(os.path.dirname(__file__), "kronyx_secret.key"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _load_or_create_secret() -> bytes:
    if os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "rb") as f:
            return f.read().strip()
    secret = os.urandom(32)
    os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
    with open(SECRET_PATH, "wb") as f:
        f.write(secret)
    return secret


SECRET = _load_or_create_secret()


def sign_token(payload: Dict[str, Any]) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(SECRET, body, hashlib.sha256).digest()
    return f"{_b64url_encode(body)}.{_b64url_encode(sig)}"


def verify_token(tok: str) -> Dict[str, Any]:
    try:
        body_b64, sig_b64 = tok.split(".", 1)
        body = _b64url_decode(body_b64)
        sig = _b64url_decode(sig_b64)
    except Exception:
        raise ValueError("invalid_token_format")

    expected = hmac.new(SECRET, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("invalid_token_signature")

    payload = json.loads(body.decode("utf-8"))
    now = int(time.time())
    exp = int(payload.get("exp", 0))
    if exp and now > exp:
        raise ValueError("token_expired")
    return payload


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS agents (
                agent TEXT PRIMARY KEY,
                created_ts INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS grants (
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                PRIMARY KEY (agent, action)
            );

            CREATE TABLE IF NOT EXISTS budgets (
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                max_count INTEGER,
                max_amount_cents INTEGER,
                PRIMARY KEY (agent, action)
            );

            CREATE TABLE IF NOT EXISTS allow_hosts (
                host TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                idem_key TEXT,
                ok INTEGER NOT NULL,
                response_json TEXT NOT NULL,
                created_ts INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS idem_cache (
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                idem_key TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                PRIMARY KEY (agent, action, idem_key)
            );
            """
        )


def _err(message: str, code: str = "client_error") -> Dict[str, Any]:
    return {"ok": False, "error": code, "message": message}


def _ok(result: Any) -> Dict[str, Any]:
    return {"ok": True, "result": result}


def _is_granted(conn: sqlite3.Connection, agent: str, action: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM grants WHERE agent=? AND action=?",
        (agent, action),
    ).fetchone()
    return row is not None


def _budget_check_and_consume(conn: sqlite3.Connection, agent: str, action: str, amount_cents: Optional[int]) -> Optional[Dict[str, Any]]:
    b = conn.execute(
        "SELECT max_count, max_amount_cents FROM budgets WHERE agent=? AND action=?",
        (agent, action),
    ).fetchone()
    if b is None:
        return None  # no budget configured => unlimited

    # Count usage so far (successful receipts only)
    used_count = conn.execute(
        "SELECT COUNT(*) AS n FROM receipts WHERE agent=? AND action=? AND ok=1",
        (agent, action),
    ).fetchone()["n"]

    used_amount = conn.execute(
        "SELECT COALESCE(SUM(json_extract(response_json,'$.amount_cents')),0) AS s "
        "FROM receipts WHERE agent=? AND action=? AND ok=1",
        (agent, action),
    ).fetchone()["s"]

    max_count = b["max_count"]
    max_amount = b["max_amount_cents"]

    if max_count is not None and used_count >= int(max_count):
        return _err("budget_exceeded: max_count", "forbidden")

    if amount_cents is not None and max_amount is not None:
        if int(used_amount) + int(amount_cents) > int(max_amount):
            return _err("budget_exceeded: max_amount_cents", "forbidden")

    return None


def _host_allowed(conn: sqlite3.Connection, url: str) -> bool:
    host = urlparse(url).hostname or ""
    row = conn.execute("SELECT 1 FROM allow_hosts WHERE host=?", (host,)).fetchone()
    return row is not None


def _make_receipt_id(agent: str, action: str, idem_key: Optional[str]) -> str:
    seed = f"{agent}|{action}|{idem_key or ''}|{time.time_ns()}".encode("utf-8")
    return hashlib.sha256(seed).hexdigest()[:16]


@dataclass
class KronyxRuntimeV2:
    def handle(self, token: str, action: str, request_obj: Dict[str, Any]) -> Dict[str, Any]:
        init_db()
        try:
            claims = verify_token(token)
        except Exception as e:
            return _err(f"auth_failed: {e}", "forbidden")

        agent = claims.get("agent")
        caps = set(claims.get("caps", []))
        if not agent:
            return _err("auth_failed: missing_agent", "forbidden")

        idem_key = request_obj.get("idem_key")

        # Capability gate (token)
        if action not in caps:
            return _err(f"missing_capability: {action}", "forbidden")

        with db() as conn:
            # Policy grant gate (server-side)
            if not _is_granted(conn, agent, action):
                return _err(f"not_granted: {agent} -> {action}", "forbidden")

            # Idempotency replay
            if idem_key:
                cached = conn.execute(
                    "SELECT receipt_id FROM idem_cache WHERE agent=? AND action=? AND idem_key=?",
                    (agent, action, idem_key),
                ).fetchone()
                if cached:
                    receipt_id = cached["receipt_id"]
                    rec = conn.execute(
                        "SELECT response_json FROM receipts WHERE receipt_id=?",
                        (receipt_id,),
                    ).fetchone()
                    if rec:
                        resp = json.loads(rec["response_json"])
                        # annotate replay
                        return _ok({"idempotent_replay": True, "previous_response": resp})

            # Execute action
            if action == "noop":
                resp = _ok({"echo": request_obj.get("echo", {"hello": "world"})})

            elif action == "http_request":
                url = request_obj.get("url")
                method = (request_obj.get("method") or "GET").upper()
                if not url:
                    resp = _err("missing_url")
                elif method not in ("GET", "POST"):
                    resp = _err("unsupported_method")
                elif not _host_allowed(conn, url):
                    resp = _err(f"host_not_allowlisted: {urlparse(url).hostname}", "forbidden")
                else:
                    try:
                        req = urllib.request.Request(url=url, method=method, headers={"User-Agent": "KronyxV2"})
                        with urllib.request.urlopen(req, timeout=10) as r:
                            body = r.read(2048)
                            resp = _ok(
                                {
                                    "status": r.status,
                                    "content_type": r.headers.get("content-type"),
                                    "url": url,
                                    "body_preview": body.decode("utf-8", errors="replace"),
                                }
                            )
                    except Exception as e:
                        resp = _err(f"http_error: {e}")

            elif action == "simulate_payment":
                amount_cents = int(request_obj.get("amount_cents", 0))
                recipient = request_obj.get("recipient", "acct_demo")
                if amount_cents <= 0:
                    resp = _err("invalid_amount_cents")
                else:
                    budget_err = _budget_check_and_consume(conn, agent, action, amount_cents)
                    if budget_err:
                        resp = budget_err
                    else:
                        resp = _ok(
                            {
                                "simulated": True,
                                "receipt_id": _make_receipt_id(agent, action, idem_key),
                                "amount_cents": amount_cents,
                                "recipient": recipient,
                            }
                        )
            else:
                resp = _err(f"unknown_action: {action}")

            # Persist receipt + idempotency mapping
            receipt_id = _make_receipt_id(agent, action, idem_key)
            conn.execute(
                "INSERT OR REPLACE INTO receipts(receipt_id, agent, action, idem_key, ok, response_json, created_ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    receipt_id,
                    agent,
                    action,
                    idem_key,
                    1 if resp.get("ok") else 0,
                    json.dumps(resp, separators=(",", ":"), sort_keys=True),
                    int(time.time()),
                ),
            )
            if idem_key:
                conn.execute(
                    "INSERT OR REPLACE INTO idem_cache(agent, action, idem_key, receipt_id) VALUES (?,?,?,?)",
                    (agent, action, idem_key, receipt_id),
                )

        return resp
