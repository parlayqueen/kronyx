#!/usr/bin/env python3
"""
KRONYX MVP Runtime (Atlas) — execution-time governance for autonomous actions.

- Standard library only (Termux friendly)
- SQLite storage for:
  - capabilities registry
  - budgets
  - policies
  - idempotency keys
  - append-only execution ledger
- HMAC-signed capability tokens
- Governed "actions":
  - http_request (GET/POST) with allowlist
  - noop (for testing)
  - simulate_payment (NO real payments; just demonstrates governance)

Run:
  python kronyx_runtime.py --host 127.0.0.1 --port 8787

Then use:
  python tools_admin.py init
  python tools_admin.py issue-token --agent agent_42 --cap http_request --cap noop
  python agent_demo.py
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import urllib.request
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple


DB_FILE_DEFAULT = os.environ.get("KRONYX_DB", "kronyx.db")
HMAC_SECRET_DEFAULT = os.environ.get("KRONYX_HMAC_SECRET", "CHANGE_ME__set_KRONYX_HMAC_SECRET")
LEDGER_MAX_BODY = 4096  # store small payload excerpts
UTC = dt.timezone.utc


def utc_now_iso() -> str:
    return dt.datetime.now(tz=UTC).isoformat()


def day_key_utc() -> str:
    d = dt.datetime.now(tz=UTC).date()
    return d.isoformat()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def hmac_sign(secret: str, msg: bytes) -> str:
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return b64url(sig)


def canonical_json(obj: Any) -> bytes:
    # Deterministic serialization (lightweight). For strict canonicalization later, use RFC 8785 JCS.
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class DB:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._ensure()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure(self) -> None:
        with self._lock:
            conn = self._conn()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS agents (
                        agent_id TEXT PRIMARY KEY,
                        display_name TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS agent_caps (
                        agent_id TEXT NOT NULL,
                        capability TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (agent_id, capability),
                        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                    );

                    CREATE TABLE IF NOT EXISTS budgets (
                        agent_id TEXT NOT NULL,
                        day TEXT NOT NULL,
                        action TEXT NOT NULL,
                        max_count INTEGER NOT NULL,
                        used_count INTEGER NOT NULL,
                        max_amount_cents INTEGER,  -- optional (for payment-like actions)
                        used_amount_cents INTEGER NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (agent_id, day, action),
                        FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                    );

                    CREATE TABLE IF NOT EXISTS policies (
                        policy_id TEXT PRIMARY KEY,
                        action TEXT NOT NULL,
                        mode TEXT NOT NULL, -- 'allow' or 'deny'
                        rules_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS idempotency (
                        agent_id TEXT NOT NULL,
                        idem_key TEXT NOT NULL,
                        action TEXT NOT NULL,
                        status TEXT NOT NULL, -- 'approved'|'rejected'|'executed'|'failed'
                        response_json TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (agent_id, idem_key, action)
                    );

                    CREATE TABLE IF NOT EXISTS ledger (
                        ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        outcome TEXT NOT NULL, -- approved|rejected|executed|failed
                        reason TEXT,
                        request_excerpt TEXT,
                        response_excerpt TEXT,
                        cap_token_hash TEXT,
                        policy_snapshot TEXT,
                        budget_snapshot TEXT,
                        idem_key TEXT,
                        prev_hash TEXT,
                        entry_hash TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_ledger_agent_ts ON ledger(agent_id, ts);
                    """
                )
            finally:
                conn.close()

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        conn = self._conn()
        try:
            conn.execute(sql, params)
        finally:
            conn.close()

    def fetchone(self, sql: str, params: Tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
        conn = self._conn()
        try:
            cur = conn.execute(sql, params)
            return cur.fetchone()
        finally:
            conn.close()

    def fetchall(self, sql: str, params: Tuple[Any, ...] = ()) -> list:
        conn = self._conn()
        try:
            cur = conn.execute(sql, params)
            return cur.fetchall()
        finally:
            conn.close()

    def transaction(self):
        # context manager for transaction
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE;")
        return conn


class GovernanceError(Exception):
    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class KronyxRuntime:
    def __init__(self, db: DB, secret: str):
        self.db = db
        self.secret = secret
        self.allowed_http_hosts = set(
            (os.environ.get("KRONYX_HTTP_ALLOWLIST", "httpbin.org,postman-echo.com").split(","))
        )

    # -------- Token format --------
    # token = base64url(payload_json) + "." + base64url(hmac_sha256(payload_json))
    # payload: {agent_id, caps:[...], iat, exp}
    def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            payload_bytes = b64url_decode(payload_b64)
            payload = json.loads(payload_bytes.decode("utf-8"))
            expected = hmac_sign(self.secret, payload_bytes)
            if not hmac.compare_digest(expected, sig_b64):
                raise GovernanceError("bad_token", "Token signature invalid")
            now = int(time.time())
            if int(payload.get("iat", 0)) > now + 60:
                raise GovernanceError("bad_token", "Token iat is in the future")
            if int(payload.get("exp", 0)) < now:
                raise GovernanceError("expired_token", "Token is expired")
            return payload
        except ValueError:
            raise GovernanceError("bad_token", "Token format invalid")
        except json.JSONDecodeError:
            raise GovernanceError("bad_token", "Token payload invalid JSON")

    def token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    # -------- Core checks --------
    def require_capability(self, agent_id: str, cap: str) -> None:
        row = self.db.fetchone(
            "SELECT 1 FROM agent_caps WHERE agent_id=? AND capability=?",
            (agent_id, cap),
        )
        if not row:
            raise GovernanceError("cap_denied", f"Agent '{agent_id}' lacks capability '{cap}'")

    def eval_policies(self, action: str, request_obj: Dict[str, Any]) -> Dict[str, Any]:
        # Policies are simple JSON rules. MVP supports:
        # - allow/deny by matching keys in request_obj with exact values
        # rules_json: {"match": {"field":"value", ...}}
        policies = self.db.fetchall(
            "SELECT policy_id, mode, rules_json FROM policies WHERE action=?",
            (action,),
        )
        snapshot = {"evaluated": [], "decision": "allow"}  # default allow if no deny matches
        for p in policies:
            rules = json.loads(p["rules_json"])
            match = rules.get("match", {})
            ok = True
            for k, v in match.items():
                if request_obj.get(k) != v:
                    ok = False
                    break
            snapshot["evaluated"].append({"policy_id": p["policy_id"], "mode": p["mode"], "matched": ok})
            if ok and p["mode"] == "deny":
                snapshot["decision"] = "deny"
                snapshot["deny_policy_id"] = p["policy_id"]
                return snapshot
        return snapshot

    def enforce_budget(self, agent_id: str, action: str, amount_cents: int = 0) -> Dict[str, Any]:
        dkey = day_key_utc()
        # If no budget row exists, create a permissive default for MVP.
        # In production you’d be explicit. Here defaults prevent runaway:
        # - max_count: 1000/day per action
        # - max_amount_cents: 0 means not tracked unless set
        with self.db.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM budgets WHERE agent_id=? AND day=? AND action=?",
                (agent_id, dkey, action),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO budgets(agent_id, day, action, max_count, used_count, max_amount_cents, used_amount_cents, updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (agent_id, dkey, action, 1000, 0, None, 0, utc_now_iso()),
                )
                row = conn.execute(
                    "SELECT * FROM budgets WHERE agent_id=? AND day=? AND action=?",
                    (agent_id, dkey, action),
                ).fetchone()

            max_count = int(row["max_count"])
            used_count = int(row["used_count"])
            max_amount = row["max_amount_cents"]
            used_amount = int(row["used_amount_cents"])

            if used_count + 1 > max_count:
                raise GovernanceError("budget_exhausted", f"Budget exceeded for action '{action}' (count)")

            if max_amount is not None and amount_cents > 0:
                if used_amount + amount_cents > int(max_amount):
                    raise GovernanceError("budget_exhausted", f"Budget exceeded for action '{action}' (amount)")

            # commit consumption
            new_used_count = used_count + 1
            new_used_amount = used_amount + max(0, amount_cents)
            conn.execute(
                "UPDATE budgets SET used_count=?, used_amount_cents=?, updated_at=? "
                "WHERE agent_id=? AND day=? AND action=?",
                (new_used_count, new_used_amount, utc_now_iso(), agent_id, dkey, action),
            )

            return {
                "day": dkey,
                "action": action,
                "max_count": max_count,
                "used_count": new_used_count,
                "max_amount_cents": max_amount,
                "used_amount_cents": new_used_amount,
            }

    def idempotency_check(self, agent_id: str, action: str, idem_key: str) -> Optional[Dict[str, Any]]:
        if not idem_key:
            return None
        row = self.db.fetchone(
            "SELECT status, response_json FROM idempotency WHERE agent_id=? AND action=? AND idem_key=?",
            (agent_id, action, idem_key),
        )
        if row:
            resp = json.loads(row["response_json"]) if row["response_json"] else None
            return {"status": row["status"], "response": resp}
        return None

    def idempotency_set(self, agent_id: str, action: str, idem_key: str, status: str, response: Optional[Dict[str, Any]]) -> None:
        if not idem_key:
            return
        now = utc_now_iso()
        resp_json = json.dumps(response) if response is not None else None
        self.db.execute(
            "INSERT INTO idempotency(agent_id, idem_key, action, status, response_json, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(agent_id, idem_key, action) DO UPDATE SET status=excluded.status, response_json=excluded.response_json, updated_at=excluded.updated_at",
            (agent_id, idem_key, action, status, resp_json, now, now),
        )

    # -------- Ledger --------
    def ledger_append(
        self,
        agent_id: str,
        action: str,
        outcome: str,
        reason: str,
        request_obj: Dict[str, Any],
        response_obj: Optional[Dict[str, Any]],
        cap_token: str,
        policy_snapshot: Dict[str, Any],
        budget_snapshot: Optional[Dict[str, Any]],
        idem_key: Optional[str],
    ) -> str:
        req_excerpt = json.dumps(request_obj)[:LEDGER_MAX_BODY]
        resp_excerpt = json.dumps(response_obj)[:LEDGER_MAX_BODY] if response_obj is not None else None
        cap_hash = self.token_hash(cap_token)

        prev = self.db.fetchone("SELECT entry_hash FROM ledger ORDER BY ledger_id DESC LIMIT 1")
        prev_hash = prev["entry_hash"] if prev else None

        entry = {
            "ts": utc_now_iso(),
            "agent_id": agent_id,
            "action": action,
            "outcome": outcome,
            "reason": reason,
            "request_excerpt": req_excerpt,
            "response_excerpt": resp_excerpt or "",
            "cap_token_hash": cap_hash,
            "policy_snapshot": policy_snapshot,
            "budget_snapshot": budget_snapshot,
            "idem_key": idem_key or "",
            "prev_hash": prev_hash or "",
        }
        entry_hash = hashlib.sha256(canonical_json(entry)).hexdigest()

        self.db.execute(
            "INSERT INTO ledger(ts, agent_id, action, outcome, reason, request_excerpt, response_excerpt, cap_token_hash, policy_snapshot, budget_snapshot, idem_key, prev_hash, entry_hash) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                entry["ts"],
                agent_id,
                action,
                outcome,
                reason,
                req_excerpt,
                resp_excerpt,
                cap_hash,
                json.dumps(policy_snapshot),
                json.dumps(budget_snapshot) if budget_snapshot is not None else None,
                idem_key,
                prev_hash,
                entry_hash,
            ),
        )
        return entry_hash

    # -------- Action handlers --------
    def _handle_noop(self, req: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": True, "echo": req.get("payload", {}), "ts": utc_now_iso()}

    def _handle_simulate_payment(self, req: Dict[str, Any]) -> Dict[str, Any]:
        # This is a simulation only. It proves idempotency + budgets + ledger.
        payload = req.get("payload", {})
        amount_cents = int(payload.get("amount_cents", 0))
        recipient = str(payload.get("recipient", "unknown"))
        if amount_cents <= 0:
            raise GovernanceError("bad_request", "amount_cents must be > 0")
        # Return a deterministic fake receipt id
        receipt_id = hashlib.sha256(f"{recipient}:{amount_cents}:{req.get('idem_key','')}".encode("utf-8")).hexdigest()[:16]
        return {"ok": True, "simulated": True, "receipt_id": receipt_id, "amount_cents": amount_cents, "recipient": recipient}

    def _handle_http_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        payload = req.get("payload", {})
        method = str(payload.get("method", "GET")).upper()
        url = str(payload.get("url", ""))
        data = payload.get("data", None)
        headers = payload.get("headers", {})

        if not url.startswith("http://") and not url.startswith("https://"):
            raise GovernanceError("bad_request", "url must start with http:// or https://")

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if host not in self.allowed_http_hosts:
            raise GovernanceError("policy_denied", f"host '{host}' not in allowlist")

        if method not in ("GET", "POST"):
            raise GovernanceError("policy_denied", "Only GET/POST allowed in MVP")

        body_bytes = None
        if data is not None:
            if isinstance(data, (dict, list)):
                body_bytes = json.dumps(data).encode("utf-8")
                headers = dict(headers)
                headers.setdefault("Content-Type", "application/json")
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            else:
                raise GovernanceError("bad_request", "data must be dict/list/str")

        req_obj = urllib.request.Request(url=url, method=method, data=body_bytes)
        for k, v in (headers or {}).items():
            req_obj.add_header(str(k), str(v))

        try:
            with urllib.request.urlopen(req_obj, timeout=10) as resp:
                raw = resp.read()
                ct = resp.headers.get("Content-Type", "")
                text = raw[:8192].decode("utf-8", errors="replace")
                return {
                    "ok": True,
                    "status": int(resp.status),
                    "content_type": ct,
                    "body_preview": text,
                }
        except Exception as e:
            raise GovernanceError("external_error", f"http_request failed: {e.__class__.__name__}: {e}")

    def execute(self, agent_id: str, token: str, action: str, capability: str, idem_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        # 1) token verify
        tok = self.verify_token(token)
        if tok.get("agent_id") != agent_id:
            raise GovernanceError("bad_token", "Token agent_id mismatch")

        # 2) capability must be in signed token AND in registry (two-man rule)
        caps = set(tok.get("caps", []))
        if capability not in caps:
            raise GovernanceError("cap_denied", f"Capability '{capability}' not present in token")
        self.require_capability(agent_id, capability)

        # 3) idempotency
        hit = self.idempotency_check(agent_id, action, idem_key)
        if hit:
            # return previously computed response, do not repeat side effect
            return {
                "ok": True,
                "idempotent_replay": True,
                "previous_status": hit["status"],
                "previous_response": hit["response"],
            }

        # 4) policy evaluation (MVP: allow/deny match rules)
        request_obj = {
            "agent_id": agent_id,
            "action": action,
            "capability": capability,
            "idem_key": idem_key,
            "payload": payload or {},
        }
        pol = self.eval_policies(action, request_obj)
        if pol.get("decision") == "deny":
            reason = f"Denied by policy {pol.get('deny_policy_id','unknown')}"
            self.idempotency_set(agent_id, action, idem_key, "rejected", {"error": "policy_denied", "reason": reason})
            self.ledger_append(agent_id, action, "rejected", reason, request_obj, {"error": "policy_denied"}, token, pol, None, idem_key)
            raise GovernanceError("policy_denied", reason)

        # 5) budget enforcement (action-specific amount optional)
        amount_cents = 0
        if action == "simulate_payment":
            amount_cents = int((payload or {}).get("amount_cents", 0))
        budget = self.enforce_budget(agent_id, action, amount_cents=amount_cents)

        # 6) approve & execute action
        self.idempotency_set(agent_id, action, idem_key, "approved", {"approved": True})
        self.ledger_append(agent_id, action, "approved", "approved", request_obj, {"approved": True}, token, pol, budget, idem_key)

        try:
            if action == "noop":
                resp = self._handle_noop(request_obj)
            elif action == "http_request":
                resp = self._handle_http_request(request_obj)
            elif action == "simulate_payment":
                resp = self._handle_simulate_payment(request_obj)
            else:
                raise GovernanceError("unknown_action", f"Unknown action '{action}'")

            self.idempotency_set(agent_id, action, idem_key, "executed", resp)
            self.ledger_append(agent_id, action, "executed", "executed", request_obj, resp, token, pol, budget, idem_key)
            return resp
        except GovernanceError as ge:
            self.idempotency_set(agent_id, action, idem_key, "failed", {"error": ge.code, "message": ge.message, "details": ge.details})
            self.ledger_append(agent_id, action, "failed", f"{ge.code}: {ge.message}", request_obj, {"error": ge.code, "message": ge.message}, token, pol, budget, idem_key)
            raise
        except Exception as e:
            msg = f"{e.__class__.__name__}: {e}"
            self.idempotency_set(agent_id, action, idem_key, "failed", {"error": "internal_error", "message": msg})
            self.ledger_append(agent_id, action, "failed", msg, request_obj, {"error": "internal_error", "message": msg}, token, pol, budget, idem_key)
            raise GovernanceError("internal_error", msg)


class Handler(BaseHTTPRequestHandler):
    server_version = "KRONYX/0.1"

    def _json(self, code: int, obj: Dict[str, Any]) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise GovernanceError("bad_request", "Invalid JSON body")

    def do_GET(self):
        # simple health + ledger tail
        if self.path == "/health":
            return self._json(200, {"ok": True, "ts": utc_now_iso()})
        if self.path.startswith("/ledger/tail"):
            try:
                qs = urllib.parse.urlparse(self.path).query
                q = urllib.parse.parse_qs(qs)
                n = int(q.get("n", ["20"])[0])
                rows = self.server.db.fetchall(
                    "SELECT ledger_id, ts, agent_id, action, outcome, reason, idem_key, entry_hash, prev_hash "
                    "FROM ledger ORDER BY ledger_id DESC LIMIT ?",
                    (n,),
                )
                out = [dict(r) for r in rows][::-1]
                return self._json(200, {"ok": True, "rows": out})
            except Exception as e:
                return self._json(500, {"ok": False, "error": str(e)})

        self._json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        if self.path != "/execute":
            return self._json(404, {"ok": False, "error": "not_found"})

        try:
            body = self._read_json()
            agent_id = str(body.get("agent_id", ""))
            token = str(body.get("token", ""))
            action = str(body.get("action", ""))
            capability = str(body.get("capability", ""))
            idem_key = str(body.get("idem_key", "")) or ""
            payload = body.get("payload", {}) or {}

            if not (agent_id and token and action and capability):
                raise GovernanceError("bad_request", "agent_id, token, action, capability required")

            resp = self.server.runtime.execute(agent_id, token, action, capability, idem_key, payload)
            return self._json(200, {"ok": True, "result": resp})
        except GovernanceError as ge:
            return self._json(403, {"ok": False, "error": ge.code, "message": ge.message, "details": ge.details})
        except Exception as e:
            return self._json(500, {"ok": False, "error": "internal_error", "message": str(e)})


class KronyxHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, db: DB, runtime: KronyxRuntime):
        super().__init__(server_address, RequestHandlerClass)
        self.db = db
        self.runtime = runtime


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--db", default=DB_FILE_DEFAULT)
    ap.add_argument("--secret", default=HMAC_SECRET_DEFAULT)
    args = ap.parse_args()

    if args.secret == "CHANGE_ME__set_KRONYX_HMAC_SECRET":
        print("WARNING: You should set KRONYX_HMAC_SECRET in your environment for real use.")

    db = DB(args.db)
    runtime = KronyxRuntime(db, args.secret)

    httpd = KronyxHTTPServer((args.host, args.port), Handler, db, runtime)
    print(f"[KRONYX] runtime listening on http://{args.host}:{args.port}")
    print(f"[KRONYX] db={args.db}")
    print(f"[KRONYX] allowlist hosts={sorted(runtime.allowed_http_hosts)}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
