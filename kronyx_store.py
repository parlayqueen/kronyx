#!/usr/bin/env python3
import os
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def now_ts() -> int:
    return int(time.time())


class KronyxStore:
    def __init__(self, db_path: Optional[str] = None) -> None:
        default_path = os.environ.get("KRONYX_DB_PATH", "./data/kronyx.db")
        self.db_path = str(db_path or default_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS receipts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        receipt_id TEXT UNIQUE,
                        timestamp_epoch INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        agent_id TEXT,
                        action TEXT,
                        allowed INTEGER,
                        reason TEXT,
                        estimated_cost_usd REAL,
                        auth_type TEXT,
                        delegation_jti TEXT,
                        payload_json TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_receipts_ts
                    ON receipts(timestamp_epoch DESC);

                    CREATE INDEX IF NOT EXISTS idx_receipts_agent_ts
                    ON receipts(agent_id, timestamp_epoch DESC);

                    CREATE INDEX IF NOT EXISTS idx_receipts_event_type_ts
                    ON receipts(event_type, timestamp_epoch DESC);

                    CREATE INDEX IF NOT EXISTS idx_receipts_delegation_jti
                    ON receipts(delegation_jti);

                    CREATE TABLE IF NOT EXISTS revoked_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        jti TEXT UNIQUE NOT NULL,
                        revoked_at_epoch INTEGER NOT NULL,
                        revoked_by_agent_id TEXT,
                        reason TEXT,
                        payload_json TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti
                    ON revoked_tokens(jti);

                    CREATE TABLE IF NOT EXISTS delegations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        jti TEXT UNIQUE NOT NULL,
                        delegator_agent_id TEXT NOT NULL,
                        delegatee_agent_id TEXT NOT NULL,
                        issued_at_epoch INTEGER NOT NULL,
                        expires_at_epoch INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_delegations_delegatee
                    ON delegations(delegatee_agent_id, issued_at_epoch DESC);

                    CREATE INDEX IF NOT EXISTS idx_delegations_delegator
                    ON delegations(delegator_agent_id, issued_at_epoch DESC);

                    CREATE INDEX IF NOT EXISTS idx_delegations_status
                    ON delegations(status, issued_at_epoch DESC);
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def insert_receipt(self, receipt: Dict[str, Any]) -> None:
        payload_json = json.dumps(receipt, sort_keys=True, ensure_ascii=False)
        timestamp_epoch = int(receipt.get("timestamp_epoch", now_ts()))
        event_type = str(receipt.get("event_type", "execution"))
        agent_id = receipt.get("agent_id")
        action = receipt.get("action")
        allowed = receipt.get("allowed")
        reason = receipt.get("reason")
        estimated_cost_usd = float(receipt.get("estimated_cost_usd", 0.0) or 0.0)

        auth_context = receipt.get("auth_context", {})
        if not isinstance(auth_context, dict):
            auth_context = {}
        auth_type = auth_context.get("auth_type")
        delegation_jti = auth_context.get("jti")

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO receipts (
                        receipt_id,
                        timestamp_epoch,
                        event_type,
                        agent_id,
                        action,
                        allowed,
                        reason,
                        estimated_cost_usd,
                        auth_type,
                        delegation_jti,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.get("receipt_id"),
                        timestamp_epoch,
                        event_type,
                        agent_id,
                        action,
                        1 if allowed else 0 if allowed is not None else None,
                        reason,
                        estimated_cost_usd,
                        auth_type,
                        delegation_jti,
                        payload_json,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def list_receipts(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT payload_json
                    FROM receipts
                    ORDER BY timestamp_epoch DESC, id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            finally:
                conn.close()

        out: List[Dict[str, Any]] = []
        for row in rows:
            try:
                out.append(json.loads(row["payload_json"]))
            except Exception:
                continue
        return out

    def usage_for_agent(self, agent_id: str) -> Dict[str, Any]:
        ts_now = now_ts()
        hour_start = ts_now - (ts_now % 3600)
        day_start = ts_now - (ts_now % 86400)

        usage = {
            "requests_this_hour": 0,
            "http_requests_this_hour": 0,
            "file_reads_this_hour": 0,
            "spend_today_usd": 0.0
        }

        with self._lock:
            conn = self._connect()
            try:
                rows_hour = conn.execute(
                    """
                    SELECT action
                    FROM receipts
                    WHERE agent_id = ?
                      AND event_type = 'execution'
                      AND timestamp_epoch >= ?
                    """,
                    (agent_id, hour_start),
                ).fetchall()

                for row in rows_hour:
                    usage["requests_this_hour"] += 1
                    action = row["action"]
                    if action == "http.fetch":
                        usage["http_requests_this_hour"] += 1
                    if action == "file.read":
                        usage["file_reads_this_hour"] += 1

                row_day = conn.execute(
                    """
                    SELECT COALESCE(SUM(estimated_cost_usd), 0.0) AS spend_today_usd
                    FROM receipts
                    WHERE agent_id = ?
                      AND event_type = 'execution'
                      AND timestamp_epoch >= ?
                    """,
                    (agent_id, day_start),
                ).fetchone()

                usage["spend_today_usd"] = round(float(row_day["spend_today_usd"] or 0.0), 6)
            finally:
                conn.close()

        return usage

    def insert_delegation(self, payload: Dict[str, Any]) -> None:
        jti = str(payload.get("jti", "")).strip()
        if not jti:
            raise ValueError("Delegation payload missing jti")

        delegator_agent_id = str(payload.get("delegator_agent_id", "")).strip()
        delegatee_agent_id = str(payload.get("delegatee_agent_id", "")).strip()
        issued_at_epoch = int(payload.get("iat", now_ts()))
        expires_at_epoch = int(payload.get("exp", 0))
        payload_json = json.dumps(payload, sort_keys=True, ensure_ascii=False)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO delegations (
                        jti,
                        delegator_agent_id,
                        delegatee_agent_id,
                        issued_at_epoch,
                        expires_at_epoch,
                        status,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        jti,
                        delegator_agent_id,
                        delegatee_agent_id,
                        issued_at_epoch,
                        expires_at_epoch,
                        "active",
                        payload_json,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def revoke_token(
        self,
        jti: str,
        revoked_by_agent_id: str,
        reason: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not jti:
            raise ValueError("Missing jti")

        payload_json = json.dumps(payload or {}, sort_keys=True, ensure_ascii=False)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO revoked_tokens (
                        jti,
                        revoked_at_epoch,
                        revoked_by_agent_id,
                        reason,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        jti,
                        now_ts(),
                        revoked_by_agent_id,
                        reason,
                        payload_json,
                    ),
                )

                conn.execute(
                    """
                    UPDATE delegations
                    SET status = 'revoked'
                    WHERE jti = ?
                    """,
                    (jti,),
                )
                conn.commit()
            finally:
                conn.close()

    def is_token_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT 1
                    FROM revoked_tokens
                    WHERE jti = ?
                    LIMIT 1
                    """,
                    (jti,),
                ).fetchone()
            finally:
                conn.close()
        return row is not None

    def get_delegation(self, jti: str) -> Optional[Dict[str, Any]]:
        if not jti:
            return None
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT payload_json, status
                    FROM delegations
                    WHERE jti = ?
                    LIMIT 1
                    """,
                    (jti,),
                ).fetchone()
            finally:
                conn.close()

        if row is None:
            return None

        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            return None

        payload["_status"] = row["status"]
        return payload

    def list_delegations(
        self,
        limit: int = 50,
        delegatee_agent_id: Optional[str] = None,
        delegator_agent_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        clauses = []
        params: List[Any] = []

        if delegatee_agent_id:
            clauses.append("delegatee_agent_id = ?")
            params.append(delegatee_agent_id)

        if delegator_agent_id:
            clauses.append("delegator_agent_id = ?")
            params.append(delegator_agent_id)

        if status:
            clauses.append("status = ?")
            params.append(status)

        where_sql = ""
        if clauses:
            where_sql = "WHERE " + " AND ".join(clauses)

        sql = f"""
            SELECT payload_json, status
            FROM delegations
            {where_sql}
            ORDER BY issued_at_epoch DESC, id DESC
            LIMIT ?
        """
        params.append(limit)

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(sql, tuple(params)).fetchall()
            finally:
                conn.close()

        out: List[Dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
                payload["_status"] = row["status"]
                out.append(payload)
            except Exception:
                continue
        return out
