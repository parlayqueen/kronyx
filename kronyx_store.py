#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


def now_ts() -> int:
    return int(time.time())


class KronyxStoreError(RuntimeError):
    """Base storage error for persistence failures."""


class RecordValidationError(KronyxStoreError):
    """Raised when a caller provides an invalid persistence payload."""


class DelegationLifecycle:
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class KronyxPersistence(Protocol):
    def insert_receipt(self, receipt: dict[str, Any]) -> None: ...

    def list_receipts(self, limit: int = 50) -> list[dict[str, Any]]: ...

    def usage_for_agent(self, agent_id: str) -> dict[str, Any]: ...

    def insert_delegation(self, payload: dict[str, Any]) -> None: ...

    def revoke_token(
        self,
        jti: str,
        revoked_by_agent_id: str,
        reason: str,
        payload: dict[str, Any] | None = None,
    ) -> None: ...

    def is_token_revoked(self, jti: str) -> bool: ...

    def get_delegation(self, jti: str) -> dict[str, Any] | None: ...

    def list_delegations(
        self,
        limit: int = 50,
        delegatee_agent_id: str | None = None,
        delegator_agent_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class SQLiteStoreConfig:
    db_path: str
    busy_timeout_ms: int = 5000
    journal_mode: str = "WAL"
    synchronous: str = "NORMAL"


@dataclass(frozen=True)
class ReceiptRecord:
    receipt_id: str
    timestamp_epoch: int
    event_type: str
    agent_id: str | None
    action: str | None
    allowed: int | None
    reason: str | None
    estimated_cost_usd: float
    auth_type: str | None
    delegation_jti: str | None
    payload_json: str

    @classmethod
    def from_payload(cls, receipt: Mapping[str, Any]) -> ReceiptRecord:
        if not isinstance(receipt, Mapping):
            raise RecordValidationError("receipt payload must be an object")

        auth_context = receipt.get("auth_context")
        if not isinstance(auth_context, Mapping):
            auth_context = {}

        return cls(
            receipt_id=_clean_optional_str(receipt.get("receipt_id")) or f"receipt-{uuid.uuid4().hex}",
            timestamp_epoch=_safe_int(receipt.get("timestamp_epoch"), default=now_ts()),
            event_type=_clean_required_str(receipt.get("event_type"), default="execution"),
            agent_id=_clean_optional_str(receipt.get("agent_id")),
            action=_clean_optional_str(receipt.get("action")),
            allowed=_bool_to_db(receipt.get("allowed")),
            reason=_clean_optional_str(receipt.get("reason")),
            estimated_cost_usd=_safe_float(receipt.get("estimated_cost_usd"), default=0.0),
            auth_type=_clean_optional_str(auth_context.get("auth_type")),
            delegation_jti=_clean_optional_str(auth_context.get("jti")),
            payload_json=_serialize_payload(receipt),
        )


@dataclass(frozen=True)
class DelegationRecord:
    jti: str
    delegator_agent_id: str
    delegatee_agent_id: str
    issued_at_epoch: int
    expires_at_epoch: int
    status: str
    payload_json: str

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        status: str = DelegationLifecycle.ACTIVE,
    ) -> DelegationRecord:
        if not isinstance(payload, Mapping):
            raise RecordValidationError("delegation payload must be an object")

        jti = _clean_required_str(payload.get("jti"))
        delegator_agent_id = _clean_required_str(payload.get("delegator_agent_id"))
        delegatee_agent_id = _clean_required_str(payload.get("delegatee_agent_id"))
        issued_at_epoch = _safe_int(payload.get("iat"), default=now_ts())
        expires_at_epoch = _safe_int(payload.get("exp"), default=0)
        if expires_at_epoch <= 0:
            raise RecordValidationError("delegation payload missing exp")

        return cls(
            jti=jti,
            delegator_agent_id=delegator_agent_id,
            delegatee_agent_id=delegatee_agent_id,
            issued_at_epoch=issued_at_epoch,
            expires_at_epoch=expires_at_epoch,
            status=status,
            payload_json=_serialize_payload(payload),
        )


@dataclass(frozen=True)
class RevocationRecord:
    jti: str
    revoked_at_epoch: int
    revoked_by_agent_id: str | None
    reason: str | None
    payload_json: str

    @classmethod
    def create(
        cls,
        *,
        jti: str,
        revoked_by_agent_id: str,
        reason: str,
        payload: Mapping[str, Any] | None = None,
    ) -> RevocationRecord:
        cleaned_jti = _clean_required_str(jti)
        return cls(
            jti=cleaned_jti,
            revoked_at_epoch=now_ts(),
            revoked_by_agent_id=_clean_optional_str(revoked_by_agent_id),
            reason=_clean_optional_str(reason),
            payload_json=_serialize_payload(payload or {}),
        )


class SQLiteDatabase:
    _SCHEMA_SQL = """
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

    def __init__(self, config: SQLiteStoreConfig) -> None:
        self.config = config
        Path(self.config.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        self._shared_conn: sqlite3.Connection | None = None

        if self.config.db_path.startswith("file:") or self.config.db_path == ":memory:":
            self._shared_conn = self._connect()

        self.initialize()

    def initialize(self) -> None:
        with self.connection(write=True) as conn:
            conn.executescript(self._SCHEMA_SQL)

    @contextmanager
    def connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._shared_conn is not None:
                conn = self._shared_conn
                try:
                    yield conn
                    if write:
                        conn.commit()
                except sqlite3.Error as exc:
                    if write:
                        conn.rollback()
                    raise KronyxStoreError(f"sqlite operation failed: {exc}") from exc
            else:
                conn = self._connect()
                try:
                    yield conn
                    if write:
                        conn.commit()
                except sqlite3.Error as exc:
                    if write:
                        conn.rollback()
                    raise KronyxStoreError(f"sqlite operation failed: {exc}") from exc
                finally:
                    conn.close()

    def _connect(self) -> sqlite3.Connection:
        db_path = self.config.db_path
        use_uri = db_path.startswith("file:")

        conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
            uri=use_uri,
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA journal_mode={self.config.journal_mode};")
        conn.execute(f"PRAGMA synchronous={self.config.synchronous};")
        conn.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms};")
        return conn


class ReceiptRepository:
    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def upsert(
        self,
        receipt: Mapping[str, Any],
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        record = ReceiptRecord.from_payload(receipt)
        sql = """
            INSERT INTO receipts (
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
            ON CONFLICT(receipt_id) DO UPDATE SET
                timestamp_epoch = excluded.timestamp_epoch,
                event_type = excluded.event_type,
                agent_id = excluded.agent_id,
                action = excluded.action,
                allowed = excluded.allowed,
                reason = excluded.reason,
                estimated_cost_usd = excluded.estimated_cost_usd,
                auth_type = excluded.auth_type,
                delegation_jti = excluded.delegation_jti,
                payload_json = excluded.payload_json
        """

        params = (
            record.receipt_id,
            record.timestamp_epoch,
            record.event_type,
            record.agent_id,
            record.action,
            record.allowed,
            record.reason,
            record.estimated_cost_usd,
            record.auth_type,
            record.delegation_jti,
            record.payload_json,
        )
        self._execute_write(sql, params, conn=conn)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = _normalize_limit(limit)
        with self._db.connection() as conn:
            rows = conn.execute(
                """
                SELECT payload_json
                FROM receipts
                ORDER BY timestamp_epoch DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return _decode_payload_rows(rows)

    def usage_for_agent(self, agent_id: str) -> dict[str, Any]:
        agent_id = _clean_required_str(agent_id)
        ts_now = now_ts()
        hour_start = ts_now - (ts_now % 3600)
        day_start = ts_now - (ts_now % 86400)

        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(CASE
                        WHEN event_type = 'execution' AND timestamp_epoch >= ? THEN 1
                    END) AS requests_this_hour,
                    COALESCE(SUM(CASE
                        WHEN event_type = 'execution'
                         AND timestamp_epoch >= ?
                         AND action = 'http.fetch'
                        THEN 1 ELSE 0
                    END), 0) AS http_requests_this_hour,
                    COALESCE(SUM(CASE
                        WHEN event_type = 'execution'
                         AND timestamp_epoch >= ?
                         AND action = 'file.read'
                        THEN 1 ELSE 0
                    END), 0) AS file_reads_this_hour,
                    COALESCE(SUM(CASE
                        WHEN event_type = 'execution' AND timestamp_epoch >= ?
                        THEN estimated_cost_usd ELSE 0.0
                    END), 0.0) AS spend_today_usd
                FROM receipts
                WHERE agent_id = ?
                """,
                (hour_start, hour_start, hour_start, day_start, agent_id),
            ).fetchone()

        return {
            "requests_this_hour": int(row["requests_this_hour"] or 0),
            "http_requests_this_hour": int(row["http_requests_this_hour"] or 0),
            "file_reads_this_hour": int(row["file_reads_this_hour"] or 0),
            "spend_today_usd": round(float(row["spend_today_usd"] or 0.0), 6),
        }

    def _execute_write(
        self,
        sql: str,
        params: tuple[Any, ...],
        *,
        conn: sqlite3.Connection | None,
    ) -> None:
        if conn is not None:
            conn.execute(sql, params)
            return
        with self._db.connection(write=True) as owned_conn:
            owned_conn.execute(sql, params)


class RevocationRepository:
    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def upsert(
        self,
        record: RevocationRecord,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        sql = """
            INSERT INTO revoked_tokens (
                jti,
                revoked_at_epoch,
                revoked_by_agent_id,
                reason,
                payload_json
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(jti) DO UPDATE SET
                revoked_at_epoch = excluded.revoked_at_epoch,
                revoked_by_agent_id = excluded.revoked_by_agent_id,
                reason = excluded.reason,
                payload_json = excluded.payload_json
        """
        params = (
            record.jti,
            record.revoked_at_epoch,
            record.revoked_by_agent_id,
            record.reason,
            record.payload_json,
        )
        self._execute_write(sql, params, conn=conn)

    def exists(self, jti: str) -> bool:
        cleaned_jti = _clean_required_str(jti)
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM revoked_tokens
                WHERE jti = ?
                LIMIT 1
                """,
                (cleaned_jti,),
            ).fetchone()
        return row is not None

    def _execute_write(
        self,
        sql: str,
        params: tuple[Any, ...],
        *,
        conn: sqlite3.Connection | None,
    ) -> None:
        if conn is not None:
            conn.execute(sql, params)
            return
        with self._db.connection(write=True) as owned_conn:
            owned_conn.execute(sql, params)


class DelegationRepository:
    def __init__(self, db: SQLiteDatabase) -> None:
        self._db = db

    def upsert_active(
        self,
        payload: Mapping[str, Any],
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        record = DelegationRecord.from_payload(payload, status=DelegationLifecycle.ACTIVE)
        sql = """
            INSERT INTO delegations (
                jti,
                delegator_agent_id,
                delegatee_agent_id,
                issued_at_epoch,
                expires_at_epoch,
                status,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(jti) DO UPDATE SET
                delegator_agent_id = excluded.delegator_agent_id,
                delegatee_agent_id = excluded.delegatee_agent_id,
                issued_at_epoch = excluded.issued_at_epoch,
                expires_at_epoch = excluded.expires_at_epoch,
                status = excluded.status,
                payload_json = excluded.payload_json
        """
        params = (
            record.jti,
            record.delegator_agent_id,
            record.delegatee_agent_id,
            record.issued_at_epoch,
            record.expires_at_epoch,
            record.status,
            record.payload_json,
        )
        self._execute_write(sql, params, conn=conn)

    def get(self, jti: str) -> dict[str, Any] | None:
        cleaned_jti = _clean_required_str(jti)
        with self._db.connection() as conn:
            row = conn.execute(
                """
                SELECT payload_json, status, expires_at_epoch
                FROM delegations
                WHERE jti = ?
                LIMIT 1
                """,
                (cleaned_jti,),
            ).fetchone()

        return _decode_delegation_row(row)

    def list(
        self,
        *,
        limit: int = 50,
        delegatee_agent_id: str | None = None,
        delegator_agent_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        limit = _normalize_limit(limit)
        clauses: list[str] = []
        params: list[Any] = []

        if delegatee_agent_id:
            clauses.append("delegatee_agent_id = ?")
            params.append(_clean_required_str(delegatee_agent_id))

        if delegator_agent_id:
            clauses.append("delegator_agent_id = ?")
            params.append(_clean_required_str(delegator_agent_id))

        if status:
            normalized_status = status.strip().lower()
            if normalized_status == DelegationLifecycle.ACTIVE:
                clauses.append("status = ?")
                params.append(DelegationLifecycle.ACTIVE)
                clauses.append("expires_at_epoch > ?")
                params.append(now_ts())
            elif normalized_status == DelegationLifecycle.EXPIRED:
                clauses.append("status = ?")
                params.append(DelegationLifecycle.ACTIVE)
                clauses.append("expires_at_epoch <= ?")
                params.append(now_ts())
            else:
                clauses.append("status = ?")
                params.append(normalized_status)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT payload_json, status, expires_at_epoch
            FROM delegations
            {where_sql}
            ORDER BY issued_at_epoch DESC, id DESC
            LIMIT ?
        """
        params.append(limit)

        with self._db.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()

        out: list[dict[str, Any]] = []
        for row in rows:
            decoded = _decode_delegation_row(row)
            if decoded is not None:
                out.append(decoded)
        return out

    def mark_revoked(self, jti: str, *, conn: sqlite3.Connection | None = None) -> None:
        cleaned_jti = _clean_required_str(jti)
        sql = """
            UPDATE delegations
            SET status = ?
            WHERE jti = ?
        """
        self._execute_write(sql, (DelegationLifecycle.REVOKED, cleaned_jti), conn=conn)

    def _execute_write(
        self,
        sql: str,
        params: tuple[Any, ...],
        *,
        conn: sqlite3.Connection | None,
    ) -> None:
        if conn is not None:
            conn.execute(sql, params)
            return
        with self._db.connection(write=True) as owned_conn:
            owned_conn.execute(sql, params)


class KronyxStore(KronyxPersistence):
    """Facade preserving the original store API over clearer repository boundaries."""

    def __init__(self, db_path: str | None = None) -> None:
        default_path = os.environ.get("KRONYX_DB_PATH", "./data/kronyx.db")
        config = SQLiteStoreConfig(db_path=str(db_path or default_path))
        self._db = SQLiteDatabase(config)
        self.receipts = ReceiptRepository(self._db)
        self.revocations = RevocationRepository(self._db)
        self.delegations = DelegationRepository(self._db)

    def insert_receipt(self, receipt: dict[str, Any]) -> None:
        self.receipts.upsert(receipt)

    def list_receipts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.receipts.list(limit=limit)

    def usage_for_agent(self, agent_id: str) -> dict[str, Any]:
        return self.receipts.usage_for_agent(agent_id)

    def insert_delegation(self, payload: dict[str, Any]) -> None:
        self.delegations.upsert_active(payload)

    def revoke_token(
        self,
        jti: str,
        revoked_by_agent_id: str,
        reason: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        record = RevocationRecord.create(
            jti=jti,
            revoked_by_agent_id=revoked_by_agent_id,
            reason=reason,
            payload=payload,
        )
        with self._db.connection(write=True) as conn:
            self.revocations.upsert(record, conn=conn)
            self.delegations.mark_revoked(record.jti, conn=conn)

    def is_token_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        return self.revocations.exists(jti)

    def get_delegation(self, jti: str) -> dict[str, Any] | None:
        if not jti:
            return None
        return self.delegations.get(jti)

    def list_delegations(
        self,
        limit: int = 50,
        delegatee_agent_id: str | None = None,
        delegator_agent_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        return self.delegations.list(
            limit=limit,
            delegatee_agent_id=delegatee_agent_id,
            delegator_agent_id=delegator_agent_id,
            status=status,
        )


def _normalize_limit(limit: int) -> int:
    return max(1, min(int(limit), 500))


def _clean_required_str(value: Any, default: str | None = None) -> str:
    text = _clean_optional_str(value)
    if text:
        return text
    if default is not None:
        return default
    raise RecordValidationError("required string value missing")


def _clean_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bool_to_db(value: Any) -> int | None:
    if value is None:
        return None
    return 1 if bool(value) else 0


def _serialize_payload(payload: Mapping[str, Any]) -> str:
    try:
        return json.dumps(dict(payload), sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise RecordValidationError(f"payload is not JSON serializable: {exc}") from exc


def _decode_payload_rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError, KeyError):
            continue
        if isinstance(payload, dict):
            out.append(payload)
    return out


def _decode_delegation_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None

    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, ValueError, KeyError):
        return None
    if not isinstance(payload, dict):
        return None

    stored_status = str(row["status"])
    expires_at_epoch = _safe_int(row["expires_at_epoch"], default=0)
    payload["_status"] = stored_status
    payload["_lifecycle_state"] = _derive_delegation_lifecycle(stored_status, expires_at_epoch)
    payload["_is_expired"] = payload["_lifecycle_state"] == DelegationLifecycle.EXPIRED
    return payload


def _derive_delegation_lifecycle(stored_status: str, expires_at_epoch: int) -> str:
    if stored_status == DelegationLifecycle.REVOKED:
        return DelegationLifecycle.REVOKED
    if expires_at_epoch > 0 and now_ts() >= expires_at_epoch:
        return DelegationLifecycle.EXPIRED
    return DelegationLifecycle.ACTIVE
