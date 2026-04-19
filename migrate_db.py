#!/usr/bin/env python3
import os
import sqlite3

DB = os.environ.get("KRONYX_DB", "kronyx.db")

def col_exists(conn, table: str, col: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == col for r in rows)

def add_col(conn, table: str, col: str, decl: str):
    if col_exists(conn, table, col):
        print(f"[OK] {table}.{col} already exists")
        return
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    print(f"[OK] added {table}.{col} {decl}")

def main():
    conn = sqlite3.connect(DB)
    try:
        # ledger upgrades
        add_col(conn, "ledger", "request_hash", "TEXT")
        add_col(conn, "ledger", "response_hash", "TEXT")

        # (optional) token tables if you upgraded runtime
        # These may already exist; CREATE IF NOT EXISTS is safe.
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS token_revocations (
            token_hash TEXT PRIMARY KEY,
            jti TEXT,
            agent_id TEXT,
            revoked_at TEXT NOT NULL,
            reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_revocations_jti ON token_revocations(jti);

        CREATE TABLE IF NOT EXISTS used_jti (
            jti TEXT PRIMARY KEY,
            agent_id TEXT,
            used_at TEXT NOT NULL
        );
        """)
        print("[OK] ensured token_revocations + used_jti tables")

        conn.commit()
        print("[DONE] migration complete")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
