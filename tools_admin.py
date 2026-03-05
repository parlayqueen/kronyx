#!/usr/bin/env python3
"""
Admin tooling for KRONYX MVP.

Commands:
  python tools_admin.py init
  python tools_admin.py add-agent --agent agent_42 --name "Demo Agent"
  python tools_admin.py grant --agent agent_42 --cap noop
  python tools_admin.py grant --agent agent_42 --cap http_request
  python tools_admin.py set-budget --agent agent_42 --action http_request --max-count 50
  python tools_admin.py set-budget --agent agent_42 --action simulate_payment --max-count 10 --max-amount-cents 20000
  python tools_admin.py add-policy --id deny_payments --action simulate_payment --mode deny --match action simulate_payment
  python tools_admin.py issue-token --agent agent_42 --cap noop --cap http_request --cap simulate_payment --ttl 86400
"""

import argparse
import json
import os
import time
import sqlite3
import hashlib
import hmac
import base64
from typing import Any, Dict, List

DB_FILE = os.environ.get("KRONYX_DB", "kronyx.db")
SECRET = os.environ.get("KRONYX_HMAC_SECRET", "CHANGE_ME__set_KRONYX_HMAC_SECRET")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def hmac_sign(secret: str, msg: bytes) -> str:
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return b64url(sig)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def conn():
    c = sqlite3.connect(DB_FILE, timeout=30, isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute("PRAGMA synchronous=NORMAL;")
    return c


def init_db():
    import kronyx_runtime  # ensures schema exists
    _ = kronyx_runtime.DB(DB_FILE)
    print(f"[OK] initialized db: {DB_FILE}")


def add_agent(agent_id: str, name: str):
    c = conn()
    try:
        c.execute(
            "INSERT INTO agents(agent_id, display_name, created_at) VALUES(?,?,datetime('now')) "
            "ON CONFLICT(agent_id) DO UPDATE SET display_name=excluded.display_name",
            (agent_id, name),
        )
        print(f"[OK] agent upserted: {agent_id}")
    finally:
        c.close()


def grant_cap(agent_id: str, cap: str):
    c = conn()
    try:
        c.execute(
            "INSERT INTO agent_caps(agent_id, capability, created_at) VALUES(?,?,datetime('now')) "
            "ON CONFLICT(agent_id, capability) DO NOTHING",
            (agent_id, cap),
        )
        print(f"[OK] granted {cap} to {agent_id}")
    finally:
        c.close()


def set_budget(agent_id: str, action: str, max_count: int, max_amount_cents: int | None):
    day = time.strftime("%Y-%m-%d", time.gmtime())
    c = conn()
    try:
        c.execute(
            "INSERT INTO budgets(agent_id, day, action, max_count, used_count, max_amount_cents, used_amount_cents, updated_at) "
            "VALUES(?,?,?,?,?,?,?,datetime('now')) "
            "ON CONFLICT(agent_id, day, action) DO UPDATE SET max_count=excluded.max_count, max_amount_cents=excluded.max_amount_cents, updated_at=excluded.updated_at",
            (agent_id, day, action, max_count, 0, max_amount_cents, 0),
        )
        print(f"[OK] budget set for {agent_id} {action} day={day} max_count={max_count} max_amount_cents={max_amount_cents}")
    finally:
        c.close()


def add_policy(pid: str, action: str, mode: str, match_pairs: List[str]):
    match: Dict[str, Any] = {}
    # match_pairs like: ["field", "value", "field2", "value2"]
    if len(match_pairs) % 2 != 0:
        raise SystemExit("match pairs must be even: field value field value ...")
    it = iter(match_pairs)
    for k, v in zip(it, it):
        match[k] = v
    rules = {"match": match}
    c = conn()
    try:
        c.execute(
            "INSERT INTO policies(policy_id, action, mode, rules_json, created_at) VALUES(?,?,?,?,datetime('now')) "
            "ON CONFLICT(policy_id) DO UPDATE SET action=excluded.action, mode=excluded.mode, rules_json=excluded.rules_json",
            (pid, action, mode, json.dumps(rules)),
        )
        print(f"[OK] policy upserted: {pid} action={action} mode={mode} match={match}")
    finally:
        c.close()


def issue_token(agent_id: str, caps: List[str], ttl: int):
    if SECRET == "CHANGE_ME__set_KRONYX_HMAC_SECRET":
        print("WARNING: Set KRONYX_HMAC_SECRET in your environment.")
    now = int(time.time())
    payload = {"agent_id": agent_id, "caps": caps, "iat": now, "exp": now + ttl}
    payload_bytes = canonical_json(payload)
    token = b64url(payload_bytes) + "." + hmac_sign(SECRET, payload_bytes)
    print(token)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")

    p_add = sub.add_parser("add-agent")
    p_add.add_argument("--agent", required=True)
    p_add.add_argument("--name", default="")

    p_grant = sub.add_parser("grant")
    p_grant.add_argument("--agent", required=True)
    p_grant.add_argument("--cap", required=True)

    p_budget = sub.add_parser("set-budget")
    p_budget.add_argument("--agent", required=True)
    p_budget.add_argument("--action", required=True)
    p_budget.add_argument("--max-count", type=int, required=True)
    p_budget.add_argument("--max-amount-cents", type=int, default=None)

    p_pol = sub.add_parser("add-policy")
    p_pol.add_argument("--id", required=True)
    p_pol.add_argument("--action", required=True)
    p_pol.add_argument("--mode", choices=["allow", "deny"], required=True)
    p_pol.add_argument("--match", nargs="*", default=[])

    p_tok = sub.add_parser("issue-token")
    p_tok.add_argument("--agent", required=True)
    p_tok.add_argument("--cap", action="append", default=[])
    p_tok.add_argument("--ttl", type=int, default=86400)

    args = ap.parse_args()

    if args.cmd == "init":
        init_db()
    elif args.cmd == "add-agent":
        add_agent(args.agent, args.name)
    elif args.cmd == "grant":
        grant_cap(args.agent, args.cap)
    elif args.cmd == "set-budget":
        set_budget(args.agent, args.action, args.max_count, args.max_amount_cents)
    elif args.cmd == "add-policy":
        add_policy(args.id, args.action, args.mode, args.match)
    elif args.cmd == "issue-token":
        issue_token(args.agent, args.cap, args.ttl)


if __name__ == "__main__":
    main()
