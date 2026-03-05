import argparse
import os
import sqlite3
import time
from typing import Optional

from runtime_v2 import DB_PATH, init_db, sign_token


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def cmd_init(_: argparse.Namespace) -> None:
    init_db()
    print("[ok] db initialized:", DB_PATH)


def cmd_add_agent(args: argparse.Namespace) -> None:
    init_db()
    with db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO agents(agent, created_ts) VALUES (?,?)",
            (args.agent, int(time.time())),
        )
    print(f"[ok] added agent {args.agent}")


def cmd_grant(args: argparse.Namespace) -> None:
    init_db()
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO grants(agent, action) VALUES (?,?)",
            (args.agent, args.action),
        )
    print(f"[ok] granted {args.action} to {args.agent}")


def cmd_allow_host(args: argparse.Namespace) -> None:
    init_db()
    with db() as conn:
        conn.execute("INSERT OR REPLACE INTO allow_hosts(host) VALUES (?)", (args.host,))
    print(f"[ok] allowlisted host {args.host}")


def cmd_set_budget(args: argparse.Namespace) -> None:
    init_db()
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO budgets(agent, action, max_count, max_amount_cents) VALUES (?,?,?,?)",
            (args.agent, args.action, args.max_count, args.max_amount_cents),
        )
    print(f"[ok] set budget for {args.agent} action={args.action} max_count={args.max_count} max_amount_cents={args.max_amount_cents}")


def cmd_issue_token(args: argparse.Namespace) -> None:
    init_db()
    exp = int(time.time()) + int(args.ttl)
    payload = {"agent": args.agent, "caps": args.cap, "exp": exp}
    tok = sign_token(payload)
    print(tok)


def main() -> None:
    p = argparse.ArgumentParser(prog="tools_admin_v2.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("add-agent")
    s.add_argument("--agent", required=True)
    s.set_defaults(fn=cmd_add_agent)

    s = sub.add_parser("grant")
    s.add_argument("--agent", required=True)
    s.add_argument("--action", required=True)
    s.set_defaults(fn=cmd_grant)

    s = sub.add_parser("allow-host")
    s.add_argument("--host", required=True)
    s.set_defaults(fn=cmd_allow_host)

    s = sub.add_parser("set-budget")
    s.add_argument("--agent", required=True)
    s.add_argument("--action", required=True)
    s.add_argument("--max-count", type=int, default=None)
    s.add_argument("--max-amount-cents", type=int, default=None)
    s.set_defaults(fn=cmd_set_budget)

    s = sub.add_parser("issue-token")
    s.add_argument("--agent", required=True)
    s.add_argument("--cap", action="append", default=[], required=True)
    s.add_argument("--ttl", type=int, default=3600)
    s.set_defaults(fn=cmd_issue_token)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
