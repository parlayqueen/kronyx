#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
import hashlib
import hmac
import base64
from typing import Any, Dict, Optional

DB_FILE = os.environ.get("KRONYX_DB", "kronyx.db")
SECRET = os.environ.get("KRONYX_HMAC_SECRET", "CHANGE_ME__set_KRONYX_HMAC_SECRET")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def hmac_sign(secret: str, msg: bytes) -> str:
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return b64url(sig)


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def _json_load_maybe(s: Optional[str]) -> Any:
    if s is None:
        return None
    s = str(s)
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        # If it isn't valid JSON, treat as raw string
        return s


def recompute_entry_hash(row: sqlite3.Row) -> str:
    # Must match kronyx_runtime.py ledger hashing logic
    policy_obj = _json_load_maybe(row["policy_snapshot"]) or {}
    budget_obj = _json_load_maybe(row["budget_snapshot"])  # can be None
    response_excerpt = row["response_excerpt"]
    if response_excerpt is None:
        response_excerpt = ""  # runtime hashed "" when None

    entry = {
        "ts": row["ts"],
        "agent_id": row["agent_id"],
        "action": row["action"],
        "outcome": row["outcome"],
        "reason": row["reason"] or "",
        "request_excerpt": row["request_excerpt"] or "",
        "response_excerpt": response_excerpt,
        "cap_token_hash": row["cap_token_hash"] or "",
        "policy_snapshot": policy_obj,
        "budget_snapshot": budget_obj,
        "idem_key": row["idem_key"] or "",
        "prev_hash": row["prev_hash"] or "",
    }
    return hashlib.sha256(canonical_json(entry)).hexdigest()


def audit_ledger(limit: Optional[int] = None) -> Dict[str, Any]:
    conn = connect_db()
    try:
        q = "SELECT * FROM ledger ORDER BY ledger_id ASC"
        if limit is not None:
            q = "SELECT * FROM ledger ORDER BY ledger_id ASC LIMIT ?"
            rows = conn.execute(q, (int(limit),)).fetchall()
        else:
            rows = conn.execute(q).fetchall()

        if not rows:
            return {"ok": True, "checked": 0, "message": "ledger empty"}

        checked = 0
        prev_entry_hash = None

        for r in rows:
            checked += 1

            # Check prev_hash links
            prev_hash = r["prev_hash"]
            if prev_entry_hash is None:
                if prev_hash not in (None, "", "null"):
                    return {
                        "ok": False,
                        "checked": checked,
                        "error": "bad_prev_hash_on_first_entry",
                        "ledger_id": r["ledger_id"],
                        "prev_hash": prev_hash,
                    }
            else:
                if (prev_hash or "") != (prev_entry_hash or ""):
                    return {
                        "ok": False,
                        "checked": checked,
                        "error": "prev_hash_mismatch",
                        "ledger_id": r["ledger_id"],
                        "expected_prev_hash": prev_entry_hash,
                        "found_prev_hash": prev_hash,
                    }

            # Recompute entry_hash
            expected = recompute_entry_hash(r)
            found = r["entry_hash"]
            if expected != found:
                return {
                    "ok": False,
                    "checked": checked,
                    "error": "entry_hash_mismatch",
                    "ledger_id": r["ledger_id"],
                    "expected_entry_hash": expected,
                    "found_entry_hash": found,
                }

            prev_entry_hash = found

        return {"ok": True, "checked": checked, "message": "ledger chain validates"}
    finally:
        conn.close()


def verify_receipt(receipt: Dict[str, Any]) -> bool:
    if SECRET == "CHANGE_ME__set_KRONYX_HMAC_SECRET":
        # still works, but user probably forgot to export it
        return False
    r = dict(receipt)
    sig = r.pop("sig", None)
    if not sig:
        return False
    expected = hmac_sign(SECRET, canonical_json(r))
    return hmac.compare_digest(expected, sig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit-ledger", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--verify-receipt", default=None, help="Receipt JSON string or @file.json")
    args = ap.parse_args()

    out: Dict[str, Any] = {}

    if args.audit_ledger:
        out["ledger_audit"] = audit_ledger(args.limit)

    if args.verify_receipt:
        src = args.verify_receipt
        if src.startswith("@"):
            with open(src[1:], "r", encoding="utf-8") as f:
                receipt = json.load(f)
        else:
            receipt = json.loads(src)
        out["receipt_ok"] = verify_receipt(receipt)

    if not out:
        ap.print_help()
        return

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
