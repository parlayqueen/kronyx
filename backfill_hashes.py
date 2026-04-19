#!/usr/bin/env python3
import os, json, sqlite3, hashlib

DB = os.environ.get("KRONYX_DB", "kronyx.db")

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT ledger_id, request_excerpt, response_excerpt, request_hash, response_hash "
            "FROM ledger ORDER BY ledger_id ASC"
        ).fetchall()

        updated = 0
        skipped = 0

        for r in rows:
            lid = r["ledger_id"]
            req_h = r["request_hash"]
            resp_h = r["response_hash"]

            need_req = (req_h is None) or (req_h == "")
            need_resp = (resp_h is None) or (resp_h == "")

            if not (need_req or need_resp):
                continue

            try:
                req_obj = json.loads(r["request_excerpt"]) if r["request_excerpt"] else None
                resp_obj = None
                if r["response_excerpt"]:
                    resp_obj = json.loads(r["response_excerpt"])
            except Exception:
                skipped += 1
                continue

            new_req = req_h
            new_resp = resp_h

            if need_req and req_obj is not None:
                new_req = sha256_hex(canonical_json(req_obj))

            if need_resp:
                # If response excerpt is missing, hash empty object
                if resp_obj is None:
                    new_resp = sha256_hex(canonical_json({}))
                else:
                    new_resp = sha256_hex(canonical_json(resp_obj))

            conn.execute(
                "UPDATE ledger SET request_hash=?, response_hash=? WHERE ledger_id=?",
                (new_req, new_resp, lid),
            )
            updated += 1

        conn.commit()
        print(json.dumps({"ok": True, "updated_rows": updated, "skipped_rows": skipped}, indent=2))
    finally:
        conn.close()

if __name__ == "__main__":
    main()
