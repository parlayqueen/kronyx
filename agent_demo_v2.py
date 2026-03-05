import os
import time
import uuid

from kronyx_v2.runtime_v2 import KronyxRuntimeV2

def idem() -> str:
    return "idem_" + uuid.uuid4().hex[:12]

def main():
    tok = os.environ.get("KRONYX_TOKEN")
    if not tok:
        raise SystemExit("KRONYX_TOKEN is not set")

    rt = KronyxRuntimeV2()

    print("\n[1] NOOP governed")
    r1 = rt.handle(tok, "noop", {"idem_key": idem(), "echo": {"hello": "world"}})
    print(r1)

    print("\n[2] Idempotency replay (same idem_key)")
    same = idem()
    r2a = rt.handle(tok, "noop", {"idem_key": same, "echo": {"hello": "world"}})
    r2b = rt.handle(tok, "noop", {"idem_key": same, "echo": {"hello": "world"}})
    print({"first": r2a, "second": r2b})

    print("\n[3] Governed HTTP GET (allowlist host)")
    r3 = rt.handle(tok, "http_request", {"idem_key": idem(), "method": "GET", "url": "https://httpbin.org/get"})
    print(r3)

    print("\n[4] Simulated payment (NOT real money)")
    pay_idem = idem()
    r4 = rt.handle(tok, "simulate_payment", {"idem_key": pay_idem, "amount_cents": 2500, "recipient": "acct_demo"})
    print(r4)

    print("\n[5] Replay simulated payment (same idem_key)")
    r5 = rt.handle(tok, "simulate_payment", {"idem_key": pay_idem, "amount_cents": 2500, "recipient": "acct_demo"})
    print(r5)

if __name__ == "__main__":
    main()
