#!/usr/bin/env python3
import os
from kronyx_client import KronyxClient

BASE = os.environ.get("KRONYX_URL", "http://127.0.0.1:8788")
AGENT = os.environ.get("KRONYX_AGENT", "agent_42")
TOKEN = os.environ.get("KRONYX_TOKEN", "")

def main():
    if not TOKEN:
        print("Set KRONYX_TOKEN first.")
        print('Example: export KRONYX_TOKEN="$(python tools_admin.py issue-token --agent agent_42 --cap noop --ttl 3600)"')
        return

    c = KronyxClient(BASE, AGENT, TOKEN)

    print("\n[1] NOOP governed")
    print(c.execute("noop", "noop", idem_key="demo-noop-1", payload={"hello": "world"}))

    print("\n[2] Idempotency replay (same idem_key)")
    print(c.execute("noop", "noop", idem_key="demo-noop-1", payload={"hello": "world"}))

    print("\n[3] Governed HTTP GET (allowlist host)")
    print(c.execute(
        "http_request",
        "http_request",
        idem_key="demo-http-1",
        payload={"method": "GET", "url": "https://httpbin.org/get"}
    ))

    print("\n[4] Simulated payment (NOT real money)")
    print(c.execute(
        "simulate_payment",
        "simulate_payment",
        idem_key="pay-1",
        payload={"amount_cents": 2500, "recipient": "acct_demo"}
    ))

    print("\n[5] Replay simulated payment (same idem_key)")
    print(c.execute(
        "simulate_payment",
        "simulate_payment",
        idem_key="pay-1",
        payload={"amount_cents": 2500, "recipient": "acct_demo"}
    ))

if __name__ == "__main__":
    main()
