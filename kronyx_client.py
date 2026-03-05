#!/usr/bin/env python3
import json
import urllib.request

class KronyxClient:
    def __init__(self, base_url: str, agent_id: str, token: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.token = token
        self.timeout = timeout

    def execute(self, action: str, capability: str, idem_key: str = "", payload: dict | None = None) -> dict:
        body = {
            "agent_id": self.agent_id,
            "token": self.token,
            "action": action,
            "capability": capability,
            "idem_key": idem_key or "",
            "payload": payload or {},
        }
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url=self.base_url + "/execute",
            data=data,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                out = json.loads(resp.read().decode("utf-8"))
                return out
        except Exception as e:
            return {"ok": False, "error": "client_error", "message": str(e)}
