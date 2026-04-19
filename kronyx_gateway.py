#!/usr/bin/env python3
"""
kronyx_gateway.py — governed egress gateway for Kronyx.

This gateway is the boundary enforcer:
clients talk to the gateway; gateway asks Kronyx for authorization + execution;
gateway returns the result plus receipts.

Features:
- GET/POST/PUT/PATCH/DELETE forwarding
- Accepts URL as:
    - /proxy?url=https://example.com/path
    - /https://example.com/path   (convenience)
- Deterministic idem_key derived from request hash
- Pure stdlib; works in Termux
"""

import base64
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, Optional, Tuple


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8788

KRONYX_URL = os.environ.get("KRONYX_URL", "http://127.0.0.1:8787").rstrip("/")
KRONYX_AGENT = os.environ.get("KRONYX_AGENT", "agent_42")
KRONYX_TOKEN = os.environ.get("KRONYX_TOKEN", "")  # MUST be set
KRONYX_CAP = os.environ.get("KRONYX_HTTP_CAP", "http_request")

MAX_BODY_BYTES = int(os.environ.get("KRONYX_GW_MAX_BODY", "1048576"))  # 1 MiB
TIMEOUT_SECS = int(os.environ.get("KRONYX_GW_TIMEOUT", "20"))

# Limit which inbound headers we forward into the governed request
FORWARD_HEADER_ALLOWLIST = {
    "accept",
    "accept-encoding",
    "content-type",
    "user-agent",
    "authorization",  # optional: if you want downstream auth forwarded
}


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    cl = handler.headers.get("content-length")
    if not cl:
        return b""
    try:
        n = int(cl)
    except ValueError:
        return b""
    if n <= 0:
        return b""
    if n > MAX_BODY_BYTES:
        raise ValueError(f"body too large: {n} > {MAX_BODY_BYTES}")
    return handler.rfile.read(n)


def _extract_target_url(handler: BaseHTTPRequestHandler) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (url, err). url must be absolute http(s).
    Accept:
      /proxy?url=...
      /https://example.com/...
      /http://example.com/...
    """
    parsed = urllib.parse.urlparse(handler.path)
    path = parsed.path or ""
    qs = urllib.parse.parse_qs(parsed.query or "")

    # 1) /proxy?url=...
    if path == "/proxy":
        u = (qs.get("url") or [None])[0]
        if not u:
            return None, "missing url query parameter"
        u = u.strip()
        if not (u.startswith("http://") or u.startswith("https://")):
            return None, "url must start with http:// or https://"
        return u, None

    # 2) /https://example.com/...
    if path.startswith("/http://") or path.startswith("/https://"):
        u = path.lstrip("/")
        # preserve query string if present (because url is in path)
        if parsed.query:
            u = u + "?" + parsed.query
        return u, None

    return None, "use /proxy?url=https://... or /https://..."


def _select_forward_headers(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in handler.headers.items():
        lk = k.lower()
        if lk in FORWARD_HEADER_ALLOWLIST:
            out[k] = v
    return out


def kronyx_execute(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Call Kronyx /execute with Bearer token.
    """
    if not KRONYX_TOKEN:
        return {"ok": False, "error": "KRONYX_TOKEN is not set in environment"}

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        KRONYX_URL + "/execute",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {KRONYX_TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECS) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        return {"ok": False, "error": f"failed to call kronyx /execute: {e}"}


class KronyxGateway(BaseHTTPRequestHandler):
    server_version = "KronyxGateway/1.0"

    def log_message(self, fmt: str, *args) -> None:
        # quieter logs (still useful)
        sys.stderr.write("[%s] %s\n" % (_now_iso(), (fmt % args)))

    def _send_json(self, code: int, obj: Dict[str, Any]) -> None:
        b = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _handle(self) -> None:
        target_url, err = _extract_target_url(self)
        if err:
            return self._send_json(400, {"ok": False, "error": err})

        method = self.command.upper()
        try:
            body = _read_body(self)
        except ValueError as e:
            return self._send_json(413, {"ok": False, "error": str(e)})

        fwd_headers = _select_forward_headers(self)

        # deterministic idempotency key from canonical request components
        idem_material = _json_bytes(
            {
                "method": method,
                "url": target_url,
                "headers": {k.lower(): v for k, v in sorted(fwd_headers.items(), key=lambda kv: kv[0].lower())},
                "body_b64": _b64(body) if body else "",
            }
        )
        idem_key = "gw-" + _sha256_hex(idem_material)[:24]

        # This is the governed action. Kronyx runtime enforces allowlist, caps, policy, budgets.
        exec_payload = {
            "agent_id": KRONYX_AGENT,
            "action": "http_request",
            "capability": KRONYX_CAP,
            "idem_key": idem_key,
            "payload": {
                "method": method,
                "url": target_url,
                "headers": fwd_headers,
                # send body as base64 so JSON-safe
                "body_b64": _b64(body) if body else "",
            },
        }

        out = kronyx_execute(exec_payload)

        # Normalize response from runtime into gateway response (always JSON)
        if not out.get("ok"):
            return self._send_json(502, {"ok": False, "error": out.get("error", "unknown kronyx error"), "kronyx": out})

        # If Kronyx denies: typically ok=False, but if your runtime uses ok=True with a denial status,
        # we handle both patterns.
        result = out.get("result", {})
        receipts = out.get("receipts", {})

        denied = False
        if isinstance(result, dict):
            # convention: some runtimes return {"ok": false, "error": "..."} inside result
            if result.get("ok") is False:
                denied = True

        if denied:
            return self._send_json(
                403,
                {
                    "ok": False,
                    "blocked": True,
                    "kronyx_result": result,
                    "receipts": receipts,
                    "idem_key": idem_key,
                },
            )

        return self._send_json(
            200,
            {
                "ok": True,
                "blocked": False,
                "idem_key": idem_key,
                "kronyx_result": result,
                "receipts": receipts,
            },
        )

    # Wire up methods
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_DELETE(self): self._handle()


def main():
    host = os.environ.get("KRONYX_GW_HOST", DEFAULT_HOST)
    port = int(os.environ.get("KRONYX_GW_PORT", str(DEFAULT_PORT)))

    if not KRONYX_TOKEN:
        sys.stderr.write("ERROR: KRONYX_TOKEN is not set. Export it before starting the gateway.\n")
        sys.exit(2)

    httpd = HTTPServer((host, port), KronyxGateway)
    print(f"[GATEWAY] listening on http://{host}:{port}")
    print(f"[GATEWAY] kronyx={KRONYX_URL} agent={KRONYX_AGENT} cap={KRONYX_CAP}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
