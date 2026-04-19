#!/usr/bin/env python3
import os
import json
import time
import uuid
import hmac
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from action_executor import ActionExecutor, ExecutionError
from delegation import DelegationManager, DelegationError
from kronyx_store import KronyxStore

APP_TITLE = "Kronyx Runtime Kernel"
APP_VERSION = "0.6.0-stdlib-sqlite-revoke-hardened"

DATA_DIR = Path(os.environ.get("KRONYX_DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

POLICY_FILE = Path(os.environ.get("KRONYX_POLICY_FILE", DATA_DIR / "policy.json"))
RECEIPT_FILE = Path(os.environ.get("KRONYX_RECEIPT_FILE", DATA_DIR / "receipts.jsonl"))

KRONYX_MASTER_TOKEN = os.environ.get("KRONYX_MASTER_TOKEN", "change-me-now")
KRONYX_SIGNING_KEY = os.environ.get("KRONYX_SIGNING_KEY", "replace-with-long-random-key")
KRONYX_DELEGATION_KEY = os.environ.get("KRONYX_DELEGATION_KEY", KRONYX_SIGNING_KEY)
KRONYX_DB_PATH = os.environ.get("KRONYX_DB_PATH", str(DATA_DIR / "kronyx.db"))
HOST = os.environ.get("KRONYX_HOST", "0.0.0.0")
PORT = int(os.environ.get("KRONYX_PORT", "8787"))

DEFAULT_POLICY = {
    "agents": {
        "agent_42": {
            "token": "agent-secret-42",
            "capabilities": [
                "http.fetch",
                "file.read",
                "math.compute",
                "delegate.issue",
                "delegate.revoke"
            ],
            "delegation_policy": {
                "max_ttl_seconds": 3600,
                "allowed_delegate_capabilities": [
                    "http.fetch",
                    "file.read",
                    "math.compute"
                ]
            },
            "limits": {
                "max_requests_per_hour": 100,
                "max_spend_usd_per_day": 1.0,
                "max_file_reads_per_hour": 50,
                "max_http_requests_per_hour": 25
            },
            "http_policy": {
                "allowed_domains": [
                    "example.com",
                    "httpbin.org"
                ],
                "blocked_domains": [],
                "allowed_methods": [
                    "GET"
                ],
                "timeout_seconds": 15,
                "max_response_bytes": 250000
            },
            "file_policy": {
                "allowed_roots": [
                    "~/kronyx_mvp",
                    "~/storage/shared/Download"
                ],
                "max_bytes": 200000
            }
        },
        "agent_readonly": {
            "token": "readonly-007",
            "capabilities": [
                "file.read"
            ],
            "limits": {
                "max_requests_per_hour": 20,
                "max_spend_usd_per_day": 0.0,
                "max_file_reads_per_hour": 20,
                "max_http_requests_per_hour": 0
            },
            "file_policy": {
                "allowed_roots": [
                    "~/kronyx_mvp"
                ],
                "max_bytes": 120000
            }
        }
    }
}


def now_ts() -> int:
    return int(time.time())


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def stable_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def ensure_policy_file() -> None:
    if not POLICY_FILE.exists():
        POLICY_FILE.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")


def load_policy() -> Dict[str, Any]:
    ensure_policy_file()
    return json.loads(POLICY_FILE.read_text(encoding="utf-8"))


def sign_receipt(receipt: Dict[str, Any]) -> str:
    payload = stable_json(receipt).encode("utf-8")
    return hmac.new(
        KRONYX_SIGNING_KEY.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def append_receipt_jsonl(receipt: Dict[str, Any]) -> None:
    with RECEIPT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(receipt, sort_keys=True, ensure_ascii=False) + "\n")


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def deep_copy_dict(value: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(value, ensure_ascii=False))


class PolicyEngine:
    def __init__(self, store: KronyxStore) -> None:
        self.policy = load_policy()
        self.store = store

    def reload(self) -> None:
        self.policy = load_policy()

    def get_policy(self) -> Dict[str, Any]:
        return self.policy

    def get_agent(self, agent_id: str) -> Dict[str, Any]:
        agents = self.policy.get("agents", {})
        agent = agents.get(agent_id)
        if not isinstance(agent, dict):
            raise ValueError(f"Unknown agent_id: {agent_id}")
        return agent

    def verify_static_token(self, agent_id: str, presented_token: Optional[str]) -> None:
        agent = self.get_agent(agent_id)
        expected = str(agent.get("token", ""))
        if not presented_token or presented_token != expected:
            raise PermissionError("Invalid agent token")

    def _build_receipt(
        self,
        receipt_id: str,
        req: Dict[str, Any],
        allowed: bool,
        reason: str,
        usage: Dict[str, Any],
        execution: Optional[Dict[str, Any]] = None,
        auth_context: Optional[Dict[str, Any]] = None,
        event_type: str = "execution",
    ) -> Dict[str, Any]:
        receipt = {
            "receipt_id": receipt_id,
            "timestamp": iso_now(),
            "timestamp_epoch": now_ts(),
            "event_type": event_type,
            "agent_id": req.get("agent_id"),
            "action": req.get("action"),
            "resource": req.get("resource"),
            "metadata": req.get("metadata", {}),
            "estimated_cost_usd": safe_float(req.get("estimated_cost_usd", 0.0), 0.0),
            "allowed": allowed,
            "reason": reason,
            "usage_snapshot": usage,
        }
        if execution is not None:
            receipt["execution"] = execution
        if auth_context is not None:
            receipt["auth_context"] = auth_context
        return receipt

    def authorize(
        self,
        req: Dict[str, Any],
        auth_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        agent_id = str(req.get("agent_id", "")).strip()
        action = str(req.get("action", "")).strip()

        if not agent_id:
            raise ValueError("Missing agent_id")
        if not action:
            raise ValueError("Missing action")

        usage = self.store.usage_for_agent(agent_id)
        receipt_id = f"krx_{uuid.uuid4().hex[:18]}"

        if auth_context and auth_context.get("auth_type") == "delegation":
            allowed = set(auth_context.get("capabilities", []))
        else:
            agent = self.get_agent(agent_id)
            allowed = set(agent.get("capabilities", []))

        if action not in allowed:
            return {
                "ok": False,
                "reason": f"Action not allowed: {action}",
                "receipt_id": receipt_id,
                "usage": usage,
                "granted_capability": None,
            }

        agent = self.get_agent(agent_id)
        limits = agent.get("limits", {})

        if usage["requests_this_hour"] >= safe_int(limits.get("max_requests_per_hour", 10**9), 10**9):
            return {
                "ok": False,
                "reason": "Hourly request budget exceeded",
                "receipt_id": receipt_id,
                "usage": usage,
                "granted_capability": action,
            }

        if action == "http.fetch":
            if usage["http_requests_this_hour"] >= safe_int(limits.get("max_http_requests_per_hour", 10**9), 10**9):
                return {
                    "ok": False,
                    "reason": "Hourly HTTP request budget exceeded",
                    "receipt_id": receipt_id,
                    "usage": usage,
                    "granted_capability": action,
                }

        if action == "file.read":
            if usage["file_reads_this_hour"] >= safe_int(limits.get("max_file_reads_per_hour", 10**9), 10**9):
                return {
                    "ok": False,
                    "reason": "Hourly file-read budget exceeded",
                    "receipt_id": receipt_id,
                    "usage": usage,
                    "granted_capability": action,
                }

        projected_spend = round(
            usage["spend_today_usd"] + safe_float(req.get("estimated_cost_usd", 0.0), 0.0),
            6
        )
        if projected_spend > safe_float(limits.get("max_spend_usd_per_day", 10**9), 10**9):
            return {
                "ok": False,
                "reason": f"Daily spend budget exceeded: projected={projected_spend}",
                "receipt_id": receipt_id,
                "usage": usage,
                "granted_capability": action,
            }

        new_usage = dict(usage)
        new_usage["requests_this_hour"] += 1
        if action == "http.fetch":
            new_usage["http_requests_this_hour"] += 1
        if action == "file.read":
            new_usage["file_reads_this_hour"] += 1
        new_usage["spend_today_usd"] = projected_spend

        return {
            "ok": True,
            "reason": "Approved",
            "receipt_id": receipt_id,
            "usage": new_usage,
            "granted_capability": action,
        }

    def finalize(
        self,
        req: Dict[str, Any],
        decision: Dict[str, Any],
        execution: Optional[Dict[str, Any]] = None,
        auth_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        allowed = bool(decision.get("ok"))
        reason = str(decision.get("reason", ""))
        receipt_id = str(decision.get("receipt_id", ""))
        usage = decision.get("usage", {})
        if not isinstance(usage, dict):
            usage = {}

        receipt = self._build_receipt(
            receipt_id=receipt_id,
            req=req,
            allowed=allowed,
            reason=reason,
            usage=usage,
            execution=execution,
            auth_context=auth_context,
            event_type="execution",
        )
        sig = sign_receipt(receipt)
        receipt["signature"] = sig

        append_receipt_jsonl(receipt)
        self.store.insert_receipt(receipt)

        return {
            "ok": allowed,
            "reason": reason,
            "receipt_id": receipt_id,
            "signature": sig,
            "usage": usage,
            "granted_capability": decision.get("granted_capability"),
            "execution": execution,
            "auth_context": auth_context,
        }


store = KronyxStore(KRONYX_DB_PATH)
engine = PolicyEngine(store)
delegation_manager = DelegationManager(KRONYX_DELEGATION_KEY)
executor = ActionExecutor(engine.get_policy())


class KronyxHandler(BaseHTTPRequestHandler):
    server_version = "KronyxHTTP/0.6"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        timestamp = iso_now()
        message = fmt % args
        print(f"[{timestamp}] {self.address_string()} {message}", flush=True)

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = safe_int(self.headers.get("Content-Length", "0"), 0)
        if content_length <= 0:
            raise ValueError("Missing request body")
        raw = self.rfile.read(content_length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _get_bearer_token(self) -> Optional[str]:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return auth.split(" ", 1)[1].strip()

    def _require_master_token(self) -> None:
        token = self._get_bearer_token()
        if token != KRONYX_MASTER_TOKEN:
            raise PermissionError("Forbidden")

    def _is_master_token(self, token: Optional[str]) -> bool:
        return bool(token) and token == KRONYX_MASTER_TOKEN

    def _build_executor_for_auth(self, auth_context: Optional[Dict[str, Any]]) -> ActionExecutor:
        if not auth_context or auth_context.get("auth_type") != "delegation":
            return executor

        base_policy = engine.get_policy()
        scoped_policy = deep_copy_dict(base_policy)
        agent_id = str(auth_context.get("delegatee_agent_id", "")).strip()
        if not agent_id:
            return executor

        token_http_policy = auth_context.get("http_policy")
        token_file_policy = auth_context.get("file_policy")

        agent_cfg = scoped_policy.get("agents", {}).get(agent_id)
        if not isinstance(agent_cfg, dict):
            return executor

        if isinstance(token_http_policy, dict):
            agent_cfg["http_policy"] = token_http_policy
        if isinstance(token_file_policy, dict):
            agent_cfg["file_policy"] = token_file_policy

        return ActionExecutor(scoped_policy)

    def _authenticate_request(self, req: Dict[str, Any], token: str) -> Dict[str, Any]:
        requested_agent_id = str(req.get("agent_id", "")).strip()
        if not requested_agent_id:
            raise ValueError("Missing agent_id")

        try:
            payload = delegation_manager.verify_token(token)
            jti = str(payload.get("jti", "")).strip()
            if store.is_token_revoked(jti):
                raise PermissionError("Delegation token revoked")

            stored = store.get_delegation(jti)
            if stored is None:
                raise PermissionError("Delegation token unknown")
            if stored.get("_status") == "revoked":
                raise PermissionError("Delegation token revoked")

            delegatee_agent_id = str(payload.get("delegatee_agent_id", "")).strip()
            if requested_agent_id != delegatee_agent_id:
                raise PermissionError("Delegation token agent mismatch")

            auth_context = {
                "auth_type": "delegation",
                "jti": jti,
                "delegator_agent_id": str(payload.get("delegator_agent_id", "")).strip(),
                "delegatee_agent_id": delegatee_agent_id,
                "capabilities": list(payload.get("capabilities", [])),
                "exp": int(payload.get("exp", 0)),
                "http_policy": payload.get("http_policy"),
                "file_policy": payload.get("file_policy"),
                "metadata": payload.get("metadata", {}),
            }
            return auth_context
        except DelegationError:
            engine.verify_static_token(requested_agent_id, token)
            return {
                "auth_type": "static",
                "agent_id": requested_agent_id,
            }

    def _write_event_receipt(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        receipt["signature"] = sign_receipt(receipt)
        append_receipt_jsonl(receipt)
        store.insert_receipt(receipt)
        return receipt

    def _authenticate_revoker(self, token: Optional[str], revoker_agent_id: str) -> Dict[str, Any]:
        if not revoker_agent_id:
            raise ValueError("Missing revoker_agent_id")

        if self._is_master_token(token):
            return {
                "auth_type": "master",
                "agent_id": "master",
                "is_master": True,
            }

        engine.verify_static_token(revoker_agent_id, token)
        revoker = engine.get_agent(revoker_agent_id)
        revoker_caps = set(revoker.get("capabilities", []))
        if "delegate.revoke" not in revoker_caps:
            raise PermissionError("Revoker lacks delegate.revoke capability")

        return {
            "auth_type": "static",
            "agent_id": revoker_agent_id,
            "is_master": False,
        }

    def _authorize_revocation(
        self,
        auth_context: Dict[str, Any],
        revoker_agent_id: str,
        delegation_payload: Dict[str, Any],
    ) -> None:
        if auth_context.get("is_master"):
            return

        delegator_agent_id = str(delegation_payload.get("delegator_agent_id", "")).strip()
        if not delegator_agent_id:
            raise PermissionError("Delegation payload missing delegator_agent_id")

        if revoker_agent_id != delegator_agent_id:
            raise PermissionError("Only the original delegator may revoke this token")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json(200, {
                "ok": True,
                "service": APP_TITLE,
                "version": APP_VERSION,
                "policy_file": str(POLICY_FILE),
                "receipt_file": str(RECEIPT_FILE),
                "db_path": KRONYX_DB_PATH,
                "host": HOST,
                "port": PORT
            })
            return

        if parsed.path == "/receipts":
            try:
                self._require_master_token()
                qs = parse_qs(parsed.query)
                limit = safe_int(qs.get("limit", ["50"])[0], 50)
                rows = store.list_receipts(limit=limit)
                self._send_json(200, {
                    "ok": True,
                    "count": len(rows),
                    "receipts": rows
                })
            except PermissionError as exc:
                self._send_json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
            return

        if parsed.path == "/delegations":
            try:
                self._require_master_token()
                qs = parse_qs(parsed.query)
                limit = safe_int(qs.get("limit", ["50"])[0], 50)
                delegatee_agent_id = qs.get("delegatee_agent_id", [None])[0]
                delegator_agent_id = qs.get("delegator_agent_id", [None])[0]
                status = qs.get("status", [None])[0]

                rows = store.list_delegations(
                    limit=limit,
                    delegatee_agent_id=delegatee_agent_id,
                    delegator_agent_id=delegator_agent_id,
                    status=status,
                )
                self._send_json(200, {
                    "ok": True,
                    "count": len(rows),
                    "delegations": rows
                })
            except PermissionError as exc:
                self._send_json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
            return

        self._send_json(404, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/reload":
            try:
                self._require_master_token()
                engine.reload()
                self._send_json(200, {"ok": True, "message": "Policy reloaded"})
            except PermissionError as exc:
                self._send_json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
            return

        if parsed.path == "/delegate":
            try:
                req = self._read_json_body()
                token = self._get_bearer_token()
                if token is None:
                    self._send_json(401, {"ok": False, "error": "Missing Bearer token"})
                    return

                delegator_agent_id = str(req.get("delegator_agent_id", "")).strip()
                delegatee_agent_id = str(req.get("delegatee_agent_id", "")).strip()
                requested_capabilities = req.get("capabilities", [])
                ttl_seconds = safe_int(req.get("ttl_seconds", 0), 0)
                http_policy = req.get("http_policy")
                file_policy = req.get("file_policy")
                metadata = req.get("metadata", {})

                if not delegator_agent_id:
                    raise ValueError("Missing delegator_agent_id")
                if not delegatee_agent_id:
                    raise ValueError("Missing delegatee_agent_id")
                if not isinstance(requested_capabilities, list) or not requested_capabilities:
                    raise ValueError("capabilities must be a non-empty list")
                if ttl_seconds <= 0:
                    raise ValueError("ttl_seconds must be > 0")
                if not isinstance(metadata, dict):
                    metadata = {}

                engine.verify_static_token(delegator_agent_id, token)
                delegator = engine.get_agent(delegator_agent_id)

                delegator_caps = set(delegator.get("capabilities", []))
                if "delegate.issue" not in delegator_caps:
                    raise PermissionError("Delegator lacks delegate.issue capability")

                delegation_policy = delegator.get("delegation_policy", {})
                if not isinstance(delegation_policy, dict):
                    delegation_policy = {}

                max_ttl_seconds = safe_int(delegation_policy.get("max_ttl_seconds", 3600), 3600)
                if ttl_seconds > max_ttl_seconds:
                    raise PermissionError(f"ttl_seconds exceeds max_ttl_seconds={max_ttl_seconds}")

                allowed_delegate_capabilities = set(delegation_policy.get("allowed_delegate_capabilities", []))
                if not allowed_delegate_capabilities:
                    allowed_delegate_capabilities = delegator_caps.copy()
                    allowed_delegate_capabilities.discard("delegate.issue")
                    allowed_delegate_capabilities.discard("delegate.revoke")

                requested_caps_set = set(str(x).strip() for x in requested_capabilities if str(x).strip())
                if not requested_caps_set:
                    raise ValueError("No valid capabilities requested")

                if not requested_caps_set.issubset(allowed_delegate_capabilities):
                    disallowed = sorted(requested_caps_set - allowed_delegate_capabilities)
                    raise PermissionError(f"Requested capabilities not delegable: {disallowed}")

                if http_policy is not None and not isinstance(http_policy, dict):
                    raise ValueError("http_policy must be an object")
                if file_policy is not None and not isinstance(file_policy, dict):
                    raise ValueError("file_policy must be an object")

                exp = now_ts() + ttl_seconds
                payload = delegation_manager.build_payload(
                    delegator_agent_id=delegator_agent_id,
                    delegatee_agent_id=delegatee_agent_id,
                    allowed_capabilities=sorted(requested_caps_set),
                    expires_at_epoch=exp,
                    http_policy=http_policy,
                    file_policy=file_policy,
                    metadata=metadata,
                )
                delegation_token = delegation_manager.mint_token(payload)
                store.insert_delegation(payload)

                receipt = {
                    "receipt_id": f"krxdel_{uuid.uuid4().hex[:18]}",
                    "timestamp": iso_now(),
                    "timestamp_epoch": now_ts(),
                    "event_type": "delegation_issued",
                    "agent_id": delegator_agent_id,
                    "action": "delegate.issue",
                    "allowed": True,
                    "reason": "Delegation issued",
                    "estimated_cost_usd": 0.0,
                    "delegator_agent_id": delegator_agent_id,
                    "delegatee_agent_id": delegatee_agent_id,
                    "delegation_jti": payload["jti"],
                    "capabilities": sorted(requested_caps_set),
                    "exp": exp,
                    "ttl_seconds": ttl_seconds,
                    "http_policy": http_policy,
                    "file_policy": file_policy,
                    "metadata": metadata,
                    "auth_context": {
                        "auth_type": "static",
                        "agent_id": delegator_agent_id,
                    }
                }
                receipt = self._write_event_receipt(receipt)

                self._send_json(200, {
                    "ok": True,
                    "delegation_token": delegation_token,
                    "delegation_payload": payload,
                    "receipt_id": receipt["receipt_id"],
                    "signature": receipt["signature"],
                })
                return

            except PermissionError as exc:
                self._send_json(403, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
                return

        if parsed.path == "/revoke":
            try:
                req = self._read_json_body()
                token = self._get_bearer_token()
                if token is None:
                    self._send_json(401, {"ok": False, "error": "Missing Bearer token"})
                    return

                revoker_agent_id = str(req.get("revoker_agent_id", "")).strip()
                jti = str(req.get("jti", "")).strip()
                reason = str(req.get("reason", "revoked")).strip() or "revoked"

                if not jti:
                    raise ValueError("Missing jti")
                if not self._is_master_token(token) and not revoker_agent_id:
                    raise ValueError("Missing revoker_agent_id")

                revocation_auth = self._authenticate_revoker(token, revoker_agent_id)
                effective_revoker_agent_id = revoker_agent_id if revoker_agent_id else "master"

                delegation_payload = store.get_delegation(jti)
                if delegation_payload is None:
                    raise ValueError("Unknown delegation jti")

                self._authorize_revocation(
                    auth_context=revocation_auth,
                    revoker_agent_id=effective_revoker_agent_id,
                    delegation_payload=delegation_payload,
                )

                already_revoked = store.is_token_revoked(jti) or delegation_payload.get("_status") == "revoked"

                if already_revoked:
                    receipt = {
                        "receipt_id": f"krxrev_{uuid.uuid4().hex[:18]}",
                        "timestamp": iso_now(),
                        "timestamp_epoch": now_ts(),
                        "event_type": "delegation_revoke_noop",
                        "agent_id": effective_revoker_agent_id,
                        "action": "delegate.revoke",
                        "allowed": True,
                        "reason": "Delegation already revoked",
                        "estimated_cost_usd": 0.0,
                        "delegation_jti": jti,
                        "revoked_by_agent_id": effective_revoker_agent_id,
                        "delegation_payload": delegation_payload,
                        "auth_context": revocation_auth
                    }
                    receipt = self._write_event_receipt(receipt)

                    self._send_json(200, {
                        "ok": True,
                        "jti": jti,
                        "status": "already_revoked",
                        "receipt_id": receipt["receipt_id"],
                        "signature": receipt["signature"],
                    })
                    return

                store.revoke_token(
                    jti=jti,
                    revoked_by_agent_id=effective_revoker_agent_id,
                    reason=reason,
                    payload=delegation_payload,
                )

                receipt = {
                    "receipt_id": f"krxrev_{uuid.uuid4().hex[:18]}",
                    "timestamp": iso_now(),
                    "timestamp_epoch": now_ts(),
                    "event_type": "delegation_revoked",
                    "agent_id": effective_revoker_agent_id,
                    "action": "delegate.revoke",
                    "allowed": True,
                    "reason": reason,
                    "estimated_cost_usd": 0.0,
                    "delegation_jti": jti,
                    "revoked_by_agent_id": effective_revoker_agent_id,
                    "delegation_payload": delegation_payload,
                    "auth_context": revocation_auth
                }
                receipt = self._write_event_receipt(receipt)

                self._send_json(200, {
                    "ok": True,
                    "jti": jti,
                    "status": "revoked",
                    "receipt_id": receipt["receipt_id"],
                    "signature": receipt["signature"],
                })
                return

            except PermissionError as exc:
                self._send_json(403, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
                return

        if parsed.path == "/execute":
            try:
                req = self._read_json_body()
                token = self._get_bearer_token()
                if token is None:
                    self._send_json(401, {"ok": False, "error": "Missing Bearer token"})
                    return

                auth_context = self._authenticate_request(req, token)

                decision = engine.authorize(req, auth_context=auth_context)
                if not decision.get("ok"):
                    finalized = engine.finalize(req, decision, execution=None, auth_context=auth_context)
                    self._send_json(403, finalized)
                    return

                scoped_executor = self._build_executor_for_auth(auth_context)

                try:
                    execution = scoped_executor.execute(req)
                    final_decision = engine.finalize(req, decision, execution=execution, auth_context=auth_context)
                    self._send_json(200, final_decision)
                    return
                except ExecutionError as exc:
                    denied = dict(decision)
                    denied["ok"] = False
                    denied["reason"] = f"Execution failed: {exc}"
                    final_decision = engine.finalize(req, denied, execution=None, auth_context=auth_context)
                    self._send_json(400, final_decision)
                    return

            except PermissionError as exc:
                self._send_json(403, {"ok": False, "error": str(exc)})
                return
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
                return

        self._send_json(404, {"ok": False, "error": "Not found"})


def main() -> None:
    ensure_policy_file()
    server = ThreadingHTTPServer((HOST, PORT), KronyxHandler)
    print(f"{APP_TITLE} listening on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Kronyx Runtime Kernel...", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
