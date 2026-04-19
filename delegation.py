#!/usr/bin/env python3
import os
import json
import time
import uuid
import base64
import hmac
import hashlib
from typing import Any, Dict, Optional


def now_ts() -> int:
    return int(time.time())


def stable_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


class DelegationError(Exception):
    pass


class DelegationManager:
    def __init__(self, signing_key: Optional[str] = None) -> None:
        self.signing_key = signing_key or os.environ.get(
            "KRONYX_DELEGATION_KEY",
            os.environ.get("KRONYX_SIGNING_KEY", "replace-with-long-random-key"),
        )

    def _sign(self, payload_json: str) -> str:
        return hmac.new(
            self.signing_key.encode("utf-8"),
            payload_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def mint_token(self, payload: Dict[str, Any]) -> str:
        body_json = stable_json(payload)
        sig = self._sign(body_json)
        body_b64 = b64url_encode(body_json.encode("utf-8"))
        sig_b64 = b64url_encode(sig.encode("utf-8"))
        return f"krxdt.{body_b64}.{sig_b64}"

    def verify_token(self, token: str) -> Dict[str, Any]:
        if not token or not token.startswith("krxdt."):
            raise DelegationError("Not a delegation token")

        parts = token.split(".")
        if len(parts) != 3:
            raise DelegationError("Malformed delegation token")

        _, body_b64, sig_b64 = parts

        try:
            body_json = b64url_decode(body_b64).decode("utf-8")
            sig = b64url_decode(sig_b64).decode("utf-8")
        except Exception as exc:
            raise DelegationError(f"Invalid token encoding: {exc}") from exc

        expected = self._sign(body_json)
        if not hmac.compare_digest(sig, expected):
            raise DelegationError("Delegation token signature mismatch")

        try:
            payload = json.loads(body_json)
        except Exception as exc:
            raise DelegationError(f"Invalid token payload: {exc}") from exc

        if not isinstance(payload, dict):
            raise DelegationError("Delegation payload must be a JSON object")

        exp = int(payload.get("exp", 0))
        if exp <= 0:
            raise DelegationError("Delegation token missing expiration")
        if now_ts() >= exp:
            raise DelegationError("Delegation token expired")

        jti = str(payload.get("jti", "")).strip()
        if not jti:
            raise DelegationError("Delegation token missing jti")

        return payload

    def build_payload(
        self,
        delegator_agent_id: str,
        delegatee_agent_id: str,
        allowed_capabilities: list[str],
        expires_at_epoch: int,
        http_policy: Optional[Dict[str, Any]] = None,
        file_policy: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "iss": "Kronyx",
            "typ": "delegation",
            "jti": f"krxjti_{uuid.uuid4().hex}",
            "delegator_agent_id": delegator_agent_id,
            "delegatee_agent_id": delegatee_agent_id,
            "capabilities": allowed_capabilities,
            "exp": int(expires_at_epoch),
            "iat": now_ts(),
        }

        if http_policy is not None:
            payload["http_policy"] = http_policy
        if file_policy is not None:
            payload["file_policy"] = file_policy
        if metadata is not None:
            payload["metadata"] = metadata

        return payload
