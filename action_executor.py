#!/usr/bin/env python3
import ast
import json
import math
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


class ExecutionError(Exception):
    pass


class SafeMathEvaluator(ast.NodeVisitor):
    ALLOWED_BINOPS = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
        ast.Pow: lambda a, b: a ** b,
    }

    ALLOWED_UNARYOPS = {
        ast.UAdd: lambda a: +a,
        ast.USub: lambda a: -a,
    }

    ALLOWED_FUNCS = {
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
        "sum": sum,
        "sqrt": math.sqrt,
        "ceil": math.ceil,
        "floor": math.floor,
        "sin": math.sin,
        "cos": math.cos,
        "tan": math.tan,
        "log": math.log,
        "log10": math.log10,
        "exp": math.exp,
    }

    ALLOWED_CONSTS = {
        "pi": math.pi,
        "e": math.e,
        "tau": math.tau,
    }

    def visit(self, node: ast.AST) -> Any:
        return super().visit(node)

    def generic_visit(self, node: ast.AST) -> Any:
        raise ExecutionError(f"Unsupported math syntax: {type(node).__name__}")

    def visit_Expression(self, node: ast.Expression) -> Any:
        return self.visit(node.body)

    def visit_Constant(self, node: ast.Constant) -> Any:
        if isinstance(node.value, (int, float)):
            return node.value
        raise ExecutionError("Only numeric constants are allowed")

    def visit_Num(self, node: ast.Num) -> Any:
        return node.n

    def visit_Name(self, node: ast.Name) -> Any:
        if node.id in self.ALLOWED_CONSTS:
            return self.ALLOWED_CONSTS[node.id]
        raise ExecutionError(f"Unknown identifier: {node.id}")

    def visit_UnaryOp(self, node: ast.UnaryOp) -> Any:
        op_type = type(node.op)
        if op_type not in self.ALLOWED_UNARYOPS:
            raise ExecutionError(f"Unsupported unary operator: {op_type.__name__}")
        value = self.visit(node.operand)
        return self.ALLOWED_UNARYOPS[op_type](value)

    def visit_BinOp(self, node: ast.BinOp) -> Any:
        op_type = type(node.op)
        if op_type not in self.ALLOWED_BINOPS:
            raise ExecutionError(f"Unsupported binary operator: {op_type.__name__}")
        left = self.visit(node.left)
        right = self.visit(node.right)
        return self.ALLOWED_BINOPS[op_type](left, right)

    def visit_Call(self, node: ast.Call) -> Any:
        if not isinstance(node.func, ast.Name):
            raise ExecutionError("Only simple function calls are allowed")
        func_name = node.func.id
        if func_name not in self.ALLOWED_FUNCS:
            raise ExecutionError(f"Function not allowed: {func_name}")
        func = self.ALLOWED_FUNCS[func_name]
        args = [self.visit(arg) for arg in node.args]
        return func(*args)

    def visit_List(self, node: ast.List) -> Any:
        return [self.visit(elt) for elt in node.elts]

    def visit_Tuple(self, node: ast.Tuple) -> Any:
        return tuple(self.visit(elt) for elt in node.elts)


class ActionExecutor:
    def __init__(self, policy: Dict[str, Any]) -> None:
        self.policy = policy

    def reload_policy(self, policy: Dict[str, Any]) -> None:
        self.policy = policy

    def execute(self, req: Dict[str, Any]) -> Dict[str, Any]:
        action = str(req.get("action", "")).strip()
        if action == "http.fetch":
            return self._http_fetch(req)
        if action == "file.read":
            return self._file_read(req)
        if action == "math.compute":
            return self._math_compute(req)
        raise ExecutionError(f"Unsupported action: {action}")

    def _get_agent_policy(self, agent_id: str) -> Dict[str, Any]:
        agents = self.policy.get("agents", {})
        agent = agents.get(agent_id)
        if not isinstance(agent, dict):
            raise ExecutionError(f"Unknown agent_id: {agent_id}")
        return agent

    def _http_fetch(self, req: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = str(req.get("agent_id", "")).strip()
        resource = str(req.get("resource", "")).strip()
        metadata = req.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        if not resource:
            raise ExecutionError("Missing resource URL")

        parsed = urlparse(resource)
        if parsed.scheme not in ("http", "https"):
            raise ExecutionError("Only http and https URLs are allowed")

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise ExecutionError("Invalid URL hostname")

        agent = self._get_agent_policy(agent_id)
        http_policy = agent.get("http_policy", {})
        if not isinstance(http_policy, dict):
            http_policy = {}

        allowed_domains = http_policy.get("allowed_domains", [])
        blocked_domains = http_policy.get("blocked_domains", [])
        max_response_bytes = safe_int(http_policy.get("max_response_bytes", 250000), 250000)
        timeout_seconds = safe_int(http_policy.get("timeout_seconds", 15), 15)
        allowed_methods = http_policy.get("allowed_methods", ["GET"])

        if not isinstance(allowed_domains, list):
            allowed_domains = []
        if not isinstance(blocked_domains, list):
            blocked_domains = []
        if not isinstance(allowed_methods, list):
            allowed_methods = ["GET"]

        method = str(metadata.get("method", "GET")).upper().strip()
        if method not in allowed_methods:
            raise ExecutionError(f"HTTP method not allowed: {method}")

        if blocked_domains:
            for blocked in blocked_domains:
                blocked = str(blocked).lower().strip()
                if blocked and (hostname == blocked or hostname.endswith("." + blocked)):
                    raise ExecutionError(f"Domain blocked: {hostname}")

        if allowed_domains:
            matched = False
            for allowed in allowed_domains:
                allowed = str(allowed).lower().strip()
                if allowed and (hostname == allowed or hostname.endswith("." + allowed)):
                    matched = True
                    break
            if not matched:
                raise ExecutionError(f"Domain not allowed: {hostname}")

        request = urllib.request.Request(
            resource,
            method=method,
            headers={
                "User-Agent": "KronyxRuntime/0.3",
                "Accept": "*/*",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                status_code = safe_int(getattr(response, "status", 200), 200)
                content_type = str(response.headers.get("Content-Type", "application/octet-stream"))
                raw = response.read(max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raise ExecutionError(f"HTTP error: {exc.code} {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise ExecutionError(f"Network error: {exc.reason}") from exc

        truncated = len(raw) > max_response_bytes
        if truncated:
            raw = raw[:max_response_bytes]

        text_preview: Optional[str] = None
        if "text" in content_type or "json" in content_type or "xml" in content_type:
            try:
                text_preview = raw.decode("utf-8", errors="replace")
            except Exception:
                text_preview = None

        return {
            "action": "http.fetch",
            "ok": True,
            "status_code": status_code,
            "content_type": content_type,
            "bytes_received": len(raw),
            "truncated": truncated,
            "url": resource,
            "hostname": hostname,
            "text_preview": text_preview,
        }

    def _file_read(self, req: Dict[str, Any]) -> Dict[str, Any]:
        agent_id = str(req.get("agent_id", "")).strip()
        resource = str(req.get("resource", "")).strip()
        if not resource:
            raise ExecutionError("Missing file resource path")

        agent = self._get_agent_policy(agent_id)
        file_policy = agent.get("file_policy", {})
        if not isinstance(file_policy, dict):
            file_policy = {}

        allowed_roots = file_policy.get("allowed_roots", [])
        max_bytes = safe_int(file_policy.get("max_bytes", 200000), 200000)

        if not isinstance(allowed_roots, list) or not allowed_roots:
            raise ExecutionError("No allowed file roots configured for this agent")

        target = Path(resource).expanduser().resolve()

        root_matches = []
        for root in allowed_roots:
            root_path = Path(str(root)).expanduser().resolve()
            try:
                target.relative_to(root_path)
                root_matches.append(str(root_path))
            except Exception:
                continue

        if not root_matches:
            raise ExecutionError(f"Path not allowed: {target}")

        if not target.exists():
            raise ExecutionError(f"File not found: {target}")
        if not target.is_file():
            raise ExecutionError(f"Not a file: {target}")

        raw = target.read_bytes()
        truncated = len(raw) > max_bytes
        if truncated:
            raw = raw[:max_bytes]

        try:
            text_preview = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ExecutionError(f"Failed reading text file: {exc}") from exc

        return {
            "action": "file.read",
            "ok": True,
            "path": str(target),
            "allowed_root": root_matches[0],
            "bytes_returned": len(raw),
            "truncated": truncated,
            "text_preview": text_preview,
        }

    def _math_compute(self, req: Dict[str, Any]) -> Dict[str, Any]:
        metadata = req.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        expression = str(metadata.get("expression", "")).strip()
        if not expression:
            raise ExecutionError("Missing metadata.expression for math.compute")

        if len(expression) > 500:
            raise ExecutionError("Expression too long")

        try:
            parsed = ast.parse(expression, mode="eval")
            evaluator = SafeMathEvaluator()
            result = evaluator.visit(parsed)
        except ZeroDivisionError:
            raise ExecutionError("Division by zero")
        except ExecutionError:
            raise
        except Exception as exc:
            raise ExecutionError(f"Invalid math expression: {exc}") from exc

        if isinstance(result, (int, float)):
            normalized: Any = float(result) if isinstance(result, float) else result
        else:
            normalized = result

        return {
            "action": "math.compute",
            "ok": True,
            "expression": expression,
            "result": normalized,
        }
