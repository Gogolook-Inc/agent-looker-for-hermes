"""Minimal Streamable HTTP MCP client (stdlib only) for calling Agent Looker tools from hooks.

Mirrors the Claude Code plugin's ``web-checker.mjs``: one ``initialize`` to get a session id, one
``tools/call``, then a best-effort ``DELETE`` of the session. Responses may be plain JSON or SSE.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

from . import config

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"


class AgentLookerError(Exception):
    """Transport, protocol or tool-level failure."""


class AuthError(AgentLookerError):
    """401 from the MCP endpoint: no token or a revoked one."""


def _request(url: str, method: str, headers: Dict[str, str], body: Optional[bytes],
             timeout: float) -> Tuple[int, Dict[str, str], str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https endpoint)
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, text


def _parse_message(raw: str) -> Dict[str, Any]:
    stripped = raw.strip()
    if not stripped:
        raise AgentLookerError("empty response from MCP server")
    if stripped.startswith("{"):
        return json.loads(stripped)
    for line in raw.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    raise AgentLookerError("no JSON or SSE data line in MCP response")


def call_tool(name: str, arguments: Dict[str, Any], *, url: Optional[str] = None,
              token: Optional[str] = None, timeout: Optional[float] = None) -> Dict[str, Any]:
    """Call one Agent Looker MCP tool and return its first JSON ``content`` item as a dict."""
    url = url or config.mcp_url()
    token = token or config.api_token()
    timeout = float(timeout or config.setting("timeout_seconds") or 10)
    if not token:
        raise AuthError("no Agent Looker token configured")
    client_name, client_version = config.client_info()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
    }
    init = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                   "clientInfo": {"name": client_name, "version": client_version}},
    }).encode()
    status, resp_headers, text = _request(url, "POST", headers, init, timeout)
    if status == 401:
        raise AuthError("Agent Looker rejected the token (401)")
    if status >= 400:
        raise AgentLookerError(f"initialize failed with HTTP {status}: {text[:200]}")
    session_id = resp_headers.get("mcp-session-id")
    if not session_id:
        raise AgentLookerError("MCP server returned no session id")
    call_headers = {**headers, "mcp-session-id": session_id}
    call = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}).encode()
    try:
        status, _, text = _request(url, "POST", call_headers, call, timeout)
        if status == 401:
            raise AuthError("Agent Looker rejected the token (401)")
        if status >= 400:
            raise AgentLookerError(f"tools/call {name} failed with HTTP {status}: {text[:200]}")
        message = _parse_message(text)
    finally:
        try:
            _request(url, "DELETE", call_headers, None, min(timeout, 3))
        except Exception:  # best effort, like the Node hooks
            pass
    if "error" in message:
        raise AgentLookerError(f"{name}: {message['error']}")
    result = message.get("result") or {}
    if result.get("isError"):
        raise AgentLookerError(f"{name} returned isError: {_first_text(result)[:200]}")
    for item in result.get("content") or []:
        try:
            parsed = json.loads(item.get("text") or "")
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    raise AgentLookerError(f"{name} returned no JSON content")


def _first_text(result: Dict[str, Any]) -> str:
    for item in result.get("content") or []:
        if item.get("text"):
            return str(item["text"])
    return ""


# ---- typed wrappers -------------------------------------------------------------------------------

def check_url_safety(url: str, *, deep_scan: bool = False, **kw) -> Dict[str, Any]:
    """Normalised verdict for one URL.

    Returns ``{"status", "unsafe", "threats", "trust_score", "reasons"}``:

    * ``status`` -- ``analyzed`` (verdict available), ``not_analyzed`` (not in the trust cache;
      only a ``deep_scan=True`` call produces a verdict, and it takes 10-25 s) or ``no_data``.
      Older backends send no ``status``; that is treated as ``analyzed``.
    * ``unsafe`` -- ``isSafe is False``. ``None`` (not analyzed) is *not* unsafe; the hook
      decides what to do with ``status``.
    * ``threats`` -- threat type strings (old ``{threatType}`` objects are flattened).
    * ``trust_score`` -- 0-100 or ``None``; ``reasons`` -- up to five provider explanations.
    """
    arguments: Dict[str, Any] = {"url": url}
    if deep_scan:
        arguments["deep_scan"] = True
    data = call_tool("check_url_safety", arguments, **kw)
    if "isSafe" not in data:
        raise AgentLookerError("check_url_safety returned an unexpected payload")
    threats = []
    for threat in data.get("threats") or []:
        if isinstance(threat, str):
            threats.append(threat)
        elif isinstance(threat, dict) and threat.get("threatType"):
            threats.append(str(threat["threatType"]))
    status = data.get("status")
    if status not in ("analyzed", "not_analyzed", "no_data"):
        status = "analyzed"
    unsafe = data["isSafe"] is False
    score = data.get("trustScore")
    trust_score = score if isinstance(score, (int, float)) and not isinstance(score, bool) else None
    reasons = [str(r) for r in (data.get("reasons") or []) if isinstance(r, str) and r][:5]
    return {
        "status": status,
        "unsafe": unsafe,
        "threats": threats or (["UNSAFE"] if unsafe else []),
        "trust_score": trust_score,
        "reasons": reasons,
    }


def check_text_safety(text: str, source: str, content_source: str, **kw) -> Dict[str, Any]:
    """Returns the raw ``{action, prompt_attack, categories, ...}`` payload."""
    data = call_tool("check_text_safety", {"text": text, "source": source, "content_source": content_source}, **kw)
    if "action" not in data:
        raise AgentLookerError("check_text_safety returned an unexpected payload")
    return data
