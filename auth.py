"""Device-flow sign-in against the Agent Looker API (port of the Claude Code plugin's setup.mjs).

Flow: ``POST {base}/auth/device`` with ``{"client": "hermes-cli", "device": <hostname>}`` returns
``device_code``, ``verification_url``, ``expires_in``, ``interval``. The user opens the URL and
authorises; we poll ``GET {base}/auth/device/token?code=...`` until ``status`` is ``ok`` (token),
``expired``, or the deadline passes. The token is persisted to ``~/.hermes/.env`` via Hermes'
``save_env_value`` so hooks, the MCP ``headers`` placeholder and every profile read the same value.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional

from . import config

Printer = Callable[[str], None]


class AuthFlowError(Exception):
    pass


def _http(url: str, method: str = "GET", body: Optional[dict] = None, token: Optional[str] = None,
          timeout: float = 15) -> tuple[int, str]:
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace") if exc.fp else ""


def verify_token(token: str, mcp_url: Optional[str] = None, timeout: float = 10) -> bool:
    """True unless the endpoint answers 401 (same probe as setup.mjs: GET /mcp with the bearer)."""
    try:
        status, _ = _http(mcp_url or config.mcp_url(), token=token, timeout=timeout)
    except (urllib.error.URLError, socket.timeout, OSError):
        return False
    return status != 401


def start_device_flow(base: str, timeout: float = 15) -> Dict[str, Any]:
    status, body = _http(f"{base}/auth/device", "POST",
                         {"client": config.DEVICE_CLIENT, "device": socket.gethostname()}, timeout=timeout)
    if status != 200:
        raise AuthFlowError(f"device flow init failed ({status}): {body[:200]}")
    data = json.loads(body)
    for key in ("device_code", "verification_url", "expires_in"):
        if key not in data:
            raise AuthFlowError(f"device flow response missing {key}")
    return data


def poll_device_flow(base: str, device_code: str, timeout: float = 15) -> Dict[str, Any]:
    url = f"{base}/auth/device/token?code={urllib.parse.quote(device_code)}"
    status, body = _http(url, timeout=timeout)
    try:
        return json.loads(body)
    except ValueError as exc:
        raise AuthFlowError(f"device flow poll returned non-JSON ({status})") from exc


def run_device_flow(base: str, *, on_url: Printer, open_browser: bool = True,
                    sleep: Callable[[float], None] = time.sleep) -> str:
    """Blocking device flow; returns the token."""
    start = start_device_flow(base)
    verification_url = start["verification_url"]
    on_url(verification_url)
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(verification_url)
        except Exception:
            pass
    interval = float(start.get("interval") or 3)
    deadline = time.monotonic() + float(start["expires_in"])
    while time.monotonic() < deadline:
        sleep(interval)
        data = poll_device_flow(base, start["device_code"])
        state = data.get("status")
        if state == "ok" and data.get("token"):
            return str(data["token"])
        if state == "expired":
            raise AuthFlowError("authorization expired; run login again")
        # "pending": keep waiting
    raise AuthFlowError("timed out waiting for authorization")


def login(*, mcp_url: Optional[str] = None, dashboard_url: Optional[str] = None,
          open_browser: bool = True, printer: Printer = print, force: bool = False) -> Dict[str, Any]:
    """Interactive login. Reuses a still-valid token unless ``force``. Persists token + non-default URLs."""
    target = (mcp_url or config.mcp_url()).rstrip("/")
    base = config.base_url(target)
    existing = config.api_token()
    token: Optional[str] = None
    reused = False
    if existing and not force:
        printer("Verifying existing token...")
        if verify_token(existing, target):
            printer("Token valid.")
            token, reused = existing, True
        else:
            printer("Existing token rejected (401); signing in again.")
    if token is None:
        def _show(url: str) -> None:
            printer("")
            printer("Open this URL in your browser to authorize:")
            printer("")
            printer(f"  {url}")
            printer("")
            printer("Waiting for authorization...")
        token = run_device_flow(base, on_url=_show, open_browser=open_browser)
        printer("Authorized.")

    config.save_env(config.ENV_TOKEN, token)
    if target == config.DEFAULT_MCP_URL:
        _remove_quiet(config.ENV_MCP_URL)
    else:
        config.save_env(config.ENV_MCP_URL, target)
    if dashboard_url:
        if dashboard_url.rstrip("/") == config.DEFAULT_DASHBOARD_URL:
            _remove_quiet(config.ENV_DASHBOARD_URL)
        else:
            config.save_env(config.ENV_DASHBOARD_URL, dashboard_url.rstrip("/"))
    return {"token_saved": True, "reused": reused, "mcp_url": target}


def logout(printer: Printer = print, *, remove_mcp: bool = True) -> None:
    """Undo ``login``: drop the token and endpoint overrides, and (by default) the MCP entry it added."""
    for key in (config.ENV_TOKEN, config.ENV_MCP_URL, config.ENV_DASHBOARD_URL):
        _remove_quiet(key)
    printer("✓ Agent Looker credentials removed from ~/.hermes/.env.")
    if remove_mcp:
        try:
            removed = config.remove_mcp_entry()
        except Exception as exc:
            printer(f"! Could not remove mcp_servers.agent-looker from ~/.hermes/config.yaml: {exc}")
        else:
            if removed:
                printer("✓ mcp_servers.agent-looker removed from ~/.hermes/config.yaml.")
    printer("The token stays listed on the dashboard; revoke it there if this machine is gone.")


def _remove_quiet(key: str) -> None:
    try:
        config.remove_env(key)
    except Exception:
        pass


def status(verify: bool = True) -> Dict[str, Any]:
    token = config.api_token()
    info: Dict[str, Any] = {
        "mcp_url": config.mcp_url(), "dashboard_url": config.dashboard_url(),
        "signed_in": bool(token), "token_valid": None,
    }
    if token and verify:
        info["token_valid"] = verify_token(token)
    return info
