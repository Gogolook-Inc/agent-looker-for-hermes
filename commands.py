"""``/agent-looker [login|status]`` in-session slash command (CLI and gateway platforms).

Gateway users have no terminal, so ``login`` replies with the verification URL and polls in a
background thread; a second ``/agent-looker status`` shows the outcome.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional

from . import auth, config

logger = logging.getLogger(__name__)

_pending: Dict[str, Optional[str]] = {"state": None, "detail": None}
_lock = threading.Lock()


def _background_login() -> None:
    base = config.base_url()
    try:
        token = auth.run_device_flow(base, on_url=lambda _u: None, open_browser=False)
        config.save_env(config.ENV_TOKEN, token)
        _connect_mcp_quiet()
        with _lock:
            _pending.update(state="done", detail=None)
    except Exception as exc:
        with _lock:
            _pending.update(state="failed", detail=str(exc))


def _connect_mcp_quiet() -> None:
    try:
        config.ensure_mcp_entry()
    except Exception as exc:
        logger.warning("agent-looker: could not write mcp_servers entry: %s", exc)


def handle(raw_args: str = "") -> str:
    sub = (raw_args or "").strip().split(" ", 1)[0].lower() or "status"
    if sub == "status":
        info = auth.status()
        with _lock:
            pending = dict(_pending)
        lines = [f"Agent Looker endpoint: {info['mcp_url']}"]
        if info["signed_in"]:
            lines.append("Token: valid" if info["token_valid"] else "Token: rejected (401), run `/agent-looker login`")
        else:
            lines.append("Token: not set, run `/agent-looker login`")
        lines.append("MCP tools: " + ("connected" if config.mcp_entry_present() else "not connected"))
        if pending["state"] == "waiting":
            lines.append("A sign-in is waiting for you to authorize in the browser.")
        elif pending["state"] == "failed":
            lines.append(f"Last sign-in failed: {pending['detail']}")
        return "\n".join(lines)
    if sub == "login":
        with _lock:
            if _pending["state"] == "waiting":
                return "A sign-in is already waiting for authorization. Finish it in the browser, then `/agent-looker status`."
        try:
            start = auth.start_device_flow(config.base_url())
        except Exception as exc:
            return f"Agent Looker login failed to start: {exc}"
        with _lock:
            _pending.update(state="waiting", detail=None)
        threading.Thread(target=_poll_started, args=(start,), name="agent-looker-login", daemon=True).start()
        return ("Open this URL to authorize Agent Looker on this Hermes install:\n"
                f"{start['verification_url']}\n"
                f"It expires in {int(start.get('expires_in', 0)) // 60} minutes. "
                "The token and the MCP tools are connected automatically once you authorize; new sessions pick them up. "
                "Run `/agent-looker status` to check.")
    return "Usage: /agent-looker [login|status]"


def _poll_started(start: dict) -> None:
    import time
    base = config.base_url()
    interval = float(start.get("interval") or 3)
    deadline = time.monotonic() + float(start.get("expires_in") or 600)
    try:
        while time.monotonic() < deadline:
            time.sleep(interval)
            data = auth.poll_device_flow(base, start["device_code"])
            if data.get("status") == "ok" and data.get("token"):
                config.save_env(config.ENV_TOKEN, str(data["token"]))
                _connect_mcp_quiet()
                with _lock:
                    _pending.update(state="done", detail=None)
                return
            if data.get("status") == "expired":
                raise auth.AuthFlowError("authorization expired")
        raise auth.AuthFlowError("timed out waiting for authorization")
    except Exception as exc:
        logger.warning("agent-looker: background login failed: %s", exc)
        with _lock:
            _pending.update(state="failed", detail=str(exc))
