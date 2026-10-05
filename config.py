"""Endpoint, credential and settings resolution shared by hooks, CLI and slash command.

Priority for the endpoint: ``AGENT_LOOKER_MCP_URL`` (process env or ``~/.hermes/.env``) >
``plugins.entries.agent-looker.settings.mcp_url`` > production default. The token only ever lives in
``~/.hermes/.env`` as ``AGENT_LOOKER_API_TOKEN``; ``hermes agent-looker login`` writes it there.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

PLUGIN_NAME = "agent-looker"
PLUGIN_ROOT = Path(__file__).resolve().parent

DEFAULT_MCP_URL = "https://api-develop.agentlooker.ai/mcp"
DEFAULT_DASHBOARD_URL = "https://app.agentlooker.ai/dashboard"

ENV_MCP_URL = "AGENT_LOOKER_MCP_URL"
ENV_DASHBOARD_URL = "AGENT_LOOKER_DASHBOARD_URL"
ENV_TOKEN = "AGENT_LOOKER_API_TOKEN"

# Sent with POST /auth/device so the dashboard labels the token per install
# (hermes-cli_<hostname>) instead of one shared `cli` token.
DEVICE_CLIENT = "hermes-cli"

# Set by register(ctx); hooks read settings through it. None when imported outside Hermes (tests).
_CTX: Any = None

_DEFAULTS = {
    "mcp_url": DEFAULT_MCP_URL,
    "check_urls": True,
    "check_text": True,
    "block_when_unauthenticated": True,
    "fail_closed": False,
    "timeout_seconds": 10,
    "max_text_chars": 20000,
}


def bind_context(ctx: Any) -> None:
    global _CTX
    _CTX = ctx


def setting(key: str) -> Any:
    default = _DEFAULTS[key]
    if _CTX is None:
        return default
    try:
        value = _CTX.get_config(key, default)
    except Exception:
        return default
    return default if value is None else value


def plugin_version() -> str:
    try:
        text = (PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8")
    except OSError:
        return "0.0.0"
    match = re.search(r'^version:\s*"?([^"\n]+)"?', text, re.MULTILINE)
    return match.group(1).strip() if match else "0.0.0"


def _env(key: str) -> Optional[str]:
    """Scope-aware read: Hermes' ``get_env_value`` honours profiles and ``~/.hermes/.env``."""
    value = None
    try:
        from hermes_cli.config import get_env_value
        value = get_env_value(key)
    except Exception:
        value = os.environ.get(key)
    value = (value or "").strip()
    return value or None


def mcp_url() -> str:
    return _env(ENV_MCP_URL) or str(setting("mcp_url") or DEFAULT_MCP_URL).strip()


def dashboard_url() -> str:
    return _env(ENV_DASHBOARD_URL) or DEFAULT_DASHBOARD_URL


def api_token() -> Optional[str]:
    return _env(ENV_TOKEN)


def base_url(url: Optional[str] = None) -> str:
    """Strip the trailing ``/mcp``: the device-flow routes live on the bare API host."""
    return re.sub(r"/mcp/?$", "", (url or mcp_url()).rstrip("/"))


def save_env(key: str, value: str) -> None:
    from hermes_cli.config import save_env_value
    save_env_value(key, value)
    os.environ[key] = value


def remove_env(key: str) -> None:
    from hermes_cli.config import remove_env_value
    remove_env_value(key)
    os.environ.pop(key, None)


MCP_SERVER_NAME = "agent-looker"


def mcp_entry() -> dict:
    """The ``mcp_servers.agent-looker`` entry: same endpoint, token resolved from .env at connect time."""
    return {"url": mcp_url(), "headers": {"Authorization": f"Bearer ${{{ENV_TOKEN}}}"}}


def _raw_mcp_servers() -> dict:
    """``mcp_servers`` as written in config.yaml (placeholders intact, no env expansion)."""
    try:
        from hermes_cli.config import read_raw_config
        servers = (read_raw_config() or {}).get("mcp_servers") or {}
    except Exception:
        return {}
    return servers if isinstance(servers, dict) else {}


def mcp_entry_present() -> bool:
    return MCP_SERVER_NAME in _raw_mcp_servers()


def ensure_mcp_entry() -> str:
    """Upsert ``mcp_servers.agent-looker`` so the model gets the Agent Looker tools with the token
    ``login`` just saved. Compares against the RAW file (so ``${AGENT_LOOKER_API_TOKEN}`` is never
    confused with its expansion) and writes through Hermes' own ``hermes mcp add`` saver.
    Returns ``"added"``, ``"updated"`` or ``"unchanged"``."""
    wanted = mcp_entry()
    current = _raw_mcp_servers().get(MCP_SERVER_NAME)
    if current == wanted:
        return "unchanged"
    state = "updated" if isinstance(current, dict) else "added"
    try:
        from hermes_cli.mcp_config import _save_mcp_server
        if not _save_mcp_server(MCP_SERVER_NAME, wanted):
            raise RuntimeError("Hermes refused the mcp_servers entry")
    except ImportError:
        from hermes_cli.config import load_config, save_config
        cfg = load_config() or {}
        cfg.setdefault("mcp_servers", {})[MCP_SERVER_NAME] = wanted
        save_config(cfg)
    return state


def remove_mcp_entry() -> bool:
    """Remove ``mcp_servers.agent-looker`` (the entry ``login`` added). True when it existed."""
    if not mcp_entry_present():
        return False
    try:
        from hermes_cli.mcp_config import _remove_mcp_server
        return bool(_remove_mcp_server(MCP_SERVER_NAME))
    except ImportError:
        from hermes_cli.config import load_config, save_config
        cfg = load_config() or {}
        servers = cfg.get("mcp_servers") or {}
        servers.pop(MCP_SERVER_NAME, None)
        if servers:
            cfg["mcp_servers"] = servers
        else:
            cfg.pop("mcp_servers", None)
        save_config(cfg)
        return True


def client_info() -> tuple[str, str]:
    """``clientInfo`` for MCP initialize: who and where, so dashboard logs tell installs apart."""
    import getpass
    import socket
    try:
        user = getpass.getuser()
    except Exception:
        user = "user"
    return f"agent-looker-for-hermes-{user}@{socket.gethostname()}", plugin_version()
