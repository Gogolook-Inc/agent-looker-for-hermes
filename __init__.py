"""Agent Looker for Hermes: URL and content safety guardrails backed by the Agent Looker MCP server.

What ``register(ctx)`` wires up:

* hooks    ``pre_tool_call`` (URL gate), ``transform_tool_result`` (content scan), ``on_session_start``
* skills   the four Agent Looker skills, as ``agent-looker:<name>``
* prompt   a bounded system-prompt section with the security rules
* CLI      ``hermes agent-looker login|status|logout|mcp-config``
* chat     ``/agent-looker login|status``

Credentials: ``hermes agent-looker login`` runs the Agent Looker device flow and stores the token in
``~/.hermes/.env`` as ``AGENT_LOOKER_API_TOKEN``. Nothing runs at install time; Hermes only imports a
plugin on the next start after ``hermes plugins enable agent-looker``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from . import cli, commands, config, hooks

logger = logging.getLogger(__name__)

_RULES_PATH = config.PLUGIN_ROOT / "context" / "rules.md"
_SKILLS_DIR = config.PLUGIN_ROOT / "skills"
_MCP_NOT_CONNECTED = (
    "\n\nNote: the Agent Looker MCP tools are not connected in this session, so steps 1 to 3 cannot be "
    "performed by hand; the automatic hooks still cover web_extract, web_search and browser_navigate. "
    "Do not bring this up on your own. Mention it only when the user asks about Agent Looker or when a task "
    "actually needs one of those tools, and then say once that `hermes agent-looker mcp-config --write` connects them."
)


def _skill_description(skill_md: Path) -> str:
    try:
        text = skill_md.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r"^description:\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip().strip('"') if match else ""


def _mcp_tools_connected() -> bool:
    try:
        from hermes_cli.config import load_config_readonly
        servers = (load_config_readonly() or {}).get("mcp_servers") or {}
    except Exception:
        return False
    target = config.mcp_url().rstrip("/")
    return any(str((entry or {}).get("url", "")).rstrip("/") == target for entry in servers.values()
               if isinstance(entry, dict))


def _rules(_session_info=None) -> str:
    try:
        text = _RULES_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return text if _mcp_tools_connected() else text + _MCP_NOT_CONNECTED


def register(ctx) -> None:
    config.bind_context(ctx)

    ctx.register_hook("pre_tool_call", hooks.pre_tool_call)
    ctx.register_hook("transform_tool_result", hooks.transform_tool_result)
    ctx.register_hook("on_session_start", hooks.on_session_start)

    ctx.register_system_prompt_section("agent-looker.security-rules", _rules, position="after_memory", max_chars=4000)

    if _SKILLS_DIR.is_dir():
        for skill_dir in sorted(p for p in _SKILLS_DIR.iterdir() if p.is_dir()):
            skill_md = skill_dir / "SKILL.md"
            if skill_md.is_file():
                ctx.register_skill(skill_dir.name, skill_md, description=_skill_description(skill_md))

    ctx.register_cli_command(
        name="agent-looker",
        help="Agent Looker: sign in, show status, expose the MCP tools",
        description="Device-flow sign-in and status for the Agent Looker safety plugin.",
        setup_fn=cli.setup_parser,
        handler_fn=cli.handle,
    )
    ctx.register_command("agent-looker", commands.handle,
                         description="Agent Looker: sign in or show status", args_hint="[login|status]")

    logger.info("agent-looker plugin registered (endpoint %s, signed in: %s)",
                config.mcp_url(), bool(config.api_token()))
