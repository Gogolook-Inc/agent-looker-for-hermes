"""``hermes agent-looker <login|status|logout|mcp-config>`` (registered via ctx.register_cli_command)."""

from __future__ import annotations

import argparse
import sys

from . import auth, config

MCP_SNIPPET = """mcp_servers:
  agent-looker:
    url: "{url}"
    headers:
      Authorization: "Bearer ${{{token_env}}}"
"""


def setup_parser(parser: argparse.ArgumentParser) -> None:
    subs = parser.add_subparsers(dest="agent_looker_cmd")

    login = subs.add_parser("login", help="Sign in with the device flow and store the token in ~/.hermes/.env")
    login.add_argument("--mcp-url", help=f"Agent Looker MCP endpoint (default: {config.DEFAULT_MCP_URL}; "
                                         f"or set {config.ENV_MCP_URL})")
    login.add_argument("--dashboard-url", help="Dashboard URL when the environment has its own")
    login.add_argument("--no-browser", action="store_true", help="Print the URL only; do not open a browser")
    login.add_argument("--force", action="store_true", help="Sign in again even if the stored token still works")
    login.add_argument("--no-mcp", action="store_true",
                       help="Only save the token; do not add mcp_servers.agent-looker to ~/.hermes/config.yaml")

    subs.add_parser("status", help="Show endpoint and whether the stored token is accepted")
    logout = subs.add_parser("logout", help="Remove the token, endpoint overrides and the MCP entry login added")
    logout.add_argument("--keep-mcp", action="store_true", help="Leave mcp_servers.agent-looker in config.yaml")

    subs.add_parser("uninstall", help="logout, then remove the plugin (`hermes plugins remove agent-looker`)")

    mcp = subs.add_parser("mcp-config", help="Print (or write) the mcp_servers entry that exposes the "
                                             "Agent Looker tools to the model with the same token")
    mcp.add_argument("--write", action="store_true", help="Add the entry to ~/.hermes/config.yaml")
    parser.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    cmd = getattr(args, "agent_looker_cmd", None)
    if cmd == "login":
        return _login(args)
    if cmd == "status":
        return _status()
    if cmd == "logout":
        auth.logout(remove_mcp=not getattr(args, "keep_mcp", False))
        return 0
    if cmd == "uninstall":
        return _uninstall()
    if cmd == "mcp-config":
        return _mcp_config(write=bool(getattr(args, "write", False)))
    print("Usage: hermes agent-looker <login|status|logout|mcp-config>")
    return 1


def _login(args: argparse.Namespace) -> int:
    try:
        result = auth.login(mcp_url=args.mcp_url, dashboard_url=args.dashboard_url,
                            open_browser=not args.no_browser, force=args.force)
    except auth.AuthFlowError as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # network etc.
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1
    print(f"✓ Token saved to ~/.hermes/.env as {config.ENV_TOKEN}")
    if result["mcp_url"] != config.DEFAULT_MCP_URL:
        print(f"✓ MCP endpoint: {result['mcp_url']}")
    print("Hooks are active in new Hermes sessions.")
    if args.no_mcp:
        print("MCP tools not connected (--no-mcp). Run `hermes agent-looker mcp-config --write` to connect them later.")
        return 0
    _write_mcp_entry()
    return 0


def _uninstall() -> int:
    """Full removal: credentials + MCP entry (logout), then the plugin itself through Hermes' own
    remover so provenance and enable state are cleaned up the same way `hermes plugins remove` does."""
    import shutil
    import subprocess
    auth.logout()
    hermes = shutil.which("hermes") or sys.argv[0]
    try:
        rc = subprocess.call([hermes, "plugins", "remove", config.PLUGIN_NAME])
    except OSError as exc:
        print(f"Could not run `hermes plugins remove {config.PLUGIN_NAME}`: {exc}", file=sys.stderr)
        print(f"Run it yourself to finish: hermes plugins remove {config.PLUGIN_NAME}")
        return 1
    if rc == 0:
        print("✓ Agent Looker plugin removed. Restart Hermes to apply.")
    return rc


def _status() -> int:
    info = auth.status()
    print(f"MCP endpoint : {info['mcp_url']}")
    print(f"Dashboard    : {info['dashboard_url']}")
    if not info["signed_in"]:
        print("Token        : not set  -> run `hermes agent-looker login`")
        return 1
    valid = info["token_valid"]
    print("Token        : " + ("valid" if valid else "rejected (401) -> run `hermes agent-looker login`"
                               if valid is False else "set (not verified)"))
    print(f"MCP tools    : {'configured' if config.mcp_entry_present() else 'not configured -> hermes agent-looker mcp-config --write'}")
    return 0 if valid is not False else 1


def _mcp_config(*, write: bool) -> int:
    snippet = MCP_SNIPPET.format(url=config.mcp_url(), token_env=config.ENV_TOKEN)
    if not write:
        print("Add this to ~/.hermes/config.yaml (or run with --write):\n")
        print(snippet)
        return 0
    _write_mcp_entry()
    return 0


def _write_mcp_entry() -> None:
    state = config.ensure_mcp_entry()
    if state == "unchanged":
        print("✓ MCP tools already connected (mcp_servers.agent-looker is up to date).")
    else:
        print(f"✓ MCP tools connected: mcp_servers.agent-looker {state} in ~/.hermes/config.yaml. "
              "Restart Hermes to pick it up.")
