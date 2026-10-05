# Agent Looker for Hermes Agent

[繁體中文](README_zh-TW.md)

A native [Hermes Agent](https://hermes-agent.nousresearch.com/) plugin that protects sessions from unsafe URLs, malicious content and prompt injection via the [Agent Looker](https://agentlooker.ai/) MCP server.

## What it does

**Hooks (automatic)** run inside Hermes without the model's involvement:

| Hook | Tools | What happens |
|---|---|---|
| `pre_tool_call` | `web_extract`, `browser_navigate` | Every URL is sent to `check_url_safety`. Unsafe URLs block the call; the model is told the threat categories. |
| `transform_tool_result` | `web_extract`, `web_search` | The result is sent to `check_text_safety`. FLAG / BLOCK verdicts prepend an `[AGENT LOOKER CONTENT SAFETY]` warning so the model treats the content as data. |
| `on_session_start` | | Reminds you to sign in when no token is configured. |

**Skills (model-driven)** cover the paths hooks do not see (curl / git clone in `terminal`, files, emails, pasted text). They are listed by `skills_list` as `agent-looker:<name>` and opened with `skill_view`:

| Skill | MCP tool |
|---|---|
| `check-url-safety` | `check_url_safety` |
| `check-text-safety` | `check_text_safety` |
| `report-risk-url` | `report_risk_url` |
| `report-risk-text` | `report_risk_text` |

**System prompt section** with the five Agent Looker security rules is frozen into every new session.

```
web_extract(urls) / browser_navigate(url)
      |
pre_tool_call ── check_url_safety ──UNSAFE──> blocked, threat categories returned to the model
      |                            ──SAFE────> tool runs
      v
transform_tool_result ── check_text_safety ──FLAG/BLOCK──> warning prepended to the result
                                           ──ALLOW───────> result unchanged
```

## Requirements

- Hermes Agent with the plugin system (`hermes plugins` CLI)
- An Agent Looker account ([dashboard](https://app.agentlooker.ai/))

No Python dependencies: the plugin uses only the standard library.

## Installation

```bash
hermes plugins install Gogolook-Inc/agent-looker-for-hermes --enable
hermes agent-looker login
```

`login` prints an authorization URL (and opens it when a browser is available). Sign in with Google, click Authorize, and the token is saved to `~/.hermes/.env` as `AGENT_LOOKER_API_TOKEN`. The Agent Looker MCP tools are connected in the same step (see below). Each machine gets its own token named `hermes-cli_<hostname>`, so you can tell installs apart and revoke them individually from the dashboard. Re-running `login` reuses a token that still works.

Hooks are active in every new session after that. Nothing runs at install time: Hermes imports a plugin on the next start after it is enabled.

### Give the model the MCP tools too

Hooks cover the web tools. For the skills to call `check_url_safety` and friends directly, the model needs the Agent Looker MCP server connected with the same token. A native Hermes plugin cannot ship an MCP server itself, so the entry goes into your `config.yaml`. `login` writes it automatically right after saving the token (pass `--no-mcp` to keep the token only). To add or refresh it by hand:

```bash
hermes agent-looker mcp-config --write   # adds mcp_servers.agent-looker to ~/.hermes/config.yaml
```

Without `--write` the command prints the entry instead:

```yaml
mcp_servers:
  agent-looker:
    url: "https://api.agentlooker.ai/mcp"
    headers:
      Authorization: "Bearer ${AGENT_LOOKER_API_TOKEN}"
```

Hermes resolves `${AGENT_LOOKER_API_TOKEN}` from `~/.hermes/.env` at connect time, so one `login` serves hooks and MCP tools alike.

### Signing in from a chat session

Gateway users (Telegram, Discord, ...) have no terminal. Type `/agent-looker login` in the chat: the bot replies with the authorization URL, finishes the sign-in in the background and connects the MCP tools the same way. `/agent-looker status` shows the result.

### Desktop

The plugin's settings form (Capabilities → Plugins → gear) shows the endpoint, the behaviour toggles and a masked **API token** field that writes the same `.env` variable, for anyone who prefers to paste a token.

## Commands

| Command | Purpose |
|---|---|
| `hermes agent-looker login [--mcp-url URL] [--dashboard-url URL] [--no-browser] [--force] [--no-mcp]` | Device-flow sign-in; saves the token and connects the MCP tools |
| `hermes agent-looker status` | Endpoint, token validity, whether the MCP entry exists |
| `hermes agent-looker logout [--keep-mcp]` | Undo `login`: remove the token, endpoint overrides and the MCP entry |
| `hermes agent-looker uninstall` | `logout`, then `hermes plugins remove agent-looker` |
| `hermes agent-looker mcp-config [--write]` | Print or write the `mcp_servers` entry |
| `/agent-looker login` / `/agent-looker status` | Same, inside a session |

## Settings

Stored under `plugins.entries.agent-looker.settings` in `~/.hermes/config.yaml`, editable in Desktop:

| Key | Default | Meaning |
|---|---|---|
| `mcp_url` | `https://api.agentlooker.ai/mcp` | Endpoint. `AGENT_LOOKER_MCP_URL` overrides it. |
| `check_urls` | `true` | URL gate before `web_extract` / `browser_navigate` |
| `check_text` | `true` | Content scan of `web_extract` / `web_search` results |
| `block_when_unauthenticated` | `true` | Refuse the web tools until signed in (off = warn once and allow) |
| `fail_closed` | `false` | Block the web tools when Agent Looker is unreachable (default: allow with a warning in the log) |
| `timeout_seconds` | `10` | Per-request API timeout; keep it under `plugins.hook_callback_timeout` |
| `max_text_chars` | `20000` | Head of the result sent to `check_text_safety` |

## Environments

Branch == environment. Each branch carries its own default MCP URL in `config.py` (`DEFAULT_MCP_URL`) and `plugin.yaml` (`config_schema.mcp_url.default`).

| Branch | API |
|---|---|
| `production` | `https://api.agentlooker.ai/mcp` |
| `staging` | `https://api-staging.agentlooker.ai/mcp` |
| `develop` | `https://api-develop.agentlooker.ai/mcp` |

Never edit the URL by hand. The [mcp-url workflow](.github/workflows/mcp-url.yml) fails a pull request whose URL does not match the target branch and rewrites it on push.

`hermes plugins install owner/repo` installs the repository's default branch (`production`). Hermes refuses branch and tag names in `--ref`; it accepts only a 40-character commit SHA. To test staging or develop, install that branch's head commit:

```bash
sha=$(git ls-remote https://github.com/Gogolook-Inc/agent-looker-for-hermes staging | cut -f1)
hermes plugins install Gogolook-Inc/agent-looker-for-hermes --ref "$sha" --enable
hermes agent-looker login
```

A pinned install stays on that commit. To move to a newer one, reinstall with the new SHA: `hermes plugins install Gogolook-Inc/agent-looker-for-hermes --ref <new sha> --force`.

### Overriding the endpoint without reinstalling

The endpoint is also one variable, `AGENT_LOOKER_MCP_URL`, read by the hooks, the CLI and the MCP entry. Pass it to `login` once:

```bash
hermes agent-looker login --mcp-url https://api-staging.agentlooker.ai/mcp
```

This stores the override in `~/.hermes/.env`, authenticates against that environment and points `mcp_servers.agent-looker` at it. Run `login` again with the branch's default URL to drop the override. Staging and develop sign-in pages sit behind HTTP Basic Auth at the CDN; the browser prompts once before the Google login.

## Uninstall

```bash
hermes agent-looker uninstall
```

One command: removes the token and endpoint overrides from `~/.hermes/.env`, removes `mcp_servers.agent-looker` from `~/.hermes/config.yaml`, then runs `hermes plugins remove agent-looker`. Restart Hermes afterwards.

The pieces are also available separately: `hermes agent-looker logout` undoes only what `login` did (token, overrides, MCP entry; add `--keep-mcp` to keep the entry), and `hermes plugins remove agent-looker` removes only the plugin. The token stays listed on the dashboard; revoke it there if the machine is gone.

## Project structure

```
.github/workflows/mcp-url.yml   # pins the default MCP URL to the branch environment
plugin.yaml          # manifest: hooks, config_schema (token = secret -> .env)
__init__.py          # register(ctx): hooks, skills, prompt section, CLI, slash command
config.py            # endpoint / token / settings resolution
mcp_client.py        # stdlib Streamable HTTP MCP client (initialize, tools/call, DELETE)
auth.py              # device flow (POST /auth/device, poll /auth/device/token), login/logout/status
hooks.py             # pre_tool_call, transform_tool_result, on_session_start
cli.py               # hermes agent-looker ...
commands.py          # /agent-looker ...
context/rules.md     # system prompt section text
skills/*/SKILL.md    # the four Agent Looker skills
```

## License

GPL-3.0 -- see [LICENSE](LICENSE).
