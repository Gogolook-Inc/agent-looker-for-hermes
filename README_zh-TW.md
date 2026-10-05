# Agent Looker for Hermes Agent

[English](README.md)

原生的 [Hermes Agent](https://hermes-agent.nousresearch.com/) plugin，透過 [Agent Looker](https://agentlooker.ai/) MCP server 防護 session 不受不安全的 URL、惡意內容與 prompt injection 影響。

## 功能

**Hooks（自動）** 在 Hermes 內部執行，不經過模型：

| Hook | 工具 | 行為 |
|---|---|---|
| `pre_tool_call` | `web_extract`、`browser_navigate` | 每個 URL 先送 `check_url_safety`。不安全就擋下呼叫，並告訴模型威脅類別。 |
| `transform_tool_result` | `web_extract`、`web_search` | 結果送 `check_text_safety`。FLAG / BLOCK 時在結果最前面加上 `[AGENT LOOKER CONTENT SAFETY]` 警告，讓模型把內容當資料而不是指令。 |
| `on_session_start` | | 尚未登入時提醒你登入。 |

**Skills（模型主導）** 補 hooks 看不到的路徑（`terminal` 裡的 curl / git clone、檔案、email、貼上的文字）。`skills_list` 會列成 `agent-looker:<name>`，用 `skill_view` 開啟：

| Skill | MCP tool |
|---|---|
| `check-url-safety` | `check_url_safety` |
| `check-text-safety` | `check_text_safety` |
| `report-risk-url` | `report_risk_url` |
| `report-risk-text` | `report_risk_text` |

**System prompt 區段** 把五條 Agent Looker 安全規則固定寫進每個新 session。

```
web_extract(urls) / browser_navigate(url)
      |
pre_tool_call ── check_url_safety ──UNSAFE──> 擋下，威脅類別回給模型
      |                            ──SAFE────> 工具執行
      v
transform_tool_result ── check_text_safety ──FLAG/BLOCK──> 結果前加警告
                                           ──ALLOW───────> 結果不變
```

## 需求

- 有 plugin 系統（`hermes plugins` CLI）的 Hermes Agent
- Agent Looker 帳號（[dashboard](https://app.agentlooker.ai/)）

沒有 Python 依賴，只用標準庫。

## 安裝

```bash
hermes plugins install Gogolook-Inc/agent-looker-for-hermes --enable
hermes agent-looker login
```

`login` 會印出授權網址（有瀏覽器時會自動打開）。用 Google 登入、按 Authorize，token 就存進 `~/.hermes/.env` 的 `AGENT_LOOKER_API_TOKEN`，同一步也會把 Agent Looker MCP tools 接上（見下節）。每台機器各自拿到一個名為 `hermes-cli_<hostname>` 的 token，dashboard 上分得出來、也能個別撤銷。重跑 `login` 會沿用還有效的 token。

之後每個新 session 的 hooks 都會生效。安裝階段不會執行任何東西：Hermes 在 enable 之後的下一次啟動才載入 plugin。

### 讓模型也拿到 MCP tools

Hooks 只管網頁工具。要讓 skills 能直接呼叫 `check_url_safety` 等工具，模型需要用同一個 token 連上 Agent Looker MCP server。原生 Hermes plugin 不能自己帶 MCP server，所以這條設定要寫進你的 `config.yaml`。`login` 存完 token 後會直接寫入（只想存 token 可加 `--no-mcp`）。要手動加入或更新：

```bash
hermes agent-looker mcp-config --write   # 把 mcp_servers.agent-looker 加進 ~/.hermes/config.yaml
```

不加 `--write` 只會印出設定：

```yaml
mcp_servers:
  agent-looker:
    url: "https://api.agentlooker.ai/mcp"
    headers:
      Authorization: "Bearer ${AGENT_LOOKER_API_TOKEN}"
```

Hermes 連線時從 `~/.hermes/.env` 展開 `${AGENT_LOOKER_API_TOKEN}`，所以登入一次，hooks 和 MCP tools 共用。

### 在對話裡登入

Gateway 使用者（Telegram、Discord 等）沒有終端機。在對話輸入 `/agent-looker login`，bot 回傳授權網址、在背景完成登入並同樣接上 MCP tools；`/agent-looker status` 看結果。

### Desktop

plugin 的設定表單（Capabilities → Plugins → 齒輪）會顯示 endpoint、行為開關，以及一個遮罩的 **API token** 欄位，寫入的是同一個 `.env` 變數，給想手動貼 token 的人用。

## 指令

| 指令 | 用途 |
|---|---|
| `hermes agent-looker login [--mcp-url URL] [--dashboard-url URL] [--no-browser] [--force] [--no-mcp]` | device flow 登入；存 token 並接上 MCP tools |
| `hermes agent-looker status` | endpoint、token 是否有效、MCP 設定是否存在 |
| `hermes agent-looker logout [--keep-mcp]` | 還原 `login`：移除 token、endpoint 覆寫與 MCP 設定 |
| `hermes agent-looker uninstall` | `logout` 後執行 `hermes plugins remove agent-looker` |
| `hermes agent-looker mcp-config [--write]` | 印出或寫入 `mcp_servers` 設定 |
| `/agent-looker login` / `/agent-looker status` | 同上，在 session 內使用 |

## 設定

放在 `~/.hermes/config.yaml` 的 `plugins.entries.agent-looker.settings`，Desktop 可直接編輯：

| Key | 預設 | 意義 |
|---|---|---|
| `mcp_url` | `https://api.agentlooker.ai/mcp` | endpoint。`AGENT_LOOKER_MCP_URL` 會覆寫它。 |
| `check_urls` | `true` | `web_extract` / `browser_navigate` 前的 URL 檢查 |
| `check_text` | `true` | `web_extract` / `web_search` 結果的內容掃描 |
| `block_when_unauthenticated` | `true` | 未登入時拒絕網頁工具（關掉 = 警告一次後放行） |
| `fail_closed` | `false` | Agent Looker 連不上時擋下網頁工具（預設：放行並在 log 警告） |
| `timeout_seconds` | `10` | 單次 API 逾時；要小於 `plugins.hook_callback_timeout` |
| `max_text_chars` | `20000` | 送給 `check_text_safety` 的結果前段長度 |

## 環境

Branch == 環境。每個 branch 在 `config.py`（`DEFAULT_MCP_URL`）與 `plugin.yaml`（`config_schema.mcp_url.default`）帶自己的預設 MCP URL。

| Branch | API |
|---|---|
| `production` | `https://api.agentlooker.ai/mcp` |
| `staging` | `https://api-staging.agentlooker.ai/mcp` |
| `develop` | `https://api-develop.agentlooker.ai/mcp` |

不要手改 URL。[mcp-url workflow](.github/workflows/mcp-url.yml) 會讓 URL 與目標 branch 不符的 pull request 失敗，push 時自動改寫。

`hermes plugins install owner/repo` 裝的是 repo 的預設 branch（`production`）。Hermes 的 `--ref` 不接受 branch 或 tag 名稱，只接受 40 碼 commit SHA。要測 staging 或 develop，裝該 branch 的最新 commit：

```bash
sha=$(git ls-remote https://github.com/Gogolook-Inc/agent-looker-for-hermes staging | cut -f1)
hermes plugins install Gogolook-Inc/agent-looker-for-hermes --ref "$sha" --enable
hermes agent-looker login
```

釘住 SHA 的安裝會停在那個 commit。要換版本就用新的 SHA 重裝：`hermes plugins install Gogolook-Inc/agent-looker-for-hermes --ref <new sha> --force`。

### 不重裝直接切換 endpoint

endpoint 同時也是一個變數 `AGENT_LOOKER_MCP_URL`，hooks、CLI、MCP 設定都讀它。登入時帶一次即可：

```bash
hermes agent-looker login --mcp-url https://api-staging.agentlooker.ai/mcp
```

覆寫會存進 `~/.hermes/.env`，對該環境認證，並把 `mcp_servers.agent-looker` 指到該環境。再用該 branch 的預設 URL 跑一次 `login` 就會清掉覆寫。staging 與 develop 的登入頁在 CDN 有 HTTP Basic Auth，瀏覽器會在 Google 登入前先問一次。

## 解除安裝

```bash
hermes agent-looker uninstall
```

一個指令做完：從 `~/.hermes/.env` 移除 token 與 endpoint 覆寫、從 `~/.hermes/config.yaml` 移除 `mcp_servers.agent-looker`，再執行 `hermes plugins remove agent-looker`。之後重啟 Hermes。

也可以分開做：`hermes agent-looker logout` 只還原 `login` 做過的事（token、覆寫、MCP 設定；加 `--keep-mcp` 可保留 MCP 設定），`hermes plugins remove agent-looker` 只移除 plugin。token 仍會列在 dashboard 上，機器不再使用時請到那裡撤銷。

## 專案結構

```
.github/workflows/mcp-url.yml   # 把預設 MCP URL 釘在 branch 對應的環境
plugin.yaml          # manifest：hooks、config_schema（token 是 secret -> .env）
__init__.py          # register(ctx)：hooks、skills、prompt 區段、CLI、slash command
config.py            # endpoint / token / 設定解析
mcp_client.py        # 標準庫 Streamable HTTP MCP client（initialize、tools/call、DELETE）
auth.py              # device flow（POST /auth/device、輪詢 /auth/device/token）、login/logout/status
hooks.py             # pre_tool_call、transform_tool_result、on_session_start
cli.py               # hermes agent-looker ...
commands.py          # /agent-looker ...
context/rules.md     # system prompt 區段文字
skills/*/SKILL.md    # 四個 Agent Looker skills
```

## 授權

GPL-3.0，見 [LICENSE](LICENSE)。
