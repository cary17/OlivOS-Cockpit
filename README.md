# OlivOS Cockpit

以 OPK 插件形式运行的 OlivOS MCP 调试入口。在插件加载器子进程内运行，通过 Streamable HTTP 把宿主状态和受控操作暴露给 AI 客户端。

- 当前静态审阅基线：OlivOS **Release 1.0.2-beta.3**，commit [`c6a99fc2a3b4`](https://github.com/OlivOS-Team/OlivOS/tree/c6a99fc2a3b4cc7dd1ea8e7b6fe762b7bee7c7d4)。开发前会按 [开发流程](AGENTS.md#80-开发前识别最新上游源码) 核实上游最新发布版，正式版与测试版按发布时间选择。
- 本插件与配套 skill 版本：`v0.1.0`，不附加 SVN 版本号。
- 运行依赖只有 OlivOS 框架、Python 标准库和宿主发行环境本身提供的 `aiohttp`。不引入官方 MCP SDK，不依赖任何其他 OPK，也不依赖 OlivOS-Docker。

> **升级提示**：2026-11-08 起 `terminal_bot_id` 配置字段已移除——调试终端账号改由使用者在宿主账号配置中预置（详见 [虚拟终端调试账号](docs/reference.md#6-虚拟终端调试账号2026-11-08-契约变更)）。旧配置文件如残留该字段会被按未知字段拒绝（服务 fail-closed），请手动删除该行。

> **使用前必读的三条警示**
>
> 1. **明文 HTTP + Bearer key**：本项目不提供 TLS。`api_key` 与全部数据以明文 HTTP 传输；默认只监听 `127.0.0.1`，跨机访问请使用能到达该回环端点的 SSH 隧道，不要放宽 `listen_host`。容器部署时回环地址属于容器自己的网络命名空间。
> 2. **虚拟终端不是沙箱**：`cockpit_terminal_input` 触发的是普通插件消息回调，被触发的插件仍可能写真实文件/数据库、访问网络或产生其他真实副作用；`queued: true` 只表示入队。
> 3. **真实账号写默认关闭**：发送、重载、配置/账号写入都需要在 `config.json` 中显式开启 `full_real_account_write`（底层能力还需同时开启 `full_low_level_access`）。写操作超时后**不要自动重试**。

深度安全机制、失败边界与实现契约见 [docs/reference.md](docs/reference.md)；开发与验收见 [AGENTS.md](AGENTS.md)。

## 两个安装包

| 产物 | 工具数 | 内容 |
| --- | --- | --- |
| `OlivOSCockpit-v0.1.0.opk` | 61 | 受控读写与入站调试 |
| `OlivOSCockpitLite-v0.1.0.opk` | 35 | 受控只读 + 虚拟终端输入 |

工具数由静态注册表导出（Full `OlivOSCockpit/registry.py`，Lite `profiles/lite_registry.py`）。Lite 是 Full 的受控只读子集外加 `cockpit_terminal_input`（Lite 唯一写入口）；Lite 归档在打包时就不含 Full-only 写模块，不是运行时开关。两个包 `namespace` 相同，**互斥安装**。所有工具名统一以 `cockpit_` 开头；完整工具清单与参数以 `tools/list` 返回的静态 schema 为准，未声明的参数会被拒绝。

没有安全绑定的候选、hidden / blocked / internal 接口仅保留在 `interfaces.json` 台账，不出现在 `tools/list` 中，猜名调用同样失败。已绑定的工具不随权限或连接变化从表中删去，运行时能力缺失时返回 `isError`。

## 依赖与安装

- Python 3.11（与上游一致）、OlivOS 框架本身、宿主发行环境中可导入的 `aiohttp`。
- 从本仓库的 GitHub Releases 下载所需版本的 Full 或 Lite OPK；仓库不保存构建产物，正式发布由人工触发 GitHub Actions 完成。
- 把选中的 OPK 放入**当前 OlivOS 实例实际使用的插件包目录**（基线默认 `<cwd>/plugin/app/`；宿主配置不同时以实例实际 I/O 为准），按宿主常规方式加载。

## 首次配置

首次加载后的第一次配置轮询会在 `<插件数据根>/OlivOSCockpit/control/` 自动创建两个模板文件（`api_key` 为空），之后**只由人工编辑**；配置不经环境变量，也不通过 MCP 读写。

`config.json`：

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 8767,
  "api_key": "",
  "redaction_enabled": true,
  "lite_real_account_read": false,
  "full_real_account_write": false,
  "full_low_level_access": false,
  "denied_paths": []
}
```

- `api_key` 为空时服务不监听；格式为 `OlivOS-` + 32–64 位 ASCII 字母数字，且必须同时含大写、小写和数字。
- 编辑保存后插件在 1 秒轮询内热更新，无需重启；改端口/地址会先停旧监听再绑定，轮换 `api_key` 会使已有传统会话失效。
- 配置无效、文件被删或改坏时 fail-closed：服务停止监听并清空会话，不会重建模板，也不会匿名放行；恢复合法配置后才重新放行。
- Full 与 Lite 若共用同一数据根，会共享同一组配置文件（互斥安装，不会同时运行）。

`redaction.json` 模板为 `{"redact_fields": [], "allow_fields": []}`；字段规则按完整字段名、大小写不敏感精确匹配，优先级为用户 `allow_fields` > 用户 `redact_fields` > 内置凭据字段。关闭脱敏（`redaction_enabled: false`）后返回未清理的应用值，未知业务秘密无法被识别。规则细节见 [客户端输出脱敏](docs/reference.md#5-客户端输出脱敏)。

## 权限开关

配置有效且 `api_key` 非空是任何调用的前提：

| 开关 | 默认 | 放行内容 |
| --- | --- | --- |
| （Full 无需开关） | 允许 | 真实账号读（仍受路径、字段白名单与资源上限约束） |
| `full_real_account_write` | 关 | Full：发送、重载、插件配置/配置文件更新、账号存档更新 |
| `full_low_level_access` | 关 | Full：`cockpit_proc_get`、`cockpit_intercept_rules`（还需 Full 写同时开启） |
| `lite_real_account_read` | 关 | Lite：真实账号查询、账号存档、日志、插件数据、真实原始事件 |
| （无需开关） | — | `cockpit_terminal_input`（Lite 唯一写入口；虚拟终端非沙箱；需在宿主账号配置中预置 `terminal_link/terminal/default` 账号并重启宿主，未预置时明确停用） |

## MCP 接入

默认端点 `http://127.0.0.1:8767/mcp`（随 `listen_host` / `listen_port` 变化）。客户端必须发送：

```text
Authorization: Bearer <config.json 中的 api_key>
Content-Type: application/json
Accept: application/json, text/event-stream
```

只返回 JSON，不实现 SSE，不接受批量请求。`Origin` 存在且与 `listen_host` 不一致时返回 403（DNS rebinding 防护；不是认证）。

### 传统客户端（2024-11-05 / 2025-03-26 / 2025-06-18 / 2025-11-25）

1. POST `initialize`（`protocolVersion`、`capabilities`、`clientInfo` 必填；未知版本协商回落到 `2025-11-25`），响应头返回 `Mcp-Session-Id`。
2. 带会话 ID 发送 `notifications/initialized`，返回 202 空正文。
3. 后续请求携带会话 ID 与已协商的协议版本头；版本头与协商值不一致返回 400。
4. 会话 30 分钟过期、被淘汰、key 轮换或加载器重启后返回 404，客户端不带旧 ID 重新 `initialize`。

`2024-11-05` 仅通过本服务的 POST 绑定承载；先等 SSE `endpoint` 事件的原生 HTTP+SSE 老客户端不在支持范围。

### 现代客户端（2026-07-28）

每个请求携带 `_meta`，无需 `initialize` 或 `server/discover`：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

同时发送 `MCP-Protocol-Version: 2026-07-28`、`Mcp-Method: tools/list`；`tools/call` 还必须发送与 `params.name` 一致、按协议编码的 `Mcp-Name`。断线重试仍逐请求携带 `_meta`，不要求重新握手。

### 常见错误

| 现象 | 含义与处理 |
| --- | --- |
| `401` | 缺少或错误的 Bearer key；检查 `Authorization` 头 |
| `403` | `Origin` 与 `listen_host` 不一致 |
| `400 / -32020` | 现代必填头缺失或不一致（优先于版本错误） |
| `400 / -32022` | 版本不在支持集（现代信封即使携带传统版本号也一样；`supported` 只含 `["2026-07-28"]`） |
| `400 / -32602` | 缺少必需 `_meta` 字段（`protocolVersion`、`clientCapabilities`） |
| `404 / -32601` | 未实现的 method |
| `404`（会话） | 传统会话未知/过期/淘汰/key 轮换：重新 `initialize` |
| `503` | 并发名额满（入口与 worker 是两套独立 8 名额），立即返回不排队 |
| `408` | 请求体读取超时 |
| 游标失效 | `cockpit_data` 续读游标 5 分钟过期，或文件修订/清洗上下文/配置代次变化：从头重新读取 |
| 写超时 | 调用可能仍在执行且占用名额：**不要自动重试**，先读回状态 |

工具自身失败用 `isError: true` 表示，不是 JSON-RPC 协议错误。

## 给 AI 代理的使用 skill

[使用技能入口](skills/olivos-cockpit/SKILL.md) 面向通过 MCP 操作本插件的 agent，覆盖工具发现、排障、数据续读、虚拟终端输入、权限与受控写入；不是开发或构建手册。

从同一 Release 下载 `olivos-cockpit-skill-v0.1.0.zip`，解压后将整个 `olivos-cockpit/` 目录（含 `references/`）按所用 Agent 客户端的技能机制安装或提供给 agent，并先完成上面的 MCP 接入。也可使用仓库的 `skills/olivos-cockpit/` 源文件。OPK 不会自动替客户端安装 skill；加载 skill 也不代表授权写操作，仍需用户意图与服务端权限共同允许。请让 skill 与 OPK 保持同一版本；开发本插件请看 [AGENTS.md](AGENTS.md)。

## 人工发布（维护者）

1. 同步 `app.json.version`、`contracts.VERSION`、skill 的 `metadata.version` 与版本文案，更新 README 的附件名并完成开发验收。三个版本必须一致，格式如 `v0.1.0`；预发布版本可使用 `v0.2.0-beta.1`。插件不使用自身 `svn`，保留 `compatible_svn`。
2. 将待发布源码放到 GitHub 的 `main` 分支，在 **Actions → Release → Run workflow** 中选择 `main`、填写版本并人工运行。推送代码、tag 或上游发版均不会自动触发本工作流。
3. 工作流校验版本及已有 tag 的 commit，预留草稿后，在 Python 3.11 + `aiohttp` 下执行单元、HTTP 与打包回归，然后构建并上传 Full OPK、Lite OPK、同版本 skill ZIP 三个附件，最后发布该草稿。tag 不存在时按本次运行的固定 commit 创建；已有公开版本不会被覆盖。上游源码 AST 和真实加载器验收由开发者在隔离环境另行启用，不能把发布测试的 skipped 当作已验证。

首次发布只列出已有功能；以后按最近仍公开存在的 Release 到当前 commit 生成简短的“新增 / 优化 / 修复”。建议功能提交使用 `feat:`、修复使用 `fix:`，性能或重构使用 `perf:` / `refactor:`；`docs/test/ci/build/chore/style` 提交不列入说明，其他标题归为优化。

测试或构建失败会保留草稿；临时故障可重跑原任务，源码修正后则需删除旧草稿，从更新后的 `main` 重新人工触发（已有同版本 tag 必须指向本次 commit）。需要撤版时在 GitHub 删除对应 Release 或转回草稿。下次发布按实际公开的 Release 重新选择比较起点，遗留 tag 不会使撤回版本的变化漏记。若在工作流执行期间删除当前草稿，上传或发布会失败；重跑旧任务不会重新创建已删除的草稿，需要重新人工触发。仓库仅保存源码，构建目录、缓存和本地账号数据不提交；本地定点验证构建方法见 [AGENTS.md §8.2](AGENTS.md#82-定点与全量命令)。

## 参考项目与许可

- 上游框架：[OlivOS-Team/OlivOS](https://github.com/OlivOS-Team/OlivOS)（main 分支 LICENSE 为 **AGPL-3.0**；本插件与其衍生边界以 FSF 解释与上游声明为准，本项目自身许可由维护者另行确定后在同处声明）。
- 插件开发文档：[OlivOSDoc](https://github.com/OlivOS-Team/OlivOSDoc)、[OlivOSPluginTemplate](https://github.com/OlivOS-Team/OlivOSPluginTemplate)。
- MCP 规范：[modelcontextprotocol/modelcontextprotocol](https://github.com/modelcontextprotocol/modelcontextprotocol)（MIT → Apache-2.0 过渡多许可，文档 CC-BY-4.0）、[python-sdk](https://github.com/modelcontextprotocol/python-sdk)（MIT，本项目未引入其代码与依赖）。
- 其余引用以各仓库 LICENSE 文件为准；本项目不依据未经核实的外部许可组合做法律定论。
