# OlivOS Cockpit

以 OPK 插件形式运行在 [OlivOS](https://github.com/OlivOS-Team/OlivOS) 插件加载器内的 MCP 调试入口，把宿主状态和受控操作暴露给 MCP 客户端。当前版本 `v0.1.0`。

## 免责声明与危险警告

本项目按现状提供，使用者应自行评估并承担使用风险。

- **明文 HTTP**：本项目不提供 TLS，`api_key` 与全部数据以明文 HTTP 传输。默认只监听 `127.0.0.1:8767`；跨机访问请使用能到达该回环端点的 SSH 隧道，不要直接放宽 `listen_host`。容器内的回环属于容器自己的网络命名空间。
- **数据暴露**：工具可读取日志、插件数据、账号信息等宿主内容。脱敏默认开启，但可由配置关闭，且只覆盖已核实字段；未知业务秘密仍可能泄露。不要把服务暴露给不受信任的客户端。
- **Full 写操作**：真实账号写默认关闭。开启 `full_real_account_write` 后才允许发送消息、重载、插件配置/配置文件更新和账号存档更新；底层能力还需同时开启 `full_low_level_access`。重载会重启整个插件加载器（含本服务）；写操作超时可能仍在执行，不要自动重试。
- **宿主进程可靠性**：插件运行在 OlivOS 插件加载器内；宿主或插件的 C 级缺陷、死循环、内存耗尽或崩溃仍可能中断服务，本项目不能保证避免。

## 使用说明

**依赖与安装**：Python 3.11、OlivOS 框架本身、宿主发行环境可导入的 `aiohttp`。不引入官方 MCP SDK，不依赖其他 OPK，也不依赖 OlivOS-Docker。从 GitHub Releases 下载所需版本的 OPK，放入当前实例实际使用的插件包目录（默认 `<cwd>/plugin/app/`；以宿主实际 I/O 为准），按宿主常规方式加载。

**Full / Lite**：两个包 `namespace` 相同，**互斥安装**。Full 默认允许真实账号读取（仍受路径、字段与资源上限约束）；Lite 默认关闭真实账号读取，需开启 `lite_real_account_read` 才允许受限文件与账号读取。Lite 在打包时剔除 Full-only 写模块，不是运行时开关。

| 产物 | 工具数 | 内容 |
| --- | --- | --- |
| `OlivOSCockpit-v0.1.0.opk` | 61 | Full：受控读写与底层调试 |
| `OlivOSCockpitLite-v0.1.0.opk` | 35 | Lite：受控只读 + 终端输入 |

Full 与 Lite 若共用同一数据根，会共享 `control/` 下的同一组配置文件；因互斥安装，不会同时运行。

**首次配置**：插件数据根由宿主配置决定，默认是宿主运行目录下的 `plugin/data`。首次加载时会在 `<插件数据根>/OlivOSCockpit/control/` 自动创建 `config.json` 和 `redaction.json`，之后只由人工编辑；不经环境变量，也不通过 MCP 读写。`api_key` 初始为空，必须改为 `OlivOS-` 加 32–64 位 ASCII 字母数字，且同时含大写、小写和数字；为空或配置无效时服务不监听。

`config.json` 字段：

| 字段 | 说明 |
| --- | --- |
| `listen_host` / `listen_port` | 监听地址与端口，默认 `127.0.0.1:8767`。 |
| `api_key` | Bearer 认证 key，格式见上。 |
| `redaction_enabled` | 是否脱敏，默认 `true`；关闭后返回未清理的应用值。 |
| `lite_real_account_read` | Lite 是否允许受限文件与账号读取，默认 `false`。 |
| `full_real_account_write` | Full 是否允许写操作，默认 `false`。 |
| `full_low_level_access` | Full 底层能力，默认 `false`；还需 `full_real_account_write`。 |
| `denied_paths` | 拒绝访问的路径列表。 |

`redaction.json` 字段：`redact_fields` 与 `allow_fields`。规则按完整字段名大小写不敏感匹配，优先级为 `allow_fields` > `redact_fields` > 内置凭据字段。

配置每秒轮询一次，连续两次指纹一致后才发布；保存后不会立即生效，也不承诺固定时延。改端口或地址会先停旧监听再绑定；轮换 `api_key` 会使已有会话失效。文件被删除、写坏或配置无效时停止监听并清空会话，不重建模板；恢复合法配置后重新监听。

**客户端接入（Streamable HTTP）**：先配置好 `api_key` 并保持 OlivOS 运行。以下使用同机默认地址，`<api_key>` 替换为 `config.json` 中的值。

**[Claude Code](https://code.claude.com/docs/en/mcp-quickstart)**：在终端执行：

```sh
claude mcp add --transport http --scope user olivos-cockpit http://127.0.0.1:8767/mcp --header "Authorization: Bearer <api_key>"
```

**[Codex](https://developers.openai.com/codex/mcp)**：添加到 `~/.codex/config.toml`：

```toml
[mcp_servers.olivos-cockpit]
url = "http://127.0.0.1:8767/mcp"
http_headers = { Authorization = "Bearer <api_key>" }
```

**[DSH（DeepSeek Harness）](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.zh.md)**：追加到配置目录下的 `cordis.patch.yml`（默认 `~/.dsh/cordis.patch.yml`，保留原有配置）：

```yaml
- insert:
    - id: olivos-cockpit-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: olivos-cockpit
        transport: streamable-http
        url: http://127.0.0.1:8767/mcp
        headers: { Authorization: "Bearer <api_key>" }
```

配置后重开客户端；Claude Code / Codex 中输入 `/mcp` 查看连接状态。

**可选 skill**：同版本 `olivos-cockpit-skill-v0.1.0.zip` 供 agent 阅读，指导其使用插件全部已发布功能。从同一 Release 下载后，将整个 `olivos-cockpit/` 目录（含 `references/`）按客户端技能机制安装。skill 不改变服务端权限；OPK 不会自动安装它。

**调试终端账号（使用者预置）**：在 OlivOS 账号编辑器中选择“虚拟终端”，创建使用整数 ID 的账号并启用，然后重启整个宿主；不要选“接口终端”或 FF14 模型。配置中没有 `terminal_bot_id` 字段。没有合格账号时 `cockpit_terminal_input` 明确停用并返回错误，其他只读工具不受影响。

## 参考项目

- [OlivOS](https://github.com/OlivOS-Team/OlivOS)：运行宿主；本项目通过其插件机制与 API 工作。
- [OlivaDiceCore](https://github.com/OlivOS-Team/OlivaDiceCore)：发布与插件样式参考。
- [OlivOSPluginTemplate](https://github.com/OlivOS-Team/OlivOSPluginTemplate) / [OlivOSDoc](https://github.com/OlivOS-Team/OlivOSDoc)：插件结构与开发文档参考。
- [MCP 规范](https://github.com/modelcontextprotocol/modelcontextprotocol) / [python-sdk](https://github.com/modelcontextprotocol/python-sdk)：协议与实现参考；本项目未引入其代码或依赖。

## 授权许可

本项目代码与 `skills/olivos-cockpit/` 采用 **AGPL-3.0-or-later**，完整条款见根目录 [`LICENSE`](LICENSE)。两个 OPK 与 skill ZIP 均携带该文件。源码：https://github.com/cary17/OlivOS-Cockpit 。

本项目使用 [OlivOS](https://github.com/OlivOS-Team/OlivOS)，上游以 AGPL-3.0-or-later 发布并要求衍生项目声明来源；本项目未包含 OlivOS 源码。OlivOS 的形象图、图标及相关介绍文字的权利不属于本项目许可范围。

参考项目仍适用其各自 LICENSE；若后续复制其代码或文档，需保留相应版权、许可与归属声明。
