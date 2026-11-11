# OlivOS Cockpit

以 OPK 插件形式运行在 [OlivOS](https://github.com/OlivOS-Team/OlivOS) 插件加载器内的 MCP 调试入口，把宿主状态和受控操作暴露给 MCP 客户端。

## 使用前必读：危险警告

> [!WARNING]
> **只在隔离的沙箱/测试实例中调试使用。不要部署到生产环境，不要把服务暴露到公网或不受信任的网络。** 本项目不提供 TLS，`api_key` 与数据以明文 HTTP 传输，传输路径上的节点可能窃取凭据和数据。默认回环地址用于限制可达范围；跨机访问优先通过 SSH 隧道保护传输，仍应只用于隔离的调试环境。
>
> **授予 AI 权限的后果由使用者承担。** 工具可以读取宿主数据、发送消息、修改配置与账号、安装或替换插件包、重启插件加载器。使用者必须理解自己授予或放任 AI 使用的能力，并对授权操作造成的后果负责，包括数据泄露或丢失、账号与消息影响、服务或业务中断，以及执行第三方 OPK 代码。授权前确认目标、内容和影响；只开启完成当前调试所必需的最小权限。
>
> **安装校验不是沙箱。** `cockpit_plugin_install` 只校验包结构、目标路径和覆盖边界。被安装的 OPK 不是被隔离运行的：它在后续加载时以 OlivOS 宿主进程权限执行，即使这次重启由宿主自动策略或外部操作触发。只安装你信任的代码。

## 免责声明

本项目按现状提供，使用者应自行评估并承担使用风险。

- **数据暴露**：工具可读取日志、插件数据、账号信息等宿主内容。脱敏默认开启，但可由配置关闭，且只覆盖已核实字段；未知业务秘密仍可能泄露。不要把服务暴露给不受信任的客户端。
- **Full 写操作**：真实账号写默认关闭。开启 `full_real_account_write` 后才允许发送消息、重载、插件配置/配置文件更新和账号存档更新；插件安装还需独立的 `full_plugin_install`，底层能力还需同时开启 `full_low_level_access`。重载会重启整个插件加载器（含本服务）；写操作超时可能仍在执行，不要自动重试。
- **宿主进程可靠性**：插件运行在 OlivOS 插件加载器内；宿主或插件的 C 级缺陷、死循环、内存耗尽或崩溃仍可能中断服务，本项目不能保证避免。

## 使用说明

**依赖与安装**：Python 3.11、OlivOS 框架本身、宿主发行环境可导入的 `aiohttp`。不引入官方 MCP SDK，不依赖其他 OPK，也不依赖 OlivOS-Docker。从 GitHub Releases 下载所需版本的 OPK，放入当前实例实际使用的插件包目录（默认 `<cwd>/plugin/app/`；以宿主实际 I/O 为准），按宿主常规方式加载。

**运行平台**：OPK 是与 CPU 架构无关的 Python 包，同一份 Full/Lite 包面向 Linux x64/ARM64、Windows x86/x64/ARM64 与 macOS x64/ARM64；按宿主提供 Python 3.11 和 `aiohttp` 运行，不需要按架构重新打包。Windows 文件安全后端使用系统原生接口，不增加第三方依赖，并保留路径边界、权限和失败关闭规则。自动化 CI 会在这些 OS/架构组合上运行测试和 Full/Lite 构建检查；这不等同于在每种 OlivOS 实际发行包、二进制宿主或容器中的运行验收，具体部署仍须按宿主环境核实。

**Full / Lite**：两个包 `namespace` 相同，**互斥安装**。Full 默认允许真实账号读取（仍受路径、字段与资源上限约束），并提供受控写入与插件安装；Lite 默认关闭真实账号读取，需开启 `lite_real_account_read` 才允许受限文件与账号读取。Lite 在打包时剔除 Full-only 写模块，不是运行时开关。

| 产物 | 工具数 | 内容 |
| --- | --- | --- |
| `OlivOSCockpit.opk` | 62 | Full：受控读写、插件安装与底层调试 |
| `OlivOSCockpitLite.opk` | 35 | Lite：受控只读 + 终端输入 |

Full 与 Lite 若共用同一数据根，会共享 `control/` 下的同一组配置文件；因互斥安装，不会同时运行。两个 OPK 与配套 skill ZIP 使用同一发布版本，版本号不一致不代表某次修复已经部署。

**首次配置**：插件数据根由宿主配置决定，默认是宿主运行目录下的 `plugin/data`。首次加载时会在 `<插件数据根>/OlivOSCockpit/control/` 自动创建 `config.json` 和 `redaction.json`，之后只由人工编辑；唯一例外是端口回退成功后的 `listen_port` 自动写回。配置不经环境变量，也不通过 MCP 读写。`api_key` 初始为空，必须改为 `OlivOS-` 加 32–64 位 ASCII 字母数字，且同时含大写、小写和数字；为空或配置无效时服务不监听。

`config.json` 字段：

| 字段 | 说明 |
| --- | --- |
| `listen_host` / `listen_port` | 监听地址与端口，默认 `127.0.0.1:8767`；8767 只是示例默认值，实际端口以监听成功日志为准（本机也可直接查看 `config.json` 的 `listen_port`）。 |
| `api_key` | Bearer 认证 key，格式见上。 |
| `redaction_enabled` | 是否脱敏，默认 `true`；关闭后返回未清理的应用值。 |
| `lite_real_account_read` | Lite 是否允许受限文件与账号读取，默认 `false`。 |
| `full_real_account_write` | Full 是否允许写操作，默认 `false`。 |
| `full_plugin_install` | Full 插件安装的独立开关，默认 `false`；还须 `full_real_account_write` 同时开启。旧配置缺少该字段仍有效，按 `false` 处理。 |
| `full_low_level_access` | Full 底层能力，默认 `false`；还需 `full_real_account_write`。 |
| `denied_paths` | 拒绝访问的路径列表。 |

`redaction.json` 字段：`redact_fields` 与 `allow_fields`。规则按完整字段名大小写不敏感匹配，优先级为 `allow_fields` > `redact_fields` > 内置凭据字段。

配置每秒轮询一次，连续两次指纹一致后才发布；保存后不会立即生效，也不承诺固定时延。改端口或地址会先停旧监听再绑定。端口被占用时会在有界范围内依次尝试后续正整数端口（不接受端口 0），并让 IPv4/IPv6 使用同一个实际端口；只有真实绑定成功后，manager 才把 `listen_port` 写回 `config.json`，其余本地配置保持不变。该自动写回不保证与并发外部编辑构成 compare-and-swap，多人同时改配置时应先协调。若回退后的候选绑定失败或配置已过期，候选监听关闭；实际端点以监听成功日志为准，客户端必须改用实际端口；本机使用者也可直接查看 `config.json` 的 `listen_port`，不要通过 MCP 读取控制文件。轮换 `api_key` 会使已有会话失效；文件被删除、写坏或配置无效时停止监听并清空会话，不重建模板；恢复合法配置后重新监听。

**插件安装与更新（仅 Full）**：`cockpit_plugin_install` 需要 `full_real_account_write` 与 `full_plugin_install` 同时开启；Lite 包物理不含该实现。它通过 `begin` / `write` / `commit` / `cancel` 四个动作接收一个完整的 `.opk`：包体 ≤8 MiB，原始分块 ≤512 KiB（base64 ≤699052 字符），全局同时最多一个待上传包，固定 5 分钟过期，并绑定请求 owner 与配置代次。

- 服务端路径根是宿主 `OlivOS.pluginAPI.plugin_path`（相对初始化上下文根解析），MCP 请求不能指定任意绝对路径，也不能读写本插件控制数据或覆盖 Cockpit 自身包。客户端本地的文件读取、源码打包权限属于客户端自身环境，与服务端 MCP 路径权限无关；服务端只处理上传的包内容，不会读取客户端本地路径。不要把完整 base64 包体粘贴到对话中。
- 同 `namespace` 覆盖明确允许，**不需要旧包 SHA-256，也没有替代的旧内容修订门槛，不需要 force 开关**。旧包可能因此被替换丢失；有外部写入方时应先协调，本项目不保证跨进程 compare-and-swap。`commit` 必须携带本次**新包**的完整 SHA-256（64 位十六进制），服务端据此核验上传字节与最终落盘内容，不匹配会拒绝，成功结果也返回该值供核验；它与旧包判断无关。普通文件/账号更新的 `expected_sha256` 规则不变。
- 官方包格式是 ZIP 根部直接放置插件目录内容（`app.json`、`__init__.py`、`main.py` 及 `resources` 等），不要再套一层文件夹；`app.json` 使用 UTF-8 无 BOM。已有 `.opk` 应保持字节不变；从本地源码打包时用客户端自己的文件/zip 能力（无需安装 OlivOS），不要导入或执行被安装源码及构建脚本，并排除本地密钥、VCS、缓存、虚拟环境和构建产物。
- 上传只完成持久化与校验，**不会自动重载插件，也不自动启用新代码**。需要加载器重载时，`cockpit_reload` 是另一项需要用户明确授权的整加载器操作，不是单插件热重载；否则等待使用者安排宿主重启。结构校验不构成沙箱，包内代码在后续加载（含自动或外部触发的重启）时以宿主进程权限运行。

**客户端接入（Streamable HTTP）**：先配置好 `api_key` 并保持 OlivOS 运行。以下使用同机默认地址；8767 只是示例默认值，端口回退后必须改用监听成功日志中的实际端口；本机也可查看 `config.json` 的 `listen_port`，但不要通过 MCP 读取控制文件。`<api_key>` 替换为 `config.json` 中的值。

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

**可选 skill**：同版本 `olivos-cockpit-skill.zip` 供 agent 阅读，指导其使用插件全部已发布功能。从同一 Release 下载后，将整个 `olivos-cockpit/` 目录（含 `references/`）按客户端技能机制安装。skill 不改变服务端权限；OPK 不会自动安装它。

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
