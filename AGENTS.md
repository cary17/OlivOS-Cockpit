# OlivOS Cockpit（开发指引）

OlivOS 的 MCP 调试工具。以 OPK 插件形态运行在 OlivOS 插件加载器内，把 OlivOS 的运行状态与操作能力暴露给 AI 客户端。

**文档分工**：README.md 面向真人使用者（安装、配置、风险提示与许可）；skills/olivos-cockpit/ 面向通过 MCP 使用插件的 agent，指导使用全部已发布功能；docs/reference.md 承接协议接入、工具行为、深度安全机制与失败边界；interfaces.json 是固定上游版本的静态阅读台账。**本文件是开发 agent 的唯一指令来源**；与源码不一致时以源码为准，并顺手更正本文件。用户用法、逐工具参数表和接口台账数字不在本文件复述——以 registry 导出、`tools/list` schema 与 interfaces.json 为准，这里只留指针。

设计覆盖源码运行、打包二进制和容器部署；不依赖容器入口脚本或固定安装位置。实际兼容范围以已验证的 OlivOS 版本、平台与运行环境为准。

同时支持 MCP 的两个时代：**现代**（2026-07-28，无握手、无状态）与**传统**（2025-11-25 及更早，`initialize` 握手）。同一端口、同一份代码，按请求自动分派。

**开发源码基线**：每次开始开发前，按 §8.0 自动查询上游最新公开 Release；正式版和测试版一起按发布时间选择，以对应 commit 的源码为本次开发基线，不能把下面的历史审阅版本当作永久开发目标。

**当前已审阅基线**：OlivOS Release **1.0.2-beta.3**，commit [`c6a99fc2a3b4`](https://github.com/OlivOS-Team/OlivOS/tree/c6a99fc2a3b4cc7dd1ea8e7b6fe762b7bee7c7d4)（2026-11-11 核实时仍为最新发布版）。对该版本的完整静态阅读台账为仓库根目录的 `interfaces.json`（分区与计数见 docs/reference.md §1）。本插件与配套 skill 版本统一为 `v0.1.0`，不使用插件自身的 SVN 版本号；`compatible_svn` 是独立的宿主兼容闸门，仍保留。

## 开发约定

- 基线语言为 Python 3.11，与上游项目（https://github.com/OlivOS-Team/OlivOS）保持一致。
- 兼容性以实测为准：只宣称已在指定 OlivOS 版本 / SVN 或 commit 上验证的结论；版本范围未验收前不声明最小支持版本。
- 代码兼容性优先于美观；优先使用已核实的稳定 API，非稳定属性做能力探测，缺失能力保留工具并安全失败；对上游未来版本尽力兼容，不做无限承诺。
- MCP 开发严格按规范标准实现，复用宿主框架现有组件，尽量减少额外依赖。
- 本插件不依赖任何其他 OlivOS 插件；依赖边界见 §3.3。
- 交付形态：`OlivOSCockpit-<version>.opk` / `OlivOSCockpitLite-<version>.opk`，另有同版本 `olivos-cockpit-skill-<version>.zip`。数量由静态注册表导出并由构建与测试核对。工具清单与行为细节见 registry 导出与 docs/reference.md；本文件不复述。

---

## 1. 项目介绍

### 1.1 要解决的问题

OlivOS 是 Python 机器人框架，插件是一堆被宿主动态加载的模块。出问题时，排查手段只有翻日志、看宿主运行状态、逐个 opk 解包看 `app.json`。AI 拿不到结构化入口。

本项目提供一层 MCP 接口，让 AI 能直接读日志、读插件数据、查账号信息，必要时主动发消息或请求重启插件加载器。

### 1.2 为什么是插件而不是独立进程

OlivOS 的关键状态（`Proc` 对象：`bot_info_dict`、`plugin_models_dict`、插件实例）位于**插件加载器子进程**的内存中，不在总控进程；外部进程拿不到。

```
独立进程   只能读文件（日志、数据、配置、opk 元数据）
插件内     文件 + 加载器内存状态，两者都能拿
```

要访问这些内存状态，插件必须被加载器加载（进程结构见 §3.1）。

### 1.3 核心矛盾

同进程意味着插件缺陷可能拖垮其所在的插件加载器子进程，并中断 OlivOS 的插件运行。这是本项目最重要的设计约束，也是所有技术选择的出发点（见 §2）。

---

## 2. 约束（始终生效的硬规则）

### 2.1 不得拖垮 OlivOS

OlivOS 对插件回调做了 `except Exception` 兜底（`core/core/pluginAPI.py`），但不覆盖：

```
BaseException         SystemExit / KeyboardInterrupt 会穿透
插件自建的线程        OlivOS 不管，线程内异常自己承担
```

兜底边界与做法：

```
宿主回调入口        捕获 BaseException，记录安全日志（不记录凭据或敏感值），不上抛
后台线程顶层        捕获 BaseException，转入结构化错误或安全日志，线程不因未处理异常退出
调用宿主 SDK 处     对可能抛出的调用单独捕获 BaseException，转成工具的结构化错误
```

`asyncio.CancelledError` 是例外，不作为错误吞掉：它必须在 `finally` 完成清理后继续传播到本服务私有的 asyncio 事件循环，遵循 Python 3.11 取消语义，不跨越宿主回调边界传出。同步宿主观察路径（raw 观察器）没有可传播的 asyncio 任务，其自身异常（含构造期取消）转为 drop 计数，原宿主调用仍恰好执行一次；两条取消语义不可混用。捕获异常只能避免未处理异常逃逸，不能停止已阻塞的线程，也不能保证避免 OOM。

### 2.2 进程级禁令

以下操作会破坏 OlivOS 的运行假设，一律禁止：

```
signal.signal()                      覆盖宿主信号处理，干扰优雅退出
sys.exit() / os._exit()               前者可结束当前线程或加载器；后者立即终止加载器进程
sys.excepthook / threading.excepthook  影响加载器内所有插件的异常行为
修改 logging 根 logger 的 handler    改动宿主的日志处理
os.chdir()                           其他插件可能依赖相对路径
重定向 sys.stdout / sys.stderr        污染 OlivOS 日志
```

### 2.3 资源

内存耗尽可能使加载器或宿主相关进程异常或被终止；容器部署还受容器内存限额约束。请求体之外，日志、文件、目录、OPK 等读取也必须先有界再序列化，使用以下保守设计常量（非用户配置，发布前须验收；权威定义在 `OlivOSCockpit/contracts.py` 与各模块）：

```
单请求体                 ≤ 1 MiB
日志扫描总量             ≤ 8 MiB，单次返回 ≤ 2000 行
单次文件源读取           ≤ 1 MiB；数据续读不提高单次读取与响应预算
数据续读游标             ≤ 1024 字符、签发后 5 分钟到期、无状态签名，不缓存正文
目录条目                 ≤ 500 条/次，超出截断并标记
OPK 包体 / 中央目录      ≤ 8 MiB / 256 KiB，最多 1024 项；拒绝 ZIP64、多卷和加密
OPK app.json 实际解压量   ≤ 64 KiB，超限报错，仅读元数据，不 extractall
响应 UTF-8 序列化后大小   ≤ 1 MiB
并发在途调用             ≤ 8，达到上限立即返回 503，不排队
                          （两套独立 8 名额：全部 HTTP 请求占入口名额；
                          tools/call 另占 worker 名额；超时释放 HTTP 等待
                          不代表尚未结束的 worker 名额已归还）
工具调用等待预算         ≤ 10 秒
legacy 会话              TTL 30 分钟，最多 256 个，先清过期，再淘汰最旧
cockpit_proc_get 嵌套深度 ≤ 8 层
原始事件缓存             ≤ 256 条、单条 ≤ 64 KiB、总量 ≤ 4 MiB、保留 5 分钟、单次返回 ≤ 8 条
配置 / 脱敏文件          单文件 ≤ 64 KiB；denied_paths ≤ 256 条；脱敏规则各 ≤ 256 条、字段 ≤ 128 字符
原始事件单次读取         ASCII JSON ≤ 256 KiB
脱敏单串匹配/转义片段    各 ≤ 20000
账号存档                 文件 ≤ 1 MiB、账号 ≤ 500、单页 ≤ 50
入站拦截                 ≤ 16 条规则、单文本 ≤ 64 KiB、规则总量 ≤ 256 KiB
脱敏遍历                 深度 ≤ 16，节点 ≤ 20000
脱敏单串 / 累计扫描      ≤ 1048576 / 4194304 字符
脱敏匹配工作预算         ≤ 67108864 字符单位（扫描计数，不是耗时保证）
已知凭据快照             ≤ 500 账号、256 条非空唯一字符串
凭据单条 / 总量          ≤ 4096 / 65536 字符，逐次快照、不缓存历史值
```

先做有界读与内容截断，再对待发送副本脱敏并序列化；最终响应超限时裁剪工具内容、标记截断并重新序列化，保留完整 JSON-RPC 信封，不能截断已编码的 JSON 字节。`cockpit_data` 在最终边界清洗完整有界源内容后，按完整响应预算分页其干净视图；不能安全确认记录边界时拒绝，不按裸字节独立脱敏。脱敏预算按单次清理遍历/凭据快照计，文本由同一份干净的结构化结果生成。会话只保存协商与到期处理所需的有限元数据，不保存请求或响应全文；数据续读无服务端页面缓存。

SDK 调用优先使用其自身超时；等待预算耗尽时返回明确错误，不保证撤销已发出的写操作。超时或取消只结束等待，未真正结束的调用继续占用并发名额，不能强杀线程、补开线程或无界提交 `to_thread`；未安全绑定的宿主能力仅内部登记，不发布占位工具；已绑定工具在目标运行时能力缺失时安全失败。

```
内存缓存         不存日志全文、不存媒体文件
初始化           init_after 只起线程，不做阻塞 I/O
```

### 2.4 网络

```
监听             config.json 的 listen_host / listen_port（默认 127.0.0.1:8767）
认证             Authorization: Bearer <api_key>；api_key 为空或配置无效时不监听
Origin 校验      存在时必须与 listen_host 一致，否则 403（DNS rebinding 防护，规范 MUST）
```

监听地址可配置，包括非回环地址，但本项目不提供 TLS：Bearer key 与数据以明文 HTTP 传输，跨网络使用等于把凭据和数据暴露给路径上的所有节点。默认保持回环；推荐跨机访问走能到达该回环端点的 SSH 隧道，而不是放宽 `listen_host`。容器部署时回环属于容器自己的网络命名空间，不能默认与容器外宿主相同。

### 2.5 协议合规

```
两代版本均须满足各自规范中的 MUST 条款
现代：逐请求 _meta、HTTP 头校验、resultType、ttlMs/cacheScope
传统：initialize 握手、会话 ID、宽松头处理
```

### 2.6 配置与权限

配置和脱敏规则是宿主插件数据目录中的本地文件，**不通过环境变量提供，也不通过 MCP 暴露**：

```
<插件数据根>/OlivOSCockpit/control/config.json
<插件数据根>/OlivOSCockpit/control/redaction.json
```

`<插件数据根>` 由 `OlivOS.infoAPI.OlivOS_plugin_data_path` 解析：绝对路径直接用，相对路径（基线 `./plugin/data`）按初始化时保存的宿主 cwd 拼接（§3.1）。

```
首次轮询        自动创建模板，api_key 为空；之后只由人工编辑
热更新          1 秒轮询；指纹变化先撤权（verifying），连续两次一致后发布
删除 / 损坏      不重建、不沿用旧快照；服务停止监听并清空会话（fail-closed）
MCP 读写         本插件数据 namespace（含 control 目录及两份文件）永久拒绝；不因其他插件使用同名文件而放宽或误禁路径
Lite / Full     互斥安装，若共用同一数据根则共享同一组文件
```

默认权限（配置有效且 `api_key` 非空才谈得上放行）：

```
Full 真实账号读      默认允许；仍受路径、字段白名单与资源上限约束
Full 真实账号写      默认关闭；发送、重载、插件配置/文件更新与账号存档更新需要 full_real_account_write
Full 底层能力        需要 full_real_account_write + full_low_level_access 同时开启
Lite 真实账号读      默认关闭；开启 lite_real_account_read 后才允许文件与账号读取
Lite 写入口          cockpit_terminal_input（虚拟终端输入），不受上述开关约束
```

发送、重载、插件配置/配置文件更新和账号存档更新绑定 `real_account_write`；`cockpit_proc_get` 与 `cockpit_intercept_rules` 绑定 `low_level_access`，同时要求 Full 写与底层开关。敏感 handler 内与提交前均复核权限/请求代次，不将 `readOnlyHint` 当授权。`cockpit_terminal_input` 不使用真实写开关，是 Lite 唯一写入口。虚拟终端不是沙箱：被触发插件仍可能写真实文件/数据库、访问网络或产生其他副作用。

控制目录、`denied_paths`、OlivOS 运行数据范围之外的路径及宿主源码写入属于最高禁令。普通文件读取限于日志、插件包元数据与其他插件数据 namespace；Full 文件更新另限已有非执行文本配置，账号存档另从磁盘启动配置解析。源码、插件包及本插件控制数据均不可写；数据根只来自受信任宿主上下文，MCP 请求不能扩根。写入格式、提交后核验与运行生效边界见 [受限写入与入站规则](docs/reference.md#4-受限写入与入站规则)。

### 2.7 出站脱敏

两版默认开启（`redaction_enabled: true`），但这是用户可关闭的配置项，不是不可绕过的强制层。关闭后仍校验 JSON 形状、有限浮点、深度/节点/扫描预算。字段规则按完整字段名 case-insensitive 精确匹配，优先级为**用户 allow_fields > 用户 redact_fields > 内置凭据字段**；内置规则只覆盖已核实的凭据字段及分隔符变体，不含泛化的手机号、邮箱、IP、路径、证件号或账号 ID 猜测。

数据续读的 `next_cursor` 在应用值清洗后生成，作为签名操作句柄保留；文件正文中的同名字段没有豁免，仍执行用户字段规则。游标绑定文件修订、namespace/path、配置代次及清洗上下文，变更后拒绝续读。

`cockpit_raw_events` 的观察范围仅为加载器 `proc.run_plugin` 转换前、经白名单投影的数据面事件，不覆盖适配器在接缝前丢弃的帧、控制面/菜单/WebUI 事件，也不拦截插件主动出站调用。因此不得宣称"原始流量全覆盖"。详细规则与协议保留项见 [客户端输出脱敏](docs/reference.md#5-客户端输出脱敏)。

---

## 3. 技术路线

### 3.1 运行形态

```
运行环境（源码 / 二进制；可选容器）
└── OlivOS 总控进程
    └── 插件加载器子进程（按上游设计启动/重启）
        └── OlivOSCockpit 插件
            ├── 配置监督 daemon 线程（1 秒轮询本地文件）
            └── 服务 daemon 线程 ── <listen_host>:<listen_port>/mcp（默认 127.0.0.1:8767）
```

插件在 `init_after` 里起配置监督线程；配置首次有效后，由同一个监督线程启动服务线程。线程均为 daemon，随加载器进程退出，不单独增加停服机制。加载器重启会结束本服务，重载范围见 §3.2，客户端恢复规则见 §3.4。

生命周期闭合要求：

- init 在第一个可能失败的操作前捕获旧 context/manager/thread；init 失败与 save 共用逐步拆除序列（manager 撤权停止 → 服务停止 → raw 卸载 → registry.detach 清规则），每步独立兜底并按对象身份去重。失败清 `_context/_manager/_target/_pending`；活 `_thread` 引用保留，由线程退出边缘按身份释放监督归属，不能清引用后补开另一个监督器。
- `Context` 保持冻结。同 Proc、root/data_root、OlivOS 引用及同一未停止 manager 全部相同才复用原 Context；来源变化走新 owner 并撤销旧 manager，不原地刷新路径字段。`_target` 只保留最新监督目标，旧循环返回后在同一把锁内决定接替或退出；旧 owner 的回调不能发布新状态。`ConfigManager.stop()` 清 pending、发布无 key 的失效快照并递增 generation，拒绝迟到发布。
- `_pending` 仅保存资源占位造成的待接替目标；健康 tick 只读检查终端，不反复 apply/reconcile。旧 refresh/SDK 阻塞时不承诺接替时延。服务在建池前保留唯一 `_STARTING` 启动位，旧池 `drained` 前不建新池；关闭的池拒绝新任务，不能把清 `_ACTIVE` 当成 worker 已退出。
- 托管发布前重查 manager 停止/快照失效；`request_stop` 先记住关闭再通知 loop。`_run_loop` 在 runner.setup 后才发布 loop，已停则不监听；首轮与后续轮次统一走 `_kick → _job`，不直接 reconcile。

**路径以宿主实际 I/O 上下文为准，不以部署形态或程序安装位置推断。** 优先复用经核实存在且语义匹配的 OlivOS 路径接口或资源配置，各类资源可有不同的允许根。宿主提供绝对路径时直接使用；相对路径才按其运行数据基准解析。仅在已确认宿主按 cwd 解析相对路径时，才在插件初始化阶段保存当时的 cwd 作为解析基准；不要求它等于源码目录或可执行文件目录。

在参考版本 `c6a99fc2a3b4` 中，`OlivOS/core/info/infoAPI.py` 的版本与路径常量为 `OlivOS_Version='1.0.2'`、`SVN=300`、`SVN_Compatible=190`、`OlivOS_plugin_data_path='./plugin/data'`。这是**相对路径常量，不是绝对根查询 API**；插件只把它当作相对运行数据基准的默认值，缺失或非法时相关工具安全失败。`Proc.get_main_root()` 返回 GUI 根对象，不是文件系统目录，不能拿来解析路径。

不凭 `__file__`、`sys.executable`、`argv[0]`、打包临时目录（如 `sys._MEIPASS`）或 Docker `WORKDIR` 猜数据根，不调用 `os.chdir()` 或全盘搜索补救。使用标准库原生路径语义处理 Windows / POSIX 路径、空格和非 ASCII 名称；存在性、权限及边界检查等 I/O 在服务线程内完成。根目录只能来自受信任的宿主上下文，不能由 MCP 请求指定。

### 3.2 能力分层

**文件层** — 普通工具只读；Full 配置/账号存档更新采用受限原子替换加提交后核验，不声称立即更新 OlivOS 运行时；路径根按 §3.1 从宿主上下文确定。

以下是参考版本的默认布局，仅用于宿主仍采用该布局时的回退；不是固定安装路径，不能覆盖宿主实际资源配置：

```
日志      <cwd>/logfile/*.log
数据      <插件数据根>/<namespace>/
包元数据  <cwd>/plugin/app/*.opk（或已解包目录的 app.json）
控制文件  <插件数据根>/OlivOSCockpit/control/（本插件 namespace 整体永久禁止工具访问，见 §2.6）
```

只读所需的 `app.json` 元数据，不整体解包 OPK；默认目录不存在也不切换到其他猜测目录或为读取而创建目录。

`cockpit_data.read` 自动返回全文或首个安全分页，客户端显式用 `cursor` 顺序续读；不增加开关、不提供任意 offset。末页仍标为 `paged`，所有分页片段均不带原 `sha256`，不能当作一次性全文回写。文件修订核验是尽力检测而非跨请求快照；支持格式及拒绝边界见 [插件数据自动续读](docs/reference.md#3-插件数据自动续读cockpit_data)。

文件安全（所有文件工具的公共前置）：

```
namespace 只允许单个目录名；拒绝绝对路径、"."、".."、路径分隔符
文件相对路径允许正常子目录，但拒绝绝对路径及任意 ".." 组件
按目录 fd 逐组件打开并校验位于对应允许根内，不用字符串前缀判断
只读普通文件与目录；拒绝 FIFO / 设备 / socket 等特殊文件
符号链接不得越界，路径校验与实际打开之间的链接替换也不得绕过边界
```

首版使用 POSIX 目录句柄逐组件安全打开，保守拒绝所有符号链接（包括根的祖先目录）。缺少所需安全打开原语的平台仅禁用文件读取能力并返回明确错误，工具仍在列表中；不得以存在竞态的 `resolve` 后 `open` 替代。跨平台支持以实际验收为准。

**运行时层** — 需要 `Proc`，仅在加载器进程内可用

```
配置账号             Proc.Proc_data['bot_info_dict']（配置启用的账号，不等于在线）
已加载插件           Proc.get_plugin_list()（已加载的 namespace 清单）
原始事件观察        包装 proc.run_plugin，在 API.Event 转换前复制白名单字段
主动发消息          构造 sdk event → event.send()，或适配器文本发送（§4）
重载插件             Proc.set_restart()（队列请求，见下）
属性读取             白名单路径（cockpit_proc_get）
```

OlivOS 框架已有接口覆盖所需语义时直接复用，不另写同功能实现。`Proc.get_plugin_list()` 只提供已加载插件的 namespace，不能替代已安装 OPK 的元数据、历史日志或任意插件文件读取；这些未被接口覆盖的内容仍按文件层约束有界读取。

`cockpit_raw_events` 只包装当前 `Proc` 实例的 `run_plugin`：先复制已核实字段，再恰好调用原方法一次；观察失败不会改变宿主调用结果，也不消费队列、不改 Event、不建线程。无法用当前账号字典唯一确认归属的事件直接丢弃；持有账号字典超过 500 项按专门 `bot_limit` 原因丢弃。

`cockpit_reload` 的准确契约：上游 `Proc.set_restart()` 是把重启请求入队，效果是重启整个插件加载器并重载全部插件，不是单插件热重载。Cockpit 自身、HTTP 服务与所有内存会话一并结束，响应不承诺重启完成。

```
1. HTTP 响应完整发送后，才入队 set_restart()，避免连接被提前切断
2. 结果只表示"重启请求已接受"，不表示已重载
3. 账号更新、配置变化或宿主自动重启策略也可能打断服务，调用方按断线处理
```

传统会话只存内存，不持久化；会话有效性与协商版本在 `_Sessions.version` 单锁内一次查询（过期、淘汰、owner 不符都按未知会话 404）。服务重启后的断线与失效会话处理统一见 §3.4。

`cockpit_bots` 从 `Proc.Proc_data['bot_info_dict']` 读取加载器账号，而不是执行在线探测；没有可靠适配器状态时 `connection` 取 `"unknown"`，不把字典成员报告为已连接。

**调试终端账号（2026-11-08 契约变更：由使用者预置，本插件零突变）**：Cockpit **从不在运行期或 init 期对宿主 `bot_info_dict` 做键级增删**（不 setdefault、不 pop、不建内存账号；BUG-16 的突变路径由此消除）。调试终端账号由使用者在宿主账号配置中自行创建（三元组严格 `terminal_link / terminal / default`，`enable` 未禁用，ID 为真整数；postapi/ff14 等模型不被选中），重启宿主后由原生启动流程创建。Cockpit 只读发现：init、配置发布边缘与每秒监督 tick 都会验证当前选择（活映射成员身份、键与 hash 一致、三元组、整数 ID），失效则有界重选（每次至多 2×500 项，状态最后一次性发布）；多个合格账号按 hash 确定性选择。没有任何合格账号时明确停用（`debug_terminal` 返回可操作的固定错误），只读工具不受影响，tick 持续重试，账号出现后自动发现。配置中**没有** `terminal_bot_id` 字段（2026-11-08 移除；旧配置残留该字段会被按未知字段拒绝，需手动删除）。

变更终端注册策略前，读取[启动注册安全验证](docs/startup-account-safety.md)，按其中的实测范围与重新评估条件判断，不仅凭启动回调名称认定安全。

`cockpit_bots` / `cockpit_status` 的配置账号数量为字典全部账号（不再扣减内存账号）；两者另带脱敏的 `debug_terminal` 状态（`selected`、`connection='unknown'` 及错误，无 `memory_created` 字段）。`cockpit_proc_get` 的 `bot_hashes` 只返回 hash 字符串，不含凭据。

`cockpit_terminal_input` 固定使用当前选中账号：必填 `message`（UTF-8 ≤64 KiB），可选 `user_id`（默认 `-1`）与 `group_id`（省略为私聊），不接受 bot_hash、平台或原始 payload。开始与提交前都复核对象身份/hash/平台/enable/ID/当前选择；包与 SDK 事件在私有提交临界区外构造，构造后核对 `sdk_event.base_info.self_id` 等于捕获目标（覆盖 ID 变化又还原的 ABA），最终用短小的 Cockpit 私有临界区协调"选择未切换、活映射/对象/ID、配置代次复核、非阻塞 put"。该锁只协调本插件自己的发布与提交窗口，不代表宿主或第三方参与同步。`queued: true` 只表示已入队，processing 恒为 unknown。队列满、代次变化、API 缺失或 SDK 异常返回结构化 `isError`。虚拟终端不是沙箱，被触发的插件仍可能产生真实副作用。

### 3.3 协议栈

```
传输      Streamable HTTP
端点      POST /mcp
格式      JSON-RPC 2.0（单请求单响应，不批量）
编码      JSON（不实现 SSE）
```

**插件独立性是硬约束。** 运行依赖仅限 OlivOS 框架本身、标准库及宿主发行环境本身提供的 `aiohttp`。各工具不得导入或调用其他 OPK 的模块、API 或辅助服务，不能依靠其他插件的加载顺序、初始化副作用或其捆绑的依赖；插件清单也不得声明其他 OPK 为必需依赖。其他插件仅作为调试对象，不是实现依赖；经宿主 API 查询或重载它们不构成对其代码的依赖。其缺失、禁用或卸载不得影响 Cockpit 启动及静态工具注册；目标不存在时只返回对应的结构化结果或错误。本项目也不依赖 OlivOS-Docker 或任何容器入口脚本。

**不引入官方 SDK。** 官方 `mcp` 2.3.0 会带入一批额外强依赖，与插件"挂上即用"的目标冲突。不新增依赖，源码与二进制发行版均须独立核验依赖可用性；缺少 `aiohttp` 时仅禁用 Cockpit 服务并记录安全错误，不自动安装依赖，也不借助其他插件补齐。

参考 SDK 的数据结构与分派逻辑，不引入 SDK 的代码与依赖。

### 3.4 双时代分派

分派分两阶段：**先分类**（决定语义时代），**再校验**（按该时代的 MUST 校验头与 `_meta`）。不靠版本号大小推断。

分类阶梯（本服务在规范判据上的具体化）：

```
1. method == "initialize"                                    → 传统语义
2. params._meta 含 io.modelcontextprotocol/protocolVersion   → 现代语义
3. 请求头 mcp-session-id 存在                                 → 验证会话：
     命中已知会话                                            → 传统语义
     未知或已过期                                            → HTTP 404
4. 完全无时代依据                                             → 400 Bad Request
```

注意：第 3 条中"header 存在即验证、未知会话回 404"是本服务的会话回落规则，不与规范的判据混为一谈。

现代校验中，头错误优先于版本不支持错误，其余按对应规范处理：

```
MCP-Protocol-Version 缺失或与 _meta protocolVersion 不一致    → 400 / -32020
Mcp-Method 缺失或与 method 不一致                             → 400 / -32020
tools/call 的 Mcp-Name 缺失或与 params.name 不一致             → 400 / -32020
请求版本不在现代支持集中                                      → 400 / -32022（data.supported 见 §3.5）
缺少必需 _meta 字段（protocolVersion、clientCapabilities）     → 400 / -32602
未实现的 method                                               → 404 / -32601
```

传统头处理按已协商的会话判断，不套用现代必填头规则；有有效传统会话且缺版本头时，按该会话协商的版本处理，完全没有时代依据时仍按分类阶梯第 4 条返回 400。传统服务端必须实现 `initialize` 并接受 `notifications/initialized`：初始化校验成功后才分配会话，通知接受后返回 HTTP 202 且无 body。会话 TTL 与存储上限见 §2.3，过期或淘汰按未知会话处理；服务恢复后，旧会话收到 404 时客户端不带旧 ID 重新 `initialize`。轮换 `api_key` 也会使旧会话失效。

现代服务端必须实现 `server/discover`，客户端可不调用；现代请求无需会话或握手，断线重试仍逐请求携带 `_meta`，不要求 `initialize`。两者共用 `tools/list`、`tools/call`；`ping` 属于传统核心方法，不列为现代核心方法或依赖。

代次变化窗口的响应边界：已成功接受的通知保留 202 空正文；错误响应保留既有 HTTP 状态、头与已知 Reject 错误码，不把 4xx/5xx 改成 200/202；普通有 id 的工具成功结果替换为固定安全错误且 `after_send` 不执行。响应 `prepare()` 后不可再改写。

### 3.5 版本支持

总接受集为五个。按时代划分实际承载范围：

```
传统  2024-11-05、2025-03-26、2025-06-18、2025-11-25
现代  2026-07-28（仅此一个）
```

```
传统  未知版本 → 协商回落 2025-11-25
现代  任何非现代支持集内的版本 → 400 / -32022，data.supported 为 ["2026-07-28"]
```

现代信封携带传统版本号也返回上述版本错误，不切回传统语义。`2024-11-05` 仅承载其消息与握手语义，通过本服务的 POST 绑定实现；原生 HTTP+SSE 旧客户端不在支持范围。本项目不实现 SSE。`-32022` 错误中仅 `supported` 字段精确等于服务端固定版本列表时按 schema 保留；`requested` 与其他字段仍走普通脱敏。

### 3.6 明确排除

```
CLI 形态              本项目交付 OPK，不接管宿主的 stdin/argv
独立进程 / 容器       Proc 内存不能直接跨进程读取，不另设独立服务形态
官方 SDK 依赖         与"挂上即用"冲突
SSE / MRTR            调试场景无需求，纯 POST 足够
OAuth / JWT           单 key + 可配置监听地址，不提供多用户认证
resources / prompts   无需求
sampling / elicitation 无需求
WebUI 页面            AI 不需要浏览器
HTTP+SSE 传输         仅在 Streamable HTTP 上支持两代版本
TLS 终止              本项目不做；需要时由外部反向代理承担
```

---

## 4. 工具集契约

完整工具清单、参数与权限元数据以 `OlivOSCockpit/registry.py`（Full）/ `profiles/lite_registry.py`（Lite）导出和 `tools/list` 静态 schema 为准；逐工具行为细节见 docs/reference.md。要点：

- 静态工具表：现代规范要求 `tools/list` 不随连接变化且顺序确定。运行时拿不到某个能力也不从列表删工具，调用返回 `isError: true`；未完成安全绑定的接口只在内部台账登记，二者不可混淆。全部工具名以 `cockpit_` 开头，定义按名称确定性排序。
- `interfaces.json` 的 candidate 是固定源码审阅分类，不等于公开执行表。只有实际安全绑定进入 `tool_bindings` / registry 的名称对客户端可见；未绑定项不展示、不接受猜名调用，不发布永久失败的候选占位工具。hidden/blocked/internal（进程终止、线程强停、账号保存、消息反射等）只内部分类。
- `catalog_tools.py` 是历史/审计候选快照，**永不并入运行注册表**，两个构建都不导入。
- Lite 物理剔除：Lite 归档不含 `full_only.py`、`adapter_tools.py`、`file_write.py`、`account_write.py`、`intercept.py`，不通过运行时开关隐藏 Full 实现；共享的 `cockpit_terminal_input` 是 Lite 唯一非只读工具。
- 日志与插件数据只在 §3.2 的允许路径和 §2.3 的资源上限内读取，截断必须标记。所有发往客户端的应用值在统一响应构造边界按 §2.7 脱敏，两版同策略、无绕过参数；覆盖工具结果、正文、错误和降级路径。
- 脱敏仅生成副本，不能改变宿主数据、文件或 SDK 原始参数；工具的文本与结构化结果必须来自同一份干净数据。必须区分应用值与协议信封/schema，保留必要的请求 ID、错误码、会话头及操作句柄。已知凭据只从 `api_key` 和宿主字段白名单有界采集，不反射补搜或记录原值。脱敏失败、超限或编码失败只能返回固定安全错误/截断并禁止 after_send，不得回退原文；CancelledError 继续按 §2.1 传播。
- 用户选择保留规则脱敏后的正文，而非隐藏全部未知内容。不能把未命中规则等同于无敏感信息：无标签或未知格式的个人信息、业务秘密仍可能漏识别，原始磁盘内容也未被修改。

---

## 5. 文献

### 5.1 MCP 规范

**传统时代**

```
https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
https://modelcontextprotocol.io/specification/2025-11-25/server/tools
```

**现代时代**

```
https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
https://modelcontextprotocol.io/specification/2026-07-28/server/discover
https://modelcontextprotocol.io/specification/2026-07-28/server/tools
https://modelcontextprotocol.io/specification/2026-07-28/changelog
```

**规范仓库与 schema**

```
https://github.com/modelcontextprotocol/modelcontextprotocol
https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts
```

### 5.2 SDK

```
https://github.com/modelcontextprotocol/python-sdk/tree/v2.3.0
https://py.sdk.modelcontextprotocol.io/
https://pypi.org/project/mcp-types/
```

重点关注：

```
src/mcp/shared/inbound.py                      双时代分派阶梯
src/mcp/server/_streamable_http_modern.py      现代 HTTP 层语义
src/mcp/server/streamable_http.py              传统 HTTP 层语义
src/mcp-types/mcp_types/_types.py              字段定义
```

### 5.3 OlivOS

```
https://github.com/OlivOS-Team/OlivOS
https://github.com/OlivOS-Team/OlivOSPluginTemplate
https://github.com/OlivOS-Team/OlivOSDoc
```

修改路径解析前，须对照目标宿主源码或发行版核实，不能把已读源码当作所有部署的运行验收。参考版本为 [1.0.2-beta.3 / c6a99fc2a3b4](https://github.com/OlivOS-Team/OlivOS/tree/c6a99fc2a3b4cc7dd1ea8e7b6fe762b7bee7c7d4)：

- infoAPI 版本与路径常量：`OlivOS/core/info/infoAPI.py`（`OlivOS_plugin_data_path='./plugin/data'`，SVN 300 / 兼容闸门 190）
- 插件路径与默认布局：`OlivOS/core/core/pluginAPI.py`
- 日志默认路径：`OlivOS/core/core/diagnoseAPI.py`（`./logfile/`）
- 接口台账：仓库根目录 `interfaces.json`（docs/reference.md §1）

插件开发需对照上游 `docs/DevPlugin/`（template/event/api/message/webui）。

### 5.4 相关规范条款

```
JSON-RPC 2.0                     https://www.jsonrpc.org/specification
RFC 9110（HTTP 语义、头字段）       https://www.rfc-editor.org/rfc/rfc9110.html
SSE                              https://html.spec.whatwg.org/multipage/server-sent-events.html
OAuth 2.1（本项目不实现，仅备查）    https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
```

### 5.5 治理与背景

```
MCP 由 Anthropic 提出（2024-09），现由 Linux Foundation 托管
治理文档  https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/GOVERNANCE.md
SEP 索引  https://modelcontextprotocol.io/seps
```

---

## 6. 已知残余风险

以下无法通过本项目的代码规避，与 OlivOS 原生崩溃同源：

```
OlivOS 内部 API 的 C 级缺陷      → 段错误，加载器进程死
C 扩展死循环占满 GIL            → 加载器进程卡死
宿主或容器内存耗尽              → 加载器或相关进程可能异常或被终止
```

§2.1 的兜底与 §2.3 的有界读取降低概率，不构成保证，也不能终止已阻塞的调用或线程。

协议侧风险：现代时代仍在演进，客户端实现可能超前或滞后于规范文本。分派必须依赖判据而非版本号，也不能假定客户端会主动调用 `server/discover`。

配置侧风险：配置文件是可编辑的本地状态，写错端口/地址会让服务停止监听；改为非回环地址会以明文 HTTP 暴露 key 与数据；关闭脱敏会返回未清理的应用值，未知业务秘密仍无法识别。

---

## 7. 验收要点

以下是实现完成后、发布前必须执行的验收项；列出清单不表示已运行或通过：

```
双时代隔离     initialize 走传统；_meta 现代键走现代；未知 session-id 回 404
               现代必填头缺失/不一致返回 400/-32020，优先于版本不支持错误
               现代信封携带传统或未知版本时，-32022 的 supported 仅含现代版本
               传统 notifications/initialized 返回 202 无 body；会话过期/淘汰回 404
               现代无会话可直接调用工具，重连不要求 initialize 或 server/discover
生命周期       init 失败按对象身份执行完整拆除序列，旧钩子/服务/规则不存活
               manager.stop 撤权后迟到轮询不能恢复授权或监听
               托管发布前重查停止/失效；request_stop 先记停止再通知 loop
               启动交错峰值最多一个 reconcile，最终只监听最新合法地址或停用，池不重建
               代次变化：已接受通知保持 202 空正文；错误保留状态/头/码；成功结果被替换且 after_send 不执行
配置           首次加载创建两份模板且 api_key 为空；无 key 不监听
               修好配置后自动监听；改端口/地址会先停旧监听再绑定
               删除或写坏任一文件后 fail-closed；恢复才重新放行
               key 轮换使旧传统会话失效；配置热更新先撤权再发布
               config.json / redaction.json 与本插件 namespace（含 control）对所有文件工具不可读
配置格式       非 OlivOS- 前缀、长度越界、缺大小写/数字的 api_key 被拒绝
               未知字段、重复键、非布尔开关、越界端口、超长列表被拒绝
               非回环 listen_host 被接受，且 Origin 必须与之一致，否则 403
reload         HTTP 响应完成后才入队 set_restart；结果仅为"已接受"
               整个插件加载器与 Cockpit 重启，传统旧会话回 404 后重新 initialize
bots           无可靠适配器状态时 connection 为 'unknown'，断线账号不能伪报在线
文件安全       namespace 含分隔符、路径含 .. 组件、绝对路径、越界链接、FIFO 均拒绝
               正常子目录可读；链接替换不能绕过允许根，其他特殊文件同样拒绝
               控制目录、控制文件、denied_paths 在脱敏关闭时同样拒绝
数据续读       Full/Lite、两时代、OPK 清理后首次调用及真实加载器顺序续读
               完整上下文脱敏后分页；字段/认证前缀、PEM、已知值不跨裸片漏洗
               篡改/过期/修订与配置或清洗上下文变化拒绝；末页不冒充全文 SHA
受限写入       提交后核验失败不报成功 SHA、不回滚、不删外部对象；目录 fsync 失败如实 durability=unknown
               预先存在的同前缀临时文件在成功与失败路径都不被扫描删除
部署与路径     分别验证源码、目标二进制发行版及容器，不把单种部署结果推广到其他形态
               程序目录与启动 cwd 不同、空格/非 ASCII 路径、目标平台路径规则均须覆盖
               数据路径来自 infoAPI 相对常量 + 宿主 cwd；不猜 Docker WORKDIR，不全盘搜索
资源限制       超限返回截断标记或结构化错误；响应始终是完整、有效的 JSON-RPC
               并发满立即 503；超时调用未结束前仍占名额，不额外补开线程
取消           CancelledError 在 finally 清理后传播，不转成工具错误
               同步宿主观察边界转 drop 计数且原调用一次；读侧取消继续传播
出站脱敏       两版、两时代、结果/错误/日志/文件正文均适用；文本与结构化内容一致
               用户 allow > redact > 内置，完整字段名 case-insensitive
               -32022 固定 supported 按 schema 保留，requested 仍脱敏
               关闭脱敏仍做 JSON/限额校验；未知业务秘密可能漏识别
               原始事件仅覆盖 run_plugin 转换前白名单字段，不宣称流量全覆盖
               异常/超限无原文降级、不执行 after_send
工具集         Full 61 个、Lite 35 个（以注册表导出为准）；全部以 cockpit_ 开头
               Lite 包内与 Full 共用 cockpit_terminal_input，但不含
               full_only / adapter_tools / file_write / account_write / intercept 的任何实现
               未安全绑定的 candidate 及 hidden/blocked 只内部登记，不列出且猜名调用失败
               tool_bindings 与 Full/Lite registry、handler、测试文件一致；动态声明不遗漏
               运行时能力缺失时工具仍在表中，调用返回 isError: true
权限           Full 真实写默认关闭；适配器发送被拒，开启 full_real_account_write 后放行
               low_level 需要 full_real_account_write + full_low_level_access 同时开启
               Lite 真实账号读默认关闭，开启 lite_real_account_read 后才可读
               cockpit_terminal_input 在 Lite 可用；虚拟终端非沙箱已文档化
终端账号       运行期与 init 期对宿主账号字典零增删；无合格账号明确停用并可操作
               用户预置账号（任意 ID）被发现并复用；多个按 hash 确定性选择
               扫描超限、选择失效有界重选（≤2×500 项）；status 失效写回并可自愈
终端输入       私聊/群聊字段正确；postapi/ff14、替换对象、ID 缺失或非整数均拒绝
               构造后核对 self_id；代次变化、队列满或 SDK 异常返回 isError；成功只表示已入队
独立性         宿主依赖满足时，分别只安装 Full 或 Lite、无其他 OPK，服务可启动并注册完整工具集
               禁用/移除调试目标插件不影响服务；目标缺失仅产生对应结构化结果或错误
               清单不声明其他 OPK 必需依赖，代码不导入其模块，也不借用其捆绑依赖
               不依赖 OlivOS-Docker；无 aiohttp 时仅禁用服务并记录安全错误
配置写入       仅已有非执行文本配置；完整原文 SHA-256、最终路径/身份/权限复核
               账号存档按原生 boot/patch 路径解析，停用/未知字段保留，禁脱敏占位符回写
               持久化与运行生效分开报告；需要完整宿主重启，不假报加载器重载即可生效
入站规则       写∧底层双授权；旧请求不能清新规则；配置代次变化清空
               原调用次数、drop/replace_text、一致字段及非全流量覆盖均需验证
文档一致性     README / AGENTS 的工具数与 registry 导出一致，统一使用 cockpit_ 前缀
               interfaces.json 的 tool_bindings 随 handler 移动同步首行号，上游静态审阅区不重写
发布说明       仅明确标记的插件/skill 功能变更进入说明，内部维护与未知标题不收录
许可分发       根 LICENSE 与两个 OPK、skill ZIP 中的许可证副本一致
兼容性弃用     service.start 弃用为固定失败 stub 属外部兼容性变化，须单独披露
```

---

## 8. 开发流程

本节给出修改本插件的开发触达清单与验收命令。任务是通过已连接的 Cockpit MCP 排障、读取数据或执行受控操作时，读取 [AI 代理使用 skill](skills/olivos-cockpit/SKILL.md)；该 skill 面向工具调用，不承担源码开发流程。

### 8.0 开发前识别最新上游源码

每次开始源码开发时，先查询 `OlivOS-Team/OlivOS` 全部分页 Release，排除草稿和未发布项，正式版与 prerelease 不分优先级，按 `published_at` 选最新。不能用仅返回正式版的 `/releases/latest`、GitHub 的 Latest 标记、版本号大小或 main 分支 HEAD 替代这个选择；被删除或转回草稿的版本不再作为开发目标。

使用 GitHub CLI，例如：

```bash
upstream_tag="$(gh api repos/OlivOS-Team/OlivOS/releases --paginate --slurp | jq -er '
  [.[][] | select(.draft == false and .published_at != null)]
  | max_by([.published_at, .id])
  | .tag_name // error("No published OlivOS release")')" &&
gh api "repos/OlivOS-Team/OlivOS/commits/$upstream_tag" --jq '{sha, html_url}'
```

读取或检出该 tag 对应的固定 commit 源码，核实本次变更涉及的宿主 API、事件、路径和依赖，并记录 tag、完整 SHA 与核查日期。可复用 SHA 一致的本地检出；不能仅凭旧文档、相同 SVN 或 tag 名认定源码一致。查询失败时如实说明无法确认最新版本，不把缓存版本冒充最新。

遇到新 Release，应先核对与现有审阅基线的差异，再按新源码开发和验收。`interfaces.json` 继续标明实际审阅的固定版本；未完成对应审阅，不得只替换 source.commit 或放宽库存断言来伪造新基线台账。历史运行实验保留其实际版本，兼容性仍按实测范围声明。本规则属于开发流程，发布 Actions 不自动追踪或安装上游最新源码。

### 8.1 修改触达清单

```
改一个工具          handler → ToolSpec(schema/permission/read_only) → registry.TOOLS
                    → Lite 剔除判断 → 测试 → interfaces.json tool_bindings
                    → reference 工具行为 + skill 功能路由与使用指引（涉及安装/配置时同步 README）→ 计数核对
改路径/写入         fs.py 安全打开原语 → files.py / file_write.py / account_write.py
                    → path_policy 回归 → 上游基线核实（§5.3）
改协议              protocol.py 纯值层 → service.py 分派/边界 → test_protocol / test_service
                    → 两时代回归 + AGENTS §3.4 与 reference 同步
改生命周期          main.py → config.py → service.py → test_entry / test_config_service / test_service_core
```

### 8.2 定点与全量命令

在具备宿主发行依赖（含 `aiohttp`）的 Python 3.11 环境从仓库根目录执行：

```bash
# 定点回归（按改动文件选择，不为每个条目跑整套）
python -m unittest discover -s tests -p 'test_entry.py'
python -m unittest discover -s tests -p 'test_config_service.py'
python -m unittest discover -s tests -p 'test_service_core.py'

# 全量
python -m unittest discover -s tests

# 构建（新输出目录，避免覆盖现有产物）
output="$(mktemp -d /tmp/olivos-cockpit-build.XXXXXX)"
python scripts/build_opk.py --output "$output"
```

可选：`OLIVOS_COCKPIT_UPSTREAM_SOURCE` 指向核实的固定 Release 源码后运行上游 AST 签名检查（只解析签名，不等于运行验收）；`OLIVOS_COCKPIT_TEST_REAL_LOADER=1` 在隔离环境启用真实加载器测试，不能在生产宿主上执行。必须记录实际通过/失败/跳过数，不把 OK/skipped 写成全部验收通过。

### 8.3 新增工具的完整层清单

handler（模块内，含权限/只读元数据）→ ToolSpec（schema、required_permission、read_only）→ 加入对应 TOOLS 元组 → registry.TOOLS（Full）与 Lite 剔除判断（`profiles/lite_registry.py` 不含写模块；Lite 可用的共享工具单独确认）→ 测试（单元 + HTTP + 必要时真实加载器）→ interfaces.json tool_bindings（handler、首行号、权限、profile、测试映射）→ docs/reference.md 行为细节 + skill 功能路由与使用指引（涉及安装/配置时同步 README）→ 全量测试与构建核对计数与排序。

### 8.4 常见陷阱

- 在 helper 前插行、改模块 docstring 会移动 handler 首行：同步 tool_bindings 的 `handler_line`（`test_inventory.py` 会拦住），但不要重写上游静态审阅区。
- 无 aiohttp 的本机测试会跳过 HTTP 集成；提交前在容器或 venv 里跑全量。
- 无 manager 的服务 `_policy().generation` 为 `None`，测试注入代次变化时按 `0` 起步，不要直接 `+1`。
- 同步宿主回调边界与服务私有 loop 的取消语义不同（§2.1）；不要在 BaseException 前统一加取消透传。
- 写工具的报告口径：超时/失败不承诺"没有副作用"，提交后核验失败明确"可能已替换"。

### 8.5 人工发布与版本同步

`.github/workflows/release.yml` 仅允许 `workflow_dispatch`；待发布源码放到 GitHub 的 main 后，在 **Actions → Release → Run workflow** 选择 main、输入版本并人工运行，不添加 push、tag、release 或定时发版触发器。`scripts/build_opk.py` 复用同一打包入口生成 Full/Lite OPK 与完整 skill ZIP，只有这三个附件；构建输出用临时目录，不把归档、dist 或缓存提交到仓库，也不捆绑宿主或其他插件。

本项目代码与配套 skill 采用 `AGPL-3.0-or-later`，根 `LICENSE` 为完整许可证文本；两个 OPK 的 `LICENSE` 与 skill ZIP 的 `olivos-cockpit/LICENSE` 必须携带同一副本。README 首次提及 OlivOS 时链接上游以声明来源；第三方项目及素材仍遵循各自许可。

发版时同步 `OlivOSCockpit/app.json` 的 version、`contracts.VERSION`、`skills/olivos-cockpit/SKILL.md` 的 metadata.version 与版本文案，再更新 README 附件名和相关测试；三者与人工输入版本必须完全一致。版本使用 `vX.Y.Z` 或带预发布后缀的形式，不添加自身 svn；宿主兼容字段与宿主 SVN 查询不受影响。

`scripts/release.py` 在测试前预留固定 commit 的草稿，上传前后检查原 Release ID，并只发布这份草稿；已公开版本或 tag 指向不同 commit 时拒绝覆盖。测试或构建失败保留草稿；临时故障可重跑原任务，源码修正后需删除旧草稿，从更新后的 main 重新人工触发（已有同版本 tag 必须指向本次 commit）。草稿被删除后旧任务重跑不得重建，重新人工触发才允许创建。

发布说明只写插件与 skill 的功能性新增、优化、修复；首版简述已有功能。后续比较起点来自仍公开的 Release，不能以最近 tag、被撤回版本或草稿代替，撤回版本中的功能变化继续计入下次增量。

仅 `feat(plugin):` / `fix(plugin):` / `perf(plugin):` 及相同的 `(skill)` scope 收录为新增、修复、优化，允许 Conventional Commit 的 `!`，标题用面向用户的一句话描述功能变化。例如 `feat(plugin): 支持插件数据续读`、`fix(skill): 修正游标失效后的处理指引`。scope 是明确的功能声明，不是改动路径：混合提交只描述其中用户可见的功能，不罗列伴随的内部维护。README、许可、开发流程、CI、构建、测试、接口台账、纯重构或单纯版本整理不使用这些功能标记；其他类型、scope、无 scope 与未知标题均忽略，不自动归为优化。没有功能条目时说明为空，不用内部改动补齐。
