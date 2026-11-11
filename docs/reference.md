# OlivOS Cockpit 深度参考

本文件承接协议接入、工具行为、安全机制与失败边界的完整说明；README 面向真人使用者的安装、配置、风险提示与许可，[配套 skill](../skills/olivos-cockpit/SKILL.md) 指导 agent 使用全部已发布功能，[AGENTS.md](../AGENTS.md) 面向开发 agent。文档与实现不一致时，以源码为准并顺手更正文档。

当前静态审阅基线：OlivOS Release 1.0.2-beta.3，commit [`c6a99fc2a3b4`](https://github.com/OlivOS-Team/OlivOS/tree/c6a99fc2a3b4cc7dd1ea8e7b6fe762b7bee7c7d4)；本插件与配套 skill 均为 `v0.1.0`，无插件自身 SVN 版本。每次源码开发的最新上游选择流程见 [AGENTS.md §8.0](../AGENTS.md#80-开发前识别最新上游源码)，不将此历史台账自动重标为新版本。

## 1. 接口台账（interfaces.json）

`interfaces.json` 是针对固定基线的完整静态阅读台账，不是运行时验收结果：

| 项 | 数量 |
| --- | --- |
| 文件 / 已审阅 / 未读 | 227 / 227 / 0 |
| Python 文件 | 171 |
| 接口定义 | 3355（internal 2776、hidden 395、candidate 184） |
| 额外接口（常量、副作用等） | 75 |

分区：core 98 文件 / 860 定义、qq_onebot 19 / 1028、adapters 63 / 780、web_tests 47 / 687。另保留 87 条动态声明记录：HTTP 端点 2、WebSocket 端点 12、注册表 7、Milky action 64、条件导入 2；它们不计入 3355 个定义或 75 个额外项。

- 各审阅分区 `runtime_executed` 均为 false：未修改上游源码，未把 adapter/web 源码导入运行。
- 227 个文件中 223 个按文本审阅；4 个二进制资源（图片、图标）只记录 sha256、字节数、格式和引用位置，**没有当文本解码**，也没有像素级分析。
- `tool_bindings` 记录实际公开工具、handler（含首行号）、权限、Full/Lite 归属及对应测试文件。插件代码移动 handler 首行后必须同步该映射（`tests/test_inventory.py` 有独立回归），但上游静态审阅区不随本插件代码重写。
- 台账用于确定候选能力与危险接口；未绑定 candidate 与 hidden/blocked/internal 只内部登记，不出现在 `tools/list`，猜名调用同样失败。台账不能替代目标部署的实机运行验证。

## 2. 工具行为细节

### 已加载插件详情（cockpit_plugin_loaded_list）

保留原有 `namespaces`、`count`、`truncated`，追加 `plugins`、`details_available` 与 `details_truncated`。原 `truncated` 仍只描述名称清单；详情达到独立预算时，`plugins` 可能只覆盖清单前部，以 `details_truncated: true` 标记，不改变名称清单和计数。

每条详情只投影 `namespace`、`name`、`version`、`svn`、`info`、`author`、`compatible_svn`、`priority`、`priority_default`、`priority_user`、`priority_effective`。`unknown_fields` 列出未能从宿主记录确认的字段，其值默认为 `null`；`namespace` 仍尽可能保留所选名称以便与清单对应。`available` 表示该条全部白名单字段均可用，`details_available` 表示本次详情来源与所选条目均完整可用。宿主明确提供的 `priority_user: null` 表示无有效覆盖，不会列为未知；合法零值保留。优先级仅回报宿主字段，不重算，也不读取覆盖配置数据库。

字符串至多 200 字符、整数至多 256 bits、浮点必须有限；详情投影的紧凑 ASCII JSON 总量至多 128 KiB，之后仍受统一脱敏与完整响应上限约束。只读取当前加载器元数据，不导入或反射插件模块、不导出任意配置字段；这是尽力读取，不是跨字段原子快照。只有名称查询能力的宿主仍返回原清单，详情明确标记不可用。两版沿用原元数据权限，不增加工具或配置开关。

### 适配器文本发送（仅 Full）

19 个适配器单 text 段发送工具显式绑定于 `adapter_tools.py`。固定基线下仅支持字符串重解析的 OPQ、BiliLive、HackChat、MhyVila、Xiaoheihe 专用项只内部登记，不公开。`cockpit_send` 与它们都只构造**单个 text 段**，不接受媒体段、文件路径参数、原始 payload 或动态 action。仅在原生消息模式能安全传递段列表时提交；会把文本重新编码后解析为 CQ/OP 的适配器模式返回 `isError`，不做不安全回退。因而静态注册不等于所有适配器当前可执行。提交成功不代表送达，`delivery` 恒为 `unknown`。

dingtalk/discord 的 `API.sendGroupMessage` / `API.sendPrivateMessage` / `API.sendMessage` 是不公开的低层裸 API（需调用方自造 msgKey/embeds、绕过段落处理）；已发布的 dingtalk/discord 文本发送工具走 `event_action.send_msg` 段列表的安全路径，与裸 API 无关。

`cockpit_proc_get` 只接受枚举路径 `plugin_names`、`bot_hashes`、`olivos_version`、`olivos_svn`，按资源上限限制返回大小与深度，只返回原生 JSON 标量（数值须有限）、列表及字符串键字典，不做任意属性反射或自定义对象的 `str()`/`repr()` 转换。

## 3. 插件数据自动续读（cockpit_data）

`cockpit_data` 不需要启用新开关：`read` 的完整结果能放入响应预算时按原形态返回，否则自动返回第一页。先清洗完整的有界源内容，再分页其脱敏视图，不独立清洗裸字节切片。

首次读取：

```json
{"namespace":"Demo","mode":"read","path":"settings.json"}
```

分页结果带 `paged: true`、源文件总字节数 `file_size` 和可选的 `next_cursor`。将成功页的 `content` 加入结果，再原样传回游标续读同一 namespace/path；仅在 `isError: false` 且 `next_cursor` 缺失时才算读完。服务端不会自动扫完整个文件或后台预读。

```json
{"namespace":"Demo","mode":"read","path":"settings.json","cursor":"<上一页的 next_cursor>"}
```

- 游标请求可省略 `mode`，此时按 `read` 处理；首次不带游标仍默认 `list`。显式 `list` 不能携带游标；不提供任意 `offset/length` 跳读。
- 游标最长 1024 字符、签发后 5 分钟到期，带签名且不含正文或凭据。有效游标可重试；篡改、跨路径复用、文件修订或清洗上下文变化、配置代次变化及加载器重启后会拒绝续读，应从头重新读取。数据游标现为 v2，包含本次文本/JSONL 格式；旧 v1 游标不再接受。
- 每次源读取仍至多 1 MiB，定位读取还要求平台提供 `os.pread`，缺失时安全失败。支持此预算内的完整 UTF-8 文本/JSON，以及更大文件中能确认安全边界的换行文本。超大单行、超大单一 JSON 文档、不完整 UTF-8 或无法确认脱敏上下文的记录明确失败；不承诺任意大文档都能续读。
- `.jsonl` 后缀（不区分大小写）明确启用 JSONL；其他文件仅在完整非空行均为有效 JSON、且至少有两条记录时确认该格式，完整单一 JSON 文档优先保留原路径。未使用 `.jsonl` 后缀且首窗口仅有一条 JSON 记录时，不擅自改成 JSONL；需要完整行分页时使用 `.jsonl` 后缀。确定格式后由游标延续，后续坏行、非有限数或不完整记录安全失败，不降级为普通文本清洗。
- JSONL 保留空行、LF/CRLF 和无末尾换行；每条非空记录在清洗后仍可解析为 JSON，未脱敏值按既有 JSON 解析/编码的值语义保留。未变化行保留原文，变化行可能重新编码，**不承诺空白或数字词法逐字节不变**。所有行共用累计清洗预算，节点、扫描和工作上限不会因换行重置。外层 `content` 的 allow/redact 规则仍优先；若整字段被遮盖，返回统一标记，不再具有 JSONL 结构。
- JSONL 只在完整行末尾分页，按包含文本、结构化内容和游标的完整响应计量。一条记录无法装入响应时安全失败，不拆成半行、不提高限额；普通文本与单一 JSON 文档仍返回字符视图片段，需要拼接后使用。
- 按顺序拼接的是**脱敏视图**，不是磁盘原始字节；格式可能因 JSON/文本脱敏规则改变。`size` 是该页所依据的源内容块字节数，不是脱敏后 `content` 的长度。发生错误时，已收集的片段不能当作完整文件。
- 所有分页结果（包括末页）保留 `paged: true`，不提供原 `sha256` 字段；只有真正一次性完整返回才保留该修订摘要，避免把末页误当全文回写。文件修订通过读前后身份、大小与纳秒级修改/状态时间检测，属于尽力检测，不是跨请求快照。

Full/Lite 的现有真实数据读权限、路径拒绝与全部资源预算保持不变；工具数量也不变。

## 4. 受限写入与入站规则

### 插件配置文件（cockpit_plugin_file_update）

只更新其他插件数据目录里**已存在**的 UTF-8 配置文件，后缀限 `.json/.ini/.toml/.yaml/.yml/.conf/.cfg`，不创建任意文件。先用一次性完整、未分页的 `cockpit_data` 读取结果取得 `sha256`，更新时作为 `expected_sha256`；分页片段不提供该字段，不能把末页当作全文回写；上限 1 MiB。

写入流程：同目录临时文件（0600 创建、随后继承原文件权限）→ 提交前修订/身份/权限复核 → 原子替换 → 目录 fsync → **提交后核验**：重开最终路径，确认最终文件 dev/ino 与仍持有的暂存 fd 一致、完整内容 SHA 与本次提交一致，才报告成功。核验失败返回固定安全错误（替换可能已经完成，最终状态无法确认；应重新读取，不要自动重试），不返回成功 SHA，不宣称原文件未变，不自动回滚，也不清理外部对象。目录 fsync 失败但核验通过时如实返回 `persisted: true, durability: "unknown"`。

核验成功只说明核验观察点的路径解析、inode 身份和读到的内容符合本次提交：它不是跨进程 compare-and-swap，不能阻止非协作写入者，不能避免覆盖外部更新，也不承诺核验之后不再被改写。Cockpit 的写锁只串行化自身请求；应避免同时由多个写入方修改同一文件。

JSON 另做严格解析与解码前结构预算。不保证目标插件自动重载配置。异常残留的 `.cockpit-*.tmp` 名称不能证明归属；插件不做启动期或后台清扫，只对本次仍持有 fd 且身份匹配的暂存尽力清理。注意：账号存档更新会把完整存档写入暂存文件（含已有凭据），崩溃残留可能是额外敏感副本。

### 插件配置数据库（cockpit_plugin_config_set）

经宿主现有 `set_config(..., pkl=False)` 写入配置数据库。仅支持无损 SQLite/JSON 标量（null、布尔、63-bit 范围整数、有限浮点和 ≤64 KiB 字符串），不接收列表/字典、SQL、pickle 或文件路径。自身 namespace 永久拒绝，已知数据库路径也必须通过路径策略；该预检不能给宿主内部数据库连接增加目录 fd 级竞态保护。

### 账号存档（cockpit_accounts_config / cockpit_accounts_update）

`cockpit_accounts_config` 读取标准磁盘启动配置声明的账号文件：`<cwd>/conf/basic.json` 与 `conf/config.json` 补丁，复用宿主 `get_patch_config` 的合并语义；真正缺失时使用原生启动默认值。参考版本默认模型 `models.OlivOS_account_config.data.path` 为 `./conf/account.json`。损坏或被禁止的启动文件不回退，也不新增手工路径配置项。

结果明确标为 `source: "configured_file"`、`path_source: "disk_boot_configuration"`、`runtime_active_config: "unknown"`，不能当成总控当前内存配置；保留停用账号和未知字段，凭据在统一出站边界处理。文件 ≤1 MiB、账号 ≤500，分页最多 50 条，`sha256` 来自完整原文而不是脱敏后的正文。

`cockpit_accounts_update` 用 `index`、`expected_sha256`、`changes` 修改已有账号，仅允许 `enable` / `debug` 布尔值、`password` 和 `server.access_token`。凭据最多 4096 个 ASCII 字符，限字母数字及 `_.:@+=/-`，拒绝 `[REDACTED]` 占位符；空字符串表示显式清空凭据，仍须通过宿主校验，可能影响账号连接或鉴权。ID、SDK/model、endpoint、路径及路由字段不可改。写前执行原生纯校验（固定基线的原生校验器拒绝未知顶层/server 字段，因此“保留未知数据并校验已知部分”不等于整份存档必被宿主接受加载），保留未知与未修改字段，提交前再核对账号文件及启动配置修订，提交后同样执行上文的核验。

返回将持久化与运行更新分开：`runtime_updated: false`、`requires_host_restart: true`。需要**整个 OlivOS 宿主重启**才按启动流程应用，不声称只重载插件就能更新所有适配器；本工具不自动重启、不持久化内存调试账号。

### 入站拦截（cockpit_intercept_rules，仅 Full）

提供 `list/set/clear`，`set` 原子替换内存规则表。每条规则明确指定 `id`、`bot_hash`、`stage`（`sdk_in` 或 `processed_in`）、`event_type`（`private_message` 或 `group_message`）、`action`（`drop` 或 `replace_text`，后者另需 `message`）。最多 16 条、单文本 ≤64 KiB、规则总量 ≤256 KiB。

当前只绑定 OneBot V11 和默认虚拟终端：`run_plugin` 转换前或 `plugin_event_router` 逐插件回调前，实际范围以返回的 `coverage` 为准。不接受脚本、表达式、任意字段改写、CQ/OP 段语法、凭据/路由修改或出站拦截。固定基线原生 `Message_templet` 为 OP/CQ 传入大写前缀并做精确字符串比较，本守卫与其一致；未知第三方插件自行做大小写不敏感解析的行为需具体源码另查。配置代次变化清空规则，旧请求不能清掉新规则；已应用的修改不能撤销。异常、未知形状或锁竞争时旁路，不等待 AI；规则登记成功不代表已有事件命中，也不为目标插件提供沙箱。

## 5. 客户端输出脱敏

默认开启（`redaction_enabled: true`），但它是用户可关的配置项，不是不可绕过的强制层。开启时：

- 字段规则按**完整字段名**、case-insensitive 精确匹配；优先级为 **用户 `allow_fields` > 用户 `redact_fields` > 内置凭据字段**。内置字段覆盖已核实的凭据名（password、token、cookie、private key、secret、api key、app_key/app_secret、qsign 使用的 key、bili_jct、ticket、中文“密码/令牌/私钥”等），并额外接受分隔符不敏感变体；不做泛化的手机号、邮箱、IP、路径、证件号或账号 ID 猜测。
- 已知凭据只从 `api_key` 与宿主账号白名单中的 `password`、`post_info.access_token` 有界采集（≤500 账号、≤256 条），处理字段名缺失和常见 JSON 转义形式；逐次快照，不缓存历史值。
- 工具结果、日志/文件正文、错误与降级路径使用同一份规则和同一份干净数据；替换标记为 `[REDACTED]`，命中时结果带 `_meta.redacted: true`。
- 按单一 JSON 文档路径解析的正文会递归脱敏并保持 JSON 语法；普通合法、未修改的 JSON 文本保留原格式。出站文本中的重复键按末值语义规范化，并从干净结构重新编码；带 Unicode 转义且无法安全解析的畸形普通 JSON 文本只遮盖该字符串，不丢工具其余数据；已确定的 JSONL 坏记录则安全失败。配置与协议请求的重复键拒绝策略不变。
- 字典键保持不变，允许字段不会被后续已知凭据扫描覆盖。协议字段、错误码、请求 ID、schema 与正常握手头保持可用；`hash` / `bot_hash` / `namespace` 作为操作句柄，只匹配已知秘密。自动续读的 `next_cursor` 是清洗后生成的签名操作句柄，保持原值；文件正文中的同名字段仍正常脱敏。
- 协议错误中的版本信息例外：`-32022` 且 `supported` 精确等于服务端固定版本列表时，仅 `supported` 字段按 schema 保留（仍执行 JSON 形状、预算与形状校验）；`requested` 与其他字段仍走普通清理，用户字段规则与已知凭据照常生效。
- 关闭规则替换后仍校验结构化应用值的 JSON 形状、有限浮点和深度/节点/扫描预算；按 JSONL 处理的内容也仍逐记录校验，不等于保证任意普通文本内部的 JSON 都已校验。超限或清洗失败只返回固定安全错误或结构化截断，不回退原文，也不执行 `after_send`。

**覆盖范围必须分清**：脱敏作用于所有发往客户端的应用值，但 `cockpit_raw_events` 的**观察**范围只有加载器 `proc.run_plugin` 转换前、且经显式白名单投影的数据面事件。它不包含适配器在进入该接缝前丢弃的帧、控制面数据包、菜单/WebUI 事件，也不拦截或记录插件主动发出的出站调用。没有对应字段名或已知值的未知业务秘密、个人信息仍可能漏过；磁盘和宿主原值不会因此变成脱敏数据。

原始事件观察运行在同步宿主回调线程：观察自身异常（含构造期间的取消）一律转为 drop 计数，原宿主方法仍恰好执行一次；服务私有 loop 读侧的取消则在清理后继续传播。持有账号字典超过 500 项时，事件按专门原因 `bot_limit` 丢弃，形状错误与归属不匹配仍为 `unknown_bot`。

## 6. 虚拟终端调试账号（2026-11-08 契约变更）

**调试终端账号由使用者在宿主账号配置中预置，Cockpit 对宿主账号字典零增删。** 在启动账号文件（`<cwd>/conf/` 下的启动链声明，默认 `./conf/account.json`）或宿主自带界面中创建一个虚拟终端账号：平台三元组严格为 `terminal_link / terminal / default`（postapi/ff14 等模型不被选中）、`enable` 未禁用、ID 为真整数，然后**重启整个宿主**，由原生启动流程创建并校验。配置中没有 `terminal_bot_id` 字段（本轮移除；旧配置残留该字段会被按未知字段拒绝，需手动删除）。

本轮启动注册[安全验证](startup-account-safety.md)未通过：真实加载器中较早插件的后台账号读者，可以被另一插件在 `init_after` 的一次插入破坏。因此没有恢复自动创建；这不是对所有宿主版本或所有 `init` 时序的失败断言。

Cockpit 的发现与维护全部只读：

- `init`、配置发布边缘与每秒监督 tick 都会验证当前选择（活映射成员身份 `data.get(hash) is bot`、键与对象 hash 一致、三元组、整数 ID）；失效则有界重选，每次调用至多 2×500 项，候选先局部计算、状态最后一次性发布，第二次仍变化就固定安全失败等下一周期。
- 多个合格账号按 hash 确定性选择。启用账号集合超出 500 项时报告超限，不把账号当成不存在。
- 没有任何合格账号时明确停用：`debug_terminal` 返回可操作的固定错误（提示创建账号并重启宿主），`cockpit_terminal_input` 安全失败，其余只读工具不受影响；tick 持续重试，账号出现后自动发现，无需改配置。
- 候选发布前重新核验完整账号资格。账号字典在两次观察之间被替换或清空时，`status` 会把失效写回状态并触发下一周期重选；状态校验、错误写回与选择发布共用同一私有锁，旧查询不能把错误写到已经发布的新选择上。不缓存旧 hash 冒充当前数据。

`cockpit_terminal_input` 固定使用当前选中账号：必填 `message`（UTF-8 ≤64 KiB），可选 `user_id`（默认 `-1`）、`group_id`（省略为私聊）。开始与提交前都复核对象身份/hash/平台/enable/ID/当前选择；消息包与 SDK 事件在私有提交临界区外构造，构造后核对 `base_info.self_id` 绑定捕获目标（覆盖构造期间 ID 被替换又还原的 ABA），最终用短小的 Cockpit 私有临界区协调"选择未切换、活映射/对象/ID、配置代次复核、非阻塞 put"。该锁只协调本插件自己的窗口，不代表宿主或第三方参与同步；竞争可安全失败并等下一周期。消息按宿主原生路径投入当前加载器的 `rx_queue`；`queued: true` 只表示已入队，`processing` 恒为 `unknown`。队列满、代次变化、API 缺失或 SDK 异常返回 `isError`。本插件不捕获或返回插件回复，`cockpit_log` 也不是与单次输入关联的回复。

**虚拟终端不是沙箱**：被触发的插件仍可能写真实文件/数据库、访问网络或通过其他已配置账号产生副作用。

## 7. 资源与安全限制

- 文件读取要求 POSIX 目录句柄与逐组件 `O_NOFOLLOW` 打开；**保守拒绝所有符号链接，包括根目录的祖先链接**。缺少这些原语的平台（包括未实现对应安全打开方式的 Windows）文件工具明确不可用，但工具仍注册；宿主运行时能力分别判断。
- 只允许各资源根内的普通文件和目录，拒绝路径穿越、绝对路径、特殊文件（FIFO/设备/socket）及检查与打开之间的链接替换。
- 单次日志扫描 ≤8 MiB、返回 ≤2000 行；单次文件源读取 ≤1 MiB；目录 ≤500 条；单请求体与最终 JSON 响应各 ≤1 MiB。超限结果标记截断或安全失败，不截断已编码的 JSON 字节。
- OPK 最多读取 8 MiB 快照，在 `ZipFile` 构造前校验实际中央目录 ≤256 KiB / 1024 项，拒绝有歧义的 EOCD 注释；拒绝 ZIP64、多卷、加密包与重复清单；只读取 ≤64 KiB 的 `app.json`，不 `extractall`。
- `cockpit_plugins` 按逐条记录的紧凑 ASCII JSON 字节累计聚合预算（响应上限的 1/4），可能早于 500 条截断并标记；文件名和错误记录同样计入，单包 `cockpit_meta` 不因此截短字段。
- **两套独立 8 名额**：所有 HTTP 请求（含 ping/tools/list）占入口名额，满额立即 503；`tools/call` 另占 worker 名额，超时释放 HTTP 等待不代表尚未结束的 worker 名额已归还。等待预算 10 秒；超时或取消只结束等待，未结束的调用继续占用名额，不补开线程；不会撤销已提交的发送或重启。**写操作超时后不要自动重试**。
- `cockpit_raw_events` 缓存 ≤256 条、单条 ≤64 KiB、总量 ≤4 MiB、保留 5 分钟；单次返回最多 8 条且 ASCII JSON 合计 ≤256 KiB；裁剪、预算丢弃及采集锁竞争都会标记不完整。意外读取故障返回固定安全工具错误，不伪装正常空快照；服务侧取消继续传播。
- `cockpit_reload` 在 HTTP 响应写完后才请求 `set_restart()`。响应只表示已接受，重启的是整个插件加载器（含 Cockpit 自身），所有传统会话随之结束。
- 插件与其他插件共用加载器进程。Python 异常兜底不能隔离段错误、C 扩展死循环占满 GIL 或宿主内存耗尽；`BaseException` 捕获也不能终止已阻塞的线程。

## 8. 服务生命周期与协议边界

- 初始化失败（含重复 init 时 `getcwd()` 失败或宿主数据路径非法）会按对象身份对旧 context/manager 及新建候选执行完整拆除序列：manager 撤权并停止 → 服务停止 → 原始事件观察卸载 → 拦截器卸载并清规则；每步独立兜底，旧钩子不会因清引用而失去清理入口。
- `ConfigManager.stop()` 在自身锁内清 pending、使快照失效且无 key、递增 generation；停止后的迟到轮询不能重新发布或恢复授权。`_on_config` 忽略已停止 manager 的迟到回调。
- 同一加载器重复初始化且 Proc、路径根、OlivOS 引用与未停止 manager 均未改变时，复用原冻结 Context；来源变化会撤销旧 manager 并建立新 owner，不原地改写在途请求使用的路径字段。新监督目标先登记，旧监督循环退出后接替；旧回调不能用迟到结果覆盖新 owner 的待启动状态。
- 旧服务或 worker 尚未退尽时保留有限待接替目标，不另建池；健康 tick 不重复 apply/reconcile。服务创建前有唯一启动占位，发布前重新检查 manager 停止/快照失效；失败候选也要关闭并等待 worker 退尽。关闭的池不再接收新任务。旧 refresh 或 SDK 阻塞可能无限期延后接替，不承诺一个轮询周期内恢复。
- `request_stop` 先经 close/_closed 记住停止并关闭提交门，再通知 loop；loop 尚未发布也不丢失停止意图。首轮与后续配置重绑共用同一调度入口，同一服务峰值最多一个 reconcile，正常配置热更新不重建池。
- 配置代次在请求开始与响应写出之间变化时：已成功接受的通知保留 202 空正文；错误响应保留既有 HTTP 状态、头与已知 Reject 错误码；普通有 id 的工具成功结果被替换为固定安全错误且 `after_send` 不执行。
- 会话有效性与协商版本在单锁内一次查询；过期、淘汰或 key 轮换都按未知会话返回 404。
- 旧的固定地址入口 `service.start(...)` 已**显式弃用**（2026-11-08）：保留同名签名以便导入兼容，但调用即返回固定 `ToolError`，不再建池或监听。它没有配置快照，服务级放行与 handler 内代次/授权复核相互矛盾；请改用配置驱动的 `apply_config` / `start_managed` 入口。这是外部兼容性变化，依赖旧入口的仓库外调用方必须迁移。
- 协议响应在 `prepare()` 后不可再改写；不承诺网络发送与配置更新是原子事务。

### 客户端接入

默认端点为 `http://127.0.0.1:8767/mcp`（随 `listen_host` / `listen_port` 变化），通过 Streamable HTTP 的 POST 请求接入。请求头包括：

```text
Authorization: Bearer <config.json 中的 api_key>
Content-Type: application/json
Accept: application/json, text/event-stream
```

服务只返回 JSON，不实现 SSE，不接受批量请求。`Origin` 存在且与 `listen_host` 不一致时返回 403（DNS rebinding 防护；不是认证）。

#### 传统客户端（2024-11-05 / 2025-03-26 / 2025-06-18 / 2025-11-25）

1. POST `initialize`（`protocolVersion`、`capabilities`、`clientInfo` 必填；未知版本协商回落到 `2025-11-25`），响应头返回 `Mcp-Session-Id`。
2. 带会话 ID 发送 `notifications/initialized`，返回 202 空正文。
3. 后续请求携带会话 ID 与已协商的协议版本头；版本头与协商值不一致返回 400。
4. 会话 30 分钟过期、被淘汰、key 轮换或加载器重启后返回 404，客户端不带旧 ID 重新 `initialize`。

`2024-11-05` 仅通过本服务的 POST 绑定承载；先等 SSE `endpoint` 事件的原生 HTTP+SSE 老客户端不在支持范围。

#### 现代客户端（2026-07-28）

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

#### 常见错误

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

## 9. 验收边界与测试

- 无 `aiohttp` 的环境会跳过 HTTP 相关集成测试，未显式启用时也会跳过真实加载器测试；跳过不等于通过。`test_service_core.py` 的无 HTTP 库单元测试不能替代真实传输验收。
- OPK 解包目录删除后首次调用、Full/Lite 模块物理隔离、接口台账/工具绑定与资源预算均有独立回归检查。
- 真实平台送达、源码/目标二进制/容器部署、不同操作系统必须分别验证；不由静态源码或 stub 测试推断兼容范围。缺少 POSIX 安全文件原语的平台禁用相关文件能力，不做有竞态的降级。
- 台账不是“所有接口均可执行”的承诺。未安全绑定的接口内部保留，已经发布的工具仍可能因权限、账号模型或运行时能力缺失而安全失败。

开发与测试命令见 [AGENTS.md](../AGENTS.md)。
