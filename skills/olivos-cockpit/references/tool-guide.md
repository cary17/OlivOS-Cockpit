# 工具路由与读取

这是运行时使用参考，不是源码模块地图。名称与参数来自当前公开注册表；现场工具 schema 与实际返回值始终优先。不要猜不存在的候选工具或从名字推导额外参数。先按主 skill 确认实际接入与调用条件：没有实际工具时停止；目标与必填参数来自已授权、可核实的结果。

## 1. 总览、插件与元数据

| 工具 | 必填参数 | 适用问题与限制 |
|---|---|---|
| `cockpit_status` | 无 | 宿主/加载器总览、已加载 namespace、配置账号数量、调试终端状态；读取权限不足的字段可能 unknown |
| `cockpit_plugins` | 无 | 已安装 OPK/解包目录的安全元数据，不证明已经加载 |
| `cockpit_meta` | namespace 或 filename 选目标 | 只读取包的 app.json 元数据，不整体解包；先从安装清单取得目标 |
| `cockpit_plugin_loaded_list` | 无 | 当前加载清单与可取得的详情，注意 available、unknown_fields 和 details_truncated |
| `cockpit_account_type_catalog` | 无 | 宿主声明的账号类型，不是当前账号清单 |
| `cockpit_accounts_schema` | 无 | 账号输入 schema，不读取现有凭据 |
| `cockpit_accounts_validate` | account | 对给定账号配置做校验，不创建账号、不证明能连接；不要求用户把凭据贴到对话 |

示例（目标 namespace 须来自实际安装清单）：

```json
{"name":"cockpit_plugin_loaded_list","arguments":{}}
```

```json
{"name":"cockpit_meta","arguments":{"namespace":"target_plugin"}}
```

## 2. 账号、日志、数据和事件

| 工具 | 参数入口 | 正确解释 |
|---|---|---|
| `cockpit_bots` | `{}` | 加载器账号字典的配置账号；从实际返回的 `bots[].hash` 原样取得值，作为下游工具的 `bot_hash` 参数；不计算或猜 hash。存在不等于在线 |
| `cockpit_log` | 可选 filename、lines、level、namespace | 只读宿主日志目录；先少量尾部再缩小范围；最多 2000 行。插件数据 namespace 内的 `.log` 文件用 `cockpit_data` 读取。当前 `lines` 返回拼接字符串，分析时按换行处理，不按数组逐字符消费 |
| `cockpit_data` | namespace；可选 mode、path、cursor | mode=list/read，path 相对 namespace；只读文本/目录，不接受任意 offset；游标续读保持原目标 |
| `cockpit_raw_events` | 可选 limit（1–8） | 加载器 run_plugin 转换前的白名单快照；有界缓存约保留 5 分钟，不是网络抓包或全部原始流量 |
| `cockpit_accounts_config` | 可选 offset、limit（每页最多 50） | 磁盘启动链声明的账号存档，含停用项；不是总控当前内存配置 |

读取原则：

- 日志没有匹配项、原始事件为空，都要同时检查权限、过滤、采样范围、截断和可用性；不直接判定“对方没发”或“插件没收到”。
- raw 不包括适配器在接缝前丢弃的帧、控制面/菜单/WebUI，也不记录插件主动出站调用。Lite 真实读关闭时只保留允许的选中虚拟终端范围。
- `cockpit_data` 每次源读和响应有预算；paged 结果按 next_cursor 续读。末页仍是分页片段，不带完整原文 SHA。
- 账号存档另用 offset/limit。返回 `accounts[].index`、全文件 `sha256` 和 total；每次写前重读目标页并核对用户目标，不能把不同修订的索引/哈希拼在一起。
- 返回正文可能已经脱敏。`[REDACTED]` 不是真实密码或可回写配置；未知敏感值也可能没有被识别。

## 3. 原生账号只读查询

这些查询需要真实账号读权限，并可能联系适配器。只对当前任务的目标账号按需调用；不在 status 初查时遍历所有账号发起全部查询。`bot_hash` 参数值只从 `cockpit_bots` 实际返回的 `bots[].hash` 原样取得；虚拟终端目标只从 `cockpit_status.debug_terminal.account.hash` 的实际返回取得（字段以现场返回为准）。普通账号、终端账号都不猜、不遍历扇出；群/用户/消息 ID 从用户授权范围或对应清单取得。

schema 校验通过不等于适配器查询成功；原生查询返回 unsupported、failed safely 或 `isError` 时保留不确定性，不当作空列表、离线或成功。

下表只列必填参数；可选 no_cache、host_id、count、file_count 等必须按现场 schema 使用，ID 类型也以 schema 为准。

| 工具 | 必填参数 |
|---|---|
| `cockpit_account_connection_status` | bot_hash |
| `cockpit_account_login_info` | bot_hash |
| `cockpit_protocol_version` | bot_hash |
| `cockpit_send_capabilities` | bot_hash |
| `cockpit_friend_list` | bot_hash |
| `cockpit_friend_doubt_requests` | bot_hash |
| `cockpit_group_list` | bot_hash |
| `cockpit_group_info` | bot_hash、group_id |
| `cockpit_group_member_list` | bot_hash、group_id |
| `cockpit_group_member_info` | bot_hash、group_id、user_id |
| `cockpit_group_notice_list` | bot_hash、group_id |
| `cockpit_group_system_msg` | bot_hash |
| `cockpit_group_ignored_requests` | bot_hash |
| `cockpit_group_essence_list` | bot_hash、group_id |
| `cockpit_group_file_stats` | bot_hash、group_id |
| `cockpit_group_file_list` | bot_hash、group_id |
| `cockpit_group_folder_list` | bot_hash、group_id、folder_id |
| `cockpit_host_list` | bot_hash |
| `cockpit_host_info` | bot_hash、host_id |
| `cockpit_user_info` | bot_hash、user_id |
| `cockpit_message_get` | bot_hash、message_id |
| `cockpit_message_forward_get` | bot_hash、message_id |

`cockpit_protocol_version` 查询的是账号适配器的原生版本信息，不是 MCP 协议协商。群文件查询返回原生信息，不授权下载任意 URL 或读取宿主任意文件。

报告 SDK 查询结论时保留来源，例如“该适配器查询报告在线”；不要用它把所有账号统一标成在线，也不要用一次查询证明历史时刻的状态。

## 4. 高权限只读取值

常规版本/加载信息先用 status，不为方便而要求开启底层权限。

`cockpit_proc_get` 仅接受 `plugin_names`、`bot_hashes`、`olivos_version`、`olivos_svn` 四个 path，不能读取任意对象、调用方法或访问凭据。即使 readOnlyHint 为真，仍需 Full 写与底层开关同时开启。

```json
{"name":"cockpit_proc_get","arguments":{"path":"bot_hashes"}}
```

该例仅供已经具备相应授权的底层诊断任务使用；取到空数组也需检查截断和采样语义，不把它等同于原子快照中的“全局没有账号”。
