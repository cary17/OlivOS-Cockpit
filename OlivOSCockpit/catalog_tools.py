"""固定版本接口目录中的历史/审计候选快照；永不并入运行注册表。

本模块是固定 Release 静态审阅的候选登记快照，仅作审计对照；Full/Lite
两个构建都不导入它，公开工具表以 registry 与 interfaces.json 的
tool_bindings 为准，不得把此表并入任何运行时注册层。

这些候选项使用显式 ToolSpec 登记，但尚未绑定可证明安全的执行路径，
因此 handler 只返回固定不可用错误；不提供模块/属性/SQL/shell 反射入口。
隐藏或内部接口不会进入此表。
"""

from .contracts import ToolSpec, failure, object_schema

REAL_READ = 'real_account_read'
REAL_WRITE = 'real_account_write'
LOW_LEVEL = 'low_level_access'

def _unavailable(_ctx, _args):
    return failure('This registered capability has no safe execution path')

def _permission(value):
    return {'real_read': REAL_READ, 'write': REAL_WRITE, 'low_level': LOW_LEVEL}.get(value)

def _read_only(value):
    return value not in ('write', 'low_level')

CATALOG = (
    {
        'name': 'cockpit_account_connection_status',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_account_connection_status 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_account_login_info',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_account_login_info 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_account_type_catalog',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_account_type_catalog 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/accountMetadataAPI.py',
    },
    {
        'name': 'cockpit_accounts_schema',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_accounts_schema 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/webUI/pageAPI.py',
    },
    {
        'name': 'cockpit_accounts_validate',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_accounts_validate 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/webUI/pageAPI.py',
    },
    {
        'name': 'cockpit_friend_doubt_requests',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_friend_doubt_requests 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_friend_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_friend_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_essence_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_essence_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_file_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_file_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_file_stats',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_file_stats 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_folder_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_folder_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_ignored_requests',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_ignored_requests 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_info',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_info 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_member_info',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_member_info 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_member_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_member_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_notice_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_notice_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_group_system_msg',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_group_system_msg 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_host_info',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_host_info 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_host_list',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_host_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_message_forward_get',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_message_forward_get 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_message_get',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_message_get 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_message_reaction',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_message_reaction 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_message_recall',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_message_recall 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_onebot11_capability',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_onebot11_capability 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot11_contacts',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_onebot11_contacts 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot11_file_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_onebot11_file_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot11_identity',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_onebot11_identity 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot11_message_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_onebot11_message_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot11_recall',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_onebot11_recall 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot11_send_message',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_onebot11_send_message 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV11/onebotSDK.py',
    },
    {
        'name': 'cockpit_onebot12_recall',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_onebot12_recall 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV12/onebotV12SDK.py',
    },
    {
        'name': 'cockpit_onebot12_send_message',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_onebot12_send_message 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/onebotV12/onebotV12SDK.py',
    },
    {
        'name': 'cockpit_plugin_config_get',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_plugin_config_get 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/userModule/UserConfDB.py',
    },
    {
        'name': 'cockpit_plugin_config_set',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_plugin_config_set 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/userModule/UserConfDB.py',
    },
    {
        'name': 'cockpit_plugin_loaded_list',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_plugin_loaded_list 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/pluginAPI.py',
    },
    {
        'name': 'cockpit_plugin_priority',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_plugin_priority 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/pluginAPI.py',
    },
    {
        'name': 'cockpit_plugin_reload',
        'permission': 'low_level',
        'description': '固定 Release 中登记的 cockpit_plugin_reload 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/pluginAPI.py',
    },
    {
        'name': 'cockpit_poke',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_poke 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_protocol_version',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_protocol_version 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_qqguild_guild_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_guild_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKGuild.py',
    },
    {
        'name': 'cockpit_qqguild_identity',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_identity 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildSDK.py',
    },
    {
        'name': 'cockpit_qqguild_member_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_member_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKGuild.py',
    },
    {
        'name': 'cockpit_qqguild_menu_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_menu_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_qqguild_message_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_message_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_qqguild_qq_group_read',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_qq_group_read 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKGroup.py',
    },
    {
        'name': 'cockpit_qqguild_recall',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_qqguild_recall 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_qqguild_send_card',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_qqguild_send_card 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_qqguild_send_markdown',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_qqguild_send_markdown 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_qqguild_send_message',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_qqguild_send_message 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildSDK.py',
    },
    {
        'name': 'cockpit_qqguild_send_private',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_qqguild_send_private 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKGuildPrivate.py',
    },
    {
        'name': 'cockpit_qqguild_unhandled_events',
        'permission': 'virtual_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_unhandled_events 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_qqguild_user_cache',
        'permission': 'virtual_read',
        'description': '固定 Release 中登记的 cockpit_qqguild_user_cache 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/adapter/qqGuild/qqGuildv2SDKCommon.py',
    },
    {
        'name': 'cockpit_send_capabilities',
        'permission': 'metadata',
        'description': '固定 Release 中登记的 cockpit_send_capabilities 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_send_forward',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_send_forward 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_send_message',
        'permission': 'write',
        'description': '固定 Release 中登记的 cockpit_send_message 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
    {
        'name': 'cockpit_user_info',
        'permission': 'real_read',
        'description': '固定 Release 中登记的 cockpit_user_info 能力；当前无安全执行路径，调用返回结构化不可用错误。来源：OlivOS/core/core/API.py',
    },
)

TOOLS = tuple(
    ToolSpec(
        name=item['name'],
        description=item['description'],
        schema=object_schema(),
        handler=_unavailable,
        read_only=_read_only(item['permission']),
        required_permission=_permission(item['permission']),
    ) for item in CATALOG
)
LITE_TOOLS = tuple(tool for tool in TOOLS if tool.required_permission is None)
