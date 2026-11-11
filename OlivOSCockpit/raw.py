"""有界的 SDK 原始事件观察。

这里只包装传入 Context 的 ``proc.run_plugin`` 实例。包装器先尝试复制
SDK 事件的显式白名单字段，再恰好调用原方法一次；观察失败不会改变宿主
调用结果。模块不读写文件、不等待队列、不创建线程，也不提供脚本执行或
出站调用拦截。调用方通过 ``policy`` 在采集和读取时实现 Full/Lite 权限过滤。

缓存保存的是白名单投影后的原生 JSON 副本，包括字段名敏感的键；缓存本身
不做脱敏，字段 allow/redact 与关闭脱敏只在唯一出站边界（协议响应构造）
生效。读取先按 limit 选取最新记录，再有界复制，返回明确标记截断。

观察范围是 ``run_plugin`` 收到的、SDK 转换前的数据面事件。控制面、菜单、
WebUI、插件主动发出的出站调用，以及适配器在进入该接缝前丢弃的帧都不在
覆盖范围内；快照不是全流量记录。无法用当前加载器的账号字典唯一确认归属
的事件直接丢弃。
"""

import asyncio
import json
import math
import threading
import time

from .contracts import ToolError

MAX_DEPTH = 8
MAX_NODES = 2000
MAX_RECORD_BYTES = 64 * 1024
MAX_RECORDS = 256
MAX_CACHE_BYTES = 4 * 1024 * 1024
RETENTION_SECONDS = 5 * 60
MAX_RETURN_RECORDS = 8
# 双表示中 text 再转义最坏接近两倍，加 structuredContent 接近三倍；留出信封余量。
MAX_READ_BYTES = 256 * 1024
MAX_BOTS = 500
HASH_LENGTH = 32

# 与固定 Release 的 OneBot V11 账号类型一致：messageAPI 中 sdk=onebot/
# platform=qq 且收发文本为 old_string 的模型，加上 accountMetadataAPI 中
# 仅有账号类型、接收同样走 old_string 的 shamrock_default。
# 原生 V11 SDK 事件始终上报 model='default'。
ONEBOT_V11_MODELS = (
    'default', 'gocqhttp', 'gocqhttp_hide', 'gocqhttp_show',
    'gocqhttp_show_Android_Phone', 'gocqhttp_show_Android_Pad',
    'gocqhttp_show_Android_Watch', 'gocqhttp_show_iPad', 'gocqhttp_show_iMac',
    'gocqhttp_show_old', 'napcat', 'napcat_hide', 'napcat_show', 'napcat_show_new',
    'napcat_show_new_9_9_19', 'napcat_show_old', 'napcat_default',
    'llonebot_default', 'lagrange_default', 'shamrock_default',
)

_USE_INSTALLED = object()
_MISSING = object()
_SKIP = object()
_ANY = object()
_MARKER = '_olivos_cockpit_raw_observer'
_READ_FAILED = 'Raw event snapshot unavailable'
# 模块级安装/卸载互斥；事件回调从不获取它。
_INSTALL_LOCK = threading.RLock()

_ADAPTER_NAMES = (
    'onebot_v11',
    'onebot_v12',
    'milky',
    'opqbot',
    'red',
    'biliLive',
    'dingtalk',
    'discord',
    'dodo_link',
    'dodo_poll',
    'dodobot_ea',
    'fanbook',
    'hackChat',
    'kaiheila',
    'mhyVila',
    'qqGuild',
    'qqGuildv2',
    'telegram',
    'virtualTerminal',
    'xiaoheihe',
)

_COVERAGE_EXCLUDED = (
    'control-plane packets',
    'menu and WebUI events',
    'plugin-initiated outbound calls',
    'frames discarded before run_plugin',
)

_NOT_FULL_TRAFFIC = (
    'Snapshot of whitelisted fields on run_plugin input only; '
    'not a full traffic capture and not a substitute for adapter logs.'
)


def _keys(*names):
    return {name: None for name in names}


def _list(spec):
    return ('list', spec)


# The specs below are deliberately explicit. _ANY is used only for a native JSON
# field whose adapter owns the field as a whole; every string key is kept so the
# outbound redaction boundary can see credential-named fields.
_OPQ_SPEC = {
    'CurrentQQ': None,
    'CurrentPacket': {
        'EventName': None,
        'EventData': {
            'MsgHead': _keys(
                'FromUin', 'ToUin', 'SenderUin', 'SenderNick', 'MsgType',
                'C2cCmd', 'FromUid',
            ),
            'MsgBody': {
                'Content': None,
                'AtUinLists': _list(_keys('Uin', 'Nick')),
            },
            'Event': _keys('Invitee', 'Invitor'),
            'MsgType': None,
            'GroupCode': None,
            'MsgSeq': None,
            'Status': None,
            'MsgAdditional': None,
            'ActorUid': None,
        },
    },
    'CgiBaseResponse': {'Ret': None},
    'ReqId': None,
    'ResponseData': _ANY,
}

_ONEBOT_SENDER_SPEC = _keys(
    'user_id', 'nickname', 'card', 'sex', 'age', 'area', 'level', 'role', 'title',
)
_ONEBOT_SPEC = {
    'time': None,
    'self_id': None,
    'post_type': None,
    'message_type': None,
    'sub_type': None,
    'message_id': None,
    'user_id': None,
    'group_id': None,
    'discuss_id': None,
    'guild_id': None,
    'channel_id': None,
    'host_id': None,
    'message': _ANY,
    'raw_message': _ANY,
    'alt_message': _ANY,
    'sender': _ONEBOT_SENDER_SPEC,
    'anonymous': _ANY,
    'font': None,
    'status': _ANY,
    'notice_type': None,
    'notice_sub_type': None,
    'operator_id': None,
    'request_type': None,
    'comment': None,
    'flag': None,
    'approve': None,
    'role': None,
    'invitee': None,
    'group_upload': _ANY,
}

_ONEBOT_V12_SPEC = {
    'type': None,
    'detail_type': None,
    'sub_type': None,
    'self_id': None,
    'time': None,
    'id': None,
    'version': None,
    'protocol': None,
    'request_id': None,
    'user_id': None,
    'group_id': None,
    'guild_id': None,
    'channel_id': None,
    'message_scene': None,
    'message': _ANY,
    'alt_message': _ANY,
    'mentions': _ANY,
    'sender': _ANY,
    'friend': _ANY,
    'group': _ANY,
    'group_member': _ANY,
    'operator_id': None,
    'role': None,
    'emoji': _ANY,
    'button': _ANY,
}

_MILKY_DATA_SPEC = {
    'message_scene': None,
    'peer_id': None,
    'message_seq': None,
    'sender_id': None,
    'segments': _ANY,
    'friend': _ANY,
    'group': _ANY,
    'group_member': _ANY,
    'operator_id': None,
    'user_id': None,
    'group_id': None,
    'duration': None,
    'is_set': None,
    'file_id': None,
    'file_name': None,
    'file_size': None,
    'initiator_id': None,
    'initiator_uid': None,
    'notification_seq': None,
    'invitation_seq': None,
    'is_filtered': None,
    'comment': None,
    'users': _ANY,
    'message': _ANY,
}
_MILKY_SPEC = {
    'status': None,
    'retcode': None,
    'message': None,
    'post_id': None,
    'data': _MILKY_DATA_SPEC,
    'event_type': None,
    'self_id': None,
    'time': None,
}

_DINGTALK_SPEC = {
    'headers': _keys('messageId', 'topic'),
    'type': None,
    'data': {
        'chatbotUserId': None,
        'msgtype': None,
        'conversationType': None,
        'conversationId': None,
        'senderStaffId': None,
        'senderId': None,
        'senderNick': None,
        'isAdmin': None,
        'atUsers': _list(_keys('staffId', 'dingtalkId')),
        'text': {'content': None},
        'content': {
            'richText': _list(_keys('text', 'type')),
            'downloadCode': None,
            'videoType': None,
        },
    },
}

_DISCORD_SPEC = {
    'op': None,
    's': None,
    't': None,
    'd': {
        'content': None,
        'channel_id': None,
        'id': None,
        'guild_id': None,
        'author': _keys('id', 'username'),
        'attachments': _list(_keys('content_type', 'url')),
        'member': {'roles': _list(None)},
    },
}

_DODO_LINK_SPEC = {
    'type': None,
    'data': {
        'eventType': None,
        'eventBody': {
            'messageType': None,
            'messageBody': _keys('content', 'url'),
            'islandSourceId': None,
            'dodoSourceId': None,
            'islandId': None,
            'dodoId': None,
            'channelId': None,
            'messageId': None,
            'personal': None,
        },
    },
}

_DODO_POLL_SPEC = _keys(
    'id', 'uid', 'nickName', 'content', 'resourceJson', 'channelId', 'islandId',
)
_DODOBOT_EA_SPEC = _keys(
    'FromChannel', 'Uid', 'Content', 'OriginalContent', 'Id', 'NickName',
)
_FANBOOK_SPEC = {
    'channel_post': {
        'text': None,
        'photo': _list(_keys('file_id')),
        'message_id': None,
        'chat': _keys('id', 'type', 'guild_id'),
        'from': _keys('id', 'first_name'),
    },
}
_HACKCHAT_SPEC = {
    'cmd': None,
    'nick': None,
    'text': None,
    'userid': None,
    'users': _list(_keys('isme', 'userid')),
}
_KAIHEILA_SPEC = {
    's': None,
    'sn': None,
    'd': {
        'channel_type': None,
        'target_id': None,
        'author_id': None,
        'msg_id': None,
        'type': None,
        'content': None,
        'extra': {
            'type': None,
            'guild_id': None,
            'body': _ANY,
            'author': _keys('id', 'username', 'is_master', 'roles'),
        },
    },
}
_MHY_VILA_SPEC = {
    'type': None,
    'id': None,
    'createdAt': None,
    'extendData': {
        'sendMessage': _keys(
            'content', 'fromUserId', 'roomId', 'nickname', 'msgUid', 'villaId',
            'objectName',
        ),
    },
}
_QQ_GUILD_SPEC = {
    'op': None,
    'd': _ANY,
    's': None,
    't': None,
    'id': None,
}
_MILKY_OR_TELEGRAM_ENTITY = _list(_keys('type', 'offset', 'length'))
_TELEGRAM_SPEC = {
    'update_id': None,
    'message': {
        'date': None,
        'message_id': None,
        'text': None,
        'caption': None,
        'entities': _MILKY_OR_TELEGRAM_ENTITY,
        'photo': _list(_keys('file_id')),
        'sticker': {'file_id': None},
        'chat': _keys('id', 'type'),
        'from': _keys('id', 'first_name'),
        'new_chat_member': {'id': None},
        'left_chat_member': {'id': None},
    },
}
_TERMINAL_KEY_SPEC = {
    'data': {
        'data': None,
        'user_conf': _keys(
            'user_name', 'user_id', 'flag_group', 'target_id', 'group_role',
        ),
    },
}
_TERMINAL_HTTP_SPEC = {
    'type': None,
    'message_type': None,
    'group_id': None,
    'user_id': None,
    'message': None,
}
_XIAOHEIHE_SPEC = {
    'sequence': None,
    'type': None,
    'notify_type': None,
    'timestamp': None,
    'data': {
        'room_id': None,
        'channel_id': None,
        'msg_id': None,
        'user_id': None,
        'nickname': None,
        'msg': None,
        'is_master': None,
        'roles': _ANY,
        'room_base_info': {'room_id': None},
        'user_info': {'user_id': None},
        'state': None,
    },
}

# (adapter name, event source path, projection spec)
_EXTRACTORS = {
    'onebot_v11': (('json',), _ONEBOT_SPEC),
    'onebot_v12': (('json',), _ONEBOT_V12_SPEC),
    'milky': (('json',), _MILKY_SPEC),
    'opqbot': (('payload', 'data'), _OPQ_SPEC),
    'red': (('payload',), {
        'type': None,
        'payload': _list({
            'chatType': None,
            'peerUid': None,
            'senderUin': None,
            'sendNickName': None,
            'sendMemberName': None,
            'peerUin': None,
            'elements': _list({
                'textElement': _keys('content', 'atType', 'atNtUin'),
            }),
        }),
    }),
    'biliLive': (('payload',), _keys('msg', 'uid', 'uname')),
    'dingtalk': (('payload', 'data'), _DINGTALK_SPEC),
    'discord': (('payload', 'data'), _DISCORD_SPEC),
    'dodo_link': (('payload', 'data'), _DODO_LINK_SPEC),
    'dodo_poll': (('json',), _DODO_POLL_SPEC),
    'dodobot_ea': (('json',), _DODOBOT_EA_SPEC),
    'fanbook': (('json',), _FANBOOK_SPEC),
    'hackChat': (('payload',), _HACKCHAT_SPEC),
    'kaiheila': (('payload', 'data'), _KAIHEILA_SPEC),
    'mhyVila': (('payload',), _MHY_VILA_SPEC),
    'qqGuild': (('payload', 'data'), _QQ_GUILD_SPEC),
    'qqGuildv2': (('payload', 'data'), _QQ_GUILD_SPEC),
    'telegram': (('json',), _TELEGRAM_SPEC),
    'xiaoheihe': (('payload', 'data'), _XIAOHEIHE_SPEC),
}


def _register_models(adapter, sdk, platform, models):
    for model in models:
        _ADAPTER_BY_PLATFORM[(sdk, platform, model)] = adapter


_ADAPTER_BY_PLATFORM = {}
_register_models('onebot_v11', 'onebot', 'qq', ONEBOT_V11_MODELS)
_register_models('onebot_v12', 'onebot', 'qq', ('onebotV12',))
_register_models(
    'milky', 'onebot', 'qq',
    ('milky_default', 'llonebot_milky', 'lagrange_milky', 'yogurt_milky'),
)
_register_models(
    'opqbot', 'onebot', 'qq',
    ('opqbot_default', 'opqbot_auto', 'opqbot_port', 'opqbot_port_old'),
)
_register_models('red', 'onebot', 'qq', ('red',))
_register_models('biliLive', 'biliLive_link', 'biliLive', ('default',))
_register_models('dingtalk', 'dingtalk_link', 'dingtalk', ('default',))
_register_models('discord', 'discord_link', 'discord', ('default',))
_register_models('dodo_link', 'dodo_link', 'dodo', ('default', 'v1'))
_register_models('dodo_poll', 'dodo_poll', 'dodo', ('default',))
_register_models('dodobot_ea', 'dodobot_ea', 'dodo', ('default',))
_register_models('fanbook', 'fanbook_poll', 'fanbook', ('default',))
_register_models('hackChat', 'hackChat_link', 'hackChat', ('default',))
_register_models('kaiheila', 'kaiheila_link', 'kaiheila', ('default', 'text', 'card'))
_register_models('mhyVila', 'mhyVila_link', 'mhyVila', ('default',))
_register_models('qqGuild', 'qqGuild_link', 'qqGuild', ('default',))
_register_models('qqGuildv2', 'qqGuildv2_link', 'qqGuild', ('default',))
_register_models(
    'telegram', 'telegram_poll', 'telegram', ('default',)
)
_register_models(
    'telegram', 'telegram_hook', 'telegram', ('default',)
)
_register_models(
    'telegram', 'telegram', 'telegram', ('default',)
)
_register_models('virtualTerminal', 'terminal_link', 'terminal', ('default', 'postapi', 'ff14'))
_register_models('xiaoheihe', 'xiaoheihe_link', 'xiaoheihe', ('default',))


def _mapping(value):
    if type(value) is dict:
        return value
    try:
        # 按实例字典取值，避免逐字段 getattr 触发宿主属性逻辑。
        fields = object.__getattribute__(value, '__dict__')
    except (AttributeError, TypeError):
        return None
    return fields if type(fields) is dict else None


def _value(value, key):
    mapping = _mapping(value)
    if mapping is None:
        return _MISSING
    return mapping.get(key, _MISSING)


def _path(value, path):
    for key in path:
        value = _value(value, key)
        if value is _MISSING:
            return _MISSING
    return value


def _scalar(value):
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > MAX_RECORD_BYTES * 8:
            raise _Limit
        return value
    if type(value) is float:
        return value if math.isfinite(value) else _SKIP
    if type(value) is str:
        if len(value) > MAX_RECORD_BYTES:
            raise _Limit
        if len(value.encode('utf-8')) > MAX_RECORD_BYTES:
            raise _Limit
        return value[:]
    return _SKIP


class _Budget:
    __slots__ = ('nodes', 'bytes')

    def __init__(self):
        self.nodes = 0
        self.bytes = 0

    def charge(self, amount=1):
        self.nodes += 1
        self.bytes += amount
        if self.nodes > MAX_NODES or self.bytes > MAX_RECORD_BYTES:
            raise _Limit


class _Limit(Exception):
    pass


class _HostHashUnavailable(Exception):
    """宿主 getBotHash 缺失、出错或返回值形状不符；按 unknown_bot 丢弃。"""


def _copy_json(value, budget, depth=0):
    if depth > MAX_DEPTH:
        raise _Limit
    budget.charge()
    scalar = _scalar(value)
    if scalar is not _SKIP:
        budget.charge(len(scalar.encode('utf-8')) if type(scalar) is str else 1)
        return scalar
    if type(value) is list:
        result = []
        for item in value:
            result.append(_copy_json(item, budget, depth + 1))
        return result
    if type(value) is dict:
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                continue
            budget.charge(len(key.encode('utf-8')))
            copied = _copy_json(item, budget, depth + 1)
            if copied is not _SKIP:
                result[key[:]] = copied
        return result
    return _SKIP


def _project(value, spec, budget, depth=0):
    if depth > MAX_DEPTH:
        raise _Limit
    if spec is _ANY:
        return _copy_json(value, budget, depth)
    if spec is None:
        return _scalar(value)
    if type(spec) is tuple and len(spec) == 2 and spec[0] == 'list':
        if type(value) is not list:
            return _SKIP
        budget.charge()
        result = []
        for item in value:
            copied = _project(item, spec[1], budget, depth + 1)
            if copied is not _SKIP:
                result.append(copied)
        return result
    if type(spec) is dict:
        mapping = _mapping(value)
        if mapping is None:
            return _SKIP
        budget.charge()
        result = {}
        for key, child_spec in spec.items():
            item = mapping.get(key, _MISSING)
            if item is _MISSING:
                continue
            copied = _project(item, child_spec, budget, depth + 1)
            if copied is not _SKIP:
                result[key] = copied
        return result
    return _SKIP


def _identifier(value):
    if type(value) is str:
        return value
    if type(value) is int and not isinstance(value, bool):
        return str(value)
    return None


def _native_digest(native, bot_id, sdk, platform):
    """调用注入的宿主 getBotHash（id+sdk+platform，不含 model）。

    参数名与固定基线 ``API.getBotHash`` 一致；缺失能力、调用失败或返回值
    形状不符时归为 ``_HostHashUnavailable``（按 unknown_bot 丢弃），不回落
    本地算法，返回值须为 32 字符的原生字符串。
    """
    if not callable(native):
        raise _HostHashUnavailable
    try:
        digest = native(
            bot_id=bot_id, platform_sdk=sdk, platform_platform=platform,
            platform_model=None)
    except asyncio.CancelledError:
        # 这不是向宿主透传取消：本模块运行在同步宿主回调线程，没有可传播的
        # asyncio 任务。重抛只是内部分类约定，最终由 _observe 的边界把取消
        # 与其他观察自身异常一并转为 drop 计数，原宿主调用仍恰好执行一次。
        raise
    except BaseException:
        raise _HostHashUnavailable from None
    if type(digest) is not str or len(digest) != HASH_LENGTH:
        raise _HostHashUnavailable
    return digest


def _platform(event):
    platform = _mapping(_value(event, 'platform'))
    if platform is None:
        return None
    sdk = platform.get('sdk')
    name = platform.get('platform')
    model = platform.get('model')
    if type(sdk) is not str or type(name) is not str or type(model) is not str:
        return None
    return sdk, name, model


_LIMITED = object()


def _owned_bot(proc, native, self_id, event_platform):
    """按宿主 getBotHash（id+sdk+platform，不含 model）定位唯一配置账号。

    原生 V11 SDK 事件始终上报 model='default'，配置账号可能是 napcat_default
    等；这类事件按 V11 模型清单映射。其他适配器（V12/Milky/OPQ 等共享
    sdk=onebot/platform=qq）必须与配置三元组完全一致，避免误归属。
    未知 model 仍由 ``_adapter`` 拒绝，不扩大支持范围。
    持有字典超过 MAX_BOTS 时返回 _LIMITED，与形状错误/归属不匹配区分诊断。
    """
    proc_data = _value(proc, 'Proc_data')
    bots = _value(proc_data, 'bot_info_dict')
    if type(bots) is not dict:
        return None
    if len(bots) > MAX_BOTS:
        return _LIMITED
    expected = _native_digest(native, self_id, event_platform[0], event_platform[1])
    bot = bots.get(expected, _MISSING)
    if bot is _MISSING:
        return None
    fields = _mapping(bot)
    if fields is None:
        return None
    bot_platform = _value(fields, 'platform')
    if type(bot_platform) is not dict:
        return None
    triple = (
        bot_platform.get('sdk'), bot_platform.get('platform'), bot_platform.get('model')
    )
    if (any(type(item) is not str for item in triple)
            or triple[:2] != event_platform[:2]
            or _identifier(_value(fields, 'id')) != self_id
            or (type(fields.get('hash')) is str and fields['hash'] != expected)):
        return None
    native_default = (
        event_platform[2] == 'default'
        and triple[:2] == ('onebot', 'qq')
        and triple[2] in ONEBOT_V11_MODELS
    )
    if triple[2] != event_platform[2] and not native_default:
        return None
    return expected, triple


def _adapter(platform):
    return _ADAPTER_BY_PLATFORM.get(platform)


def _terminal_payload(event, budget):
    result = {}
    key = _path(event, ('payload', 'key'))
    if key is not _MISSING:
        copied = _project(key, _TERMINAL_KEY_SPEC, budget)
        if copied is not _SKIP:
            result.update(copied)
    payload = _value(event, 'payload')
    if type(payload) is dict:
        copied = _project(payload, _TERMINAL_HTTP_SPEC, budget)
        if copied is not _SKIP:
            result.update(copied)
    event_id = _value(event, 'event_id')
    if event_id is not _MISSING:
        copied = _scalar(event_id)
        if copied is not _SKIP:
            result['event_id'] = copied
    return result


def _build_record(proc, native, event):
    platform = _platform(event)
    if platform is None:
        return None, 'invalid_platform'
    self_id = _identifier(_value(_value(event, 'base_info'), 'self_id'))
    if self_id is None:
        return None, 'unknown_bot'
    bot = _owned_bot(proc, native, self_id, platform)
    if bot is _LIMITED:
        return None, 'bot_limit'
    if bot is None:
        return None, 'unknown_bot'
    bot_hash, triple = bot
    adapter = _adapter(triple)
    if adapter is None:
        return None, 'unsupported_adapter'
    budget = _Budget()
    if adapter == 'virtualTerminal':
        payload = _terminal_payload(event, budget)
    else:
        source_path, spec = _EXTRACTORS[adapter]
        source = _path(event, source_path)
        if source is _MISSING:
            return None, 'invalid_payload'
        payload = _project(source, spec, budget)
        if payload is _SKIP:
            return None, 'invalid_payload'
        if adapter == 'biliLive':
            room_id = _value(_value(event, 'base_info'), 'room_id')
            if room_id is not _MISSING:
                copied_room = _scalar(room_id)
                if copied_room is not _SKIP:
                    payload['room_id'] = copied_room
    record = {
        'bot_hash': bot_hash,
        'platform': {
            'sdk': triple[0],
            'platform': triple[1],
            'model': triple[2],
        },
        'adapter': adapter,
        'payload': payload,
    }
    return record, None


def _serialize(record):
    """按出站编码测量记录大小；ASCII 转义后的字节数就是客户端收到的长度。"""
    encoded = json.dumps(
        record,
        ensure_ascii=True,
        allow_nan=False,
        separators=(',', ':'),
    ).encode('ascii')
    if len(encoded) > MAX_RECORD_BYTES:
        raise _Limit
    return encoded


def _coverage():
    return {
        'hook': 'proc.run_plugin before API.Event SDK conversion',
        'cached_fields': 'raw JSON copy with credential field names retained for outbound policy',
        'limits_note': _NOT_FULL_TRAFFIC,
        'adapters': list(_ADAPTER_NAMES),
        'excluded': list(_COVERAGE_EXCLUDED),
        'limits': {
            'max_depth': MAX_DEPTH,
            'max_nodes': MAX_NODES,
            'max_record_bytes': MAX_RECORD_BYTES,
            'max_records': MAX_RECORDS,
            'max_cache_bytes': MAX_CACHE_BYTES,
            'max_read_bytes': MAX_READ_BYTES,
            'retention_seconds': RETENTION_SECONDS,
        },
    }


def _empty_read(active=False):
    return {
        'active': active,
        'records': [],
        'count': 0,
        'dropped': 0,
        'overwritten': 0,
        'expired': 0,
        'filtered': 0,
        'truncated': False,
        'discarded_reasons': {},
        'coverage': _coverage(),
    }


class Observer:
    """一个 Proc 实例上的 run_plugin 包装和有界缓存。"""

    __slots__ = (
        'proc', 'original', 'native_hash', 'wrapper', '_policy', '_active', '_state',
        '_lock', '_contended',
    )

    def __init__(self, proc, original, policy=None, native_hash=None):
        self.proc = proc
        self.original = original
        self.native_hash = native_hash
        self._policy = policy
        self._active = True
        self._lock = threading.Lock()
        # 宿主回调拿不到锁时只计数，不等待；读取时并入 dropped 并标记不完整。
        self._contended = 0
        # (records, total_bytes, stats), assigned as one immutable state tuple.
        self._state = ((), 0, {
            'dropped': 0,
            'overwritten': 0,
            'expired': 0,
            'filtered': 0,
            'truncated': 0,
            'reasons': {},
        })

        def wrapped(*args, **kwargs):
            try:
                if args:
                    self._observe(args[0])
                else:
                    self._drop('invalid_call')
            except BaseException:
                # 观察永远不能改变宿主的原调用；兜底计数自身失败也不能逃逸。
                try:
                    self._drop('observer_error')
                except BaseException:
                    pass
            # 宿主原方法必须恰好调用一次；其返回值与异常原样透出。
            return original(*args, **kwargs)

        setattr(wrapped, _MARKER, self)
        self.wrapper = wrapped

    def _contend(self):
        # shortcut: 无锁自增在极端并发下可能少计一次，只影响诊断计数。
        self._contended += 1

    def _drop_locked(self, reason, filtered=False, truncated=False):
        records, total, stats = self._state
        next_stats = dict(stats)
        next_stats['dropped'] += 1
        if filtered:
            next_stats['filtered'] += 1
        if truncated:
            next_stats['truncated'] += 1
        reasons = dict(stats['reasons'])
        reasons[reason] = reasons.get(reason, 0) + 1
        next_stats['reasons'] = reasons
        self._state = (records, total, next_stats)

    def _drop(self, reason, filtered=False, truncated=False):
        if not self._lock.acquire(blocking=False):
            self._contend()
            return
        try:
            self._drop_locked(reason, filtered, truncated)
        finally:
            self._lock.release()

    def _observe(self, event):
        if not self._active:
            return
        try:
            record, reason = _build_record(self.proc, self.native_hash, event)
            if record is None:
                self._drop(reason or 'invalid_event')
                return
            policy = self._policy
            if policy is not None:
                accepted = policy(record)
                if type(accepted) is not bool or not accepted:
                    self._drop('policy', filtered=True)
                    return
            size = len(_serialize(record))
            if not self._lock.acquire(blocking=False):
                self._contend()
                return
            try:
                now = time.monotonic()
                records, total, stats = self._purged(now)
                kept = list(records)
                while kept and (
                    len(kept) >= MAX_RECORDS or total + size > MAX_CACHE_BYTES
                ):
                    _, _, old_size = kept.pop(0)
                    total -= old_size
                    next_stats = dict(stats)
                    next_stats['overwritten'] += 1
                    stats = next_stats
                if len(kept) >= MAX_RECORDS or total + size > MAX_CACHE_BYTES:
                    self._drop_locked('cache_limit', truncated=True)
                    return
                kept.append((now + RETENTION_SECONDS, record, size))
                self._state = (tuple(kept), total + size, stats)
            finally:
                self._lock.release()
        except _HostHashUnavailable:
            self._drop('unknown_bot')
        except _Limit:
            self._drop('record_limit', truncated=True)
        except BaseException:
            # 同步宿主边界：观察自身异常（含构造期间的 CancelledError）一律转为
            # drop 计数，不得逃逸改变宿主调用；这与服务私有 loop 读侧把
            # CancelledError 在 finally 清理后继续传播的语义不同，二者不可混用。
            self._drop('observer_error')

    def _purged(self, now):
        records, total, stats = self._state
        live = []
        live_total = 0
        expired = 0
        for expires, record, size in records:
            if expires > now:
                live.append((expires, record, size))
                live_total += size
            else:
                expired += 1
        if expired:
            next_stats = dict(stats)
            next_stats['expired'] += expired
            stats = next_stats
            self._state = (tuple(live), live_total, stats)
        return tuple(live), live_total, stats

    def set_policy(self, policy=None):
        """替换采集策略；策略只接收有界 JSON 副本。"""
        if policy is not None and not callable(policy):
            raise TypeError('policy must be callable or None')
        self._policy = policy
        return self

    def read(self, policy=_USE_INSTALLED, limit=None):
        """读取快照；先按 limit 选取最新记录，再有界复制。

        ``limit=None`` 表示缓存内全部记录。复制总量受 MAX_READ_BYTES 约束，
        任何裁剪、丢弃或锁竞争都会在结果中标记 truncated。
        """
        if limit is not None and (type(limit) is not int or limit < 0):
            return _empty_read(self._active)
        acquired = False
        try:
            self._lock.acquire()
            acquired = True
            records, _, stats = self._purged(time.monotonic())
            contended = self._contended
            active_policy = self._policy if policy is _USE_INSTALLED else policy
        except asyncio.CancelledError:
            raise
        except BaseException:
            # 服务侧读取不能让内部缺陷伪装成"未激活"的正常快照。
            raise ToolError(_READ_FAILED) from None
        finally:
            if acquired:
                self._lock.release()
        try:
            if active_policy is not None and not callable(active_policy):
                return _empty_read(self._active)
            result = _empty_read(self._active)
            result['dropped'] = stats['dropped']
            result['overwritten'] = stats['overwritten']
            result['expired'] = stats['expired']
            result['filtered'] = stats['filtered']
            result['truncated'] = stats['truncated'] > 0
            reasons = dict(stats['reasons'])
            if contended:
                result['dropped'] += contended
                result['truncated'] = True
                reasons['contended'] = reasons.get('contended', 0) + contended
            result['discarded_reasons'] = reasons
            selected = records[::-1]
            if limit is not None:
                selected = selected[:limit]
            cut = len(selected) < len(records)
            copied_records = []
            local_filtered = 0
            copied_bytes = 0
            for _, record, size in selected:
                if copied_bytes + size > MAX_READ_BYTES:
                    cut = True
                    break
                try:
                    budget = _Budget()
                    copied = _copy_json(record, budget)
                except _Limit:
                    cut = True
                    break
                if copied is _SKIP:
                    cut = True
                    break
                if active_policy is not None:
                    accepted = active_policy(copied)
                    if type(accepted) is not bool or not accepted:
                        local_filtered += 1
                        continue
                copied_records.append(copied)
                copied_bytes += size
            copied_records.reverse()
            result['records'] = copied_records
            result['count'] = len(copied_records)
            result['filtered'] += local_filtered
            result['truncated'] = result['truncated'] or cut
            return result
        except asyncio.CancelledError:
            raise
        except BaseException:
            # 服务侧读取不能让内部缺陷伪装成"未激活"的正常快照。
            raise ToolError(_READ_FAILED) from None

    def uninstall(self):
        """只在入口仍是本观察器时恢复原方法；持安装锁，避免并发 install 交错。"""
        with _INSTALL_LOCK:
            self._active = False
            try:
                current = _value(self.proc, 'run_plugin')
                if current is not self.wrapper:
                    return False
                setattr(self.proc, 'run_plugin', self.original)
                return True
            except BaseException:
                return False


def _context_proc(context):
    proc = _value(context, 'proc')
    return proc if proc is not _MISSING else None


def _run_plugin(proc):
    try:
        return getattr(proc, 'run_plugin')
    except AttributeError:
        return _MISSING


def _native_hash(context):
    """缓存宿主 getBotHash 函数引用；缺失或不可调用返回 None。

    重抛 CancelledError 仍是内部约定而非宿主透传：install 的生命周期
    边界（下方）会把包括取消在内的安装失败整体吞掉，保持原 hook 不被替换。
    """
    try:
        olivos = _value(context, 'olivos')
        digest = _value(_value(olivos, 'API'), 'getBotHash')
    except asyncio.CancelledError:
        raise
    except BaseException:
        return None
    return digest if callable(digest) else None


def install(context, policy=None):
    """安装到当前 Context 的 Proc 实例，失败返回 None。

    ``policy(record)`` 必须返回 bool；它只看到已经完成账号归属校验和
    白名单投影的 JSON 副本，因此可由调用方用来实现 Lite 账号过滤。
    账号指纹使用安装时缓存的宿主 ``getBotHash`` 引用；缺失该能力时事件
    按 ``unknown_bot`` 丢弃，工具仍在列表中并返回空快照，不做本地算法回落。
    """

    if policy is not None and not callable(policy):
        return None
    try:
        proc = _context_proc(context)
        if proc is None:
            return None
        with _INSTALL_LOCK:
            current = _run_plugin(proc)
            if not callable(current):
                return None
            existing = getattr(current, _MARKER, None)
            if isinstance(existing, Observer) and existing.proc is proc:
                existing.set_policy(policy)
                return existing
            native = _native_hash(context)
            observer = Observer(proc, current, policy, native)
            setattr(proc, 'run_plugin', observer.wrapper)
            return observer
    except BaseException:
        # 生命周期入口：安装失败（含取消）整体隔离，不向上抛出，也绝不替换原
        # hook；若替换已发生但后续失败，由 uninstall 按所有权恢复。
        return None


def uninstall(context):
    """移除当前 Proc 实例上的本模块包装，返回是否恢复成功。"""
    try:
        proc = _context_proc(context)
        if proc is None:
            return False
        current = _run_plugin(proc)
        observer = getattr(current, _MARKER, None)
        if not isinstance(observer, Observer) or observer.proc is not proc:
            return False
        # Observer.uninstall 自身持同一把可重入安装锁。
        return observer.uninstall()
    except BaseException:
        return False


def read(context, policy=_USE_INSTALLED, limit=None):
    """读取当前 Proc 实例的观察快照；未安装时返回空快照。

    内部缺陷转换为固定文案的 ``ToolError``，由服务层转成 isError；
    ``asyncio.CancelledError`` 继续传播。
    """
    try:
        proc = _context_proc(context)
        if proc is None:
            return _empty_read(False)
        current = _run_plugin(proc)
        observer = getattr(current, _MARKER, None)
        if not isinstance(observer, Observer) or observer.proc is not proc:
            return _empty_read(False)
        return observer.read(policy, limit)
    except asyncio.CancelledError:
        raise
    except ToolError:
        raise
    except BaseException:
        raise ToolError(_READ_FAILED) from None


__all__ = [
    'MAX_CACHE_BYTES',
    'MAX_DEPTH',
    'MAX_NODES',
    'MAX_READ_BYTES',
    'MAX_RECORD_BYTES',
    'MAX_RECORDS',
    'MAX_RETURN_RECORDS',
    'ONEBOT_V11_MODELS',
    'Observer',
    'RETENTION_SECONDS',
    'install',
    'read',
    'uninstall',
]
