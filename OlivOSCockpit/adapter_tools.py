"""Full 专属：适配器文本发送的显式白名单；Lite 构建时整个模块被删除。

消息体由本模块直接构造为单个 text 段，不把客户端字符串交给宿主解析，
因此 `[CQ:...]` / `[OP:...]` 等段语法不会变成 image/file 段。宿主若会把文本
重新编码成 CQ/OP 串交给适配器再解析（opqbot、bililive、hackchat、mhyvila、
xiaoheihe 等），相应专用工具仅内部登记，不进入公开工具表。

低层裸 API 与已发布工具的区分（审计 notes-adapters §3/§4）：
- dingtalk `API.sendGroupMessage` / `API.sendPrivateMessage` 与 discord
  `API.sendMessage` 是不公开的低层裸 API：需要调用方自造 msgKey/embeds、
  绕过段落处理，保持不绑定。
- 已发布的 dingtalk/discord 文本发送工具走 `event_action.send_msg` 接受
  段列表的安全路径，经 ENTRIES 正常公开，与上述裸 API 无关。
- dodobot_ea：投递依赖插件级 `tx_queue`，合成事件拿不到该队列，消息会被丢弃。
- 其余 image/record/video/file 段、本地路径、URL、凭据与动态 action 一律不接受，
  因为它们会打开任意文件读取与出站请求通道。
"""

from . import host
from .contracts import Outcome, ToolError, ToolSpec, failure, object_schema
from .full_only import MAX_MESSAGE, _deliver, _identity, _string

MAX_ID = 256
PERMISSION = host.REAL_ACCOUNT_WRITE

# 适配器 → 允许的平台三元组 (sdk, platform, models)；仅这些组合会进入宿主分派。
PLATFORMS = {
    'opqbot': ('onebot', 'qq',
               ('opqbot_default', 'opqbot_auto', 'opqbot_port', 'opqbot_port_old')),
    'bililive': ('biliLive_link', 'biliLive', ('default',)),
    'dingtalk': ('dingtalk_link', 'dingtalk', ('default',)),
    'discord': ('discord_link', 'discord', ('default',)),
    'dodo_link': ('dodo_link', 'dodo', ('default', 'v1')),
    'dodo_poll': ('dodo_poll', 'dodo', ('default',)),
    'fanbook': ('fanbook_poll', 'fanbook', ('default',)),
    'hackchat': ('hackChat_link', 'hackChat', ('default',)),
    'kaiheila': ('kaiheila_link', 'kaiheila', ('default', 'text', 'card')),
    'mhyvila': ('mhyVila_link', 'mhyVila', ('default',)),
    'milky': ('onebot', 'qq',
              ('milky_default', 'llonebot_milky', 'lagrange_milky', 'yogurt_milky')),
    'red': ('onebot', 'qq', ('red',)),
    'telegram': ('telegram_poll', 'telegram', ('default',)),
    'xiaoheihe': ('xiaoheihe_link', 'xiaoheihe', ('default',)),
}

# (adapter, action, send_type, 目标参数名或 None, 额外必填参数)
# 每行的目标语义来自各 SDK 的 event_action 签名；不按名字反射。
_AUDITED_ENTRIES = (
    ('opqbot', 'send_private', 'private', 'target_id', ()),
    ('opqbot', 'send_group', 'group', 'target_id', ()),
    ('bililive', 'send', 'group', None, ()),
    ('dingtalk', 'send_private', 'private', 'target_id', ()),
    ('dingtalk', 'send_group', 'group', 'target_id', ()),
    ('discord', 'send_private', 'private', 'target_id', ()),
    ('discord', 'send_group', 'group', 'target_id', ()),
    ('dodo_link', 'send_private', 'private', 'target_id', ()),
    ('dodo_link', 'send_group', 'group', 'target_id', ()),
    ('dodo_poll', 'send_private', 'private', 'target_id', ('host_id',)),
    ('dodo_poll', 'send_group', 'group', 'target_id', ()),
    ('fanbook', 'send_private', 'private', 'target_id', ()),
    ('fanbook', 'send_group', 'group', 'target_id', ()),
    ('hackchat', 'send', 'group', None, ()),
    ('kaiheila', 'send_private', 'private', 'target_id', ()),
    ('kaiheila', 'send_group', 'group', 'target_id', ()),
    ('mhyvila', 'send_group', 'group', 'target_id', ('host_id',)),
    ('milky', 'send_private', 'private', 'target_id', ()),
    ('milky', 'send_group', 'group', 'target_id', ()),
    ('red', 'send_private', 'private', 'target_id', ()),
    ('red', 'send_group', 'group', 'target_id', ()),
    ('telegram', 'send', 'group', 'target_id', ()),
    ('telegram', 'send_private', 'private', 'target_id', ()),
    ('telegram', 'send_group', 'group', 'target_id', ()),
    ('xiaoheihe', 'send_group', 'group', 'target_id', ('host_id',)),
)


# 固定基线下只有字符串重解析路径的专用项不发布；通用 send 另做逐次模式检查。
_STRING_ONLY = frozenset(('opqbot', 'bililive', 'hackchat', 'mhyvila', 'xiaoheihe'))
WITHHELD_ENTRIES = tuple(entry for entry in _AUDITED_ENTRIES if entry[0] in _STRING_ONLY)
ENTRIES = tuple(entry for entry in _AUDITED_ENTRIES if entry[0] not in _STRING_ONLY)


def _matches(adapter, triple):
    sdk, platform, models = PLATFORMS[adapter]
    return (type(triple) is tuple and len(triple) == 3 and triple[0] == sdk
            and triple[1] == platform and triple[2] in models)


def _handler(adapter, action, send_type, target_name, extras):
    def handle(ctx, args):
        # Full 写默认关闭；配置快照不可用或未授权时结构化失败。
        if not host.allowed(ctx, PERMISSION):
            return failure('Real account write is disabled')
        message = _string(args, 'message', limit=MAX_MESSAGE, max_bytes=MAX_MESSAGE)
        bot_hash = _string(args, 'bot_hash')
        target = _string(args, target_name) if target_name is not None else None
        values = {name: _string(args, name) for name in extras}
        data = host.bot_info_dict(ctx.proc)
        if data is None:
            return failure('Configured account list unavailable')
        bot = host.safe(lambda: data.get(bot_hash))
        identity = _identity(bot)
        if identity is None or identity[0] != bot_hash:
            return failure('Unknown bot_hash')
        if not _matches(adapter, identity[2]):
            return failure('bot_hash platform does not match this adapter')
        olivos = ctx.olivos
        if olivos is None:
            return failure('Host message API unavailable')
        failed = _deliver(ctx, olivos, bot, identity, send_type, target, message,
                          values.get('host_id'))
        if failed is not None:
            return failed
        return Outcome({
            'submitted': True,
            'adapter': adapter,
            'action': action,
            'send_type': send_type,
            'target_id': target if target is not None else 'fixed',
            'delivery': 'unknown',
        })
    return handle


def _spec(adapter, action, send_type, target_name, extras):
    properties = {
        'bot_hash': {'type': 'string', 'minLength': 1, 'maxLength': MAX_ID},
        'message': {'type': 'string', 'minLength': 1, 'maxLength': MAX_MESSAGE},
    }
    if target_name is not None:
        properties[target_name] = {'type': 'string', 'minLength': 1, 'maxLength': MAX_ID}
    for name in extras:
        properties[name] = {'type': 'string', 'minLength': 1, 'maxLength': MAX_ID}
    return ToolSpec(
        name=f'cockpit_{adapter}_{action}',
        description=(
            f'Send text-only via the {adapter} adapter ({send_type}). '
            'Only a single text segment is built; images, files, paths and URLs are '
            'not accepted. Submission is not proof of delivery.'
        ),
        schema=object_schema(properties, ('bot_hash', 'message') + tuple(
            name for name in (target_name,) + extras if name is not None)),
        handler=_handler(adapter, action, send_type, target_name, extras),
        read_only=False,
        capability='adapter_send',
        required_permission=PERMISSION,
    )


TOOLS = tuple(_spec(*entry) for entry in ENTRIES)
