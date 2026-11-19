"""Full 专属写工具；Lite 打包时整个模块被删除。"""

import asyncio
import logging
import math
import os
from itertools import islice

from . import fs, host
from .contracts import (
    MAX_ACCOUNT_ID_BITS,
    MAX_DEPTH,
    NAMESPACE,
    Outcome,
    ToolError,
    ToolSpec,
    failure,
    object_schema,
)
from .host import MISSING, safe, scalar

LOGGER = logging.getLogger(__name__)

SEND_TYPES = ('private', 'group')
QQ_TARGET_TYPES = ('qq_group', 'guild_channel')
MAX_MESSAGE = 64 * 1024
MAX_ID = 256
MAX_CONFIG_VALUE = 64 * 1024
WRITE_PERMISSION = host.REAL_ACCOUNT_WRITE
LOW_LEVEL_PERMISSION = 'low_level_access'
# 已核实会原样传递段列表的接收模式。old_string / olivos_string 等会把文本重新
# 编码成 CQ/OP 串交给适配器再次解析，文本里的段语法可能变成媒体段。
SAFE_MODES = frozenset(('olivos_para', 'obv12_para', 'milky_para_tx'))
MILKY_MODELS = ('milky_default', 'llonebot_milky', 'lagrange_milky', 'yogurt_milky')
# 白名单路径 → 已知宿主取值来源；不提供任意反射入口。
PATHS = ('plugin_names', 'bot_hashes', 'olivos_version', 'olivos_svn')


def _string(args, name, required=True, limit=MAX_ID, max_bytes=None):
    value = args.get(name)
    if value is None:
        if required:
            raise ToolError(f'{name} is required')
        return None
    if type(value) is not str or not value:
        raise ToolError(f'{name} must be a non-empty string')
    if len(value) > limit:  # 先按字符数挡住超长串
        raise ToolError(f'{name} is too long')
    if max_bytes is not None and len(value.encode('utf-8', 'surrogatepass')) > max_bytes:
        raise ToolError(f'{name} is too long')
    return value


def _identity(bot):
    """只读账号身份：hash、id 与平台三元组；形状不符或已禁用返回 None。

    宿主 bot_info_T 以 dict 保存 platform 并总是带 enable；不触发 property。
    """
    fields = host._fields(bot)
    if type(fields) is not dict:
        return None
    if fields.get('enable') is False:
        return None
    platform = fields.get('platform')
    if type(platform) is not dict:
        platform = host._fields(platform)  # 兼容非 dict 的宿主包装对象，不触发 property
    if type(platform) is not dict:
        return None
    triple = tuple(platform.get(key) for key in ('sdk', 'platform', 'model'))
    digest, bot_id = fields.get('hash'), fields.get('id')
    if any(type(item) is not str or not item or len(item) > MAX_ID for item in triple):
        return None
    if type(digest) is not str or not digest or len(digest) > MAX_ID:
        return None
    if not ((type(bot_id) is str and 0 < len(bot_id) <= MAX_ID)
            or (type(bot_id) is int and bot_id.bit_length() <= MAX_ACCOUNT_ID_BITS)):
        return None
    return digest, bot_id, triple


def _bound(event, bot, identity):
    """提交前复核原生事件确实绑定到当前账号对象与同一平台三元组。"""
    platform = safe(lambda: event.platform)
    return (safe(lambda: event.active) is True
            and safe(lambda: event.bot_info) is bot
            and type(platform) is dict
            and all(type(platform.get(key)) is str and platform[key] == expected
                    for key, expected in zip(('sdk', 'platform', 'model'), identity[2])))


def _milky_submission(olivos, event, template, bot, send_type, target, message):
    if not target.isascii() or not target.isdecimal():
        raise ToolError('Milky target_id must be a positive decimal string')
    peer_id = int(target)
    if peer_id == 0 or peer_id.bit_length() > MAX_ACCOUNT_ID_BITS:
        raise ToolError('Milky target_id is out of range')
    post_type = safe(lambda: bot.post_info.type)
    if type(post_type) is not str or post_type != 'auto':
        raise ToolError('Milky account requires the native auto adapter')
    queue = safe(lambda: event.plugin_info.get('control_queue'))
    if not callable(safe(lambda: queue.put)):
        raise ToolError('Milky control queue is unavailable')

    def prepare():
        segments = template.get('milky_para_tx')
        if segments != [{'type': 'text', 'data': {'text': message}}]:
            return None
        sdk = olivos.milkySDK
        if send_type == 'private':
            action = sdk.API.send_private_message(user_id=peer_id, message=segments)
        else:
            action = sdk.API.send_group_message(group_id=peer_id, message=segments)
        return sdk.send_post_event, action.gen_data(action.post_id)

    prepared = safe(prepare)
    if (type(prepared) is not tuple or not callable(prepared[0])
            or type(prepared[1]) is not dict):
        raise ToolError('Native Milky text submission is unavailable')
    return prepared[0], prepared[1], queue


def _deliver(ctx, olivos, bot, identity, send_type, target, message, host_id=None, target_type=None):
    """以已核实的原生单 text 段提交；成功返回 None，否则返回固定安全错误。

    默认把 Message_templet 直接交给 event.send；Milky 使用同一模板的结构化文本段。
    拒绝会把客户端文本重新编码成 CQ/OP 字符串再解析的消息模式。
    """
    def build():
        template = olivos.messageAPI.Message_templet(
            'olivos_para', [olivos.messageAPI.PARA.text(message)])
        fake = olivos.contentAPI.fake_sdk_event(bot_info=bot, fakename=NAMESPACE)
        return olivos.API.Event(fake, ctx.proc.log), template

    built = safe(build)
    if type(built) is not tuple or len(built) != 2:
        return failure('Message submission failed safely')
    event, template = built
    mode = safe(lambda: event.plugin_info.get('message_mode_rx'))
    if (safe(lambda: template.active) is not True or type(mode) is not str
            or mode not in SAFE_MODES):
        return failure('Adapter message mode does not support safe text-only submission')
    sdk, platform, model = identity[2]
    # 固定基线的合成事件没有被动私聊上下文；这些路径不会调用发送适配器。
    if send_type == 'private':
        if sdk in ('qqGuild_link', 'dodobot_ea'):
            return failure('Adapter does not support active private message submission')
        if sdk == 'dodo_poll' and host_id is None:
            return failure('DoDo poll private submission requires host_id in its dedicated tool')
    if sdk == 'dodobot_ea':
        queues = safe(lambda: event.plugin_info.get('tx_queue'))
        if type(queues) not in (list, tuple) or not queues:
            return failure('DoDo EA message submission queue is unavailable')
    if sdk == 'milky' and platform == 'qq':
        return failure('Host adapter dispatch does not support this Milky account model')
    milky = None
    if sdk == 'onebot' and platform == 'qq' and model in MILKY_MODELS:
        if mode != 'milky_para_tx':
            return failure('Native Milky text submission is unavailable')
        try:
            milky = _milky_submission(olivos, event, template, bot, send_type, target, message)
        except ToolError as exc:
            return failure(str(exc))
    elif target_type == 'qq_group':
        # 宿主读取 Event.data.extend，而不是构造前的 fake SDK 事件。
        flags = {'flag_from_qq': True}
        if (safe(lambda: setattr(event.data, 'extend', flags)) is MISSING
                or safe(lambda: event.data.extend) is not flags):
            return failure('Native QQ group submission is unavailable')
    data = host.bot_info_dict(ctx.proc)
    if (data is None or safe(lambda: data.get(identity[0])) is not bot
            or _identity(bot) != identity or not _bound(event, bot, identity)):
        return failure('Account binding changed before message submission')
    if not host.unchanged(ctx):
        return failure('Configuration changed before message submission')
    if milky is not None:
        enqueue, packet, queue = milky
        # Action.call 会吞掉入队失败并等待回包；这里只确认原生控制队列接收。
        if safe(lambda: enqueue(identity[0], packet, queue)) is not None:
            return failure('Milky control queue submission failed safely')
        return None
    result = safe(lambda: event.send(send_type, target, template, host_id=host_id))
    if result is MISSING:
        return failure('Message submission failed safely')
    # 正常调用也可能返回 None，只识别 QQ Guild v2 明确标记的本地拒绝。
    if (sdk == 'qqGuildv2_link' and issubclass(type(result), dict)
            and dict.get(result, 'active') is False):
        result_data = dict.get(result, 'data')
        if type(result_data) is dict:
            operation, error = result_data.get('operation'), result_data.get('error')
            if (type(operation) is str and operation == 'send' and type(error) is str and error
                    and all(result_data.get(key, MISSING) is None
                            for key in ('http_status', 'error_code', 'response'))):
                return failure('Host rejected message submission locally')
    return None


def _send(ctx, args):
    # 直接 handler 也必须默认拒绝：无配置快照或未授权时代次即失败。
    if not host.allowed(ctx, WRITE_PERMISSION):
        return failure('Real account write is disabled')
    hash_ = _string(args, 'bot_hash')
    send_type = _string(args, 'send_type')
    if send_type not in SEND_TYPES:
        raise ToolError('send_type must be private or group')
    target_type = None
    if 'target_type' in args:
        target_type = _string(args, 'target_type')
        if target_type not in QQ_TARGET_TYPES:
            raise ToolError('target_type must be qq_group or guild_channel')
    target = _string(args, 'target_id')
    message = _string(args, 'message', limit=MAX_MESSAGE, max_bytes=MAX_MESSAGE)
    data = host.bot_info_dict(ctx.proc)
    if data is None:
        return failure('Configured account list unavailable')
    bot = safe(lambda: data.get(hash_))
    identity = _identity(bot)
    if identity is None or identity[0] != hash_:
        return failure('Unknown bot_hash')
    if target_type is not None and (send_type != 'group' or identity[2][0] != 'qqGuildv2_link'):
        return failure('target_type is only supported for QQ Guild v2 group submission')
    olivos = ctx.olivos
    if olivos is None:
        return failure('Host message API unavailable')
    failed = _deliver(ctx, olivos, bot, identity, send_type, target, message, target_type=target_type)
    if failed is not None:
        return failed
    return Outcome({'submitted': True, 'send_type': send_type, 'target_id': target,
                    'delivery': 'unknown'})


def _reload(ctx, args):
    if not host.allowed(ctx, WRITE_PERMISSION):
        return failure('Real account write is disabled')
    if args.get('confirm') is not True:
        raise ToolError('confirm must be true')
    restart = safe(lambda: ctx.proc.set_restart) if ctx.proc is not None else None
    if restart is None or restart is MISSING or not callable(restart):
        return failure('Host restart API unavailable')

    def after_send(restart=restart):
        # 在响应发送后的工作线程执行；任何异常都不得逃逸。
        try:
            if not host.allowed(ctx, WRITE_PERMISSION):
                LOGGER.warning('restart request skipped: permission changed')
                return
            result = restart()
            if result is not True:
                LOGGER.warning('restart request not accepted')
        except asyncio.CancelledError:
            raise
        except BaseException:
            LOGGER.warning('restart request failed safely')

    return Outcome({'accepted': True, 'scope': 'all_plugins'}, after_send=after_send)


def _bounded(value, depth=0):
    """只转原生 JSON 结构；深度与规模有界，自定义对象取值返回 None。"""
    if type(value) is str:
        return value[:host.MAX_TEXT]
    if type(value) in (bool, int, float):
        return scalar(value)
    if depth >= MAX_DEPTH:
        return None
    if type(value) is list:
        return [_bounded(item, depth + 1) for item in value[:host.MAX_ENTRIES]]
    if type(value) is dict:
        return {
            key[:host.MAX_TEXT]: _bounded(item, depth + 1)
            for key, item in islice(value.items(), host.MAX_ENTRIES)
            if type(key) is str
        }
    return None


def _proc_get(ctx, args):
    # 底层只读也必须在 handler 内默认拒绝，不依赖调用层授权。
    if not host.allowed(ctx, LOW_LEVEL_PERMISSION):
        return failure('Low-level access is disabled')
    path = _string(args, 'path')
    if path not in PATHS:
        raise ToolError('Path not allowed')
    source = {
        'plugin_names': lambda: host.plugin_names(ctx.proc),
        'bot_hashes': lambda: host.bot_hashes(ctx.proc),
        'olivos_version': lambda: host.olivos_info(ctx, 'version'),
        'olivos_svn': lambda: host.olivos_info(ctx, 'svn'),
    }[path]()
    if source is None:
        return failure('Value unavailable')
    truncated = False
    if type(source) is tuple and len(source) == 2:
        source, truncated = source
    result = {'path': path, 'value': _bounded(source)}
    if truncated:
        result['truncated'] = True
    return Outcome(result)


def _config_value(value):
    """只接受 sqlite 原生可无损写入的 JSON 标量；不截断、不猜类型。"""
    if value is None:
        return None
    if type(value) is bool:
        return value
    if type(value) is int:
        if value.bit_length() > 63:
            raise ToolError('Configuration value is out of range')
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ToolError('Configuration value must be a finite number')
        return value
    if type(value) is str:
        if '\x00' in value or len(value.encode('utf-8', 'surrogatepass')) > MAX_CONFIG_VALUE:
            raise ToolError('Configuration value is too long')
        return value
    raise ToolError('Configuration value must be a JSON scalar')


def _plugin_config_set(ctx, args):
    """经宿主配置数据库写入单个标量；不开放 SQL、pickle 或任意文件路径。"""
    if not host.allowed(ctx, WRITE_PERMISSION):
        return failure('Real account write is disabled')
    namespace = _string(args, 'namespace', limit=128)
    key = _string(args, 'key', limit=256)
    if (namespace.casefold() == NAMESPACE.casefold() or '\x00' in namespace
            or '/' in namespace or '\\' in namespace or '\x00' in key):
        raise ToolError('Namespace is not writable')
    value = _config_value(args.get('value'))
    root = getattr(ctx, 'root', None)
    if not root:
        return failure('Plugin configuration path is unavailable')
    # 已核实的宿主数据库路径（上游 DATABASE_PATH 相对 cwd）；同一文件策略必须放行。
    db_path = os.path.join(root, 'plugin', 'conf', 'UserConfAll.db')
    try:
        fs.authorize_path(ctx, db_path, write=True)
    except ToolError:
        return failure('Plugin configuration path is forbidden')
    database = safe(lambda: getattr(ctx.proc, 'database', None))
    setter = safe(lambda: getattr(database, 'set_config', None)) if database is not None else None
    if setter is MISSING or not callable(setter):
        return failure('Host plugin configuration API unavailable')
    if not host.unchanged(ctx):
        return failure('Configuration changed before plugin configuration update')
    # 已核实契约：pkl=False 时直接写入 sqlite 原生值，成功返回 True。
    if safe(lambda: setter(namespace, key, value, pkl=False)) is not True:
        return failure('Plugin configuration update failed safely')
    return Outcome({'accepted': True, 'namespace': namespace, 'key': key})


TOOLS = (
    ToolSpec(
        name='cockpit_send',
        description=(
            'Send text as the given configured account. For QQ Guild v2 group sends, '
            'set target_type=qq_group for a QQ group; omission keeps guild_channel routing. '
            'Submission is not proof of delivery.'
        ),
        schema=object_schema({
            'bot_hash': {'type': 'string', 'minLength': 1},
            'send_type': {'type': 'string', 'enum': list(SEND_TYPES)},
            'target_type': {'type': 'string', 'enum': list(QQ_TARGET_TYPES),
                            'description': 'Optional QQ Guild v2 group route; default is guild_channel.'},
            'target_id': {'type': 'string', 'minLength': 1},
            'message': {'type': 'string', 'minLength': 1, 'maxLength': MAX_MESSAGE},
        }, ('bot_hash', 'send_type', 'target_id', 'message')),
        handler=_send,
        read_only=False,
        required_permission='real_account_write',
    ),
    ToolSpec(
        name='cockpit_reload',
        description=(
            'Request a restart of the whole plugin loader after the response is sent. '
            'Set confirm=true. All plugins and every Cockpit HTTP session end; '
            'success only means the restart request was accepted.'
        ),
        schema=object_schema({
            'confirm': {'type': 'boolean'},
        }, ('confirm',)),
        handler=_reload,
        read_only=False,
        required_permission='real_account_write',
    ),
    ToolSpec(
        name='cockpit_proc_get',
        description=(
            'High-privilege read-only lookup of an explicitly allowed path. '
            'No arbitrary attribute access.'
        ),
        schema=object_schema({
            'path': {'type': 'string', 'enum': list(PATHS)},
        }, ('path',)),
        handler=_proc_get,
        required_permission='low_level_access',
    ),
    ToolSpec(
        name='cockpit_plugin_config_set',
        description=(
            'Write one bounded scalar through the host plugin configuration API. '
            'SQL, pickle, the Cockpit control directory, and arbitrary file paths are rejected.'
        ),
        schema=object_schema({
            'namespace': {'type': 'string', 'minLength': 1, 'maxLength': 128},
            'key': {'type': 'string', 'minLength': 1, 'maxLength': 256},
            'value': {},
        }, ('namespace', 'key', 'value')),
        handler=_plugin_config_set,
        read_only=False,
        required_permission='real_account_write',
    ),
)
