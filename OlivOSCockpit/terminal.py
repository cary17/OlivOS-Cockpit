"""用户预置的虚拟终端账号只读发现与原生输入注入；不创建、不删除、不写配置。

Cockpit 不再向宿主账号字典插入或移除任何键（BUG-16 止血）：调试终端账号
由使用者在宿主账号配置中自行创建（terminal_link/terminal/default），本模块
只做有界只读发现与验证；缺失时明确停用并等待下一监督周期，不做内存兜底。
"""

import threading
from itertools import islice

from . import host
from .contracts import MAX_ENTRIES, Outcome, ToolError, ToolSpec, failure, object_schema

SDK = 'terminal_link'
PLATFORM = 'terminal'
MODEL = 'default'
NICKNAME = 'OlivOSCockpit'
DEFAULT_USER_ID = '-1'
MAX_MESSAGE = 64 * 1024
MAX_ID = 256

# 选择发布与输入提交共用同一把 Cockpit 私有短临界区；它只协调本插件自己的
# 发布/提交窗口，不代表宿主或第三方读者参与同步。
_COMMIT_LOCK = threading.Lock()

NOT_CONFIGURED = ('No virtual terminal account is configured; create a '
                  'terminal_link/terminal/default account in the host account '
                  'configuration and restart the host')


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


def _fields(value):
    """只读实例 __dict__，不触发 property。"""
    fields = host.safe(lambda: object.__getattribute__(value, '__dict__'))
    return fields if type(fields) is dict else None


def _platform(bot):
    fields = _fields(bot)
    platform = fields.get('platform') if fields is not None else None
    platform = platform if type(platform) is dict else _fields(platform)
    if type(platform) is not dict:
        return None
    return platform.get('sdk'), platform.get('platform'), platform.get('model')


def _entries(data):
    """有界扫描；超限时不能把账号当成不存在。"""
    items = list(islice(iter(data.items()), MAX_ENTRIES + 1))
    return (items, False) if len(items) <= MAX_ENTRIES else (items[:MAX_ENTRIES], True)


def _qualified(data, key, value):
    """统一验证：活映射成员身份、键与 hash 一致、enable、三元组与真整数 ID。"""
    fields = _fields(value)
    if fields is None:
        return False
    digest = fields.get('hash')
    if type(digest) is not str or not digest or digest != key:
        return False
    if fields.get('enable') is False:
        return False
    if _platform(value) != (SDK, PLATFORM, MODEL):
        return False
    # type is int 同时排除 bool/float 冒充。
    if type(fields.get('id')) is not int:
        return False
    return host.safe(lambda: data.get(key)) is value


def _valid_selection(state, data):
    """O(1) 快路径：当前选择仍是活字典中身份一致的合格账号。"""
    digest = state.get('hash')
    bot = state.get('bot')
    if type(digest) is not str or bot is None or type(data) is not dict:
        return False
    if host.safe(lambda: data.get(digest)) is not bot:
        return False
    return _qualified(data, digest, bot)


def _scan(data):
    """有界扫描全部合格账号，按 hash 确定性排序；超限不算不存在。"""
    items, too_many = _entries(data)
    if too_many:
        return None, 'Account list too large to inspect safely'
    found = [(key, value) for key, value in items if _qualified(data, key, value)]
    found.sort(key=lambda pair: pair[0])
    return found, None


def prepare(ctx):
    """只读发现：验证当前选择，失效则有界重选；从不增删宿主账号。

    先计算局部候选，发布前复核活映射与成员身份；每次调用至多 2×500 项，
    第二次仍变化就固定安全失败，等下一监督周期，不忙等、不无限重试。
    """
    state = ctx.terminal
    with _COMMIT_LOCK:
        data = host.bot_info_dict(ctx.proc)
        if data is None:
            state['checked'] = True
            state['error'] = 'Configured account list unavailable'
            return state
        if _valid_selection(state, data):
            state['checked'] = True
            state.pop('error', None)
            return state
        for _ in range(2):
            found, error = _scan(data)
            if error is not None:
                state['checked'] = True
                state['error'] = error
                return state
            if not found:
                state['checked'] = True
                state['error'] = NOT_CONFIGURED
                return state
            digest, bot = found[0]
            fresh = host.bot_info_dict(ctx.proc)
            if fresh is data and _qualified(fresh, digest, bot):
                state['checked'] = True
                state['hash'] = digest
                state['bot'] = bot
                state.pop('error', None)
                return state
            if fresh is None:
                break
            data = fresh
        state['checked'] = True
        state['error'] = 'Account list changed during inspection; retry later'
        return state


def tick(ctx):
    """监督循环每秒的只读接缝：验证或重选，不发布配置、不清会话、不改代次。"""
    try:
        prepare(ctx)
    except BaseException:
        state = ctx.terminal
        if type(state) is dict:
            state['checked'] = True
            state['error'] = 'Debug terminal preparation failed'


def status(ctx):
    # 与选择发布互斥，旧查询不能把错误写到刚完成的新选择上。
    with _COMMIT_LOCK:
        state = ctx.terminal
        result = {'selected': False, 'connection': 'unknown'}
        if type(state) is not dict or not state.get('checked'):
            return result
        if state.get('error'):
            result['error'] = state['error']
            return result
        data = host.bot_info_dict(ctx.proc)
        record = host._bot(state.get('hash'), state.get('bot')) if _valid_selection(state, data) else None
        if record is None:
            result['error'] = 'Selected account is no longer available'
            state['error'] = result['error']
            return result
        result['selected'] = True
        result['account'] = record
        return result


def _base_self_id(event):
    """容忍属性或字典两种 base_info 形态读取 self_id，归一化为字符串。"""
    base = host.safe(lambda: getattr(event, 'base_info'))
    if base is host.MISSING or base is None:
        return None
    value = host.safe(lambda: getattr(base, 'self_id', None))
    if value is None or value is host.MISSING:
        value = host.safe(lambda: base.get('self_id'))
        if value is host.MISSING:
            return None
    if type(value) is int and not isinstance(value, bool):
        return str(value)
    return value if type(value) is str else None


def _input(ctx, args):
    message = _string(args, 'message', limit=MAX_MESSAGE, max_bytes=MAX_MESSAGE)
    user_id = _string(args, 'user_id', required=False) or DEFAULT_USER_ID
    group_id = _string(args, 'group_id', required=False)
    state = ctx.terminal
    if type(state) is not dict or not state.get('checked') or state.get('error') or type(
            state.get('hash')) is not str:
        return failure('Debug terminal account unavailable')
    digest = state['hash']
    data = host.bot_info_dict(ctx.proc)
    if data is None:
        return failure('Configured account list unavailable')
    bot = host.safe(lambda: data.get(digest))
    if (bot is None or bot is host.MISSING or bot is not state.get('bot')
            or not _qualified(data, digest, bot)):
        return failure('Debug terminal account is no longer available')
    fields = _fields(bot)
    target_id = fields.get('id') if fields is not None else None
    if type(target_id) is not int:
        return failure('Debug terminal account is no longer available')
    olivos = ctx.olivos
    if olivos is None:
        return failure('Host terminal API unavailable')
    proc = ctx.proc
    rx_queue = host.safe(lambda: proc.Proc_info.rx_queue) if proc is not None else None
    if rx_queue is None or rx_queue is host.MISSING or not callable(getattr(rx_queue, 'put', None)):
        return failure('Host event queue unavailable')
    user_conf = {
        'user_name': NICKNAME,
        'user_id': user_id,
        'flag_group': group_id is not None,
        'group_role': 'member',
    }
    if group_id is not None:
        user_conf['target_id'] = group_id
    # 包与 SDK 事件在锁外构造；随后核对 self_id 绑定捕获目标，
    # 覆盖构造期间账号对象或 ID 被替换后又被还原的 ABA 情形。
    packet = host.safe(lambda: olivos.API.Control.packet(
        'send', {'data': {'action': 'input', 'data': message, 'user_conf': user_conf}}))
    sdk_event = None if packet is host.MISSING else host.safe(
        lambda: olivos.virtualTerminalSDK.event(packet, bot, model=MODEL))
    if sdk_event is None or sdk_event is host.MISSING:
        return failure('Message submission failed safely')
    if _base_self_id(sdk_event) != str(target_id):
        return failure('Message submission failed safely')
    rx_packet = host.safe(lambda: olivos.pluginAPI.shallow.rx_packet(sdk_event))
    if rx_packet is host.MISSING:
        return failure('Message submission failed safely')
    # 短私有提交临界区：代次、活映射、对象身份、ID 与选择复核后非阻塞投递。
    with _COMMIT_LOCK:
        if not host.unchanged(ctx):
            return failure('Configuration changed before message submission')
        final_fields = _fields(bot)
        current_id = final_fields.get('id') if final_fields is not None else None
        if (host.bot_info_dict(proc) is not data
                or state.get('bot') is not bot or not _qualified(data, digest, bot)
                or type(current_id) is not int or current_id != target_id):
            return failure('Debug terminal account is no longer available')
        if host.safe(lambda: rx_queue.put(rx_packet, block=False)) is host.MISSING:
            return failure('Host event queue is unavailable')
    return Outcome({
        'queued': True,
        'chat': 'group' if group_id is not None else 'private',
        'account': {'hash': digest, 'platform': {'sdk': SDK, 'platform': PLATFORM, 'model': MODEL}},
        'processing': 'unknown',
    })


TOOLS = (
    ToolSpec(
        name='cockpit_terminal_input',
        description=(
            'Inject a simulated user message through a user-provisioned virtual '
            'terminal account (terminal_link/terminal/default in the host account '
            'configuration) so normal plugin message callbacks run. Reports queue '
            'acceptance only, never processing or replies.'
        ),
        schema=object_schema({
            'message': {'type': 'string', 'minLength': 1, 'maxLength': MAX_MESSAGE},
            'user_id': {'type': 'string', 'minLength': 1, 'maxLength': MAX_ID},
            'group_id': {'type': 'string', 'minLength': 1, 'maxLength': MAX_ID},
        }, ('message',)),
        handler=_input,
        read_only=False,
    ),
)
