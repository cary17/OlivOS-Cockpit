"""只读宿主工具：运行总览与配置账号清单。"""

import asyncio
import json
import math
import platform
from itertools import islice

from .contracts import (
    MAX_ENTRIES,
    MODE_FULL,
    Outcome,
    ToolSpec,
    failure,
    object_schema,
)

MAX_TEXT = 200
MAX_PLUGIN_DETAIL_BYTES = 128 * 1024
MAX_PLUGIN_INTEGER_BITS = 256
MISSING = object()
# 与 config.PERMISSION_* 对应；按字符串匹配避免耦合具体实现。
REAL_ACCOUNT_READ = 'real_account_read'
REAL_ACCOUNT_WRITE = 'real_account_write'

# 已实测的宿主常量名优先；旧候选仅作能力探测，输出 unknown 兜底，不做遍历反射。
_INFO_ATTRS = {
    'version': ('OlivOS_Version', 'OlivOS_version'),
    'svn': ('OlivOS_SVN', 'OlivOS_svn_version', 'OlivOS_svn'),
}


def safe(call):
    """宿主 SDK 边界：BaseException 转 MISSING；异步取消继续传播。"""
    try:
        return call()
    except asyncio.CancelledError:
        raise
    except BaseException:
        return MISSING


def snapshot(ctx):
    """读取当前配置快照；配置接口缺失时返回 None，由调用方按安全默认处理。"""
    manager = getattr(ctx, 'config', None)
    if manager is None:
        manager = getattr(ctx, 'config_manager', None)
    if manager is None:
        return None
    reader = getattr(manager, 'snapshot', None)
    if not callable(reader):
        return None
    return safe(reader)


def _same_generation(ctx, current):
    expected = getattr(ctx, 'request_generation', None)
    return (current is not MISSING and (expected is None
            or (current is not None and getattr(current, 'generation', 0) == expected)))


def unchanged(ctx):
    """提交动作前复核请求开始时的策略代次；已提交动作不承诺撤销。"""
    return _same_generation(ctx, snapshot(ctx))


def allowed(ctx, permission):
    """默认拒绝：无配置快照时只允许 Full 默认开启的权限。"""
    current = snapshot(ctx)
    if not _same_generation(ctx, current):
        return False
    if current is None:
        # shortcut: 配置接口未落地时按 Full 默认放行只读真实数据；接入后由快照判定。
        return (permission == REAL_ACCOUNT_READ
                and getattr(ctx, 'permission_mode', MODE_FULL) == MODE_FULL)
    check = getattr(current, 'allows', None)
    if not callable(check):
        return False
    return safe(lambda: check(permission, getattr(ctx, 'permission_mode', MODE_FULL))) is True


def setting(ctx, names, default):
    """从配置快照读取首个存在的字段；缺失或读取失败时用安全默认。"""
    current = snapshot(ctx)
    if current is None:
        return default
    for name in names:
        value = getattr(current, name, MISSING)
        if value is not MISSING:
            return value
    return default


def scalar(value):
    """只保留原生 JSON 标量；字符串截断，非有限浮点丢弃。"""
    if type(value) is str:
        return value[:MAX_TEXT]
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    return None


def _fields(obj):
    """只读实例 __dict__，不触发 property 或自定义 getter。"""
    fields = safe(lambda: object.__getattribute__(obj, '__dict__'))
    return fields if type(fields) is dict else None


def _platform(value):
    fields = value if type(value) is dict else _fields(value)
    if type(fields) is not dict:
        fields = {}
    return {key: scalar(fields.get(key)) for key in ('sdk', 'platform', 'model')}


def _bot(bot_hash, bot):
    fields = _fields(bot)
    if fields is None:
        return None
    digest = scalar(fields.get('hash'))
    if type(digest) is not str:
        digest = scalar(bot_hash) if type(bot_hash) is str else None
    return {
        'hash': digest,
        'id': scalar(fields.get('id')),
        'platform': _platform(fields.get('platform')),
        'connection': 'unknown',
    }


def bot_info_dict(proc):
    """Proc.Proc_data['bot_info_dict']；缺失或形状不符返回 None。"""
    if proc is None:
        return None
    proc_data = safe(lambda: proc.Proc_data)
    if type(proc_data) is not dict:
        return None
    data = safe(lambda: proc_data.get('bot_info_dict'))
    return data if type(data) is dict else None


def bot_list(data):
    """有界提取配置账号，字段白名单，不含凭据；账号均来自宿主配置。"""
    items = list(islice(iter(data.items()), MAX_ENTRIES + 1))
    bots = [bot for bot in (_bot(k, v) for k, v in items[:MAX_ENTRIES]) if bot is not None]
    return bots, len(items) > MAX_ENTRIES


def bot_hashes(proc):
    data = bot_info_dict(proc)
    if data is None:
        return None
    items = list(islice(iter(data), MAX_ENTRIES + 1))
    hashes = sorted(h[:MAX_TEXT] for h in items[:MAX_ENTRIES] if type(h) is str)
    return hashes, len(items) > MAX_ENTRIES


_PLUGIN_FIELDS = (
    'namespace', 'name', 'version', 'svn', 'info', 'author', 'compatible_svn',
    'priority', 'priority_default', 'priority_user', 'priority_effective',
)
_PLUGIN_STRING_FIELDS = frozenset(('namespace', 'name', 'version', 'info', 'author'))
_PLUGIN_INTEGER_FIELDS = frozenset(('svn', 'compatible_svn', 'priority_user'))
_PLUGIN_PRIORITY_FIELDS = frozenset(('priority', 'priority_default', 'priority_effective'))


def _plugin_snapshot(proc):
    if proc is None:
        return None
    raw = safe(lambda: proc.get_plugin_list())
    if raw is MISSING or not isinstance(raw, (dict, list, tuple, set)):
        return None
    items = list(islice(iter(raw), MAX_ENTRIES + 1))
    entries = [(name[:MAX_TEXT], name) for name in items[:MAX_ENTRIES] if type(name) is str]
    entries.sort(key=lambda item: item[0])
    return [item[0] for item in entries], len(items) > MAX_ENTRIES, entries


def plugin_names(proc):
    result = safe(lambda: _plugin_snapshot(proc))
    if result is MISSING or result is None:
        return None
    return result[0], result[1]


def _plugin_text(value):
    if type(value) is not str or len(value) > MAX_TEXT:
        return MISSING
    try:
        value.encode('utf-8', 'strict')
    except UnicodeError:
        return MISSING
    return value


def _plugin_field(field, value):
    if field in _PLUGIN_STRING_FIELDS:
        return _plugin_text(value)
    if field in _PLUGIN_INTEGER_FIELDS:
        if type(value) is int and value.bit_length() <= MAX_PLUGIN_INTEGER_BITS:
            return value
        if field == 'priority_user' and value is None:
            return None
        return MISSING
    if field in _PLUGIN_PRIORITY_FIELDS:
        if type(value) is int and value.bit_length() <= MAX_PLUGIN_INTEGER_BITS:
            return value
        if type(value) is float and math.isfinite(value):
            return value
    return MISSING


def _plugin_detail(namespace, source_namespace, models):
    visible_namespace = _plugin_text(namespace)
    if visible_namespace is MISSING:
        visible_namespace = None
    unknown = list(_PLUGIN_FIELDS)
    fields = {field: None for field in _PLUGIN_FIELDS}
    fields['namespace'] = visible_namespace
    record = MISSING
    if (models is not MISSING and len(source_namespace) <= MAX_TEXT
            and _plugin_text(source_namespace) is not MISSING):
        record = dict.get(models, source_namespace, MISSING)
    if type(record) is dict:
        record_namespace = _plugin_field('namespace', dict.get(record, 'namespace', MISSING))
        if record_namespace == source_namespace:
            unknown = []
            for field in _PLUGIN_FIELDS:
                value = _plugin_field(field, dict.get(record, field, MISSING))
                if value is MISSING:
                    unknown.append(field)
                else:
                    fields[field] = value
        else:
            fields['namespace'] = visible_namespace
    fields['available'] = not unknown
    fields['unknown_fields'] = unknown
    return fields


def plugin_catalog(proc):
    snapshot = safe(lambda: _plugin_snapshot(proc))
    if snapshot is MISSING or snapshot is None:
        return None
    names, truncated, entries = snapshot
    proc_fields = _fields(proc)
    raw_models = dict.get(proc_fields, 'plugin_models_dict', MISSING) if proc_fields is not None else MISSING
    models = raw_models if type(raw_models) is dict else MISSING
    details = []
    details_bytes = 2
    details_available = models is not MISSING
    details_truncated = False
    for namespace, source_namespace in entries:
        row = _plugin_detail(namespace, source_namespace, models)
        if row['available'] is not True:
            details_available = False
        encoded = json.dumps(row, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
        row_bytes = len(encoded) + (1 if details else 0)
        if details_bytes + row_bytes > MAX_PLUGIN_DETAIL_BYTES:
            details_available = False
            details_truncated = True
            break
        details.append(row)
        details_bytes += row_bytes
    return names, truncated, details, details_available, details_truncated


def olivos_info(ctx, key):
    """已知常量做能力探测；拿不到返回 None。"""
    names = _INFO_ATTRS.get(key)
    if not names or ctx.olivos is None:
        return None
    sources = [safe(lambda: getattr(ctx.olivos, 'infoAPI', None)), ctx.olivos]
    for name in names:
        for source in sources:
            if source is None or source is MISSING:
                continue
            value = scalar(safe(lambda: getattr(source, name, None)))
            if type(value) in (str, int) and value != '':  # SVN 可为整数
                return value
    return None


def _status(ctx, args):
    from . import terminal

    plugins = {'namespaces': [], 'count': 0, 'truncated': False, 'available': False}
    names = plugin_names(ctx.proc)
    if names is not None:
        plugins = {
            'namespaces': names[0],
            'count': len(names[0]),
            'truncated': names[1],
            'available': True,
        }
    bots = bot_info_dict(ctx.proc)
    version = olivos_info(ctx, 'version')
    svn = olivos_info(ctx, 'svn')
    configured = 'unknown'
    if bots is not None and allowed(ctx, REAL_ACCOUNT_READ):
        configured = len(bots)
    return Outcome({
        'python': platform.python_version(),
        'olivos_version': 'unknown' if version is None else version,
        'olivos_svn': 'unknown' if svn is None else svn,
        'plugins': plugins,
        'configured_bot_count': configured,
        'debug_terminal': terminal.status(ctx),
        'root': ctx.root,
    })


def _bots(ctx, args):
    from . import terminal

    if not allowed(ctx, REAL_ACCOUNT_READ):
        return failure('Reading real configured accounts is not permitted')
    data = bot_info_dict(ctx.proc)
    if data is None:
        return failure('Configured account list unavailable')
    bots, truncated = bot_list(data)
    return Outcome({
        'source': 'configured',
        'bots': bots,
        'count': len(bots),
        'truncated': truncated,
        'debug_terminal': terminal.status(ctx),
    })


TOOLS = (
    ToolSpec(
        name='cockpit_status',
        description=(
            'Host and plugin loader overview: Python and OlivOS versions, '
            'loaded plugin namespaces, and configured account count.'
        ),
        schema=object_schema(),
        handler=_status,
    ),
    ToolSpec(
        name='cockpit_bots',
        description=(
            'List configured accounts (not an online check); connection is always '
            "'unknown'. Never includes credentials. Requires configured real-account "
            'access.'
        ),
        schema=object_schema(),
        handler=_bots,
        required_permission=REAL_ACCOUNT_READ,
    ),
)
