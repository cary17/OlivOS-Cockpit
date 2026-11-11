"""固定公共 Event 只读查询与无 I/O 账号元数据；Full/Lite 共用，不自行注册。"""

import math
from itertools import islice

from . import host
from .contracts import (
    MAX_DEPTH,
    MAX_ENTRIES,
    NAMESPACE,
    Outcome,
    ToolSpec,
    failure,
    object_schema,
    validate_arguments,
)

PERMISSION = 'real_account_read'
MAX_ID = 256
MAX_NODES = 20000
MAX_STRING = 64 * 1024
MAX_TOTAL_TEXT = 256 * 1024
MAX_INTEGER_BITS = 256

# 固定 c6a99fc 的原生结果模板；不接纳任意 Mapping、宿主对象或其他 dict 子类。
_RESULT_TEMPLATES = (
    'universal_result', 'get_msg', 'get_forward_msg', 'get_login_info',
    'get_user_info_strip', 'get_stranger_info', 'get_friend_list',
    'get_group_info_strip', 'get_group_info', 'get_group_list',
    'get_group_member_info_strip', 'get_group_member_info', 'get_group_member_list',
    'can_send_image', 'can_send_record', 'get_status', 'get_version_info',
    'get_group_file_system_info', 'get_group_root_files', 'get_group_files_by_folder',
    'get_essence_msg_list', 'get_group_ignore_add_request',
    'get_doubt_friends_add_request', 'get_group_notice', 'get_group_system_msg',
)

_ID = {'type': 'string', 'minLength': 1, 'maxLength': MAX_ID}
_PARAMETERS = {
    'user_id': _ID,
    'group_id': _ID,
    'host_id': _ID,
    'message_id': _ID,
    'folder_id': _ID,
    'no_cache': {'type': 'boolean', 'default': False},
    'count': {'type': 'integer', 'minimum': 1, 'maximum': MAX_ENTRIES, 'default': 50},
    'file_count': {'type': 'integer', 'minimum': 1, 'maximum': MAX_ENTRIES},
}
_DEFAULTS = {'no_cache': False, 'count': 50}

# 工具名、固定方法、位置参数顺序、必填参数；不暴露 remote/flag_log 或通用分派字段。
_QUERIES = (
    ('account_login_info', ('get_login_info',), (), ()),
    ('account_connection_status', ('get_status',), (), ()),
    ('protocol_version', ('get_version_info',), (), ()),
    ('user_info', ('get_stranger_info',), ('user_id', 'no_cache'), ('user_id',)),
    ('friend_list', ('get_friend_list',), (), ()),
    ('group_list', ('get_group_list',), (), ()),
    ('group_info', ('get_group_info',), ('group_id', 'host_id', 'no_cache'), ('group_id',)),
    ('group_member_info', ('get_group_member_info',),
     ('group_id', 'user_id', 'host_id', 'no_cache'), ('group_id', 'user_id')),
    ('group_member_list', ('get_group_member_list',), ('group_id', 'host_id'), ('group_id',)),
    ('host_list', ('get_host_list',), (), ()),
    ('host_info', ('get_host_info',), ('host_id',), ('host_id',)),
    ('message_get', ('get_msg',), ('message_id',), ('message_id',)),
    ('message_forward_get', ('get_forward_msg',), ('message_id',), ('message_id',)),
    ('group_essence_list', ('get_essence_msg_list',), ('group_id',), ('group_id',)),
    ('group_notice_list', ('get_group_notice',), ('group_id',), ('group_id',)),
    ('group_system_msg', ('get_group_system_msg',), ('count',), ()),
    ('group_ignored_requests', ('get_group_ignore_add_request',), ('group_id',), ()),
    ('friend_doubt_requests', ('get_doubt_friends_add_request',), ('count',), ()),
    ('group_file_stats', ('get_group_file_system_info',), ('group_id',), ('group_id',)),
    ('group_file_list', ('get_group_root_files',), ('group_id', 'file_count'), ('group_id',)),
    ('group_folder_list', ('get_group_files_by_folder',),
     ('group_id', 'folder_id', 'file_count'), ('group_id', 'folder_id')),
    ('send_capabilities', ('can_send_image', 'can_send_record'), (), ()),
)


class _BoundaryError(ValueError):
    pass


class _JSONCopy:
    def __init__(self, dict_types=(), truncate_lists=True):
        self.dict_types = dict_types
        self.truncate_lists = truncate_lists
        self.nodes = 0
        self.text = 0
        self.truncated = False

    def string(self, value):
        if type(value) is not str or len(value) > MAX_STRING:
            raise _BoundaryError
        size = len(value.encode('utf-8', 'strict'))
        self.text += size
        if size > MAX_STRING or self.text > MAX_TOTAL_TEXT:
            raise _BoundaryError
        return value

    def value(self, value, depth=0):
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise _BoundaryError
        kind = type(value)
        if value is None or kind is bool:
            return value
        if kind is str:
            return self.string(value)
        if kind is int and value.bit_length() <= MAX_INTEGER_BITS:
            return value
        if kind is float and math.isfinite(value):
            return value
        if depth >= MAX_DEPTH:
            raise _BoundaryError
        if kind is list:
            if len(value) > MAX_ENTRIES:
                if not self.truncate_lists:
                    raise _BoundaryError
                self.truncated = True
            return [self.value(item, depth + 1) for item in islice(value, MAX_ENTRIES)]
        if kind is dict or any(kind is template for template in self.dict_types):
            if dict.__len__(value) > MAX_ENTRIES:
                raise _BoundaryError
            result = {}
            for key, item in dict.items(value):
                self.nodes += 1
                if self.nodes > MAX_NODES:
                    raise _BoundaryError
                result[self.string(key)] = self.value(item, depth + 1)
            return result
        raise _BoundaryError


def _policy_ready(ctx):
    # host.allowed 的旧兼容回退会放行无配置的 Full 只读；这里额外要求配置快照存在。
    current = host.safe(lambda: host.snapshot(ctx))
    return current is not None and current is not host.MISSING


def _identity(bot):
    fields = host._fields(bot)
    if fields is None or fields.get('enable') is False:
        return None
    platform = fields.get('platform')
    if type(platform) is not dict:
        return None
    triple = tuple(platform.get(key) for key in ('sdk', 'platform', 'model'))
    digest, bot_id = fields.get('hash'), fields.get('id')
    if any(type(item) is not str or not item or len(item) > MAX_ID for item in (digest,) + triple):
        return None
    if not ((type(bot_id) is str and 0 < len(bot_id) <= MAX_ID)
            or (type(bot_id) is int and bot_id.bit_length() <= MAX_INTEGER_BITS)):
        return None
    return digest, bot_id, triple


def _make_event(ctx, bot_hash):
    data = host.bot_info_dict(ctx.proc)
    bot = data.get(bot_hash) if data is not None else None
    identity = _identity(bot)
    if identity is None or identity[0] != bot_hash or ctx.olivos is None:
        return None
    digest = ctx.olivos.API.getBotHash(
        bot_id=identity[1], platform_sdk=identity[2][0],
        platform_platform=identity[2][1], platform_model=identity[2][2])
    if type(digest) is not str or digest != bot_hash:
        return None
    fake = ctx.olivos.contentAPI.fake_sdk_event(bot_info=bot, fakename=NAMESPACE)
    event = ctx.olivos.API.Event(fake, ctx.proc.log)
    return event, bot, identity


def _bound(ctx, event, bot, identity):
    data = host.bot_info_dict(ctx.proc)
    if data is None or data.get(identity[0]) is not bot or _identity(bot) != identity:
        return False
    platform = event.platform
    return (event.active is True and event.bot_info is bot and type(platform) is dict
            and all(type(platform.get(key)) is str and platform[key] == expected
                    for key, expected in zip(('sdk', 'platform', 'model'), identity[2])))


def _dict_types(ctx):
    templates = host.safe(lambda: ctx.olivos.contentAPI.api_result_data_template)
    result = []
    for name in _RESULT_TEMPLATES:
        template = host.safe(lambda: getattr(templates, name, None))
        if type(template) is type and issubclass(template, dict):
            result.append(template)
    return tuple(result)


def _read_spec(name, methods, parameters, required):
    schema = object_schema({'bot_hash': _ID, **{key: _PARAMETERS[key] for key in parameters}},
                           ('bot_hash',) + required)

    def handle(ctx, args):
        if (host.safe(lambda: host.allowed(ctx, PERMISSION)) is not True
                or not _policy_ready(ctx)):
            return failure('Reading real configured accounts is not permitted')
        validate_arguments(spec, args)
        built = host.safe(lambda: _make_event(ctx, args['bot_hash']))
        if built is None or built is host.MISSING:
            return failure('Configured account or native query event unavailable')
        event, bot, identity = built
        copier = _JSONCopy(_dict_types(ctx))
        results = []
        values = tuple(args.get(key, _DEFAULTS.get(key)) for key in parameters)
        for method_name in methods:
            method = host.safe(lambda: getattr(event, method_name, None))
            if not callable(method) or host.safe(lambda: _bound(ctx, event, bot, identity)) is not True:
                return failure('Account binding or native query API unavailable')
            if not host.allowed(ctx, PERMISSION):
                return failure('Configuration changed before native query')
            raw = host.safe(lambda: method(*values, flag_log=False, remote=False))
            if raw is None or raw is host.MISSING:
                return failure('Native query unsupported or failed safely')
            if host.safe(lambda: _bound(ctx, event, bot, identity)) is not True:
                return failure('Account binding changed during query')
            clean = host.safe(lambda: copier.value(raw, depth=1 if len(methods) > 1 else 0))
            if clean is host.MISSING:
                return failure('Native query result is not bounded JSON')
            if type(clean) is not dict or clean.get('active') is not True or 'data' not in clean:
                return Outcome({'error': 'Native query unsupported or unsuccessful', 'result': clean},
                               is_error=True, truncated=copier.truncated)
            results.append(clean)
        data = results[0] if len(results) == 1 else {'image': results[0], 'record': results[1]}
        return Outcome(data, truncated=copier.truncated)

    spec = ToolSpec(
        name='cockpit_' + name,
        description=(
            'Query the selected current account through native Event.' + '/'.join(methods)
            + '; may contact its adapter. Requires real_account_read. Unsupported models '
              'and unavailable event context fail safely; lists are bounded. No media download or file URL API.'
        ),
        schema=schema,
        handler=handle,
        required_permission=PERMISSION,
    )
    return spec


def _plugins(ctx, args):
    catalog = host.plugin_catalog(ctx.proc)
    if catalog is None:
        return failure('Loaded plugin namespaces unavailable')
    names, truncated, plugins, details_available, details_truncated = catalog
    return Outcome({
        'namespaces': names,
        'count': len(names),
        'truncated': truncated,
        'plugins': plugins,
        'details_available': details_available,
        'details_truncated': details_truncated,
    }, truncated=truncated)


def _account_metadata(ctx, args):
    raw = host.safe(lambda: ctx.olivos.accountMetadataAPI.getAccountEditorMetadata())
    if raw is None or raw is host.MISSING:
        return failure('Account editor metadata unavailable')
    copier = _JSONCopy()
    clean = host.safe(lambda: copier.value(raw))
    if type(clean) is not dict:
        return failure('Account editor metadata is not bounded JSON')
    return Outcome(clean, truncated=copier.truncated)


def _validate_account(ctx, args):
    # 输入不能截断后再校验；给纯校验器副本，即使宿主实现有误也不修改调用方输入。
    account = host.safe(lambda: _JSONCopy(truncate_lists=False).value(args['account']))
    if account is host.MISSING:
        return failure('Account input is not bounded native JSON')
    errors = host.safe(lambda: ctx.olivos.accountAPI._validate_account_config(account))
    if type(errors) is not list:
        return failure('Pure account validator unavailable or failed safely')
    rows = []
    for row in islice(errors, MAX_ENTRIES):
        if (type(row) is not tuple or len(row) != 2
                or type(row[0]) is not str or type(row[1]) is not str):
            return failure('Pure account validator returned an invalid result')
        rows.append({'field': row[0], 'reason': row[1]})
    truncated = len(errors) > MAX_ENTRIES
    copier = _JSONCopy()
    clean = host.safe(lambda: copier.value({'valid': not errors, 'errors': rows, 'truncated': truncated}))
    if clean is host.MISSING:
        return failure('Account validation result is not bounded JSON')
    return Outcome(clean, truncated=truncated)


def _metadata_spec(name, description, operation, schema=None):
    def handle(ctx, args):
        if (host.safe(lambda: host.allowed(ctx, None)) is not True
                or not _policy_ready(ctx)):
            return failure('Metadata access is not permitted')
        validate_arguments(spec, args)
        outcome = host.safe(lambda: operation(ctx, args))
        return failure('Metadata API failed safely') if outcome is host.MISSING else outcome

    spec = ToolSpec(name='cockpit_' + name, description=description,
                    schema=schema if schema is not None else object_schema(), handler=handle,
                    required_permission=None)
    return spec


READ_TOOLS = tuple(_read_spec(*entry) for entry in _QUERIES)
METADATA_TOOLS = (
    _metadata_spec('plugin_loaded_list',
                   'Read loaded plugin namespaces plus bounded runtime metadata and host priority values; unavailable fields are marked explicitly. No disk I/O.', _plugins),
    _metadata_spec('account_type_catalog',
                   'Read static native account editor metadata, not configured accounts or Cockpit settings.',
                   _account_metadata),
    _metadata_spec('accounts_schema',
                   'Read native getAccountEditorMetadata field/schema metadata; no account file is loaded.',
                   _account_metadata),
    _metadata_spec('accounts_validate',
                   'Validate one supplied stored-format account object with the native pure validator. '
                   'Returns valid/errors without loading, saving or creating accounts; '
                   'input must be bounded native JSON.',
                   _validate_account, object_schema({
                       'account': {'type': 'object',
                                   'description': 'One account object; unknown fields are validated too.'},
                   }, ('account',))),
)
TOOLS = READ_TOOLS + METADATA_TOOLS
