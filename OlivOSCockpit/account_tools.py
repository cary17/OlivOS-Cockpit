"""共享只读账号文件工具：路径只来自核实的磁盘启动配置，不推断总控内存状态。"""

import hashlib
import json
import os

from . import config, fs, host, read_tools
from .contracts import (
    MAX_DEPTH,
    MAX_ENTRIES,
    MAX_FILE,
    Outcome,
    ToolError,
    ToolSpec,
    failure,
    object_schema,
    validate_arguments,
)

_MODEL = 'OlivOS_account_config'
_BOOT_FILES = ('basic.json', 'config.json')
MAX_PAGE = 50


def _permitted(ctx, permission=host.REAL_ACCOUNT_READ):
    current = host.safe(lambda: host.snapshot(ctx))
    return (current is not None and current is not host.MISSING
            and getattr(current, 'valid', False) is True
            and host.safe(lambda: host.allowed(ctx, permission)) is True)


def _copy(value):
    result = host.safe(lambda: read_tools._JSONCopy(truncate_lists=False).value(value))
    if result is host.MISSING:
        raise ToolError('Account or boot configuration is not bounded native JSON')
    return result


def _integer(text):
    if len(text) > 80:
        raise ValueError
    return int(text)


def _json(raw):
    try:
        text = raw.decode('utf-8', 'strict')
        depth = nodes = 0
        quoted = escaped = False
        # 宿主会大幅提高递归上限；在 json 解码前限制嵌套，避免耗尽 C 栈。
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in '[{':
                depth += 1
                nodes += 1
                if depth > MAX_DEPTH:
                    raise ValueError
            elif char in ']}':
                depth -= 1
            elif char in ',:':
                nodes += 1
            if nodes > read_tools.MAX_NODES:
                raise ValueError
        value = json.loads(text, object_pairs_hook=config._unique,
                           parse_constant=config._bad_constant, parse_int=_integer)
    except (UnicodeError, ValueError, RecursionError):
        raise ToolError('Account or boot configuration is not strict bounded UTF-8 JSON') from None
    value = _copy(value)
    if type(value) is not dict:
        raise ToolError('Account or boot configuration must be a JSON object')
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_at(parent, name, optional=False):
    if optional:
        fs._path_policy(parent.context, os.path.join(parent.path, name))
        fs._check_fd(parent)
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            fs._check_fd(parent)
            return None
        except OSError:
            raise ToolError('Boot configuration is unavailable') from None
    fd, kind = fs.open_rel(parent, name)
    try:
        info = os.fstat(fd)
        if kind != 'file' or info.st_size > MAX_FILE:
            raise ToolError('Account or boot configuration is not a bounded regular file')
        raw, _, truncated = fs.read_fd(fd, MAX_FILE)
        if truncated or _stamp(info) != _stamp(os.fstat(fd)):
            raise ToolError('Account or boot configuration changed or exceeded its limit')
        return _json(raw), hashlib.sha256(raw).hexdigest(), info
    except OSError:
        raise ToolError('Account or boot configuration is unavailable') from None
    finally:
        os.close(fd)


def _boot_files(ctx):
    root = fs.open_root(ctx.root, context=ctx)
    parent = None
    try:
        for name in _BOOT_FILES:
            fs._path_policy(ctx, os.path.join(root.path, 'conf', name))
        try:
            os.stat('conf', dir_fd=root, follow_symlinks=False)
        except FileNotFoundError:
            fs._check_fd(root)
            return None, None
        except OSError:
            raise ToolError('Boot configuration is unavailable') from None
        parent, kind = fs.open_rel(root, 'conf')
        if kind != 'dir':
            raise ToolError('Boot configuration directory is unavailable')
        return tuple(_read_at(parent, name, optional=True) for name in _BOOT_FILES)
    finally:
        if parent is not None:
            os.close(parent)
        os.close(root)


def _resolve(ctx):
    """返回 (账号绝对路径, 启动配置指纹)，不宣称它是运行时当前活动路径。"""
    basic, patch = _boot_files(ctx)
    if basic is None:
        default = host.safe(lambda: ctx.olivos.bootDataAPI.default_Conf)
        if default is host.MISSING:
            raise ToolError('Verified native boot defaults are unavailable')
        base = _copy(default)
        if type(base) is not dict:
            raise ToolError('Verified native boot defaults are unavailable')
        encoded = json.dumps(base, ensure_ascii=False, allow_nan=False, sort_keys=True).encode('utf-8')
        if len(encoded) > MAX_FILE:
            raise ToolError('Native boot defaults exceed the configuration limit')
        basis = ('native_default', hashlib.sha256(encoded).hexdigest())
    else:
        base = basic[0]
        basis = ('disk', _stamp(basic[2]), basic[1])
    patch_revision = None
    if patch is not None:
        merged = host.safe(lambda: ctx.olivos.bootAPI.get_patch_config(base, patch[0]))
        if merged is host.MISSING:
            raise ToolError('Native boot patch API unavailable or failed safely')
        base = _copy(merged)
        patch_revision = (_stamp(patch[2]), patch[1])
    models = base.get('models') if type(base) is dict else None
    model = models.get(_MODEL) if type(models) is dict else None
    if (type(model) is not dict or model.get('enable') is not True
            or model.get('type') != 'account_config' or model.get('name') != _MODEL):
        raise ToolError('Disk boot configuration does not declare an enabled standard account model')
    data = model.get('data')
    path = data.get('path') if type(data) is dict else None
    if (type(path) is not str or not path or len(path) > config.MAX_PATH_CHARS
            or '\x00' in path or '\\' in path or '..' in path.split('/')
            or (len(path) > 1 and path[1] == ':')):
        raise ToolError('Declared account configuration path is unsupported')
    path = os.path.normpath(path if os.path.isabs(path) else os.path.join(ctx.root, path))
    # authorize_path 只做即时预检；实际读取仍用目录 fd 安全打开并复核身份。
    fs.authorize_path(ctx, path)
    return path, (basis, patch_revision)


def _read(parent, name):
    document, revision, info = _read_at(parent, name)
    accounts = document.get('account')
    if (type(accounts) is not list or len(accounts) > MAX_ENTRIES
            or any(type(account) is not dict for account in accounts)):
        raise ToolError('Account configuration must contain a bounded account object array')
    return document, revision, info


def cockpit_accounts_config(ctx, args):
    if not _permitted(ctx):
        return failure('Reading real configured accounts is not permitted')
    validate_arguments(TOOLS[0], args)
    path, _ = _resolve(ctx)
    parent = fs.open_root(os.path.dirname(path), context=ctx)
    try:
        document, revision, _ = _read(parent, os.path.basename(path))
    finally:
        os.close(parent)
    if not _permitted(ctx):
        return failure('Account access policy changed; retry with the current policy')
    accounts = document['account']
    offset, limit = args.get('offset', 0), args.get('limit', MAX_PAGE)
    end = min(len(accounts), offset + limit)
    more = end < len(accounts)
    return Outcome({
        'source': 'configured_file',
        'path_source': 'disk_boot_configuration',
        'runtime_active_config': 'unknown',
        'sha256': revision,
        'accounts': [{'index': index, 'account': accounts[index]} for index in range(offset, end)],
        'total': len(accounts),
        'offset': offset,
        'limit': limit,
        'truncated': more,
    }, truncated=more)


TOOLS = (
    ToolSpec(
        'cockpit_accounts_config',
        'Read configured account file entries, including disabled accounts, with indices and complete-file SHA-256. '
        'Resolves only the verified standard disk boot configuration (conf/basic.json, conf/config.json and native '
        'defaults); does not claim the active runtime path. Requires real_account_read; output redaction applies '
        'at the common response boundary. No caller-supplied file path.',
        object_schema({
            'offset': {'type': 'integer', 'minimum': 0, 'maximum': MAX_ENTRIES, 'default': 0},
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_PAGE, 'default': MAX_PAGE},
        }),
        cockpit_accounts_config,
        required_permission=host.REAL_ACCOUNT_READ,
    ),
)
