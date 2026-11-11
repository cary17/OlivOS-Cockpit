"""四个只读文件工具：cockpit_plugins / cockpit_log / cockpit_data / cockpit_meta。"""

import base64
import codecs
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from dataclasses import dataclass

from . import fs, host, redaction
from .contracts import (MAX_FILE, MAX_LOG_LINES, MAX_LOG_SCAN, MAX_MANIFEST,
                        MAX_OPK, MAX_RESPONSE, Outcome, ToolError, ToolSpec, check_json_budget,
                        failure, object_schema)

LOG_SUFFIX = '.log'
_CURSOR_KEY = secrets.token_bytes(32)
_CURSOR_TTL = 300
_CURSOR_RE = re.compile(r'[A-Za-z0-9_-]{1,1024}\Z')


def _tag(label, value):
    return hmac.new(_CURSOR_KEY, label + value, hashlib.sha256).hexdigest()


def _path_tag(namespace, path):
    return _tag(b'path\\0', (namespace + '\\0' + path).encode('utf-8'))


def _context_tag(known, policy):
    rules = redaction.as_policy(policy)
    data = json.dumps(
        [rules.enabled, sorted(rules.redact_fields), sorted(rules.allow_fields), list(known)],
        ensure_ascii=True, separators=(',', ':'), allow_nan=False,
    ).encode('ascii')
    return _tag(b'context\\0', data)


def _view_tag(text):
    return _tag(b'view\\0', text.encode('utf-8'))


def _encode_cursor(payload):
    raw = json.dumps(payload, ensure_ascii=True, allow_nan=False,
                     sort_keys=True, separators=(',', ':')).encode('ascii')
    signature = hmac.new(_CURSOR_KEY, b'cursor\\0' + raw, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw + signature).rstrip(b'=').decode('ascii')


def _consume_cursor(token):
    if type(token) is not str or not _CURSOR_RE.fullmatch(token):
        raise ToolError('Invalid or expired read cursor')
    try:
        padded = token + '=' * (-len(token) % 4)
        packed = base64.urlsafe_b64decode(padded.encode('ascii'))
        if (len(packed) <= 32
                or base64.urlsafe_b64encode(packed).rstrip(b'=').decode('ascii') != token):
            raise ValueError
        raw, signature = packed[:-32], packed[-32:]
        expected = hmac.new(_CURSOR_KEY, b'cursor\\0' + raw, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        payload = json.loads(raw.decode('ascii'))
        if (type(payload) is not dict or type(payload.get('exp')) is not int
                or payload['exp'] <= time.time()):
            raise ValueError
        return payload
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        raise ToolError('Invalid or expired read cursor') from None


@dataclass(frozen=True)
class DataPage:
    state: dict | None
    path_tag: str
    revision: tuple
    file_size: int
    source_start: int
    fixed_end: int | None
    complete_file: bool
    eof: bool
    generation: object
    jsonl: bool | None = None

    def context_tag(self, known, policy):
        return _context_tag(known, policy)

    def view_tag(self, text):
        return _view_tag(text)

    def issue_cursor(self, block_start, block_end, view_offset, view_tag, context_tag, jsonl=False):
        generation = self.generation if type(self.generation) in (int, str, type(None)) else None
        payload = {
            'v': 2,
            'path': self.path_tag,
            'revision': list(self.revision),
            'generation': generation,
            'block_start': block_start,
            'block_end': block_end,
            'view_offset': view_offset,
            'view_tag': view_tag,
            'context_tag': context_tag,
            'jsonl': jsonl,
            'exp': int(time.time()) + _CURSOR_TTL,
        }
        return _encode_cursor(payload)

def _cursor_state(token, namespace, path, generation):
    state = _consume_cursor(token)
    if (state.get('v') != 2 or state.get('path') != _path_tag(namespace, path)
            or state.get('generation') != (generation if type(generation) in (int, str, type(None)) else None)):
        raise ToolError('Read cursor is no longer valid')
    integers = ('block_start', 'block_end', 'view_offset', 'exp')
    revision = state.get('revision')
    if (any(type(state.get(name)) is not int or state[name] < 0 for name in integers)
            or type(revision) is not list or len(revision) != 5
            or any(type(item) is not int for item in revision)
            or type(state.get('jsonl')) is not bool):
        raise ToolError('Invalid or expired read cursor')
    if (state['block_end'] < state['block_start']
            or state['block_end'] - state['block_start'] > MAX_FILE
            or state['block_end'] > revision[2]
            or type(state.get('view_tag')) is not str
            or type(state.get('context_tag')) is not str):
        raise ToolError('Invalid or expired read cursor')
    return state
MANIFEST_FIELDS = ('name', 'namespace', 'version', 'svn', 'info', 'author',
                   'compatible_svn', 'priority')
REAL_ACCOUNT_READ = 'real_account_read'


def _open_root(path, ctx):
    return fs.open_root(path, context=ctx)


def _permitted(ctx):
    """真实数据读取权限：Full 默认开启，Lite 默认关闭，配置快照可覆盖。"""
    # shortcut: 复用现有 real_account_read 权限位；出现独立路径权限位后改为该权限。
    return host.allowed(ctx, REAL_ACCOUNT_READ)


def _denied_outcome():
    return failure('Reading real file data is not permitted')


def _check_namespace(value):
    if (type(value) is not str or not value or value in ('.', '..')
            or '/' in value or '\\' in value or '\x00' in value):
        raise ToolError('Invalid namespace')
    return value


def _check_rel(value):
    if type(value) is not str or '\x00' in value or value.startswith('/'):
        raise ToolError('Invalid path')
    if '..' in value.split('/'):
        raise ToolError('Parent components are not allowed')
    return value


def _entry(entry):
    size = entry['size'] if entry['type'] == 'file' else None
    return {'name': entry['name'], 'type': entry['type'], 'size': size,
            'mtime': entry['mtime']}


def _read_text(data, truncated=False):
    """截断读取时只丢弃末尾不完整的码点，真正非法的 UTF-8 仍然拒绝。"""
    decoder = codecs.getincrementaldecoder('utf-8')()
    try:
        return decoder.decode(data, final=not truncated), False
    except UnicodeDecodeError:
        return None, True


def _scan_logs(dir_fd, ctx):
    """在有界目录扫描内选最新的 .log；被禁止项不参与选择，也不暴露名称。"""
    entries, more = fs.list_dir(dir_fd)
    best = None
    for entry in entries:
        if entry['type'] == 'file' and entry['name'].endswith(LOG_SUFFIX):
            if best is None or entry['mtime'] > best['mtime']:
                best = entry
    return best, more


def _read_manifest(dir_fd, rel):
    data, _, truncated = fs.read_at(dir_fd, rel, MAX_MANIFEST)
    if truncated:
        raise ToolError('Manifest too large')
    return data


def _manifest(raw):
    try:
        text = raw.decode('utf-8')
        # 解码前先限制嵌套与节点数，不依赖宿主的 recursionlimit。
        check_json_budget(text)
        data = json.loads(text)
    except (UnicodeDecodeError, ValueError, OverflowError, RecursionError):
        raise ToolError('Invalid manifest')
    if type(data) is not dict:
        raise ToolError('Invalid manifest')
    result = {}
    for key in MANIFEST_FIELDS:
        value = data.get(key)
        if type(value) in (str, int, bool):
            result[key] = value
        elif type(value) is float and math.isfinite(value):
            result[key] = value
        elif type(value) is list and len(value) <= 64 and all(
                type(item) in (str, int, bool) for item in value):
            result[key] = list(value)
    return result


def cockpit_plugins(ctx, args):
    app_fd = fs.open_package_root(ctx)
    try:
        entries, more = fs.list_dir(app_fd)
        items = []
        used = 0
        for entry in entries:
            if entry['type'] not in ('file', 'dir'):
                continue
            if entry['type'] == 'file' and not entry['name'].endswith('.opk'):
                continue
            if entry['type'] == 'dir':
                try:
                    check_fd, kind = fs.open_rel(app_fd, entry['name'] + '/app.json')
                except ToolError:
                    continue
                os.close(check_fd)
                if kind != 'file':
                    continue
            if entry['type'] == 'file' and entry['size'] > MAX_OPK:
                record = {'filename': entry['name'], 'error': 'Package too large'}
            else:
                record = {'filename': entry['name'], 'mtime': entry['mtime']}
                try:
                    if entry['type'] == 'file':
                        raw = fs.package_manifest(fs.read_package(app_fd, entry['name']))
                    else:
                        raw = _read_manifest(app_fd, entry['name'] + '/app.json')
                    record['manifest'] = _manifest(raw)
                except ToolError as exc:
                    record['error'] = str(exc)
            size = len(json.dumps(record, ensure_ascii=True, allow_nan=False,
                                  separators=(',', ':')).encode('ascii')) + 1
            # text 再转义后连同 structuredContent 接近三倍，另留信封余量。
            if used + size > MAX_RESPONSE // 4:
                more = True
                break
            items.append(record)
            used += size
    finally:
        os.close(app_fd)
    return Outcome({'plugins': items}, truncated=more)


def cockpit_log(ctx, args):
    if not _permitted(ctx):
        return _denied_outcome()
    root = _open_root(ctx.root, ctx)
    try:
        log_fd, kind = fs.open_rel(root, 'logfile')
    finally:
        os.close(root)
    if kind != 'dir':
        os.close(log_fd)
        raise ToolError('Log directory is unavailable')
    try:
        filename = args.get('filename')
        if filename is not None:
            if (type(filename) is not str or not filename or '/' in filename
                    or '\\' in filename or '\x00' in filename
                    or filename in ('.', '..')):
                raise ToolError('Invalid log filename')
            entry = {'name': filename}
            scan_truncated = False
        else:
            entry, scan_truncated = _scan_logs(log_fd, ctx)
            if entry is None:
                raise ToolError('No log file is available')
        data, size, cut = fs.read_tail(log_fd, entry['name'], MAX_LOG_SCAN)
    finally:
        os.close(log_fd)
    scanned = len(data)  # bytes_scanned 始终是实际扫描的原始字节数
    text_data = data
    if cut:
        # 尾部读取可能从多字节码点中间开始；按原始字节跳到下一个换行之后。
        newline = data.find(b'\n')
        text_data = data[newline + 1:] if newline >= 0 else b''
    text, binary = _read_text(text_data)
    if binary:
        raise ToolError('Log file is not valid UTF-8')
    trailing = text.endswith('\n')
    body = text[:-1] if trailing else text
    limit = args.get('lines', MAX_LOG_LINES)
    # 仅从右侧切出所需行数，避免对纯换行大文件生成海量对象。
    parts = body.rsplit('\n', limit)
    truncated = cut or scan_truncated or len(parts) > limit
    parts = parts[-limit:]
    level = args.get('level')
    namespace = args.get('namespace')
    if level is not None or namespace is not None:
        kept = []
        for line in parts:
            if level is not None and level.lower() not in line.lower():
                continue
            if namespace is not None and namespace not in line:
                continue
            kept.append(line)
        truncated = truncated or len(kept) != len(parts)
        parts = kept
    content = '\n'.join(parts)
    if trailing and parts:
        content += '\n'
    return Outcome({'filename': entry['name'], 'size': size,
                    'bytes_scanned': scanned, 'lines': content},
                   truncated=truncated)


def cockpit_data(ctx, args):
    if not _permitted(ctx):
        return _denied_outcome()
    namespace = _check_namespace(args['namespace'])
    segment = args.get('path', '')
    _check_rel(segment)
    cursor = args.get('cursor')
    mode = args.get('mode', 'read' if cursor is not None else 'list')
    if cursor is not None and mode != 'read':
        raise ToolError('Cursor is only valid in read mode')
    root = _open_root(ctx.data_root, ctx)
    try:
        base_fd, kind = fs.open_rel(root, namespace)
    finally:
        os.close(root)
    if kind != 'dir':
        os.close(base_fd)
        raise ToolError('Namespace directory is unavailable')
    try:
        fd, kind = fs.open_rel(base_fd, segment)
        try:
            if mode == 'read':
                if kind != 'file':
                    raise ToolError('Not a regular file')
                if cursor is None:
                    state = None
                    offset = 0
                    fixed_end = None
                else:
                    state = _cursor_state(
                        cursor, namespace, segment, getattr(ctx, 'request_generation', None))
                    offset = state['block_start']
                    fixed_end = state['block_end'] if state['block_end'] > offset else None
                os.close(fd)
                fd = None
                limit = fixed_end - offset if fixed_end is not None else MAX_FILE
                data, size, revision, more = fs.read_range(base_fd, segment, offset, limit)
                if state is not None and state['revision'] != list(revision):
                    raise ToolError('File changed; read cursor is no longer valid')
                if fixed_end is not None and offset + len(data) != fixed_end:
                    raise ToolError('File changed; read cursor is no longer valid')
                truncated = offset + len(data) < size
                text, binary = _read_text(data, truncated)
                if binary:
                    raise ToolError('Binary content is not supported')
                complete_file = (state is None and offset == 0
                                 and size <= MAX_FILE and not more)
                result = {'namespace': namespace, 'path': segment, 'size': len(data),
                          'content': text}
                if complete_file:
                    result['sha256'] = hashlib.sha256(data).hexdigest()
                page = DataPage(
                    state=state,
                    path_tag=_path_tag(namespace, segment),
                    revision=revision,
                    file_size=size,
                    source_start=offset,
                    fixed_end=fixed_end,
                    complete_file=complete_file,
                    eof=not more,
                    generation=getattr(ctx, 'request_generation', None),
                    jsonl=(state['jsonl'] if state is not None else
                           (True if segment.casefold().endswith('.jsonl') else None)),
                )
                return Outcome(result, truncated=(state is not None or not complete_file), page=page)
            if cursor is not None:
                raise ToolError('Cursor is only valid in read mode')
            if kind != 'dir':
                raise ToolError('Not a directory')
            entries, more = fs.list_dir(fd)
            return Outcome({'namespace': namespace, 'path': segment,
                            'entries': [_entry(entry) for entry in entries]}, truncated=more)
        finally:
            if fd is not None:
                os.close(fd)
    finally:
        os.close(base_fd)


def _find_manifest(app_fd, namespace, ctx):
    entries, _ = fs.list_dir(app_fd)
    found = []
    for entry in entries:
        record = {'filename': entry['name']}
        if entry['type'] == 'file' and entry['name'].endswith('.opk'):
            if entry['size'] > MAX_OPK:
                continue
            try:
                package = fs.read_package(app_fd, entry['name'])
                raw = fs.package_manifest(package)
            except ToolError:
                continue
            record.update(size=len(package), sha256=hashlib.sha256(package).hexdigest())
        elif entry['type'] == 'dir':
            try:
                raw = _read_manifest(app_fd, entry['name'] + '/app.json')
            except ToolError:
                continue
        else:
            continue
        try:
            manifest = _manifest(raw)
        except ToolError:
            continue
        if manifest.get('namespace') == namespace:
            record['manifest'] = manifest
            found.append(record)
            if len(found) == 2:
                break
    return found


def cockpit_meta(ctx, args):
    namespace = args.get('namespace')
    filename = args.get('filename')
    if (namespace is None) == (filename is None):
        raise ToolError('Specify exactly one of namespace or filename')
    if namespace is not None:
        namespace = _check_namespace(namespace)
    if filename is not None and (type(filename) is not str or not filename
                                 or '/' in filename or '\\' in filename
                                 or '\x00' in filename or filename in ('.', '..')):
        raise ToolError('Invalid package filename')
    app_fd = fs.open_package_root(ctx)
    try:
        if namespace is not None:
            found = _find_manifest(app_fd, namespace, ctx)
            if not found:
                raise ToolError('No package matches the namespace')
            if len(found) > 1:
                raise ToolError('Multiple packages match the namespace; specify filename')
            return Outcome(found[0])
        record = {'filename': filename}
        if filename.endswith('.opk'):
            package = fs.read_package(app_fd, filename)
            raw = fs.package_manifest(package)
            # 与本次读取同源的整包摘要，供安装结果核验；不是覆盖前内容闸门。
            record.update(size=len(package), sha256=hashlib.sha256(package).hexdigest())
        else:
            raw = _read_manifest(app_fd, filename + '/app.json')
        record['manifest'] = _manifest(raw)
        return Outcome(record)
    finally:
        os.close(app_fd)


TOOLS = (
    ToolSpec(
        'cockpit_plugins',
        'List installed plugin packages with app.json metadata (read-only, no imports)',
        object_schema(),
        cockpit_plugins,
    ),
    ToolSpec(
        'cockpit_log',
        'Read the tail of an OlivOS log file with optional level/namespace filters',
        object_schema({
            'filename': {'type': 'string', 'maxLength': 255},
            'lines': {'type': 'integer', 'minimum': 1, 'maximum': MAX_LOG_LINES},
            'level': {'type': 'string', 'maxLength': 64},
            'namespace': {'type': 'string', 'maxLength': 128},
        }),
        cockpit_log,
        required_permission=REAL_ACCOUNT_READ,
    ),
    ToolSpec(
        'cockpit_data',
        'List or read UTF-8 files under a plugin data namespace; read results may continue with cursor',
        object_schema({
            'namespace': {'type': 'string', 'maxLength': 128},
            'mode': {'type': 'string', 'enum': ['list', 'read']},
            'path': {'type': 'string', 'maxLength': 1024},
            'cursor': {'type': 'string', 'minLength': 1, 'maxLength': 1024},
        }, ('namespace',)),
        cockpit_data,
        required_permission=REAL_ACCOUNT_READ,
    ),
    ToolSpec(
        'cockpit_meta',
        'Read app.json metadata from an OPK or unpacked plugin directory',
        object_schema({
            'namespace': {'type': 'string', 'maxLength': 128},
            'filename': {'type': 'string', 'maxLength': 255},
        }),
        cockpit_meta,
    ),
)
