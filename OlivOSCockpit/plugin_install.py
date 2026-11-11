"""Full 专属：把客户端分块上传的 OPK 写入宿主插件包根。

上传只保存在有界内存中，单包 ≤ 8 MiB；写入前完整校验归档、清单与同名
namespace 冲突，再用 O_EXCL 临时文件、fsync 与原子发布落盘。不导入或
执行包内容，也不删除其他包或源码目录。
"""

import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import stat
import threading
import time
import zipfile

from . import config, fs, host
from .contracts import (MAX_MANIFEST, MAX_OPK, MAX_ZIP_ENTRIES, Outcome, ToolError,
                        ToolSpec, check_json_budget, failure, object_schema,
                        validate_arguments)

PERMISSION = 'plugin_install'
MAX_CHUNK = 512 * 1024
MAX_CHUNK_B64 = 4 * ((MAX_CHUNK + 2) // 3)
UPLOAD_TTL = 300.0
MAX_EXPANDED_TOTAL = 32 * 1024 * 1024
MAX_EXPANDED_FILE = 8 * 1024 * 1024
MAX_MEMBER_NAME = 1024
MAX_SCAN_ENTRIES = 512
MAX_SCAN_MANIFESTS = 128
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SCAN_DEPTH = 10
FRAMEWORK_NAMESPACES = frozenset(('olivos',))
_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
_SHA256 = re.compile(r'[0-9a-fA-F]{64}\Z')
_UPLOAD_ID = re.compile(r'[A-Za-z0-9_-]{32,64}\Z')
_TEMP_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
               | getattr(os, 'O_CLOEXEC', 0))
_BUSY = 'Another plugin package operation is in progress'
_INVALID_SESSION = 'Upload session is not active or is no longer valid'
_INCOMPLETE = 'Package root scan is incomplete'
_UNVERIFIED = ('Package may have been installed but the final state could not be verified; '
               'check the package root and do not retry automatically')
_WRITE_FAILED = 'Plugin package installation failed safely'
_UNSAFE_ENTRY = 'Invalid package entry'
_INVALID_PACKAGE = 'Invalid package'

_LOCK = threading.Lock()
_UPLOAD = None


def _now():
    return time.monotonic()


def _manager(ctx):
    manager = getattr(ctx, 'config', None)
    return manager if manager is not None else getattr(ctx, 'config_manager', None)


def _snapshot(ctx):
    current = host.snapshot(ctx)
    if (current is None or current is host.MISSING
            or getattr(current, 'valid', False) is not True
            or type(getattr(current, 'generation', None)) is not int):
        raise ToolError('Configuration is not available')
    return current


def _permitted(ctx):
    return host.allowed(ctx, PERMISSION)


def _owner(ctx):
    current = _snapshot(ctx)
    return (getattr(ctx, 'proc', None), getattr(ctx, 'olivos', None),
            getattr(ctx, 'root', None), getattr(ctx, 'data_root', None),
            _manager(ctx), current.generation)


def _same_owner(current, stored):
    return (current[0] is stored[0] and current[1] is stored[1]
            and current[2] == stored[2] and current[3] == stored[3]
            and current[4] is stored[4] and current[5] == stored[5])


def _authorize(ctx, state):
    if state.get('revoked'):
        raise ToolError('Upload session was revoked')
    try:
        current = _owner(ctx)
    except ToolError:
        raise ToolError(_INVALID_SESSION) from None
    if not _same_owner(current, state['owner']) or not _permitted(ctx):
        raise ToolError(_INVALID_SESSION)


def _scope_matches(ctx, state):
    stored = state['owner']
    manager = _manager(ctx)
    if stored[4] is not None and manager is stored[4]:
        return True
    if stored[0] is not None and getattr(ctx, 'proc', None) is stored[0]:
        return True
    return (stored[1] is not None and getattr(ctx, 'olivos', None) is stored[1]
            and getattr(ctx, 'root', None) == stored[2]
            and getattr(ctx, 'data_root', None) == stored[3])


def _expired(state):
    return _now() >= state['expires']


def _new_state(ctx, filename, namespace, size):
    owner = _owner(ctx)
    if not _permitted(ctx):
        raise ToolError('Installing plugin packages is not permitted')
    root = fs.open_package_root(ctx)
    fs.close(root)
    return {
        'id': secrets.token_urlsafe(32),
        'owner': owner,
        'filename': filename,
        'namespace': namespace,
        'size': size,
        'data': bytearray(),
        'expires': _now() + UPLOAD_TTL,
        'revoked': False,
    }


def _drop_if_expired():
    global _UPLOAD
    state = _UPLOAD
    if state is not None and _expired(state):
        _UPLOAD = None
        return True
    return False


def _session(ctx, upload_id):
    state = _UPLOAD
    if state is None:
        raise ToolError(_INVALID_SESSION)
    if (type(upload_id) is not str or _UPLOAD_ID.fullmatch(upload_id) is None
            or not hmac.compare_digest(upload_id.encode('ascii'), state['id'].encode('ascii'))):
        raise ToolError(_INVALID_SESSION)
    if _drop_if_expired():
        raise ToolError(_INVALID_SESSION)
    _authorize(ctx, state)
    return state


def _filename(value):
    if type(value) is not str or not 1 <= len(value) <= 255 or not value.endswith('.opk'):
        raise ToolError('filename must be a plain .opk basename')
    stem = value[:-4]
    if not stem or value.startswith('.') or value in ('.', '..'):
        raise ToolError('filename must be a plain .opk basename')
    if any(char in '<>:"/\\|?*' or ord(char) < 32 or 127 <= ord(char) <= 159
           or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ToolError('filename must be a plain .opk basename')
    folded = stem.casefold()
    if folded.startswith(config.NAMESPACE_DIR.casefold()) or folded == 'olivos':
        raise ToolError('Replacing Cockpit or OlivOS framework packages is not permitted')
    return value


def _namespace(value):
    if type(value) is not str or _IDENT.fullmatch(value) is None:
        raise ToolError('namespace must be a safe Python identifier')
    folded = value.casefold()
    if folded == config.NAMESPACE_DIR.casefold() or folded in FRAMEWORK_NAMESPACES:
        raise ToolError('Installing Cockpit or OlivOS framework namespaces is not permitted')
    return value


def _fields(args, required, allowed):
    if set(required) - set(args):
        raise ToolError('Missing required argument')
    if set(args) - set(allowed):
        raise ToolError('Unknown argument')


def cockpit_plugin_install(ctx, args):
    if not _SUPPORTED:
        raise ToolError('Secure package installation is not supported on this platform')
    validate_arguments(TOOLS[0], args)
    operation = args.get('operation')
    if operation == 'begin':
        _fields(args, ('operation', 'filename', 'namespace', 'size'),
                ('operation', 'filename', 'namespace', 'size'))
        return _begin(ctx, args)
    if operation == 'write':
        _fields(args, ('operation', 'upload_id', 'offset', 'chunk'),
                ('operation', 'upload_id', 'offset', 'chunk'))
        return _write(ctx, args)
    if operation == 'commit':
        _fields(args, ('operation', 'upload_id', 'sha256'),
                ('operation', 'upload_id', 'sha256'))
        return _commit(ctx, args)
    if operation == 'cancel':
        _fields(args, ('operation', 'upload_id'), ('operation', 'upload_id'))
        return _cancel(ctx, args)
    raise ToolError('Unsupported operation')


def _begin(ctx, args):
    global _UPLOAD
    filename = _filename(args.get('filename'))
    namespace = _namespace(args.get('namespace'))
    size = args.get('size')
    if type(size) is not int or not 1 <= size <= MAX_OPK:
        raise ToolError('size must be between 1 and the package limit')
    if not _LOCK.acquire(blocking=False):
        return failure(_BUSY)
    try:
        if _drop_if_expired():
            pass
        if _UPLOAD is not None:
            return failure(_BUSY)
        state = _new_state(ctx, filename, namespace, size)
        _UPLOAD = state
        return Outcome({
            'operation': 'begin',
            'upload_id': state['id'],
            'filename': filename,
            'namespace': namespace,
            'size': size,
            'offset': 0,
            'max_chunk_bytes': MAX_CHUNK,
            'expires_in_seconds': int(UPLOAD_TTL),
        })
    finally:
        _LOCK.release()


def _write(ctx, args):
    upload_id = args.get('upload_id')
    offset = args.get('offset')
    chunk = args.get('chunk')
    if not _LOCK.acquire(blocking=False):
        return failure(_BUSY)
    try:
        state = _session(ctx, upload_id)
        if type(offset) is not int or offset < 0 or offset != len(state['data']):
            raise ToolError('offset must equal the current received byte count')
        if type(chunk) is not str or not chunk or len(chunk) > MAX_CHUNK_B64:
            raise ToolError('chunk must be a bounded base64 string')
        try:
            raw = base64.b64decode(chunk.encode('ascii'), validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError):
            raise ToolError('chunk is not strict base64') from None
        if not raw or len(raw) > MAX_CHUNK:
            raise ToolError('chunk decodes outside the chunk byte limit')
        if len(state['data']) + len(raw) > state['size']:
            raise ToolError('Upload exceeds the declared package size')
        state['data'].extend(raw)
        return Outcome({
            'operation': 'write',
            'upload_id': state['id'],
            'offset': len(state['data']),
            'received': len(state['data']),
            'size': state['size'],
        })
    finally:
        _LOCK.release()


def _commit(ctx, args):
    global _UPLOAD
    upload_id = args.get('upload_id')
    digest = args.get('sha256')
    if type(digest) is not str or _SHA256.fullmatch(digest) is None:
        raise ToolError('sha256 must be a SHA-256 hex digest')
    if not _LOCK.acquire(blocking=False):
        return failure(_BUSY)
    state = None
    try:
        state = _session(ctx, upload_id)
        if len(state['data']) != state['size']:
            raise ToolError('Upload is incomplete')
        data = bytes(state['data'])
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, digest.lower()):
            raise ToolError('Package SHA-256 does not match the uploaded bytes')
        return _install(ctx, state, data, actual)
    finally:
        if _UPLOAD is state:
            _UPLOAD = None
        _LOCK.release()


def _cancel(ctx, args):
    global _UPLOAD
    if not _LOCK.acquire(blocking=False):
        return failure(_BUSY)
    try:
        state = _session(ctx, args.get('upload_id'))
        if _UPLOAD is state:
            _UPLOAD = None
        return Outcome({'operation': 'cancel', 'cancelled': True})
    finally:
        _LOCK.release()


def sweep(ctx):
    """监督 tick 接缝：清除过期、撤销或归属已变化的唯一上传。"""
    global _UPLOAD
    if not _LOCK.acquire(blocking=False):
        return False
    try:
        state = _UPLOAD
        if state is None:
            return False
        stale = state.get('revoked') or _expired(state) or not _scope_matches(ctx, state)
        if not stale:
            try:
                stale = not _permitted(ctx) or not _same_owner(_owner(ctx), state['owner'])
            except ToolError:
                stale = True
        if stale and _UPLOAD is state:
            _UPLOAD = None
            return True
        return False
    except Exception:
        return False
    finally:
        _LOCK.release()


def detach(ctx):
    """拆除接缝：撤销并清除属于该 owner 的上传；提交中则由最后复核拦截。"""
    global _UPLOAD
    state = _UPLOAD
    if state is None:
        return
    if ctx is not None and not _scope_matches(ctx, state):
        return
    state['revoked'] = True
    if _LOCK.acquire(blocking=False):
        try:
            if _UPLOAD is state:
                _UPLOAD = None
        finally:
            _LOCK.release()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _bad_constant(_name):
    raise ValueError('non-finite number')


def _manifest(raw):
    if type(raw) not in (bytes, bytearray) or len(raw) > MAX_MANIFEST:
        raise ToolError('Manifest too large')
    if bytes(raw).startswith(b'\xef\xbb\xbf'):
        raise ToolError('Invalid manifest encoding')
    try:
        text = bytes(raw).decode('utf-8', 'strict')
        check_json_budget(text)
        data = json.loads(text, object_pairs_hook=_unique_pairs,
                          parse_constant=_bad_constant)
    except (UnicodeDecodeError, ValueError, OverflowError, RecursionError):
        raise ToolError('Invalid manifest') from None
    if type(data) is not dict:
        raise ToolError('Invalid manifest')
    for key in ('name', 'info', 'author', 'version', 'message_mode'):
        if key in data and type(data[key]) is not str:
            raise ToolError('Invalid manifest field')
    for key in ('priority', 'svn', 'compatible_svn'):
        if key in data and (type(data[key]) is not int or data[key] < 0
                            or data[key].bit_length() > 64):
            raise ToolError('Invalid manifest field')
    if 'support' in data:
        support = data['support']
        if type(support) is not list or len(support) > 64:
            raise ToolError('Invalid manifest field')
        for item in support:
            if type(item) is not dict or len(item) > 64:
                raise ToolError('Invalid manifest field')
            if any(type(key) is not str or type(value) not in (str, int, bool)
                   for key, value in item.items()):
                raise ToolError('Invalid manifest field')
    namespace = data.get('namespace')
    if type(namespace) is not str or _IDENT.fullmatch(namespace) is None:
        raise ToolError('Manifest namespace must be a safe Python identifier')
    folded = namespace.casefold()
    if folded == config.NAMESPACE_DIR.casefold() or folded in FRAMEWORK_NAMESPACES:
        raise ToolError('Manifest namespace is protected')
    return data, namespace


def _existing_namespace(raw, fallback):
    """只取已有包的有效 namespace；形状异常按扫描不完整处理。"""
    if bytes(raw).startswith(b'\xef\xbb\xbf'):
        raise ToolError(_INCOMPLETE)
    try:
        text = bytes(raw).decode('utf-8', 'strict')
        check_json_budget(text)
        data = json.loads(text, object_pairs_hook=_unique_pairs,
                          parse_constant=_bad_constant)
    except (UnicodeDecodeError, ValueError, OverflowError, RecursionError):
        raise ToolError(_INCOMPLETE) from None
    if type(data) is not dict:
        raise ToolError(_INCOMPLETE)
    value = data.get('namespace', fallback)
    if type(value) is not str or not value:
        raise ToolError(_INCOMPLETE)
    return value


def _member_name(info):
    name = info.filename
    if type(name) is not str or '\x00' in name or len(name) > MAX_MEMBER_NAME:
        raise ToolError(_UNSAFE_ENTRY)
    if name.startswith('./'):
        name = name[2:]
    if not name or '\\' in name:
        raise ToolError(_UNSAFE_ENTRY)
    is_dir = name.endswith('/')
    if is_dir:
        name = name[:-1]
    if not name or name.startswith('/') or (len(name) > 1 and name[1] == ':'):
        raise ToolError(_UNSAFE_ENTRY)
    parts = name.split('/')
    for part in parts:
        if (not part or part in ('.', '..') or ':' in part
                or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF
                       for char in part)):
            raise ToolError(_UNSAFE_ENTRY)
    normalized = '/'.join(parts)
    if is_dir and not normalized:
        raise ToolError(_UNSAFE_ENTRY)
    return normalized, is_dir


def _member_type(info, is_dir):
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    if kind == stat.S_IFDIR and not is_dir:
        raise ToolError(_UNSAFE_ENTRY)
    if kind == stat.S_IFREG and is_dir:
        raise ToolError(_UNSAFE_ENTRY)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ToolError('Package contains a special file')


def _aliases(records):
    seen = {}
    for info, name, is_dir in records:
        key = name.casefold()
        if key in seen:
            raise ToolError('Duplicate or case-aliased package entry')
        seen[key] = is_dir
    ordered = sorted(seen)
    for index, key in enumerate(ordered[:-1]):
        following = ordered[index + 1]
        if following.startswith(key + '/') and not seen[key]:
            raise ToolError('Package entry conflicts with a file prefix')


def _validate_package(data, requested):
    """完整校验归档与清单；在任何临时文件创建前完成。"""
    if type(data) not in (bytes, bytearray) or not data or len(data) > MAX_OPK:
        raise ToolError('Package is too large or empty')
    data = bytes(data)
    try:
        fs._end_record(data)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_ZIP_ENTRIES:
                raise ToolError('Package entry count is out of bounds')
            records = []
            for info in infos:
                if info.extract_version >= 45:
                    raise ToolError('Unsupported package version')
                if info.flag_bits & 0x41:
                    raise ToolError('Encrypted packages are not supported')
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ToolError('Unsupported compression')
                name, is_dir = _member_name(info)
                _member_type(info, is_dir)
                records.append((info, name, is_dir))
            _aliases(records)
            files = {name for _info, name, is_dir in records if not is_dir}
            if not {'app.json', '__init__.py', 'main.py'} <= files:
                raise ToolError('Package is missing required root files')
            total = 0
            manifest_raw = None
            for info, name, is_dir in records:
                expanded = info.file_size
                if expanded > MAX_EXPANDED_FILE:
                    raise ToolError('Package expands beyond the file limit')
                total += expanded
                if total > MAX_EXPANDED_TOTAL:
                    raise ToolError('Package expands beyond the total limit')
                chunks = []
                size = 0
                manifest_size = 0
                with archive.open(info) as stream:
                    while True:
                        chunk = stream.read1(min(65536, MAX_EXPANDED_FILE + 1 - size))
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_EXPANDED_FILE:
                            raise ToolError('Package expands beyond the file limit')
                        if name == 'app.json' and not is_dir:
                            chunks.append(chunk)
                            manifest_size += len(chunk)
                            if manifest_size > MAX_MANIFEST:
                                raise ToolError('Manifest too large')
                if size != expanded:
                    raise ToolError('Package member length does not match')
                if info.compress_type == zipfile.ZIP_STORED and info.compress_size != expanded:
                    raise ToolError('Stored package member length does not match')
                if name == 'app.json' and not is_dir:
                    manifest_raw = b''.join(chunks)
            if manifest_raw is None:
                raise ToolError('Package is missing required root files')
            _data, namespace = _manifest(manifest_raw)
            if namespace != requested:
                raise ToolError('Manifest namespace does not match the declared namespace')
            return namespace
    except ToolError:
        raise
    except Exception:
        raise ToolError(_INVALID_PACKAGE) from None


def _read_app_manifest(dir_fd):
    raw, _size, truncated = fs.read_at(dir_fd, 'app.json', MAX_MANIFEST)
    if truncated or len(raw) > MAX_MANIFEST:
        raise ToolError(_INCOMPLETE)
    return raw


def _scan_existing(root, filename, namespace):
    """有界递归扫描包根；同名 namespace 或扫描不完整都拒绝，不删除任何对象。"""
    budget = {'entries': 0, 'manifests': 0, 'bytes': 0}
    _scan_dir(root, 0, filename, namespace.casefold(), budget)


def _scan_dir(dir_fd, depth, filename, namespace, budget):
    limit = MAX_SCAN_ENTRIES - budget['entries']
    if limit <= 0:
        raise ToolError(_INCOMPLETE)
    entries, truncated, blocked = fs.scan_dir(dir_fd, limit)
    if truncated or blocked:
        raise ToolError(_INCOMPLETE)
    budget['entries'] += len(entries)
    for entry in entries:
        name = entry['name']
        if name.startswith('.'):
            continue
        if entry['type'] == 'file':
            if not name.endswith('.opk'):
                continue
            if name.casefold() == filename.casefold():
                if name != filename:
                    raise ToolError('An entry differs only by case from the target filename')
                continue
            _scan_manifest('file', dir_fd, name, name[:-4], namespace, budget)
        elif entry['type'] == 'dir':
            child = None
            try:
                child, kind = fs.open_rel(dir_fd, name)
                if kind != 'dir':
                    raise ToolError(_INCOMPLETE)
                try:
                    info = fs.stat_at('app.json', dir_fd=child, follow_symlinks=False)
                except FileNotFoundError:
                    info = None
                except OSError:
                    raise ToolError(_INCOMPLETE) from None
                if info is None:
                    if depth >= MAX_SCAN_DEPTH:
                        raise ToolError(_INCOMPLETE)
                    _scan_dir(child, depth + 1, filename, namespace, budget)
                else:
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ToolError(_INCOMPLETE)
                    _scan_manifest('source', child, 'app.json', name, namespace, budget)
            finally:
                if child is not None:
                    fs.close(child)
        else:
            # 链接或其他特殊条目可能隐藏插件，不能声称扫描完整。
            raise ToolError(_INCOMPLETE)


def _scan_manifest(kind, dir_fd, relative, fallback, namespace, budget):
    if budget['manifests'] >= MAX_SCAN_MANIFESTS:
        raise ToolError(_INCOMPLETE)
    budget['manifests'] += 1
    try:
        if kind == 'file':
            package = fs.read_package(dir_fd, relative)
            budget['bytes'] += len(package)
            if budget['bytes'] > MAX_SCAN_BYTES:
                raise ToolError(_INCOMPLETE)
            raw = fs.package_manifest(package)
        else:
            raw = _read_app_manifest(dir_fd)
            budget['bytes'] += len(raw)
            if budget['bytes'] > MAX_SCAN_BYTES:
                raise ToolError(_INCOMPLETE)
    except ToolError as exc:
        if str(exc) == _INCOMPLETE:
            raise
        raise ToolError(_INCOMPLETE) from None
    found = _existing_namespace(raw, fallback)
    if found.casefold() == namespace:
        raise ToolError('A plugin package or source with the same namespace already exists')


def _target_exists(root, filename):
    try:
        info = fs.stat_at(filename, dir_fd=root, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        raise ToolError('Package target is unavailable') from None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ToolError('Existing package target is not a regular file')
    return True


def _target_namespace(root, filename, requested):
    """覆盖只允许同名 namespace；不比较旧包 SHA 或内容修订。"""
    try:
        package = fs.read_package(root, filename)
        found = _existing_namespace(fs.package_manifest(package), filename[:-4])
    except ToolError:
        raise ToolError('Existing package identity could not be read') from None
    if found.casefold() != requested.casefold():
        raise ToolError('Existing package namespace does not match the requested namespace')


def _temp_file(root):
    temp = '.cockpit-install-' + secrets.token_hex(16) + '.tmp'
    fd = None
    try:
        fd = fs.open_file(temp, _TEMP_FLAGS, 0o600, dir_fd=root, directory=False)
        return temp, fd
    except OSError:
        raise ToolError(_WRITE_FAILED) from None


def _write_temp(root, temp, fd, data):
    try:
        offset = 0
        while offset < len(data):
            written = fs.write(fd, data[offset:])
            if written <= 0:
                raise ToolError(_WRITE_FAILED)
            offset += written
        info = fs.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ToolError(_WRITE_FAILED)
        fs.fsync(fd)
    except ToolError:
        raise
    except OSError:
        raise ToolError(_WRITE_FAILED) from None


def _publish(root, filename, temp, overwrite):
    try:
        if overwrite:
            fs.replace(temp, filename, src_dir_fd=root, dst_dir_fd=root)
            return True
        try:
            fs.link(temp, filename, src_dir_fd=root, dst_dir_fd=root)
        except FileExistsError:
            raise ToolError('Another package appeared at the target path; nothing was overwritten') from None
        except OSError:
            raise ToolError(_WRITE_FAILED) from None
        try:
            fs.unlink(temp, dir_fd=root)
        except OSError:
            pass
        return False
    except ToolError:
        raise
    except OSError:
        raise ToolError(_WRITE_FAILED) from None


def _cleanup_temp(root, temp, fd):
    if temp is None:
        return
    try:
        staged = fs.stat_at(temp, dir_fd=root, follow_symlinks=False)
        owned = fs.fstat(fd)
        if (staged.st_dev, staged.st_ino) == (owned.st_dev, owned.st_ino):
            fs.unlink(temp, dir_fd=root)
    except OSError:
        pass


def _verify(root, filename, fd, digest, size):
    try:
        target, kind = fs.open_rel(root, filename)
    except ToolError:
        return False
    try:
        if kind != 'file':
            return False
        current = fs.fstat(target)
        owner = fs.fstat(fd)
        if (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
            return False
        data, total, truncated = fs.read_fd(target, MAX_OPK)
        if truncated or total != size or len(data) != size:
            return False
        return hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest)
    except (ToolError, OSError):
        return False
    finally:
        fs.close(target)


def _install(ctx, state, data, digest):
    _validate_package(data, state['namespace'])
    root = fs.open_package_root(ctx)
    temp = None
    temp_fd = None
    try:
        _scan_existing(root, state['filename'], state['namespace'])
        initial_exists = _target_exists(root, state['filename'])
        if initial_exists:
            _target_namespace(root, state['filename'], state['namespace'])
        fs.authorize_rel(root, state['filename'], write=True)
        temp, temp_fd = _temp_file(root)
        try:
            _write_temp(root, temp, temp_fd, data)
            # 最后复核：归属/代次/权限/路径与目标身份都在发布前重新检查。
            _authorize(ctx, state)
            fs.authorize_rel(root, state['filename'], write=True)
            if _target_exists(root, state['filename']) != initial_exists:
                raise ToolError('Package target changed during installation; nothing was overwritten')
            _authorize(ctx, state)
            replaced = _publish(root, state['filename'], temp, initial_exists)
            try:
                fs.fsync(root)
                durability = 'synced'
            except OSError:
                durability = 'unknown'
            if not _verify(root, state['filename'], temp_fd, digest, len(data)):
                raise ToolError(_UNVERIFIED)
            return Outcome({
                'filename': state['filename'],
                'namespace': state['namespace'],
                'size': len(data),
                'sha256': digest,
                'persisted': True,
                'durability': durability,
                'replaced': replaced,
                'loaded': False,
                'note': 'Package persisted on disk; it is not loaded until the plugin loader restarts',
            })
        finally:
            _cleanup_temp(root, temp, temp_fd) if temp_fd is not None else None
            if temp_fd is not None:
                fs.close(temp_fd)
    except ToolError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise ToolError(_WRITE_FAILED) from None
    finally:
        fs.close(root)


def _tool_ready():
    return fs.updates_supported()


_SUPPORTED = _tool_ready()

TOOLS = (
    ToolSpec(
        'cockpit_plugin_install',
        'Upload and atomically install one OPK into the host plugin package root. '
        'Use begin, sequential write chunks, then commit with the complete-package SHA-256. '
        'One bounded in-memory upload at a time (8 MiB, 512 KiB chunks, 5 minute fixed expiry). '
        'The archive, manifest namespace, entry names and paths, required root files and duplicate '
        'namespace/source are validated without extracting, importing or executing anything. '
        'Overwriting an existing OPK needs no old-file SHA-256; unrelated packages and source '
        'directories are never removed. Cockpit and OlivOS framework packages are protected. '
        'Requires Full write plus the plugin install switch. The loader must restart before the '
        'package is used.',
        object_schema({
            'operation': {'type': 'string', 'enum': ['begin', 'write', 'commit', 'cancel']},
            'filename': {'type': 'string', 'minLength': 1, 'maxLength': 255},
            'namespace': {'type': 'string', 'minLength': 1, 'maxLength': 64},
            'size': {'type': 'integer', 'minimum': 1, 'maximum': MAX_OPK},
            'upload_id': {'type': 'string', 'minLength': 32, 'maxLength': 64},
            'offset': {'type': 'integer', 'minimum': 0, 'maximum': MAX_OPK},
            'chunk': {'type': 'string', 'minLength': 1, 'maxLength': MAX_CHUNK_B64},
            'sha256': {'type': 'string', 'minLength': 64, 'maxLength': 64},
        }, ('operation',)),
        cockpit_plugin_install,
        read_only=False,
        required_permission=PERMISSION,
    ),
)
