"""安全文件门面：路径逐组件打开，保守拒绝符号链接及 Windows reparse point。"""

import errno
import io
import os
import stat
import struct
import unicodedata
import zipfile

from .contracts import (MAX_ENTRIES, MAX_FILE, MAX_MANIFEST, MAX_OPK,
                        MAX_ZIP_DIRECTORY, MAX_ZIP_ENTRIES, ToolError)

_DIR_FLAGS = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
_FILE_FLAGS = (os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
               | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOCTTY', 0))

_EOCD_SIG = b'PK\x05\x06'
_ZIP64_EOCD = b'PK\x06\x06'
_ZIP64_LOCATOR = b'PK\x06\x07'
_CENTRAL_SIG = b'PK\x01\x02'
_EOCD_SEARCH = 65535 + 22


_WINDOWS = os.name == 'nt'
if _WINDOWS:
    # OPK 解包目录会被宿主删除；必须在模块初始化时完成 native backend 导入。
    from . import _winfs
else:
    _winfs = None


def supported():
    if _WINDOWS:
        return _winfs.supported()
    return (os.name == 'posix'
            and hasattr(os, 'O_NOFOLLOW')
            and hasattr(os, 'O_DIRECTORY')
            and hasattr(os, 'O_NONBLOCK')
            and os.scandir in os.supports_fd
            and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks)


def updates_supported():
    if _WINDOWS:
        return supported()
    return (supported() and os.rename in os.supports_dir_fd
            and os.link in os.supports_dir_fd and os.unlink in os.supports_dir_fd
            and all(callable(getattr(os, name, None))
                    for name in ('replace', 'fchmod', 'fchown', 'fsync')))


def _raw(fd):
    return fd.handle if isinstance(fd, _FD) else fd


def _component(name):
    if (type(name) is not str or not name or name in ('.', '..')
            or '/' in name or '\\' in name or '\x00' in name):
        raise ToolError('Invalid path component')
    if _WINDOWS:
        stem = name.split('.', 1)[0].rstrip(' ').upper()
        if (name[-1] in '. ' or any(ord(char) < 32 or char in ':<>"|?*' for char in name)
                or stem in ('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$')
                or (len(stem) == 4 and stem[:3] in ('COM', 'LPT')
                    and stem[3] in '123456789¹²³')):
            raise ToolError('Invalid Windows path component')
    return name


def open_file(name, flags, mode=0o600, *, dir_fd=None, directory=None):
    """低层安全打开；相对调用只收单组件，绝对路径仍逐组件验证。"""
    if flags & getattr(os, 'O_TRUNC', 0):
        raise OSError(errno.EINVAL, 'Truncating opens are not supported')
    if dir_fd is None:
        path = _absolute(name)
        if _WINDOWS:
            return _winfs.open_file(path, flags, mode, directory=directory)
        parent = _walk(os.path.dirname(path), directory=True)
        try:
            leaf = os.path.basename(path)
            if not leaf:
                if directory is False or flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR):
                    raise OSError(errno.EISDIR, 'A file name is required')
                return dup(parent)
            return open_file(leaf, flags, mode, dir_fd=parent, directory=directory)
        finally:
            close(parent)
    _component(name)
    if _WINDOWS:
        return _winfs.open_file(name, flags, mode, dir_fd=_raw(dir_fd), directory=directory)
    flags |= os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0) | os.O_NONBLOCK
    if directory is True:
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, mode, dir_fd=_raw(dir_fd))
    try:
        info = fstat(fd)
        if ((directory is True and not stat.S_ISDIR(info.st_mode))
                or (directory is False and not stat.S_ISREG(info.st_mode))
                or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
            raise OSError(errno.EINVAL, 'Unsupported file type')
        return fd
    except BaseException:
        close(fd)
        raise


def dup(fd):
    return _winfs.dup(_raw(fd)) if _WINDOWS else os.dup(_raw(fd))


def close(fd):
    return _winfs.close(_raw(fd)) if _WINDOWS else os.close(_raw(fd))


def fstat(fd):
    return _winfs.fstat(_raw(fd)) if _WINDOWS else os.fstat(_raw(fd))


def read(fd, size):
    return _winfs.read(_raw(fd), size) if _WINDOWS else os.read(_raw(fd), size)


def write(fd, data):
    return _winfs.write(_raw(fd), data) if _WINDOWS else os.write(_raw(fd), data)


def lseek(fd, offset, whence):
    return (_winfs.lseek(_raw(fd), offset, whence) if _WINDOWS
            else os.lseek(_raw(fd), offset, whence))


def pread(fd, size, offset):
    if _WINDOWS:
        return _winfs.pread(_raw(fd), size, offset)
    return os.pread(_raw(fd), size, offset)


def scandir(fd):
    return _winfs.scandir(_raw(fd)) if _WINDOWS else os.scandir(_raw(fd))


def stat_at(name, *, dir_fd, follow_symlinks=False):
    _component(name)
    if follow_symlinks:
        raise OSError(errno.EINVAL, 'Following links is not supported')
    if _WINDOWS:
        return _winfs.stat_at(name, dir_fd=_raw(dir_fd), follow_symlinks=False)
    return os.stat(name, dir_fd=_raw(dir_fd), follow_symlinks=False)


def mkdir(name, mode=0o700, *, dir_fd):
    _component(name)
    if _WINDOWS:
        return _winfs.mkdir(name, mode, dir_fd=_raw(dir_fd))
    return os.mkdir(name, mode, dir_fd=_raw(dir_fd))


def unlink(name, *, dir_fd):
    _component(name)
    if _WINDOWS:
        return _winfs.unlink(name, dir_fd=_raw(dir_fd))
    return os.unlink(name, dir_fd=_raw(dir_fd))


def link(src, dst, *, src_dir_fd, dst_dir_fd):
    _component(src)
    _component(dst)
    if _WINDOWS:
        return _winfs.link(src, dst, src_dir_fd=_raw(src_dir_fd), dst_dir_fd=_raw(dst_dir_fd))
    return os.link(src, dst, src_dir_fd=_raw(src_dir_fd), dst_dir_fd=_raw(dst_dir_fd))


def replace(src, dst, *, src_dir_fd, dst_dir_fd):
    _component(src)
    _component(dst)
    if _WINDOWS:
        return _winfs.replace(src, dst, src_dir_fd=_raw(src_dir_fd), dst_dir_fd=_raw(dst_dir_fd))
    return os.replace(src, dst, src_dir_fd=_raw(src_dir_fd), dst_dir_fd=_raw(dst_dir_fd))


def fsync(fd):
    return _winfs.fsync(_raw(fd)) if _WINDOWS else os.fsync(_raw(fd))


def preserve_permissions(staged_fd, original_info):
    if _WINDOWS:
        return _winfs.preserve_permissions(_raw(staged_fd), original_info)
    current = fstat(staged_fd)
    if (current.st_uid, current.st_gid) != (original_info.st_uid, original_info.st_gid):
        os.fchown(_raw(staged_fd), original_info.st_uid, original_info.st_gid)
    os.fchmod(_raw(staged_fd), stat.S_IMODE(original_info.st_mode))


def permission_identity(info):
    if _WINDOWS:
        return (stat.S_IFMT(info.st_mode), getattr(info, '_win_attributes', 0) & 1,
                getattr(info, '_win_security', None))
    return info.st_mode, info.st_uid, info.st_gid


def non_executable(info):
    return _WINDOWS or not info.st_mode & (0o111 | stat.S_ISUID | stat.S_ISGID)


def require():
    """没有安全原语时明确失败，而不是退化成仅字符串检查。"""
    if not supported():
        raise ToolError('Secure file access is not supported on this platform')


class _FD(object if _WINDOWS else int):
    """句柄自携策略与身份；POSIX 保留整数兼容，不建立全局 fd 表。"""

    def __new__(cls, fd, context, path, roots=None):
        value = object.__new__(cls) if _WINDOWS else int.__new__(cls, fd)
        value.handle = fd
        value.context = context
        value.path = path
        # 受信包根可位于 cwd 之外；后续相对打开沿用同一授权根，不接受请求扩根。
        value.roots = None if roots is None else tuple(roots)
        info = fstat(fd)
        value.identity = (info.st_dev, info.st_ino)
        return value


def _absolute(path):
    if (type(path) is not str or not os.path.isabs(path) or '\x00' in path
            or '..' in path.replace('\\', '/').split('/')):
        raise ToolError('File root is unavailable')
    if _WINDOWS and not os.path.splitdrive(path)[0]:
        raise ToolError('File root is unavailable')
    return os.path.normpath(path)


def _within(path, root):
    try:
        return os.path.normcase(os.path.commonpath((path, root))) == os.path.normcase(root)
    except ValueError:
        return False


def _blocked_paths(context):
    from . import config, host

    data_root = _absolute(getattr(context, 'data_root', None))
    blocked = [os.path.join(data_root, config.NAMESPACE_DIR)]
    current = host.snapshot(context)
    if current is host.MISSING or (current is not None and getattr(current, 'valid', True) is not True):
        raise ToolError('Path policy is unavailable')
    entries = host.setting(context, ('denied_paths',), ())
    if type(entries) not in (tuple, list) or len(entries) > config.MAX_DENIED_PATHS:
        raise ToolError('Path policy is unavailable')
    for entry in entries:
        if (type(entry) is not str or not entry or '\x00' in entry
                or len(entry) > config.MAX_PATH_CHARS):
            raise ToolError('Path policy is unavailable')
        if os.path.isabs(entry):
            blocked.append(os.path.normpath(entry))
        else:
            root = _absolute(getattr(context, 'root', None))
            # 兼容旧配置的数据根基准只会额外拒绝，不授权。
            blocked.extend(os.path.normpath(os.path.join(base, entry)) for base in (root, data_root))
    return tuple(dict.fromkeys(blocked))


def _denial_key(value):
    return unicodedata.normalize('NFC', value).casefold()


def _path_parts(path):
    drive, tail = os.path.splitdrive(path)
    return drive + os.sep, [part for part in tail.split(os.sep) if part not in ('', '.')]


def _blocked_targets(context):
    if context is None:
        return ()
    targets = []
    for path in _blocked_paths(context):
        path = _absolute(path)
        fd = None
        identities = []
        try:
            fd = _walk(path, identities=identities)
            targets.append((identities[-1], ()))
        except FileNotFoundError:
            if identities:
                # 未存在叶子也绑定最近现存祖先，避免其短名/Unicode 别名绕过发布前检查。
                remaining = _path_parts(path)[1][len(identities) - 1:]
                targets.append((identities[-1], tuple(_denial_key(part) for part in remaining)))
        except OSError:
            raise ToolError('Path policy identity is unavailable') from None
        finally:
            if fd is not None:
                close(fd)
    return targets


def _unresolved_short_alias(name):
    if not _WINDOWS:
        return False
    stem, separator, extension = name.partition('.')
    prefix, tilde, number = stem.rpartition('~')
    return (1 <= len(stem) <= 8 and bool(prefix) and bool(tilde)
            and number.isascii() and number.isdecimal()
            and (not separator or (1 <= len(extension) <= 3 and '.' not in extension)))


def _identity_policy(context, identities, path, targets=None, *, write=False):
    if context is None:
        return
    if targets is None:
        targets = _blocked_targets(context)
    names = tuple(_denial_key(part) for part in _path_parts(path)[1])
    for blocked, remaining in targets:
        for depth, identity in enumerate(identities):
            if identity != blocked:
                continue
            if names[depth:depth + len(remaining)] == remaining:
                raise ToolError('Path is not accessible')
            # Windows 自动分配的短名不可预测；未解析短名规则保守阻止同父的叶子发布。
            if (write and len(remaining) == 1 and len(names) == depth + 1
                    and _unresolved_short_alias(remaining[0])):
                raise ToolError('Path is not accessible')


def _path_policy(context, path, write=False, roots=None):
    """先判路径、后做 I/O；拒绝项只收紧可信根，不能扩根。"""
    path = _absolute(path)
    if context is None:  # 仅配置管理器等受信内部入口和纯原语测试使用。
        if write:
            raise ToolError('File writes require a configuration snapshot')
        return path
    from . import host

    trusted = []
    if roots is not None:
        # 仅由 package_root() 从宿主插件 API 解析；不是 MCP 参数。
        trusted.extend(_absolute(value) for value in roots)
    else:
        for value in (getattr(context, 'root', None), getattr(context, 'data_root', None)):
            if value:
                trusted.append(_absolute(value))
    if not trusted or not any(_within(path, root) for root in trusted):
        raise ToolError('Path is outside the trusted OlivOS roots')
    # 字符串拒绝保留为 I/O 前的快速路径；实际对象身份另行复核。
    if any(_within(_denial_key(path), _denial_key(item)) for item in _blocked_paths(context)):
        raise ToolError('Path is not accessible')
    if write and not host.allowed(context, 'real_account_write'):
        raise ToolError('Writing plugin configuration is not permitted')
    return path


def _kind(info, context=None):
    if stat.S_ISREG(info.st_mode):
        if context is not None and info.st_nlink != 1:
            raise ToolError('Hard-linked files are not accessible')
        return 'file'
    if stat.S_ISDIR(info.st_mode):
        return 'dir'
    raise ToolError('Unsupported file type')


def _walk(path, directory=False, identities=None):
    """从原生绝对根逐组件打开，并收集真实祖先身份以拦截大小写/短名别名。"""
    anchor, names = _path_parts(path)
    fd = None
    try:
        fd = (_winfs.open_root(anchor) if _WINDOWS
              else os.open(anchor, _DIR_FLAGS | os.O_NOFOLLOW))
        if identities is not None:
            info = fstat(fd)
            identities.append((info.st_dev, info.st_ino))
        for index, name in enumerate(names):
            is_dir = directory or index < len(names) - 1
            nxt = open_file(name, _DIR_FLAGS if is_dir else _FILE_FLAGS,
                            dir_fd=fd, directory=True if is_dir else None)
            close(fd)
            fd = nxt
            if identities is not None:
                info = fstat(fd)
                identities.append((info.st_dev, info.st_ino))
        return fd
    except BaseException:
        if fd is not None:
            close(fd)
        raise


def authorize_path(context, absolute_path, write=False):
    """已知 SDK 路径的即时预检；成功返回绝对路径，不替 SDK 提供竞态保证。"""
    require()
    if context is None:
        raise ToolError('Path policy is unavailable')
    path = _path_policy(context, absolute_path, write)
    fd = None
    try:
        identities = []
        fd = _walk(path, identities=identities)
        _kind(fstat(fd), context)
        _identity_policy(context, identities, path, write=write)
        return path
    except OSError:
        raise ToolError('Path is unavailable') from None
    finally:
        if fd is not None:
            close(fd)


def _check_fd(fd, identities=None):
    """读/枚举前后复核当前策略与已开对象及祖先身份，拒绝路径替换和别名。"""
    require()
    try:
        info = fstat(fd)
        context = getattr(fd, 'context', None)
        _kind(info, context)
        if not isinstance(fd, _FD):
            return info
        roots = getattr(fd, 'roots', None)
        path = _path_policy(context, fd.path, roots=roots)
        if fd.identity != (info.st_dev, info.st_ino):
            raise ToolError('Path identity changed')
        identities = [] if identities is None else identities
        check = _walk(path, identities=identities)
        try:
            current = fstat(check)
            _kind(current, context)
            if (current.st_dev, current.st_ino) != fd.identity:
                raise ToolError('Path identity changed')
            _identity_policy(context, identities, path)
        finally:
            close(check)
        return info
    except OSError:
        raise ToolError('Path is unavailable') from None


def open_root(root, context=None):
    """按原生路径逐组件安全打开可信根；context 随派生句柄传递。"""
    return _open_root(root, context, None)


def package_root(context):
    """从宿主插件 API 解析包根；绝对路径直接使用，相对路径按捕获的 cwd 解析。

    缺失或非法一律安全失败，不按部署形态猜测目录。
    """
    if context is None:
        raise ToolError('Plugin package root is unavailable')
    try:
        olivos = getattr(context, 'olivos', None)
        plugin_api = getattr(olivos, 'pluginAPI', None) if olivos is not None else None
        value = getattr(plugin_api, 'plugin_path', None) if plugin_api is not None else None
    except BaseException:
        raise ToolError('Plugin package root is unavailable') from None
    if type(value) is not str or not value or '\x00' in value:
        raise ToolError('Plugin package root is unavailable')
    if os.path.isabs(value):
        root = os.path.normpath(value)
    else:
        base = getattr(context, 'root', None)
        if type(base) is not str or not os.path.isabs(base) or '\x00' in base:
            raise ToolError('Plugin package root is unavailable')
        root = os.path.normpath(os.path.join(base, value))
    if not os.path.isabs(root) or '\x00' in root:
        raise ToolError('Plugin package root is unavailable')
    return root


def open_package_root(context):
    """打开宿主声明的包根；根来源于宿主上下文，后续相对路径不扩根。"""
    root = package_root(context)
    return _open_root(root, context, (root,))


def _open_root(root, context, roots):
    require()
    root = _path_policy(context, root, roots=roots)
    fd = None
    try:
        fd = _walk(root, directory=True)
        result = _FD(fd, context, root, roots)
        _check_fd(result)
        fd = None
        return result
    except OSError:
        raise ToolError('File root is unavailable') from None
    finally:
        if fd is not None:
            close(fd)


def _relative_names(rel):
    if type(rel) is not str or '\x00' in rel or '\\' in rel:
        raise ToolError('Invalid path')
    if rel.startswith('/') or (len(rel) > 1 and rel[1] == ':'):
        raise ToolError('Absolute paths are not allowed')
    parts = rel.split('/')
    if '..' in parts:
        raise ToolError('Parent components are not allowed')
    return [_component(part) for part in parts if part not in ('', '.')]


def authorize_rel(dir_fd, rel, write=False):
    """不要求目标存在：只校验相对路径与当前策略，返回绝对路径供调用方发布。"""
    require()
    names = _relative_names(rel)
    context = getattr(dir_fd, 'context', None)
    path = None
    if isinstance(dir_fd, _FD):
        path = _path_policy(context, os.path.join(dir_fd.path, *names), write=write,
                            roots=getattr(dir_fd, 'roots', None))
    _check_fd(dir_fd)
    if path is not None:
        target = None
        identities = []
        try:
            target = _walk(path, identities=identities)
        except FileNotFoundError:
            pass
        except OSError:
            raise ToolError('Path is unavailable') from None
        finally:
            if target is not None:
                close(target)
        _identity_policy(context, identities, path, write=write)
    return path


def open_rel(dir_fd, rel):
    """相对 dir_fd 打开；返回 (fd, 'file'|'dir')，保留策略及绝对路径身份。"""
    require()
    names = _relative_names(rel)
    context = getattr(dir_fd, 'context', None)
    roots = getattr(dir_fd, 'roots', None)
    path = None
    if isinstance(dir_fd, _FD):
        path = _path_policy(context, os.path.join(dir_fd.path, *names), roots=roots)
    _check_fd(dir_fd)
    fd = None
    try:
        fd = dup(dir_fd)
        for name in names[:-1]:
            nxt = open_file(name, _DIR_FLAGS, dir_fd=fd, directory=True)
            close(fd)
            fd = nxt
        if names:
            nxt = open_file(names[-1], _FILE_FLAGS, dir_fd=fd)
            close(fd)
            fd = nxt
        info = fstat(fd)
        kind = _kind(info, context)
        result = _FD(fd, context, path, roots) if path is not None else fd
        _check_fd(result)
        opened = result, kind
        fd = None
        return opened
    except OSError:
        raise ToolError('Path is unavailable') from None
    finally:
        if fd is not None:
            close(fd)


def _list(dir_fd, limit, audit):
    """最多读 limit+1 条目录项；audit 模式额外报告被策略隐藏的条目数。"""
    identities = []
    _check_fd(dir_fd, identities)
    entries = []
    seen = 0
    blocked = 0
    truncated = False
    context = getattr(dir_fd, 'context', None)
    roots = getattr(dir_fd, 'roots', None)
    forbidden = _blocked_targets(context)
    try:
        with scandir(dir_fd) as iterator:
            for entry in iterator:
                seen += 1  # 不可 stat 的条目也计入上限，避免无界迭代
                if seen > limit:
                    truncated = True
                    break
                try:
                    _component(entry.name)
                    path = None
                    if isinstance(dir_fd, _FD):
                        path = _path_policy(context, os.path.join(dir_fd.path, entry.name), roots=roots)
                    info = entry.stat(follow_symlinks=False)
                    _identity_policy(context, identities + [(info.st_dev, info.st_ino)], path, forbidden)
                    if context is not None and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                        if audit:
                            blocked += 1
                        continue
                except (ToolError, OSError):
                    if audit:
                        blocked += 1
                    continue
                if stat.S_ISREG(info.st_mode):
                    kind = 'file'
                elif stat.S_ISDIR(info.st_mode):
                    kind = 'dir'
                elif stat.S_ISLNK(info.st_mode):
                    kind = 'link'
                else:
                    kind = 'other'
                entries.append({'name': entry.name, 'type': kind,
                                'size': info.st_size, 'mtime': info.st_mtime})
    except OSError:
        raise ToolError('Directory is unavailable') from None
    _check_fd(dir_fd)
    return entries, truncated, blocked


def list_dir(dir_fd, limit=MAX_ENTRIES):
    """最多读 limit+1 条目录项，不排序、不 collect 全部。返回 (entries, truncated)。"""
    entries, truncated, _ = _list(dir_fd, limit, False)
    return entries, truncated


def scan_dir(dir_fd, limit=MAX_ENTRIES):
    """审计式枚举：返回 (entries, truncated, blocked)；不暴露被隐藏条目的名称。

    安装前的同名 namespace 扫描必须知道目录是否完整，因此被拒绝或无法 stat
    的条目按 blocked 计数，由调用方 fail-closed。
    """
    return _list(dir_fd, limit, True)


def read_fd(fd, limit=MAX_FILE):
    """从当前偏移有界读取；返回 (data, size, truncated)。"""
    if not stat.S_ISREG(_check_fd(fd).st_mode):
        raise ToolError('Not a regular file')
    chunks = []
    total = 0
    try:
        while total < limit:
            chunk = read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b''.join(chunks)
        truncated = read(fd, 1) != b''
    except OSError:
        raise ToolError('File is unavailable') from None
    _check_fd(fd)
    return data, total, truncated


def _revision(info):
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_range(dir_fd, rel, offset, limit=MAX_FILE):
    """按字节偏移/长度安全读取，返回数据、总大小、修订和后续标记；修订变化拒绝，非快照。"""
    if (type(offset) is not int or offset < 0 or type(limit) is not int
            or not 1 <= limit <= MAX_FILE):
        raise ToolError('Invalid file range')
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        if not _WINDOWS and not hasattr(os, 'pread'):
            raise ToolError('Positioned file reads are not supported')
        try:
            before = fstat(fd)
            if offset > before.st_size:
                raise ToolError('File range is out of bounds')
            revision = _revision(before)
            chunks = []
            total = 0
            while total < limit:
                chunk = pread(fd, min(65536, limit - total), offset + total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = fstat(fd)
        except OSError:
            raise ToolError('File is unavailable') from None
        data = b''.join(chunks)
        current = _check_fd(fd)
        expected = min(limit, before.st_size - offset)
        if (total != expected or revision != _revision(after)
                or revision != _revision(current)):
            raise ToolError('File changed during read')
        return data, before.st_size, revision, offset + total < before.st_size
    finally:
        close(fd)


def read_at(dir_fd, rel, limit=MAX_FILE):
    """安全打开普通文件并读取；返回 (data, st_size, truncated)。"""
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        try:
            size = fstat(fd).st_size
        except OSError:
            raise ToolError('File is unavailable')
        data, _, truncated = read_fd(fd, limit)
        return data, size, truncated
    finally:
        close(fd)


def read_tail(dir_fd, rel, limit=MAX_FILE):
    """从尾部有界读取；返回 (data, st_size, truncated)，truncated 表示丢弃了前半部分。"""
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        try:
            size = fstat(fd).st_size
        except OSError:
            raise ToolError('File is unavailable')
        offset = max(0, size - limit)
        lseek(fd, offset, os.SEEK_SET)
        data, _, more = read_fd(fd, limit)
        return data, size, offset > 0 or more
    finally:
        close(fd)


def read_package(dir_fd, rel):
    """把整个 OPK 有界读入内存（≤ MAX_OPK），再做 zip 结构校验。"""
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        try:
            size = fstat(fd).st_size
        except OSError:
            raise ToolError('Package is unavailable')
        if size > MAX_OPK:
            raise ToolError('Package too large')
        data, _, truncated = read_fd(fd, MAX_OPK)
        if truncated:
            raise ToolError('Package too large')
        return data
    finally:
        close(fd)


def _central_count(data, start, size):
    """按 stdlib 的物理起点有界数中央目录条目；只走头部长度，不构造 ZipInfo。"""
    end = start + size
    if start < 0 or end > len(data):
        raise ToolError('Invalid package')
    count = 0
    pos = start
    while pos < end:
        if pos + 46 > end or data[pos:pos + 4] != _CENTRAL_SIG:
            raise ToolError('Invalid package')
        name, extra, comment = struct.unpack('<HHH', data[pos + 28:pos + 34])
        count += 1
        if count > MAX_ZIP_ENTRIES:
            raise ToolError('Package too large')
        pos += 46 + name + extra + comment
    if pos != end:
        raise ToolError('Invalid package')
    return count


def _end_record(data):
    """校验单一磁盘、非 ZIP64、中央目录有界的 EOCD，并与 stdlib 选同一条记录。"""
    if len(data) > MAX_OPK:
        raise ToolError('Package too large')
    tail = data[-_EOCD_SEARCH:]
    # 不回退到更早的 EOCD，避免与 zipfile 对注释内末个签名的选择分叉。
    pos = tail.rfind(_EOCD_SIG)
    if pos < 0 or pos + 22 > len(tail):
        raise ToolError('Invalid package')
    comment = int.from_bytes(tail[pos + 20:pos + 22], 'little')
    if pos + 22 + comment != len(tail):
        raise ToolError('Invalid package')
    disk, cd_disk, n_disk, n_total, cd_size, cd_offset = struct.unpack(
        '<HHHHII', tail[pos + 4:pos + 20])
    if disk or cd_disk or n_disk != n_total:
        raise ToolError('Invalid package')
    if n_total > MAX_ZIP_ENTRIES or cd_size > MAX_ZIP_DIRECTORY:
        raise ToolError('Package too large')
    eocd_abs = len(data) - len(tail) + pos
    if cd_offset + cd_size > eocd_abs:
        raise ToolError('Invalid package')
    # locator 可覆盖 EOCD 的限额字段，必须在 zipfile 构造前拒绝。
    if eocd_abs >= 20 and data[eocd_abs - 20:eocd_abs - 16] == _ZIP64_LOCATOR:
        raise ToolError('Unsupported package')
    # 固定 ZIP64 结束记录为 56 字节，locator 为 20 字节。
    if data.rfind(_ZIP64_EOCD, max(0, eocd_abs - 76), eocd_abs) >= 0:
        raise ToolError('Unsupported package')
    # zipfile 会按前缀偏移修正目录位置；预检须遍历同一段物理字节。
    if _central_count(data, eocd_abs - cd_size, cd_size) != n_total:
        raise ToolError('Invalid package')


def package_manifest(data, max_size=MAX_MANIFEST):
    """返回 app.json 原始字节；只读中央目录与单个 app.json，不 extractall。"""
    _end_record(data)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise ToolError('Package too large')
            target = None
            for info in infos:
                if info.extract_version >= 45:  # ZIP64 的最低提取版本为 4.5。
                    raise ToolError('Unsupported package version')
                if info.flag_bits & 0x1:
                    raise ToolError('Encrypted packages are not supported')
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ToolError('Unsupported compression')
                name = info.filename
                if '\x00' in name or name.startswith('/') or '\\' in name:
                    raise ToolError('Invalid package entry')
                if '..' in name.split('/'):
                    raise ToolError('Invalid package entry')
                if name == 'app.json':
                    if target is not None:
                        raise ToolError('Duplicate manifest')
                    target = info
            if target is None or target.is_dir():
                raise ToolError('Package has no manifest')
            if target.file_size > max_size:
                raise ToolError('Manifest too large')
            # read1 每次至多解压一段，不依赖声明大小；超过上限立即停止。
            with archive.open(target) as fp:
                chunks = []
                total = 0
                while total <= max_size:
                    chunk = fp.read1(min(16384, max_size + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
            if total > max_size:
                raise ToolError('Manifest too large')
            return b''.join(chunks)
    except ToolError:
        raise
    except Exception:
        raise ToolError('Invalid package')
