"""POSIX 只读文件原语：路径校验与打开全部经由已持有的目录 fd，不用 realpath 代替。

v0.1 保守拒绝一切符号链接（含根祖先）。
"""

import io
import os
import stat
import struct
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


def supported():
    return (os.name == 'posix'
            and hasattr(os, 'O_NOFOLLOW')
            and hasattr(os, 'O_DIRECTORY')
            and hasattr(os, 'O_NONBLOCK')
            and os.scandir in os.supports_fd
            and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
            and os.stat in os.supports_follow_symlinks)


def require():
    """没有安全原语时明确失败，而不是退化成仅字符串检查。"""
    if not supported():
        raise ToolError('Secure file access is not supported on this platform')


class _FD(int):
    """fd 自携策略和路径身份；os.close 原样可用，不建立全局 fd 表。"""

    def __new__(cls, fd, context, path):
        value = super().__new__(cls, fd)
        value.context = context
        value.path = path
        info = os.fstat(fd)
        value.identity = (info.st_dev, info.st_ino)
        return value


def _absolute(path):
    if (type(path) is not str or not path.startswith('/') or '\x00' in path
            or '..' in path.split('/')):
        raise ToolError('File root is unavailable')
    return os.path.normpath(path)


def _within(path, root):
    return os.path.commonpath((path, root)) == root


def _path_policy(context, path, write=False):
    """先判路径、后做 I/O；拒绝项只收紧可信根，不能扩根。"""
    path = _absolute(path)
    if context is None:  # 仅配置管理器等受信内部入口和纯原语测试使用。
        if write:
            raise ToolError('File writes require a configuration snapshot')
        return path
    from . import config, host

    roots = []
    for value in (getattr(context, 'root', None), getattr(context, 'data_root', None)):
        if value:
            roots.append(_absolute(value))
    if not roots or not any(_within(path, root) for root in roots):
        raise ToolError('Path is outside the trusted OlivOS roots')
    data_root = getattr(context, 'data_root', None)
    if not data_root or config.is_protected(data_root, path):
        raise ToolError('Path is not accessible')
    # 保留既有 namespace 禁令；包目录里的同名插件元数据不受影响。
    own = os.path.join(_absolute(data_root), config.NAMESPACE_DIR)
    if _within(path.casefold(), own.casefold()):
        raise ToolError('Path is not accessible')
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
            denied = (os.path.normpath(entry),)
        else:
            root = _absolute(getattr(context, 'root', None))
            # 旧配置曾以插件数据根为基准；兼容只额外拒绝，绝不授权。
            denied = (os.path.normpath(os.path.join(root, entry)),
                      os.path.normpath(os.path.join(data_root, entry)))
        if any(_within(path.casefold(), item.casefold()) for item in denied):
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


def _walk(path, directory=False):
    """仅在路径策略通过后调用；从 / 逐组件打开，任何祖先均不可是链接。"""
    names = [part for part in path.split('/') if part not in ('', '.')]
    fd = None
    try:
        fd = os.open('/', _DIR_FLAGS | os.O_NOFOLLOW)
        for index, name in enumerate(names):
            flags = _DIR_FLAGS | os.O_NOFOLLOW if directory or index < len(names) - 1 else _FILE_FLAGS
            nxt = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise


def authorize_path(context, absolute_path, write=False):
    """已知 SDK 路径的即时预检；成功返回绝对路径，不替 SDK 提供竞态保证。"""
    require()
    if context is None:
        raise ToolError('Path policy is unavailable')
    path = _path_policy(context, absolute_path, write)
    fd = None
    try:
        fd = _walk(path)
        _kind(os.fstat(fd), context)
        return path
    except OSError:
        raise ToolError('Path is unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)


def _check_fd(fd):
    """读/枚举前后复核当前策略与 fd 路径身份，拒绝祖先或叶子的替换。"""
    require()
    try:
        info = os.fstat(fd)
        context = getattr(fd, 'context', None)
        _kind(info, context)
        if not isinstance(fd, _FD):
            return info
        path = _path_policy(context, fd.path)
        if fd.identity != (info.st_dev, info.st_ino):
            raise ToolError('Path identity changed')
        check = _walk(path)
        try:
            current = os.fstat(check)
            _kind(current, context)
            if (current.st_dev, current.st_ino) != fd.identity:
                raise ToolError('Path identity changed')
        finally:
            os.close(check)
        return info
    except OSError:
        raise ToolError('Path is unavailable') from None


def open_root(root, context=None):
    """逐组件 O_NOFOLLOW 打开可信根；context 随派生 fd 传递。"""
    require()
    root = _path_policy(context, root)
    fd = None
    try:
        fd = _walk(root, directory=True)
        result = _FD(fd, context, root)
        _check_fd(result)
        fd = None
        return result
    except OSError:
        raise ToolError('File root is unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)


def open_rel(dir_fd, rel):
    """相对 dir_fd 打开；返回 (fd, 'file'|'dir')，保留策略及绝对路径身份。"""
    require()
    if type(rel) is not str or '\x00' in rel or '\\' in rel:
        raise ToolError('Invalid path')
    if rel.startswith('/') or (len(rel) > 1 and rel[1] == ':'):
        raise ToolError('Absolute paths are not allowed')
    parts = rel.split('/')
    if '..' in parts:
        raise ToolError('Parent components are not allowed')
    names = [part for part in parts if part not in ('', '.')]
    context = getattr(dir_fd, 'context', None)
    path = None
    if isinstance(dir_fd, _FD):
        path = _path_policy(context, os.path.join(dir_fd.path, *names))
    _check_fd(dir_fd)
    fd = None
    try:
        fd = os.dup(dir_fd)
        for name in names[:-1]:
            nxt = os.open(name, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        if names:
            nxt = os.open(names[-1], _FILE_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        kind = _kind(info, context)
        result = _FD(fd, context, path) if path is not None else fd
        _check_fd(result)
        opened = result, kind
        fd = None
        return opened
    except OSError:
        raise ToolError('Path is unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)


def list_dir(dir_fd, limit=MAX_ENTRIES):
    """最多读 limit+1 条目录项，不排序、不 collect 全部。返回 (entries, truncated)。"""
    _check_fd(dir_fd)
    entries = []
    seen = 0
    truncated = False
    context = getattr(dir_fd, 'context', None)
    try:
        with os.scandir(dir_fd) as iterator:
            for entry in iterator:
                seen += 1  # 不可 stat 的条目也计入上限，避免无界迭代
                if seen > limit:
                    truncated = True
                    break
                try:
                    if isinstance(dir_fd, _FD):
                        _path_policy(context, os.path.join(dir_fd.path, entry.name))
                    info = entry.stat(follow_symlinks=False)
                    if context is not None and stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                        continue
                except (ToolError, OSError):
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
    return entries, truncated


def read_fd(fd, limit=MAX_FILE):
    """从当前偏移有界读取；返回 (data, size, truncated)。"""
    if not stat.S_ISREG(_check_fd(fd).st_mode):
        raise ToolError('Not a regular file')
    chunks = []
    total = 0
    try:
        while total < limit:
            chunk = os.read(fd, min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b''.join(chunks)
        truncated = os.read(fd, 1) != b''
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
        if not hasattr(os, 'pread'):
            raise ToolError('Positioned file reads are not supported')
        try:
            before = os.fstat(fd)
            if offset > before.st_size:
                raise ToolError('File range is out of bounds')
            revision = _revision(before)
            chunks = []
            total = 0
            while total < limit:
                chunk = os.pread(fd, min(65536, limit - total), offset + total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(fd)
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
        os.close(fd)


def read_at(dir_fd, rel, limit=MAX_FILE):
    """安全打开普通文件并读取；返回 (data, st_size, truncated)。"""
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        try:
            size = os.fstat(fd).st_size
        except OSError:
            raise ToolError('File is unavailable')
        data, _, truncated = read_fd(fd, limit)
        return data, size, truncated
    finally:
        os.close(fd)


def read_tail(dir_fd, rel, limit=MAX_FILE):
    """从尾部有界读取；返回 (data, st_size, truncated)，truncated 表示丢弃了前半部分。"""
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        try:
            size = os.fstat(fd).st_size
        except OSError:
            raise ToolError('File is unavailable')
        offset = max(0, size - limit)
        os.lseek(fd, offset, os.SEEK_SET)
        data, _, more = read_fd(fd, limit)
        return data, size, offset > 0 or more
    finally:
        os.close(fd)


def read_package(dir_fd, rel):
    """把整个 OPK 有界读入内存（≤ MAX_OPK），再做 zip 结构校验。"""
    fd, kind = open_rel(dir_fd, rel)
    try:
        if kind != 'file':
            raise ToolError('Not a regular file')
        try:
            size = os.fstat(fd).st_size
        except OSError:
            raise ToolError('Package is unavailable')
        if size > MAX_OPK:
            raise ToolError('Package too large')
        data, _, truncated = read_fd(fd, MAX_OPK)
        if truncated:
            raise ToolError('Package too large')
        return data
    finally:
        os.close(fd)


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
