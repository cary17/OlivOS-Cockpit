"""Windows handle-relative file operations; no pathname fallback or CRT fd table.

Directory handles deny delete sharing and retain their opened ancestry. All later
opens and commits name one component relative to those pinned directory objects.
"""

import ctypes as C
import errno
import ntpath
import os
import stat
import struct
import threading
from contextlib import contextmanager
from types import SimpleNamespace

_U8, _U16, _U32, _U64 = C.c_uint8, C.c_uint16, C.c_uint32, C.c_uint64
_I32, _I64, _PTR = C.c_int32, C.c_int64, C.c_void_p


def _layouts(pointer, size_t):
    """Also instantiate with integer pointers to check both Windows ABIs on POSIX."""
    class UnicodeString(C.Structure):
        _fields_ = [('Length', _U16), ('MaximumLength', _U16), ('Buffer', pointer)]

    class ObjectAttributes(C.Structure):
        _fields_ = [('Length', _U32), ('RootDirectory', pointer),
                    ('ObjectName', pointer), ('Attributes', _U32),
                    ('SecurityDescriptor', pointer), ('SecurityQualityOfService', pointer)]

    class Status(C.Union):
        _fields_ = [('Status', _I32), ('Pointer', pointer)]

    class IoStatus(C.Structure):
        _fields_ = [('Result', Status), ('Information', size_t)]

    class Rename(C.Structure):
        _fields_ = [('Flags', _U32), ('RootDirectory', pointer),
                    ('FileNameLength', _U32), ('FileName', _U16 * 1)]

    return UnicodeString, ObjectAttributes, IoStatus, Rename


_UNICODE_STRING, _OBJECT_ATTRIBUTES, _IO_STATUS_BLOCK, _RENAME_INFO = _layouts(_PTR, C.c_size_t)


class _BASIC_INFO(C.Structure):
    _fields_ = [('CreationTime', _I64), ('LastAccessTime', _I64),
                ('LastWriteTime', _I64), ('ChangeTime', _I64), ('FileAttributes', _U32)]


class _STANDARD_INFO(C.Structure):
    _fields_ = [('AllocationSize', _I64), ('EndOfFile', _I64),
                ('NumberOfLinks', _U32), ('DeletePending', _U8), ('Directory', _U8)]


class _ID_INFO(C.Structure):
    _fields_ = [('VolumeSerialNumber', _U64), ('FileId', _U8 * 16)]


class _ATTRIBUTE_TAG_INFO(C.Structure):
    _fields_ = [('FileAttributes', _U32), ('ReparseTag', _U32)]


# WCHAR is always two bytes, including when this module is imported on POSIX.
class _DIRECTORY_INFO(C.Structure):
    _fields_ = [('NextEntryOffset', _U32), ('FileIndex', _U32),
                ('CreationTime', _I64), ('LastAccessTime', _I64),
                ('LastWriteTime', _I64), ('ChangeTime', _I64),
                ('EndOfFile', _I64), ('AllocationSize', _I64),
                ('FileAttributes', _U32), ('FileNameLength', _U32), ('FileName', _U16 * 1)]


_READ_DATA, _WRITE_DATA, _APPEND_DATA = 0x1, 0x2, 0x4
_TRAVERSE, _READ_ATTRIBUTES, _WRITE_ATTRIBUTES = 0x20, 0x80, 0x100
_DELETE, _READ_CONTROL, _WRITE_DAC, _WRITE_OWNER, _SYNCHRONIZE = 0x10000, 0x20000, 0x40000, 0x80000, 0x100000
_DIRECTORY, _REPARSE, _DEVICE, _READONLY, _NORMAL = 0x10, 0x400, 0x40, 0x1, 0x80
_FILE_OPEN, _FILE_CREATE, _FILE_OPEN_IF = 1, 2, 3
_DIRECTORY_FILE, _NON_DIRECTORY_FILE = 0x1, 0x40
_SYNCHRONOUS, _OPEN_REPARSE = 0x20, 0x200000
_SHARE_READ_WRITE, _SHARE_ALL = 0x3, 0x7
_OWNER_GROUP_DACL, _DACL_PROTECTED = 0x7, 0x1000
_MAX_SECURITY, _MAX_IO, _DIRECTORY_BUFFER = 65536, 1048576, 4096
_EPOCH_TICKS = 116444736000000000
_NO_MORE_FILES = 0x80000006
_ACCMODE = 3  # MSVC does not expose O_ACCMODE on every supported Python build.
_OPEN_FLAGS = 0
for _flag in ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_EXCL', 'O_TRUNC', 'O_APPEND',
              'O_BINARY', 'O_NOINHERIT', 'O_CLOEXEC', 'O_DIRECTORY', 'O_NOFOLLOW',
              'O_NONBLOCK', 'O_NOCTTY'):
    _OPEN_FLAGS |= getattr(os, _flag, 0)
_RESERVED = frozenset(('CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$') + tuple(
    prefix + digit for prefix in ('COM', 'LPT') for digit in '123456789¹²³'))


class _Native:
    def __init__(self):
        nt = C.WinDLL('ntdll', use_last_error=True)
        kernel = C.WinDLL('kernel32', use_last_error=True)
        security = C.WinDLL('advapi32', use_last_error=True)

        def bind(dll, name, result, *arguments):
            function = getattr(dll, name)
            function.restype, function.argtypes = result, list(arguments)
            setattr(self, name, function)

        ptr, u32, handle = _PTR, _U32, _PTR
        bind(nt, 'NtCreateFile', _I32, C.POINTER(handle), u32,
             C.POINTER(_OBJECT_ATTRIBUTES), C.POINTER(_IO_STATUS_BLOCK), ptr,
             u32, u32, u32, u32, ptr, u32)
        bind(nt, 'NtSetInformationFile', _I32, handle, C.POINTER(_IO_STATUS_BLOCK), ptr, u32, u32)
        bind(nt, 'NtQueryDirectoryFile', _I32, handle, handle, ptr, ptr,
             C.POINTER(_IO_STATUS_BLOCK), ptr, u32, u32, _U8, ptr, _U8)
        bind(nt, 'RtlNtStatusToDosError', u32, _I32)
        bind(kernel, 'GetFileInformationByHandleEx', _I32, handle, u32, ptr, u32)
        bind(kernel, 'GetFileType', u32, handle)
        bind(kernel, 'ReadFile', _I32, handle, ptr, u32, C.POINTER(u32), ptr)
        bind(kernel, 'WriteFile', _I32, handle, ptr, u32, C.POINTER(u32), ptr)
        bind(kernel, 'SetFilePointerEx', _I32, handle, _I64, C.POINTER(_I64), u32)
        bind(kernel, 'FlushFileBuffers', _I32, handle)
        bind(kernel, 'CloseHandle', _I32, handle)
        bind(kernel, 'GetCurrentProcess', handle)
        bind(kernel, 'DuplicateHandle', _I32, handle, handle, handle,
             C.POINTER(handle), u32, _I32, u32)
        bind(kernel, 'LocalFree', ptr, ptr)
        bind(security, 'GetKernelObjectSecurity', _I32, handle, u32, ptr, u32, C.POINTER(u32))
        bind(security, 'SetKernelObjectSecurity', _I32, handle, u32, ptr)
        bind(security, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', _I32,
             ptr, u32, C.POINTER(ptr), C.POINTER(u32))


_api = None
if os.name == 'nt':
    try:
        _api = _Native()
    except (OSError, AttributeError):
        pass


def supported():
    return _api is not None


def _require():
    if _api is None:
        raise OSError(errno.ENOSYS, 'Native Windows file operations are unavailable')


def _winerror(code=None):
    code = C.get_last_error() if code is None else code
    # WinError preserves the FileNotFoundError/FileExistsError subclasses.
    raise C.WinError(code)


def _status(value):
    if value < 0:
        _winerror(int(_api.RtlNtStatusToDosError(value)))


def _component(name):
    if (type(name) is not str or not name or name in ('.', '..')
            or any(character in name for character in '\\/:\x00<>"|?*')
            or any(ord(character) < 32 for character in name)
            or name[-1] in '. ' or name.split('.', 1)[0].rstrip(' ').upper() in _RESERVED):
        raise OSError(errno.EINVAL, 'Invalid Windows path component')
    try:
        encoded = name.encode('utf-16-le', 'strict')
    except UnicodeError:
        raise OSError(errno.EINVAL, 'Invalid Windows path component') from None
    if len(encoded) > 510:
        raise OSError(errno.ENAMETOOLONG, 'Windows path component is too long')
    return encoded


def _root_parts(path):
    if type(path) is not str or '\x00' in path or len(path) > 32767:
        raise OSError(errno.EINVAL, 'Invalid Windows root')
    path = path.replace('/', '\\')
    if path.startswith(('\\\\?\\', '\\\\.\\', '\\??\\')):
        raise OSError(errno.EINVAL, 'Device namespace roots are not allowed')
    drive, tail = ntpath.splitdrive(path)
    if len(drive) == 2 and drive[0].isascii() and drive[0].isalpha() and drive[1] == ':':
        if not tail.startswith('\\'):
            raise OSError(errno.EINVAL, 'An absolute Windows root is required')
        anchor = '\\??\\' + drive + '\\'
    elif drive.startswith('\\\\'):
        share = drive[2:].split('\\')
        if len(share) != 2:
            raise OSError(errno.EINVAL, 'Invalid UNC root')
        for part in share:
            _component(part)
        if tail and not tail.startswith('\\'):
            raise OSError(errno.EINVAL, 'Invalid UNC root')
        anchor = '\\??\\UNC\\' + '\\'.join(share) + '\\'
    else:
        raise OSError(errno.EINVAL, 'An absolute Windows root is required')
    names = [part for part in tail.split('\\') if part]
    for name in names:
        _component(name)
    return anchor, names


def _unicode(encoded):
    buffer = C.create_string_buffer(encoded + b'\0\0')
    value = _UNICODE_STRING(len(encoded), len(encoded) + 2, C.addressof(buffer))
    return value, buffer


def _private_descriptor():
    # OWNER RIGHTS follows the creating token's owner without querying global token state.
    text = C.create_string_buffer('D:P(A;;FA;;;OW)'.encode('utf-16-le') + b'\0\0')
    pointer, size = _PTR(), _U32()
    try:
        if not _api.ConvertStringSecurityDescriptorToSecurityDescriptorW(text, 1, C.byref(pointer), C.byref(size)):
            _winerror()
        if not pointer.value or not 20 <= size.value <= _MAX_SECURITY:
            raise OSError(errno.EIO, 'Invalid creation security descriptor')
        return pointer
    except BaseException:
        if pointer.value:
            _api.LocalFree(pointer)
        raise


def _create_raw(encoded, parent, access, disposition, directory, mode):
    name, buffer = _unicode(encoded)
    descriptor, result = None, _PTR()
    try:
        try:
            if disposition != _FILE_OPEN:
                descriptor = _private_descriptor()
            attributes = _OBJECT_ATTRIBUTES(C.sizeof(_OBJECT_ATTRIBUTES), parent,
                                            C.addressof(name), 0x40, descriptor.value if descriptor else None, None)
            io = _IO_STATUS_BLOCK()
            options = _SYNCHRONOUS | _OPEN_REPARSE | (_DIRECTORY_FILE if directory else _NON_DIRECTORY_FILE)
            file_attributes = _NORMAL if mode & 0o200 or directory else _READONLY
            status = _api.NtCreateFile(C.byref(result), access, C.byref(attributes), C.byref(io),
                                       None, file_attributes, _SHARE_READ_WRITE if directory else _SHARE_ALL,
                                       disposition, options, None, 0)
            _status(status)
            if not result.value:
                raise OSError(errno.EIO, 'Native file open returned an invalid handle')
        finally:
            if descriptor is not None:
                _api.LocalFree(descriptor)
    except BaseException:
        if result.value:
            _close_raw(result.value)
        raise
    return result.value


def _close_raw(raw):
    if not _api.CloseHandle(raw):
        _winerror()


class _Node:
    def __init__(self, raw, parent=None, cursor=None, security=True):
        self.raw, self.parent, self.security = raw, parent, security
        self.cursor = cursor if cursor is not None else threading.RLock()
        self.lock, self.references = threading.Lock(), 1

    def retain(self):
        with self.lock:
            if self.references == 0:
                raise OSError(errno.EBADF, 'File handle is closed')
            self.references += 1
        return self

    def release(self):
        node, error = self, None
        while node is not None:
            with node.lock:
                node.references -= 1
                last = node.references == 0
            if not last:
                break
            try:
                _close_raw(node.raw)
            except BaseException as failure:
                if error is None:
                    error = failure
            node = node.parent
        if error is not None:
            raise error


class _Handle:
    def __init__(self, node):
        self._lock = threading.Lock()
        self._node = node

    def __del__(self):
        try:
            close(self)
        except BaseException:
            pass


@contextmanager
def _borrow(fd):
    _require()
    if not isinstance(fd, _Handle):
        raise OSError(errno.EBADF, 'Invalid native file handle')
    with fd._lock:
        if fd._node is None:
            raise OSError(errno.EBADF, 'File handle is closed')
        node = fd._node.retain()
    try:
        yield node
    finally:
        node.release()


def close(fd):
    if not isinstance(fd, _Handle):
        raise OSError(errno.EBADF, 'Invalid native file handle')
    with fd._lock:
        node, fd._node = fd._node, None
    if node is not None:
        node.release()


def _query(raw, information_class, structure):
    result = structure()
    if not _api.GetFileInformationByHandleEx(raw, information_class, C.byref(result), C.sizeof(result)):
        _winerror()
    return result


def _check_raw(raw, directory, allow_reparse=False):
    if _api.GetFileType(raw) != 1:  # FILE_TYPE_DISK, never a pipe/character device.
        raise OSError(errno.ENOTSUP, 'Unsupported Windows file object')
    attributes = _query(raw, 9, _ATTRIBUTE_TAG_INFO).FileAttributes
    if attributes & _DEVICE or attributes & _REPARSE and not allow_reparse:
        raise OSError(errno.ELOOP, 'Reparse points and devices are not accessible')
    is_directory = bool(attributes & _DIRECTORY)
    if directory is not None and directory != is_directory:
        raise OSError(errno.ENOTDIR if directory else errno.EISDIR, 'Unexpected Windows file type')
    return is_directory


def _own(raw, parent=None, cursor=None, security=True):
    pin = None
    try:
        pin = parent.retain() if parent else None
        return _Handle(_Node(raw, pin, cursor=cursor, security=security))
    except BaseException:
        try:
            _close_raw(raw)
        finally:
            if pin is not None:
                pin.release()
        raise


def _open(encoded, parent, access, disposition, directory, mode, allow_reparse=False):
    raw, security = None, True
    try:
        try:
            raw = _create_raw(encoded, parent.raw if parent else None, access | _READ_CONTROL,
                              disposition, directory, mode)
        except PermissionError:
            if disposition != _FILE_OPEN or access & (_WRITE_DAC | _WRITE_OWNER):
                raise
            security = False
            raw = _create_raw(encoded, parent.raw if parent else None, access,
                              disposition, directory, mode)
        _check_raw(raw, directory, allow_reparse)
        owned, raw = raw, None
        return _own(owned, parent, security=security)
    finally:
        if raw is not None:
            _close_raw(raw)


def open_root(path):
    _require()
    anchor, names = _root_parts(path)
    access = _READ_DATA | _TRAVERSE | _READ_ATTRIBUTES | _SYNCHRONIZE
    result = _open(anchor.encode('utf-16-le'), None, access, _FILE_OPEN, True, 0o700)
    try:
        for name in names:
            child = open_file(name, os.O_RDONLY, dir_fd=result, directory=True)
            close(result)
            result = child
        opened, result = result, None
        return opened
    finally:
        if result is not None:
            close(result)


def _open_relative(name, access, disposition, directory, mode, dir_fd, allow_reparse=False):
    encoded = _component(name)
    with _borrow(dir_fd) as parent:
        _check_raw(parent.raw, True)
        return _open(encoded, parent, access, disposition, directory, mode, allow_reparse)


def open_file(name, flags, mode=0o600, *, dir_fd=None, directory=None):
    _require()
    if (type(flags) is not int or flags < 0 or flags & ~_OPEN_FLAGS
            or flags & _ACCMODE == _ACCMODE or type(mode) is not int or mode < 0
            or directory is not None and type(directory) is not bool):
        raise OSError(errno.EINVAL, 'Invalid Windows open flags')
    if dir_fd is None:
        # Absolute native paths are opened only through the same component walk.
        anchor, names = _root_parts(name)
        if not names:
            if directory is False or flags & (os.O_CREAT | os.O_TRUNC):
                raise OSError(errno.EISDIR, 'A file name is required')
            return open_root(name)
        root = open_root(ntpath.splitdrive(name.replace('/', '\\'))[0] + '\\')
        try:
            for part in names[:-1]:
                child = open_file(part, os.O_RDONLY, dir_fd=root, directory=True)
                close(root)
                root = child
            return open_file(names[-1], flags, mode, dir_fd=root, directory=directory)
        finally:
            close(root)
    writing = flags & _ACCMODE in (os.O_WRONLY, os.O_RDWR)
    if flags & os.O_TRUNC and not writing:
        raise OSError(errno.EINVAL, 'Truncation requires write access')
    disposition = _FILE_CREATE if flags & os.O_CREAT and flags & os.O_EXCL else (
        _FILE_OPEN_IF if flags & os.O_CREAT else _FILE_OPEN)
    if directory is None and not writing and disposition == _FILE_OPEN:
        try:
            return open_file(name, flags, mode, dir_fd=dir_fd, directory=True)
        except NotADirectoryError:
            pass
    is_directory = directory is True
    if is_directory and (writing or flags & os.O_TRUNC):
        raise OSError(errno.EISDIR, 'Directory content writes are not allowed')
    access = _READ_ATTRIBUTES | _SYNCHRONIZE
    if flags & _ACCMODE != os.O_WRONLY:
        access |= _READ_DATA
    if is_directory:
        access |= _TRAVERSE
    if writing:
        access |= (_APPEND_DATA if flags & os.O_APPEND else _WRITE_DATA) | _WRITE_ATTRIBUTES
    if disposition != _FILE_OPEN:
        access |= _DELETE | _WRITE_DAC | _WRITE_OWNER
    result = _open_relative(name, access, disposition, is_directory, mode, dir_fd)
    try:
        if flags & os.O_TRUNC:
            with _borrow(result) as node:
                _set_information(node.raw, 20, _I64(0))
        opened, result = result, None
        return opened
    finally:
        if result is not None:
            close(result)


def dup(fd):
    with _borrow(fd) as node:
        raw = _PTR()
        process = _api.GetCurrentProcess()
        try:
            if not _api.DuplicateHandle(process, node.raw, process, C.byref(raw), 0, False, 2):
                _winerror()
            if not raw.value:
                raise OSError(errno.EIO, 'Native duplication returned an invalid handle')
            owned, raw.value = raw.value, None
            return _own(owned, node.parent, cursor=node.cursor, security=node.security)
        finally:
            if raw.value:
                _close_raw(raw.value)


def _security_parts(descriptor):
    if type(descriptor) is not bytes or not 20 <= len(descriptor) <= _MAX_SECURITY:
        raise OSError(errno.EIO, 'Invalid Windows security descriptor')
    revision, _, control, owner, group, sacl, dacl = struct.unpack_from('<BBHIIII', descriptor)
    if revision != 1 or not control & 0x8000 or sacl:
        raise OSError(errno.EIO, 'Invalid Windows security descriptor')

    def sid(offset):
        if offset < 20 or offset + 8 > len(descriptor):
            raise OSError(errno.EIO, 'Invalid Windows security owner')
        length = 8 + descriptor[offset + 1] * 4
        if descriptor[offset] != 1 or length > 68 or offset + length > len(descriptor):
            raise OSError(errno.EIO, 'Invalid Windows security owner')
        return descriptor[offset:offset + length]

    acl = None
    if dacl:
        if dacl < 20 or dacl + 8 > len(descriptor):
            raise OSError(errno.EIO, 'Invalid Windows file permissions')
        length = struct.unpack_from('<H', descriptor, dacl + 2)[0]
        if length < 8 or dacl + length > len(descriptor):
            raise OSError(errno.EIO, 'Invalid Windows file permissions')
        acl = descriptor[dacl:dacl + length]
    return sid(owner), sid(group), acl, control & (0x4 | _DACL_PROTECTED)


def _security_snapshot(raw):
    buffer, needed = C.create_string_buffer(_MAX_SECURITY), _U32()
    if not _api.GetKernelObjectSecurity(raw, _OWNER_GROUP_DACL, buffer, len(buffer), C.byref(needed)):
        _winerror()
    if not 20 <= needed.value <= len(buffer):
        raise OSError(errno.EIO, 'Windows security descriptor exceeds its limit')
    descriptor = buffer.raw[:needed.value]
    _security_parts(descriptor)
    return descriptor


def fstat(fd):
    with _borrow(fd) as node:
        _check_raw(node.raw, None, allow_reparse=True)
        basic = _query(node.raw, 0, _BASIC_INFO)
        standard = _query(node.raw, 1, _STANDARD_INFO)
        identity = _query(node.raw, 18, _ID_INFO)
        descriptor = None
        if node.security:
            try:
                descriptor = _security_snapshot(node.raw)
            except OSError:
                pass  # Reading content may be allowed without reading its DACL.
        owner, group = (0, 0)
        if descriptor is not None:
            owner, group = (int.from_bytes(value, 'little') for value in _security_parts(descriptor)[:2])
        attributes = basic.FileAttributes
        kind = stat.S_IFLNK if attributes & _REPARSE else (
            stat.S_IFDIR if standard.Directory else stat.S_IFREG)
        mode = kind | 0o444 | (0 if attributes & _READONLY else 0o222)
        if kind == stat.S_IFDIR:
            mode |= 0o111
        mtime, ctime, atime = ((value - _EPOCH_TICKS) * 100 for value in (
            basic.LastWriteTime, basic.ChangeTime, basic.LastAccessTime))
        return SimpleNamespace(st_dev=int(identity.VolumeSerialNumber),
                               st_ino=int.from_bytes(bytes(identity.FileId), 'little'),
                               st_mode=mode, st_nlink=int(standard.NumberOfLinks),
                               st_size=int(standard.EndOfFile), st_uid=owner, st_gid=group,
                               st_mtime=mtime / 1e9, st_mtime_ns=mtime,
                               st_ctime=ctime / 1e9, st_ctime_ns=ctime,
                               st_atime=atime / 1e9, st_atime_ns=atime,
                               _win_security=descriptor, _win_attributes=attributes)


def _size(value):
    if type(value) is not int or value < 0:
        raise OSError(errno.EINVAL, 'Invalid native I/O size')
    return min(value, _MAX_IO)


def read(fd, n):
    n = _size(n)
    with _borrow(fd) as node, node.cursor:
        buffer, count = C.create_string_buffer(n), _U32()
        if not _api.ReadFile(node.raw, buffer, n, C.byref(count), None):
            _winerror()
        if count.value > n:
            raise OSError(errno.EIO, 'Invalid native read length')
        return buffer.raw[:count.value]


def write(fd, data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError('A bytes-like object is required')
    data = bytes(memoryview(data).cast('B')[:_MAX_IO])
    with _borrow(fd) as node, node.cursor:
        buffer, count = C.create_string_buffer(data), _U32()
        if not _api.WriteFile(node.raw, buffer, len(data), C.byref(count), None):
            _winerror()
        if count.value > len(data):
            raise OSError(errno.EIO, 'Invalid native write length')
        return count.value


def _seek(raw, offset, whence):
    if type(offset) is not int or not -(1 << 63) <= offset < 1 << 63 or whence not in (0, 1, 2):
        raise OSError(errno.EINVAL, 'Invalid native file position')
    position = _I64()
    if not _api.SetFilePointerEx(raw, offset, C.byref(position), whence):
        _winerror()
    return position.value


def lseek(fd, offset, whence):
    with _borrow(fd) as node, node.cursor:
        return _seek(node.raw, offset, whence)


def pread(fd, n, offset):
    n = _size(n)
    if type(offset) is not int or not 0 <= offset < 1 << 63:
        raise OSError(errno.EINVAL, 'Invalid native file position')
    with _borrow(fd) as node, node.cursor:
        position = _seek(node.raw, 0, os.SEEK_CUR)
        try:
            _seek(node.raw, offset, os.SEEK_SET)
            return read(fd, n)
        finally:
            _seek(node.raw, position, os.SEEK_SET)


def _set_information(raw, information_class, buffer):
    io = _IO_STATUS_BLOCK()
    _status(_api.NtSetInformationFile(raw, C.byref(io), C.byref(buffer), C.sizeof(buffer), information_class))


def fsync(fd):
    with _borrow(fd) as node:
        if _check_raw(node.raw, None):
            raise OSError(errno.ENOTSUP, 'Windows directory durability is not guaranteed')
        if not _api.FlushFileBuffers(node.raw):
            _winerror()


def preserve_permissions(staged_fd, original_info):
    descriptor = getattr(original_info, '_win_security', None)
    original_attributes = getattr(original_info, '_win_attributes', None)
    expected = _security_parts(descriptor)
    if type(original_attributes) is not int or not stat.S_ISREG(original_info.st_mode):
        raise OSError(errno.EINVAL, 'Original Windows permissions are unavailable')
    # Native replacement rejects readonly targets; leave staging permissions safe for cleanup.
    if original_attributes & _READONLY:
        raise PermissionError(errno.EACCES, 'Replacing readonly Windows files is not supported')
    with _borrow(staged_fd) as node:
        _check_raw(node.raw, False)
        before = _security_parts(_security_snapshot(node.raw))
        mask = 0x4 | (0x80000000 if expected[3] & _DACL_PROTECTED else 0x20000000)
        if expected[0] != before[0]:
            mask |= 0x1
        if expected[1] != before[1]:
            mask |= 0x2
        buffer = C.create_string_buffer(descriptor)
        if not _api.SetKernelObjectSecurity(node.raw, mask, buffer):
            _winerror()
        basic = _query(node.raw, 0, _BASIC_INFO)
        attributes = (basic.FileAttributes & ~_READONLY) | (original_attributes & _READONLY)
        update = _BASIC_INFO()
        update.FileAttributes = attributes or _NORMAL
        _set_information(node.raw, 4, update)
        if (_security_parts(_security_snapshot(node.raw)) != expected
                or _query(node.raw, 0, _BASIC_INFO).FileAttributes & _READONLY != original_attributes & _READONLY):
            raise OSError(errno.EACCES, 'Windows permission preservation could not be verified')


def stat_at(name, *, dir_fd, follow_symlinks=False):
    if follow_symlinks is not False:
        raise OSError(errno.ENOTSUP, 'Following Windows reparse points is not supported')
    access = _READ_ATTRIBUTES | _SYNCHRONIZE
    try:
        handle = _open_relative(name, access | _TRAVERSE, _FILE_OPEN, True, 0o700, dir_fd, True)
    except NotADirectoryError:
        handle = _open_relative(name, access, _FILE_OPEN, False, 0o600, dir_fd, True)
    try:
        return fstat(handle)
    finally:
        close(handle)


def mkdir(name, mode=0o700, *, dir_fd):
    handle = _open_relative(name, _READ_DATA | _TRAVERSE | _READ_ATTRIBUTES | _SYNCHRONIZE,
                            _FILE_CREATE, True, mode, dir_fd)
    close(handle)


def unlink(name, *, dir_fd):
    handle = _open_relative(name, _DELETE | _READ_ATTRIBUTES | _SYNCHRONIZE,
                            _FILE_OPEN, False, 0o600, dir_fd)
    try:
        with _borrow(handle) as node:
            # POSIX disposition removes this name while other handles remain open.
            _set_information(node.raw, 64, _U32(0x1 | 0x2))
    finally:
        close(handle)


def _name_information(destination, raw_directory, replace_existing):
    encoded = _component(destination)
    size = C.sizeof(_RENAME_INFO) + len(encoded)
    buffer = C.create_string_buffer(size)
    information = _RENAME_INFO.from_buffer(buffer)
    information.Flags = int(replace_existing)
    information.RootDirectory = raw_directory
    information.FileNameLength = len(encoded)
    C.memmove(C.addressof(buffer) + _RENAME_INFO.FileName.offset, encoded, len(encoded))
    return buffer


def _publish(src, dst, src_dir_fd, dst_dir_fd, replace_existing):
    _component(dst)
    source = _open_relative(src, _READ_ATTRIBUTES | _SYNCHRONIZE | (_DELETE if replace_existing else 0),
                            _FILE_OPEN, False, 0o600, src_dir_fd)
    try:
        try:
            target = stat_at(dst, dir_fd=dst_dir_fd)
        except FileNotFoundError:
            target = None
        if target is not None and not stat.S_ISREG(target.st_mode):
            raise OSError(errno.ELOOP, 'Publish target is not a regular Windows file')
        with _borrow(source) as node, _borrow(dst_dir_fd) as parent:
            _check_raw(parent.raw, True)
            information = _name_information(dst, parent.raw, replace_existing)
            _set_information(node.raw, 10 if replace_existing else 11, information)
    finally:
        close(source)


def link(src, dst, *, src_dir_fd, dst_dir_fd):
    _publish(src, dst, src_dir_fd, dst_dir_fd, False)


def replace(src, dst, *, src_dir_fd, dst_dir_fd):
    _publish(src, dst, src_dir_fd, dst_dir_fd, True)


class _Entry:
    def __init__(self, name, directory):
        self.name, self._directory = name, directory

    def stat(self, *, follow_symlinks=False):
        return stat_at(self.name, dir_fd=self._directory, follow_symlinks=follow_symlinks)


class _Scandir:
    def __init__(self, fd):
        self._buffer = C.create_string_buffer(_DIRECTORY_BUFFER)
        self._node, self._started, self._closed = None, False, False
        self._handle = dup(fd)

    def __enter__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        if self._closed:
            raise StopIteration
        if self._node is None:
            try:
                with _borrow(self._handle) as node:
                    _check_raw(node.raw, True)
                    node.retain()
                    try:
                        node.cursor.acquire()
                    except BaseException:
                        node.release()
                        raise
                    self._node = node
            except BaseException:
                self.close()
                raise
        try:
            while True:
                io = _IO_STATUS_BLOCK()
                value = _api.NtQueryDirectoryFile(self._node.raw, None, None, None, C.byref(io),
                                                   self._buffer, len(self._buffer), 1, True, None, not self._started)
                self._started = True
                if value & 0xFFFFFFFF == _NO_MORE_FILES:
                    self.close()
                    raise StopIteration
                _status(value)
                size, offset = int(io.Information), _DIRECTORY_INFO.FileName.offset
                if not offset <= size <= len(self._buffer):
                    raise OSError(errno.EIO, 'Invalid Windows directory response')
                information = _DIRECTORY_INFO.from_buffer(self._buffer)
                length = information.FileNameLength
                if length % 2 or not 0 < length <= 510 or offset + length > size or information.NextEntryOffset:
                    raise OSError(errno.EIO, 'Invalid Windows directory entry')
                name = self._buffer.raw[offset:offset + length].decode('utf-16-le', 'strict')
                if name not in ('.', '..'):
                    return _Entry(name, self._handle)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            if self._node is not None:
                node, self._node = self._node, None
                try:
                    node.cursor.release()
                finally:
                    node.release()
        finally:
            close(self._handle)

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except BaseException:
            pass


def scandir(fd):
    return _Scandir(fd)
