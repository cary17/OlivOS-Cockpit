"""Windows native paths run on Windows; ABI and failure cleanup run everywhere."""

import ctypes as C
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from OlivOSCockpit import _winfs as native


def security_descriptor(*, protected=True, owner=18, group=32):
    def sid(identifier):
        return bytes((1, 1, 0, 0, 0, 0, 0, 5)) + struct.pack('<I', identifier)
    first, second = sid(owner), sid(group)
    acl = struct.pack('<BBHHH', 2, 0, 8, 0, 0)
    control = 0x8004 | (0x1000 if protected else 0)
    return (struct.pack('<BBHIIII', 1, 0, control, 20, 20 + len(first), 0,
                        20 + len(first) + len(second)) + first + second + acl)


class LayoutAndValidationTests(unittest.TestCase):
    def test_both_pointer_width_layouts(self):
        for width, pointer in ((32, C.c_uint32), (64, C.c_uint64)):
            with self.subTest(width=width):
                unicode, attributes, io, rename = native._layouts(pointer, pointer)
                self.assertEqual(C.sizeof(unicode), 8 if width == 32 else 16)
                self.assertEqual(unicode.Buffer.offset, 4 if width == 32 else 8)
                self.assertEqual(C.sizeof(attributes), 24 if width == 32 else 48)
                self.assertEqual(attributes.RootDirectory.offset, 4 if width == 32 else 8)
                self.assertEqual(attributes.SecurityDescriptor.offset, 16 if width == 32 else 32)
                self.assertEqual(C.sizeof(io), 8 if width == 32 else 16)
                self.assertEqual(io.Information.offset, width // 8)
                self.assertEqual(rename.RootDirectory.offset, 4 if width == 32 else 8)
                self.assertEqual(rename.FileNameLength.offset, 8 if width == 32 else 16)
                self.assertEqual(rename.FileName.offset, 12 if width == 32 else 20)
                self.assertEqual(C.sizeof(rename), 16 if width == 32 else 24)

    def test_fixed_width_structures(self):
        self.assertEqual(C.sizeof(native._U32), 4)
        self.assertEqual(C.sizeof(native._U16), 2)
        self.assertEqual(C.sizeof(native._BASIC_INFO), 40)
        self.assertEqual(C.sizeof(native._STANDARD_INFO), 24)
        self.assertEqual(C.sizeof(native._ID_INFO), 24)
        self.assertEqual(native._ID_INFO.FileId.offset, 8)
        self.assertEqual(native._DIRECTORY_INFO.FileName.offset, 64)
        self.assertEqual(native._BASIC_INFO.FileAttributes.offset, 32)
        self.assertEqual(native._STANDARD_INFO.Directory.offset, 21)
        self.assertEqual(C.sizeof(native._UNICODE_STRING), 2 * C.sizeof(C.c_void_p))

    def test_utf16_lengths_and_relative_publish_buffer(self):
        name = '配置-\U0001f916.json'
        encoded = name.encode('utf-16-le')
        value, backing = native._unicode(encoded)
        self.assertEqual(value.Length, len(encoded))
        self.assertEqual(value.MaximumLength, len(encoded) + 2)
        self.assertEqual(C.string_at(value.Buffer, value.Length), encoded)
        raw = (1 << (C.sizeof(C.c_void_p) * 8 - 1)) + 7
        buffer = native._name_information(name, raw, True)
        rename = native._RENAME_INFO.from_buffer(buffer)
        self.assertEqual(rename.RootDirectory, raw)
        self.assertEqual(rename.Flags, 1)
        self.assertEqual(rename.FileNameLength, len(encoded))
        offset = native._RENAME_INFO.FileName.offset
        self.assertEqual(buffer.raw[offset:offset + len(encoded)], encoded)
        self.assertGreaterEqual(len(backing), len(encoded) + 2)

    def test_unsafe_components_are_rejected_before_native_calls(self):
        invalid = ('', '.', '..', 'x/y', 'x\\y', 'x:stream', 'C:relative', '\\server',
                   'tail.', 'tail ', 'CON', 'nUl.txt', 'COM1.json', 'COM1 .cfg', 'LPT\u00b9.ini',
                   'CONIN$', 'CONOUT$.txt', 'wild*', 'wild?', 'a\x00b', 'a\x01b', '\ud800')
        for name in invalid:
            with self.subTest(name=ascii(name)), self.assertRaises(OSError):
                native._component(name)
        self.assertEqual(native._component('终端配置.json'), '终端配置.json'.encode('utf-16-le'))
        self.assertEqual(native._component('COM10.cfg'), b'C\x00O\x00M\x001\x000\x00.\x00c\x00f\x00g\x00')
        with self.assertRaises(OSError):
            native._component('x' * 256)
        with self.assertRaises(OSError):
            native._component('\U0001f916' * 128)

    def test_absolute_roots_and_unc_are_parsed_without_host_path_rules(self):
        self.assertEqual(native._root_parts('C:/run data/插件'),
                         ('\\??\\C:\\', ['run data', '插件']))
        self.assertEqual(native._root_parts('\\\\server\\share\\plugins'),
                         ('\\??\\UNC\\server\\share\\', ['plugins']))
        self.assertEqual(native._root_parts('\\\\server\\share'),
                         ('\\??\\UNC\\server\\share\\', []))
        for path in ('relative', 'C:relative', '/host/absolute', '\\rooted',
                     'C:\\a\\..\\b', 'C:\\a\\.\\b', 'C:\\a.', 'C:\\NUL',
                     '\\\\?\\C:\\data', '\\\\.\\pipe\\x', '\\??\\C:\\data',
                     '\\\\server', '\\\\server\\share\\..'):
            with self.subTest(path=path), self.assertRaises(OSError):
                native._root_parts(path)

    def test_security_snapshot_parser_and_resource_bounds(self):
        descriptor = security_descriptor()
        owner, group, acl, control = native._security_parts(descriptor)
        self.assertEqual(owner[-4:], struct.pack('<I', 18))
        self.assertEqual(group[-4:], struct.pack('<I', 32))
        self.assertEqual(len(acl), 8)
        self.assertEqual(control, 0x1004)
        for malformed in (None, b'', descriptor[:19], descriptor[:35], b'x' * 65537,
                          descriptor[:4] + struct.pack('<I', 0) + descriptor[8:],
                          descriptor[:16] + struct.pack('<I', 65000) + descriptor[20:]):
            with self.subTest(length=len(malformed) if malformed is not None else None), self.assertRaises(OSError):
                native._security_parts(malformed)
        self.assertEqual(native._size(0), 0)
        self.assertEqual(native._size(1 << 40), 1048576)
        for invalid in (-1, True, 1.5, None):
            with self.subTest(value=invalid), self.assertRaises(OSError):
                native._size(invalid)

    @unittest.skipIf(os.name == 'nt', 'POSIX import boundary')
    def test_posix_import_never_binds_windows_dlls(self):
        self.assertIsNone(native._api)
        self.assertFalse(native.supported())
        with self.assertRaises(OSError) as error:
            native.open_root('C:\\data')
        self.assertEqual(error.exception.errno, errno.ENOSYS)


class HandleAndFailureTests(unittest.TestCase):
    def setUp(self):
        self.api = SimpleNamespace()
        self.closed = []
        self.patches = [patch.object(native, '_api', self.api),
                        patch.object(native, '_close_raw', side_effect=self.closed.append)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def handle(self, raw=101, parent=None):
        result = native._own(raw, parent)
        self.addCleanup(native.close, result)
        return result

    def test_child_keeps_ancestor_alive_after_parent_close(self):
        parent = self.handle()
        child = self.handle(202, parent._node)
        native.close(parent)
        self.assertEqual(self.closed, [])
        with native._borrow(child) as node:
            self.assertEqual(node.parent.raw, 101)
        native.close(child)
        native.close(child)
        self.assertEqual(self.closed, [202, 101])
        with self.assertRaises(OSError):
            with native._borrow(child):
                pass

    def test_deep_ancestry_cleanup_is_iterative(self):
        handle = self.handle(1)
        for raw in range(2, 1102):
            child = native._own(raw, handle._node)
            native.close(handle)
            handle = child
        native.close(handle)
        self.assertEqual(self.closed, list(range(1101, 0, -1)))

    def test_validation_and_allocation_failures_close_owned_handles(self):
        parent = self.handle()
        for failure in (OSError(errno.ELOOP, 'reparse'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(native, '_create_raw', return_value=202), \
                    patch.object(native, '_check_raw', side_effect=failure):
                with self.assertRaises(type(failure)):
                    native._open(b'x\0', parent._node, 1, 1, False, 0o600)
                self.assertEqual(parent._node.references, 1)
        with patch.object(native, '_Handle', side_effect=MemoryError):
            with self.assertRaises(MemoryError):
                native._own(303, parent._node)
        self.assertEqual(parent._node.references, 1)
        self.assertEqual(self.closed, [202, 202, 303])

    def test_close_failure_still_releases_every_ancestor(self):
        parent = self.handle()
        child = self.handle(202, parent._node)
        native.close(parent)

        def close_raw(raw):
            self.closed.append(raw)
            if raw == 202:
                raise OSError(errno.EIO, 'close')

        with patch.object(native, '_close_raw', side_effect=close_raw):
            with self.assertRaises(OSError):
                native.close(child)
        self.assertEqual(self.closed, [202, 101])
        self.assertIsNone(child._node)

    def test_security_access_fallback_does_not_bypass_content_validation(self):
        with patch.object(native, '_create_raw', side_effect=[PermissionError(), 202]) as create, \
                patch.object(native, '_check_raw') as validate:
            handle = native._open(b'x\0', None, native._READ_DATA, 1, False, 0o600)
        self.addCleanup(native.close, handle)
        self.assertFalse(handle._node.security)
        self.assertEqual(create.call_count, 2)
        self.assertEqual(create.call_args_list[1].args[2] & native._READ_CONTROL, 0)
        validate.assert_called_once_with(202, False, False)
        with patch.object(native, '_create_raw', side_effect=PermissionError()) as create:
            with self.assertRaises(PermissionError):
                native._open(b'x\0', None, native._WRITE_DAC, 1, False, 0o600)
        self.assertEqual(create.call_count, 1)

    def test_native_creation_releases_security_and_handle_on_interruption(self):
        self.api.LocalFree = Mock()

        def interrupted(result, *_):
            C.cast(result, C.POINTER(C.c_void_p))[0] = 202
            raise KeyboardInterrupt()

        self.api.NtCreateFile = Mock(side_effect=interrupted)
        with patch.object(native, '_private_descriptor', return_value=C.c_void_p(303)):
            with self.assertRaises(KeyboardInterrupt):
                native._create_raw(b'x\0', None, 1, native._FILE_CREATE, False, 0o600)
        self.api.LocalFree.assert_called_once()
        self.assertEqual(self.closed, [202])

    def test_duplicate_allocation_failure_closes_new_handle(self):
        handle = self.handle()
        self.api.GetCurrentProcess = Mock(return_value=7)

        def duplicate(process, source, destination_process, result, *_):
            C.cast(result, C.POINTER(C.c_void_p))[0] = 202
            return 1

        self.api.DuplicateHandle = Mock(side_effect=duplicate)
        with patch.object(native, '_Node', side_effect=MemoryError):
            with self.assertRaises(MemoryError):
                native.dup(handle)
        self.assertEqual(self.closed, [202])
        self.assertEqual(handle._node.references, 1)

    def test_directory_query_failure_closes_iterator_owned_handle(self):
        handle = self.handle()
        copied = self.handle(202)
        self.api.NtQueryDirectoryFile = Mock(side_effect=OSError('query failed'))
        with patch.object(native, 'dup', return_value=copied), patch.object(native, '_check_raw'):
            iterator = native.scandir(handle)
            with self.assertRaises(OSError):
                next(iterator)
            iterator.close()
        self.assertIsNone(copied._node)
        self.assertEqual(self.closed, [202])
        self.assertEqual(handle._node.references, 1)

    def test_missing_permissions_and_setting_failure_reject_before_publish(self):
        handle = self.handle()
        descriptor = security_descriptor()
        original = SimpleNamespace(_win_security=descriptor, _win_attributes=0,
                                   st_mode=stat.S_IFREG | 0o600)
        with self.assertRaises(OSError):
            native.preserve_permissions(handle, SimpleNamespace(_win_security=None))
        self.api.SetKernelObjectSecurity = Mock(side_effect=PermissionError('DACL denied'))
        with patch.object(native, '_check_raw'), \
                patch.object(native, '_security_snapshot', return_value=descriptor), \
                patch.object(native, '_set_information') as metadata:
            with self.assertRaises(PermissionError):
                native.preserve_permissions(handle, original)
        metadata.assert_not_called()
        self.assertEqual(handle._node.references, 1)

    def test_readonly_original_is_rejected_before_any_staging_permission_change(self):
        handle = self.handle()
        original = SimpleNamespace(_win_security=security_descriptor(),
                                   _win_attributes=native._READONLY,
                                   st_mode=stat.S_IFREG | 0o444)
        self.api.SetKernelObjectSecurity = Mock()
        with patch.object(native, '_borrow') as borrowed, \
                patch.object(native, '_set_information') as metadata:
            with self.assertRaises(PermissionError) as error:
                native.preserve_permissions(handle, original)
        self.assertEqual(error.exception.errno, errno.EACCES)
        borrowed.assert_not_called()
        self.api.SetKernelObjectSecurity.assert_not_called()
        metadata.assert_not_called()
        self.assertEqual(handle._node.references, 1)
        self.assertEqual(self.closed, [])

    def test_permission_roundtrip_and_readonly_mismatch_fail_closed(self):
        handle = self.handle()
        descriptor = security_descriptor()
        original = SimpleNamespace(_win_security=descriptor, _win_attributes=0,
                                   st_mode=stat.S_IFREG | 0o600)
        self.api.SetKernelObjectSecurity = Mock(return_value=1)
        for changed in ('acl', 'readonly'):
            security = [descriptor, security_descriptor(owner=19) if changed == 'acl' else descriptor]
            attributes = [SimpleNamespace(FileAttributes=0),
                          SimpleNamespace(FileAttributes=native._READONLY if changed == 'readonly' else 0)]
            with self.subTest(changed=changed), patch.object(native, '_check_raw'), \
                    patch.object(native, '_security_snapshot', side_effect=security), \
                    patch.object(native, '_query', side_effect=attributes), \
                    patch.object(native, '_set_information') as metadata:
                with self.assertRaises(OSError):
                    native.preserve_permissions(handle, original)
                metadata.assert_called_once()
                self.assertEqual(metadata.call_args.args[:2], (101, 4))
            self.assertEqual(handle._node.references, 1)

    def test_directory_fsync_is_never_claimed_as_durable(self):
        handle = self.handle()
        self.api.FlushFileBuffers = Mock(return_value=1)
        with patch.object(native, '_check_raw', return_value=True), self.assertRaises(OSError) as error:
            native.fsync(handle)
        self.assertEqual(error.exception.errno, errno.ENOTSUP)
        self.api.FlushFileBuffers.assert_not_called()
        with patch.object(native, '_check_raw', return_value=False):
            native.fsync(handle)
        self.api.FlushFileBuffers.assert_called_once_with(101)

    def test_invalid_open_flags_are_rejected_before_native_access(self):
        for flags, mode, directory in ((-1, 0o600, None), (3, 0o600, None),
                                       (1 << 48, 0o600, None), (True, 0o600, None),
                                       (os.O_RDONLY, True, None), (os.O_RDONLY, 0o600, 1)):
            with self.subTest(flags=flags, mode=mode, directory=directory), self.assertRaises(OSError):
                native.open_file('safe', flags, mode, directory=directory)

    def test_positioned_read_restores_cursor_on_read_failure(self):
        handle = self.handle()
        with patch.object(native, '_seek', side_effect=[17, 100, 17]) as seek, \
                patch.object(native, 'read', side_effect=OSError(errno.EIO, 'read failed')):
            with self.assertRaises(OSError):
                native.pread(handle, 50, 100)
        self.assertEqual(seek.call_args_list[-1].args, (101, 17, os.SEEK_SET))
        self.assertEqual(handle._node.references, 1)

    def test_publish_failure_always_closes_its_source_handle(self):
        source, destination = self.handle(202), self.handle(303)
        for failure in ('destination', 'native'):
            with self.subTest(failure=failure), \
                    patch.object(native, '_open_relative', return_value=source), \
                    patch.object(native, 'stat_at', side_effect=OSError('denied') if failure == 'destination' else FileNotFoundError()), \
                    patch.object(native, '_check_raw'), \
                    patch.object(native, '_set_information', side_effect=OSError('rename denied')):
                with self.assertRaises(OSError):
                    native.replace('stage', 'final', src_dir_fd=destination, dst_dir_fd=destination)
                self.assertIsNone(source._node)
            if failure == 'destination':
                source = self.handle(204)
        self.assertEqual(self.closed, [202, 204])
        self.assertEqual(destination._node.references, 1)


@unittest.skipUnless(os.name == 'nt', 'Windows native filesystem is unavailable on POSIX')
class WindowsNativeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(native.supported(), 'Required Windows DLL functions must bind')
        self.temporary = tempfile.TemporaryDirectory(prefix='cockpit win 测试 ')
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.root = native.open_root(str(self.path))
        self.addCleanup(native.close, self.root)

    def opened(self, name, flags=os.O_RDONLY, **kwargs):
        handle = native.open_file(name, flags, dir_fd=self.root, **kwargs)
        self.addCleanup(native.close, handle)
        return handle

    def test_unicode_create_read_pread_seek_and_stable_file_identity(self):
        handle = self.opened('配置.json', os.O_CREAT | os.O_EXCL | os.O_RDWR, directory=False)
        self.assertEqual(native.write(handle, b'abcdef'), 6)
        native.fsync(handle)
        self.assertEqual(native.lseek(handle, 2, os.SEEK_SET), 2)
        self.assertEqual(native.pread(handle, 3, 0), b'abc')
        self.assertEqual(native.lseek(handle, 0, os.SEEK_CUR), 2)
        self.assertEqual(native.read(handle, 2), b'cd')
        information = native.fstat(handle)
        self.assertTrue(stat.S_ISREG(information.st_mode))
        self.assertEqual(information.st_size, 6)
        self.assertIsNotNone(information._win_security)
        reopened = self.opened('配置.json', directory=False)
        same = native.fstat(reopened)
        self.assertEqual((information.st_dev, information.st_ino), (same.st_dev, same.st_ino))
        with self.assertRaises(FileExistsError):
            self.opened('配置.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        self.assertEqual(native.pread(handle, 20, 0), b'abcdef')
        with self.assertRaises(FileNotFoundError):
            native.stat_at('absent', dir_fd=self.root)

    def test_absolute_file_open_and_explicit_truncation(self):
        (self.path / 'value.cfg').write_bytes(b'keep')
        handle = native.open_file(str(self.path / 'value.cfg'), os.O_RDWR)
        self.addCleanup(native.close, handle)
        self.assertEqual(native.read(handle, 10), b'keep')
        native.close(handle)
        handle = self.opened('value.cfg', os.O_WRONLY | os.O_TRUNC, directory=False)
        self.assertEqual(native.fstat(handle).st_size, 0)
        with self.assertRaises(OSError):
            self.opened('value.cfg', os.O_RDONLY | os.O_TRUNC)

    def test_atomic_replace_hardlink_unlink_and_permission_preservation(self):
        (self.path / 'original.cfg').write_bytes(b'old')
        original = self.opened('original.cfg', directory=False)
        before = native.fstat(original)
        staged = self.opened('stage', os.O_RDWR | os.O_CREAT | os.O_EXCL, directory=False)
        native.write(staged, b'new')
        native.preserve_permissions(staged, before)
        self.assertEqual(native._security_parts(native.fstat(staged)._win_security),
                         native._security_parts(before._win_security))
        native.fsync(staged)
        native.close(original)
        native.replace('stage', 'original.cfg', src_dir_fd=self.root, dst_dir_fd=self.root)
        published = self.opened('original.cfg', directory=False)
        self.assertEqual(native.read(published, 10), b'new')
        self.assertEqual(native.fstat(staged).st_ino, native.fstat(published).st_ino)
        native.link('original.cfg', 'linked.cfg', src_dir_fd=self.root, dst_dir_fd=self.root)
        self.assertEqual(native.stat_at('linked.cfg', dir_fd=self.root).st_ino, native.fstat(staged).st_ino)
        with self.assertRaises(FileExistsError):
            native.link('original.cfg', 'linked.cfg', src_dir_fd=self.root, dst_dir_fd=self.root)
        native.unlink('linked.cfg', dir_fd=self.root)
        with self.assertRaises(FileNotFoundError):
            native.stat_at('linked.cfg', dir_fd=self.root)
        with self.assertRaises(OSError):
            native.fsync(self.root)

    def test_link_publish_removes_temp_before_verifying_with_staged_handle_open(self):
        content = b'configuration content for publication'
        staged = self.opened('stage', os.O_RDWR | os.O_CREAT | os.O_EXCL, directory=False)
        native.write(staged, content)
        native.fsync(staged)
        identity = native.fstat(staged)
        native.link('stage', 'published.cfg', src_dir_fd=self.root, dst_dir_fd=self.root)
        native.unlink('stage', dir_fd=self.root)
        with self.assertRaises(FileNotFoundError):
            native.stat_at('stage', dir_fd=self.root)
        published = self.opened('published.cfg', directory=False)
        current = native.fstat(published)
        self.assertEqual((identity.st_dev, identity.st_ino), (current.st_dev, current.st_ino))
        self.assertEqual(hashlib.sha256(native.read(published, len(content) + 1)).digest(),
                         hashlib.sha256(content).digest())
        self.assertEqual(native.pread(staged, len(content), 0), content)
        native.close(staged)
        native.close(published)
        self.assertEqual((self.path / 'published.cfg').read_bytes(), content)

    def test_permissions_require_an_authorized_handle_and_fail_before_publish(self):
        (self.path / 'original.cfg').write_bytes(b'original')
        (self.path / 'stage').write_bytes(b'staged')
        original = self.opened('original.cfg', directory=False)
        staged = self.opened('stage', directory=False)
        with self.assertRaises(PermissionError):
            native.preserve_permissions(staged, native.fstat(original))
        self.assertEqual((self.path / 'original.cfg').read_bytes(), b'original')
        self.assertEqual((self.path / 'stage').read_bytes(), b'staged')

    def test_failed_native_opens_do_not_leak_directory_ancestry_handles(self):
        (self.path / 'file.cfg').write_bytes(b'value')
        kernel = C.WinDLL('kernel32', use_last_error=True)
        count_handles = kernel.GetProcessHandleCount
        count_handles.argtypes = [C.c_void_p, C.POINTER(C.c_uint32)]
        count_handles.restype = C.c_int32

        def count():
            result = C.c_uint32()
            self.assertTrue(count_handles(native._api.GetCurrentProcess(), C.byref(result)))
            return result.value

        before = count()
        for _ in range(20):
            with self.assertRaises(OSError):
                native.open_root(str(self.path / 'file.cfg' / 'nested'))
            with self.assertRaises(OSError):
                self.opened('file.cfg', directory=True)
        self.assertEqual(count(), before)

    def test_readonly_update_rejected_before_stage_permissions_change_and_cleanup_succeeds(self):
        original_path, staged_path = self.path / 'readonly.cfg', self.path / '.readonly.cfg.stage.tmp'
        original_path.write_bytes(b'original content')
        os.chmod(original_path, stat.S_IREAD)

        def restore_attributes():
            for path in (original_path, staged_path):
                if path.exists():
                    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)

        self.addCleanup(restore_attributes)
        original = self.opened(original_path.name, directory=False)
        before = native.fstat(original)
        self.assertTrue(before._win_attributes & native._READONLY)
        staged = self.opened(staged_path.name, os.O_RDWR | os.O_CREAT | os.O_EXCL, directory=False)
        native.write(staged, b'replacement content')
        permissions = native.fstat(staged)
        with self.assertRaises(PermissionError):
            native.preserve_permissions(staged, before)
        unchanged = native.fstat(staged)
        self.assertFalse(unchanged._win_attributes & native._READONLY)
        self.assertEqual(native._security_parts(unchanged._win_security),
                         native._security_parts(permissions._win_security))
        native.unlink(staged_path.name, dir_fd=self.root)
        with self.assertRaises(FileNotFoundError):
            native.stat_at(staged_path.name, dir_fd=self.root)
        self.assertEqual(native.pread(staged, 100, 0), b'replacement content')
        after = native.stat_at(original_path.name, dir_fd=self.root)
        self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
        self.assertTrue(after._win_attributes & native._READONLY)
        self.assertEqual(original_path.read_bytes(), b'original content')

    def test_child_handle_and_duplicate_pin_directory_ancestry(self):
        native.mkdir('parent', dir_fd=self.root)
        parent = self.opened('parent', directory=True)
        child = native.open_file('child.cfg', os.O_RDWR | os.O_CREAT | os.O_EXCL, dir_fd=parent)
        self.addCleanup(native.close, child)
        copied = native.dup(child)
        self.addCleanup(native.close, copied)
        native.close(parent)
        native.close(child)
        with self.assertRaises(OSError):
            os.rename(self.path / 'parent', self.path / 'moved')
        self.assertEqual(native.write(copied, b'x'), 1)
        native.close(copied)
        os.rename(self.path / 'parent', self.path / 'moved')
        self.assertEqual((self.path / 'moved' / 'child.cfg').read_bytes(), b'x')

    def test_incremental_directory_enumeration_can_stop_and_restart(self):
        for index in range(20):
            (self.path / ('item-%d.cfg' % index)).write_text(str(index), encoding='utf-8')
        native.mkdir('子目录', dir_fd=self.root)
        with native.scandir(self.root) as entries:
            first = next(entries)
            self.assertTrue(stat.S_ISREG(first.stat(follow_symlinks=False).st_mode)
                            or stat.S_ISDIR(first.stat(follow_symlinks=False).st_mode))
        with native.scandir(self.root) as entries:
            names = {entry.name for entry in entries}
        self.assertEqual(names, {'item-%d.cfg' % index for index in range(20)} | {'子目录'})

    def test_junction_and_unsafe_names_are_never_followed(self):
        native.mkdir('outside', dir_fd=self.root)
        (self.path / 'outside' / 'secret.cfg').write_bytes(b'secret')
        command = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J',
                                  str(self.path / 'junction'), str(self.path / 'outside')],
                                 capture_output=True, check=False)
        self.assertEqual(command.returncode, 0, command.stderr.decode(errors='replace'))
        information = native.stat_at('junction', dir_fd=self.root)
        self.assertTrue(stat.S_ISLNK(information.st_mode))
        with self.assertRaises(OSError):
            self.opened('junction', directory=True)
        with self.assertRaises(OSError):
            native.open_root(str(self.path / 'junction'))
        with self.assertRaises(OSError):
            native.open_file(str(self.path / 'junction' / 'secret.cfg'), os.O_RDONLY)
        with native.scandir(self.root) as entries:
            found = {entry.name: stat.S_ISLNK(entry.stat(follow_symlinks=False).st_mode) for entry in entries}
        self.assertTrue(found['junction'])
        for name in ('NUL', 'outside:stream', 'trailing.', 'trailing ', '..', 'a/b', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(OSError):
                self.opened(name)
        self.assertEqual((self.path / 'outside' / 'secret.cfg').read_bytes(), b'secret')


if __name__ == '__main__':
    unittest.main()
