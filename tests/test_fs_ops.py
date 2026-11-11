"""跨平台门面、真实对象策略和配置写入边界。"""

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import ntpath
import os
import stat
import sys
import tempfile
import types
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import account_write, config, contracts, file_write, files, fs, plugin_install


class FacadeTests(unittest.TestCase):
    def test_windows_dispatch_keeps_handles_opaque(self):
        backend = Mock()
        handle, parent = object(), object()
        info = types.SimpleNamespace(st_dev=1, st_ino=2)
        with patch.object(fs, 'fstat', return_value=info):
            wrapped = fs._FD(1, None, None)
        wrapped.handle = handle
        with patch.object(fs, '_WINDOWS', True), patch.object(fs, '_winfs', backend):
            fs.open_file('config.json', os.O_RDONLY, dir_fd=parent, directory=False)
            fs.close(wrapped)
            fs.dup(wrapped)
            fs.fstat(wrapped)
            fs.read(wrapped, 4)
            fs.write(wrapped, b'data')
            fs.lseek(wrapped, 2, os.SEEK_SET)
            fs.pread(wrapped, 4, 2)
            fs.scandir(parent)
            fs.stat_at('config.json', dir_fd=parent)
            fs.mkdir('child', dir_fd=parent)
            fs.unlink('config.json', dir_fd=parent)
            fs.link('old', 'new', src_dir_fd=parent, dst_dir_fd=parent)
            fs.replace('old', 'new', src_dir_fd=parent, dst_dir_fd=parent)
            fs.fsync(wrapped)
            fs.preserve_permissions(wrapped, info)
        backend.open_file.assert_called_once_with(
            'config.json', os.O_RDONLY, 0o600, dir_fd=parent, directory=False)
        for name in ('close', 'dup', 'fstat', 'fsync'):
            getattr(backend, name).assert_called_once_with(handle)
        backend.read.assert_called_once_with(handle, 4)
        backend.write.assert_called_once_with(handle, b'data')
        backend.lseek.assert_called_once_with(handle, 2, os.SEEK_SET)
        backend.pread.assert_called_once_with(handle, 4, 2)
        backend.scandir.assert_called_once_with(parent)
        backend.stat_at.assert_called_once_with('config.json', dir_fd=parent, follow_symlinks=False)
        backend.mkdir.assert_called_once_with('child', 0o700, dir_fd=parent)
        backend.unlink.assert_called_once_with('config.json', dir_fd=parent)
        backend.link.assert_called_once_with('old', 'new', src_dir_fd=parent, dst_dir_fd=parent)
        backend.replace.assert_called_once_with('old', 'new', src_dir_fd=parent, dst_dir_fd=parent)
        backend.preserve_permissions.assert_called_once_with(handle, info)

    @unittest.skipUnless(os.name == 'posix', 'POSIX os hooks')
    def test_posix_fault_injection_uses_current_os_functions(self):
        with patch.object(os, 'write', return_value=2) as write:
            self.assertEqual(fs.write(123, b'abc'), 2)
            write.assert_called_once_with(123, b'abc')
        with patch.object(os, 'fsync', side_effect=OSError), self.assertRaises(OSError):
            fs.fsync(123)
        with patch.object(os, 'replace', side_effect=OSError), self.assertRaises(OSError):
            fs.replace('old', 'new', src_dir_fd=123, dst_dir_fd=123)

    def test_windows_dangerous_names_reach_all_request_parsers(self):
        names = ('NUL', 'con.txt', 'AUX.json', 'COM1', 'LPT9.log', 'COM¹', 'CONIN$',
                 'name.', 'name ', 'x:stream', 'a<b', 'a\x01b', 'a?b')
        with patch.object(fs, '_WINDOWS', True):
            for name in names:
                for parser, value in ((files._check_namespace, name),
                                      (files._check_rel, 'sub/' + name),
                                      (fs._relative_names, name)):
                    with self.subTest(name=name, parser=parser.__name__), self.assertRaises(contracts.ToolError):
                        parser(value)
            self.assertEqual(fs._relative_names('./子目录/config.json'), ['子目录', 'config.json'])
            self.assertEqual(files._check_namespace('Company'), 'Company')
        for value in ('C:/a', '//server/share', r'\\?\C:\a', r'sub\config.json', '../x'):
            with self.subTest(value=value), self.assertRaises(contracts.ToolError):
                fs._relative_names(value)

    def test_native_windows_roots_can_use_different_drives(self):
        native_os = types.SimpleNamespace(path=ntpath)
        with patch.object(fs, 'os', native_os), patch.object(fs, '_WINDOWS', True):
            self.assertEqual(fs._absolute(r'D:\插件 数据'), r'D:\插件 数据')
            self.assertFalse(fs._within(r'C:\runtime\x', r'D:\data'))
            self.assertFalse(fs._within(r'C:\runtime-other\x', r'C:\runtime'))
            self.assertTrue(fs._within(r'C:\Runtime\x', r'c:\runtime'))
            with self.assertRaises(contracts.ToolError):
                fs._absolute(r'\relative-drive')

    def test_windows_identity_uses_security_and_readonly_instead_of_unix_bits(self):
        values = dict(st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4, st_ctime_ns=5,
                      st_nlink=1, st_mode=stat.S_IFREG | 0o777, st_uid=10, st_gid=11,
                      _win_security=b'owner-dacl', _win_attributes=0)
        first = types.SimpleNamespace(**values)
        second = types.SimpleNamespace(**dict(values, st_uid=20, st_gid=21, st_mode=stat.S_IFREG | 0o444))
        with patch.object(fs, '_WINDOWS', True):
            self.assertTrue(fs.non_executable(first))
            self.assertEqual(file_write._identity(first), file_write._identity(second))
            second._win_attributes = 1
            self.assertNotEqual(file_write._identity(first), file_write._identity(second))
            second._win_attributes = 0
            second._win_security = b'changed-dacl'
            self.assertNotEqual(file_write._identity(first), file_write._identity(second))

    def test_update_request_joins_keep_slashes_on_windows(self):
        root = object()
        parent = types.SimpleNamespace(path=r'D:\data\Demo\sub dir')
        outcome = contracts.Outcome({})
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(file_write, 'os', types.SimpleNamespace(path=ntpath)))
            stack.enter_context(patch.object(fs, '_WINDOWS', True))
            stack.enter_context(patch.object(file_write, '_snapshot', return_value=1))
            stack.enter_context(patch.object(fs, 'require'))
            stack.enter_context(patch.object(fs, 'updates_supported', return_value=True))
            stack.enter_context(patch.object(fs, 'open_root', return_value=root))
            opening = stack.enter_context(patch.object(fs, 'open_rel', return_value=(parent, 'dir')))
            stack.enter_context(patch.object(fs, 'close'))
            stack.enter_context(patch.object(fs, 'authorize_path'))
            replacing = stack.enter_context(patch.object(file_write, '_replace', return_value=outcome))
            file_write.cockpit_plugin_file_update(types.SimpleNamespace(data_root=r'D:\data'), {
                'namespace': 'Demo', 'path': 'sub dir/config.json',
                'expected_sha256': '0' * 64, 'content': '{}',
            })
        opening.assert_called_once_with(root, 'Demo/sub dir')
        self.assertEqual(replacing.call_args.args[2], 'config.json')
        self.assertEqual(outcome.data['path'], 'sub dir/config.json')

    def test_install_capability_uses_common_update_gate(self):
        with patch.object(fs, 'updates_supported', return_value=True):
            self.assertTrue(plugin_install._tool_ready())
        with patch.object(fs, 'updates_supported', return_value=False):
            self.assertFalse(plugin_install._tool_ready())


@unittest.skipUnless(fs.supported(), 'Secure filesystem backend unavailable')
class FilesystemFlowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='cockpit-fs-ops-')
        self.addCleanup(directory.cleanup)
        self.root = Path(os.path.realpath(directory.name))
        self.data = self.root / 'plugin' / 'data'
        self.data.mkdir(parents=True)
        self.control = self.data / config.NAMESPACE_DIR / config.CONTROL_DIR
        self.control.mkdir(parents=True)
        (self.control / 'secret.json').write_text('{"secret":"private"}', encoding='utf-8')
        self.snapshot = config.Snapshot(valid=True, generation=1, full_real_account_write=True)
        manager = types.SimpleNamespace(snapshot=lambda: self.snapshot)
        self.ctx = contracts.Context(None, str(self.root), str(self.data), config=manager)

    def opened(self, path, context=None):
        fd = fs.open_root(str(path), context=context)
        self.addCleanup(fs.close, fd)
        return fd

    def test_protected_short_name_alias_ancestor_is_rejected_before_read(self):
        parent = self.opened(self.data, self.ctx)
        opening = fs.open_file

        def alias(name, *args, **kwargs):
            return opening(config.NAMESPACE_DIR if name == 'OLIVOS~1' else name, *args, **kwargs)

        with patch.object(fs, 'open_file', side_effect=alias), patch.object(fs, 'read') as reading:
            with self.assertRaises(contracts.ToolError):
                fs.read_at(parent, 'OLIVOS~1/control/secret.json')
            reading.assert_not_called()

    def test_denied_unicode_alias_ancestor_rejects_read_and_missing_write(self):
        denied = self.data / 'Caf\u00e9'
        denied.mkdir()
        (denied / 'secret.json').write_text('{}', encoding='utf-8')
        self.snapshot = config.Snapshot(valid=True, generation=2, full_real_account_write=True,
                                        denied_paths=(str(denied),))
        parent = self.opened(self.data, self.ctx)
        opening = fs.open_file

        def alias(name, *args, **kwargs):
            return opening('Caf\u00e9' if name == 'Cafe\u0301' else name, *args, **kwargs)

        with patch.object(fs, 'open_file', side_effect=alias):
            with self.assertRaises(contracts.ToolError):
                fs.read_at(parent, 'Cafe\u0301/secret.json')
            with self.assertRaises(contracts.ToolError):
                fs.authorize_rel(parent, 'Cafe\u0301/new.json', write=True)

    def assert_install_denied(self, app, filename, denied, *, aliases=None, package_path=None):
        self.addCleanup(plugin_install.detach, None)
        self.snapshot = replace(self.snapshot, api_key='test-key', full_plugin_install=True,
                                denied_paths=(str(denied),))
        ctx = replace(self.ctx, olivos=types.SimpleNamespace(
            pluginAPI=types.SimpleNamespace(plugin_path=str(package_path or app))))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('app.json', json.dumps({'namespace': 'Demo'}))
            archive.writestr('__init__.py', b'')
            archive.writestr('main.py', b'')
        data = buffer.getvalue()
        opening = fs.open_file

        def alias(name, *args, **kwargs):
            return opening((aliases or {}).get(name, name), *args, **kwargs)

        with patch.object(fs, 'open_file', side_effect=alias), \
                patch.object(fs, 'link', wraps=fs.link) as linking, \
                patch.object(fs, 'replace', wraps=fs.replace) as replacing:
            begin = plugin_install.cockpit_plugin_install(ctx, {
                'operation': 'begin', 'filename': filename, 'namespace': 'Demo', 'size': len(data),
            })
            self.assertFalse(begin.is_error, begin.data)
            upload_id = begin.data['upload_id']
            written = plugin_install.cockpit_plugin_install(ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 0,
                'chunk': base64.b64encode(data).decode('ascii'),
            })
            self.assertFalse(written.is_error, written.data)
            with self.assertRaises(contracts.ToolError):
                plugin_install.cockpit_plugin_install(ctx, {
                    'operation': 'commit', 'upload_id': upload_id,
                    'sha256': hashlib.sha256(data).hexdigest(),
                })
            linking.assert_not_called()
            replacing.assert_not_called()
        self.assertEqual(list(app.iterdir()), [])

    def test_install_missing_unicode_denied_name_rejects_before_publish(self):
        app = self.root / 'plugin' / 'app'
        app.mkdir()
        for denied_name, filename in (('Café.opk', 'Café.opk'),
                                      ('Café.opk', 'Café.opk')):
            with self.subTest(denied=denied_name, filename=filename):
                self.assert_install_denied(app, filename, app / denied_name)

    def test_install_missing_denied_name_below_parent_alias_rejects_before_publish(self):
        app = self.root / 'plugin' / 'Café Packages'
        app.mkdir()
        for alias_name in ('CAFEPA~1', 'Café Packages'):
            aliases = {alias_name: app.name}
            alias_path = app.parent / alias_name
            for alias_is_host_root in (False, True):
                with self.subTest(alias=alias_name, alias_is_host_root=alias_is_host_root):
                    denied_parent = app if alias_is_host_root else alias_path
                    self.assert_install_denied(
                        app, 'Café.opk', denied_parent / 'Café.opk', aliases=aliases,
                        package_path=alias_path if alias_is_host_root else app)

    def test_install_unresolved_dos_alias_denial_rejects_before_publish(self):
        app = self.root / 'plugin' / 'app'
        app.mkdir()
        recognize = fs._unresolved_short_alias

        def windows_alias(name):
            # 仅模拟 Windows 的未解析短名策略；实际文件 I/O 仍使用本机安全后端。
            with patch.object(fs, '_WINDOWS', True):
                return recognize(name)

        with patch.object(fs, '_unresolved_short_alias', side_effect=windows_alias):
            self.assert_install_denied(app, 'HelloWorld.opk', app / 'HELLOW~1.OPK')

    def test_unresolved_dos_alias_rule_only_blocks_windows_sibling_publication(self):
        app = self.root / 'plugin' / 'app'
        app.mkdir()
        (app / 'child').mkdir()
        (app / 'existing.json').write_bytes(b'{}')
        self.snapshot = replace(self.snapshot, denied_paths=(str(app / 'HELLOW~1.OPK'),))
        parent = self.opened(app, self.ctx)
        recognize = fs._unresolved_short_alias

        def windows_alias(name):
            with patch.object(fs, '_WINDOWS', True):
                return recognize(name)

        with patch.object(fs, '_unresolved_short_alias', side_effect=windows_alias):
            for name in ('HelloWorld.opk', 'existing.json'):
                with self.subTest(name=name), self.assertRaises(contracts.ToolError):
                    fs.authorize_rel(parent, name, write=True)
            with self.assertRaises(contracts.ToolError):
                fs.authorize_path(self.ctx, str(app / 'existing.json'), write=True)
            for name, write in (('HelloWorld.opk', False), ('existing.json', False),
                                ('child/HelloWorld.opk', True)):
                with self.subTest(name=name, write=write):
                    self.assertEqual(fs.authorize_rel(parent, name, write=write), str(app / name))
        with patch.object(fs, '_WINDOWS', False):
            self.assertFalse(recognize('HELLOW~1.OPK'))

    def test_missing_denied_subtree_checks_parent_identity_and_remaining_components(self):
        parent = self.data / 'Long Package Root'
        parent.mkdir()
        self.snapshot = replace(self.snapshot, denied_paths=(str(parent / 'missing' / 'Café.opk'),))
        root = self.opened(self.data, self.ctx)
        opening = fs.open_file

        def alias(name, *args, **kwargs):
            return opening(parent.name if name == 'LONGPA~1' else name, *args, **kwargs)

        with patch.object(fs, 'open_file', side_effect=alias):
            for relative in ('LONGPA~1/missing/Café.opk', 'LONGPA~1/missing/Café.opk/child'):
                with self.subTest(relative=relative), self.assertRaises(contracts.ToolError):
                    fs.authorize_rel(root, relative, write=True)
            self.assertEqual(fs.authorize_rel(root, 'LONGPA~1/missing/Café.opk-safe', write=True),
                             str(self.data / 'LONGPA~1' / 'missing' / 'Café.opk-safe'))

    def test_unicode_denial_key_never_widens_trusted_roots(self):
        ctx = replace(self.ctx, root=str(self.root / 'Café'), data_root=str(self.root / 'Café'))
        with self.assertRaisesRegex(contracts.ToolError, 'outside the trusted'):
            fs._path_policy(ctx, str(self.root / 'Café' / 'config.json'))

    def test_listing_hides_unicode_denied_leaf_below_parent_alias(self):
        parent = self.data / 'Long Package Root'
        parent.mkdir()
        (parent / 'Café.json').write_bytes(b'{}')
        self.snapshot = replace(self.snapshot, denied_paths=(str(self.data / 'LONGPA~1' / 'Café.json'),))
        root = self.opened(parent, self.ctx)
        opening = fs.open_file

        def alias(name, *args, **kwargs):
            return opening(parent.name if name == 'LONGPA~1' else name, *args, **kwargs)

        with patch.object(fs, 'open_file', side_effect=alias):
            self.assertEqual(fs.scan_dir(root), ([], False, 1))
            with self.assertRaises(contracts.ToolError):
                fs.read_at(root, 'Café.json')

    def test_listing_hides_protected_alias_object(self):
        parent = self.opened(self.data, self.ctx)
        own = self.opened(self.control.parent)
        entry = types.SimpleNamespace(name='OLIVOS~1', stat=Mock(return_value=fs.fstat(own)))
        with patch.object(fs, 'scandir', return_value=contextlib.nullcontext(iter([entry]))):
            entries, more, blocked = fs.scan_dir(parent)
        self.assertEqual((entries, more, blocked), ([], False, 1))

    def test_account_archive_cannot_alias_a_boot_configuration(self):
        conf = self.root / 'conf'
        conf.mkdir()
        path = conf / 'basic.json'
        raw = json.dumps({
            'models': {'OlivOS_account_config': {
                'enable': True, 'type': 'account_config', 'name': 'OlivOS_account_config',
                'data': {'path': './conf/BASIC~1.JSON'},
            }},
            'account': [{'enable': False}],
        }).encode('utf-8')
        path.write_bytes(raw)
        opening = fs.open_file

        def alias(name, *args, **kwargs):
            return opening('basic.json' if name == 'BASIC~1.JSON' else name, *args, **kwargs)

        with patch.object(fs, 'open_file', side_effect=alias):
            with self.assertRaisesRegex(contracts.ToolError, 'Boot configuration files'):
                account_write.cockpit_accounts_update(self.ctx, {
                    'index': 0, 'changes': {'enable': True},
                    'expected_sha256': hashlib.sha256(raw).hexdigest(),
                })
        self.assertEqual(path.read_bytes(), raw)

    def test_absolute_low_level_open_does_not_allow_truncation(self):
        path = self.root / 'config.json'
        path.write_bytes(b'original')
        fd = fs.open_file(str(path), os.O_RDONLY, directory=False)
        try:
            self.assertEqual(fs.read(fd, 16), b'original')
        finally:
            fs.close(fd)
        with self.assertRaises(OSError):
            fs.open_file(str(path), os.O_WRONLY | os.O_TRUNC, directory=False)
        self.assertEqual(path.read_bytes(), b'original')

    @contextlib.contextmanager
    def readonly_permission_boundary(self):
        from OlivOSCockpit import _winfs as native

        api = types.SimpleNamespace(SetKernelObjectSecurity=Mock())
        borrowed, attributes = Mock(), Mock()

        def preserve(staged, original):
            self.assertTrue(fs.fstat(staged).st_mode & 0o200)
            metadata = types.SimpleNamespace(st_mode=original.st_mode,
                                            _win_attributes=native._READONLY,
                                            _win_security=b'simulated-owner-group-dacl')
            # 只隔离权限复制边界，Windows 上其余真实 I/O 仍使用原生 API。
            with patch.object(native, '_security_parts', return_value=(b'owner', b'group', b'dacl', 0)), \
                    patch.object(native, '_api', api), \
                    patch.object(native, '_borrow', borrowed), \
                    patch.object(native, '_set_information', attributes):
                return native.preserve_permissions(staged, metadata)

        with patch.object(fs, 'preserve_permissions', side_effect=preserve) as preserving:
            yield preserving
        borrowed.assert_not_called()
        api.SetKernelObjectSecurity.assert_not_called()
        attributes.assert_not_called()

    def test_full_readonly_update_rejects_before_permissions_and_leaves_no_temp(self):
        parent = self.data / 'Demo'
        parent.mkdir()
        path = parent / 'config.json'
        original = b'{"old":true}'
        path.write_bytes(original)
        path.chmod(0o444)
        self.addCleanup(path.chmod, 0o600)
        unrelated = parent / '.cockpit-unrelated.tmp'
        unrelated.write_bytes(b'keep')
        with self.readonly_permission_boundary() as preserving, \
                patch.object(fs, 'replace', wraps=fs.replace) as replacing:
            with self.assertRaises(contracts.ToolError):
                file_write.cockpit_plugin_file_update(self.ctx, {
                    'namespace': 'Demo', 'path': 'config.json', 'content': '{"new":true}',
                    'expected_sha256': hashlib.sha256(original).hexdigest(),
                })
            preserving.assert_called_once()
            replacing.assert_not_called()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(unrelated.read_bytes(), b'keep')
        self.assertEqual(sorted(item.name for item in parent.iterdir()),
                         ['.cockpit-unrelated.tmp', 'config.json'])

    def test_readonly_listen_port_writeback_fails_and_leaves_no_temp(self):
        manager = config.ConfigManager(str(self.data))
        self.addCleanup(manager.stop)
        manager.refresh()
        manager.refresh()
        path = self.control / config.CONFIG_NAME
        document = json.loads(path.read_bytes())
        document['api_key'] = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8
        original = config._encode(document)
        path.write_bytes(original)
        path.chmod(0o444)
        self.addCleanup(path.chmod, 0o600)
        manager.refresh()
        manager.refresh()
        snapshot = manager.snapshot()
        self.assertTrue(snapshot.ready)
        request = manager.request_listen_port(snapshot.listen_port + 1, snapshot.fingerprint)
        self.assertIsNotNone(request)
        before = sorted(item.name for item in self.control.iterdir())
        with self.readonly_permission_boundary() as preserving, \
                patch.object(fs, 'replace', wraps=fs.replace) as replacing:
            manager.refresh()
            manager._process_write_request()
            self.assertFalse(request.result(0))
            preserving.assert_called_once()
            replacing.assert_not_called()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(sorted(item.name for item in self.control.iterdir()), before)

    def test_config_templates_and_port_writeback_preserve_permissions(self):
        manager = config.ConfigManager(str(self.data))
        manager.refresh()
        manager.refresh()
        self.assertTrue(manager.snapshot().valid)
        parent = manager._control_fd(False)
        self.addCleanup(fs.close, parent)
        raw, identity = config._read_file(parent, config.CONFIG_NAME)
        document = json.loads(raw)
        document['listen_port'] += 1
        encoded = config._encode(document)
        with patch.object(fs, 'preserve_permissions', wraps=fs.preserve_permissions) as preserving:
            result = config._replace_file(parent, config.CONFIG_NAME, encoded, identity)
        preserving.assert_called_once()
        actual, actual_identity = config._read_file(parent, config.CONFIG_NAME)
        self.assertEqual(actual, encoded)
        self.assertEqual(result, actual_identity)
        self.assertFalse(any(path.name.endswith('.tmp') for path in self.control.iterdir()))

    def test_config_permissions_failure_keeps_original_and_cleans_only_owned_temp(self):
        parent = self.opened(self.root)
        path = self.root / 'config.json'
        path.write_bytes(b'original')
        unrelated = self.root / '.config.json.unrelated.tmp'
        unrelated.write_bytes(b'keep')
        raw, identity = config._read_file(parent, 'config.json')
        with patch.object(fs, 'preserve_permissions', side_effect=OSError), self.assertRaises(config.ConfigError):
            config._replace_file(parent, 'config.json', b'replacement', identity)
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(unrelated.read_bytes(), b'keep')
        self.assertEqual(sorted(item.name for item in self.root.glob('.*.tmp')), [unrelated.name])

    def test_config_short_write_and_cancellation_cleanup(self):
        parent = self.opened(self.root)
        for behavior, expected in (({'return_value': 0}, config.ConfigError),
                                   ({'side_effect': asyncio.CancelledError}, asyncio.CancelledError)):
            with self.subTest(behavior=behavior):
                with patch.object(fs, 'write', **behavior), self.assertRaises(expected):
                    config._create_new(parent, 'new.json', b'data')
                self.assertFalse((self.root / 'new.json').exists())
                self.assertEqual(list(self.root.glob('.*.tmp')), [])


if __name__ == '__main__':
    unittest.main()
