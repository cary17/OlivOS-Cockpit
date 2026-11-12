"""共享文件边界：直接原语与工具必须遵守同一策略。"""

import json
import os
import sys
import tempfile
import types
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import config, contracts, files, fs, redaction


class Manager:
    def __init__(self, **values):
        self.current = config.Snapshot(valid=True, generation=1, **values)

    def snapshot(self):
        return self.current


def host_stub(plugin_path='./plugin/app/'):
    return types.SimpleNamespace(pluginAPI=types.SimpleNamespace(plugin_path=plugin_path))


class PathPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='cockpit-policy-')
        self.addCleanup(directory.cleanup)
        self.root = Path(os.path.realpath(directory.name))
        self.data = self.root / 'plugin/data'
        self.ns = self.data / 'Demo'
        self.ns.mkdir(parents=True)
        self.control = Path(config.control_dir(str(self.data)))
        self.control.mkdir(parents=True)
        (self.control / config.CONFIG_NAME).write_text('{"secret":"private"}', encoding='utf-8')
        (self.control / config.REDACTION_NAME).write_text('{}', encoding='utf-8')
        (self.control / '.pending.tmp').write_text('private', encoding='utf-8')
        self.app = self.root / 'plugin/app'
        self.app.mkdir()
        self.logs = self.root / 'logfile'
        self.logs.mkdir()
        self.manager = Manager(redaction_enabled=False, full_real_account_write=True)
        self.ctx = contracts.Context(None, str(self.root), str(self.data),
                                     olivos=host_stub(), config=self.manager)

    def fd(self, path=None):
        fd = fs.open_root(str(path or self.root), context=self.ctx)
        self.addCleanup(fs.close, fd)
        return fd

    def deny(self, *paths):
        self.manager.current = replace(self.manager.current, denied_paths=paths, generation=2)

    def package(self, path, namespace):
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('app.json', json.dumps({'namespace': namespace}))

    def test_control_and_temporary_files_rejected_before_io(self):
        root = self.fd()
        for name in ('', config.CONFIG_NAME, config.REDACTION_NAME, '.pending.tmp'):
            absolute = str(self.control / name)
            with self.subTest(name=name), patch.object(fs, '_walk') as walk:
                with self.assertRaises(contracts.ToolError):
                    fs.authorize_path(self.ctx, absolute)
                walk.assert_not_called()
                with self.assertRaises(contracts.ToolError):
                    fs.open_rel(root, os.path.relpath(absolute, self.root))
                walk.assert_not_called()
        data_fd = self.fd(self.data)
        entries, _ = fs.list_dir(data_fd)
        self.assertNotIn('OlivOSCockpit', [entry['name'] for entry in entries])

    def test_internal_configuration_reads_still_work(self):
        root = fs.open_root(str(self.data))
        try:
            raw, _, _ = fs.read_at(root, 'OlivOSCockpit/control/config.json')
        finally:
            fs.close(root)
        self.assertIn(b'private', raw)
        manager = config.ConfigManager(str(self.data))
        manager.refresh()
        self.assertFalse(manager.snapshot().valid)  # 测试文件并非合法配置模板。
        (self.control / config.CONFIG_NAME).write_text(json.dumps(config.config_template()), encoding='utf-8')
        manager.refresh()
        manager.refresh()
        self.assertTrue(manager.snapshot().valid)

    def test_absolute_and_runtime_relative_denials_reach_all_readers(self):
        target = self.ns / 'secret.txt'
        target.write_text('private', encoding='utf-8')
        for deny in (str(target), 'plugin/data/Demo/secret.txt'):
            self.deny(deny)
            fd = self.fd(self.data)
            for reader in (fs.read_at, fs.read_tail, fs.read_package):
                with self.subTest(deny=deny, reader=reader.__name__), self.assertRaises(contracts.ToolError):
                    reader(fd, 'Demo/secret.txt')
            with self.assertRaises(contracts.ToolError):
                fs.authorize_path(self.ctx, str(target))
            entries, _ = fs.list_dir(self.fd(self.ns))
            self.assertEqual(entries, [])

    def test_denial_matching_is_casefolded_and_component_based(self):
        # 大小写不敏感文件系统上同一文件有多个拼写；两侧 casefold 后再做组件判断。
        target = self.ns / 'secret.txt'
        target.write_text('private', encoding='utf-8')
        (self.ns / 'Hidden').mkdir()
        (self.ns / 'Hidden' / 'x.txt').write_text('private', encoding='utf-8')
        for deny in ('plugin/data/DEMO/SECRET.TXT', str(target).upper()):
            self.deny(deny)
            with self.assertRaises(contracts.ToolError):
                fs.authorize_path(self.ctx, str(target))
            for reader in (fs.read_at, fs.read_tail, fs.read_package):
                with self.subTest(deny=deny, reader=reader.__name__), self.assertRaises(contracts.ToolError):
                    reader(self.fd(self.data), 'Demo/secret.txt')
            entries, _ = fs.list_dir(self.fd(self.ns))
            self.assertNotIn('secret.txt', [entry['name'] for entry in entries])
        self.deny('plugin/data/demo/HIDDEN')
        with self.assertRaises(contracts.ToolError):
            fs.authorize_path(self.ctx, str(self.ns / 'Hidden' / 'x.txt'))
        with self.assertRaises(contracts.ToolError):
            files.cockpit_data(self.ctx, {'namespace': 'Demo', 'path': 'Hidden',
                                          'mode': 'read'})
        (self.ns / 'hidden-safe').mkdir()
        safe = self.ns / 'hidden-safe' / 'ok.txt'
        safe.write_text('ok', encoding='utf-8')
        self.assertEqual(fs.authorize_path(self.ctx, str(safe)), str(safe))

    def test_casefold_denial_never_widens_allowed_roots(self):
        # 大小写归一只能收紧拒绝集，不能授权根外路径（含大小写变体拼写）。
        self.deny(str(self.root.with_name(self.root.name + '-unrelated')))
        directory = tempfile.TemporaryDirectory(prefix=self.root.name + '-sibling-')
        self.addCleanup(directory.cleanup)
        outside = Path(os.path.realpath(directory.name))
        (outside / 'x').write_text('x', encoding='utf-8')
        for path in (str(outside / 'x'), str(outside / 'x').upper()):
            with self.assertRaises(contracts.ToolError):
                fs.authorize_path(self.ctx, path)
        self.deny(str(outside).upper())
        with self.assertRaises(contracts.ToolError):
            fs.authorize_path(self.ctx, str(outside / 'x'))
        nested = self.ns / 'Sub'
        nested.mkdir()
        (nested / 'ok').write_text('ok', encoding='utf-8')
        self.assertEqual(fs.authorize_path(self.ctx, str(nested / 'ok')),
                         str(nested / 'ok'))

    def test_denial_is_component_based_and_never_expands_roots(self):
        (self.ns / 'hidden').mkdir()
        (self.ns / 'hidden-safe').mkdir()
        target = self.ns / 'hidden-safe/ok.txt'
        target.write_text('ok', encoding='utf-8')
        self.deny('plugin/data/Demo/hidden',
                  str(self.root.with_name(self.root.name + '-unrelated')))
        self.assertEqual(fs.authorize_path(self.ctx, str(target)), str(target))
        for path in ('/etc/passwd', str(self.root) + '-sibling/file', 'plugin/data/Demo/ok.txt',
                     str(self.root / '../outside')):
            with self.subTest(path=path), self.assertRaises(contracts.ToolError):
                fs.authorize_path(self.ctx, path)

    def test_normal_nested_unicode_paths_and_explicit_data_root(self):
        nested = self.ns / 'sub dir/中文'
        nested.mkdir(parents=True)
        (nested / 'ok.txt').write_text('正常', encoding='utf-8')
        outcome = files.cockpit_data(self.ctx, {'namespace': 'Demo', 'path': './sub dir/中文/ok.txt', 'mode': 'read'})
        self.assertEqual(outcome.data['content'], '正常')
        # 单独提供的可信宿主数据根可以与运行数据基准不同，不从客户端扩展。
        self.ctx = replace(self.ctx, root=str(self.logs))
        self.assertEqual(fs.authorize_path(self.ctx, str(nested / 'ok.txt')), str(nested / 'ok.txt'))

    def test_held_file_and_directory_recheck_current_denial(self):
        (self.ns / 'x').write_bytes(b'private')
        parent = self.fd(self.ns)
        fd, _ = fs.open_rel(parent, 'x')
        self.addCleanup(fs.close, fd)
        self.deny(str(self.ns / 'x'))
        with patch.object(fs, 'read') as read:
            with self.assertRaises(contracts.ToolError):
                fs.read_fd(fd)
            read.assert_not_called()
        self.deny(str(self.ns))
        with self.assertRaises(contracts.ToolError):
            fs.list_dir(parent)

    def test_hard_link_aliases_filtered_from_data_logs_and_packages(self):
        secret = self.control / config.CONFIG_NAME
        for path in (self.ns / 'alias.json', self.logs / 'private.log', self.app / 'private.opk'):
            try:
                os.link(secret, path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('hard links are unavailable: ' + str(exc))
            with self.assertRaises(contracts.ToolError):
                fs.authorize_path(self.ctx, str(path))
        entries = files.cockpit_data(self.ctx, {'namespace': 'Demo'}).data['entries']
        self.assertEqual(entries, [])
        with self.assertRaises(contracts.ToolError):
            files.cockpit_log(self.ctx, {'filename': 'private.log'})
        with self.assertRaises(contracts.ToolError):
            files.cockpit_log(self.ctx, {})
        self.assertEqual(files.cockpit_plugins(self.ctx, {}).data['plugins'], [])
        with self.assertRaises(contracts.ToolError):
            files.cockpit_meta(self.ctx, {'filename': 'private.opk'})
        unpacked = self.app / 'Private'
        unpacked.mkdir()
        os.link(secret, unpacked / 'app.json')
        self.assertEqual(files.cockpit_plugins(self.ctx, {}).data['plugins'], [])

    def test_package_root_comes_from_host_path_not_client_or_cwd(self):
        self.package(self.app / 'Demo.opk', 'Demo')
        self.assertEqual(files.cockpit_plugins(self.ctx, {}).data['plugins'][0]['filename'],
                         'Demo.opk')
        # 宿主声明的绝对包根可位于运行 cwd 之外，仍受同一策略与包根身份约束。
        outside = tempfile.TemporaryDirectory(prefix='cockpit-package-root-')
        self.addCleanup(outside.cleanup)
        external = Path(os.path.realpath(outside.name)) / 'app'
        external.mkdir()
        self.package(external / 'Outside.opk', 'Outside')
        ctx = replace(self.ctx, olivos=host_stub(str(external)))
        plugins = files.cockpit_plugins(ctx, {}).data['plugins']
        self.assertEqual([item['filename'] for item in plugins], ['Outside.opk'])
        # 缺能力或根为符号链接时安全失败，不猜目录。
        with self.assertRaises(contracts.ToolError):
            files.cockpit_plugins(replace(self.ctx, olivos=None), {})
        link = Path(os.path.realpath(outside.name)) / 'link'
        try:
            link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('directory symlinks are unavailable: ' + str(exc))
        with self.assertRaises(contracts.ToolError):
            files.cockpit_plugins(replace(self.ctx, olivos=host_stub(str(link))), {})
        self.deny(str(external))
        with self.assertRaises(contracts.ToolError):
            files.cockpit_plugins(ctx, {})

    def test_manifest_and_package_scans_hide_denied_names_and_metadata(self):
        self.package(self.app / 'Hidden.opk', 'Hidden')
        self.package(self.app / 'Visible.opk', 'Visible')
        source = self.app / 'Source'
        source.mkdir()
        (source / 'app.json').write_text('{"namespace":"Hidden"}', encoding='utf-8')
        self.deny('plugin/app/Hidden.opk', 'plugin/app/Source/app.json')
        plugins = files.cockpit_plugins(self.ctx, {}).data['plugins']
        self.assertEqual([item['filename'] for item in plugins], ['Visible.opk'])
        with self.assertRaises(contracts.ToolError):
            files.cockpit_meta(self.ctx, {'namespace': 'Hidden'})
        for name in ('Hidden.opk', 'Source'):
            with self.assertRaises(contracts.ToolError):
                files.cockpit_meta(self.ctx, {'filename': name})

    def test_metadata_is_readable_by_default_in_lite(self):
        self.package(self.app / 'Demo.opk', 'Demo')
        ctx = replace(self.ctx, permission_mode=contracts.MODE_LITE)
        self.assertEqual(files.cockpit_plugins(ctx, {}).data['plugins'][0]['filename'], 'Demo.opk')
        self.assertEqual(files.cockpit_meta(ctx, {'namespace': 'Demo'}).data['manifest']['namespace'], 'Demo')
        self.assertTrue(files.cockpit_data(ctx, {'namespace': 'Demo'}).is_error)
        self.assertTrue(files.cockpit_log(ctx, {}).is_error)
        self.assertIsNone(files.TOOLS[0].required_permission)
        self.assertIsNone(files.TOOLS[3].required_permission)

    @unittest.skipUnless(os.name == 'posix', 'POSIX os.open dir_fd race injection')
    def test_leaf_swapped_to_symlink_or_hardlink_never_reads_secret(self):
        target = self.ns / 'target'
        secret = self.control / config.CONFIG_NAME
        fd = self.fd(self.ns)
        real_open = os.open
        for hard in (False, True):
            target.write_bytes(b'ok')
            changed = []

            def racing_open(path, flags, *args, **kwargs):
                if path == 'target' and not changed:
                    changed.append(True)
                    target.unlink()
                    if hard:
                        os.link(secret, target)
                    else:
                        target.symlink_to(secret)
                return real_open(path, flags, *args, **kwargs)

            os.supports_dir_fd.add(racing_open)
            try:
                with patch.object(os, 'open', racing_open), patch.object(fs, 'read') as read:
                    with self.assertRaises(contracts.ToolError):
                        fs.read_at(fd, 'target')
                    read.assert_not_called()
            finally:
                os.supports_dir_fd.discard(racing_open)
                target.unlink(missing_ok=True)
            self.assertTrue(changed)

    def test_held_handle_rejects_replaced_ancestor(self):
        nested = self.ns / 'sub'
        nested.mkdir()
        (nested / 'ok.txt').write_bytes(b'ok')
        fd, _ = fs.open_rel(self.fd(self.ns), 'sub/ok.txt')
        self.addCleanup(fs.close, fd)
        moved = self.ns / 'moved'
        if os.name == 'nt':
            # Native ancestor handles prevent the redirect before it can occur.
            with self.assertRaises(PermissionError) as caught:
                nested.rename(moved)
            self.assertEqual(caught.exception.winerror, 32)
            self.assertTrue(nested.is_dir())
            self.assertFalse(moved.exists())
            self.assertEqual(fs.read_fd(fd), (b'ok', 2, False))
            fs.close(fd)
            nested.rename(moved)
            self.assertFalse(nested.exists())
            self.assertEqual((moved / 'ok.txt').read_bytes(), b'ok')
            return
        nested.rename(moved)
        try:
            nested.symlink_to(self.control, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('directory symlinks are unavailable: ' + str(exc))
        with self.assertRaises(contracts.ToolError):
            fs.read_fd(fd)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO is unavailable on this platform')
    def test_fifo_is_rejected(self):
        pipe = self.ns / 'pipe'
        try:
            os.mkfifo(pipe)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('FIFO creation is unavailable: ' + str(exc))
        with self.assertRaises(contracts.ToolError):
            fs.authorize_path(self.ctx, str(pipe))
        parent = self.fd(self.ns)
        with self.assertRaises(contracts.ToolError):
            fs.read_at(parent, 'pipe')

    def test_missing_primitives_fail_safely(self):
        parent = self.fd(self.ns)
        with patch.object(fs, 'supported', return_value=False):
            for fn, args in ((fs.authorize_path, (self.ctx, str(self.ns / 'missing'))),
                             (fs.open_root, (str(self.root), self.ctx)),
                             (fs.open_rel, (parent, 'x')), (fs.list_dir, (parent,)),
                             (fs.read_fd, (parent,))):
                with self.subTest(function=fn.__name__), self.assertRaises(contracts.ToolError):
                    fn(*args)

    def test_invalid_snapshot_and_rules_fail_closed(self):
        self.manager.current = config.Snapshot(valid=False)
        with self.assertRaises(contracts.ToolError):
            self.fd()
        self.manager.current = replace(self.manager.current, valid=True, denied_paths=('bad\x00path',))
        with self.assertRaises(contracts.ToolError):
            self.fd()


class RuleLimitTests(unittest.TestCase):
    def test_rules_fit_redaction_engine_without_silent_drops(self):
        self.assertEqual(config.MAX_RULES, redaction.MAX_FIELDS)
        self.assertEqual(config.MAX_RULE_CHARS, redaction.MAX_FIELD)
        fields = ['field' + str(index) for index in range(redaction.MAX_FIELDS)]
        values = config._redaction_values({'redact_fields': fields, 'allow_fields': ['x' * redaction.MAX_FIELD]})
        self.assertEqual(len(redaction.policy(values).redact_fields), len(fields))
        for name in ('redact_fields', 'allow_fields'):
            for entries in (fields + ['overflow'], ['x' * (redaction.MAX_FIELD + 1)], ['ß' * redaction.MAX_FIELD]):
                with self.subTest(name=name, size=len(entries)), self.assertRaises(config.ConfigError):
                    config._redaction_values({name: entries})

    def test_invalid_control_roots_are_protected(self):
        for root in ('relative', '/tmp/../elsewhere', None, ''):
            with self.subTest(root=root):
                self.assertIsNone(config.control_dir(root))
                self.assertTrue(config.is_protected(root, 'config.json'))


if __name__ == '__main__':
    unittest.main()
