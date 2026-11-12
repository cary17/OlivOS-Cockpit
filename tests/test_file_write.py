"""Full 文件配置写入：修订、权限、原子替换及失败清理。"""

import hashlib
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import config, contracts, file_write, files, fs


class Manager:
    def __init__(self):
        self.current = config.Snapshot(valid=True, full_real_account_write=True, generation=1)

    def snapshot(self):
        return self.current


class FileWriteTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='cockpit-write-')
        self.addCleanup(directory.cleanup)
        self.root = Path(os.path.realpath(directory.name))
        self.data = self.root / 'plugin/data'
        self.parent = self.data / 'Demo/sub dir/中文'
        self.parent.mkdir(parents=True)
        self.target = self.parent / 'config.json'
        self.original = b'{"value":"old"}\n'
        self.target.write_bytes(self.original)
        self.target.chmod(0o640)
        self.manager = Manager()
        self.ctx = contracts.Context(None, str(self.root), str(self.data), config=self.manager)

    def args(self, **values):
        args = {'namespace': 'Demo', 'path': 'sub dir/中文/config.json',
                'expected_sha256': hashlib.sha256(self.original).hexdigest(), 'content': '{"value":"new"}\n'}
        args.update(values)
        return args

    def update(self, **values):
        return file_write.cockpit_plugin_file_update(self.ctx, self.args(**values))

    def assert_unchanged(self):
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def during_sync(self, action):
        real = fs.fsync
        calls = []

        def fsync(fd):
            result = real(fd)
            if not calls:
                calls.append(True)
                action()
            return result

        return patch.object(fs, 'fsync', fsync)

    def test_revision_from_complete_read_and_persistent_replace(self):
        old = self.target.stat()
        read = files.cockpit_data(self.ctx, {'namespace': 'Demo', 'mode': 'read', 'path': self.args()['path']})
        outcome = self.update(expected_sha256=read.data['sha256'])
        self.assertEqual(self.target.read_text(encoding='utf-8'), self.args()['content'])
        self.assertNotEqual(self.target.stat().st_ino, old.st_ino)
        if os.name == 'posix':
            self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertTrue(outcome.data['persisted'])
        self.assertEqual(outcome.data['durability'], 'unknown' if os.name == 'nt' else 'synced')
        self.assertEqual(outcome.data['namespace'], 'Demo')
        self.assertFalse(outcome.data['reloaded'])
        self.assertIsNone(outcome.after_send)
        self.assertEqual(outcome.data['sha256'], hashlib.sha256(self.target.read_bytes()).hexdigest())
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def test_partial_writes_keep_staging_private_until_content_is_complete(self):
        content = self.args()['content'].encode('utf-8')
        real_write = fs.write
        real_preserve = fs.preserve_permissions
        writes = []

        def write(fd, chunk):
            info = fs.fstat(fd)
            if os.name == 'posix':
                self.assertEqual(info.st_mode & 0o777, 0o600)
            writes.append(info.st_size)
            return real_write(fd, chunk[:4])

        def preserve(fd, original):
            self.assertEqual(fs.fstat(fd).st_size, len(content))
            return real_preserve(fd, original)

        with patch.object(fs, 'write', write), patch.object(fs, 'preserve_permissions', preserve):
            outcome = self.update()
        self.assertGreater(len(writes), 1)
        self.assertEqual(writes[0], 0)
        self.assertTrue(outcome.data['persisted'])
        self.assertEqual(self.target.read_bytes(), content)
        if os.name == 'posix':
            self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def test_all_documented_text_suffixes(self):
        for suffix in ('.ini', '.toml', '.yaml', '.yml', '.conf', '.cfg', '.JSON'):
            target = self.parent / ('other' + suffix)
            target.write_bytes(self.original)
            content = '[section]\nvalue=新值\n' if suffix != '.JSON' else '[1,true,null,"新值"]'
            with self.subTest(suffix=suffix):
                outcome = self.update(path='sub dir/中文/' + target.name, content=content)
                self.assertTrue(outcome.data['persisted'])
                self.assertEqual(target.read_text(encoding='utf-8'), content)

    def test_full_write_is_required_even_for_direct_handler(self):
        for current, mode in ((config.Snapshot(valid=True), contracts.MODE_FULL),
                              (config.Snapshot(valid=False, full_real_account_write=True), contracts.MODE_FULL),
                              (self.manager.current, contracts.MODE_LITE)):
            self.manager.current = current
            ctx = replace(self.ctx, permission_mode=mode)
            with self.subTest(mode=mode, valid=current.valid), self.assertRaises(contracts.ToolError):
                file_write.cockpit_plugin_file_update(ctx, self.args())
            self.assert_unchanged()
        with self.assertRaises(contracts.ToolError):
            file_write.cockpit_plugin_file_update(replace(self.ctx, config=None), self.args())

    def test_required_revision_and_revision_conflict(self):
        args = self.args()
        del args['expected_sha256']
        with self.assertRaises(contracts.ToolError):
            file_write.cockpit_plugin_file_update(self.ctx, args)
        for expected in ('0' * 64, 'x' * 64, 'short'):
            with self.subTest(expected=expected), self.assertRaises(contracts.ToolError):
                self.update(expected_sha256=expected)
            self.assert_unchanged()

    def test_write_cannot_create_files_or_directories(self):
        for path in ('new.json', 'missing/new.json'):
            with self.subTest(path=path), self.assertRaises(contracts.ToolError):
                self.update(path=path)
        self.assertFalse((self.data / 'Demo/new.json').exists())
        self.assertFalse((self.data / 'Demo/missing').exists())
        self.assert_unchanged()

    def test_control_namespace_denials_and_outside_paths(self):
        for namespace in ('OlivOSCockpit', 'olivoscockpit', '.', '..', '/tmp', 'a/b', 'a\\b', 'C:'):
            with self.subTest(namespace=namespace), self.assertRaises(contracts.ToolError):
                self.update(namespace=namespace)
        for path in ('../config.json', 'a/../../config.json', '/etc/config.json', 'C:/config.json', '..\\config.json'):
            with self.subTest(path=path), self.assertRaises(contracts.ToolError):
                self.update(path=path)
        for denied in (str(self.target), 'plugin/data/Demo/sub dir'):
            self.manager.current = replace(self.manager.current, denied_paths=(denied,), redaction_enabled=False)
            with self.subTest(denied=denied), self.assertRaises(contracts.ToolError):
                self.update()
        self.assert_unchanged()

    def test_code_packages_databases_and_executable_configs_are_rejected(self):
        for suffix in ('.py', '.pyc', '.so', '.pth', '.opk', '.zip', '.db', '.txt'):
            target = self.parent / ('code' + suffix)
            target.write_bytes(self.original)
            with self.subTest(suffix=suffix), self.assertRaises(contracts.ToolError):
                self.update(path='sub dir/中文/' + target.name)
            self.assertEqual(target.read_bytes(), self.original)
        if os.name == 'posix':
            self.target.chmod(0o755)
            with self.assertRaises(contracts.ToolError):
                self.update()
            self.assert_unchanged()

    def test_content_is_bounded_utf8_and_strict_json(self):
        for content in ('NaN', 'Infinity', '{"x":1,"x":2}', '{} trailing', '\ufeff{}', '\ud800',
                        '中' * (contracts.MAX_FILE // 3 + 1)):
            with self.subTest(length=len(content)), self.assertRaises(contracts.ToolError):
                self.update(content=content)
            self.assert_unchanged()
        self.assertTrue(self.update(content='{"large":1e999}').data['persisted'])

    def test_original_must_be_complete_bounded_utf8(self):
        for raw in (b'\xff', b' ' * (contracts.MAX_FILE + 1)):
            self.target.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises(contracts.ToolError):
                self.update(expected_sha256=hashlib.sha256(raw).hexdigest())
            self.assertEqual(self.target.read_bytes(), raw)
            self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])
        read = files.cockpit_data(self.ctx, {'namespace': 'Demo', 'mode': 'read', 'path': self.args()['path']})
        self.assertTrue(read.truncated)
        self.assertNotIn('sha256', read.data)

    def test_symlink_target_is_rejected(self):
        outside = self.root / 'outside.json'
        outside.write_bytes(self.original)
        self.target.unlink()
        try:
            self.target.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('file symlinks are unavailable: ' + str(exc))
        with self.assertRaises(contracts.ToolError):
            self.update()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO is unavailable on this platform')
    def test_fifo_target_is_rejected(self):
        self.target.unlink()
        try:
            os.mkfifo(self.target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('FIFO creation is unavailable: ' + str(exc))
        with self.assertRaises(contracts.ToolError):
            self.update()

    def test_hardlink_target_is_rejected(self):
        outside = self.root / 'outside.json'
        outside.write_bytes(self.original)
        self.target.unlink()
        try:
            os.link(outside, self.target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('hard links are unavailable: ' + str(exc))
        with self.assertRaises(contracts.ToolError):
            self.update()
        self.assertEqual(outside.read_bytes(), self.original)

    def test_changed_generation_revoked_write_or_added_deny_prevents_commit(self):
        start = self.manager.current
        for values in ({'generation': 2}, {'full_real_account_write': False}, {'denied_paths': (str(self.target),)}):
            self.manager.current = start

            def revoke():
                self.manager.current = replace(start, **values)

            with self.subTest(values=values), self.during_sync(revoke), self.assertRaises(contracts.ToolError):
                self.update()
            self.assert_unchanged()

    def test_same_content_replacement_identity_conflict_does_not_overwrite(self):
        def swap():
            staged = self.parent / 'external.json'
            staged.write_bytes(self.original)
            staged.chmod(0o640)
            os.replace(staged, self.target)

        with self.during_sync(swap), self.assertRaises(contracts.ToolError):
            self.update()
        self.assert_unchanged()

    def test_in_place_content_change_with_restored_mtime_is_not_overwritten(self):
        original_stat = self.target.stat()
        changed = b'{"value":"external"}\n'

        def mutate():
            self.target.write_bytes(changed)
            os.utime(self.target, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

        with self.during_sync(mutate), self.assertRaises(contracts.ToolError):
            self.update()
        self.assertEqual(self.target.read_bytes(), changed)
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def test_ancestor_swap_to_symlink_cannot_redirect_replace(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / self.target.name).write_bytes(b'private')
        moved = self.parent.with_name('moved')
        parent_identity, target_identity = self.parent.stat(), self.target.stat()
        rename_errors = []

        def swap():
            try:
                self.parent.rename(moved)
            except OSError as error:
                rename_errors.append(error)
                raise
            self.parent.symlink_to(outside, target_is_directory=True)

        if os.name != 'nt':
            probe = self.root / 'symlink-probe'
            try:
                probe.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('directory symlinks are unavailable: ' + str(exc))
            probe.unlink()
        with self.during_sync(swap), self.assertRaises(contracts.ToolError):
            self.update()
        if os.name == 'nt':
            self.assertEqual([error.winerror for error in rename_errors], [32])
            self.assertFalse(moved.exists())
            self.assertFalse(self.parent.is_symlink())
            retained = self.parent
        else:
            self.assertEqual(rename_errors, [])
            self.assertTrue(self.parent.is_symlink())
            retained = moved
        self.assertTrue(os.path.samestat(retained.stat(), parent_identity))
        self.assertTrue(os.path.samestat((retained / self.target.name).stat(), target_identity))
        self.assertEqual((outside / self.target.name).read_bytes(), b'private')
        self.assertEqual((retained / self.target.name).read_bytes(), self.original)
        self.assertEqual(list(retained.glob('.cockpit-*.tmp')), [])

    def test_temporary_name_replacement_is_detected(self):
        outside = self.root / 'outside.json'
        outside.write_bytes(b'private')
        probe = self.root / 'symlink-probe'
        try:
            probe.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('file symlinks are unavailable: ' + str(exc))
        probe.unlink()

        def swap():
            temp = next(self.parent.glob('.cockpit-*.tmp'))
            temp.unlink()
            temp.symlink_to(outside)

        with self.during_sync(swap), self.assertRaises(contracts.ToolError):
            self.update()
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(outside.read_bytes(), b'private')

    def test_staging_content_tamper_does_not_commit(self):
        def mutate():
            next(self.parent.glob('.cockpit-*.tmp')).write_bytes(b'{"tampered":true}')

        with self.during_sync(mutate), self.assertRaises(contracts.ToolError):
            self.update()
        self.assert_unchanged()

    def test_replace_write_and_precommit_sync_failures_cleanup(self):
        for name, behavior in (('replace', {'side_effect': OSError()}),
                               ('write', {'return_value': 0}), ('fsync', {'side_effect': OSError()})):
            with self.subTest(operation=name), patch.object(fs, name, **behavior), self.assertRaises(contracts.ToolError):
                self.update()
            self.assert_unchanged()

    def test_directory_sync_failure_reports_actual_replacement(self):
        real = fs.fsync
        calls = []

        def fsync(fd):
            calls.append(fd)
            if len(calls) == 2:
                raise OSError()
            return real(fd)

        with patch.object(fs, 'fsync', fsync):
            outcome = self.update()
        self.assertTrue(outcome.data['persisted'])
        self.assertEqual(outcome.data['durability'], 'unknown')
        self.assertEqual(self.target.read_text(encoding='utf-8'), self.args()['content'])

    @contextmanager
    def after_replace(self, action):
        """在真实核验前注入，避免注入错误被目录同步的 OSError 降级吞掉。"""
        real = file_write._verify_committed
        completed = []

        def verify(parent, name, staged, content):
            self.assertTrue(os.path.samestat(
                fs.stat_at(name, dir_fd=parent), fs.fstat(staged)))
            self.assertEqual(fs.read_at(parent, name, len(content) + 1)[0], content)
            action(parent, name, staged, content)
            completed.append(True)
            return real(parent, name, staged, content)

        with patch.object(file_write, '_verify_committed', side_effect=verify) as hook:
            try:
                yield
            finally:
                hook.assert_called_once()
                self.assertEqual(completed, [True])

    def test_post_replace_leaf_swap_is_not_reported_as_success(self):
        outside = self.root / 'outside.json'

        def swap(parent, name, staged, content):
            # 正文相同，仅替换身份；原生 unlink 支持仍持有发布句柄的文件。
            outside.write_bytes(content)
            source = fs.open_root(str(self.root))
            try:
                external = fs.stat_at(outside.name, dir_fd=source)
                self.assertFalse(os.path.samestat(external, fs.fstat(staged)))
                fs.unlink(name, dir_fd=parent)
                fs.replace(outside.name, name, src_dir_fd=source, dst_dir_fd=parent)
                current = fs.stat_at(name, dir_fd=parent)
                self.assertTrue(os.path.samestat(current, external))
                self.assertFalse(os.path.samestat(current, fs.fstat(staged)))
            finally:
                fs.close(source)

        with self.after_replace(swap), self.assertRaises(contracts.ToolError) as caught:
            self.update()
        self.assertIn('may have completed', str(caught.exception))
        # 不回滚、不删除外部对象：外部内容保持原样，暂存路径无残留。
        self.assertEqual(self.target.read_bytes(), b'{"value":"new"}\n')
        self.assertFalse(outside.exists())
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def test_post_replace_same_inode_rewrite_is_not_reported_as_success(self):
        changed = b'{"value":"bad"}\n'

        def mutate(parent, name, staged, content):
            self.assertEqual(len(changed), len(content))
            writer = fs.open_file(name, os.O_WRONLY, dir_fd=parent, directory=False)
            try:
                self.assertTrue(os.path.samestat(fs.fstat(writer), fs.fstat(staged)))
                self.assertEqual(fs.write(writer, changed), len(changed))
                self.assertTrue(os.path.samestat(
                    fs.stat_at(name, dir_fd=parent), fs.fstat(staged)))
            finally:
                fs.close(writer)

        with self.after_replace(mutate), self.assertRaises(contracts.ToolError) as caught:
            self.update()
        self.assertIn('may have completed', str(caught.exception))
        # 同 inode 内容改写被核验发现；不回滚，外部写入保持原样。
        self.assertEqual(self.target.read_bytes(), changed)
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def test_post_replace_ancestor_move_is_blocked_or_detected(self):
        moved = self.parent.with_name('moved')
        parent_identity = self.parent.stat()
        committed = []
        rename_errors = []

        def move(parent, name, staged, content):
            current = fs.stat_at(name, dir_fd=parent)
            self.assertEqual(content, b'{"value":"new"}\n')
            try:
                self.parent.rename(moved)
            except OSError as error:
                if os.name != 'nt':
                    raise
                rename_errors.append(error)
            committed.append(current)

        if os.name == 'nt':
            with self.after_replace(move):
                outcome = self.update()
            self.assertTrue(outcome.data['persisted'])
            self.assertEqual(outcome.data['durability'], 'unknown')
            self.assertEqual([error.winerror for error in rename_errors], [32])
            self.assertFalse(moved.exists())
            self.assertFalse(self.parent.is_symlink())
            retained = self.parent
        else:
            with self.after_replace(move), self.assertRaises(contracts.ToolError) as caught:
                self.update()
            self.assertIn('may have completed', str(caught.exception))
            self.assertFalse(self.parent.exists())
            retained = moved
        self.assertEqual(len(committed), 1)
        self.assertTrue(os.path.samestat(retained.stat(), parent_identity))
        retained_fd = fs.open_root(str(retained))
        try:
            self.assertTrue(os.path.samestat(
                fs.stat_at(self.target.name, dir_fd=retained_fd), committed[0]))
        finally:
            fs.close(retained_fd)
        self.assertEqual((retained / self.target.name).read_bytes(), b'{"value":"new"}\n')
        self.assertEqual(list(retained.glob('.cockpit-*.tmp')), [])

    def test_preexisting_temp_prefixed_files_are_never_scanned_or_removed(self):
        decoy = self.parent / '.cockpit-decoy.tmp'
        decoy.write_bytes(b'external debris')
        self.assertTrue(self.update().data['persisted'])
        self.assertEqual(decoy.read_bytes(), b'external debris')
        # 失败路径同样不清扫：修订冲突不触碰既有同前缀文件。
        with self.assertRaises(contracts.ToolError):
            self.update(expected_sha256='0' * 64)
        self.assertEqual(decoy.read_bytes(), b'external debris')
        self.assertEqual([entry.name for entry in self.parent.glob('.cockpit-*.tmp')],
                         ['.cockpit-decoy.tmp'])

    def test_cockpit_writers_are_serialized_and_second_revision_conflicts(self):
        def update(content):
            try:
                return self.update(content=content).data['persisted']
            except contracts.ToolError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(update, ('{"winner":1}', '{"winner":2}')))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(list(self.parent.glob('.cockpit-*.tmp')), [])

    def test_deep_json_is_rejected_before_decode(self):
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(100000)
        try:
            for content in ('[' * 40 + ']' * 40, '{"a":' * 40 + '1' + '}' * 40):
                with self.subTest(length=len(content)), self.assertRaises(contracts.ToolError):
                    self.update(content=content)
                self.assert_unchanged()
        finally:
            sys.setrecursionlimit(old)

    def test_before_replace_runs_before_commit_and_can_abort(self):
        expected = hashlib.sha256(self.original).hexdigest()
        generation = self.manager.current.generation
        root = fs.open_root(str(self.data), context=self.ctx)
        try:
            parent, kind = fs.open_rel(root, 'Demo/sub dir/中文')
        finally:
            fs.close(root)
        self.assertEqual(kind, 'dir')
        seen = []

        def abort():
            seen.append(self.target.read_bytes())
            raise contracts.ToolError('abort before commit')

        try:
            with self.assertRaises(contracts.ToolError):
                file_write._replace(self.ctx, parent, 'config.json', b'{"value":"new"}\n',
                                    expected, generation, before_replace=abort)
        finally:
            fs.close(parent)
        # 回调在替换前执行，原文件仍未被覆盖，暂存文件被清理。
        self.assertEqual(seen, [self.original])
        self.assert_unchanged()

        root = fs.open_root(str(self.data), context=self.ctx)
        try:
            parent, _ = fs.open_rel(root, 'Demo/sub dir/中文')
        finally:
            fs.close(root)
        try:
            outcome = file_write._replace(self.ctx, parent, 'config.json',
                                          b'{"value":"new"}\n', expected, generation,
                                          before_replace=lambda: seen.append('ok'))
        finally:
            fs.close(parent)
        self.assertEqual(seen[-1], 'ok')
        self.assertTrue(outcome.data['persisted'])
        self.assertEqual(self.target.read_text(encoding='utf-8'), '{"value":"new"}\n')

    def test_missing_secure_primitives_and_tool_contract(self):
        with patch.object(fs, 'supported', return_value=False), self.assertRaises(contracts.ToolError):
            self.update()
        self.assert_unchanged()
        with patch.object(fs, 'updates_supported', return_value=False), self.assertRaises(contracts.ToolError):
            self.update()
        self.assert_unchanged()
        self.assertEqual(len(file_write.TOOLS), 1)
        spec = file_write.TOOLS[0]
        self.assertEqual(spec.name, 'cockpit_plugin_file_update')
        self.assertFalse(spec.read_only)
        self.assertEqual(spec.required_permission, config.PERMISSION_REAL_ACCOUNT_WRITE)

    @unittest.skipUnless(os.name == 'posix', 'POSIX dir_fd capability probe')
    def test_missing_posix_rename_dir_fd_support_fails(self):
        with patch.object(os, 'supports_dir_fd', os.supports_dir_fd - {os.rename}), \
                self.assertRaises(contracts.ToolError):
            self.update()
        self.assert_unchanged()


if __name__ == '__main__':
    unittest.main()
