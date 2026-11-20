"""使用临时目录和假宿主验证 OPK 删除边界及部分完成语义。"""

import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from OlivOSCockpit import config, files, fs, plugin_delete
from OlivOSCockpit.contracts import MODE_LITE, Context, ToolError


def opk(namespace='Demo'):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('app.json', json.dumps({'namespace': namespace}))
        archive.writestr('__init__.py', b'')
        archive.writestr('main.py', b'')
    return buffer.getvalue()


class PluginDeleteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='cockpit-delete-')
        self.addCleanup(temp.cleanup)
        root = Path(os.path.realpath(temp.name))
        self.app = root / 'plugin' / 'app'
        self.app.mkdir(parents=True)
        self.data = root / 'plugin' / 'data'
        self.namespace = self.data / 'Demo'
        self.nested = self.namespace / 'nested'
        self.nested.mkdir(parents=True)
        self.record = self.nested / 'record.txt'
        self.record.write_bytes(b'plugin data')
        self.file = self.app / 'Demo.opk'
        self.file.write_bytes(opk())
        self.snapshot = config.Snapshot(api_key='test-key', valid=True, generation=1,
                                        full_real_account_write=True, full_plugin_delete=True)
        self.proc = SimpleNamespace(get_plugin_list=lambda: ['Demo'], set_restart=Mock())
        olivos = SimpleNamespace(pluginAPI=SimpleNamespace(plugin_path=str(self.app)))
        self.ctx = Context(self.proc, str(root), str(self.data), olivos=olivos,
                           config=SimpleNamespace(snapshot=lambda: self.snapshot), request_generation=1)
        meta = files.cockpit_meta(self.ctx, {'filename': self.file.name}).data
        self.args = {'filename': meta['filename'], 'namespace': meta['manifest']['namespace'],
                     'expected_sha256': meta['sha256']}
        self.addCleanup(self.proc.set_restart.assert_not_called)

    def delete(self, **updates):
        return plugin_delete.cockpit_plugin_delete(self.ctx, dict(self.args, **updates))

    def test_package_only_keeps_data_and_does_not_unload(self):
        result = self.delete()
        self.assertFalse(result.is_error, result.data)
        self.assertTrue(result.data['package_removed'])
        self.assertEqual(result.data['data'], 'kept')
        self.assertTrue(result.data['currently_loaded'])
        self.assertTrue(result.data['requires_loader_restart'])
        self.assertFalse(self.file.exists())
        self.assertEqual(self.record.read_bytes(), b'plugin data')

    def test_data_choice_removes_only_matching_namespace(self):
        other = self.data / 'Other'
        other.mkdir()
        outside = other / 'keep.txt'
        outside.write_text('keep', encoding='utf-8')
        other_package = self.app / 'Other.opk'
        other_package.write_bytes(opk('Other'))
        result = self.delete(delete_data=True)
        self.assertFalse(result.is_error, result.data)
        self.assertEqual(result.data['data'], 'removed')
        self.assertFalse(self.file.exists())
        self.assertFalse(self.namespace.exists())
        self.assertEqual(outside.read_text(encoding='utf-8'), 'keep')
        self.assertTrue(other_package.is_file())

    def test_missing_namespace_is_not_failure(self):
        self.record.unlink()
        self.nested.rmdir()
        self.namespace.rmdir()
        result = self.delete(delete_data=True)
        self.assertFalse(result.is_error, result.data)
        self.assertEqual(result.data['data'], 'absent')
        self.assertFalse(self.file.exists())

    def test_exact_package_digest_namespace_and_protected_names(self):
        for updates in (
                {'expected_sha256': '0' * 64}, {'namespace': 'demo'}, {'filename': 'demo.opk'},
                {'filename': '../Demo.opk'}, {'filename': 'OlivOSCockpitLite.opk'},
                {'namespace': 'OlivOSCockpit'}, {'namespace': 'olivos'}, {'delete_data': 'true'}):
            with self.subTest(updates=updates), self.assertRaises(ToolError):
                self.delete(**updates)
        contents = opk('OlivOSCockpit')
        self.file.write_bytes(contents)
        with self.assertRaises(ToolError):
            self.delete(expected_sha256=hashlib.sha256(contents).hexdigest())
        self.assertTrue(self.file.exists())
        self.assertTrue(self.record.exists())

    def test_delete_permission_is_independent_of_install_and_disabled_on_lite(self):
        self.snapshot = replace(self.snapshot, full_plugin_delete=False, full_plugin_install=True)
        with self.assertRaises(ToolError):
            self.delete()
        self.snapshot = replace(self.snapshot, full_plugin_delete=True)
        self.ctx = replace(self.ctx, permission_mode=MODE_LITE)
        with self.assertRaises(ToolError):
            self.delete()
        self.assertTrue(self.file.exists())

    def test_nested_package_with_same_name_blocks_shared_data_removal(self):
        nested = self.app / 'group'
        nested.mkdir()
        duplicate = nested / self.file.name
        duplicate.write_bytes(opk())
        with self.assertRaises(ToolError):
            self.delete(delete_data=True)
        self.assertTrue(self.file.exists())
        self.assertTrue(duplicate.exists())
        self.assertTrue(self.record.exists())

    def test_denied_entry_or_budget_abort_before_any_removal(self):
        snapshot = self.snapshot
        self.snapshot = replace(snapshot, denied_paths=(str(self.record),))
        with self.assertRaises(ToolError):
            self.delete(delete_data=True)
        self.snapshot = snapshot
        with patch.object(plugin_delete, 'MAX_DATA_ENTRIES', 1), self.assertRaises(ToolError):
            self.delete(delete_data=True)
        self.assertTrue(self.file.exists())
        self.assertTrue(self.record.exists())

    def test_link_does_not_delete_the_package_or_follow_the_target(self):
        outside = self.data / 'untouched.txt'
        outside.write_bytes(b'keep')
        try:
            (self.namespace / 'link').symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('symbolic link creation unavailable')
        with self.assertRaises(ToolError):
            self.delete(delete_data=True)
        self.assertTrue(self.file.exists())
        self.assertEqual(outside.read_bytes(), b'keep')
        self.assertTrue(self.record.exists())

    def test_mount_boundary_preflight_preserves_package_and_data(self):
        require_same_mount = fs.require_same_mount

        def require(parent, child):
            if Path(child.path) == self.nested:
                raise ToolError('Removal cannot cross a mount boundary')
            require_same_mount(parent, child)

        with patch.object(fs, 'require_same_mount', side_effect=require), self.assertRaises(ToolError):
            self.delete(delete_data=True)
        self.assertTrue(self.file.exists())
        self.assertTrue(self.record.exists())

    def test_overlapping_package_and_data_roots_are_refused(self):
        self.ctx = replace(self.ctx, data_root=str(self.app))
        with self.assertRaisesRegex(ToolError, 'overlaps'):
            self.delete(delete_data=True)
        self.assertTrue(self.file.exists())

    def test_package_revision_change_prevents_removal_and_data_cleanup(self):
        remove_checked = fs.remove_checked

        def remove(parent, name, expected, **kwargs):
            self.file.write_bytes(b'new bytes')
            return remove_checked(parent, name, expected, **kwargs)

        with patch.object(fs, 'remove_checked', side_effect=remove):
            result = self.delete(delete_data=True)
        self.assertTrue(result.is_error)
        self.assertIsNone(result.data['package_removed'])
        self.assertEqual(result.data['data'], 'not_attempted')
        self.assertEqual(self.file.read_bytes(), b'new bytes')
        self.assertTrue(self.record.exists())

    def test_data_removal_failure_reports_partial_after_package_removal(self):
        remove_checked = fs.remove_checked

        def remove(parent, name, expected, **kwargs):
            if name == self.record.name:
                raise PermissionError('simulated')
            return remove_checked(parent, name, expected, **kwargs)

        with patch.object(fs, 'remove_checked', side_effect=remove):
            result = self.delete(delete_data=True)
        self.assertTrue(result.is_error)
        self.assertTrue(result.data['package_removed'])
        self.assertEqual(result.data['data'], 'partial_or_unknown')
        self.assertFalse(self.file.exists())
        self.assertTrue(self.record.exists())


if __name__ == '__main__':
    unittest.main()
