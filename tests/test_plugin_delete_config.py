"""full_plugin_delete 开关：默认关闭、旧配置缺键按 false、非布尔仍拒绝。"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import config

KEY = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8


class PluginDeletePermissionTests(unittest.TestCase):

    def test_truth_table(self):
        def snapshot(**values):
            base = dict(api_key=KEY, valid=True, full_real_account_write=True,
                        full_plugin_delete=True)
            base.update(values)
            return config.Snapshot(**base)

        self.assertTrue(snapshot().allows('plugin_delete', 'full'))
        self.assertFalse(snapshot(full_plugin_delete=False)
                         .allows('plugin_delete', 'full'))
        self.assertFalse(snapshot(full_real_account_write=False)
                         .allows('plugin_delete', 'full'))
        self.assertFalse(snapshot(valid=False).allows('plugin_delete', 'full'))
        self.assertFalse(snapshot(api_key='').allows('plugin_delete', 'full'))
        self.assertFalse(snapshot().allows('plugin_delete', 'lite'))
        self.assertFalse(snapshot().allows('plugin_delete', 'bogus'))
        # 删除开关不放宽其他权限，安装也不被删除开关替代。
        self.assertFalse(snapshot().allows('plugin_install', 'full'))
        self.assertFalse(snapshot(full_plugin_delete=False, full_real_account_write=False)
                         .allows('low_level_access', 'full'))

    def test_template_and_old_config_omission(self):
        self.assertIs(config.config_template()['full_plugin_delete'], False)
        self.assertEqual(config.PERMISSION_PLUGIN_DELETE, 'plugin_delete')
        self.assertIn('PERMISSION_PLUGIN_DELETE', config.__all__)
        with tempfile.TemporaryDirectory() as directory:
            root = os.path.realpath(directory)
            data_root = os.path.join(root, 'data')
            os.makedirs(data_root)
            manager = config.ConfigManager(data_root, 'full')
            try:
                manager.refresh()
                manager.refresh()
                path = Path(config.control_dir(data_root)) / config.CONFIG_NAME
                data = json.loads(path.read_text('utf-8'))
                data.pop('full_plugin_delete')
                data['api_key'] = KEY
                data['full_real_account_write'] = True
                path.write_text(json.dumps(data), encoding='utf-8')
                manager.refresh()
                manager.refresh()
                snapshot = manager.snapshot()
                self.assertTrue(snapshot.valid and snapshot.ready)
                self.assertIs(snapshot.full_plugin_delete, False)
                self.assertFalse(snapshot.allows('plugin_delete', 'full'))
                data['full_plugin_delete'] = True
                path.write_text(json.dumps(data), encoding='utf-8')
                manager.refresh()
                manager.refresh()
                self.assertTrue(manager.snapshot().allows('plugin_delete', 'full'))
                data['full_plugin_delete'] = 'yes'
                path.write_text(json.dumps(data), encoding='utf-8')
                manager.refresh()
                manager.refresh()
                self.assertFalse(manager.snapshot().valid)
            finally:
                manager.stop()


if __name__ == '__main__':
    unittest.main()
