"""账号文件的路径来源、只读权限及 Full 有限编辑；不启动适配器或其他插件。"""

import ast
import asyncio
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import account_tools, account_write, config, contracts, file_write, fs, protocol


def native_patch(base, override):
    # c6a99fc 的 model patch 是浅合并，data 整体替换，不是递归合并。
    for key in ('system', 'queue'):
        if key in base and type(override.get(key)) is type(base[key]):
            if type(base[key]) is dict:
                base[key].update(override[key])
            else:
                base[key] = override[key]
    for key, value in base.get('models', {}).items():
        incoming = override.get('models', {}).get(key)
        if type(incoming) is type(value):
            value.update(incoming)
    return base


def account(bot_id, enabled=True):
    return {
        'id': bot_id, 'enable': enabled, 'password': 'unchanged-"password"\\line\n',
        'sdk_type': 'onebot', 'platform_type': 'qq', 'model_type': 'default',
        'server': {'auto': False, 'type': 'post', 'host': 'http://127.0.0.1', 'port': 5700,
                   'access_token': 'unchanged-TOKEN', 'future_server': {'keep': True}},
        'extends': {'future_extension': ['keep', 7]}, 'debug': False, 'future_account': {'keep': '原值'},
    }


class Manager:
    def __init__(self):
        self.current = config.Snapshot(valid=True, generation=1, full_real_account_write=True)

    def snapshot(self):
        return self.current


class SDK:
    def __init__(self):
        self.default = {
            'system': {'init': ['OlivOS_account_config']},
            'models': {'OlivOS_account_config': {
                'enable': True, 'name': 'OlivOS_account_config', 'type': 'account_config',
                'data': {'path': './conf/account.json', 'future_default': 1},
            }},
        }
        self.bootDataAPI = SimpleNamespace(default_Conf=self.default)
        self.bootAPI = SimpleNamespace(get_patch_config=self.apply_patch)
        self.accountAPI = SimpleNamespace(_validate_account_config=self.validate)
        self.patches = []
        self.validated = []
        self.on_validate = None

    def apply_patch(self, base, override):
        self.patches.append((base, override))
        return native_patch(base, override)

    def validate(self, value):
        self.validated.append(copy.deepcopy(value))
        if self.on_validate:
            return self.on_validate(value)
        fields = {'id', 'password', 'sdk_type', 'platform_type', 'model_type', 'server', 'debug'}
        if fields - value.keys() or value.keys() - (fields | {'extends', 'enable'}):
            return [('account', 'invalid fields')]
        server = value['server']
        if type(server) is not dict or set(server) != {'auto', 'type', 'host', 'port', 'access_token'}:
            return [('server', 'invalid fields')]
        if type(value['debug']) is not bool or type(value.get('enable', True)) is not bool:
            return [('debug', 'invalid type')]
        return []


class AccountToolsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='cockpit-accounts-')
        self.addCleanup(directory.cleanup)
        self.root = Path(os.path.realpath(directory.name))
        self.conf = self.root / 'conf'
        self.conf.mkdir()
        self.data = self.root / 'plugin/data'
        self.data.mkdir(parents=True)
        self.target = self.conf / 'account.json'
        self.document = {'account': [account('10001'), account('10002', False)],
                         'future_document': {'keep': ['untouched']}}
        self.original = (json.dumps(self.document, ensure_ascii=False, indent=4) + '\n').encode('utf-8')
        self.target.write_bytes(self.original)
        self.target.chmod(0o640)
        self.sdk, self.manager = SDK(), Manager()
        self.ctx = contracts.Context(
            SimpleNamespace(Proc_data={'bot_info_dict': {'memory-debug': account('memory-debug')}}),
            str(self.root), str(self.data), olivos=self.sdk, config=self.manager, request_generation=1,
        )

    def read(self, args=None, ctx=None):
        return account_tools.cockpit_accounts_config(ctx or self.ctx, args or {})

    def arguments(self, **values):
        result = {'index': 0, 'expected_sha256': hashlib.sha256(self.original).hexdigest(),
                  'changes': {'debug': True}}
        result.update(values)
        return result

    def update(self, ctx=None, **values):
        return account_write.cockpit_accounts_update(ctx or self.ctx, self.arguments(**values))

    def rejects(self, operation):
        try:
            outcome = operation()
        except contracts.ToolError as error:
            message = str(error)
        else:
            self.assertTrue(outcome.is_error, outcome.data)
            message = json.dumps(outcome.data)
        for credential in ('unchanged-TOKEN', 'PRIVATE-SECRET', 'memory-debug'):
            self.assertNotIn(credential, message)
        return message

    def unchanged(self, expected=None):
        self.assertEqual(self.target.read_bytes(), self.original if expected is None else expected)
        self.assertEqual(list(self.target.parent.glob('.cockpit-*.tmp')), [])

    def boot(self, path='./conf/account.json', **model_values):
        value = copy.deepcopy(self.sdk.default)
        value['models']['OlivOS_account_config']['data'] = {'path': path, 'old_data_key': 1}
        value['models']['OlivOS_account_config'].update(model_values)
        return value

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')

    def another(self, name='路径 with spaces/account.json'):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.original)
        return target

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

    def after_replace(self, action):
        """在目录 fsync（replace 已完成、核验未开始）时机注入外部操作。"""
        real = fs.fsync
        calls = []

        def fsync(fd):
            result = real(fd)
            calls.append(fd)
            if len(calls) == 2:
                action()
            return result

        return patch.object(fs, 'fsync', fsync)

    def test_native_default_full_file_revision_disabled_and_raw_credentials(self):
        defaults = copy.deepcopy(self.sdk.default)
        result = self.read()
        self.assertFalse(result.is_error)
        self.assertEqual(result.data['source'], 'configured_file')
        self.assertEqual(result.data['path_source'], 'disk_boot_configuration')
        self.assertEqual(result.data['runtime_active_config'], 'unknown')
        self.assertEqual(result.data['sha256'], hashlib.sha256(self.original).hexdigest())
        self.assertEqual(result.data['accounts'], [{'index': i, 'account': row}
                                                  for i, row in enumerate(self.document['account'])])
        self.assertFalse(result.data['accounts'][1]['account']['enable'])
        self.assertEqual(result.data['total'], 2)
        self.assertFalse(result.truncated)
        self.assertIsNone(result.after_send)
        self.assertEqual(self.sdk.default, defaults)
        self.assertFalse((self.conf / 'basic.json').exists())
        self.assertFalse((self.conf / 'config.json').exists())
        self.unchanged()

    def test_disk_basic_precedes_defaults_and_relative_paths_use_context_root(self):
        target = self.another()
        self.write_json(self.conf / 'basic.json', self.boot(str(target.relative_to(self.root))))
        self.sdk.bootDataAPI.default_Conf = object()
        self.assertEqual(account_tools._resolve(self.ctx)[0], str(target))
        self.assertEqual(self.read().data['total'], 2)
        self.assertEqual(self.sdk.patches, [])

    def test_native_shallow_patch_replaces_data_and_does_not_mutate_host_defaults(self):
        before = copy.deepcopy(self.sdk.default)
        target = self.another()
        self.write_json(self.conf / 'config.json', {
            'models': {'OlivOS_account_config': {'data': {'path': str(target)}}},
        })
        self.assertEqual(account_tools._resolve(self.ctx)[0], str(target))
        self.assertEqual(self.sdk.default, before)
        self.assertEqual(self.sdk.patches[-1][0]['models']['OlivOS_account_config']['data'], {'path': str(target)})
        self.write_json(self.conf / 'basic.json', self.boot())
        self.assertEqual(self.read().data['total'], 2)
        self.assertEqual(self.sdk.default, before)

    def test_bad_shallow_patch_cannot_recover_path_from_default_or_basic(self):
        self.write_json(self.conf / 'basic.json', self.boot())
        for data in ({'unrelated': 1}, [], None):
            self.write_json(self.conf / 'config.json', {'models': {'OlivOS_account_config': {'data': data}}})
            self.rejects(self.read)
        self.unchanged()

    def test_missing_boot_files_do_not_create_resources(self):
        moved = self.root / 'accounts.json'
        self.target.rename(moved)
        self.conf.rmdir()
        self.sdk.default['models']['OlivOS_account_config']['data']['path'] = './accounts.json'
        self.assertEqual(self.read().data['total'], 2)
        self.assertFalse(self.conf.exists())

    def test_disabled_or_unknown_model_never_falls_back(self):
        for changes in ({'enable': False}, {'enable': 'true'}, {'type': 'other'}, {'name': 'other'}):
            self.write_json(self.conf / 'basic.json', self.boot(**changes))
            self.rejects(self.read)
        self.write_json(self.conf / 'basic.json', {'models': {}})
        self.rejects(self.read)

    def test_corrupt_boot_files_and_denied_paths_never_fall_back(self):
        for filename in ('basic.json', 'config.json'):
            path = self.conf / filename
            for raw in (b'{', b'{"models":{},"models":{}}', b'{"x":NaN}', b'{"x":1e999}', b'[]', b'\xff'):
                path.write_bytes(raw)
                self.rejects(self.read)
            path.unlink()
            self.manager.current = replace(self.manager.current, denied_paths=(str(path),), redaction_enabled=False)
            self.rejects(self.read)
            self.manager.current = replace(self.manager.current, denied_paths=())
        self.unchanged()

    def test_permission_error_is_not_treated_as_missing_boot_file(self):
        original_stat = fs.stat_at

        def denied(path, *, dir_fd, follow_symlinks=False):
            if path == 'basic.json':
                raise PermissionError('PRIVATE-SECRET')
            return original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        with patch.object(fs, 'supported', return_value=True), patch.object(fs, 'stat_at', denied):
            self.assertIn('unavailable', self.rejects(self.read))
        self.unchanged()

    def test_unavailable_default_or_patch_sdk_fails_safely_and_cancel_propagates(self):
        self.sdk.bootDataAPI.default_Conf = object()
        self.rejects(self.read)
        self.sdk.bootDataAPI.default_Conf = self.sdk.default
        self.write_json(self.conf / 'config.json', {'system': {'name': 'x'}})
        for error in (SystemExit('PRIVATE-SECRET'), KeyboardInterrupt('PRIVATE-SECRET')):
            def explode(*_args):
                raise error
            self.sdk.bootAPI.get_patch_config = explode
            self.rejects(self.read)
        self.sdk.bootAPI.get_patch_config = None
        self.rejects(self.read)
        self.sdk.bootAPI.get_patch_config = lambda *_args: (_ for _ in ()).throw(asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            self.read()

    def test_read_full_lite_and_missing_invalid_or_stale_snapshot(self):
        self.assertFalse(self.read().is_error)
        lite = replace(self.ctx, permission_mode=contracts.MODE_LITE)
        self.rejects(lambda: self.read(ctx=lite))
        self.manager.current = replace(self.manager.current, lite_real_account_read=True)
        self.assertFalse(self.read(ctx=lite).is_error)
        for ctx in (replace(self.ctx, config=None), replace(self.ctx, request_generation=0),
                    replace(self.ctx, permission_mode='unknown')):
            with patch.object(account_tools, '_resolve', side_effect=AssertionError('must not read')):
                self.rejects(lambda: self.read(ctx=ctx))
        self.manager.current = replace(self.manager.current, valid=False)
        self.rejects(self.read)

    def test_paging_is_server_validated_and_sha256_always_covers_complete_file(self):
        value = {'account': [account(str(i)) for i in range(120)]}
        self.write_json(self.target, value)
        expected = hashlib.sha256(self.target.read_bytes()).hexdigest()
        result = self.read({'offset': 50, 'limit': 50})
        self.assertEqual([row['index'] for row in result.data['accounts']], list(range(50, 100)))
        self.assertEqual(result.data['sha256'], expected)
        self.assertTrue(result.truncated)
        self.assertEqual(self.read({'offset': 100, 'limit': 50}).data['accounts'][-1]['index'], 119)
        self.assertEqual(self.read({'offset': 500}).data['accounts'], [])
        for args in ({'limit': 51}, {'limit': 0}, {'limit': True}, {'limit': 1.0}, {'offset': -1},
                     {'offset': 501}, {'offset': False}, {'path': 'conf/account.json'}):
            self.rejects(lambda: self.read(args))

    def test_malformed_large_deep_or_non_native_documents_are_rejected(self):
        raw_values = [b'{"account":[],"account":[]}', b'{"account":NaN}', b'{"account":[],"x":Infinity}',
                      b'{"account":[],"x":1e999}', b'{"account":[1]}', b'{"account":{}}',
                      b' ' * (contracts.MAX_FILE + 1),
                      b'{"account":[],"x":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}',
                      b'{"account":[],"x":[' + b'0,' * 20000 + b'0]}',
                      b'{"account":[],"x":' + b'9' * 1000 + b'}', b'\xef\xbb\xbf{"account":[]}']
        for raw in raw_values:
            self.target.write_bytes(raw)
            self.rejects(self.read)
        self.write_json(self.target, {'account': [account(str(i)) for i in range(contracts.MAX_ENTRIES + 1)]})
        self.rejects(self.read)
        for value in ({'account': [], 'unknown': '\ud800'}, {'account': [], 'unknown': 'x' * (64 * 1024 + 1)}):
            self.target.write_text(json.dumps(value), encoding='utf-8')
            self.rejects(self.read)

    def test_control_namespace_denied_external_parent_and_drive_paths(self):
        outside = tempfile.TemporaryDirectory(prefix='cockpit-outside-')
        self.addCleanup(outside.cleanup)
        external = Path(outside.name) / 'account.json'
        external.write_bytes(self.original)
        own = self.data / 'OlivOSCockpit/control/config.json'
        self.write_json(own, self.document)
        for path in (str(own), str(self.data / 'olivoscockpit/secret.json'), str(external),
                     '../account.json', './conf/../conf/account.json', 'C:/conf/account.json', 'conf\\account.json'):
            self.write_json(self.conf / 'basic.json', self.boot(path))
            self.rejects(self.read)
        self.write_json(self.conf / 'basic.json', self.boot())
        self.manager.current = replace(self.manager.current, denied_paths=('conf/account.json',),
                                       redaction_enabled=False)
        self.rejects(self.read)
        self.assertEqual(external.read_bytes(), self.original)
        self.unchanged()

    def test_absolute_path_in_distinct_trusted_data_root_is_allowed(self):
        directory = tempfile.TemporaryDirectory(prefix='cockpit-account-data-')
        self.addCleanup(directory.cleanup)
        data_root = Path(os.path.realpath(directory.name))
        target = data_root / 'Other/account.json'
        self.write_json(target, self.document)
        self.write_json(self.conf / 'basic.json', self.boot(str(target)))
        context = replace(self.ctx, data_root=str(data_root))
        self.assertEqual(self.read(ctx=context).data['total'], 2)
        self.assertTrue(self.update(ctx=context,
                                   expected_sha256=hashlib.sha256(target.read_bytes()).hexdigest()).data['persisted'])

    def test_symlink_boot_files_cannot_be_treated_as_missing(self):
        real = self.another()
        for filename in ('basic.json', 'config.json'):
            path = self.conf / filename
            try:
                path.symlink_to(real)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('file symlinks are unavailable: ' + str(exc))
            self.rejects(self.read)
            path.unlink()
        self.unchanged()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO is unavailable on this platform')
    def test_fifo_boot_files_cannot_be_treated_as_missing(self):
        for filename in ('basic.json', 'config.json'):
            path = self.conf / filename
            try:
                os.mkfifo(path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('FIFO creation is unavailable: ' + str(exc))
            self.rejects(self.read)
            path.unlink()
        self.unchanged()

    def test_hardlinked_boot_files_cannot_be_treated_as_missing(self):
        real = self.another()
        for filename in ('basic.json', 'config.json'):
            path = self.conf / filename
            try:
                os.link(real, path)
            except (OSError, NotImplementedError) as exc:
                self.skipTest('hard links are unavailable: ' + str(exc))
            self.rejects(self.read)
            path.unlink()
        self.unchanged()

    def test_boot_configuration_itself_and_executable_json_are_not_write_targets(self):
        for filename in ('basic.json', 'config.json'):
            path = self.conf / filename
            value = self.boot(str(path))
            value['account'] = self.document['account']
            self.write_json(path, value)
            if filename == 'config.json':
                self.write_json(self.conf / 'basic.json', value)
            before = path.read_bytes()
            self.rejects(lambda: self.update(expected_sha256=hashlib.sha256(before).hexdigest()))
            self.assertEqual(path.read_bytes(), before)
            path.unlink()
        self.write_json(self.conf / 'basic.json', self.boot())
        if os.name == 'posix':
            self.target.chmod(0o755)
            self.rejects(self.update)
            self.unchanged()

    def test_boot_path_case_variants_are_rejected_before_opening_for_update(self):
        for name in account_tools._BOOT_FILES:
            path = str(self.root / 'CONF' / name.upper())
            with (
                self.subTest(name=name),
                patch.object(account_tools, '_resolve', return_value=(path, None)),
                patch.object(fs, 'open_root', side_effect=AssertionError('must reject before opening')) as opened,
            ):
                with self.assertRaises(contracts.ToolError):
                    self.update()
                opened.assert_not_called()
            self.unchanged()

    def test_target_symlink_is_rejected(self):
        real = self.another()
        self.target.unlink()
        try:
            self.target.symlink_to(real)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('file symlinks are unavailable: ' + str(exc))
        self.rejects(self.read)
        self.rejects(self.update)

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO is unavailable on this platform')
    def test_fifo_target_is_rejected(self):
        self.target.unlink()
        try:
            os.mkfifo(self.target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('FIFO creation is unavailable: ' + str(exc))
        self.rejects(self.read)
        self.rejects(self.update)

    def test_hardlink_target_is_rejected(self):
        real = self.another()
        self.target.unlink()
        try:
            os.link(real, self.target)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('hard links are unavailable: ' + str(exc))
        self.rejects(self.read)
        self.rejects(self.update)
        self.assertEqual(real.read_bytes(), self.original)

    def test_ancestor_symlink_is_rejected(self):
        moved = self.root / 'moved-conf'
        probe = self.root / 'symlink-probe'
        try:
            probe.symlink_to(moved, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('directory symlinks are unavailable: ' + str(exc))
        probe.unlink()
        self.conf.rename(moved)
        self.conf.symlink_to(moved, target_is_directory=True)
        self.rejects(self.read)
        self.rejects(self.update)
        self.assertEqual((moved / 'account.json').read_bytes(), self.original)

    def test_common_outbound_redaction_can_be_disabled_or_overridden_without_mutation(self):
        outcome = self.read()
        original = copy.deepcopy(outcome.data)
        for modern in (False, True):
            body = protocol.result_body(1, protocol.tool_result(outcome, ''), modern)
            for settings, expected in (
                (self.manager.current, '[REDACTED]'),
                (replace(self.manager.current, redaction_enabled=False), 'unchanged-TOKEN'),
                (replace(self.manager.current, allow_fields=('access_token',)), 'unchanged-TOKEN'),
            ):
                reply = protocol.encode_reply(body, modern, policy=settings)
                result = json.loads(reply.body)['result']
                data = result['structuredContent']
                self.assertEqual(data['accounts'][0]['account']['server']['access_token'], expected)
                self.assertEqual(json.loads(result['content'][0]['text']), data)
        self.assertEqual(outcome.data, original)
        self.unchanged()

    def test_write_preserves_unknown_disabled_and_unmodified_credentials(self):
        args = self.arguments(index=1, changes={'debug': True, 'enable': False})
        original_args = copy.deepcopy(args)
        before = self.target.stat()
        result = account_write.cockpit_accounts_update(self.ctx, args)
        expected = copy.deepcopy(self.document)
        expected['account'][1]['debug'] = True
        self.assertEqual(json.loads(self.target.read_bytes()), expected)
        self.assertEqual(args, original_args)
        self.assertNotEqual(self.target.stat().st_ino, before.st_ino)
        if os.name == 'posix':
            self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertTrue(result.data['persisted'])
        self.assertFalse(result.data['runtime_updated'])
        self.assertTrue(result.data['requires_host_restart'])
        self.assertEqual(result.data['runtime_active_config'], 'unknown')
        self.assertEqual(result.data['path_source'], 'disk_boot_configuration')
        self.assertEqual(result.data['sha256'], hashlib.sha256(self.target.read_bytes()).hexdigest())
        self.assertEqual(result.data['durability'], 'synced')
        self.assertIsNone(result.after_send)
        self.assertNotIn('future_account', self.sdk.validated[-1])
        self.assertNotIn('future_server', self.sdk.validated[-1]['server'])
        self.assertEqual(self.sdk.validated[-1]['extends'], self.document['account'][1]['extends'])
        self.assertEqual(list(self.conf.glob('.cockpit-*.tmp')), [])
        self.assertEqual(self.ctx.proc.Proc_data['bot_info_dict']['memory-debug'], account('memory-debug'))

    def test_credential_updates_and_clear_are_bounded_without_normalizing_other_fields(self):
        result = self.update(changes={'password': '', 'server': {'access_token': 'new_TOKEN.:@+=/-'}})
        self.assertTrue(result.data['persisted'])
        expected = copy.deepcopy(self.document)
        expected['account'][0]['password'] = ''
        expected['account'][0]['server']['access_token'] = 'new_TOKEN.:@+=/-'
        self.assertEqual(json.loads(self.target.read_bytes()), expected)
        self.assertEqual(self.sdk.default['models']['OlivOS_account_config']['data']['future_default'], 1)

    def test_write_switch_full_mode_valid_snapshot_and_request_generation_required(self):
        start = self.manager.current
        cases = ((replace(start, full_real_account_write=False), self.ctx),
                 (replace(start, valid=False), self.ctx),
                 (start, replace(self.ctx, permission_mode=contracts.MODE_LITE)),
                 (start, replace(self.ctx, config=None)),
                 (start, replace(self.ctx, request_generation=0)))
        for current, ctx in cases:
            self.manager.current = current
            with patch.object(account_tools, '_resolve', side_effect=AssertionError('must not read')):
                self.rejects(lambda: self.update(ctx=ctx))
            self.unchanged()

    def test_required_revision_index_validation_and_conflicts(self):
        for values in ({'index': True}, {'index': -1}, {'index': 500}, {'index': 2},
                       {'expected_sha256': '0' * 64}, {'expected_sha256': 'z' * 64},
                       {'expected_sha256': 'short'}, {'changes': []}):
            self.rejects(lambda: self.update(**values))
            self.unchanged()
        for required in ('index', 'expected_sha256', 'changes'):
            args = self.arguments()
            del args[required]
            self.rejects(lambda: account_write.cockpit_accounts_update(self.ctx, args))
        self.assertTrue(self.update(expected_sha256=self.arguments()['expected_sha256'].upper()).data['persisted'])

    def test_routing_code_and_arbitrary_paths_cannot_be_written(self):
        for changes in ({}, {'id': 'new'}, {'sdk_type': 'other'}, {'model_type': 'other'}, {'platform_type': 'other'},
                        {'server': {'host': 'http://evil'}}, {'server': {'auto': True}},
                        {'server': {'type': 'post'}}, {'server': {'port': 80}}, {'server': {}},
                        {'extends': {'path': 'code.py'}}, {'rawSDK': {}}, {'module': 'os'},
                        {'code': 'PRIVATE-SECRET'}, {'sql': 'DROP TABLE account'}, {'path': '/tmp/target'}):
            self.rejects(lambda: self.update(changes=changes))
            self.unchanged()
        for extra in ('path', 'module', 'code', 'sql', 'rawSDK'):
            self.rejects(lambda: self.update(**{extra: 'arbitrary'}))
        for suffix in ('.py', '.opk', '.zip', '.db', '.pth', '.so'):
            target = self.another('OlivOS/code' + suffix)
            self.write_json(self.conf / 'basic.json', self.boot(str(target)))
            self.rejects(self.update)
            self.assertEqual(target.read_bytes(), self.original)
        self.unchanged()

    def test_boolean_credential_types_redacted_placeholders_and_booster_injection_are_rejected(self):
        for changes in ({'enable': 1}, {'debug': 'true'}, {'password': None}, {'password': 42},
                        {'server': {'access_token': None}}, {'server': {'access_token': 42}}):
            self.rejects(lambda: self.update(changes=changes))
        values = ('[REDACTED]', 'prefix[redacted]suffix', 'x' * 4097, '\ud800', '非ASCII',
                  'two words', 'line\nvalue', 'quote"', "quote'", 'x;run', 'x&run', 'x|run',
                  'x>file', '$(run)', '`run`', '%VAR%', 'x{format}', 'x\\escape')
        for value in values:
            for changes in ({'password': value}, {'server': {'access_token': value}}):
                self.rejects(lambda: self.update(changes=changes))
                self.unchanged()

    def test_native_validator_failure_or_sdk_exception_is_safe_and_cancel_propagates(self):
        for callback in (lambda _value: [('password', 'PRIVATE-SECRET')], lambda _value: None,
                         lambda _value: (_ for _ in ()).throw(SystemExit('PRIVATE-SECRET')),
                         lambda _value: (_ for _ in ()).throw(KeyboardInterrupt('PRIVATE-SECRET'))):
            self.sdk.on_validate = callback
            self.rejects(self.update)
            self.unchanged()
        self.sdk.on_validate = lambda _value: (_ for _ in ()).throw(asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            self.update()
        self.unchanged()

    def test_validator_gets_an_independent_known_field_projection(self):
        def mutate(value):
            value['id'] = 'mutated-sdk-id'
            value['server']['host'] = 'mutated-sdk-host'
            value['extends']['future_extension'].append('mutated-sdk-extension')
            return []
        self.sdk.on_validate = mutate
        self.update()
        expected = copy.deepcopy(self.document)
        expected['account'][0]['debug'] = True
        self.assertEqual(json.loads(self.target.read_bytes()), expected)

    def test_boot_path_or_file_identity_changed_during_validation_is_not_committed(self):
        other = self.another()
        for mutation in (
            lambda: self.write_json(self.conf / 'config.json', {
                'models': {'OlivOS_account_config': {'data': {'path': str(other)}}}}),
            lambda: os.replace(other, self.target),
        ):
            self.target.write_bytes(self.original)
            self.target.chmod(0o640)
            if not other.exists():
                other.write_bytes(self.original)
            patch_path = self.conf / 'config.json'
            if patch_path.exists():
                patch_path.unlink()
            def change(_value):
                mutation()
                return []
            self.sdk.on_validate = change
            self.rejects(self.update)
            self.unchanged()

    def test_generation_revocation_and_denied_path_during_staging_prevent_commit(self):
        start = self.manager.current
        for values in ({'generation': 2}, {'full_real_account_write': False}, {'denied_paths': (str(self.target),)}):
            self.manager.current = start
            def change():
                self.manager.current = replace(start, **values)
            with self.during_sync(change):
                self.rejects(self.update)
            self.unchanged()

    def test_account_identity_swap_during_staging_prevents_commit(self):
        other = self.another()
        with self.during_sync(lambda: os.replace(other, self.target)):
            self.rejects(self.update)
        self.unchanged()

    def test_account_ancestor_symlink_swap_during_staging_prevents_commit(self):
        moved = self.root / 'old-conf'
        probe = self.root / 'symlink-probe'
        try:
            probe.symlink_to(moved, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest('directory symlinks are unavailable: ' + str(exc))
        probe.unlink()

        def swap():
            self.conf.rename(moved)
            self.conf.symlink_to(moved, target_is_directory=True)

        with self.during_sync(swap):
            self.rejects(self.update)
        self.assertEqual((moved / 'account.json').read_bytes(), self.original)
        self.assertEqual(list(moved.glob('.cockpit-*.tmp')), [])

    def test_replace_failure_cleanup_and_directory_sync_reports_actual_persisted_state(self):
        with patch.object(fs, 'replace', side_effect=OSError('PRIVATE-SECRET')):
            self.rejects(self.update)
        self.unchanged()
        real_sync = fs.fsync
        calls = []
        def fsync(fd):
            calls.append(fd)
            if len(calls) == 2:
                raise OSError('PRIVATE-SECRET')
            return real_sync(fd)
        with patch.object(fs, 'fsync', fsync):
            result = self.update()
        self.assertTrue(result.data['persisted'])
        self.assertEqual(result.data['durability'], 'unknown')
        self.assertFalse(result.data['runtime_updated'])
        self.assertTrue(result.data['requires_host_restart'])

    def test_post_replace_verification_failure_is_not_wrapped_as_success(self):
        changed = b'{"external":true}\n'

        def swap():
            outside = self.root / 'outside.json'
            outside.write_bytes(changed)
            os.replace(outside, self.target)

        def rewrite():
            self.target.write_bytes(changed)

        for label, action in (('leaf_replace', swap), ('same_inode_rewrite', rewrite)):
            with self.subTest(action=label):
                self.target.write_bytes(self.original)
                self.target.chmod(0o640)
                with self.after_replace(action), self.assertRaises(contracts.ToolError) as caught:
                    self.update()
                self.assertIn('may have completed', str(caught.exception))
                # 不回滚、不删除外部对象：外部内容保留，暂存路径无残留。
                self.assertEqual(self.target.read_bytes(), changed)
                self.assertEqual(list(self.conf.glob('.cockpit-*.tmp')), [])

    def test_same_path_boot_revision_change_during_validation_or_staging_prevents_commit(self):
        basic = self.conf / 'basic.json'
        valid = self.boot()

        for stage in ('validation', 'staging'):
            with self.subTest(stage=stage):
                self.write_json(basic, valid)
                self.target.write_bytes(self.original)
                self.target.chmod(0o640)

                def change_boot():
                    # 路径与账号模型不变，仅无关顶层字段变化，改变磁盘文件指纹。
                    changed = copy.deepcopy(valid)
                    changed['future_boot_key'] = 'changed'
                    self.write_json(basic, changed)

                if stage == 'validation':
                    self.sdk.on_validate = lambda _value: (change_boot(), [])[1]
                    with self.assertRaises(contracts.ToolError) as caught:
                        self.update()
                else:
                    self.sdk.on_validate = None
                    with self.during_sync(change_boot), self.assertRaises(contracts.ToolError) as caught:
                        self.update()
                expected = ('Disk boot configuration changed; read the account configuration again'
                            if stage == 'validation'
                            else 'Disk boot configuration changed before account commit')
                self.assertIn(expected, str(caught.exception))
                self.assertEqual(self.target.read_bytes(), self.original)
                self.assertEqual(list(self.conf.glob('.cockpit-*.tmp')), [])

    def test_invalid_server_missing_validator_and_encoded_overflow(self):
        document = copy.deepcopy(self.document)
        del document['account'][0]['server']
        raw = (json.dumps(document, ensure_ascii=False, indent=4) + '\n').encode('utf-8')
        self.target.write_bytes(raw)
        with self.assertRaises(contracts.ToolError) as caught:
            self.update(expected_sha256=hashlib.sha256(raw).hexdigest(),
                        changes={'server': {'access_token': 'x'}})
        self.assertIn('Configured account server fields are invalid', str(caught.exception))
        self.assertEqual(self.target.read_bytes(), raw)
        self.assertEqual(list(self.conf.glob('.cockpit-*.tmp')), [])

        self.target.write_bytes(self.original)
        self.target.chmod(0o640)
        with patch.object(self.sdk, 'accountAPI', SimpleNamespace()):
            with self.assertRaises(contracts.ToolError) as caught:
                self.update()
        self.assertIn('Native pure account validator unavailable or failed safely', str(caught.exception))
        self.assertEqual(self.target.read_bytes(), self.original)

        # 紧凑源可读，但 indent=2 重编码后超限；阈值取源长度，介于两者之间。
        document = {'account': [account('10001')], 'padding': list(range(300))}
        compact = json.dumps(document, separators=(',', ':')).encode('utf-8')
        indented = (json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8')
        self.assertLessEqual(len(compact), len(indented))
        self.target.write_bytes(compact)
        self.target.chmod(0o640)
        expected = hashlib.sha256(compact).hexdigest()
        with patch.object(account_write, 'MAX_FILE', len(compact)), \
                patch.object(account_tools, 'MAX_FILE', len(compact)):
            self.assertLessEqual(len(compact), account_write.MAX_FILE)
            self.assertLess(account_write.MAX_FILE, len(indented))
            with self.assertRaises(contracts.ToolError) as caught:
                self.update(expected_sha256=expected)
        self.assertIn('Updated account configuration exceeds the file limit', str(caught.exception))
        self.assertEqual(self.target.read_bytes(), compact)
        self.assertEqual(list(self.conf.glob('.cockpit-*.tmp')), [])

    def test_parallel_cockpit_updates_share_lock_and_second_revision_conflicts(self):
        def run(debug):
            try:
                return self.update(changes={'debug': debug}).data['persisted']
            except contracts.ToolError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, (True, True)))
        self.assertEqual(sorted(results), [False, True])
        self.assertEqual(list(self.conf.glob('.cockpit-*.tmp')), [])

    def test_missing_secure_primitives_fail_without_writing(self):
        with patch.object(fs, 'supported', return_value=False):
            self.rejects(self.read)
            self.rejects(self.update)
        with patch.object(fs, 'updates_supported', return_value=False):
            self.rejects(self.update)
        self.unchanged()

    @unittest.skipUnless(os.name == 'posix', 'POSIX dir_fd capability probe')
    def test_missing_posix_rename_dir_fd_support_fails(self):
        with patch.object(os, 'supports_dir_fd', os.supports_dir_fd - {os.rename}):
            self.rejects(self.update)
        self.unchanged()

    def test_tool_metadata_schema_and_shared_module_have_no_generic_or_write_surface(self):
        self.assertEqual(len(account_tools.TOOLS), 1)
        self.assertEqual(len(account_write.TOOLS), 1)
        read, write = account_tools.TOOLS[0], account_write.TOOLS[0]
        self.assertEqual(read.name, 'cockpit_accounts_config')
        self.assertTrue(read.read_only)
        self.assertEqual(read.required_permission, 'real_account_read')
        self.assertEqual(write.name, 'cockpit_accounts_update')
        self.assertFalse(write.read_only)
        self.assertEqual(write.required_permission, 'real_account_write')
        self.assertEqual(set(read.schema['properties']), {'offset', 'limit'})
        self.assertEqual(set(write.schema['properties']), {'index', 'expected_sha256', 'changes'})
        self.assertEqual(set(write.schema['properties']['changes']['properties']),
                         {'enable', 'debug', 'password', 'server'})
        self.assertFalse(read.schema['additionalProperties'])
        self.assertFalse(write.schema['additionalProperties'])
        source = Path(account_tools.__file__).read_text(encoding='utf-8')
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                names += [alias.name for alias in node.names]
                self.assertFalse(set(names) & {'account_write', 'file_write', 'full_only', 'adapter_tools'})


if __name__ == '__main__':
    unittest.main()
