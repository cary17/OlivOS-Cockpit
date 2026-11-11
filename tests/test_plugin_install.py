"""cockpit_plugin_install：分块上传、归档校验、路径边界与原子发布。"""

import base64
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import types
import unittest
import warnings
import zipfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import config, contracts, files, plugin_install

MODE_FULL = contracts.MODE_FULL
MODE_LITE = contracts.MODE_LITE
ToolError = contracts.ToolError

MANIFEST = {
    'name': 'Demo', 'namespace': 'Demo', 'version': '1.0.0',
    'svn': 1, 'info': 'x', 'author': 'a', 'compatible_svn': 190, 'priority': 10,
}


class Manager:
    def __init__(self, **values):
        values.setdefault('api_key', 'test-key')
        values.setdefault('full_real_account_write', True)
        values.setdefault('full_plugin_install', True)
        self.current = config.Snapshot(valid=True, generation=1, **values)

    def snapshot(self):
        return self.current


def host_stub(plugin_path='./plugin/app/'):
    return types.SimpleNamespace(pluginAPI=types.SimpleNamespace(plugin_path=plugin_path))


def make_ctx(root, manager=None, package_path='./plugin/app/', mode=MODE_FULL):
    return contracts.Context(
        None, root, os.path.join(root, 'plugin/data'),
        olivos=host_stub(package_path), config=manager or Manager(), permission_mode=mode)


def manifest(namespace='Demo', **values):
    data = dict(MANIFEST, namespace=namespace)
    data.update(values)
    return data


def package(namespace='Demo', manifest_data=None, members=None,
            compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression) as archive:
        archive.writestr('app.json', json.dumps(
            manifest_data if manifest_data is not None else manifest(namespace)))
        archive.writestr('__init__.py', b'')
        archive.writestr('main.py', b'')
        for name, data in (members or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


def raw_member(name, data=b'', external_attr=None, compression=zipfile.ZIP_STORED):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = compression
    info.external_attr = (0o100644 << 16) if external_attr is None else external_attr
    return info, data


def build_entries(entries, manifest_raw=None, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        with zipfile.ZipFile(buffer, 'w', compression) as archive:
            archive.writestr('app.json', manifest_raw if manifest_raw is not None
                              else json.dumps(manifest()).encode())
            archive.writestr('__init__.py', b'')
            archive.writestr('main.py', b'')
            for item in entries:
                if isinstance(item, tuple):
                    info, data = item
                    archive.writestr(info, data)
                else:
                    archive.writestr(item, b'x')
    return buffer.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='cockpit-install-')
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(plugin_install.detach, None)
        self.root = os.path.realpath(self.directory.name)
        self.app = os.path.join(self.root, 'plugin/app')
        os.makedirs(self.app)
        self.manager = Manager()
        self.ctx = make_ctx(self.root, self.manager)
        self.tool = plugin_install.TOOLS[0]

    def begin(self, data=None, ctx=None, filename='Demo.opk', namespace='Demo', size=None):
        data = package() if data is None else data
        return self.tool.handler(ctx or self.ctx, {
            'operation': 'begin', 'filename': filename, 'namespace': namespace,
            'size': len(data) if size is None else size})

    def upload(self, data=None, ctx=None, filename='Demo.opk', namespace='Demo'):
        data = package() if data is None else data
        outcome = self.begin(data, ctx, filename, namespace)
        self.assertFalse(outcome.is_error, outcome.data)
        upload_id = outcome.data['upload_id']
        offset = 0
        for start in range(0, len(data), plugin_install.MAX_CHUNK):
            raw = data[start:start + plugin_install.MAX_CHUNK]
            outcome = self.tool.handler(ctx or self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': offset,
                'chunk': base64.b64encode(raw).decode('ascii')})
            self.assertFalse(outcome.is_error, outcome.data)
            offset = outcome.data['offset']
        return upload_id

    def commit(self, upload_id, data=None, ctx=None, digest=None):
        data = package() if data is None else data
        return self.tool.handler(ctx or self.ctx, {
            'operation': 'commit', 'upload_id': upload_id,
            'sha256': hashlib.sha256(data).hexdigest() if digest is None else digest})

    def install(self, data=None, ctx=None, **kwargs):
        data = package() if data is None else data
        upload_id = self.upload(data, ctx=ctx, **kwargs)
        return self.commit(upload_id, data, ctx=ctx)

    def write_existing(self, name, data):
        with open(os.path.join(self.app, name), 'wb') as stream:
            stream.write(data)

    def assert_no_temp(self):
        self.assertEqual([name for name in os.listdir(self.app)
                          if name.startswith('.cockpit-install-')], [])


class InstallTests(Base):
    def test_new_package_round_trip_and_metadata_digest(self):
        data = package(manifest_data={
            key: value for key, value in manifest().items() if key != 'svn'})
        outcome = self.install(data)
        self.assertFalse(outcome.is_error, outcome.data)
        self.assertEqual(outcome.data['filename'], 'Demo.opk')
        self.assertEqual(outcome.data['namespace'], 'Demo')
        self.assertEqual(outcome.data['size'], len(data))
        self.assertEqual(outcome.data['sha256'], hashlib.sha256(data).hexdigest())
        self.assertTrue(outcome.data['persisted'])
        self.assertIn(outcome.data['durability'], ('synced', 'unknown'))
        self.assertFalse(outcome.data['replaced'])
        self.assertFalse(outcome.data['loaded'])
        with open(os.path.join(self.app, 'Demo.opk'), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        meta = files.cockpit_meta(self.ctx, {'filename': 'Demo.opk'})
        self.assertEqual(meta.data['size'], len(data))
        self.assertEqual(meta.data['sha256'], hashlib.sha256(data).hexdigest())
        self.assert_no_temp()

    def test_overwrite_existing_package_without_old_digest(self):
        old = package(manifest_data=manifest(info='old'))
        new = package(manifest_data=manifest(info='new'))
        self.assertNotEqual(old, new)
        self.write_existing('Demo.opk', old)
        outcome = self.install(new)
        self.assertFalse(outcome.is_error, outcome.data)
        self.assertTrue(outcome.data['replaced'])
        with open(os.path.join(self.app, 'Demo.opk'), 'rb') as stream:
            self.assertEqual(stream.read(), new)
        self.assert_no_temp()

    def test_overwrite_requires_matching_existing_namespace(self):
        old = package(namespace='Other')
        self.write_existing('Demo.opk', old)
        with self.assertRaises(ToolError):
            self.install(package(namespace='Demo'))
        with open(os.path.join(self.app, 'Demo.opk'), 'rb') as stream:
            self.assertEqual(stream.read(), old)
        self.assert_no_temp()

    def test_cancel_discards_upload(self):
        data = package()
        outcome = self.begin(data)
        upload_id = outcome.data['upload_id']
        cancelled = self.tool.handler(self.ctx, {'operation': 'cancel', 'upload_id': upload_id})
        self.assertFalse(cancelled.is_error)
        self.assertTrue(cancelled.data['cancelled'])
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 0,
                'chunk': base64.b64encode(data[:1]).decode()})
        self.assertFalse(os.path.exists(os.path.join(self.app, 'Demo.opk')))

    def test_commit_sha_mismatch_leaves_target_untouched(self):
        old = package(manifest_data=manifest(info='old'))
        self.write_existing('Demo.opk', old)
        data = package(manifest_data=manifest(info='new'))
        upload_id = self.upload(data)
        with self.assertRaises(ToolError):
            self.commit(upload_id, data, digest='0' * 64)
        with open(os.path.join(self.app, 'Demo.opk'), 'rb') as stream:
            self.assertEqual(stream.read(), old)
        self.assert_no_temp()
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 0,
                'chunk': base64.b64encode(data[:1]).decode()})

    def test_new_target_appearing_before_publish_is_not_clobbered(self):
        data = package(manifest_data=manifest(info='new'))
        calls = []

        def changed(root, filename):
            calls.append(True)
            return len(calls) > 1

        with patch.object(plugin_install, '_target_exists', side_effect=changed):
            with self.assertRaises(ToolError):
                self.install(data)
        self.assertFalse(os.path.exists(os.path.join(self.app, 'Demo.opk')))
        self.assert_no_temp()

    def test_new_target_appearing_at_link_time_is_not_clobbered(self):
        data = package(manifest_data=manifest(info='new'))
        real_link = os.link
        target = os.path.join(self.app, 'Demo.opk')

        def racing_link(source, destination, *args, **kwargs):
            with open(target, 'wb') as stream:
                stream.write(b'outer-writer')
            return real_link(source, destination, *args, **kwargs)

        with patch.object(plugin_install.os, 'link', side_effect=racing_link):
            with self.assertRaises(ToolError):
                self.install(data)
        with open(target, 'rb') as stream:
            self.assertEqual(stream.read(), b'outer-writer')
        self.assert_no_temp()

    def test_trusted_absolute_package_root_outside_cwd(self):
        with tempfile.TemporaryDirectory(prefix='cockpit-external-root-') as directory:
            external = os.path.join(os.path.realpath(directory), 'app')
            os.makedirs(external)
            ctx = make_ctx(self.root, self.manager, package_path=external)
            outcome = self.install(package(), ctx=ctx)
            self.assertFalse(outcome.is_error, outcome.data)
            self.assertTrue(os.path.isfile(os.path.join(external, 'Demo.opk')))
            self.assertFalse(os.path.exists(os.path.join(self.app, 'Demo.opk')))

    def test_package_root_capability_errors_fail_safely(self):
        for olivos in (None, types.SimpleNamespace(),
                       types.SimpleNamespace(pluginAPI=types.SimpleNamespace(plugin_path=''))):
            with self.subTest(olivos=olivos):
                ctx = contracts.Context(None, self.root, os.path.join(self.root, 'plugin/data'),
                                        olivos=olivos, config=self.manager)
                with self.assertRaises(ToolError):
                    self.begin(package(), ctx)

    def test_symlink_package_root_is_rejected(self):
        real = os.path.join(self.root, 'real-app')
        os.makedirs(real)
        link = os.path.join(self.root, 'linked-app')
        os.symlink(real, link)
        ctx = make_ctx(self.root, self.manager, package_path=link)
        with self.assertRaises(ToolError):
            self.begin(package(), ctx)

    def test_denied_package_root_is_rejected(self):
        self.manager.current = config.Snapshot(
            valid=True, generation=1, api_key='test-key', full_real_account_write=True,
            full_plugin_install=True, denied_paths=(self.app,))
        with self.assertRaises(ToolError):
            self.begin(package())

    def test_permission_and_mode_gate_direct_handler_calls(self):
        for mode, values in (
                (MODE_LITE, {}),
                (MODE_FULL, {'full_real_account_write': False}),
                (MODE_FULL, {'full_plugin_install': False})):
            with self.subTest(mode=mode, values=values):
                manager = Manager(**values)
                ctx = make_ctx(self.root, manager, mode=mode)
                with self.assertRaises(ToolError):
                    self.begin(package(), ctx)

    def test_archive_validation_failure_leaves_no_file_or_temp(self):
        bad = build_entries([('../evil', b'x')])
        with self.assertRaises(ToolError):
            self.install(bad)
        self.assertFalse(os.path.exists(os.path.join(self.app, 'Demo.opk')))
        self.assert_no_temp()


class UploadTests(Base):
    def test_single_active_upload_and_sequential_offsets(self):
        first = self.begin()
        self.assertFalse(first.is_error)
        second = self.begin()
        self.assertTrue(second.is_error)
        self.assertIn('in progress', second.data['error'])
        upload_id = first.data['upload_id']
        chunk = base64.b64encode(b'abc').decode()
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 1, 'chunk': chunk})
        good = self.tool.handler(self.ctx, {
            'operation': 'write', 'upload_id': upload_id, 'offset': 0, 'chunk': chunk})
        self.assertFalse(good.is_error)
        self.assertEqual(good.data['offset'], 3)

    def test_strict_base64_offsets_and_size_budget(self):
        data = package()
        upload_id = self.begin(data=data).data['upload_id']
        for chunk in ('', '!!!!', 'YQ==\n'):
            with self.assertRaises(ToolError):
                self.tool.handler(self.ctx, {
                    'operation': 'write', 'upload_id': upload_id, 'offset': 0, 'chunk': chunk})
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 0,
                'chunk': base64.b64encode(b'a' * (plugin_install.MAX_CHUNK + 1)).decode()})
        self.tool.handler(self.ctx, {
            'operation': 'write', 'upload_id': upload_id, 'offset': 0,
            'chunk': base64.b64encode(b'abc').decode()})
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 3,
                'chunk': base64.b64encode(b'x' * (len(data) - 2)).decode()})
        self.assertEqual(plugin_install._UPLOAD['data'], bytearray(b'abc'))

    def test_expiry_clears_upload_and_rejects_late_writes(self):
        data = package()
        with patch.object(plugin_install, '_now', return_value=100.0):
            upload_id = self.begin(data=data).data['upload_id']
        with patch.object(plugin_install, '_now', return_value=399.9):
            outcome = self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 0,
                'chunk': base64.b64encode(data[:1]).decode()})
            self.assertFalse(outcome.is_error)
        with patch.object(plugin_install, '_now', return_value=400.0):
            with self.assertRaises(ToolError):
                self.tool.handler(self.ctx, {
                    'operation': 'write', 'upload_id': upload_id, 'offset': 1,
                    'chunk': base64.b64encode(data[1:2]).decode()})
        self.assertIsNone(plugin_install._UPLOAD)

    def test_generation_and_permission_changes_revoke_and_sweep(self):
        upload_id = self.begin().data['upload_id']
        self.manager.current = config.Snapshot(
            valid=True, generation=2, api_key='test-key', full_real_account_write=True,
            full_plugin_install=True)
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': upload_id, 'offset': 0,
                'chunk': base64.b64encode(b'x').decode()})
        self.assertTrue(plugin_install.sweep(self.ctx))
        self.assertIsNone(plugin_install._UPLOAD)
        self.assertFalse(plugin_install.sweep(self.ctx))

    def test_other_owner_and_detach_clear_upload(self):
        first = self.begin().data['upload_id']
        other = make_ctx(self.root, Manager())
        self.assertTrue(plugin_install.sweep(other))
        self.assertIsNone(plugin_install._UPLOAD)
        self.begin()
        plugin_install.detach(self.ctx)
        self.assertIsNone(plugin_install._UPLOAD)
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {
                'operation': 'write', 'upload_id': first, 'offset': 0,
                'chunk': base64.b64encode(b'x').decode()})

    def test_begin_identity_and_size_validation(self):
        for case in (
                {'filename': '../x.opk'}, {'filename': 'x'}, {'filename': '.opk'},
                {'filename': 'OlivOSCockpit.opk'}, {'filename': 'OlivOS.opk'},
                {'namespace': 'bad-name'}, {'namespace': 'OlivOSCockpit'},
                {'namespace': 'olivos'}, {'size': 0}, {'size': plugin_install.MAX_OPK + 1},
                {'size': True}, {'size': '1'}):
            values = dict(filename='Demo.opk', namespace='Demo', size=1)
            values.update(case)
            with self.subTest(case=case), self.assertRaises(ToolError):
                self.begin(**values)

    def test_schema_and_operation_fields(self):
        spec = self.tool
        self.assertEqual(spec.required_permission, 'plugin_install')
        self.assertFalse(spec.read_only)
        self.assertEqual(spec.schema['properties']['operation']['enum'],
                         ['begin', 'write', 'commit', 'cancel'])
        self.assertNotIn('expected_sha256', spec.schema['properties'])
        for args in ({}, {'operation': 'nope'}):
            with self.assertRaises(ToolError):
                contracts.validate_arguments(spec, args)
        with self.assertRaises(ToolError):
            self.tool.handler(self.ctx, {'operation': 'begin', 'filename': 'x.opk'})


class ArchiveValidationTests(Base):
    @staticmethod
    def _encrypted(data):
        cd = data.find(b'PK\x01\x02')
        data[cd + 8:cd + 10] = (int.from_bytes(data[cd + 8:cd + 10], 'little') | 1).to_bytes(2, 'little')
        local = data.find(b'PK\x03\x04')
        data[local + 6:local + 8] = (int.from_bytes(data[local + 6:local + 8], 'little') | 1).to_bytes(2, 'little')

    @staticmethod
    def _multidisk(data):
        eocd = data.rfind(b'PK\x05\x06')
        data[eocd + 4:eocd + 6] = (1).to_bytes(2, 'little')

    def assert_rejected(self, data):
        with self.assertRaises(ToolError):
            self.install(data)
        self.assertFalse(os.path.exists(os.path.join(self.app, 'Demo.opk')))
        self.assert_no_temp()

    def test_traversal_absolute_backslash_and_drive_names(self):
        for name in ('../evil', '/evil', '..\\evil', 'C:evil', 'a/../../evil',
                     'a/..', '.', 'a//b'):
            with self.subTest(name=name):
                self.assert_rejected(build_entries([(name, b'x')]))

    def test_duplicate_case_alias_and_file_prefix_conflicts(self):
        self.assert_rejected(build_entries(['same', 'same']))
        self.assert_rejected(build_entries(['Case', 'case']))
        self.assert_rejected(build_entries(['prefix', 'prefix/child']))

    def test_symlink_special_and_inconsistent_types(self):
        symlink = (stat.S_IFLNK | 0o777) << 16
        fifo = (stat.S_IFIFO | 0o644) << 16
        directory = (stat.S_IFDIR | 0o755) << 16
        self.assert_rejected(build_entries([raw_member('link', external_attr=symlink)]))
        self.assert_rejected(build_entries([raw_member('pipe', external_attr=fifo)]))
        self.assert_rejected(build_entries([raw_member('file', external_attr=directory)]))
        self.assert_rejected(build_entries([raw_member('app.json/', external_attr=directory)]))

    def test_required_root_python_entries(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('app.json', json.dumps(manifest()))
            archive.writestr('main.py', b'')
        self.assert_rejected(buffer.getvalue())
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('app.json', json.dumps(manifest()))
            archive.writestr('__init__.py', b'')
        self.assert_rejected(buffer.getvalue())

    def test_manifest_bom_duplicate_keys_budget_and_namespace(self):
        self.assert_rejected(build_entries(
            [], manifest_raw=b'\xef\xbb\xbf' + json.dumps(manifest()).encode()))
        self.assert_rejected(build_entries(
            [], manifest_raw=b'{"namespace":"Demo","namespace":"Demo"}'))
        self.assert_rejected(build_entries([], manifest_raw=b'[]'))
        self.assert_rejected(build_entries([], manifest_raw=json.dumps(
            manifest(namespace='Other')).encode()))
        self.assert_rejected(build_entries([], manifest_raw=json.dumps(
            manifest(namespace='bad-name')).encode()))
        self.assert_rejected(build_entries([], manifest_raw=json.dumps(
            {'namespace': 'Demo', 'svn': '1'}).encode()))
        payload = json.dumps({'namespace': 'Demo', 'pad': 'x' * contracts.MAX_MANIFEST}).encode()
        self.assert_rejected(build_entries([], manifest_raw=payload))

    def test_encrypted_zip64_multidisk_and_compression(self):
        valid = package(compression=zipfile.ZIP_STORED)
        for mutate in (self._encrypted, self._multidisk):
            data = bytearray(valid)
            mutate(data)
            with self.subTest(mutate=mutate.__name__):
                self.assert_rejected(bytes(data))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('app.json', json.dumps(manifest()))
            archive.writestr('__init__.py', b'')
            archive.writestr('main.py', b'')
            with archive.open('big', 'w', force_zip64=True) as stream:
                stream.write(b'x')
        self.assert_rejected(buffer.getvalue())
        data = bytearray(valid)
        cd = data.find(b'PK\x01\x02')
        data[cd + 10:cd + 12] = (12).to_bytes(2, 'little')
        self.assert_rejected(bytes(data))

    def test_expanded_package_limits(self):
        self.assert_rejected(package(members={
            'large': b'\0' * (plugin_install.MAX_EXPANDED_FILE + 1)}))
        members = {'p%d' % index: b'\0' * (7 * 1024 * 1024) for index in range(5)}
        self.assert_rejected(package(members=members))

    def test_crc_corruption_is_rejected(self):
        data = bytearray(package(compression=zipfile.ZIP_STORED))
        cd = data.find(b'PK\x01\x02')
        name_len = int.from_bytes(data[cd + 28:cd + 30], 'little')
        extra_len = int.from_bytes(data[cd + 30:cd + 32], 'little')
        local = int.from_bytes(data[cd + 42:cd + 46], 'little')
        start = local + 30 + name_len + extra_len
        data[start] ^= 1
        data[cd + 16:cd + 20] = (0xDEADBEEF).to_bytes(4, 'little')
        self.assert_rejected(bytes(data))

    def test_existing_duplicate_namespace_package_and_source(self):
        self.write_existing('Other.opk', package(namespace='Demo'))
        self.assert_rejected(package(namespace='Demo'))
        os.unlink(os.path.join(self.app, 'Other.opk'))
        source = os.path.join(self.app, 'Source')
        os.makedirs(source)
        with open(os.path.join(source, 'app.json'), 'wb') as stream:
            stream.write(json.dumps({'namespace': 'Demo'}).encode())
        self.assert_rejected(package(namespace='Demo'))
        os.unlink(os.path.join(source, 'app.json'))
        os.rmdir(source)
        # 目标自身允许同名覆盖，不算另一份包。
        self.write_existing('Demo.opk', package(namespace='Demo', manifest_data=manifest(info='old')))
        outcome = self.install(package(namespace='Demo', manifest_data=manifest(info='new')))
        self.assertFalse(outcome.is_error, outcome.data)
        self.assertTrue(outcome.data['replaced'])

    def test_scan_fails_closed_on_symlink_or_malformed_existing_package(self):
        os.symlink('/etc/passwd', os.path.join(self.app, 'Link'))
        self.assert_rejected(package())
        os.unlink(os.path.join(self.app, 'Link'))
        self.write_existing('Broken.opk', b'not a zip')
        self.assert_rejected(package())
        os.unlink(os.path.join(self.app, 'Broken.opk'))
        os.makedirs(os.path.join(self.app, 'Deep'))
        os.makedirs(os.path.join(self.app, 'Deep', 'Nested'))
        with open(os.path.join(self.app, 'Deep', 'Nested', 'x.opk'), 'wb') as stream:
            stream.write(b'not a zip')
        self.assert_rejected(package())

    def test_nul_member_name(self):
        # zipfile 构造期即截断 NUL，无法从真实归档观察；直接覆盖原始名校验。
        info = types.SimpleNamespace(filename='bad\x00name')
        with self.assertRaises(ToolError):
            plugin_install._member_name(info)


class LifecycleTests(Base):
    def test_registry_tick_and_detach_are_wired(self):
        from OlivOSCockpit import registry
        self.assertTrue(callable(registry.tick))
        self.assertIn('cockpit_plugin_install',
                      [tool.name for tool in registry.TOOLS])
        upload_id = self.begin(package()).data['upload_id']
        self.assertFalse(registry.tick(self.ctx))
        self.assertEqual(plugin_install._UPLOAD['id'], upload_id)
        with patch.object(registry.intercept, 'uninstall', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                registry.detach(self.ctx)
        self.assertIsNone(plugin_install._UPLOAD)

    def test_attach_retires_stale_other_owner_state(self):
        from OlivOSCockpit import registry
        self.begin(package())
        other = make_ctx(self.root, Manager())
        with patch.object(registry.intercept, 'install', return_value=None):
            registry.attach(other)
        self.assertIsNone(plugin_install._UPLOAD)


if __name__ == '__main__':
    unittest.main(verbosity=2)
