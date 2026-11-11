"""host 与 full_only 的隔离测试；不接触真实宿主。"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from OlivOSCockpit import full_only, host  # noqa: E402
from OlivOSCockpit.contracts import Context, ToolError, validate_arguments  # noqa: E402


class Platform:
    def __init__(self, sdk='qq', platform='qq', model='model'):
        self.sdk = sdk
        self.platform = platform
        self.model = model


class Bot:
    def __init__(self, hash_):
        self.hash = hash_
        self.id = '10001'
        self.platform = Platform()
        self.post_info = {'token': 'SECRET-TOKEN'}
        self.password = 'SECRET-PASS'
        self.vars = {'cookie': 'SECRET-COOKIE'}


class ParaText:
    def __init__(self, text):
        self.type = 'text'
        self.data = {'text': text}


class Template:
    def __init__(self, mode, data):
        self.active = True
        self.mode_rx = mode
        self.data = data


class Event:
    def __init__(self, sdk, log, bot=None):
        self.sdk = sdk
        self.calls = sdk.calls
        self.active = True
        self.bot_info = bot
        self.platform = {'sdk': 'qq', 'platform': 'qq', 'model': 'model'}
        self.plugin_info = {'message_mode_rx': 'olivos_para'}

    def send(self, send_type, target_id, message, host_id=None):
        self.calls.append(('send', send_type, target_id, message))
        return None


class ContentAPI:
    def __init__(self, sdk):
        self.sdk = sdk

    def fake_sdk_event(self, **kwargs):
        self.sdk.calls.append(('fake', kwargs.get('fakename')))
        return {'fake': True, 'bot_info': kwargs.get('bot_info')}


class API:
    def __init__(self, sdk):
        self.sdk = sdk

    def Event(self, fake, log):
        self.sdk.calls.append(('event', log))
        return Event(self.sdk, log, bot=fake.get('bot_info') if type(fake) is dict else None)


class SDK:
    def __init__(self):
        self.calls = []
        self.contentAPI = ContentAPI(self)
        self.API = API(self)
        self.messageAPI = type('M', (), {
            'PARA': type('P', (), {'text': staticmethod(ParaText)}),
            'Message_templet': Template,
        })


class Database:
    def __init__(self):
        self.calls = []
        self.result = True

    def set_config(self, namespace, key, value, pkl=False):
        self.calls.append((namespace, key, value, pkl))
        return self.result


class Proc:
    def __init__(self, bots=None, plugins=None):
        self.Proc_data = {'bot_info_dict': bots if bots is not None else {}}
        self.plugins = plugins if plugins is not None else {'A', 'B'}
        self.log = 'LOG'
        self.requests = []
        self.database = Database()

    def get_plugin_list(self):
        return self.plugins

    def set_restart(self):
        self.requests.append('restart')
        return True


def make(bots=None, plugins=None, olivos=None):
    sdk = SDK()
    proc = Proc(bots, plugins)
    return Context(proc=proc, root='/tmp/root', data_root='/tmp/data',
                   olivos=olivos if olivos is not None else sdk), sdk, proc


class Snapshot:
    def __init__(self, lite_real_account_read=False):
        self.lite_real_account_read = lite_real_account_read

    def allows(self, permission, mode):
        if permission == 'real_account_read':
            return mode == 'full' or self.lite_real_account_read
        return permission is None


class WriteSnapshot:
    """显式开启 Full 写；low_level 需两个开关同时打开。"""

    def __init__(self, write=True, low_level=True, valid=True, generation=0, denied=()):
        self.full_real_account_write = write
        self.full_low_level_access = low_level
        self.valid = valid
        self.generation = generation
        self.denied_paths = tuple(denied)

    def allows(self, permission, mode):
        if not self.valid:
            return False
        if permission == 'real_account_read':
            return mode == 'full'
        if permission == 'real_account_write':
            return mode == 'full' and self.full_real_account_write
        if permission == 'low_level_access':
            return mode == 'full' and self.full_real_account_write and self.full_low_level_access
        return permission is None


class Manager:
    def __init__(self, snapshot):
        self.value = snapshot

    def snapshot(self):
        return self.value


def scoped(mode, allowed=False):
    ctx, _, _ = make(BOTS)
    return Context(proc=ctx.proc, root='/tmp/root', data_root='/tmp/data',
                   config=Manager(Snapshot(allowed)), permission_mode=mode)


def authorized(mode='full', **kwargs):
    """显式授权的上下文；文件策略需要真实存在的允许根。"""
    ctx, sdk, proc = make(BOTS)
    ctx = Context(proc=proc, root=ctx.root, data_root=ctx.data_root, olivos=sdk,
                  config=Manager(WriteSnapshot(**kwargs)), permission_mode=mode)
    return ctx, sdk, proc


BOTS = {'hash-a': Bot('hash-a'), 'hash-b': Bot('hash-b')}
SEND_ARGS = {'bot_hash': 'hash-a', 'send_type': 'private',
             'target_id': '42', 'message': 'hello'}


class StatusTests(unittest.TestCase):
    def test_status_unknowns_and_plugins(self):
        ctx, _, _ = make(BOTS)
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(data['olivos_version'], 'unknown')
        self.assertEqual(data['olivos_svn'], 'unknown')
        self.assertEqual(data['plugins']['namespaces'], ['A', 'B'])
        self.assertEqual(data['configured_bot_count'], 2)
        self.assertEqual(data['root'], '/tmp/root')

    def test_status_olivos_info_known(self):
        class Info:
            OlivOS_version = '1.0'
            OlivOS_svn_version = '123'

        class Host:
            infoAPI = Info()

        ctx, _, _ = make(BOTS, olivos=Host())
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(data['olivos_version'], '1.0')
        self.assertEqual(data['olivos_svn'], '123')

    def test_status_real_constant_names_and_int_svn(self):
        class Info:
            OlivOS_Version = '1.0.0'
            OlivOS_SVN = 300

        class Host:
            infoAPI = Info()

        ctx, _, _ = make(BOTS, olivos=Host())
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(data['olivos_version'], '1.0.0')
        self.assertEqual(data['olivos_svn'], 300)

    def test_status_zero_svn_is_kept(self):
        class Info:
            OlivOS_SVN = 0

        class Host:
            infoAPI = Info()

        ctx, _, _ = make(BOTS, olivos=Host())
        self.assertEqual(host.TOOLS[0].handler(ctx, {}).data['olivos_svn'], 0)

    def test_status_bounds_namespaces(self):
        ctx, _, _ = make(BOTS, plugins={f'p{i}' for i in range(600)})
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(len(data['plugins']['namespaces']), 500)
        self.assertTrue(data['plugins']['truncated'])

    def test_plugin_names_and_status_read_the_host_list_once(self):
        ctx, _, proc = make(BOTS, plugins=['B', 'A'])
        calls = []
        original = proc.get_plugin_list
        proc.get_plugin_list = lambda: (calls.append('list') or original())
        self.assertEqual(host.plugin_names(proc), (['A', 'B'], False))
        self.assertEqual(calls, ['list'])
        calls.clear()
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(data['plugins']['namespaces'], ['A', 'B'])
        self.assertEqual(calls, ['list'])

    def test_status_includes_debug_terminal_state(self):
        ctx, _, _ = make(BOTS)
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(data['debug_terminal'],
                         {'selected': False, 'connection': 'unknown'})
        ctx.terminal.update(checked=True, hash='x')
        data = host.TOOLS[0].handler(ctx, {}).data
        self.assertEqual(data['debug_terminal']['error'],
                         'Selected account is no longer available')
        self.assertEqual(data['configured_bot_count'], 2)

    def test_status_survives_baseexception(self):
        ctx, _, proc = make(BOTS)

        def boom():
            raise SystemExit('bad')

        proc.get_plugin_list = boom
        out = host.TOOLS[0].handler(ctx, {})
        self.assertFalse(out.is_error)
        self.assertFalse(out.data['plugins']['available'])


class BotsTests(unittest.TestCase):
    def test_bots_fields_whitelisted(self):
        ctx, _, _ = make(BOTS)
        out = host.TOOLS[1].handler(ctx, {})
        self.assertFalse(out.is_error)
        self.assertEqual(out.data['count'], 2)
        for bot in out.data['bots']:
            self.assertEqual(set(bot), {'hash', 'id', 'platform', 'connection'})
            self.assertEqual(bot['connection'], 'unknown')
            self.assertEqual(set(bot['platform']), {'sdk', 'platform', 'model'})
        text = repr(out.data)
        self.assertNotIn('SECRET', text)
        self.assertNotIn('post_info', text)

    def test_bots_does_not_trigger_properties(self):
        triggered = []

        class Sneaky:
            def __init__(self):
                self.hash = 'h'
                self.platform = Platform()

            @property
            def id(self):
                triggered.append('id')
                raise RuntimeError('no')

        ctx, _, _ = make({'h': Sneaky()})
        out = host.TOOLS[1].handler(ctx, {})
        self.assertEqual(triggered, [])
        self.assertIsNone(out.data['bots'][0]['id'])  # 不触发 property

    def test_bots_state_without_checked_flag(self):
        ctx, _, _ = make(BOTS)
        out = host.TOOLS[1].handler(ctx, {})
        self.assertEqual(out.data['debug_terminal']['selected'], False)
        self.assertEqual(out.data['count'], 2)

    def test_bots_unavailable(self):
        ctx, _, proc = make(BOTS)
        proc.Proc_data = {}
        self.assertTrue(host.TOOLS[1].handler(ctx, {}).is_error)

    def test_malicious_object_skipped(self):
        class Slotted:
            __slots__ = ()

        ctx, _, _ = make({'h': Slotted()})
        out = host.TOOLS[1].handler(ctx, {})
        self.assertEqual(out.data['bots'], [])
        self.assertEqual(out.data['count'], 0)

    def test_real_account_read_permission_is_enforced(self):
        self.assertFalse(host.TOOLS[1].handler(scoped('full'), {}).is_error)
        self.assertTrue(host.TOOLS[1].handler(scoped('lite'), {}).is_error)
        self.assertFalse(host.TOOLS[1].handler(scoped('lite', True), {}).is_error)
        # 授权元数据不进入 MCP definition，readOnlyHint 不能作为授权依据。
        self.assertEqual(set(host.TOOLS[1].definition()),
                         {'name', 'description', 'inputSchema', 'annotations'})


class SendTests(unittest.TestCase):
    spec = full_only.TOOLS[0]

    def test_send_denied_without_configuration(self):
        ctx, sdk, _ = make(BOTS)
        out = self.spec.handler(ctx, dict(SEND_ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Real account write is disabled')
        self.assertEqual(sdk.calls, [])

    def test_send_denied_without_write_flag(self):
        ctx, sdk, _ = authorized(write=False)
        self.assertTrue(self.spec.handler(ctx, dict(SEND_ARGS)).is_error)
        self.assertEqual(sdk.calls, [])

    def test_send_denied_when_generation_changed(self):
        ctx, sdk, _ = authorized()
        ctx = Context(proc=ctx.proc, root=ctx.root, data_root=ctx.data_root,
                      olivos=ctx.olivos, config=ctx.config,
                      permission_mode='full', request_generation=99)
        self.assertTrue(self.spec.handler(ctx, dict(SEND_ARGS)).is_error)
        self.assertEqual(sdk.calls, [])

    def test_send_records_and_reports_unknown(self):
        ctx, sdk, _ = authorized()
        out = self.spec.handler(ctx, dict(SEND_ARGS))
        self.assertFalse(out.is_error, out.data)
        self.assertTrue(out.data['submitted'])
        self.assertEqual(out.data['delivery'], 'unknown')
        self.assertEqual(sdk.calls[0], ('fake', 'OlivOSCockpit'))
        send = [call for call in sdk.calls if call[0] == 'send'][0]
        self.assertEqual(send[1:3], ('private', '42'))
        self.assertIsInstance(send[3], Template)
        self.assertEqual(send[3].mode_rx, 'olivos_para')
        self.assertEqual([(para.type, para.data) for para in send[3].data],
                         [('text', {'text': 'hello'})])

    def test_message_segment_syntax_is_not_parsed(self):
        ctx, sdk, _ = authorized()
        message = '[CQ:image,file=/etc/passwd][OP:at,id=1]'
        out = self.spec.handler(ctx, dict(SEND_ARGS, message=message))
        self.assertFalse(out.is_error, out.data)
        send = [call for call in sdk.calls if call[0] == 'send'][0]
        self.assertEqual(send[3].data[0].data['text'], message)

    def test_string_encoded_adapter_mode_is_rejected(self):
        ctx, sdk, _ = authorized()
        original = Event.__init__

        def string_mode(event, sdk_, log, bot=None):
            original(event, sdk_, log, bot)
            event.plugin_info['message_mode_rx'] = 'old_string'

        Event.__init__ = string_mode
        try:
            out = self.spec.handler(ctx, dict(SEND_ARGS))
        finally:
            Event.__init__ = original
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'],
                         'Adapter message mode does not support safe text-only submission')
        self.assertEqual([call for call in sdk.calls if call[0] == 'send'], [])

    def test_send_unknown_bot(self):
        ctx, _, _ = authorized()
        args = dict(SEND_ARGS, bot_hash='nope')
        out = self.spec.handler(ctx, args)
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Unknown bot_hash')

    def test_send_rejects_bot_hash_mismatch(self):
        ctx, sdk, _ = authorized()
        # 字典键与账号自身 hash 不一致时不得发送。
        ctx.proc.Proc_data['bot_info_dict'] = {'hash-a': Bot('other')}
        out = self.spec.handler(ctx, dict(SEND_ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Unknown bot_hash')
        self.assertEqual(sdk.calls, [])

    def test_send_host_baseexception_isolated(self):
        ctx, sdk, _ = authorized()

        def boom(send_type, target, message, host_id=None):
            raise KeyboardInterrupt('SECRET-TOKEN')

        original = Event.send
        Event.send = boom
        try:
            out = self.spec.handler(ctx, dict(SEND_ARGS))
        finally:
            Event.send = original
        self.assertTrue(out.is_error)
        self.assertNotIn('SECRET', repr(out.data))

    def test_send_without_olivos(self):
        ctx, _, _ = authorized()
        ctx = Context(proc=ctx.proc, root=ctx.root, data_root=ctx.data_root,
                      olivos=None, config=ctx.config, permission_mode='full')
        self.assertTrue(self.spec.handler(ctx, dict(SEND_ARGS)).is_error)

    def test_send_schema(self):
        with self.assertRaises(ToolError):
            validate_arguments(self.spec, dict(SEND_ARGS, send_type='channel'))
        with self.assertRaises(ToolError):
            validate_arguments(self.spec, dict(SEND_ARGS, extra=1))
        with self.assertRaises(ToolError):
            validate_arguments(self.spec, dict(SEND_ARGS, message=''))

    def test_send_message_utf8_byte_budget(self):
        ctx, sdk, _ = authorized()
        half = '中' * (full_only.MAX_MESSAGE // 3 + 1)  # 未超字符数，但超 UTF-8 字节
        self.assertLessEqual(len(half), full_only.MAX_MESSAGE)
        with self.assertRaises(ToolError):
            self.spec.handler(ctx, dict(SEND_ARGS, message=half))
        self.assertEqual(sdk.calls, [])


class ReloadTests(unittest.TestCase):
    spec = full_only.TOOLS[1]

    def test_reload_denied_without_configuration(self):
        ctx, _, proc = make(BOTS)
        out = self.spec.handler(ctx, {'confirm': True})
        self.assertTrue(out.is_error)
        self.assertEqual(proc.requests, [])

    def test_reload_requires_confirm(self):
        ctx, _, proc = authorized()
        for args in ({}, {'confirm': 'true'}, {'confirm': False}):
            with self.assertRaises(ToolError):
                self.spec.handler(ctx, args)
        self.assertEqual(proc.requests, [])

    def test_reload_deferred(self):
        ctx, _, proc = authorized()
        out = self.spec.handler(ctx, {'confirm': True})
        self.assertEqual(out.data, {'accepted': True, 'scope': 'all_plugins'})
        self.assertEqual(proc.requests, [])
        out.after_send()
        self.assertEqual(proc.requests, ['restart'])

    def test_reload_skips_when_permission_revoked_after_send(self):
        ctx, _, proc = authorized()
        out = self.spec.handler(ctx, {'confirm': True})
        ctx.config.value = WriteSnapshot(write=False)
        out.after_send()
        self.assertEqual(proc.requests, [])

    def test_reload_without_api(self):
        ctx, _, proc = authorized()
        proc.set_restart = None
        self.assertTrue(self.spec.handler(ctx, {'confirm': True}).is_error)

    def test_reload_callback_never_raises(self):
        ctx, _, proc = authorized()

        def boom():
            raise SystemExit('bad')

        proc.set_restart = boom
        out = self.spec.handler(ctx, {'confirm': True})
        out.after_send()  # 不得抛出


class ProcGetTests(unittest.TestCase):
    spec = full_only.TOOLS[2]

    def test_proc_get_denied_without_configuration(self):
        ctx, _, _ = make(BOTS)
        self.assertTrue(self.spec.handler(ctx, {'path': 'bot_hashes'}).is_error)

    def test_proc_get_requires_both_low_level_switches(self):
        for kwargs in ({'write': False}, {'low_level': False}, {'valid': False}):
            ctx, _, _ = authorized(**kwargs)
            self.assertTrue(self.spec.handler(ctx, {'path': 'bot_hashes'}).is_error)

    def test_whitelist(self):
        ctx, _, _ = authorized()
        for path in ('bot_info_dict', '__class__', 'proc.__dict__', ''):
            with self.assertRaises(ToolError):
                self.spec.handler(ctx, {'path': path})
        with self.assertRaises(ToolError):
            validate_arguments(self.spec, {'path': '__class__'})

    def test_known_paths(self):
        ctx, _, _ = authorized()
        hashes = self.spec.handler(ctx, {'path': 'bot_hashes'})
        self.assertEqual(hashes.data['value'], ['hash-a', 'hash-b'])
        names = self.spec.handler(ctx, {'path': 'plugin_names'})
        self.assertEqual(names.data['value'], ['A', 'B'])
        version = self.spec.handler(ctx, {'path': 'olivos_version'})
        self.assertTrue(version.is_error)

    def test_bounded_depth(self):
        value = current = []
        for _ in range(12):
            nxt = []
            current.append(nxt)
            current = nxt
        result = full_only._bounded(value)
        depth = 0
        while isinstance(result, list) and result:
            result = result[0]
            depth += 1
        self.assertLessEqual(depth, 8)

    def test_bounded_ignores_custom_objects(self):
        class Weird:
            def __repr__(self):
                raise RuntimeError('SECRET')

        self.assertEqual(full_only._bounded({'a': Weird()}), {'a': None})


class PluginConfigSetTests(unittest.TestCase):
    spec = full_only.TOOLS[3]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        Path(self.root, 'plugin', 'conf').mkdir(parents=True)
        Path(self.root, 'plugin', 'conf', 'UserConfAll.db').write_bytes(b'')
        Path(self.root, 'plugin', 'data').mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def context(self, **kwargs):
        ctx, sdk, proc = authorized(**kwargs)
        return Context(proc=proc, root=self.root, data_root=os.path.join(self.root, 'plugin', 'data'),
                       olivos=sdk, config=ctx.config, permission_mode='full'), proc

    def test_denied_without_configuration(self):
        ctx, sdk, proc = make(BOTS)
        ctx = Context(proc=proc, root=self.root, data_root=os.path.join(self.root, 'plugin', 'data'),
                      olivos=sdk)
        out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': 1})
        self.assertTrue(out.is_error)
        self.assertEqual(proc.database.calls, [])

    def test_writes_verbatim_scalar_without_pickle(self):
        ctx, proc = self.context()
        for value in (7, -1, True, 1.5, 'text', None):
            out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': value})
            self.assertFalse(out.is_error, out.data)
        self.assertEqual(proc.database.calls, [
            ('Example', 'k', 7, False), ('Example', 'k', -1, False),
            ('Example', 'k', True, False), ('Example', 'k', 1.5, False),
            ('Example', 'k', 'text', False), ('Example', 'k', None, False)])
        self.assertEqual(self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k',
                                                 'value': 'x' * 65536}).is_error, False)

    def test_rejects_own_namespace_and_path_like_names(self):
        ctx, proc = self.context()
        for args in ({'namespace': 'OlivOSCockpit', 'key': 'k', 'value': 1},
                     {'namespace': 'olivoscockpit', 'key': 'k', 'value': 1},
                     {'namespace': 'a/b', 'key': 'k', 'value': 1},
                     {'namespace': 'a\\b', 'key': 'k', 'value': 1},
                     {'namespace': 'Example', 'key': 'a\x00b', 'value': 1}):
            with self.assertRaises(ToolError):
                self.spec.handler(ctx, args)
        self.assertEqual(proc.database.calls, [])

    def test_rejects_non_scalar_and_unbounded_values(self):
        ctx, proc = self.context()
        for value in ({}, [], [1], {'a': 1}, float('nan'), float('inf'), 2 ** 63,
                      'x\x00y', 'x' * (full_only.MAX_CONFIG_VALUE + 1)):
            with self.assertRaises(ToolError):
                self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': value})
        self.assertEqual(proc.database.calls, [])

    def test_denied_paths_cover_database(self):
        ctx, proc = self.context(denied=('plugin/conf',))
        out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': 1})
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Plugin configuration path is forbidden')
        self.assertEqual(proc.database.calls, [])

    def test_missing_database_file_is_rejected(self):
        ctx, proc = self.context()
        Path(self.root, 'plugin', 'conf', 'UserConfAll.db').unlink()
        out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': 1})
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Plugin configuration path is forbidden')
        self.assertEqual(proc.database.calls, [])

    def test_symlinked_database_is_rejected(self):
        ctx, proc = self.context()
        outside = Path(self.tmp.name, 'outside.db')
        outside.write_bytes(b'')
        db = Path(self.root, 'plugin', 'conf', 'UserConfAll.db')
        db.unlink()
        db.symlink_to(outside)
        out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': 1})
        self.assertTrue(out.is_error)
        self.assertEqual(proc.database.calls, [])

    def test_setter_failure_is_not_reported_as_success(self):
        ctx, proc = self.context()
        proc.database.result = False
        out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': 1})
        self.assertTrue(out.is_error)
        proc.database.result = None
        self.assertTrue(self.spec.handler(
            ctx, {'namespace': 'Example', 'key': 'k', 'value': 1}).is_error)

    def test_setter_baseexception_is_isolated(self):
        ctx, proc = self.context()

        def boom(*args, **kwargs):
            raise SystemExit('SECRET')

        proc.database.set_config = boom
        out = self.spec.handler(ctx, {'namespace': 'Example', 'key': 'k', 'value': 1})
        self.assertTrue(out.is_error)
        self.assertNotIn('SECRET', repr(out.data))

    def test_missing_database_api(self):
        ctx, proc = self.context()
        proc.database = None
        self.assertTrue(self.spec.handler(
            ctx, {'namespace': 'Example', 'key': 'k', 'value': 1}).is_error)

    def test_low_level_only_does_not_authorize_config_write(self):
        ctx, proc = self.context(write=False, low_level=True)
        self.assertTrue(self.spec.handler(
            ctx, {'namespace': 'Example', 'key': 'k', 'value': 1}).is_error)
        self.assertEqual(proc.database.calls, [])


class HostSafeTests(unittest.TestCase):
    def test_safe_passes_cancelled_error(self):
        def cancel():
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            host.safe(cancel)


if __name__ == '__main__':
    unittest.main()
