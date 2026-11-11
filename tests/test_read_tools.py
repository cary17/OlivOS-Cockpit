"""固定只读 API 的 host stub 测试；不导入或运行外部 OlivOS 源码。"""

import asyncio
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from OlivOSCockpit import host, read_tools  # noqa: E402
from OlivOSCockpit.contracts import Context, ToolError, validate_arguments  # noqa: E402


def native_hash(bot_id=None, platform_sdk=None, platform_platform=None, platform_model=None):
    value = hashlib.md5()
    for item in (bot_id, platform_sdk, platform_platform):
        value.update(str(item).encode('utf-8'))
    return value.hexdigest()


class Bot:
    def __init__(self, sdk='onebot', platform='qq', model='napcat'):
        self.id = '10001'
        self.platform = {'sdk': sdk, 'platform': platform, 'model': model}
        self.hash = native_hash(self.id, sdk, platform, model)
        self.enable = True
        self.password = 'BOT-PASSWORD'


class Result(dict):
    pass


class Strip(dict):
    pass


class Snapshot:
    def __init__(self, real_read=True, metadata=True):
        self.real_read = real_read
        self.metadata = metadata

    def allows(self, permission, mode):
        if mode not in ('full', 'lite'):
            return False
        return self.metadata if permission is None else permission == 'real_account_read' and self.real_read


class Manager:
    def __init__(self):
        self.value = Snapshot()

    def snapshot(self):
        return self.value


class Proc:
    def __init__(self, bot):
        self.Proc_data = {'bot_info_dict': {bot.hash: bot}}
        self.log = object()
        self.names = ['OtherPlugin', 'OlivOSCockpit']

    def get_plugin_list(self):
        return self.names


class QueryEvent:
    def __init__(self, sdk, fake, log):
        self.sdk = sdk
        self.bot_info = fake.bot_info
        self.platform = dict(fake.bot_info.platform)
        self.active = True
        sdk.calls.append(('event', fake, log))
        if sdk.on_build is not None:
            sdk.on_build(self)

    def _call(self, method, values, flag_log, remote):
        self.sdk.calls.append(('query', method, values, flag_log, remote))
        if self.sdk.on_query is not None:
            self.sdk.on_query(self, method)
        if self.platform['model'] == 'unsupported':
            return None
        return self.sdk.responses.get(method, self.sdk.result)

    def get_login_info(self, flag_log=True, remote=False):
        return self._call('get_login_info', (), flag_log, remote)

    def get_status(self, flag_log=True, remote=False):
        return self._call('get_status', (), flag_log, remote)

    def get_version_info(self, flag_log=True, remote=False):
        return self._call('get_version_info', (), flag_log, remote)

    def get_stranger_info(self, user_id, no_cache=False, flag_log=True, remote=False):
        return self._call('get_stranger_info', (user_id, no_cache), flag_log, remote)

    def get_friend_list(self, flag_log=True, remote=False):
        return self._call('get_friend_list', (), flag_log, remote)

    def get_group_list(self, flag_log=True, remote=False):
        return self._call('get_group_list', (), flag_log, remote)

    def get_group_info(self, group_id, host_id=None, no_cache=False, flag_log=True, remote=False):
        return self._call('get_group_info', (group_id, host_id, no_cache), flag_log, remote)

    def get_group_member_info(self, group_id, user_id, host_id=None, no_cache=False, flag_log=True, remote=False):
        return self._call('get_group_member_info', (group_id, user_id, host_id, no_cache), flag_log, remote)

    def get_group_member_list(self, group_id, host_id=None, flag_log=True, remote=False):
        return self._call('get_group_member_list', (group_id, host_id), flag_log, remote)

    def get_host_list(self, flag_log=True, remote=False):
        return self._call('get_host_list', (), flag_log, remote)

    def get_host_info(self, host_id, flag_log=True, remote=False):
        return self._call('get_host_info', (host_id,), flag_log, remote)

    def get_msg(self, message_id, flag_log=True, remote=False):
        return self._call('get_msg', (message_id,), flag_log, remote)

    def get_forward_msg(self, message_id, flag_log=True, remote=False):
        return self._call('get_forward_msg', (message_id,), flag_log, remote)

    def get_essence_msg_list(self, group_id, flag_log=True, remote=False):
        return self._call('get_essence_msg_list', (group_id,), flag_log, remote)

    def get_group_notice(self, group_id, flag_log=True, remote=False):
        return self._call('get_group_notice', (group_id,), flag_log, remote)

    def get_group_system_msg(self, count=50, flag_log=True, remote=False):
        return self._call('get_group_system_msg', (count,), flag_log, remote)

    def get_group_ignore_add_request(self, group_id=None, flag_log=True, remote=False):
        return self._call('get_group_ignore_add_request', (group_id,), flag_log, remote)

    def get_doubt_friends_add_request(self, count=50, flag_log=True, remote=False):
        return self._call('get_doubt_friends_add_request', (count,), flag_log, remote)

    def get_group_file_system_info(self, group_id, flag_log=True, remote=False):
        return self._call('get_group_file_system_info', (group_id,), flag_log, remote)

    def get_group_root_files(self, group_id, file_count=None, flag_log=True, remote=False):
        return self._call('get_group_root_files', (group_id, file_count), flag_log, remote)

    def get_group_files_by_folder(self, group_id, folder_id, file_count=None, flag_log=True, remote=False):
        return self._call('get_group_files_by_folder', (group_id, folder_id, file_count), flag_log, remote)

    def can_send_image(self, flag_log=True, remote=False):
        return self._call('can_send_image', (), flag_log, remote)

    def can_send_record(self, flag_log=True, remote=False):
        return self._call('can_send_record', (), flag_log, remote)


class SDK:
    def __init__(self):
        self.calls = []
        self.responses = {}
        self.result = Result(active=True, data={'name': 'reader', 'id': '42'})
        self.on_fake = None
        self.on_build = None
        self.on_query = None
        self.metadata = {'type_list': ['Test'], 'type_mapping_list_Entry_slot': {'Test': {'TOKEN': 'slot'}},
                         'platform_sdk_model_list': {'qq': {'onebot': ['napcat']}}}
        self.errors = []
        self.validator = None
        self.contentAPI = SimpleNamespace(
            fake_sdk_event=self.fake,
            api_result_data_template=SimpleNamespace(get_login_info=Result, get_user_info_strip=Strip),
        )
        self.API = SimpleNamespace(getBotHash=native_hash, Event=lambda fake, log: QueryEvent(self, fake, log))
        self.accountMetadataAPI = SimpleNamespace(getAccountEditorMetadata=self.get_metadata)
        self.accountAPI = SimpleNamespace(_validate_account_config=self.validate)

    def fake(self, **kwargs):
        self.calls.append(('fake', kwargs))
        if self.on_fake is not None:
            self.on_fake(kwargs['bot_info'])
        return SimpleNamespace(bot_info=kwargs['bot_info'])

    def get_metadata(self):
        self.calls.append(('metadata',))
        return self.metadata

    def validate(self, account):
        self.calls.append(('validate', account))
        return self.validator(account) if self.validator is not None else self.errors


def make(model='napcat'):
    bot, sdk, manager = Bot(model=model), SDK(), Manager()
    ctx = Context(proc=Proc(bot), root='/unused/root', data_root='/unused/data',
                  olivos=sdk, config=manager, permission_mode='full')
    return ctx, bot, sdk, manager


def spec(name):
    return next(tool for tool in read_tools.TOOLS if tool.name == 'cockpit_' + name)


def queries(sdk):
    return [call for call in sdk.calls if call[0] == 'query']


CASES = (
    ('account_login_info', 'get_login_info', {}, ()),
    ('account_connection_status', 'get_status', {}, ()),
    ('protocol_version', 'get_version_info', {}, ()),
    ('user_info', 'get_stranger_info', {'user_id': 'u'}, ('u', False)),
    ('friend_list', 'get_friend_list', {}, ()),
    ('group_list', 'get_group_list', {}, ()),
    ('group_info', 'get_group_info', {'group_id': 'g'}, ('g', None, False)),
    ('group_member_info', 'get_group_member_info', {'group_id': 'g', 'user_id': 'u'}, ('g', 'u', None, False)),
    ('group_member_list', 'get_group_member_list', {'group_id': 'g'}, ('g', None)),
    ('host_list', 'get_host_list', {}, ()),
    ('host_info', 'get_host_info', {'host_id': 'h'}, ('h',)),
    ('message_get', 'get_msg', {'message_id': 'm'}, ('m',)),
    ('message_forward_get', 'get_forward_msg', {'message_id': 'm'}, ('m',)),
    ('group_essence_list', 'get_essence_msg_list', {'group_id': 'g'}, ('g',)),
    ('group_notice_list', 'get_group_notice', {'group_id': 'g'}, ('g',)),
    ('group_system_msg', 'get_group_system_msg', {}, (50,)),
    ('group_ignored_requests', 'get_group_ignore_add_request', {}, (None,)),
    ('friend_doubt_requests', 'get_doubt_friends_add_request', {}, (50,)),
    ('group_file_stats', 'get_group_file_system_info', {'group_id': 'g'}, ('g',)),
    ('group_file_list', 'get_group_root_files', {'group_id': 'g'}, ('g', None)),
    ('group_folder_list', 'get_group_files_by_folder', {'group_id': 'g', 'folder_id': 'f'}, ('g', 'f', None)),
)


class CatalogTests(unittest.TestCase):
    def test_explicit_tools_permissions_and_no_dynamic_dispatch(self):
        self.assertEqual(len(read_tools.READ_TOOLS), 22)
        self.assertEqual(len(read_tools.METADATA_TOOLS), 4)
        names = [tool.name for tool in read_tools.TOOLS]
        self.assertEqual(len(set(names)), 26)
        self.assertEqual(set(names), {'cockpit_' + row[0] for row in CASES} | {
            'cockpit_send_capabilities', 'cockpit_plugin_loaded_list', 'cockpit_account_type_catalog',
            'cockpit_accounts_schema', 'cockpit_accounts_validate'})
        forbidden = {'method', 'module', 'attribute', 'action', 'kwargs', 'params', 'remote', 'flag_log',
                     'url', 'path', 'file', 'payload', 'platform', 'model', 'sdk'}
        for tool in read_tools.TOOLS:
            self.assertTrue(tool.read_only)
            self.assertFalse(tool.schema['additionalProperties'])
            self.assertFalse(set(tool.schema['properties']) & forbidden)
            self.assertEqual(tool.definition()['annotations'], {'readOnlyHint': True})
            self.assertNotIn('required_permission', tool.definition())
        self.assertTrue(all(tool.required_permission == 'real_account_read' for tool in read_tools.READ_TOOLS))
        self.assertTrue(all(tool.required_permission is None for tool in read_tools.METADATA_TOOLS))
        self.assertNotIn('host_id', spec('group_list').schema['properties'])
        self.assertFalse(any('file_url' in name or 'config_get' in name for name in names))

    def test_every_handler_rejects_unknown_dispatch_fields_directly(self):
        ctx, bot, sdk, _ = make()
        for tool in read_tools.TOOLS:
            args = {'bot_hash': bot.hash} if tool.required_permission else {}
            args.update({'account': {}} if tool.name == 'cockpit_accounts_validate' else {})
            for unknown in ('method', 'module', 'attribute', 'action', 'params', 'remote', 'url', 'path'):
                with self.subTest(tool=tool.name, unknown=unknown), self.assertRaises(ToolError):
                    tool.handler(ctx, dict(args, **{unknown: 'unsafe'}))
        self.assertEqual(sdk.calls, [])


class PermissionTests(unittest.TestCase):
    def test_all_handlers_default_deny_without_a_config(self):
        ctx, _, sdk, _ = make()
        for mode in ('full', 'lite'):
            for tool in read_tools.TOOLS:
                with self.subTest(mode=mode, tool=tool.name):
                    out = tool.handler(replace(ctx, config=None, permission_mode=mode), {})
                    self.assertTrue(out.is_error)
                    self.assertIsNone(out.after_send)
        self.assertEqual(sdk.calls, [])

    def test_direct_host_allowed_gate_cannot_be_bypassed(self):
        ctx, _, sdk, _ = make()
        with patch.object(host, 'allowed', return_value=False) as allowed:
            for tool in read_tools.TOOLS:
                self.assertTrue(tool.handler(ctx, {}).is_error)
                self.assertEqual(allowed.call_args.args, (ctx, tool.required_permission))
        self.assertEqual(sdk.calls, [])

    def test_real_reads_denied_including_version_and_capabilities(self):
        ctx, _, sdk, manager = make()
        manager.value.real_read = False
        for mode in ('full', 'lite'):
            for tool in read_tools.READ_TOOLS:
                self.assertTrue(tool.handler(replace(ctx, permission_mode=mode), {}).is_error)
        self.assertEqual(sdk.calls, [])
        self.assertFalse(spec('account_type_catalog').handler(ctx, {}).is_error)

    def test_revocation_during_event_build_does_not_start_a_query(self):
        ctx, bot, sdk, manager = make()
        sdk.on_build = lambda event: setattr(manager.value, 'real_read', False)
        self.assertTrue(spec('account_login_info').handler(ctx, {'bot_hash': bot.hash}).is_error)
        self.assertEqual(queries(sdk), [])

    def test_shared_handlers_work_in_lite_when_real_read_is_explicitly_allowed(self):
        ctx, bot, sdk, _ = make()
        ctx = replace(ctx, permission_mode='lite')
        for name, _, extra, _ in CASES:
            self.assertFalse(spec(name).handler(ctx, {'bot_hash': bot.hash, **extra}).is_error)
        self.assertFalse(spec('send_capabilities').handler(ctx, {'bot_hash': bot.hash}).is_error)
        for tool in read_tools.METADATA_TOOLS:
            args = {'account': {}} if tool.name == 'cockpit_accounts_validate' else {}
            self.assertFalse(tool.handler(ctx, args).is_error)
        self.assertEqual(len(queries(sdk)), 23)

    def test_snapshot_or_allows_failure_is_fail_closed(self):
        ctx, _, sdk, manager = make()

        def boom(*args):
            raise SystemExit('SECRET')

        for current in (None, SimpleNamespace(allows=boom), SimpleNamespace()):
            manager.value = current
            for tool in read_tools.TOOLS:
                self.assertTrue(tool.handler(ctx, {}).is_error)
        manager.snapshot = boom
        self.assertTrue(spec('account_login_info').handler(ctx, {}).is_error)
        self.assertEqual(sdk.calls, [])


class NativeCallTests(unittest.TestCase):
    def test_all_single_method_bindings_and_default_parameter_order(self):
        for name, method, extra, values in CASES:
            with self.subTest(name=name):
                ctx, bot, sdk, _ = make()
                before = copy.deepcopy(vars(bot))
                out = spec(name).handler(ctx, {'bot_hash': bot.hash, **extra})
                self.assertFalse(out.is_error, out.data)
                self.assertEqual(queries(sdk), [('query', method, values, False, False)])
                self.assertEqual(sdk.calls[0], ('fake', {'bot_info': bot, 'fakename': 'OlivOSCockpit'}))
                self.assertIs(sdk.calls[1][2], ctx.proc.log)
                self.assertEqual(vars(bot), before)
                self.assertIsNone(out.after_send)

    def test_optional_values_preserve_native_parameter_order(self):
        cases = (
            ('user_info', {'user_id': 'u', 'no_cache': True}, ('u', True)),
            ('group_info', {'group_id': 'g', 'host_id': 'h', 'no_cache': True}, ('g', 'h', True)),
            ('group_member_info', {'group_id': 'g', 'user_id': 'u', 'host_id': 'h', 'no_cache': True},
             ('g', 'u', 'h', True)),
            ('group_member_list', {'group_id': 'g', 'host_id': 'h'}, ('g', 'h')),
            ('group_system_msg', {'count': 7}, (7,)),
            ('friend_doubt_requests', {'count': 8}, (8,)),
            ('group_ignored_requests', {'group_id': 'g'}, ('g',)),
            ('group_file_list', {'group_id': 'g', 'file_count': 4}, ('g', 4)),
            ('group_folder_list', {'group_id': 'g', 'folder_id': 'f', 'file_count': 5}, ('g', 'f', 5)),
        )
        for name, extra, values in cases:
            with self.subTest(name=name):
                ctx, bot, sdk, _ = make()
                self.assertFalse(spec(name).handler(ctx, {'bot_hash': bot.hash, **extra}).is_error)
                self.assertEqual(queries(sdk)[0][2:], (values, False, False))

    def test_capabilities_execute_both_fixed_queries(self):
        ctx, bot, sdk, _ = make()
        sdk.responses = {'can_send_image': Result(active=True, data={'yes': True}),
                         'can_send_record': Result(active=True, data={'yes': False})}
        out = spec('send_capabilities').handler(ctx, {'bot_hash': bot.hash})
        self.assertFalse(out.is_error)
        self.assertTrue(out.data['image']['data']['yes'])
        self.assertFalse(out.data['record']['data']['yes'])
        self.assertEqual([call[1] for call in queries(sdk)], ['can_send_image', 'can_send_record'])
        sdk.responses['can_send_record'] = None
        self.assertTrue(spec('send_capabilities').handler(ctx, {'bot_hash': bot.hash}).is_error)

    def test_none_unsupported_and_inactive_results_never_succeed(self):
        for model, result in (('unsupported', Result(active=True, data={})), ('napcat', None),
                              ('napcat', Result(active=False, data={})), ('napcat', {'data': []}),
                              ('napcat', {'active': True})):
            with self.subTest(model=model, result=result):
                ctx, bot, sdk, _ = make(model)
                sdk.result = result
                self.assertTrue(spec('account_login_info').handler(ctx, {'bot_hash': bot.hash}).is_error)

    def test_argument_types_bounds_and_required_fields(self):
        ctx, bot, sdk, _ = make()
        for extra in ({'count': 0}, {'count': 501}, {'count': True}, {'count': '1'}):
            with self.assertRaises(ToolError):
                spec('group_system_msg').handler(ctx, {'bot_hash': bot.hash, **extra})
        for name, args in (('user_info', {'user_id': ''}), ('host_info', {'host_id': 'h' * 257}),
                           ('group_info', {'group_id': 'g', 'host_id': None}),
                           ('group_folder_list', {'group_id': 'g'})):
            with self.assertRaises(ToolError):
                validate_arguments(spec(name), {'bot_hash': bot.hash, **args})
        self.assertEqual(sdk.calls, [])


class BindingTests(unittest.TestCase):
    def test_missing_proc_bot_host_and_hash_api(self):
        ctx, bot, sdk, _ = make()
        for bad_ctx, digest in ((replace(ctx, proc=None), bot.hash), (ctx, 'unknown'),
                                (replace(ctx, olivos=None), bot.hash)):
            self.assertTrue(spec('account_login_info').handler(bad_ctx, {'bot_hash': digest}).is_error)
        sdk.API.getBotHash = None
        self.assertTrue(spec('account_login_info').handler(ctx, {'bot_hash': bot.hash}).is_error)
        self.assertEqual(queries(sdk), [])

    def test_hash_id_platform_and_enabled_binding_validation(self):
        mutations = (
            lambda bot: setattr(bot, 'hash', 'wrong'),
            lambda bot: setattr(bot, 'id', 'different-id'),
            lambda bot: setattr(bot, 'platform', object()),
            lambda bot: bot.platform.update(sdk=object()),
            lambda bot: bot.platform.update(model=''),
            lambda bot: setattr(bot, 'enable', False),
        )
        for mutate in mutations:
            ctx, bot, sdk, _ = make()
            digest = bot.hash
            mutate(bot)
            self.assertTrue(spec('account_login_info').handler(ctx, {'bot_hash': digest}).is_error)
            self.assertEqual(queries(sdk), [])

    def test_changed_object_or_platform_before_call_is_rejected(self):
        for mutation in ('object', 'dict', 'hash', 'platform', 'event_bot', 'event_platform', 'inactive'):
            with self.subTest(mutation=mutation):
                ctx, bot, sdk, _ = make()

                def change(event):
                    if mutation == 'object':
                        ctx.proc.Proc_data['bot_info_dict'][bot.hash] = Bot()
                    elif mutation == 'dict':
                        ctx.proc.Proc_data['bot_info_dict'] = {}
                    elif mutation == 'hash':
                        bot.hash = 'changed'
                    elif mutation == 'platform':
                        bot.platform['model'] = 'changed'
                    elif mutation == 'event_bot':
                        event.bot_info = Bot()
                    elif mutation == 'event_platform':
                        event.platform['model'] = 'changed'
                    else:
                        event.active = False

                sdk.on_build = change
                self.assertTrue(spec('account_login_info').handler(ctx, {'bot_hash': bot.hash}).is_error)
                self.assertEqual(queries(sdk), [])

    def test_replaced_account_while_querying_does_not_release_result(self):
        ctx, bot, sdk, _ = make()
        sdk.on_query = lambda event, method: ctx.proc.Proc_data['bot_info_dict'].update({bot.hash: Bot()})
        out = spec('account_login_info').handler(ctx, {'bot_hash': bot.hash})
        self.assertTrue(out.is_error)
        self.assertNotIn('reader', json.dumps(out.data))


class BoundaryTests(unittest.TestCase):
    def run_result(self, result):
        ctx, bot, sdk, _ = make()
        sdk.result = result
        return spec('account_login_info').handler(ctx, {'bot_hash': bot.hash})

    def test_known_native_templates_copy_without_projection_or_mutation(self):
        original = Result(active=True, data=Strip({
            'password': 'KEEP-PASSWORD', 'access_token': 'KEEP-TOKEN', 'path': '/native/private/path',
            'extra': {'cookie': 'KEEP-COOKIE', 'business_secret': 'KEEP-OTHER'},
            'list': [1, 1.5, False, None, {'name': '中文'}],
        }))
        before = copy.deepcopy(original)
        out = self.run_result(original)
        self.assertFalse(out.is_error)
        self.assertEqual(out.data, original)
        self.assertIs(type(out.data), dict)
        self.assertIs(type(out.data['data']), dict)
        out.data['data']['extra']['cookie'] = 'modified copy'
        self.assertEqual(original, before)
        json.dumps(out.data, allow_nan=False)

    def test_known_template_uses_native_dict_storage_not_custom_methods(self):
        class NativeResult(dict):
            def items(self):
                raise AssertionError('custom items must not run')

            def __len__(self):
                raise AssertionError('custom len must not run')

        ctx, bot, sdk, _ = make()
        sdk.contentAPI.api_result_data_template.get_login_info = NativeResult
        sdk.result = NativeResult(active=True, data={})
        self.assertFalse(spec('account_login_info').handler(ctx, {'bot_hash': bot.hash}).is_error)

    def test_host_objects_and_unverified_dict_subclasses_are_rejected_without_conversion(self):
        conversions = []

        class Poison:
            def __str__(self):
                conversions.append('str')
                raise AssertionError

            def __repr__(self):
                conversions.append('repr')
                raise AssertionError

        class Unknown(dict):
            pass

        class UnknownChild(Result):
            pass

        for value in (Poison(), Unknown(secret='x'), UnknownChild(secret='x'), (1, 2), {1: 'x'}, b'secret'):
            self.assertTrue(self.run_result(Result(active=True, data={'value': value})).is_error)
        self.assertEqual(conversions, [])

    def test_nonfinite_huge_integer_and_invalid_unicode_are_rejected(self):
        for value in (float('nan'), float('inf'), -float('inf'), 1 << 256, '\ud800'):
            self.assertTrue(self.run_result(Result(active=True, data={'value': value})).is_error)

    def test_list_limit_is_marked_and_input_remains_intact(self):
        source = Result(active=True, data=list(range(read_tools.MAX_ENTRIES + 1)))
        out = self.run_result(source)
        self.assertFalse(out.is_error)
        self.assertTrue(out.truncated)
        self.assertEqual(out.data['data'], source['data'][:read_tools.MAX_ENTRIES])
        self.assertEqual(len(source['data']), read_tools.MAX_ENTRIES + 1)

    def test_depth_cycles_dict_nodes_and_text_budgets_fail_safely(self):
        deep = []
        for _ in range(read_tools.MAX_DEPTH):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        for value in (deep, cycle, {str(i): i for i in range(read_tools.MAX_ENTRIES + 1)},
                      'x' * (read_tools.MAX_STRING + 1), '中' * (read_tools.MAX_STRING // 3 + 1)):
            self.assertTrue(self.run_result(Result(active=True, data=value)).is_error)
        with patch.object(read_tools, 'MAX_NODES', 10):
            self.assertTrue(self.run_result(Result(active=True, data=list(range(10)))).is_error)
        with patch.object(read_tools, 'MAX_TOTAL_TEXT', 30):
            self.assertTrue(self.run_result(Result(active=True, data=['x' * 20, 'y' * 20])).is_error)


class ExceptionTests(unittest.TestCase):
    def test_native_boundaries_isolate_baseexception_and_propagate_cancellation(self):
        for exception in (SystemExit, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            for phase in ('hash', 'fake', 'event', 'query', 'template'):
                with self.subTest(exception=exception.__name__, phase=phase):
                    ctx, bot, sdk, _ = make()

                    def boom(*args, **kwargs):
                        raise exception('SECRET-EXCEPTION')

                    if phase == 'hash':
                        sdk.API.getBotHash = boom
                    elif phase == 'fake':
                        sdk.contentAPI.fake_sdk_event = boom
                    elif phase == 'event':
                        sdk.API.Event = boom
                    elif phase == 'query':
                        sdk.on_query = boom
                    else:
                        class Templates:
                            def __getattr__(self, name):
                                return boom()
                        sdk.contentAPI.api_result_data_template = Templates()
                    if exception is asyncio.CancelledError:
                        with self.assertRaises(asyncio.CancelledError):
                            spec('account_login_info').handler(ctx, {'bot_hash': bot.hash})
                    else:
                        out = spec('account_login_info').handler(ctx, {'bot_hash': bot.hash})
                        if phase != 'template':
                            self.assertTrue(out.is_error)
                        self.assertNotIn('SECRET', json.dumps(out.data))


class MetadataTests(unittest.TestCase):
    def test_loaded_names_and_details_use_one_host_snapshot_without_other_reads(self):
        ctx, _, sdk, _ = make()
        ctx.proc.names = ['A', 'B']
        ctx.proc.plugin_models_dict = {
            name: {
                'namespace': name, 'name': 'Plugin ' + name, 'version': '1.2', 'svn': 0,
                'info': 'description', 'author': 'author', 'compatible_svn': 0,
                'priority': 0, 'priority_default': 0, 'priority_user': None,
                'priority_effective': 0, 'model': object(), 'private_path': '/not/exposed',
            }
            for name in ctx.proc.names
        }
        calls = []
        original = ctx.proc.get_plugin_list
        ctx.proc.get_plugin_list = lambda: (calls.append('list') or original())
        out = spec('plugin_loaded_list').handler(ctx, {})
        self.assertFalse(out.is_error)
        self.assertEqual(calls, ['list'])
        self.assertEqual(out.data['namespaces'], ['A', 'B'])
        self.assertEqual(out.data['count'], 2)
        self.assertFalse(out.data['truncated'])
        self.assertEqual(out.data['plugins'][0], {
            'namespace': 'A', 'name': 'Plugin A', 'version': '1.2', 'svn': 0,
            'info': 'description', 'author': 'author', 'compatible_svn': 0,
            'priority': 0, 'priority_default': 0, 'priority_user': None,
            'priority_effective': 0, 'available': True, 'unknown_fields': [],
        })
        self.assertTrue(out.data['details_available'])
        self.assertFalse(out.data['details_truncated'])
        self.assertFalse(out.truncated)
        self.assertEqual(sdk.calls, [])
        ctx.proc.get_plugin_list = lambda: None
        self.assertTrue(spec('plugin_loaded_list').handler(ctx, {}).is_error)

    def test_loaded_list_retains_names_when_details_are_missing_or_malformed(self):
        ctx, _, _, _ = make()
        ctx.proc.plugin_models_dict = {'OtherPlugin': object()}
        out = spec('plugin_loaded_list').handler(ctx, {})
        self.assertFalse(out.is_error)
        self.assertEqual(out.data['namespaces'], ['OlivOSCockpit', 'OtherPlugin'])
        self.assertFalse(out.data['details_available'])
        self.assertTrue(all(not row['available'] for row in out.data['plugins']))
        self.assertTrue(all(row['unknown_fields'] for row in out.data['plugins']))

    def test_plugin_detail_types_limits_model_traps_and_cancellation(self):
        ctx, _, _, _ = make()
        calls = []

        class Poison:
            def __str__(self):
                calls.append('str')
                raise AssertionError

            def __repr__(self):
                calls.append('repr')
                raise AssertionError

        ctx.proc.names = ['A']
        ctx.proc.plugin_models_dict = {'A': {
            'namespace': 'A', 'name': Poison(), 'version': 'v', 'svn': True,
            'info': 'x' * (host.MAX_TEXT + 1), 'compatible_svn': 1 << 257,
            'priority': float('nan'), 'priority_default': 0.0, 'priority_user': None,
            'priority_effective': False, 'model': Poison(), 'nested': {'secret': 'hidden'},
        }}
        out = spec('plugin_loaded_list').handler(ctx, {})
        row = out.data['plugins'][0]
        self.assertEqual(row['namespace'], 'A')
        self.assertEqual(row['priority_default'], 0.0)
        self.assertIsNone(row['priority_user'])
        self.assertEqual(row['unknown_fields'], [
            'name', 'svn', 'info', 'author', 'compatible_svn', 'priority', 'priority_effective'])
        self.assertFalse(row['available'])
        self.assertFalse(out.data['details_available'])
        self.assertEqual(calls, [])

        ctx.proc.get_plugin_list = lambda: (_ for _ in ()).throw(asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            spec('plugin_loaded_list').handler(ctx, {})

    def test_plugin_detail_cumulative_budget_does_not_change_legacy_truncation(self):
        ctx, _, _, _ = make()
        ctx.proc.names = ['A', 'B', 'C']
        ctx.proc.plugin_models_dict = {
            name: {
                'namespace': name, 'name': name, 'version': '1', 'svn': 1,
                'info': 'x' * 200, 'author': 'a', 'compatible_svn': 1,
                'priority': 1, 'priority_default': 1, 'priority_user': None,
                'priority_effective': 1,
            }
            for name in ctx.proc.names
        }
        with patch.object(host, 'MAX_PLUGIN_DETAIL_BYTES', 256):
            out = spec('plugin_loaded_list').handler(ctx, {})
        self.assertEqual(out.data['namespaces'], ['A', 'B', 'C'])
        self.assertFalse(out.data['truncated'])
        self.assertFalse(out.truncated)
        self.assertTrue(out.data['details_truncated'])
        self.assertFalse(out.data['details_available'])
        self.assertLessEqual(len(json.dumps(out.data['plugins'], ensure_ascii=True,
                                            separators=(',', ':'))), 256)

    def test_catalog_and_schema_use_only_fixed_native_metadata(self):
        ctx, _, sdk, _ = make()
        before = copy.deepcopy(sdk.metadata)
        ctx.proc.Proc_data = {}  # 元数据不能依赖真实账号或读取 Cockpit 配置内容。
        for name in ('account_type_catalog', 'accounts_schema'):
            out = spec(name).handler(ctx, {})
            self.assertFalse(out.is_error)
            self.assertEqual(out.data, before)
            out.data['type_list'].append('changed')
            self.assertEqual(sdk.metadata, before)
        self.assertEqual(sdk.calls, [('metadata',), ('metadata',)])
        sdk.metadata = None
        self.assertTrue(spec('accounts_schema').handler(ctx, {}).is_error)
        sdk.metadata = {'bad': object()}
        self.assertTrue(spec('account_type_catalog').handler(ctx, {}).is_error)

    def test_pure_validation_copies_input_and_returns_native_error_rows(self):
        ctx, _, sdk, _ = make()
        source = {'id': '1', 'password': 'KEEP-PASSWORD', 'server': {'access_token': 'KEEP-TOKEN'},
                  'extends': {'app_secret': 'KEEP-SECRET'}}
        before = copy.deepcopy(source)
        sdk.errors = [('server.port', 'required field is missing')]
        out = spec('accounts_validate').handler(ctx, {'account': source})
        self.assertFalse(out.is_error)
        self.assertEqual(out.data, {'valid': False, 'errors': [
            {'field': 'server.port', 'reason': 'required field is missing'}], 'truncated': False})
        self.assertEqual(sdk.calls, [('validate', source)])
        self.assertIsNot(sdk.calls[0][1], source)
        self.assertIsNot(sdk.calls[0][1]['server'], source['server'])
        self.assertNotIn('KEEP-', json.dumps(out.data))

        def mutate(account):
            account['server']['access_token'] = 'mutated copy'
            return []

        sdk.validator = mutate
        self.assertTrue(spec('accounts_validate').handler(ctx, {'account': source}).data['valid'])
        self.assertEqual(source, before)

    def test_validation_rejects_unbounded_or_non_native_input_before_native_call(self):
        ctx, _, sdk, _ = make()
        for value in (object(), float('nan'), {1: 'bad'}, ['x'] * (read_tools.MAX_ENTRIES + 1),
                      'x' * (read_tools.MAX_STRING + 1)):
            out = spec('accounts_validate').handler(ctx, {'account': {'extends': {'value': value}}})
            self.assertTrue(out.is_error)
        self.assertEqual(sdk.calls, [])
        with self.assertRaises(ToolError):
            spec('accounts_validate').handler(ctx, {'account': []})

    def test_invalid_or_missing_validator_output_is_not_claimed_valid(self):
        ctx, _, sdk, _ = make()
        for errors in (None, (), [object()], [['field', 'reason']], [(1, 'reason')]):
            sdk.errors = errors
            self.assertTrue(spec('accounts_validate').handler(ctx, {'account': {}}).is_error)
        sdk.errors = [('field', 'reason')] * (read_tools.MAX_ENTRIES + 1)
        out = spec('accounts_validate').handler(ctx, {'account': {}})
        self.assertFalse(out.data['valid'])
        self.assertTrue(out.truncated)
        self.assertEqual(len(out.data['errors']), read_tools.MAX_ENTRIES)

    def test_metadata_baseexception_and_cancellation_boundaries(self):
        for name, owner, method in (
                ('account_type_catalog', 'accountMetadataAPI', 'getAccountEditorMetadata'),
                ('accounts_validate', 'accountAPI', '_validate_account_config')):
            for exception in (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
                ctx, _, sdk, _ = make()

                def boom(*args):
                    raise exception('SECRET-METADATA')

                setattr(getattr(sdk, owner), method, boom)
                args = {'account': {}} if name == 'accounts_validate' else {}
                if exception is asyncio.CancelledError:
                    with self.assertRaises(asyncio.CancelledError):
                        spec(name).handler(ctx, args)
                else:
                    out = spec(name).handler(ctx, args)
                    self.assertTrue(out.is_error)
                    self.assertNotIn('SECRET', json.dumps(out.data))


if __name__ == '__main__':
    unittest.main()
