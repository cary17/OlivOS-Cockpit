"""两个实例接缝的回归；可选读取固定 Release AST 核对桩签名，不执行上游代码。"""

import ast
import asyncio
import hashlib
import inspect
import json
import os
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from OlivOSCockpit import intercept, raw  # noqa: E402
from OlivOSCockpit.config import ConfigManager, Snapshot  # noqa: E402
from OlivOSCockpit.contracts import Context  # noqa: E402

KEY = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8


def native_hash(bot_id=None, platform_sdk=None, platform_platform=None, platform_model=None):
    """宿主 getBotHash 桩：与宿主 md5 算法不同，必须保持 32 位十六进制。"""
    seed = 'native:' + str(bot_id) + str(platform_sdk) + str(platform_platform)
    return hashlib.md5(seed.encode('utf-8')).hexdigest()


class Packet:
    def __init__(self, action, key=None):
        self.action = action
        self.key = key


class OneBotEvent:
    def __init__(self, raw, extras=None):
        self.raw = raw
        self.json = json.loads(raw)
        self.platform = {'sdk': 'onebot', 'platform': 'qq', 'model': 'default'}
        self.active = True
        self.base_info = {key: self.json[key] for key in ('time', 'self_id', 'post_type')}
        if extras is not None:
            for source, target in (('id', 'self_id'), ('type', 'server_type'), ('token', 'access_token')):
                if source in extras:
                    self.base_info[target] = extras[source]


class TerminalEvent:
    def __init__(self, payload_obj=None, bot_info=None, model='default', event_id=None):
        self.payload = payload_obj
        self.event_id = event_id
        self.platform = {'sdk': 'terminal_link', 'platform': 'terminal', 'model': model}
        self.active = payload_obj is not None
        self.base_info = {'time': 1, 'self_id': bot_info.id, 'token': bot_info.post_info.access_token, 'post_type': None}


class Text:
    class data_T(dict):
        pass

    def __init__(self, text=''):
        self.data = self.data_T(text=text)


class Message:
    def __init__(self, mode_rx, data_raw):
        self.mode_rx = mode_rx
        self.data_raw = data_raw
        self.data = data_raw if mode_rx == 'olivos_para' else [Text(data_raw)]
        self.active = True

    def get(self, get_type):
        if get_type == 'olivos_para':
            return self
        return ''.join(item.data['text'] for item in self.data)


class CoreEvent:
    class private_message:
        def __init__(self, user_id, message, sub_type, flag_lazy=True):
            self.user_id = user_id
            self.sub_type = sub_type
            self.message = message
            self.message_sdk = message
            self.raw_message = None
            self.raw_message_sdk = None
            self.sender = {'user_id': user_id}
            self.extend = {}

    class group_message(private_message):
        def __init__(self, group_id, user_id, message, sub_type, flag_lazy=True):
            super().__init__(user_id, message, sub_type, flag_lazy)
            self.group_id = group_id

    def __init__(self, sdk_event=None, log_func=None, Proc=None):
        self.sdk_event = sdk_event
        self.sdk_event_type = type(sdk_event)
        self.active = True
        self.blocked = False
        self.bot_info = None
        self.platform = dict(sdk_event.platform)
        self.base_info = dict(sdk_event.base_info)
        self.plugin_info = {'func_type': None, 'message_mode_tx': 'olivos_string'}
        if isinstance(sdk_event, OneBotEvent):
            value = sdk_event.json
            message = Message('old_string', value['message'])
            group = value.get('message_type') == 'group'
            user_id, group_id = value['user_id'], value.get('group_id')
        else:
            value = sdk_event.payload.key['data']
            conf = value.get('user_conf') or {}
            message = Message('olivos_string', value['data'])
            group = conf.get('flag_group', True)
            user_id, group_id = conf.get('user_id', '-1'), conf.get('target_id', '-1')
        self.plugin_info['func_type'] = 'group_message' if group else 'private_message'
        self.data = (self.group_message(group_id, user_id, message, 'normal') if group
                     else self.private_message(user_id, message, 'friend'))
        self.data.raw_message_sdk = Message(message.mode_rx, message.data_raw)
        self.get_Event_on_Plugin()

    def get_Event_on_Plugin(self):
        mode = self.plugin_info['message_mode_tx']
        self.data.message = self.data.message_sdk.get(mode)
        self.data.raw_message = self.data.raw_message_sdk.get(mode)


class Proc:
    def __init__(self, bot):
        self.Proc_data = {'bot_info_dict': {bot.hash: bot}}
        self.sdk_calls = []
        self.router_calls = []
        self.deliveries = []
        self.sdk_error = None
        self.router_error = None
        self.after_plugin = None
        self.modes = ('old_string', 'olivos_string', 'olivos_para')

    def run_plugin(self, sdk_event):
        self.sdk_calls.append(sdk_event)
        if self.sdk_error is not None:
            raise self.sdk_error
        event = CoreEvent(sdk_event)
        bot_hash = native_hash(event.base_info['self_id'], event.platform['sdk'], event.platform['platform'])
        event.bot_info = self.Proc_data['bot_info_dict'].get(bot_hash)
        for name, mode in enumerate(self.modes):
            event.plugin_info['message_mode_tx'] = mode
            event.get_Event_on_Plugin()
            self.plugin_event_router(event, None, str(name))
            if self.after_plugin is not None:
                self.after_plugin(event)
            if event.blocked:
                break
        return 'sdk-result'

    def plugin_event_router(self, plugin_event, plugin_model, plugin_name):
        self.router_calls.append((plugin_event, plugin_model, plugin_name))
        if self.router_error is not None:
            raise self.router_error
        data = plugin_event.data
        text = data.message.get('olivos_string') if type(data.message) is Message else data.message
        raw_text = data.raw_message.get('olivos_string') if type(data.raw_message) is Message else data.raw_message
        self.deliveries.append((text, raw_text, data.user_id, data.sender.copy(), plugin_event.bot_info))
        return 'router-result'


def context(adapter='onebot_v11', model='default', mode='full', digest=native_hash, **policy):
    sdk, platform = ('onebot', 'qq') if adapter == 'onebot_v11' else ('terminal_link', 'terminal')
    bot_id = '10001' if adapter == 'onebot_v11' else '20261104'
    bot = SimpleNamespace(id=bot_id, platform={'sdk': sdk, 'platform': platform, 'model': model},
                          hash=digest(bot_id=bot_id, platform_sdk=sdk,
                                      platform_platform=platform, platform_model=model),
                          enable=True,
                          post_info=SimpleNamespace(access_token='adapter-secret'))
    manager = ConfigManager('/unused')
    manager._snapshot = Snapshot(valid=True, api_key=KEY, generation=1,
                                 full_real_account_write=True, full_low_level_access=True)
    manager._snapshot = replace(manager._snapshot, **policy)
    olivos = SimpleNamespace(API=SimpleNamespace(Event=CoreEvent, Control=SimpleNamespace(packet=Packet),
                                                getBotHash=digest),
                             onebotSDK=SimpleNamespace(event=OneBotEvent),
                             virtualTerminalSDK=SimpleNamespace(event=TerminalEvent),
                             messageAPI=SimpleNamespace(Message_templet=Message, PARA=SimpleNamespace(text=Text)))
    return Context(Proc(bot), '/unused', '/unused/data', olivos=olivos, config=manager, permission_mode=mode), bot


def sdk_event(ctx, bot, group=False, text='original'):
    if bot.platform['sdk'] == 'onebot':
        payload = {'time': 1, 'self_id': bot.id, 'post_type': 'message',
                   'message_type': 'group' if group else 'private', 'sub_type': 'normal' if group else 'friend',
                   'message': text, 'raw_message': text, 'message_id': '88', 'font': 0,
                   'user_id': '42', 'sender': {'user_id': '42', 'nickname': 'sender'},
                   'group_id': '43', 'extra': {'unchanged': [True, None, 3]}}
        return OneBotEvent(json.dumps(payload), {'id': bot.id, 'type': 'websocket', 'token': 'adapter-secret'})
    return TerminalEvent(Packet('send', {
        'target': {'type': 'terminal_link', 'hash': bot.hash},
        'data': {'action': 'input', 'data': text, 'user_conf': {
            'flag_group': group, 'user_id': '42', 'target_id': '43', 'user_name': 'sender', 'group_role': 'member'}},
    }), bot)


def rule(bot, stage='sdk_in', action='replace_text', group=False, id='r1', message='replacement'):
    value = {'id': id, 'bot_hash': bot.hash, 'stage': stage,
             'event_type': 'group_message' if group else 'private_message', 'action': action}
    if action == 'replace_text':
        value['message'] = message
    return value


def call(ctx, operation='list', **args):
    return intercept.TOOLS[0].handler(ctx, {'operation': operation, **args})


def set_rule(ctx, *rules):
    result = call(ctx, 'set', rules=list(rules))
    if result.is_error:
        raise AssertionError(result.data)
    return result


class InterceptionTests(unittest.TestCase):
    def test_permission_matrix_is_fail_closed_and_does_not_change_host_data(self):
        for write, low in ((False, False), (True, False), (False, True)):
            for adapter in ('onebot_v11', 'virtual_terminal'):
                with self.subTest(write=write, low=low, adapter=adapter):
                    ctx, bot = context(adapter, full_real_account_write=write, full_low_level_access=low)
                    intercept.install(ctx)
                    event = sdk_event(ctx, bot)
                    before = vars(event).copy()
                    self.assertTrue(call(ctx, 'set', rules=[rule(bot)]).is_error)
                    self.assertEqual(ctx.proc.run_plugin(event), 'sdk-result')
                    self.assertEqual(ctx.proc.sdk_calls, [event])
                    self.assertEqual(vars(event), before)
                    self.assertEqual([row[0] for row in ctx.proc.deliveries], ['original'] * 3)
        for policy in ({'valid': False}, {'api_key': ''}):
            ctx, bot = context(**policy)
            intercept.install(ctx)
            self.assertTrue(call(ctx, 'set', rules=[rule(bot)]).is_error)
        ctx, bot = context(mode='lite')
        before = dict(vars(ctx.proc))
        self.assertIsNone(intercept.install(ctx))
        self.assertTrue(call(ctx, 'set', rules=[rule(bot)]).is_error)
        self.assertEqual(vars(ctx.proc), before)

    def test_sdk_replace_rebuilds_known_classes_and_keeps_identity_credentials_and_route(self):
        for adapter in ('onebot_v11', 'virtual_terminal'):
            for group in (False, True):
                with self.subTest(adapter=adapter, group=group):
                    ctx, bot = context(adapter)
                    intercept.install(ctx)
                    set_rule(ctx, rule(bot, group=group, message='/plain/path is text'))
                    event = sdk_event(ctx, bot, group)
                    original_fields = vars(event).copy()
                    self.assertEqual(ctx.proc.run_plugin(event), 'sdk-result')
                    self.assertEqual(len(ctx.proc.sdk_calls), 1)
                    received = ctx.proc.sdk_calls[0]
                    self.assertIsNot(received, event)
                    self.assertIs(type(received), type(event))
                    self.assertEqual(received.base_info, event.base_info)
                    self.assertEqual(received.platform, event.platform)
                    self.assertEqual(vars(event), original_fields)
                    if adapter == 'onebot_v11':
                        self.assertEqual(json.loads(received.raw), received.json)
                        self.assertEqual(received.json['message'], '/plain/path is text')
                        self.assertEqual(received.json['raw_message'], '/plain/path is text')
                        expected = dict(event.json, message='/plain/path is text', raw_message='/plain/path is text')
                        self.assertEqual(received.json, expected)
                        self.assertEqual(event.json['message'], 'original')
                    else:
                        self.assertIsNot(received.payload, event.payload)
                        self.assertEqual(received.payload.key['target'], event.payload.key['target'])
                        self.assertEqual(received.payload.key['data']['user_conf'], event.payload.key['data']['user_conf'])
                        self.assertEqual(event.payload.key['data']['data'], 'original')
                    self.assertEqual([row[0] for row in ctx.proc.deliveries], ['/plain/path is text'] * 3)
                    self.assertEqual(call(ctx).data['counts']['sdk_in_replace_text'], 1)

    def test_sdk_drop_skips_original_once_and_raw_observer_records_original_first(self):
        for adapter in ('onebot_v11', 'virtual_terminal'):
            ctx, bot = context(adapter)
            intercept.install(ctx)
            observer = raw.install(ctx)
            set_rule(ctx, rule(bot, action='drop'))
            event = sdk_event(ctx, bot)
            self.assertIsNone(ctx.proc.run_plugin(event))
            self.assertEqual(ctx.proc.sdk_calls, [])
            self.assertEqual(ctx.proc.router_calls, [])
            self.assertEqual(observer.read()['count'], 1)
            self.assertEqual(call(ctx).data['counts']['sdk_in_drop'], 1)
            self.assertTrue(raw.uninstall(ctx))
            self.assertTrue(intercept.uninstall(ctx))

    def test_raw_before_sdk_replacement_keeps_original_payload(self):
        ctx, bot = context()
        intercept.install(ctx)
        observer = raw.install(ctx)
        set_rule(ctx, rule(bot))
        ctx.proc.run_plugin(sdk_event(ctx, bot))
        self.assertEqual(observer.read()['records'][0]['payload']['message'], 'original')
        self.assertEqual(ctx.proc.sdk_calls[0].json['message'], 'replacement')

    def test_processed_replace_survives_reconversion_for_every_plugin_message_mode(self):
        for adapter in ('onebot_v11', 'virtual_terminal'):
            for group in (False, True):
                with self.subTest(adapter=adapter, group=group):
                    ctx, bot = context(adapter)
                    intercept.install(ctx)
                    set_rule(ctx, rule(bot, stage='processed_in', group=group))
                    event = sdk_event(ctx, bot, group)
                    self.assertEqual(ctx.proc.run_plugin(event), 'sdk-result')
                    self.assertEqual(ctx.proc.sdk_calls, [event])
                    self.assertEqual(len(ctx.proc.router_calls), 3)
                    self.assertEqual([row[:2] for row in ctx.proc.deliveries], [('replacement', 'replacement')] * 3)
                    core = ctx.proc.router_calls[-1][0]
                    self.assertIs(type(core.data.message), Message)
                    self.assertIs(type(core.data.message_sdk), Message)
                    self.assertIs(type(core.data.message_sdk.data[0]), Text)
                    self.assertEqual(core.data.sender, {'user_id': '42'})
                    self.assertIs(core.bot_info, bot)
                    for mode in ('old_string', 'olivos_string'):
                        core.plugin_info['message_mode_tx'] = mode
                        core.get_Event_on_Plugin()
                        self.assertEqual(core.data.message, 'replacement')
                        self.assertEqual(core.data.raw_message, 'replacement')
                    self.assertEqual(call(ctx).data['counts']['processed_in_replace_text'], 3)

    def test_processed_drop_blocks_current_and_subsequent_plugin_without_sdk_drop(self):
        for adapter in ('onebot_v11', 'virtual_terminal'):
            ctx, bot = context(adapter)
            intercept.install(ctx)
            set_rule(ctx, rule(bot, stage='processed_in', action='drop'))
            seen = []
            ctx.proc.after_plugin = lambda event: seen.append(event.blocked)
            self.assertEqual(ctx.proc.run_plugin(sdk_event(ctx, bot)), 'sdk-result')
            self.assertEqual(len(ctx.proc.sdk_calls), 1)
            self.assertEqual(ctx.proc.router_calls, [])
            self.assertEqual(seen, [True])
            self.assertEqual(call(ctx).data['counts']['processed_in_drop'], 1)

    def test_both_stages_execute_in_order(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot, id='sdk', message='sdk rewrite'),
                 rule(bot, id='processed', stage='processed_in', message='processed rewrite'))
        ctx.proc.run_plugin(sdk_event(ctx, bot))
        self.assertEqual(ctx.proc.sdk_calls[0].json['message'], 'sdk rewrite')
        self.assertEqual([row[0] for row in ctx.proc.deliveries], ['processed rewrite'] * 3)

    def test_v11_account_model_is_verified_separately_from_sdk_default_model(self):
        for model in ('napcat_default', 'llonebot_default', 'lagrange_default'):
            ctx, bot = context(model=model)
            intercept.install(ctx)
            set_rule(ctx, rule(bot))
            ctx.proc.run_plugin(sdk_event(ctx, bot))
            self.assertEqual(ctx.proc.sdk_calls[0].json['message'], 'replacement')
            self.assertEqual(ctx.proc.sdk_calls[0].platform['model'], 'default')
            self.assertEqual(bot.platform['model'], model)

    def test_unknown_and_conflicting_configured_bots_are_rejected(self):
        ctx, bot = context()
        intercept.install(ctx)
        unknown = dict(rule(bot), bot_hash='0' * 32)
        self.assertTrue(call(ctx, 'set', rules=[unknown]).is_error)
        bot.hash = 'bad'
        self.assertTrue(call(ctx, 'set', rules=[rule(bot)]).is_error)
        self.assertIn('coverage', call(ctx, 'set', rules=[unknown]).data)

    def test_account_replacement_identity_change_disable_or_platform_conflict_cannot_apply(self):
        for change in ('replace', 'id', 'platform', 'hash', 'disable'):
            with self.subTest(change=change):
                ctx, bot = context()
                intercept.install(ctx)
                set_rule(ctx, rule(bot, action='drop'))
                event = sdk_event(ctx, bot)
                if change == 'replace':
                    ctx.proc.Proc_data['bot_info_dict'][bot.hash] = SimpleNamespace(**vars(bot))
                elif change == 'id':
                    bot.id = '999'
                elif change == 'platform':
                    bot.platform['model'] = 'red'
                elif change == 'hash':
                    bot.hash = 'conflict'
                else:
                    bot.enable = False
                self.assertEqual(ctx.proc.run_plugin(event), 'sdk-result')
                self.assertEqual(ctx.proc.sdk_calls, [event])
                self.assertEqual(call(ctx).data['counts']['sdk_in_drop'], 0)

    def test_payload_identity_and_terminal_route_conflicts_pass_through(self):
        for adapter in ('onebot_v11', 'virtual_terminal'):
            ctx, bot = context(adapter)
            intercept.install(ctx)
            set_rule(ctx, rule(bot, action='drop'))
            event = sdk_event(ctx, bot)
            if adapter == 'onebot_v11':
                event.json['self_id'] = '999'
            else:
                event.payload.key['target']['hash'] = '0' * 32
            ctx.proc.run_plugin(event)
            self.assertEqual(ctx.proc.sdk_calls, [event])
            self.assertEqual(call(ctx).data['counts']['sdk_in_drop'], 0)

    def test_processed_bot_object_and_function_conflicts_pass_through(self):
        for change in ('bot', 'event_type', 'self_id'):
            ctx, bot = context()
            intercept.install(ctx)
            set_rule(ctx, rule(bot, stage='processed_in', action='drop'))
            event = CoreEvent(sdk_event(ctx, bot))
            event.bot_info = bot
            if change == 'bot':
                event.bot_info = SimpleNamespace(**vars(bot))
            elif change == 'event_type':
                event.plugin_info['func_type'] = 'group_message'
            else:
                event.base_info['self_id'] = '999'
            self.assertEqual(ctx.proc.plugin_event_router(event, None, 'target'), 'router-result')
            self.assertFalse(event.blocked)
            self.assertEqual(len(ctx.proc.router_calls), 1)

    def test_unsupported_platforms_and_terminal_models_report_is_error(self):
        for adapter, model in (('onebot_v11', 'onebotV12'), ('onebot_v11', 'red'),
                               ('onebot_v11', 'milky_default'), ('virtual_terminal', 'postapi'),
                               ('virtual_terminal', 'ff14')):
            ctx, bot = context(adapter, model=model)
            intercept.install(ctx)
            result = call(ctx, 'set', rules=[rule(bot)])
            self.assertTrue(result.is_error)
            self.assertIn('Unsupported account adapter/model', result.data['error'])
            self.assertIn('coverage', result.data)

    def test_rule_schema_rejects_arbitrary_field_or_path_updates_and_segment_syntax(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot))
        for key in ('platform', 'self_id', 'token', 'access_token', 'route', 'path', 'script', 'expression', 'jsonpath'):
            with self.subTest(key=key):
                result = call(ctx, 'set', rules=[dict(rule(bot), **{key: 'untrusted'})])
                self.assertTrue(result.is_error)
                self.assertEqual(call(ctx).data['count'], 1)
        for text in ('[CQ:image,file=/etc/passwd]', '[OP:file,path=../secret]'):
            self.assertTrue(call(ctx, 'set', rules=[rule(bot, message=text)]).is_error)
        self.assertTrue(call(ctx, 'set', rules=[dict(rule(bot, action='drop'), message='x')]).is_error)
        self.assertTrue(call(ctx, 'set', rules=[dict(rule(bot), event_type='*')]).is_error)
        self.assertTrue(call(ctx, 'set', rules=[dict(rule(bot), action='script')]).is_error)
        self.assertTrue(call(ctx, 'list', rules=[]).is_error)
        self.assertTrue(call(ctx, 'set').is_error)
        self.assertTrue(intercept.TOOLS[0].handler(ctx, {'operation': 'clear', 'path': '/tmp/rules'}).is_error)

    def test_rule_and_payload_bounds_do_not_partially_replace_rules(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot))
        for message in ('界' * 21846, 'x' * (intercept.MAX_MESSAGE_BYTES + 1), '\ud800'):
            self.assertTrue(call(ctx, 'set', rules=[rule(bot, message=message)]).is_error)
            self.assertEqual(call(ctx).data['rules'], [rule(bot)])
        self.assertTrue(call(ctx, 'set', rules=[rule(bot)] * 17).is_error)
        self.assertTrue(call(ctx, 'set', rules=[rule(bot), rule(bot, id='duplicate-condition')]).is_error)
        values = []
        for index in range(5):
            another = SimpleNamespace(**vars(bot))
            another.id = str(index)
            another.hash = native_hash(another.id, 'onebot', 'qq')
            ctx.proc.Proc_data['bot_info_dict'][another.hash] = another
            values.append(rule(another, id=str(index), message='x' * 65536))
        self.assertTrue(call(ctx, 'set', rules=values).is_error)
        self.assertEqual(call(ctx).data['rules'], [rule(bot)])
        event = sdk_event(ctx, bot)
        event.json['extra'] = 'x' * (intercept.MAX_SDK_BYTES + 1)
        ctx.proc.run_plugin(event)
        self.assertEqual(ctx.proc.sdk_calls, [event])
        self.assertEqual(call(ctx).data['counts']['sdk_in_replace_text'], 0)

    def test_generation_change_or_revocation_clears_without_automatic_reactivation(self):
        for policy in ({'full_real_account_write': False}, {'full_low_level_access': False},
                       {'valid': False}, {'api_key': KEY + 'new'}):
            ctx, bot = context()
            intercept.install(ctx)
            set_rule(ctx, rule(bot, action='drop'))
            ctx.config._snapshot = replace(ctx.config._snapshot, generation=2, **policy)
            event = sdk_event(ctx, bot)
            ctx.proc.run_plugin(event)
            self.assertEqual(ctx.proc.sdk_calls, [event])
            ctx.config._snapshot = Snapshot(valid=True, api_key=KEY, generation=3,
                                            full_real_account_write=True, full_low_level_access=True)
            self.assertEqual(call(ctx).data['rules'], [])
            set_rule(ctx, rule(bot, action='drop'))
            self.assertIsNone(ctx.proc.run_plugin(sdk_event(ctx, bot)))

    def test_latest_permission_is_rechecked_after_sdk_copy_before_commit(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        set_rule(ctx, rule(bot))
        rebuild = controller.rebuild

        def revoke(event, selected):
            result = rebuild(event, selected)
            ctx.config._snapshot = replace(ctx.config._snapshot, generation=2, full_low_level_access=False)
            return result

        event = sdk_event(ctx, bot)
        with patch.object(controller, 'rebuild', revoke):
            ctx.proc.run_plugin(event)
        self.assertEqual(ctx.proc.sdk_calls, [event])
        self.assertEqual(event.json['message'], 'original')
        self.assertEqual(controller._rules, ())

    def test_revoke_between_plugins_does_not_undo_already_replaced_message(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot, stage='processed_in'))
        ctx.proc.after_plugin = lambda event: setattr(ctx.config, '_snapshot',
            replace(ctx.config._snapshot, generation=2, full_low_level_access=False))
        ctx.proc.run_plugin(sdk_event(ctx, bot))
        self.assertEqual([row[0] for row in ctx.proc.deliveries], ['replacement'] * 3)

    def test_clear_and_list_do_not_expose_host_objects_or_secrets(self):
        ctx, bot = context()
        intercept.install(ctx)
        result = set_rule(ctx, rule(bot))
        encoded = json.dumps(result.data)
        self.assertNotIn('adapter-secret', encoded)
        self.assertNotIn(KEY, encoded)
        result.data['rules'][0]['message'] = 'changed response'
        self.assertEqual(call(ctx).data['rules'][0]['message'], 'replacement')
        self.assertEqual(call(ctx, 'clear').data['count'], 0)
        self.assertEqual(bot.post_info.access_token, 'adapter-secret')

    def test_interception_and_observer_exceptions_never_change_original_call_count(self):
        for stage in ('sdk_in', 'processed_in'):
            ctx, bot = context()
            controller = intercept.install(ctx)
            set_rule(ctx, rule(bot, stage=stage))
            method = 'rebuild' if stage == 'sdk_in' else 'message_patch'
            with patch.object(controller, method, side_effect=SystemExit('must not escape')):
                self.assertEqual(ctx.proc.run_plugin(sdk_event(ctx, bot)), 'sdk-result')
            self.assertEqual(len(ctx.proc.sdk_calls), 1)
            self.assertEqual(len(ctx.proc.router_calls), 3)
            self.assertEqual([row[0] for row in ctx.proc.deliveries], ['original'] * 3)
        observer = raw.install(ctx)
        with patch.object(raw.Observer, '_observe', side_effect=KeyboardInterrupt):
            ctx.proc.run_plugin(sdk_event(ctx, bot))
        self.assertIsNotNone(observer)
        self.assertEqual(len(ctx.proc.sdk_calls), 2)

    def test_original_sdk_and_router_exceptions_propagate_unmodified_once(self):
        for kind in ('sdk', 'router'):
            ctx, bot = context()
            intercept.install(ctx)
            error = KeyboardInterrupt('original host error')
            setattr(ctx.proc, kind + '_error', error)
            with self.assertRaises(KeyboardInterrupt) as caught:
                ctx.proc.run_plugin(sdk_event(ctx, bot))
            self.assertIs(caught.exception, error)
            self.assertEqual(len(ctx.proc.sdk_calls), 1)
            self.assertEqual(len(ctx.proc.router_calls), 0 if kind == 'sdk' else 1)

    def test_only_exact_sdk_classes_are_rebuilt_and_arbitrary_objects_are_not_copied(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot))

        class Unknown(OneBotEvent):
            pass

        event = Unknown(sdk_event(ctx, bot).raw)
        ctx.proc.run_plugin(event)
        self.assertIs(ctx.proc.sdk_calls[-1], event)

        class Forbidden:
            def __str__(self):
                raise AssertionError('must not stringify')

            def __repr__(self):
                raise AssertionError('must not repr')

            def __deepcopy__(self, memo):
                raise AssertionError('must not deepcopy')

        event = sdk_event(ctx, bot)
        event.json['extra'] = Forbidden()
        ctx.proc.run_plugin(event)
        self.assertIs(ctx.proc.sdk_calls[-1], event)
        self.assertEqual(call(ctx).data['counts']['sdk_in_replace_text'], 0)
        self.assertEqual(len(ctx.proc.sdk_calls), 2)

    def test_raw_json_conflict_or_unsupported_processed_mode_passes_through(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot))
        event = sdk_event(ctx, bot)
        event.raw = '{}'
        ctx.proc.run_plugin(event)
        self.assertIs(ctx.proc.sdk_calls[0], event)
        set_rule(ctx, rule(bot, stage='processed_in'))
        ctx.proc.modes = ('unknown-mode',)
        ctx.proc.run_plugin(sdk_event(ctx, bot))
        self.assertEqual(ctx.proc.deliveries[-1][0], 'original')
        self.assertIn('Unsupported processed message mode', call(ctx).data['last_bypass'])

    def test_no_host_wait_io_or_new_threads_and_config_snapshot_lock_is_not_acquired(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        set_rule(ctx, rule(bot))
        with patch('builtins.open', side_effect=AssertionError('I/O forbidden')), \
                patch('threading.Thread', side_effect=AssertionError('threads forbidden')), \
                patch('time.sleep', side_effect=AssertionError('waiting forbidden')):
            ctx.config._lock.acquire()
            try:
                ctx.proc.run_plugin(sdk_event(ctx, bot))
            finally:
                ctx.config._lock.release()
        self.assertEqual(ctx.proc.sdk_calls[-1].json['message'], 'replacement')
        controller._lock.acquire()
        try:
            event = sdk_event(ctx, bot)
            ctx.proc.run_plugin(event)
            self.assertIs(ctx.proc.sdk_calls[-1], event)
            self.assertTrue(call(ctx).is_error)
        finally:
            controller._lock.release()

    def test_uninstall_is_instance_only_idempotent_and_never_overwrites_other_wrappers(self):
        ctx, bot = context()
        other_ctx, _ = context()
        original_run = ctx.proc.run_plugin
        original_router = ctx.proc.plugin_event_router
        controller = intercept.install(ctx)
        self.assertIs(intercept.install(ctx), controller)
        self.assertNotIn('run_plugin', vars(other_ctx.proc))
        set_rule(ctx, rule(bot, action='drop'))
        self.assertTrue(intercept.uninstall(ctx))
        self.assertEqual(ctx.proc.run_plugin, original_run)
        self.assertEqual(ctx.proc.plugin_event_router, original_router)
        self.assertFalse(intercept.uninstall(ctx))
        controller = intercept.install(ctx)
        set_rule(ctx, rule(bot, action='drop'))
        delegated = ctx.proc.run_plugin

        def another(event):
            return delegated(event)

        ctx.proc.run_plugin = another
        self.assertFalse(intercept.uninstall(ctx))
        self.assertIs(ctx.proc.run_plugin, another)
        self.assertEqual(ctx.proc.plugin_event_router, original_router)
        self.assertEqual(ctx.proc.run_plugin(sdk_event(ctx, bot)), 'sdk-result')
        self.assertFalse(controller.active)

    def test_uninstall_beneath_raw_disables_without_overwriting_observer(self):
        ctx, bot = context()
        intercept.install(ctx)
        observer = raw.install(ctx)
        set_rule(ctx, rule(bot, action='drop'))
        self.assertFalse(intercept.uninstall(ctx))
        self.assertIs(ctx.proc.run_plugin, observer.wrapper)
        self.assertEqual(ctx.proc.run_plugin(sdk_event(ctx, bot)), 'sdk-result')
        self.assertEqual(len(ctx.proc.sdk_calls), 1)

    def test_missing_apis_return_structured_errors_instead_of_placeholder_success(self):
        ctx, bot = context()
        self.assertTrue(call(ctx, 'set', rules=[rule(bot)]).is_error)
        ctx.olivos.onebotSDK.event = None
        intercept.install(ctx)
        result = call(ctx, 'set', rules=[rule(bot)])
        self.assertTrue(result.is_error)
        self.assertIn('Host SDK event class unavailable', result.data['error'])
        self.assertEqual(call(ctx).data['count'], 0)

    def test_tool_cancellation_is_not_swallowed(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        with patch.object(controller, 'compile', side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                call(ctx, 'set', rules=[rule(bot)])
        self.assertFalse(controller._lock.locked())

    def test_stale_or_unauthorized_requests_cannot_clear_newer_rules(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        ctx.config._snapshot = replace(ctx.config._snapshot, generation=2)
        set_rule(ctx, rule(bot, action='drop'))
        self.assertEqual(controller._epoch[1], 2)
        stale = replace(ctx, request_generation=1)
        denied = replace(stale, permission_mode='lite')
        for view in (stale, denied):
            result = call(view, 'clear')
            self.assertTrue(result.is_error)
            self.assertEqual(call(ctx).data['rules'], [rule(bot, action='drop')])
            self.assertTrue(controller._lock.locked() is False)
            result = call(view, 'set', rules=[])
            self.assertTrue(result.is_error)
            self.assertEqual(call(ctx).data['rules'], [rule(bot, action='drop')])
        self.assertEqual(controller._epoch[1], 2)

    def test_stale_request_cannot_replace_rules_registered_by_newer_generation(self):
        ctx, bot = context()
        intercept.install(ctx)
        set_rule(ctx, rule(bot))
        newer = replace(ctx.config._snapshot, generation=2)
        ctx.config._snapshot = newer
        set_rule(ctx, rule(bot, id='newer', action='drop'))
        stale = replace(ctx, request_generation=1)
        self.assertTrue(call(stale, 'set', rules=[rule(bot, id='old')]).is_error)
        self.assertEqual([item['id'] for item in call(ctx).data['rules']], ['newer'])
        self.assertEqual(call(ctx).data['generation'], 2)

    def test_revoked_generation_after_set_cannot_commit_rules(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        compile_rules = controller.compile

        def revoke(values):
            rules = compile_rules(values)
            ctx.config._snapshot = replace(ctx.config._snapshot, generation=2)
            return rules

        with patch.object(controller, 'compile', revoke):
            self.assertTrue(call(ctx, 'set', rules=[rule(bot)]).is_error)
        self.assertEqual(controller._rules, ())

    def test_coverage_models_match_the_shared_v11_allow_list(self):
        coverage = call(context()[0]).data['coverage']
        self.assertEqual(coverage['adapters']['onebot_v11']['models'],
                         list(raw.ONEBOT_V11_MODELS))
        self.assertIs(intercept._ONEBOT_MODELS, raw.ONEBOT_V11_MODELS)
        for model in raw.ONEBOT_V11_MODELS:
            self.assertEqual(raw._ADAPTER_BY_PLATFORM[('onebot', 'qq', model)], 'onebot_v11')
        for model in ('onebotV12', 'milky_default', 'opqbot_default', 'red'):
            self.assertNotIn(model, raw.ONEBOT_V11_MODELS)
            self.assertNotEqual(raw._ADAPTER_BY_PLATFORM[('onebot', 'qq', model)], 'onebot_v11')

    def test_host_hash_failure_fails_closed_for_compile_and_matching(self):
        # 缺宿主能力/调用失败：注册与匹配都安全失败，不改变宿主调用，不暴露异常正文。
        def failing(**kwargs):
            raise RuntimeError('hash failed')

        for api in (None, failing):
            with self.subTest(api=api):
                ctx, bot = context(adapter='onebot_v11')
                ctx.olivos.API.getBotHash = api
                controller = intercept.install(ctx)
                result = call(ctx, 'set', rules=[rule(bot)])
                self.assertTrue(result.is_error)
                self.assertNotIn('hash failed', json.dumps(result.data))
                self.assertEqual(controller._rules, ())
                self.assertEqual(ctx.proc.run_plugin(sdk_event(ctx, bot)), 'sdk-result')
                self.assertEqual(len(ctx.proc.sdk_calls), 1)
                self.assertEqual(call(ctx).data['counts']['bypassed'], 0)

    def test_host_hash_differing_from_config_rejects_rule_and_matching(self):
        # 宿主算法与配置 hash 不一致时不能猜测归属，只产生结构化失败。
        ctx, bot = context()
        ctx.olivos.API.getBotHash = lambda *args, **kwargs: native_hash('other', 'onebot', 'qq')
        # 控制器在安装时缓存宿主函数引用，因此必须在安装前替换。
        controller = intercept.install(ctx)
        result = call(ctx, 'set', rules=[rule(bot)])
        self.assertTrue(result.is_error)
        self.assertIn('identity conflict', result.data['error'])
        self.assertEqual(controller._rules, ())
        # 兼容宿主实现差异：只要宿主结果仍能交叉校验当前配置账号即可匹配。
        ctx.olivos.API.getBotHash = native_hash
        controller.native_hash = native_hash
        set_rule(ctx, rule(bot, action='drop'))
        self.assertIsNone(ctx.proc.run_plugin(sdk_event(ctx, bot)))

    def test_matching_uses_cached_host_hash_and_passes_through_on_failure(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        set_rule(ctx, rule(bot, action='drop'))
        # 安装时已缓存函数引用；之后替换宿主属性不影响既有规则。
        ctx.olivos.API.getBotHash = lambda *args, **kwargs: native_hash('other', 'onebot', 'qq')
        self.assertIsNone(ctx.proc.run_plugin(sdk_event(ctx, bot)))
        self.assertEqual(call(ctx).data['counts']['sdk_in_drop'], 1)

        # 同一缓存引用在匹配阶段失败：旁路且不改变宿主调用。
        def flaky(**kwargs):
            raise RuntimeError('hash failed at match time')

        controller.native_hash = flaky
        event = sdk_event(ctx, bot)
        self.assertEqual(ctx.proc.run_plugin(event), 'sdk-result')
        self.assertIs(ctx.proc.sdk_calls[-1], event)
        self.assertEqual([row[0] for row in ctx.proc.deliveries], ['original'] * 3)
        self.assertEqual(call(ctx).data['counts']['sdk_in_drop'], 1)
        self.assertNotIn('hash failed', json.dumps(call(ctx).data))

    def test_processed_message_patch_keeps_other_fields_and_requires_supported_mode(self):
        ctx, bot = context()
        controller = intercept.install(ctx)
        set_rule(ctx, rule(bot, stage='processed_in'))
        event = CoreEvent(sdk_event(ctx, bot))
        patch = controller.message_patch(event, 'replacement')
        self.assertEqual(set(patch), {'message', 'raw_message', 'message_sdk', 'raw_message_sdk'})
        self.assertEqual(patch['message'], 'replacement')
        self.assertEqual(patch['raw_message'], 'replacement')
        event.plugin_info['message_mode_tx'] = 'milky_para_tx'
        with self.assertRaises(intercept.ToolError):
            controller.message_patch(event, 'replacement')

    def test_rebuild_only_changes_message_fields_for_napcat_configured_accounts(self):
        for model in ('napcat_default', 'llonebot_default', 'lagrange_default'):
            ctx, bot = context(model=model)
            controller = intercept.install(ctx)
            set_rule(ctx, rule(bot))
            event = sdk_event(ctx, bot)
            rebuilt = controller.rebuild(event, controller._rules[0])
            self.assertEqual(set(vars(rebuilt)), set(vars(event)))
            self.assertEqual(rebuilt.base_info, event.base_info)
            self.assertEqual(rebuilt.platform, event.platform)
            self.assertEqual(json.loads(rebuilt.raw), rebuilt.json)
            expected = dict(event.json, message='replacement', raw_message='replacement')
            self.assertEqual(rebuilt.json, expected)
            self.assertEqual(event.json['message'], 'original')
            self.assertIs(type(rebuilt), type(event))

    @unittest.skipUnless(os.environ.get('OLIVOS_COCKPIT_UPSTREAM_SOURCE'), 'optional fixed Release AST signature check')
    def test_stubs_match_fixed_release_signatures(self):
        root = Path(os.environ['OLIVOS_COCKPIT_UPSTREAM_SOURCE'])
        checks = (
            ('OlivOS/core/core/pluginAPI.py', 'shallow', 'run_plugin', Proc.run_plugin),
            ('OlivOS/core/core/pluginAPI.py', 'shallow', 'plugin_event_router', Proc.plugin_event_router),
            ('OlivOS/core/core/API.py', 'Event', '__init__', CoreEvent.__init__),
            ('OlivOS/core/core/API.py', 'Event', 'get_Event_on_Plugin', CoreEvent.get_Event_on_Plugin),
            ('OlivOS/core/core/API.py', 'Control.packet', '__init__', Packet.__init__),
            ('OlivOS/adapter/onebotV11/onebotSDK.py', 'event', '__init__', OneBotEvent.__init__),
            ('OlivOS/adapter/virtualTerminal/virtualTerminalSDK.py', 'event', '__init__', TerminalEvent.__init__),
            ('OlivOS/core/core/messageAPI.py', 'Message_templet', '__init__', Message.__init__),
            ('OlivOS/core/core/messageAPI.py', 'Message_templet', 'get', Message.get),
        )
        for relative, owner, name, stub in checks:
            with self.subTest(owner=owner, name=name):
                node = ast.parse((root / relative).read_text(encoding='utf-8-sig'))
                for part in (*owner.split('.'), name):
                    node = next(child for child in node.body if getattr(child, 'name', None) == part)
                params = list(inspect.signature(stub).parameters.values())
                self.assertEqual([param.name for param in params], [arg.arg for arg in node.args.args])
                self.assertEqual(sum(param.default is not inspect.Parameter.empty for param in params),
                                 len(node.args.defaults))


if __name__ == '__main__':
    unittest.main()
