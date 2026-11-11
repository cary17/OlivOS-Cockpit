"""adapter_tools 的显式白名单、权限、参数与命名测试；不接触真实宿主。"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from OlivOSCockpit import adapter_tools, full_only, registry, terminal  # noqa: E402
from OlivOSCockpit.contracts import Context, ToolError, validate_arguments  # noqa: E402


class Platform:
    def __init__(self, sdk, platform, model):
        self.sdk = sdk
        self.platform = platform
        self.model = model


class Bot:
    def __init__(self, hash_, sdk='onebot', platform='qq', model='milky_default'):
        self.hash = hash_
        self.id = '10001'
        self.platform = Platform(sdk, platform, model)


class Snapshot:
    generation = 0

    def __init__(self, allowed):
        self._allowed = allowed

    def allows(self, permission, mode):
        return permission == self._allowed


class Manager:
    def __init__(self, allowed=None):
        self.value = Snapshot(allowed)
        self.fail = False

    def snapshot(self):
        if self.fail:
            raise RuntimeError('boom')
        return self.value


class ParaText:
    def __init__(self, text):
        self.type = 'text'
        self.data = {'text': text}


class Template:
    def __init__(self, mode, data):
        self.active = True
        self.mode_rx = mode
        self.data = data


class FakeEvent:
    def __init__(self, calls, bot, mode):
        self.calls = calls
        self.active = True
        self.bot_info = bot
        self.platform = bot.platform if isinstance(bot.platform, dict) else vars(bot.platform)
        # 与宿主 get_Event_from_fake_SDK 一致：按平台三元组查接收模式。
        self.plugin_info = {'message_mode_rx': mode}

    def send(self, send_type, target, message, host_id=None):
        self.calls.append((send_type, target, message, host_id))


class API:
    def __init__(self, sdk):
        self.sdk = sdk

    def Event(self, fake, log):
        self.sdk.calls.append(('event', log))
        platform = fake.platform if isinstance(fake.platform, dict) else vars(fake.platform)
        by_sdk = self.sdk.dictMessageType.get(platform['platform'], {})
        mode = by_sdk.get(platform['sdk'], {}).get(platform['model'], 'olivos_para')
        return FakeEvent(self.sdk.calls, fake, mode)


class SDK:
    def __init__(self):
        self.calls = []
        # 摘自固定基线 messageAPI.dictMessageType 的相关子集。
        self.dictMessageType = {
            'qq': {'onebot': {
                'opqbot_default': 'olivos_string', 'opqbot_auto': 'old_string',
                'opqbot_port': 'old_string', 'opqbot_port_old': 'old_string',
                'milky_default': 'milky_para_tx', 'llonebot_milky': 'milky_para_tx',
                'lagrange_milky': 'milky_para_tx', 'yogurt_milky': 'milky_para_tx',
                'red': 'olivos_para'}},
            'biliLive': {'biliLive_link': {'default': 'olivos_string'}},
            'dingtalk': {'dingtalk_link': {'default': 'olivos_para'}},
            'discord': {'discord_link': {'default': 'olivos_para'}},
            'dodo': {'dodo_link': {'default': 'olivos_para', 'v1': 'olivos_para'},
                     'dodo_poll': {'default': 'olivos_para'}},
            'fanbook': {'fanbook_poll': {'default': 'olivos_para'}},
            'hackChat': {'hackChat_link': {'default': 'olivos_string'}},
            'kaiheila': {'kaiheila_link': {'default': 'olivos_para', 'text': 'olivos_para',
                                           'card': 'olivos_para'}},
            'mhyVila': {'mhyVila_link': {'default': 'olivos_string'}},
            'xiaoheihe': {'xiaoheihe_link': {'default': 'old_string'}},
            'telegram': {'telegram_poll': {'default': 'olivos_para'}},
        }
        self.messageAPI = type('M', (), {
            'PARA': type('P', (), {'text': staticmethod(ParaText)}),
            'Message_templet': Template,
        })
        self.contentAPI = type('C', (), {
            'fake_sdk_event': staticmethod(
                lambda **kwargs: self.calls.append(('fake', kwargs.get('fakename')))
                or kwargs['bot_info']),
        })
        self.API = API(self)


class Proc:
    def __init__(self, bots):
        self.Proc_data = {'bot_info_dict': bots}
        self.log = 'LOG'


def make(bots=None, olivos='default', allowed=adapter_tools.PERMISSION):
    sdk = SDK() if olivos == 'default' else None
    proc = Proc(bots if bots is not None else {
        'm': Bot('m'), 't': Bot('t', 'telegram_poll', 'telegram', 'default')})
    manager = Manager(allowed)
    ctx = Context(proc=proc, root='/tmp/root', data_root='/tmp/data',
                  olivos=sdk, config=manager, permission_mode='full')
    return ctx, manager, sdk


def sends(sdk):
    return [call for call in sdk.calls if call[0] in ('private', 'group')]


def spec(name):
    return next(tool for tool in adapter_tools.TOOLS if tool.name == name)


MILKY_ARGS = {'bot_hash': 'm', 'message': 'hello', 'target_id': '42'}


class CatalogTests(unittest.TestCase):
    def test_names_are_cockpit_and_unique(self):
        names = [tool.name for tool in adapter_tools.TOOLS]
        self.assertEqual(len(names), 19)
        self.assertEqual(len(set(names)), 19)
        self.assertTrue(all(name.startswith('cockpit_') for name in names))

    def test_no_generic_or_unsafe_actions(self):
        names = {tool.name for tool in adapter_tools.TOOLS}
        for forbidden in ('cockpit_opqbot_send_solo_all_msg', 'cockpit_dingtalk_do_api',
                          'cockpit_discord_sendMessage', 'cockpit_virtualterminal_send',
                          'cockpit_dodobot_ea_send_group'):
            self.assertNotIn(forbidden, names)

    def test_only_text_message_parameter_exists(self):
        for tool in adapter_tools.TOOLS:
            self.assertNotIn('path', tool.schema['properties'])
            self.assertNotIn('url', tool.schema['properties'])
            self.assertNotIn('media', tool.schema['properties'])
            self.assertIn('message', tool.schema['properties'])
            self.assertFalse(tool.read_only)
            self.assertEqual(tool.required_permission, 'real_account_write')

    def test_registry_full_and_lite(self):
        names = {tool.name for tool in registry.TOOLS}
        self.assertIn('cockpit_milky_send_group', names)
        for name in ('cockpit_send', 'cockpit_reload', 'cockpit_proc_get'):
            self.assertIn(name, names)
        self.assertIn('cockpit_terminal_input', {tool.name for tool in terminal.TOOLS})

    def test_full_only_names_renamed(self):
        names = [tool.name for tool in full_only.TOOLS]
        self.assertEqual(names, [
            'cockpit_send', 'cockpit_reload', 'cockpit_proc_get', 'cockpit_plugin_config_set',
        ])


class GuardTests(unittest.TestCase):
    def test_default_denied_without_config(self):
        ctx, _, sdk = make()
        ctx = Context(proc=ctx.proc, root='/r', data_root='/d', olivos=sdk)
        out = spec('cockpit_milky_send_group').handler(ctx, dict(MILKY_ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Real account write is disabled')
        self.assertEqual(sdk.calls, [])

    def test_denied_permission(self):
        ctx, _, sdk = make(allowed=None)
        self.assertTrue(spec('cockpit_milky_send_group').handler(
            ctx, dict(MILKY_ARGS)).is_error)
        self.assertEqual(sdk.calls, [])

    def test_snapshot_failure_denies(self):
        ctx, manager, _ = make()
        manager.fail = True
        self.assertTrue(spec('cockpit_milky_send_group').handler(
            ctx, dict(MILKY_ARGS)).is_error)

    def test_generation_change_denies(self):
        ctx, _, sdk = make()
        ctx = Context(proc=ctx.proc, root=ctx.root, data_root=ctx.data_root,
                      olivos=ctx.olivos, config=ctx.config,
                      permission_mode='full', request_generation=1)
        self.assertTrue(spec('cockpit_milky_send_group').handler(
            ctx, dict(MILKY_ARGS)).is_error)
        self.assertEqual(sdk.calls, [])

    def test_platform_mismatch_is_rejected(self):
        ctx, _, sdk = make()
        args = dict(MILKY_ARGS, bot_hash='t')  # telegram 账号不能走 milky 工具
        out = spec('cockpit_milky_send_group').handler(ctx, args)
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'],
                         'bot_hash platform does not match this adapter')
        self.assertEqual(sdk.calls, [])

    def test_unknown_bot(self):
        ctx, _, _ = make()
        out = spec('cockpit_milky_send_group').handler(
            ctx, dict(MILKY_ARGS, bot_hash='nope'))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Unknown bot_hash')

    def test_missing_olivos(self):
        ctx, _, _ = make(olivos=None)
        self.assertTrue(spec('cockpit_milky_send_group').handler(
            ctx, dict(MILKY_ARGS)).is_error)

    def test_host_baseexception_is_isolated(self):
        ctx, _, sdk = make()

        def boom(*args, **kwargs):
            raise KeyboardInterrupt('SECRET-TOKEN')

        sdk.contentAPI.fake_sdk_event = staticmethod(boom)
        out = spec('cockpit_milky_send_group').handler(ctx, dict(MILKY_ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Message submission failed safely')
        self.assertNotIn('SECRET', repr(out.data))


class SubmissionTests(unittest.TestCase):
    def test_milky_group_builds_single_text_segment(self):
        ctx, _, sdk = make()
        out = spec('cockpit_milky_send_group').handler(ctx, dict(MILKY_ARGS))
        self.assertFalse(out.is_error, out.data)
        self.assertEqual(out.data['adapter'], 'milky')
        self.assertEqual(out.data['send_type'], 'group')
        self.assertEqual(out.data['delivery'], 'unknown')
        sent = sends(sdk)[0]
        send_type, target, message, host_id = sent
        self.assertEqual((send_type, target, host_id), ('group', '42', None))
        self.assertEqual(message.mode_rx, 'olivos_para')
        self.assertEqual([(para.type, para.data) for para in message.data],
                         [('text', {'text': 'hello'})])

    def test_platform_hint_is_not_interpreted_as_segments(self):
        ctx, _, sdk = make()
        message = '[CQ:image,file=/etc/passwd]'
        out = spec('cockpit_milky_send_group').handler(
            ctx, dict(MILKY_ARGS, message=message))
        self.assertFalse(out.is_error)
        sent = sends(sdk)[0]
        self.assertEqual(sent[2].data[0].data['text'], message)

    def test_syntax_rejected_when_host_reparses_strings(self):
        # 宿主把文本编码成 CQ 串再解析时，同样的输入必须拒绝而非发送。
        ctx, _, sdk = make()
        original = FakeEvent.__init__

        def legacy(event, calls, bot, mode):
            original(event, calls, bot, 'old_string')

        FakeEvent.__init__ = legacy
        try:
            out = spec('cockpit_milky_send_group').handler(
                ctx, dict(MILKY_ARGS, message='[CQ:image,file=/etc/passwd]'))
        finally:
            FakeEvent.__init__ = original
        self.assertTrue(out.is_error)
        self.assertEqual(sends(sdk), [])

    def test_private_and_host_id_paths(self):
        ctx, _, sdk = make()
        self.assertTrue(spec('cockpit_dodo_poll_send_private').handler(
            ctx, dict(MILKY_ARGS, host_id='island')).is_error)  # milky 账号不匹配
        dodo_bot = Bot('d', 'dodo_poll', 'dodo', 'default')
        ctx.proc.Proc_data['bot_info_dict']['d'] = dodo_bot
        out = spec('cockpit_dodo_poll_send_private').handler(
            ctx, dict(MILKY_ARGS, bot_hash='d', host_id='island'))
        self.assertFalse(out.is_error)
        self.assertEqual(out.data['send_type'], 'private')
        self.assertEqual(sends(sdk)[-1][1], '42')
        self.assertEqual(sends(sdk)[-1][3], 'island')

    def test_string_only_adapters_are_withheld_not_published_as_stubs(self):
        withheld = {f'cockpit_{entry[0]}_{entry[1]}' for entry in adapter_tools.WITHHELD_ENTRIES}
        self.assertEqual(len(withheld), 6)
        self.assertFalse(withheld & {tool.name for tool in adapter_tools.TOOLS})
        self.assertFalse(withheld & {tool.name for tool in registry.TOOLS})

    def test_bot_key_must_match_account_identity(self):
        ctx, _, sdk = make()
        ctx.proc.Proc_data['bot_info_dict']['m'] = Bot('other')
        out = spec('cockpit_milky_send_group').handler(ctx, dict(MILKY_ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Unknown bot_hash')
        self.assertEqual(sdk.calls, [])

    def test_argument_validation(self):
        with self.assertRaises(ToolError):
            validate_arguments(spec('cockpit_milky_send_group'),
                               dict(MILKY_ARGS, extra=1))
        with self.assertRaises(ToolError):
            validate_arguments(spec('cockpit_milky_send_group'),
                               {'bot_hash': 'm', 'target_id': '42'})
        with self.assertRaises(ToolError):
            spec('cockpit_milky_send_group').handler(ctx_or_none(), {'bot_hash': 'm'})

    def test_message_utf8_byte_budget(self):
        ctx, _, sdk = make()
        half = '中' * (adapter_tools.MAX_MESSAGE // 3 + 1)
        with self.assertRaises(ToolError):
            spec('cockpit_milky_send_group').handler(
                ctx, dict(MILKY_ARGS, message=half))
        self.assertEqual(sends(sdk), [])


def ctx_or_none():
    return make()[0]


if __name__ == '__main__':
    unittest.main()
