"""虚拟终端账号只读发现与输入注入；只使用模拟宿主，不接触真实加载器。"""

import sys
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from OlivOSCockpit import full_only, host, terminal  # noqa: E402
from OlivOSCockpit.contracts import Context, ToolError, validate_arguments  # noqa: E402


class Platform:
    def __init__(self, sdk='terminal_link', platform='terminal', model='default'):
        self.sdk = sdk
        self.platform = platform
        self.model = model


class Bot:
    def __init__(self, hash_, platform=None, id_=4242):
        self.hash = hash_
        self.id = id_
        self.platform = platform or Platform()
        self.post_info = {'token': 'SECRET-TOKEN'}


class Queue:
    def __init__(self, full=False):
        self.items = []
        self.full = full

    def put(self, item, block=True):
        if self.full:
            raise RuntimeError('full')
        self.items.append(item)


class Proc:
    def __init__(self, bots=None, rx_queue=None):
        self.Proc_data = {'bot_info_dict': bots if bots is not None else {}}
        self.Proc_info = type('Info', (), {'rx_queue': rx_queue})()

    def get_plugin_list(self):
        return ['A']


class Control:
    class packet:
        def __init__(self, action, key=None):
            self.action = action
            self.key = key


class SDKEvent:
    def __init__(self, payload, bot_info, model='default', event_id=None, self_id=None):
        self.payload = payload
        self.bot_info = bot_info
        self.model = model
        self.event_id = event_id
        self.platform = {'sdk': 'terminal_link', 'platform': 'terminal', 'model': model}
        # 真实 SDK 把账号 ID/token 复制进 base_info，不保存 bot 对象。
        self.base_info = {'self_id': str(self_id if self_id is not None else bot_info.id)}


class Host:
    def __init__(self):
        self.Control = Control
        self.virtualTerminalSDK = type('V', (), {'event': SDKEvent})
        self.pluginAPI = type('P', (), {'shallow': type(
            'S', (), {'rx_packet': staticmethod(lambda event: ('rx', event))})})
        self.packets = []

        def make_bot(id=-1, platform_sdk=None, platform_platform=None, platform_model=None):
            # 已核实的宿主 hash 不含 model。
            digest = f'{id}:{platform_sdk}:{platform_platform}'
            return Bot(digest, Platform(platform_sdk, platform_platform, platform_model), id)

        self.API = type('A', (), {'bot_info_T': staticmethod(make_bot),
                                  'Control': Control})


def make(bots=None, olivos=True, queue=None):
    h = Host() if olivos else None
    proc = Proc(bots, queue)
    ctx = Context(proc=proc, root='/tmp/root', data_root='/tmp/data', olivos=h)
    return ctx, proc, h


class PrepareTests(unittest.TestCase):
    def test_reuses_existing_user_provisioned_terminal(self):
        bot = Bot('t', id_=4242)
        ctx, proc, _ = make({'t': bot})
        state = terminal.prepare(ctx)
        self.assertNotIn('error', state)
        self.assertEqual(state['hash'], 't')
        self.assertIs(state['bot'], bot)
        # 零突变：不插入、不删除、不改动宿主字典。
        self.assertEqual(list(proc.Proc_data['bot_info_dict']), ['t'])
        self.assertNotIn('created', state)

    def test_any_configured_account_id_is_discovered(self):
        for value in (1, 20261104, 2 ** 40):
            ctx, _, _ = make({f't{value}': Bot(f't{value}', id_=value)})
            state = terminal.prepare(ctx)
            self.assertNotIn('error', state, value)
            self.assertEqual(state['bot'].id, value)

    def test_multiple_accounts_pick_deterministically(self):
        bots = {'b': Bot('b'), 'a': Bot('a')}
        first, _, _ = make(bots)
        second, _, _ = make(dict(reversed(list(bots.items()))))
        self.assertEqual(terminal.prepare(first)['hash'], 'a')
        self.assertEqual(terminal.prepare(second)['hash'], 'a')

    def test_unqualified_accounts_are_never_selected(self):
        for platform in (Platform(sdk='qq'), Platform(model='ff14'), Platform(model='postapi')):
            ctx, proc, _ = make({'x': Bot('x', platform)})
            state = terminal.prepare(ctx)
            self.assertEqual(state['error'], terminal.NOT_CONFIGURED, platform)
            # 零突变：不合格账号保留原样，也没有新账号被创建。
            self.assertEqual(list(proc.Proc_data['bot_info_dict']), ['x'])
            self.assertNotIn('hash', state)

    def test_disabled_or_mistyped_id_accounts_are_never_selected(self):
        disabled = Bot('d')
        disabled.enable = False
        for bot in (disabled, Bot('b1', id_=True), Bot('b2', id_=1.5), Bot('b3', id_='4242')):
            ctx, proc, _ = make({bot.hash: bot})
            state = terminal.prepare(ctx)
            self.assertEqual(state['error'], terminal.NOT_CONFIGURED)
            self.assertEqual(len(proc.Proc_data['bot_info_dict']), 1)

    def test_key_and_hash_must_agree(self):
        ctx, _, _ = make({'x': Bot('y')})
        self.assertEqual(terminal.prepare(ctx)['error'], terminal.NOT_CONFIGURED)

    def test_scan_limit_is_not_treated_as_absent(self):
        bots = {f'h{i}': Bot(f'h{i}', Platform(model='qq')) for i in range(501)}
        ctx, proc, _ = make(bots)
        state = terminal.prepare(ctx)
        self.assertEqual(state['error'], 'Account list too large to inspect safely')
        self.assertEqual(len(proc.Proc_data['bot_info_dict']), 501)

    def test_missing_account_dict_fails_safely(self):
        ctx, proc, _ = make({})
        proc.Proc_data = {}
        self.assertEqual(terminal.prepare(ctx)['error'],
                         'Configured account list unavailable')

    def test_absent_account_reports_actionable_error_and_waits(self):
        # 用户可能没有预置终端账号：明确停用、字典不动、等下一监督周期。
        ctx, proc, _ = make({})
        state = terminal.prepare(ctx)
        self.assertEqual(state['error'], terminal.NOT_CONFIGURED)
        self.assertEqual(state['checked'], True)
        self.assertNotIn('hash', state)
        self.assertEqual(proc.Proc_data['bot_info_dict'], {})
        status = host.TOOLS[0].handler(ctx, {}).data
        self.assertFalse(status['debug_terminal']['selected'])
        self.assertEqual(status['debug_terminal']['error'], terminal.NOT_CONFIGURED)
        # 输入入口安全失败。
        out = terminal.TOOLS[0].handler(ctx, {'message': 'hello'})
        self.assertTrue(out.is_error)
        # 用户随后预置账号（模拟宿主重启后出现）→ 下一周期自动发现。
        proc.Proc_data['bot_info_dict']['t'] = Bot('t')
        terminal.tick(ctx)
        self.assertNotIn('error', ctx.terminal)
        self.assertEqual(ctx.terminal['hash'], 't')

    def test_stale_selection_is_reselected_without_mutation(self):
        ctx, proc, _ = make({'a': Bot('a')})
        state = terminal.prepare(ctx)
        self.assertEqual(state['hash'], 'a')
        proc.Proc_data['bot_info_dict'].clear()
        proc.Proc_data['bot_info_dict']['b'] = Bot('b')
        self.assertNotIn('error', terminal.prepare(ctx))
        self.assertEqual(state['hash'], 'b')
        self.assertEqual(list(proc.Proc_data['bot_info_dict']), ['b'])

    def test_status_staleness_is_written_back_then_healed(self):
        ctx, proc, _ = make({'a': Bot('a')})
        terminal.prepare(ctx)
        proc.Proc_data['bot_info_dict'].clear()
        report = terminal.status(ctx)
        self.assertEqual(report['error'], 'Selected account is no longer available')
        self.assertEqual(ctx.terminal['error'], report['error'])
        proc.Proc_data['bot_info_dict']['a'] = Bot('a')
        terminal.tick(ctx)
        self.assertNotIn('error', ctx.terminal)
        self.assertTrue(terminal.status(ctx)['selected'])

    def test_status_does_not_overwrite_a_newer_selection(self):
        first, second = Bot('a'), Bot('b', id_=4343)
        ctx, proc, _ = make({'a': first}, queue=Queue())
        terminal.prepare(ctx)
        entered, resume, tick_done = threading.Event(), threading.Event(), threading.Event()
        reports, errors = [], []
        original = host.bot_info_dict

        def read_mapping(owner):
            data = original(owner)
            if threading.current_thread().name == 'terminal-status-test':
                entered.set()
                if not resume.wait(5):
                    raise AssertionError('Status barrier timed out')
            return data

        def query_status():
            try:
                reports.append(terminal.status(ctx))
            except BaseException as exc:
                errors.append(type(exc).__name__)

        def reselect():
            try:
                terminal.tick(ctx)
            except BaseException as exc:
                errors.append(type(exc).__name__)
            finally:
                tick_done.set()

        reader = threading.Thread(target=query_status, name='terminal-status-test', daemon=True)
        writer = threading.Thread(target=reselect, daemon=True)
        with patch.object(host, 'bot_info_dict', side_effect=read_mapping):
            reader.start()
            try:
                self.assertTrue(entered.wait(5))
                proc.Proc_data['bot_info_dict'] = {'b': second}
                unlocked = terminal._COMMIT_LOCK.acquire(blocking=False)
                if unlocked:
                    terminal._COMMIT_LOCK.release()
                writer.start()
                # 未持锁的旧查询可停在重选之后；持锁实现则先完成查询再发布。
                if unlocked:
                    self.assertTrue(tick_done.wait(5))
            finally:
                resume.set()
                reader.join(5)
                if writer.ident is not None:
                    writer.join(5)
        self.assertFalse(reader.is_alive())
        self.assertFalse(writer.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(reports), 1)
        self.assertIs(ctx.terminal['bot'], second)
        self.assertNotIn('error', ctx.terminal)
        self.assertFalse(terminal.TOOLS[0].handler(ctx, {'message': 'hello'}).is_error)

    def test_status_rejects_an_id_that_becomes_non_integer(self):
        for invalid in (True, 1.0, '1', None):
            with self.subTest(id_type=type(invalid).__name__):
                bot = Bot('t', id_=1)
                ctx, _, _ = make({'t': bot})
                terminal.prepare(ctx)
                bot.id = invalid
                report = terminal.status(ctx)
                self.assertFalse(report['selected'])
                self.assertIn('error', report)

    def test_prepare_rechecks_candidate_qualification_before_publish(self):
        for mutation in ('id', 'enable', 'platform'):
            with self.subTest(mutation=mutation):
                bot = Bot('t', id_=1)
                ctx, proc, _ = make({'t': bot})
                data = proc.Proc_data['bot_info_dict']
                calls = []

                def read_mapping(owner):
                    calls.append(1)
                    if len(calls) == 2:
                        if mutation == 'id':
                            bot.id = True
                        elif mutation == 'enable':
                            bot.enable = False
                        else:
                            bot.platform.model = 'ff14'
                    return data

                with patch.object(host, 'bot_info_dict', side_effect=read_mapping):
                    state = terminal.prepare(ctx)
                self.assertIn('error', state)
                self.assertFalse(terminal.status(ctx)['selected'])
                self.assertLessEqual(len(calls), 3)

    def test_repeated_prepare_is_stable(self):
        ctx, _, _ = make({'t': Bot('t')})
        state = terminal.prepare(ctx)
        self.assertIs(terminal.prepare(ctx), state)
        self.assertIs(terminal.tick(ctx) or state, state)

    def test_dict_swap_between_scan_and_publish_is_bounded(self):
        first, second, third = {'a': Bot('a')}, {'b': Bot('b')}, {'c': Bot('c')}
        fetches = []

        class SwappingProc(Proc):
            def __init__(self):
                pass

            @property
            def Proc_data(self):
                fetches.append(1)
                index = min(len(fetches) - 1, 2)
                return {'bot_info_dict': (first, second, third)[index]}

        ctx = Context(proc=SwappingProc(), root='/tmp/root',
                      data_root='/tmp/data', olivos=Host())
        state = terminal.prepare(ctx)
        self.assertEqual(state['error'], 'Account list changed during inspection; retry later')
        # 有界：初始读取 + 每轮重选各一次，共 2 轮。
        self.assertEqual(len(fetches), 3)

    def test_dict_swap_to_missing_stops_cleanly(self):
        fetches = []

        class VanishingProc(Proc):
            def __init__(self):
                pass

            @property
            def Proc_data(self):
                fetches.append(1)
                if len(fetches) > 1:
                    return {}
                return {'bot_info_dict': {'a': Bot('a')}}

        ctx = Context(proc=VanishingProc(), root='/tmp/root',
                      data_root='/tmp/data', olivos=Host())
        self.assertEqual(terminal.prepare(ctx)['error'],
                         'Account list changed during inspection; retry later')

    def test_tick_never_mutates_host_dict(self):
        ctx, proc, _ = make({})
        terminal.tick(ctx)
        self.assertEqual(proc.Proc_data['bot_info_dict'], {})
        self.assertEqual(ctx.terminal['error'], terminal.NOT_CONFIGURED)
        ctx2, proc2, _ = make({'t': Bot('t')})
        terminal.tick(ctx2)
        self.assertEqual(list(proc2.Proc_data['bot_info_dict']), ['t'])

    def test_context_fields_stay_frozen_and_terminal_state_is_private(self):
        from dataclasses import FrozenInstanceError

        ctx, _, _ = make({'t': Bot('t')})
        other, _, _ = make({'t': Bot('t')})
        with self.assertRaises(FrozenInstanceError):
            ctx.root = '/different-root'
        self.assertIsNot(ctx.terminal, other.terminal)
        terminal.prepare(ctx)
        self.assertFalse(other.terminal)


class VisibilityTests(unittest.TestCase):
    def test_terminal_account_is_counted_and_reported(self):
        ctx, _, _ = make({'h': Bot('h', Platform(sdk='qq')), 't': Bot('t')})
        terminal.prepare(ctx)
        status = host.TOOLS[0].handler(ctx, {})
        self.assertEqual(status.data['configured_bot_count'], 2)
        debug = status.data['debug_terminal']
        self.assertTrue(debug['selected'])
        self.assertNotIn('memory_created', debug)
        self.assertEqual(debug['connection'], 'unknown')
        self.assertEqual(set(debug['account']), {'hash', 'id', 'platform', 'connection'})
        self.assertNotIn('SECRET', repr(status.data))
        bots = host.TOOLS[1].handler(ctx, {}).data
        self.assertEqual(bots['count'], 2)
        self.assertEqual([bot['hash'] for bot in bots['bots']], ['h', 't'])

    def test_without_account_read_only_tools_still_work(self):
        ctx, _, _ = make({'h': Bot('h', Platform(sdk='qq'))})
        terminal.prepare(ctx)
        bots = host.TOOLS[1].handler(ctx, {})
        self.assertFalse(bots.is_error)
        self.assertEqual(bots.data['count'], 1)
        self.assertEqual(bots.data['debug_terminal']['connection'], 'unknown')
        self.assertIn('error', bots.data['debug_terminal'])

    def test_proc_get_lists_user_provisioned_hash_only(self):
        from OlivOSCockpit.config import Snapshot

        ctx, _, _ = make({'t': Bot('t')})
        terminal.prepare(ctx)
        snapshot = Snapshot(valid=True, full_real_account_write=True, full_low_level_access=True)
        ctx = replace(ctx, config=type('M', (), {'snapshot': staticmethod(lambda: snapshot)})())
        spec = next(tool for tool in full_only.TOOLS if tool.name == 'cockpit_proc_get')
        value = spec.handler(ctx, {'path': 'bot_hashes'}).data['value']
        self.assertEqual(value, ['t'])


ARGS = {'message': 'hello'}


class InputTests(unittest.TestCase):
    spec = terminal.TOOLS[0]

    def prepared(self, bots=None, queue=None):
        ctx, proc, host_ = make({'t': Bot('t')} if bots is None else bots,
                                queue=queue if queue is not None else Queue())
        terminal.prepare(ctx)
        return ctx, proc, host_

    def test_private_and_group_events_are_native(self):
        ctx, proc, _ = self.prepared()
        out = self.spec.handler(ctx, dict(ARGS, user_id='42'))
        self.assertFalse(out.is_error)
        self.assertEqual(out.data['chat'], 'private')
        self.assertEqual(out.data['processing'], 'unknown')
        rx, event = proc.Proc_info.rx_queue.items[0]
        user_conf = event.payload.key['data']['user_conf']
        self.assertFalse(user_conf['flag_group'])
        self.assertEqual(user_conf['user_id'], '42')
        self.assertEqual(user_conf['group_role'], 'member')
        self.assertEqual(event.payload.action, 'send')
        out = self.spec.handler(ctx, dict(ARGS, group_id='9000'))
        user_conf = proc.Proc_info.rx_queue.items[1][1].payload.key['data']['user_conf']
        self.assertTrue(user_conf['flag_group'])
        self.assertEqual(user_conf['target_id'], '9000')
        self.assertEqual(out.data['chat'], 'group')
        self.assertEqual(out.data['account']['platform'],
                         {'sdk': 'terminal_link', 'platform': 'terminal', 'model': 'default'})

    def test_rejects_non_native_or_replaced_account(self):
        ctx, proc, host_ = self.prepared()
        data = proc.Proc_data['bot_info_dict']
        digest = ctx.terminal['hash']
        data[digest] = Bot(digest, Platform(model='ff14'))
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        data[digest] = Bot('other', Platform())
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        data[digest] = Bot(digest)  # hash 相同但对象已被替换
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        self.assertEqual(proc.Proc_info.rx_queue.items, [])
        data.pop(digest)
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)

    def test_replacement_during_sdk_construction_is_not_queued(self):
        ctx, proc, h = self.prepared()
        digest = ctx.terminal['hash']

        def replace_bot(event):
            proc.Proc_data['bot_info_dict'][digest] = Bot(digest)
            return ('rx', event)

        h.pluginAPI.shallow.rx_packet = staticmethod(replace_bot)
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        self.assertEqual(proc.Proc_info.rx_queue.items, [])

    def test_same_hash_same_id_replacement_is_not_queued(self):
        # ABA：构造期间同 hash 同 ID 换对象，self_id 复核通过但身份复核必须拦下。
        ctx, proc, h = self.prepared()
        digest = ctx.terminal['hash']

        def replace_same(event):
            proc.Proc_data['bot_info_dict'][digest] = Bot(digest)
            return ('rx', event)

        h.pluginAPI.shallow.rx_packet = staticmethod(replace_same)
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        self.assertEqual(proc.Proc_info.rx_queue.items, [])

    def test_sdk_event_bound_to_other_account_is_not_queued(self):
        # 构造出的包绑定别的账号 ID：提交前 self_id 复核失败。
        ctx, proc, h = self.prepared()

        def misbound(payload, bot_info, model='default', event_id=None):
            return SDKEvent(payload, bot_info, model, self_id=999999)

        h.virtualTerminalSDK = type('V', (), {'event': staticmethod(misbound)})
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        self.assertEqual(proc.Proc_info.rx_queue.items, [])

    def test_final_id_check_requires_the_same_integer(self):
        for value, rejected in ((1, False), (True, True), (1.0, True), (2, True)):
            with self.subTest(id_type=type(value).__name__, rejected=rejected):
                bot = Bot('t', id_=1)
                ctx, proc, h = self.prepared(bots={'t': bot})

                def changed_after_sdk(event):
                    bot.id = value
                    return ('rx', event)

                h.pluginAPI.shallow.rx_packet = staticmethod(changed_after_sdk)
                outcome = self.spec.handler(ctx, dict(ARGS))
                self.assertEqual(outcome.is_error, rejected)
                self.assertEqual(len(proc.Proc_info.rx_queue.items), 0 if rejected else 1)

    def test_missing_or_full_queue_fails_safely(self):
        ctx, _, _ = self.prepared(queue=Queue(full=True))
        out = self.spec.handler(ctx, dict(ARGS))
        self.assertTrue(out.is_error)
        ctx, proc, _ = self.prepared()
        proc.Proc_info.rx_queue = None
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)
        proc.Proc_info.rx_queue = object()
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)

    def test_requires_preparation(self):
        ctx, _, _ = make({})
        self.assertTrue(self.spec.handler(ctx, dict(ARGS)).is_error)

    def test_unavailable_without_host_api(self):
        ctx, _, _ = make({'t': Bot('t')}, olivos=False)
        terminal.prepare(ctx)
        self.assertNotIn('error', ctx.terminal)  # 发现不需要宿主 API
        out = self.spec.handler(ctx, dict(ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'], 'Host terminal API unavailable')

    def test_generation_change_blocks_submission(self):
        from types import SimpleNamespace

        ctx, proc, _ = self.prepared()
        current = {'generation': 1}
        ctx = replace(ctx, config=SimpleNamespace(
            snapshot=lambda: SimpleNamespace(generation=current['generation'])))
        ctx = replace(ctx, request_generation=1)
        current['generation'] = 2
        out = self.spec.handler(ctx, dict(ARGS))
        self.assertTrue(out.is_error)
        self.assertEqual(out.data['error'],
                         'Configuration changed before message submission')
        self.assertEqual(proc.Proc_info.rx_queue.items, [])

    def test_host_baseexception_isolated(self):
        ctx, proc, host_ = self.prepared()

        def boom(*args, **kwargs):
            raise KeyboardInterrupt('SECRET-TOKEN')

        host_.pluginAPI.shallow.rx_packet = boom
        out = self.spec.handler(ctx, dict(ARGS))
        self.assertTrue(out.is_error)
        self.assertNotIn('SECRET', repr(out.data))

    def test_schema_and_utf8_budget(self):
        for args in ({}, {'message': ''}, {'message': 'x', 'bot_hash': 'h'},
                     {'message': 'x', 'user_id': 'a' * 257}):
            with self.assertRaises(ToolError):
                validate_arguments(self.spec, args)
        ctx, proc, _ = self.prepared()
        half = '中' * (terminal.MAX_MESSAGE // 3 + 1)
        self.assertLessEqual(len(half), terminal.MAX_MESSAGE)
        with self.assertRaises(ToolError):
            self.spec.handler(ctx, dict(ARGS, message=half))
        self.assertEqual(proc.Proc_info.rx_queue.items, [])


if __name__ == '__main__':
    unittest.main()
