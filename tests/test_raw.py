import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from OlivOSCockpit import raw  # noqa: E402
from OlivOSCockpit.contracts import Context  # noqa: E402


def native_hash(bot_id=None, platform_sdk=None, platform_platform=None, platform_model=None):
    """宿主 getBotHash 桩：与宿主 md5 算法不同，必须保持 32 位十六进制。"""
    seed = 'native:' + str(bot_id) + str(platform_sdk) + str(platform_platform)
    return hashlib.md5(seed.encode('utf-8')).hexdigest()


def host_api(digest=native_hash):
    return SimpleNamespace(API=SimpleNamespace(getBotHash=digest))


class RawObserverTests(unittest.TestCase):
    def make_context(self, sdk='onebot', platform='qq', model='default', bot_id='10001',
                     bot_hash=None, olivos=True):
        triple = {'sdk': sdk, 'platform': platform, 'model': model}
        bot_hash = bot_hash or native_hash(bot_id, sdk, platform)
        bot = SimpleNamespace(id=bot_id, platform=triple, hash=bot_hash)
        calls = []

        def run_plugin(event):
            calls.append(event)
            return 'host-result'

        proc = SimpleNamespace(
            Proc_data={'bot_info_dict': {bot_hash: bot}},
            run_plugin=run_plugin,
        )
        context = Context(proc=proc, root='/unused', data_root='/unused/data',
                          olivos=host_api() if olivos else None)
        return context, calls, triple, bot_hash

    @staticmethod
    def event(triple, bot_id='10001', payload=None, **extra):
        fields = {
            'platform': triple,
            'base_info': {'self_id': bot_id},
        }
        fields.update(extra)
        if payload is not None:
            fields['json'] = payload
        return SimpleNamespace(**fields)

    def test_install_wraps_only_instance_and_calls_host_once(self):
        context, calls, triple, bot_hash = self.make_context()
        payload = {
            'post_type': 'message',
            'message': {'text': 'hello'},
            'access_token': 'must-not-leak',
            'extra': 'not-whitelisted',
        }
        sdk_event = self.event(triple, payload=payload)

        observer = raw.install(context)
        self.assertIsNotNone(observer)
        self.assertIsNotNone(observer.wrapper)
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])

        payload['message']['text'] = 'changed-after-capture'
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 1)
        record = snapshot['records'][0]
        self.assertEqual(record['bot_hash'], bot_hash)
        self.assertEqual(record['payload']['message'], {'text': 'hello'})
        self.assertNotIn('access_token', record['payload'])
        self.assertNotIn('extra', record['payload'])

        snapshot['records'][0]['payload']['message']['text'] = 'changed-read-copy'
        self.assertEqual(raw.read(context)['records'][0]['payload']['message']['text'], 'hello')

    def test_unknown_bot_is_discarded_without_skipping_host_call(self):
        context, calls, triple, _ = self.make_context()
        sdk_event = self.event(triple, bot_id='not-configured', payload={'message': 'hello'})

        observer = raw.install(context)
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])
        snapshot = observer.read()
        self.assertEqual(snapshot['count'], 0)
        self.assertEqual(snapshot['discarded_reasons']['unknown_bot'], 1)

    def test_policy_is_supplied_by_caller_and_runs_on_read_boundary(self):
        context, _, triple, _ = self.make_context()
        allow = lambda record: record['payload'].get('message') == 'keep'
        observer = raw.install(context, policy=allow)
        context.proc.run_plugin(self.event(triple, payload={'message': 'drop'}))
        context.proc.run_plugin(self.event(triple, payload={'message': 'keep'}))

        self.assertEqual(observer.read()['count'], 1)
        self.assertEqual(raw.read(context, policy=lambda record: False)['count'], 0)
        self.assertEqual(observer.read()['count'], 1)

    def test_base_exception_from_observer_does_not_touch_host_call(self):
        context, calls, triple, _ = self.make_context()

        def exploding_policy(record):
            raise SystemExit('observer failure')

        raw.install(context, policy=exploding_policy)
        sdk_event = self.event(triple, payload={'message': 'hello'})
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])
        self.assertEqual(raw.read(context)['count'], 0)
        self.assertEqual(raw.read(context)['discarded_reasons']['observer_error'], 1)

    def test_observation_cancellation_keeps_single_host_call(self):
        # OPT-01：宿主 hash 抛取消时观察隔离为 drop 计数，原调用仍恰好一次。
        context, calls, triple, _ = self.make_context()
        cancelling = SimpleNamespace(API=SimpleNamespace(
            getBotHash=lambda **kwargs: (_ for _ in ()).throw(asyncio.CancelledError())))
        context = replace(context, olivos=cancelling)
        raw.install(context)
        sdk_event = self.event(triple, payload={'message': 'hello'})
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 0)
        self.assertEqual(snapshot['discarded_reasons']['observer_error'], 1)

    def test_install_cancellation_does_not_replace_hook(self):
        # OPT-01：安装被取消时不得替换原 hook，宿主调用不受影响。
        context, calls, triple, _ = self.make_context()
        with patch.object(raw, 'Observer', side_effect=asyncio.CancelledError()):
            self.assertIsNone(raw.install(context))
        sdk_event = self.event(triple)
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])

    def test_original_host_method_cancellation_propagates(self):
        # OPT-01：原宿主方法自身的取消原样保留，不被观察器吞掉或改写。
        calls = []

        def cancelling_run(event):
            calls.append(event)
            raise asyncio.CancelledError()

        proc = SimpleNamespace(Proc_data={'bot_info_dict': {}}, run_plugin=cancelling_run)
        context = Context(proc=proc, root='/unused', data_root='/unused/data',
                          olivos=host_api())
        raw.install(context)
        with self.assertRaises(asyncio.CancelledError):
            context.proc.run_plugin(self.event(
                {'sdk': 'onebot', 'platform': 'qq', 'model': 'default'}))
        self.assertEqual(len(calls), 1)

    def test_oversized_account_dict_is_dropped_as_bot_limit(self):
        # OPT-05：超过 MAX_BOTS 的持有字典整体丢弃并使用专门 reason。
        context, calls, triple, bot_hash = self.make_context()
        bots = dict(context.proc.Proc_data['bot_info_dict'])
        for index in range(raw.MAX_BOTS):
            digest = '%032d' % index
            bots[digest] = SimpleNamespace(id=str(index), platform=triple, hash=digest)
        context.proc.Proc_data['bot_info_dict'] = bots
        raw.install(context)
        sdk_event = self.event(triple, payload={'message': 'hello'})
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 0)
        self.assertEqual(snapshot['discarded_reasons'].get('bot_limit'), 1)
        self.assertNotIn('unknown_bot', snapshot['discarded_reasons'])

    def test_account_dict_at_limit_still_observes(self):
        # OPT-05：500 项仍在观察范围内，不误报超限。
        context, calls, triple, _ = self.make_context()
        bots = dict(context.proc.Proc_data['bot_info_dict'])
        for index in range(raw.MAX_BOTS - 1):
            digest = '%032d' % index
            bots[digest] = SimpleNamespace(id=str(index), platform=triple, hash=digest)
        context.proc.Proc_data['bot_info_dict'] = bots
        raw.install(context)
        context.proc.run_plugin(self.event(triple, payload={'message': 'hello'}))
        self.assertEqual(raw.read(context)['count'], 1)

    def test_nested_adapter_payload_is_projected_without_host_objects(self):
        context, _, triple, _ = self.make_context(
            sdk='dingtalk_link', platform='dingtalk', model='default', bot_id='robot'
        )
        payload = SimpleNamespace(
            data=SimpleNamespace(
                headers={'messageId': 'm-1', 'topic': 'EVENT', 'ticket': 'drop'},
                type='CALLBACK',
                data={
                    'msgtype': 'text',
                    'conversationId': 'c-1',
                    'text': {'content': 'hello'},
                    'atUsers': [{'staffId': 'u-1', 'dingtalkId': 'd-1', 'token': 'drop'}],
                    'password': 'drop',
                },
            )
        )
        sdk_event = self.event(triple, bot_id='robot', payload=payload)
        # The helper places the event in json by default; replace it with payload.
        sdk_event = SimpleNamespace(
            platform=triple,
            base_info={'self_id': 'robot'},
            payload=payload,
        )

        raw.install(context)
        context.proc.run_plugin(sdk_event)
        record = raw.read(context)['records'][0]
        self.assertEqual(record['adapter'], 'dingtalk')
        self.assertEqual(record['payload']['data']['text']['content'], 'hello')
        self.assertNotIn('ticket', record['payload']['headers'])
        self.assertNotIn('password', record['payload']['data'])
        self.assertNotIn('token', record['payload']['data']['atUsers'][0])

    def test_uninstall_restores_only_our_current_wrapper(self):
        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        self.assertTrue(raw.uninstall(context))
        self.assertFalse(raw.read(context)['active'])
        self.assertEqual(context.proc.run_plugin(self.event(triple, payload={'message': 'x'})), 'host-result')

        context, _, triple, _ = self.make_context()
        observer = raw.install(context)

        def another_wrapper(event):
            return 'other'

        context.proc.run_plugin = another_wrapper
        self.assertFalse(observer.uninstall())
        self.assertIs(context.proc.run_plugin, another_wrapper)

    def test_record_depth_and_size_limits_are_bounded(self):
        context, _, triple, _ = self.make_context()
        raw.install(context)
        oversized = self.event(
            triple,
            payload={'message': 'x' * raw.MAX_RECORD_BYTES},
        )
        deep = 'leaf'
        for _ in range(raw.MAX_DEPTH + 2):
            deep = {'next': deep}
        deeply_nested = self.event(triple, payload={'message': deep})

        context.proc.run_plugin(oversized)
        context.proc.run_plugin(deeply_nested)
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 0)
        self.assertEqual(snapshot['dropped'], 2)
        self.assertTrue(snapshot['truncated'])

    def test_cache_overwrites_oldest_at_record_limit(self):
        context, _, triple, _ = self.make_context()
        raw.install(context)
        for index in range(raw.MAX_RECORDS + 1):
            context.proc.run_plugin(self.event(triple, payload={'message': str(index)}))

        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], raw.MAX_RECORDS)
        self.assertEqual(snapshot['overwritten'], 1)
        self.assertEqual(snapshot['records'][0]['payload']['message'], '1')
        self.assertEqual(snapshot['records'][-1]['payload']['message'], str(raw.MAX_RECORDS))

    def test_credential_named_fields_stay_in_copy_for_outbound_policy(self):
        context, _, triple, _ = self.make_context()
        message = [
            {'type': 'text', 'data': {'text': 'hello', 'token': 'raw-token'}},
            {'type': 'image', 'data': {'file': 'x', 'password': 'raw-password'}},
        ]
        raw.install(context)
        context.proc.run_plugin(self.event(triple, payload={'message': message}))
        record = raw.read(context)['records'][0]
        self.assertEqual(record['payload']['message'][0]['data']['token'], 'raw-token')
        self.assertEqual(record['payload']['message'][1]['data']['password'], 'raw-password')

    def test_wildcard_copy_keeps_native_json_keys_including_sensitive_names(self):
        context, _, triple, _ = self.make_context(
            sdk='qqGuild_link', platform='qqGuild', model='default', bot_id='bot-1'
        )
        payload = SimpleNamespace(data={
            'op': 0, 't': 'MESSAGE_CREATE',
            'd': {'content': 'hi', 'token': 'raw-token', 'password': 'raw-password'},
        })
        raw.install(context)
        context.proc.run_plugin(SimpleNamespace(
            platform=triple, base_info={'self_id': 'bot-1'}, payload=payload))
        record = raw.read(context)['records'][0]
        self.assertEqual(record['adapter'], 'qqGuild')
        self.assertEqual(record['payload']['d']['token'], 'raw-token')
        self.assertEqual(record['payload']['d']['password'], 'raw-password')

    def test_read_limit_selects_newest_before_bounded_copy(self):
        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        for index in range(5):
            context.proc.run_plugin(self.event(triple, payload={'message': str(index)}))
        snapshot = observer.read(limit=2)
        self.assertEqual(snapshot['count'], 2)
        self.assertEqual([row['payload']['message'] for row in snapshot['records']], ['3', '4'])
        self.assertTrue(snapshot['truncated'])
        full = observer.read()
        self.assertEqual(full['count'], 5)
        self.assertFalse(full['truncated'])

    def test_read_budget_caps_total_copy_and_marks_truncated(self):
        from unittest.mock import patch

        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        for index in range(3):
            context.proc.run_plugin(self.event(triple, payload={'message': str(index)}))
        with patch.object(raw, 'MAX_READ_BYTES', 1):
            snapshot = observer.read()
        self.assertEqual(snapshot['count'], 0)
        self.assertTrue(snapshot['truncated'])

    def test_all_v11_models_are_owned_without_falling_through_to_other_adapters(self):
        bot_hash = native_hash('10001', 'onebot', 'qq')
        for model in raw.ONEBOT_V11_MODELS:
            with self.subTest(model=model):
                bot = SimpleNamespace(id='10001', hash=bot_hash, platform={
                    'sdk': 'onebot', 'platform': 'qq', 'model': model})
                calls = []
                proc = SimpleNamespace(
                    Proc_data={'bot_info_dict': {bot_hash: bot}},
                    run_plugin=lambda event: calls.append(event) or 'host',
                )
                context = Context(proc=proc, root='/unused', data_root='/unused/data',
                                  olivos=host_api())
                raw.install(context)
                event = SimpleNamespace(
                    platform={'sdk': 'onebot', 'platform': 'qq', 'model': 'default'},
                    base_info={'self_id': '10001'},
                    json={'post_type': 'message', 'message': 'hello'},
                )
                self.assertEqual(proc.run_plugin(event), 'host')
                snapshot = raw.read(context)
                self.assertEqual(snapshot['count'], 1)
                self.assertEqual(snapshot['records'][0]['platform']['model'], model)
                self.assertEqual(snapshot['records'][0]['adapter'], 'onebot_v11')
                self.assertEqual(calls, [event])

    def test_native_v12_milky_opq_events_are_not_attributed_to_v11_configured_accounts(self):
        bot_hash = native_hash('10001', 'onebot', 'qq')
        bot = SimpleNamespace(id='10001', hash=bot_hash, platform={
            'sdk': 'onebot', 'platform': 'qq', 'model': 'napcat_default'})
        proc = SimpleNamespace(
            Proc_data={'bot_info_dict': {bot_hash: bot}},
            run_plugin=lambda event: 'host',
        )
        context = Context(proc=proc, root='/unused', data_root='/unused/data', olivos=host_api())
        raw.install(context)
        for model, payload in (
                ('onebotV12', {'type': 'message', 'detail_type': 'private', 'message': 'x'}),
                ('milky_default', {'event_type': 'message_receive', 'data': {}}),
                ('opqbot_default', {'CurrentQQ': 10001})):
            with self.subTest(model=model):
                event = SimpleNamespace(
                    platform={'sdk': 'onebot', 'platform': 'qq', 'model': model},
                    base_info={'self_id': '10001'},
                    json=payload,
                )
                self.assertEqual(proc.run_plugin(event), 'host')
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 0)
        self.assertEqual(snapshot['discarded_reasons']['unknown_bot'], 3)

    def test_lookup_never_reflects_properties_or_custom_string_conversion(self):
        class Hostile:
            @property
            def platform(self):
                raise AssertionError('must not evaluate property')

            def __str__(self):
                raise AssertionError('must not stringify')

        context, _, triple, _ = self.make_context()
        raw.install(context)
        event = SimpleNamespace(
            platform=Hostile(), base_info=SimpleNamespace(**{'self_id': '10001'}))
        self.assertEqual(context.proc.run_plugin(event), 'host-result')
        self.assertEqual(raw.read(context)['count'], 0)

    def test_contended_capture_is_counted_and_marked_incomplete(self):
        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        observer._lock.acquire()
        try:
            context.proc.run_plugin(self.event(triple, payload={'message': 'skipped'}))
        finally:
            observer._lock.release()
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 0)
        self.assertEqual(snapshot['discarded_reasons']['contended'], 1)
        self.assertTrue(snapshot['truncated'])

    def test_coverage_states_it_is_not_full_traffic(self):
        context, _, _, _ = self.make_context()
        coverage = raw.read(context)['coverage']
        self.assertIn('not a full traffic capture', coverage['limits_note'])
        self.assertIn('frames discarded before run_plugin', coverage['excluded'])

    def test_raw_tool_reports_truncation_and_bounded_limit(self):
        from OlivOSCockpit import raw_tools

        context, _, triple, _ = self.make_context()
        raw.install(context)
        for index in range(raw_tools.MAX_RETURN_RECORDS + 2):
            context.proc.run_plugin(self.event(triple, payload={'message': str(index)}))
        outcome = raw_tools.TOOLS[0].handler(context, {'limit': 2})
        self.assertEqual(outcome.data['count'], 2)
        self.assertEqual(
            [row['payload']['message'] for row in outcome.data['records']], ['8', '9'])
        self.assertTrue(outcome.truncated)
        oversized = raw_tools.TOOLS[0].handler(
            context, {'limit': raw_tools.MAX_RETURN_RECORDS + 1})
        self.assertTrue(oversized.data['count'] <= raw_tools.MAX_RETURN_RECORDS)

    def test_final_text_and_structured_reply_stay_within_response_budget(self):
        from OlivOSCockpit import protocol, raw_tools
        from OlivOSCockpit.contracts import MAX_RESPONSE

        # 引号/反斜线会让 text 再次转义；不能只看中文样本或把安全错误当成功。
        for chunk in ('界' * 8000, chr(92) * 26000, (chr(34) + chr(92)) * 13000):
            with self.subTest(sample=chunk[:2]):
                context, _, triple, _ = self.make_context()
                raw.install(context)
                for _ in range(raw_tools.MAX_RETURN_RECORDS):
                    context.proc.run_plugin(self.event(triple, payload={'message': chunk}))
                outcome = raw_tools.TOOLS[0].handler(context, {})
                self.assertGreater(outcome.data['count'], 0)
                self.assertFalse(outcome.is_error)
                for modern in (False, True):
                    body = protocol.result_body(
                        'raw', protocol.tool_result(outcome, protocol.dumps(outcome.data)), modern)
                    reply = protocol.encode_reply(body, modern)
                    self.assertLessEqual(len(reply.body), MAX_RESPONSE)
                    self.assertFalse(reply.failed)
                    decoded = json.loads(reply.body)['result']
                    self.assertFalse(decoded.get('isError', False))
                    self.assertEqual(decoded['structuredContent']['count'], outcome.data['count'])

    def test_read_cap_keeps_latest_records_and_reports_cut(self):
        from unittest.mock import patch

        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        for index in range(raw.MAX_RETURN_RECORDS):
            context.proc.run_plugin(self.event(
                triple, payload={'message': 'x' * 40000 + str(index)}))
        with patch.object(raw, 'MAX_READ_BYTES', raw.MAX_RECORD_BYTES * 2):
            snapshot = observer.read(limit=raw.MAX_RETURN_RECORDS)
        self.assertEqual(snapshot['count'], 3)
        self.assertTrue(snapshot['truncated'])
        self.assertTrue(snapshot['records'][-1]['payload']['message'].endswith('7'))

    # MAINT01：账号指纹只来自注入的宿主函数，不再本地复写算法。
    def test_observer_uses_injected_host_hash_not_a_local_algorithm(self):
        context, _, triple, bot_hash = self.make_context()
        self.assertFalse(hasattr(raw, '_bot_hash'))
        raw.install(context)
        context.proc.run_plugin(self.event(triple, payload={'message': 'hello'}))
        snapshot = raw.read(context)
        self.assertEqual(snapshot['count'], 1)
        self.assertEqual(snapshot['records'][0]['bot_hash'], bot_hash)

    def test_missing_or_failing_host_hash_fails_closed_without_breaking_host_call(self):
        # 缺能力：事件按 unknown_bot 丢弃，工具读取方得到空快照，宿主调用不受影响。
        for olivos in (None, host_api(None)):
            with self.subTest(olivos=olivos):
                context, calls, triple, _ = self.make_context(olivos=False)
                context = Context(proc=context.proc, root='/unused', data_root='/unused/data',
                                  olivos=olivos)
                self.assertIsNotNone(raw.install(context))
                sdk_event = self.event(triple, payload={'message': 'hello'})
                self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
                self.assertEqual(calls, [sdk_event])
                snapshot = raw.read(context)
                self.assertTrue(snapshot['active'])
                self.assertEqual(snapshot['count'], 0)
                self.assertEqual(snapshot['discarded_reasons']['unknown_bot'], 1)

        # 宿主函数在场但调用失败：事件丢弃并计数，宿主调用仍恰好一次。
        def boom(**kwargs):
            raise RuntimeError('host hash failure')

        context, calls, triple, _ = self.make_context(olivos=False)
        context = Context(proc=context.proc, root='/unused', data_root='/unused/data',
                          olivos=host_api(boom))
        self.assertIsNotNone(raw.install(context))
        sdk_event = self.event(triple, payload={'message': 'hello'})
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])
        self.assertEqual(raw.read(context)['discarded_reasons']['unknown_bot'], 1)

    # BUG10：安装/卸载自身生命周期原子；不嵌套检查，第三方 wrapper 不被覆盖。
    def test_concurrent_install_and_uninstall_keep_one_observer(self):
        context, _, triple, _ = self.make_context()
        original = context.proc.run_plugin
        entered = threading.Event()
        release = threading.Event()

        class Tracking(raw.Observer):
            live = 0
            peak = 0

            def __init__(self, *args, **kwargs):
                type(self).live += 1
                type(self).peak = max(type(self).peak, type(self).live)
                entered.set()
                # 构造期暂停；第二个 install 必须在生命周期锁外等待，不得并发构造。
                release.wait(2)
                super().__init__(*args, **kwargs)
                type(self).live -= 1

        results = []
        with patch.object(raw, 'Observer', Tracking):
            first = threading.Thread(target=lambda: results.append(raw.install(context)))
            first.start()
            self.assertTrue(entered.wait(2))
            second = threading.Thread(target=lambda: results.append(raw.install(context)))
            second.start()
            time.sleep(0.1)
            release.set()
            first.join(2)
            second.join(2)
        self.assertEqual(len(results), 2)
        self.assertEqual(Tracking.peak, 1, 'install lifecycles overlapped')
        observer = results[0]
        self.assertIs(results[1], observer)
        self.assertIs(context.proc.run_plugin, observer.wrapper)
        self.assertIs(observer.original, original)
        self.assertIs(observer.native_hash, native_hash)

        # 已安装后再次 install 复用同一观察器，不叠加包装。
        again = raw.install(context)
        self.assertIs(again, observer)
        self.assertIs(context.proc.run_plugin, observer.wrapper)

        results.clear()
        threads = [threading.Thread(target=lambda: results.append(raw.uninstall(context)))
                   for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertIs(context.proc.run_plugin, original)
        self.assertEqual(sorted(results), [False, True])

    def test_uninstall_in_another_thread_while_observer_lock_held_does_not_deadlock(self):
        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        original = observer.original
        observer._lock.acquire()
        try:
            thread = threading.Thread(target=observer.uninstall)
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
        finally:
            observer._lock.release()
        self.assertIs(context.proc.run_plugin, original)

    def test_host_wrapper_replaced_after_install_survives_uninstall(self):
        context, _, triple, _ = self.make_context()
        observer = raw.install(context)

        def third_party(event):
            return observer.wrapper(event)

        context.proc.run_plugin = third_party
        self.assertFalse(raw.uninstall(context))
        self.assertIs(context.proc.run_plugin, third_party)

    # BUG11：wrapped 的最后兜底不得逃逸，宿主原方法必须恰好调用一次。
    def test_last_resort_failure_never_skips_or_alters_the_host_call(self):
        context, calls, triple, _ = self.make_context()
        context.proc.run_plugin = None
        observer = raw.Observer(
            context.proc, lambda event: calls.append(event) or 'host-result')
        sdk_event = self.event(triple, payload={'message': 'hello'})

        # 观察失败且兜底计数再次失败：宿主的正常返回值保持不变。
        with patch.object(type(observer), '_drop', side_effect=MemoryError('drop failed')):
            self.assertEqual(observer.wrapper(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])

        # 同一路径下宿主原异常对象原样传播，不被兜底替换。
        error = RuntimeError('host error')

        def failing(event):
            calls.append(event)
            raise error

        observer = raw.Observer(context.proc, failing)
        with patch.object(type(observer), '_drop', side_effect=MemoryError('drop failed')):
            with self.assertRaises(RuntimeError) as caught:
                observer.wrapper(sdk_event)
        self.assertIs(caught.exception, error)
        self.assertEqual(len(calls), 2)

    def test_drop_failure_when_building_record_does_not_skip_host_call(self):
        context, calls, triple, _ = self.make_context()
        observer = raw.install(context)
        sdk_event = self.event(triple, payload={'message': 'hello'})
        with patch.object(raw, '_build_record', side_effect=SystemExit('build failed')), \
                patch.object(type(observer), '_drop', side_effect=MemoryError('drop failed')):
            self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        self.assertEqual(calls, [sdk_event])

    # BUG12：服务侧读取的内部缺陷不再伪装成未激活正常状态。
    def test_read_failure_is_reported_safely_instead_of_faking_an_inactive_snapshot(self):
        from OlivOSCockpit import raw_tools
        from OlivOSCockpit.contracts import ToolError

        context, _, triple, _ = self.make_context()
        raw.install(context)
        sdk_event = self.event(triple, payload={'message': 'hello'})
        self.assertEqual(context.proc.run_plugin(sdk_event), 'host-result')
        with patch.object(raw, '_copy_json', side_effect=RuntimeError('SECRET internal defect')):
            with self.assertRaises(ToolError) as caught:
                raw_tools.TOOLS[0].handler(context, {})
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertNotIn('internal defect', str(caught.exception))
        self.assertEqual(raw.read(context)['count'], 1)

    def test_read_lookup_failures_are_not_reported_as_an_uninstalled_observer(self):
        for error in (RuntimeError('SECRET lookup'), KeyboardInterrupt('SECRET lookup'),
                      asyncio.CancelledError()):
            class FaultyProc:
                @property
                def run_plugin(self):
                    raise error

            class FaultyContext:
                @property
                def __dict__(self):
                    raise error

            context = Context(FaultyProc(), '/unused', '/unused/data')
            expected = asyncio.CancelledError if isinstance(error, asyncio.CancelledError) else raw.ToolError
            for broken in (context, FaultyContext()):
                with self.subTest(error=type(error).__name__, context=type(broken).__name__):
                    with self.assertRaises(expected) as caught:
                        raw.read(broken)
                    self.assertNotIn('SECRET', str(caught.exception))
                    self.assertIsNone(raw.install(broken))
                    self.assertFalse(raw.uninstall(broken))

    def test_read_does_not_swallow_cancellation(self):
        context, _, triple, _ = self.make_context()
        observer = raw.install(context)
        context.proc.run_plugin(self.event(triple, payload={'message': 'hello'}))
        with patch.object(raw, '_copy_json', side_effect=asyncio.CancelledError()):
            with self.assertRaises(asyncio.CancelledError):
                observer.read()
        # 取消或内部缺陷后锁必须可靠释放，后续读取仍可用。
        self.assertFalse(observer._lock.locked())
        with patch.object(raw, '_context_proc', side_effect=asyncio.CancelledError()):
            with self.assertRaises(asyncio.CancelledError):
                raw.read(context)

        with patch.object(type(observer), '_purged', side_effect=RuntimeError('purge failed')):
            with self.assertRaises(raw.ToolError):
                observer.read()
        self.assertFalse(observer._lock.locked())
        self.assertEqual(observer.read()['count'], 1)


if __name__ == '__main__':
    unittest.main()
