"""不依赖 aiohttp 的授权与 worker 取消测试；不代表真实 HTTP 验收。"""

import asyncio
from contextlib import ExitStack
from pathlib import Path
import sys
import threading
from time import monotonic as real_monotonic
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from OlivOSCockpit import protocol, service  # noqa: E402
from OlivOSCockpit.contracts import (  # noqa: E402
    MAX_SESSIONS,
    SESSION_TTL,
    Context,
    Outcome,
    ToolError,
    ToolSpec,
    object_schema,
)


class SessionTests(unittest.TestCase):
    """纯会话查询测试；不依赖 aiohttp，不因 HTTP 缺失跳过。"""

    def test_version_single_query_covers_valid_owner_and_unknown(self):
        sessions = service._Sessions()
        session = sessions.create('2025-06-18', 'owner-a')
        self.assertEqual(sessions.version(session, 'owner-a'), '2025-06-18')
        self.assertTrue(sessions.valid(session, 'owner-a'))
        # owner 不符按未知会话处理
        self.assertIsNone(sessions.version(session, 'owner-b'))
        self.assertIsNone(sessions.version('missing', 'owner-a'))

    def test_version_after_clear_and_ttl_expiry_returns_none(self):
        sessions = service._Sessions()
        cleared = sessions.create('2025-03-26', 'owner')
        sessions.clear()
        self.assertIsNone(sessions.version(cleared, 'owner'))
        expired = sessions.create('2025-11-25', 'owner')
        shift = SESSION_TTL + 1
        with patch.object(service, 'monotonic', lambda: real_monotonic() + shift):
            self.assertIsNone(sessions.version(expired, 'owner'))
        # 过期项已被同一查询清理；恢复时钟后仍不可复用。
        self.assertFalse(sessions.valid(expired, 'owner'))

    def test_version_after_eviction_returns_none(self):
        sessions = service._Sessions()
        oldest = sessions.create('2024-11-05', 'owner')
        for _ in range(MAX_SESSIONS - 1):
            sessions.create('2025-06-18', 'owner')
        extra = sessions.create('2025-11-25', 'owner')
        self.assertIsNone(sessions.version(oldest, 'owner'))
        self.assertEqual(sessions.version(extra, 'owner'), '2025-11-25')


class ManagedStartupTests(unittest.TestCase):
    def setup_service(self, stack, factory=None, lock=None):
        context = Context(None, '/unused', '/unused/data')
        manager = SimpleNamespace(stopped=False, snapshot=lambda: SimpleNamespace(valid=True, ready=True))

        class FakeService:
            def __init__(self, context, token, tools, timeout, manager):
                self.context, self.manager = context, manager
                self.pool = SimpleNamespace(drained=threading.Event())

            def close(self):
                self.pool.drained.set()

        for name in ('_ACTIVE', '_RETIRED', '_STARTING'):
            stack.enter_context(patch.object(service, name, None, create=True))
        stack.enter_context(patch.object(service, '_ACTIVE_LOCK', lock or threading.Lock()))
        stack.enter_context(patch.object(service, 'web', object()))
        stack.enter_context(patch.object(service, '_Service', factory or FakeService))
        stack.enter_context(patch.object(service, '_build_app', lambda instance: None))
        run = stack.enter_context(patch.object(service, '_run_loop', lambda instance: None))
        return context, manager, FakeService, run

    def test_ready_start_does_not_recursively_acquire_the_publication_lock(self):
        class CheckedLock:
            entered = False

            def __enter__(self):
                if self.entered:
                    raise AssertionError('Recursive publication lock acquisition')
                self.entered = True

            def __exit__(self, *args):
                self.entered = False

        with ExitStack() as stack:
            context, manager, _, _ = self.setup_service(stack, lock=CheckedLock())
            ran = []
            stack.enter_context(patch.object(service, '_run_loop', lambda instance: ran.append(instance)))
            started = threading.Event()
            service._start_managed_thread(context, manager, (), started)
            self.assertTrue(started.is_set())
            self.assertEqual(len(ran), 1)

    def test_concurrent_start_reserves_before_constructing_workers(self):
        entered, release, second_done = threading.Event(), threading.Event(), threading.Event()
        built = []
        with ExitStack() as stack:
            context, manager, fake, _ = self.setup_service(stack, lock=threading.RLock())

            def factory(*args):
                built.append(1)
                entered.set()
                if not release.wait(5):
                    raise AssertionError('Construction barrier timed out')
                return fake(*args)

            stack.enter_context(patch.object(service, '_Service', factory))

            def second_start():
                try:
                    service._start_managed_thread(context, manager, (), threading.Event())
                finally:
                    second_done.set()

            first = threading.Thread(target=service._start_managed_thread,
                                     args=(context, manager, (), threading.Event()), daemon=True)
            second = threading.Thread(target=second_start, daemon=True)
            first.start()
            try:
                self.assertTrue(entered.wait(5))
                second.start()
                self.assertTrue(second_done.wait(2))
                self.assertEqual(len(built), 1)
                with self.assertRaises(ToolError):
                    service.start_managed(context, manager, ())
            finally:
                release.set()
                first.join(5)
                if second.ident is not None:
                    second.join(5)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(len(built), 1)

    def test_partial_worker_start_failure_retires_the_started_workers(self):
        real_thread = threading.Thread
        workers, pools = [], []

        def start_worker(*args, **kwargs):
            pool = kwargs['target'].__self__
            pools.append(pool)
            if len(pools) == 2:
                raise RuntimeError('worker creation failed')
            worker = real_thread(*args, **kwargs)
            workers.append(worker)
            return worker

        try:
            with patch.object(service.threading, 'Thread', side_effect=start_worker):
                with self.assertRaises(RuntimeError):
                    service._Pool(Context(None, '/unused', '/unused/data'))
            self.assertTrue(pools[0].drained.wait(2))
        finally:
            if pools:
                pools[0].close()
            for worker in workers:
                worker.join(5)
        self.assertTrue(all(not worker.is_alive() for worker in workers))

    def test_closed_pool_rejects_new_work_and_drains(self):
        pool = service._Pool(Context(None, '/unused', '/unused/data'))
        try:
            pool.close()
            self.assertFalse(pool.submit(object()))
            self.assertTrue(pool.drained.wait(5))
        finally:
            pool.close()


class CoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_from_handler_and_guard_does_not_lose_workers(self):
        pool = service._Pool(Context(None, '/unused', '/unused/data'))
        loop = asyncio.get_running_loop()

        def cancelled(*args):
            raise asyncio.CancelledError()

        try:
            # 超过池大小的连续取消仍能结束，不能每次损失一个 worker。
            for index in range(10):
                spec = ToolSpec('cancel', 'cancel', object_schema(),
                                cancelled if index % 2 else lambda ctx, args: Outcome({}))
                task = service._Task(spec, {}, loop, loop.create_future(),
                                     guard=cancelled if not index % 2 else None)
                for _ in range(200):
                    if pool.submit(task):
                        break
                    await asyncio.sleep(0.005)
                else:
                    self.fail('worker slots were not returned')
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(asyncio.shield(task.future), 2)
            result = service._Task(
                ToolSpec('ok', 'ok', object_schema(), lambda ctx, args: Outcome({'ok': True})),
                {}, loop, loop.create_future())
            for _ in range(200):
                if pool.submit(result):
                    break
                await asyncio.sleep(0.005)
            else:
                self.fail('workers did not survive cancellation')
            outcome = await asyncio.wait_for(result.future, 2)
            self.assertEqual(outcome.data, {'ok': True})
        finally:
            pool.close()

    async def test_snapshot_without_authorization_method_fails_closed(self):
        current = SimpleNamespace(api_key='test', generation=1, valid=True)
        context = Context(None, '/unused', '/unused/data',
                          config=SimpleNamespace(snapshot=lambda: current))
        svc = service._Service(context, '', (), 1)
        spec = ToolSpec('write', 'write', object_schema(), lambda ctx, args: Outcome({}),
                        read_only=False, required_permission='real_account_write')
        try:
            self.assertFalse(svc._authorize(spec, {}, svc._policy()))
        finally:
            svc.close()

    async def test_after_send_cancellation_is_not_reclassified_as_error(self):
        def cancelled():
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            service._safe_after_send(cancelled)

    async def test_raw_read_internal_failure_becomes_safe_tool_error_not_active_snapshot(self):
        # BUG-12：观察器读取内部缺陷不得伪装成“未激活/正常”快照。
        from unittest.mock import patch

        from OlivOSCockpit import raw, raw_tools

        bot_hash = 'x' * 32
        bot = SimpleNamespace(id='10001', hash=bot_hash, platform={
            'sdk': 'onebot', 'platform': 'qq', 'model': 'default'})
        proc = SimpleNamespace(Proc_data={'bot_info_dict': {bot_hash: bot}},
                               run_plugin=lambda event: 'host')
        context = Context(proc, '/unused', '/unused/data',
                          olivos=SimpleNamespace(API=SimpleNamespace(
                              getBotHash=lambda **kwargs: bot_hash)))
        self.assertIsNotNone(raw.install(context))
        proc.run_plugin(SimpleNamespace(
            platform={'sdk': 'onebot', 'platform': 'qq', 'model': 'default'},
            base_info={'self_id': '10001'}, json={'message': 'hello'}))
        self.assertEqual(raw.read(context)['count'], 1)
        spec = raw_tools.TOOLS[0]
        pool = service._Pool(context)
        try:
            with patch.object(raw, '_copy_json', side_effect=RuntimeError('SECRET internal defect')):
                task = service._Task(spec, {}, asyncio.get_running_loop(),
                                     asyncio.get_running_loop().create_future())
                outcome = pool._run(task)
        finally:
            pool.close()
        self.assertTrue(outcome.is_error)
        self.assertNotIn('SECRET', outcome.data['error'])
        self.assertNotIn('internal defect', outcome.data['error'])
        self.assertNotIn('active', outcome.data)

    async def test_raw_read_cancellation_is_not_reclassified_as_tool_error(self):
        from unittest.mock import patch

        from OlivOSCockpit import raw, raw_tools

        bot_hash = 'x' * 32
        bot = SimpleNamespace(id='10001', hash=bot_hash, platform={
            'sdk': 'onebot', 'platform': 'qq', 'model': 'default'})
        proc = SimpleNamespace(Proc_data={'bot_info_dict': {bot_hash: bot}},
                               run_plugin=lambda event: 'host')
        context = Context(proc, '/unused', '/unused/data',
                          olivos=SimpleNamespace(API=SimpleNamespace(
                              getBotHash=lambda **kwargs: bot_hash)))
        self.assertIsNotNone(raw.install(context))
        proc.run_plugin(SimpleNamespace(
            platform={'sdk': 'onebot', 'platform': 'qq', 'model': 'default'},
            base_info={'self_id': '10001'}, json={'message': 'hello'}))
        spec = raw_tools.TOOLS[0]
        pool = service._Pool(context)
        loop = asyncio.get_running_loop()
        try:
            with patch.object(raw, '_copy_json', side_effect=asyncio.CancelledError()):
                task = service._Task(spec, {}, loop, loop.create_future())
                outcome = pool._run(task)
            self.assertIsNone(outcome)
            self.assertTrue(task.future.cancelled() is False)
        finally:
            pool.close()

    def test_deprecated_start_entry_fails_without_building(self):
        # OPT-12：旧固定入口立即安全失败，不建服务对象、不建池、不起线程。
        context = Context(None, '/unused', '/unused/data')
        with patch.object(service, '_Service',
                          side_effect=AssertionError('must not construct')), \
                patch.object(service, '_build_app',
                             side_effect=AssertionError('must not build')), \
                patch.object(service, '_run_loop',
                             side_effect=AssertionError('must not run')):
            with self.assertRaises(ToolError):
                service.start(context, 'token', 8767)


if __name__ == '__main__':
    unittest.main()
