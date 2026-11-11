"""入口测试：宿主上下文、配置监督与异常边界；不启动真实监听。"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from OlivOSCockpit import config, main, raw  # noqa: E402
from OlivOSCockpit.contracts import Context  # noqa: E402

KEY = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8


def host_stub(data='./data'):
    return SimpleNamespace(infoAPI=SimpleNamespace(OlivOS_plugin_data_path=data))


def wire(ctx, manager):
    """把监督回调接到给定管理器；service 用记录器代替真实监听。"""
    applied = []

    def apply(context, mgr, snapshot=None, tools=None):
        applied.append(snapshot.ready if snapshot is not None else None)
        return True

    manager.set_notify(lambda snapshot: main._on_config(ctx, manager, snapshot))
    return applied, apply


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.messages = []
        self.proc = SimpleNamespace(log=lambda *args: self.messages.append(args))
        # entry fixture 必须同时隔离三个 main 全局引用，避免清理动作跨测试遗留。
        self.stack = ExitStack()
        for name in ('_context', '_manager', '_thread', '_target', '_pending'):
            self.stack.enter_context(patch.object(main, name, None))
        self.addCleanup(self.stack.close)

    @staticmethod
    def _wait(predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    def init(self, proc=None, data='./data'):
        with patch.object(main, 'OlivOS', host_stub(data)):
            main.Event.init(None, proc or self.proc)
        return main._context

    def test_root_is_host_cwd_and_data_path_is_host_relative(self):
        root = os.path.join(os.path.abspath(os.sep), 'instance with spaces', '中文')
        with patch.object(main.os, 'getcwd', return_value=root):
            context = self.init(data='./custom-data')
        self.assertEqual(context.root, root)
        self.assertEqual(context.data_root, os.path.join(root, 'custom-data'))
        self.assertEqual(context.terminal['error'],
                         'Configured account list unavailable')

    def test_missing_host_data_path_is_not_guessed(self):
        with patch.object(main, 'OlivOS', SimpleNamespace(infoAPI=SimpleNamespace())):
            main.Event.init(None, self.proc)
            self.assertIsNone(main._context)
            self.assertIsNone(main._manager)

    def test_supervisor_setup_failure_does_not_escape_thread(self):
        manager = SimpleNamespace(set_log=lambda callback: (_ for _ in ()).throw(SystemExit('secret')))
        main._supervise(Context(self.proc, '/unused', '/unused/data'), manager)
        self.assertNotIn('secret', str(self.messages))

    def test_save_attempts_every_cleanup_even_after_host_exception(self):
        calls = []

        def stop():
            calls.append('config')
            raise SystemExit('secret')

        context = Context(self.proc, '/unused', '/unused/data')
        with patch.object(main, '_manager', SimpleNamespace(stop=stop)), \
                patch.object(main, '_context', context), \
                patch.object(main.service, 'request_stop', lambda: calls.append('service')), \
                patch.object(main.raw, 'uninstall', lambda ctx: calls.append('raw')), \
                patch.object(main.registry, 'detach', lambda ctx: calls.append('intercept')):
            main.Event.save(None, self.proc)
        self.assertEqual(calls, ['config', 'service', 'raw', 'intercept'])
        self.assertNotIn('secret', str(self.messages))

    def test_terminal_prepare_failure_keeps_context(self):
        with patch.object(main.terminal, 'prepare', side_effect=SystemExit('secret')):
            context = self.init()
            self.assertIsNotNone(main._context)
            self.assertEqual(context.terminal['error'],
                             'Debug terminal preparation failed')
        self.assertNotIn('secret', str(self.messages))

    def test_reinit_same_loader_keeps_terminal_state(self):
        proc = SimpleNamespace(Proc_data={'bot_info_dict': {}}, log=lambda *args: None)
        with patch.object(main, 'OlivOS', host_stub()):
            main.Event.init(None, proc)
            first = main._context.terminal
            main.Event.init(None, proc)
            self.assertIs(main._context.terminal, first)
        self.assertEqual(proc.Proc_data['bot_info_dict'], {})

    def _hooked_proc(self):
        """构造可同时安装 raw 与 intercept 的最小宿主桩。"""
        proc = SimpleNamespace(
            Proc_data={'bot_info_dict': {}}, log=lambda *args: None,
            run_plugin=lambda event: 'host', plugin_event_router=lambda event: 'host')
        context = Context(proc, '/unused', '/unused/data', host_stub(),
                          permission_mode='full')
        controller = main.registry.attach(context)
        observer = raw.install(context, policy=lambda record: True)
        return proc, context, controller, observer

    def test_init_failure_after_previous_setup_restores_previous_hooks(self):
        # 先成功 init 并安装真实 raw/intercept 桩，再让第二次 init 的 getcwd 失败。
        proc, _, controller, observer = self._hooked_proc()
        try:
            self.assertIsNotNone(controller)
            self.assertIsNotNone(observer)
            with patch.object(main, '_context', Context(proc, '/unused', '/unused/data')), \
                    patch.object(main, '_manager', config.ConfigManager('/unused/data')), \
                    patch.object(main.os, 'getcwd', side_effect=SystemExit('secret')):
                main.Event.init(None, proc)
            self.assertIsNone(main._context)
            self.assertIsNone(main._manager)
            # 观察器与拦截器都按所有权恢复原方法，规则清空且不再活动。
            self.assertFalse(observer._active)
            self.assertEqual(proc.run_plugin('event'), 'host')
            self.assertEqual(proc.plugin_event_router('event'), 'host')
            self.assertNotIn('secret', str(self.messages))
        finally:
            raw.uninstall(Context(proc, '/unused', '/unused/data'))
            main.registry.detach(Context(proc, '/unused', '/unused/data'))

    def test_init_failure_tries_every_cleanup_step_and_dedupes_candidates(self):
        calls = []

        def stop():
            calls.append('config')
            raise SystemExit('config-secret')

        def detach(context):
            calls.append('intercept')
            raise SystemExit('intercept-secret')

        previous = Context(self.proc, '/unused', '/unused/data')
        previous_manager = SimpleNamespace(stop=stop, stopped=False)
        with patch.object(main, '_context', previous), \
                patch.object(main, '_manager', previous_manager), \
                patch.object(main, '_thread', threading.Thread(target=lambda: None)), \
                patch.object(main.os, 'getcwd', lambda: (_ for _ in ()).throw(KeyboardInterrupt('init-secret'))), \
                patch.object(main.service, 'request_stop', lambda: calls.append('service')), \
                patch.object(main.raw, 'uninstall', lambda ctx: calls.append('raw')), \
                patch.object(main.registry, 'detach', detach):
            main.Event.init(None, self.proc)
        # 每步均被尝试；同一对象不重复清理；全局引用清空不代表线程已结束。
        self.assertEqual(calls, ['config', 'service', 'raw', 'intercept'])
        self.assertIsNone(main._context)
        self.assertIsNone(main._manager)
        self.assertIsNone(main._thread)
        for secret in ('config-secret', 'intercept-secret', 'init-secret'):
            self.assertNotIn(secret, str(self.messages))

    def test_stopped_manager_late_callback_is_ignored(self):
        manager = config.ConfigManager('/unused/data')
        context = Context(self.proc, '/unused', '/unused/data', config=manager)
        applied, apply = wire(context, manager)
        manager.stop()
        with patch.object(main.service, 'apply_config', apply):
            manager._notify(manager.snapshot())
        self.assertEqual(applied, [])
        self.assertFalse(manager.snapshot().ready)
        self.assertFalse(manager.snapshot().valid)

    def test_config_supervision_waits_for_key_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            data_root = os.path.join(directory, 'data')
            os.makedirs(data_root)
            manager = config.ConfigManager(data_root, 'full')
            # 首次加载前建立空上下文，模拟宿主 init 时的默认快照。
            context = Context(self.proc, directory, data_root, host_stub())
            applied, apply = wire(context, manager)
            with patch.object(main.service, 'apply_config', apply), \
                    patch.object(main, '_target', (context, manager)), \
                    patch.object(main.terminal, 'prepare', lambda ctx: ctx.terminal):
                self.assertFalse(manager.snapshot().ready)
                manager.refresh()
                manager.refresh()
                # 模板 api_key 为空：监督回调可见但从不请求监听。
                self.assertTrue(applied)
                self.assertFalse(any(applied))
                self.assertFalse(manager.snapshot().ready)

                control = Path(config.control_dir(data_root))
                template = json.loads((control / config.CONFIG_NAME).read_text('utf-8'))
                self.assertEqual(template['api_key'], '')
                template['api_key'] = KEY
                (control / config.CONFIG_NAME).write_text(
                    json.dumps(template), encoding='utf-8')
                # 内容变化先撤权，稳定确认后才发布可用快照。
                manager.refresh()
                self.assertFalse(manager.snapshot().ready)
                manager.refresh()
                self.assertTrue(manager.snapshot().ready)
                self.assertIs(applied[-1], True)

                (control / config.CONFIG_NAME).write_text('{', encoding='utf-8')
                manager.refresh()
                self.assertFalse(manager.snapshot().ready)
                self.assertIs(applied[-1], False)

                template['api_key'] = KEY
                (control / config.CONFIG_NAME).write_text(
                    json.dumps(template), encoding='utf-8')
                manager.refresh()
                manager.refresh()
                self.assertTrue(manager.snapshot().ready)
                # 已播种后再删除：不重建，按缺失安全失败。
                (control / config.CONFIG_NAME).unlink()
                manager.refresh()
                self.assertFalse(manager.snapshot().ready)
                self.assertIs(applied[-1], False)
                self.assertFalse((control / config.CONFIG_NAME).exists())

    def test_init_after_only_starts_one_daemon_thread(self):
        context = Context(self.proc, '/unused', '/unused/data')
        with patch.object(main, '_context', context), patch.object(main, '_manager', None), \
                patch.object(main, '_thread', None), patch.object(main, '_target', None):
            with patch.object(main.threading, 'Thread') as thread:
                main.Event.init_after(None, self.proc)
                # 第二个 init_after 在假线程视为存活时不得再起线程；
                # 假线程不会清 _thread，这里显式模拟守护线程仍存活。
                thread.return_value.is_alive.return_value = True
                with patch.object(main, '_thread', thread.return_value):
                    main.Event.init_after(None, self.proc)
                thread.assert_called_once()
                self.assertIs(thread.call_args.kwargs['daemon'], True)
                thread.return_value.start.assert_called_once()

    def test_callback_boundary_catches_system_exit(self):
        with patch.object(main.os, 'getcwd', side_effect=SystemExit('secret')):
            with patch.object(main, '_context', None):
                main.Event.init(None, self.proc)
                self.assertIsNone(main._context)
        self.assertNotIn('secret', str(self.messages))

    # 监督器交接：旧线程退出后接替新 manager，不并行补开监督器。

    def _managed_proc(self):
        return SimpleNamespace(Proc_data={'bot_info_dict': {}},
                               log=lambda *args: None,
                               run_plugin=lambda event: 'host',
                               plugin_event_router=lambda event: 'host')

    def _scripted_manager(self, started, release):
        """run_forever 阻塞到 release；记录绑定与轮询次数。"""
        manager = SimpleNamespace(stopped=False, bound=[], polls=0,
                                  log_cb=None, notify_cb=None, tick_cb=None)
        manager.set_log = lambda cb: setattr(manager, 'log_cb', cb)
        manager.set_notify = lambda cb: setattr(manager, 'notify_cb', cb)
        manager.set_tick = lambda cb: setattr(manager, 'tick_cb', cb)
        manager.prepare = lambda: manager

        def run_forever():
            started.set()
            release.wait(5)

        manager.run_forever = run_forever
        return manager

    def _start_supervisor(self, context, manager):
        """在补丁仍生效时启动，模拟 init_after 登记目标后起线程。"""
        thread = threading.Thread(target=main._supervise, args=(context, manager),
                                  daemon=True)
        stack = ExitStack()
        stack.enter_context(patch.object(main, '_target', (context, manager)))
        stack.enter_context(patch.object(main, '_thread', thread))
        self.addCleanup(stack.close)
        thread.start()
        return thread

    def test_supervisor_takes_over_new_manager_after_old_thread_exits(self):
        context = Context(self.proc, '/unused', '/unused/data')
        started, release = threading.Event(), threading.Event()
        old = self._scripted_manager(started, release)
        thread = self._start_supervisor(context, old)
        self.assertTrue(started.wait(2))
        new_started, new_release = threading.Event(), threading.Event()
        new = self._scripted_manager(new_started, new_release)
        with patch.object(main, '_target', (context, new)):
            release.set()  # 旧 run_forever 在目标切换后才返回
            self.assertTrue(new_started.wait(2), 'new manager was never supervised')
            self.assertIsNotNone(new.log_cb)
            new_release.set()
            self.assertTrue(self._wait(lambda: not thread.is_alive()))
        # 线程自身退出后清引用，不需要宿主回调 join 或另开线程。
        self.assertIsNone(main._thread)

    def test_supervisor_reuses_live_thread_when_target_arrives_early(self):
        context = Context(self.proc, '/unused', '/unused/data')
        started, release = threading.Event(), threading.Event()
        old = self._scripted_manager(started, release)
        thread = self._start_supervisor(context, old)
        self.assertTrue(started.wait(2))
        new_started, new_release = threading.Event(), threading.Event()
        new = self._scripted_manager(new_started, new_release)
        # init_after 在旧线程仍存活时登记新目标：不得另起线程。
        with patch.object(main, '_target', (context, new)), \
                patch.object(main, '_thread', thread):
            main.Event.init_after(None, self._managed_proc())
            self.assertIs(main._thread, thread)
            release.set()
            self.assertTrue(new_started.wait(2))
            new_release.set()
            self.assertTrue(self._wait(lambda: not thread.is_alive()))

    def test_stale_manager_callbacks_are_discarded_after_handover(self):
        context = Context(self.proc, '/unused', '/unused/data')
        old_manager = config.ConfigManager('/unused/data')
        new_manager = config.ConfigManager('/unused/data')
        applied = []
        with patch.object(main, '_target', (context, new_manager)), \
                patch.object(main.terminal, 'prepare', lambda ctx: ctx.terminal), \
                patch.object(main.service, 'apply_config',
                             lambda *a, **k: applied.append(a) or True):
            # 旧 manager 的闭包在交接后仍可能被触发：归属门必须丢弃它。
            main._on_config(context, old_manager, old_manager.snapshot())
            main._on_config(context, new_manager, new_manager.snapshot())
        self.assertEqual(len(applied), 1)
        self.assertIs(applied[0][1], new_manager)

    def test_handover_marks_pending_only_when_old_service_owner_blocks(self):
        context = Context(self.proc, '/unused', '/unused/data')
        manager = config.ConfigManager('/unused/data')
        snapshot = manager.snapshot()
        calls = []

        def apply(ctx, mgr, snapshot=None, tools=None):
            calls.append(snapshot)
            return False

        with patch.object(main, '_target', (context, manager)), \
                patch.object(main, 'service') as fake:
            fake.web = object()
            fake.apply_config = apply
            fake.can_start = lambda: False
            main._on_config(context, manager, snapshot)
            self.assertEqual(len(calls), 1)
            self.assertIsNotNone(main._pending)
            # 旧实例已释放：只重试一次，成功后停止重试。
            fake.can_start = lambda: True
            main._retry_start(context, manager)
            main._retry_start(context, manager)
        self.assertEqual(len(calls), 2)
        self.assertIsNone(main._pending)

    def test_healthy_tick_never_applies_and_retry_waits_for_owner_exit(self):
        context = Context(self.proc, '/unused', '/unused/data')
        manager = config.ConfigManager('/unused/data')
        calls = []
        with patch.object(main, '_target', (context, manager)), \
                patch.object(main, 'terminal') as terminal, \
                patch.object(main, 'service') as fake:
            fake.web = object()
            fake.apply_config = lambda *a, **k: calls.append(a) or False
            fake.can_start = lambda: False
            terminal.tick = lambda ctx: None
            main._pending = (context, manager)
            main._tick(context, manager)
            self.assertEqual(calls, [])  # 旧 owner 未退出：保持待处理，不补开
            fake.can_start = lambda: True
            main._tick(context, manager)
            self.assertEqual(len(calls), 1)
            self.assertIsNone(main._pending)
            main._tick(context, manager)
            self.assertEqual(len(calls), 1)  # 健康态 tick 不再 apply

    def test_retry_keeps_pending_if_another_start_takes_the_slot(self):
        manager = config.ConfigManager('/unused/data')
        context = Context(self.proc, '/unused', '/unused/data', config=manager)
        available, calls = [True], []

        def apply(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                available[0] = False
                return False
            return True

        with patch.object(main, '_target', (context, manager)), \
                patch.object(main, 'service') as fake:
            fake.web = object()
            fake.can_start = lambda: available[0]
            fake.apply_config = apply
            main._pending = (context, manager)
            main._retry_start(context, manager)
            self.assertIsNotNone(main._pending)
            available[0] = True
            main._retry_start(context, manager)
            main._retry_start(context, manager)
        self.assertIsNone(main._pending)
        self.assertEqual(len(calls), 2)

    def test_stale_apply_result_preserves_new_pending_owner(self):
        context = Context(self.proc, '/unused', '/unused/data')
        old = config.ConfigManager('/unused/data')
        new = config.ConfigManager('/unused/data')
        pending = (context, new)

        def apply(*args, **kwargs):
            with main._lock:
                main._target = pending
                main._pending = pending
            return False

        with patch.object(main, '_target', (context, old)), \
                patch.object(main, 'service') as fake:
            fake.web = object()
            fake.can_start = lambda: False
            fake.apply_config = apply
            main._on_config(context, old, old.snapshot())
            self.assertIs(main._pending, pending)

    def test_missing_http_dependency_is_not_a_retryable_handover(self):
        context = Context(self.proc, '/unused', '/unused/data')
        manager = config.ConfigManager('/unused/data')
        with patch.object(main, '_target', (context, manager)), \
                patch.object(main, 'service') as fake:
            fake.web = None
            fake.apply_config = lambda *a, **k: False
            fake.can_start = lambda: False
            main._on_config(context, manager, manager.snapshot())
        self.assertIsNone(main._pending)

    def test_reinit_with_identical_context_sources_reuses_context_object(self):
        proc = self._managed_proc()
        with patch.object(main, 'OlivOS', host_stub()):
            main.Event.init(None, proc)
            first = main._context
            manager = main._manager
            main.Event.init(None, proc)
            self.assertIs(main._context, first)
            self.assertIs(main._manager, manager)
            self.assertFalse(manager.stopped)
            self.assertEqual(first.proc, proc)

    def test_reinit_with_changed_sources_retires_old_manager(self):
        proc = self._managed_proc()
        with patch.object(main, 'OlivOS', host_stub()):
            main.Event.init(None, proc)
            first_context, first_manager = main._context, main._manager
            with patch.object(main.os, 'getcwd', return_value='/elsewhere'):
                main.Event.init(None, proc)
        self.assertIsNot(main._context, first_context)
        self.assertIsNot(main._manager, first_manager)
        self.assertTrue(first_manager.stopped)
        self.assertIsNot(main._context.config, first_manager)


if __name__ == '__main__':
    unittest.main()
