"""配置驱动服务边界测试；不依赖 aiohttp，使用最小请求桩。"""

import asyncio
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from OlivOSCockpit import config, protocol, redaction, service  # noqa: E402
from OlivOSCockpit.contracts import (  # noqa: E402
    CALL_TIMEOUT,
    Context,
    Outcome,
    ToolSpec,
    object_schema,
)

CONTEXT = Context(None, '/unused', '/unused/data')
KEY = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8
NEW_KEY = 'OlivOS-' + 'B' * 16 + 'c' * 8 + '2' * 8


class SiteStub:
    """记录 start/stop 的最小 TCPSite 替身；实例进入共享列表供断言。"""

    registry = None

    def __init__(self, runner, host, port):
        self.runner, self.host, self.port = runner, host, port
        self.started = False
        self.stopped = False
        if SiteStub.registry is not None:
            SiteStub.registry.append(self)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True


class RunnerStub:
    setup_gate = None

    def __init__(self, app, handle_signals=False):
        self.app = app

    async def setup(self):
        gate = RunnerStub.setup_gate
        if gate is not None:
            gate.entered.set()
            while not gate.released.is_set():
                await asyncio.sleep(0.005)

    async def cleanup(self):
        pass


def stub_web(sites, setup_gate=None):
    """构造 service.web 替身；setup_gate 提供 entered/released 两个 Event。"""
    SiteStub.registry = sites
    RunnerStub.setup_gate = setup_gate
    return SimpleNamespace(TCPSite=SiteStub, AppRunner=RunnerStub)


def gate():
    holder = SimpleNamespace(entered=threading.Event(),
                             released=threading.Event())
    return holder


class Manager:
    def __init__(self, **values):
        values.setdefault('api_key', KEY)
        values.setdefault('generation', 1)
        values.setdefault('listen_host', '127.0.0.1')
        values.setdefault('listen_port', 8767)
        values.setdefault('redaction_enabled', True)
        values.setdefault('redact_fields', [])
        values.setdefault('allow_fields', [])
        self.values = values
        self.snapshot_calls = 0
        self.permitted = True

    def snapshot(self):
        self.snapshot_calls += 1
        return SimpleNamespace(**self.values)

    def allowed(self, permission=None):
        return self.permitted

    def rotate(self, key, generation):
        self.values['api_key'] = key
        self.values['generation'] = generation


class Headers:
    def __init__(self, values):
        self.values = values

    def get(self, name, default=None):
        for key, value in self.values:
            if key.lower() == name.lower():
                return value
        return default

    def getall(self, name, default=None):
        found = [value for key, value in self.values if key.lower() == name.lower()]
        return found if found else ([] if default is None else default)


class Content:
    def __init__(self, data):
        self.data = data

    async def read(self, count):
        chunk, self.data = self.data[:count], self.data[count:]
        return chunk


class Request:
    method = 'POST'

    def __init__(self, body, headers):
        self.headers = headers
        self.content = Content(body)
        self.content_length = len(body)


def modern_body(tool=None, arguments=None):
    meta = {protocol.META_VERSION: protocol.MODERN_VERSION,
            protocol.META_CAPABILITIES: {}}
    params = {'_meta': meta}
    if tool is not None:
        params['name'] = tool
        params['arguments'] = arguments or {}
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call' if tool else 'tools/list',
            'params': params}


def headers(token=None, session=None, tool='echo'):
    values = [('Content-Type', 'application/json'),
              ('MCP-Protocol-Version', protocol.MODERN_VERSION),
              ('Mcp-Method', 'tools/call'),
              ('Mcp-Name', tool)]
    if token is not None:
        values.append(('Authorization', 'Bearer ' + token))
    if session is not None:
        values.append(('Mcp-Session-Id', session))
    return Headers(values)


def make_service(manager, tools):
    return service._Service(CONTEXT, None, tools, CALL_TIMEOUT, manager)


class ConfigServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.calls = []
        self.proc = SimpleNamespace(log=lambda *args: None)
        self.tool = ToolSpec('echo', 'echo', object_schema({'value': {'type': 'string'}}),
                             self._echo)
        self.service = make_service(Manager(), (self.tool,))

    def tearDown(self):
        self.service.close()

    def _echo(self, ctx, args):
        self.calls.append(dict(args))
        return Outcome({'echo': args.get('value', 'ok')})

    async def post(self, body, request_headers, rotate=None):
        """rotate='dispatch' 在分派返回后、边界检查前切换代次；
        rotate='error' 在首个错误响应编码后切换代次。"""
        replies = []

        async def write(_request, reply):
            replies.append(reply)
            return 'sent'

        patches = [patch.object(self.service, '_write', write)]
        if rotate == 'dispatch':
            original = self.service._dispatch

            async def dispatch(req, policy):
                reply, task = await original(req, policy)
                self.service.manager.rotate(NEW_KEY, 2)
                return reply, task

            patches.append(patch.object(self.service, '_dispatch', dispatch))
        elif rotate == 'error':
            original = self.service._error_reply
            state = {'n': 0}

            def error_reply(*args, **kwargs):
                result = original(*args, **kwargs)
                state['n'] += 1
                if state['n'] == 1:
                    self.service.manager.rotate(NEW_KEY, 2)
                return result

            patches.append(patch.object(self.service, '_error_reply', error_reply))
        raw = json.dumps(body).encode()
        for item in patches:
            item.start()
        try:
            await self.service.handle(Request(raw, request_headers))
        finally:
            for item in patches:
                item.stop()
        return replies[0]

    async def test_missing_key_rejects_even_with_bearer(self):
        self.service.manager.values['api_key'] = ''
        reply = await self.post(modern_body(), headers(token=KEY))
        self.assertEqual(reply.status, 401)
        self.assertEqual(self.calls, [])

    async def test_key_rotation_invalidates_legacy_session(self):
        init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': protocol.DEFAULT_LEGACY, 'capabilities': {},
            'clientInfo': {'name': 'client', 'version': '1.0'}}}
        legacy_headers = Headers([('Content-Type', 'application/json'),
                                  ('Authorization', 'Bearer ' + KEY)])
        reply = await self.post(init, legacy_headers)
        self.assertEqual(reply.status, 200)
        session = dict(reply.headers)['Mcp-Session-Id']

        self.service.manager.rotate(NEW_KEY, 2)
        listing = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}
        stale = Headers([('Content-Type', 'application/json'),
                         ('Authorization', 'Bearer ' + NEW_KEY),
                         ('Mcp-Session-Id', session)])
        reply = await self.post(listing, stale)
        self.assertEqual(reply.status, 404)

    async def test_authorization_runs_before_handler_and_denies(self):
        self.service.manager.permitted = False
        reply = await self.post(modern_body('echo', {'value': 'x'}),
                                headers(token=KEY))
        payload = json.loads(reply.body)['result']
        self.assertTrue(payload['isError'])
        self.assertEqual(self.calls, [])

    async def test_authorization_allows_when_snapshot_permits(self):
        reply = await self.post(modern_body('echo', {'value': 'x'}), headers(token=KEY))
        payload = json.loads(reply.body)['result']
        self.assertFalse(payload['isError'])
        self.assertEqual(self.calls, [{'value': 'x'}])

    async def test_stale_generation_is_denied_in_worker(self):
        spec = self.tool
        self.service.manager.rotate(NEW_KEY, 2)
        self.assertFalse(self.service._authorized_now(spec, {}, 1))
        self.assertTrue(self.service._authorized_now(spec, {}, 2))

    async def test_rotated_key_blocks_after_send(self):
        fired = threading.Event()

        def handler(ctx, args):
            return Outcome({'ok': True}, after_send=fired.set)

        manager = Manager()
        svc = make_service(manager, (ToolSpec('reload', 'reload', object_schema(), handler),))

        async def write(_request, reply):
            manager.rotate(NEW_KEY, 2)
            return 'sent'

        raw = json.dumps(modern_body('reload', {})).encode()
        try:
            with patch.object(svc, '_write', write):
                await svc.handle(Request(raw, headers(token=KEY)))
            await asyncio.to_thread(fired.wait, 0.2)
            self.assertFalse(fired.is_set())
        finally:
            svc.close()

    async def test_redaction_disabled_returns_original_values(self):
        self.service.manager.values['redaction_enabled'] = False
        secret = 'password=raw-value'
        self.calls.clear()

        def echo(ctx, args):
            return Outcome({'message': secret, 'password': 'raw-password'})

        self.service.tools = (ToolSpec('echo', 'echo', object_schema(), echo),)
        self.service.by_name = {tool.name: tool for tool in self.service.tools}
        reply = await self.post(modern_body('echo', {}), headers(token=KEY))
        result = json.loads(reply.body)['result']
        self.assertEqual(result['structuredContent']['message'], secret)
        self.assertEqual(result['structuredContent']['password'], 'raw-password')
        self.assertEqual(json.loads(result['content'][0]['text']), result['structuredContent'])

    async def test_redaction_enabled_still_applies(self):
        reply = await self.post(modern_body('echo', {'value': 'password=raw'}), headers(token=KEY))
        result = json.loads(reply.body)['result']
        self.assertNotIn('password=raw', reply.body.decode())
        self.assertTrue(result['_meta']['redacted'])

    async def test_reconcile_binds_rebinds_and_stops_without_rebuilding_pool(self):
        sites = []

        class Site:
            def __init__(self, runner, host, port):
                self.host, self.port, self.started, self.stopped = host, port, False, False
                sites.append(self)

            async def start(self):
                self.started = True

            async def stop(self):
                self.stopped = True

        manager = Manager()
        svc = make_service(manager, ())
        svc.runner = object()
        pool = svc.pool
        try:
            with patch.object(service, 'web', SimpleNamespace(TCPSite=Site)):
                await svc._reconcile()
                self.assertEqual((sites[-1].host, sites[-1].port), ('127.0.0.1', 8767))
                manager.values['listen_port'] = 9000
                await svc._reconcile()
                self.assertTrue(sites[-2].stopped)
                self.assertEqual(sites[-1].port, 9000)
                session = svc.sessions.create()
                manager.values['api_key'] = ''
                await svc._reconcile()
                self.assertTrue(sites[-1].stopped)
                self.assertFalse(svc.sessions.valid(session))
                self.assertIs(svc.pool, pool)
        finally:
            svc.close()

    def test_apply_config_without_http_dependency_reports_failure(self):
        # 缺少 aiohttp 时不得假装已启动，也不能抛异常到监督线程。
        with patch.object(service, 'web', None):
            self.assertFalse(service.apply_config(CONTEXT, self.service.manager))
            self.assertFalse(service.request_stop())

    def test_unready_snapshot_never_listens(self):
        manager = Manager()
        manager.values['api_key'] = ''
        with patch.object(service, 'web', SimpleNamespace()):
            self.assertTrue(service.apply_config(CONTEXT, manager))
        self.assertIsNone(service._ACTIVE)

    # ---- 交接：旧池未退尽不补新池，旧回调不能停掉新 owner ----------------

    def test_pool_drain_gate_blocks_second_pool_until_workers_exit(self):
        hold = threading.Event()
        pool = service._Pool(CONTEXT)

        def blocking(_ctx, _args):
            hold.wait(3)
            return Outcome({})

        spec = ToolSpec('block', 'block', object_schema(), blocking)
        loop = asyncio.new_event_loop()
        try:
            task = service._Task(spec, {}, loop, loop.create_future())
            self.assertTrue(pool.submit(task))
            # close 只发哨兵：阻塞中的 worker 仍在，池不能当作已回收。
            pool.close()
            self.assertFalse(pool.drained.is_set())
            with patch.object(service, '_RETIRED', SimpleNamespace(pool=pool)), \
                    patch.object(service, '_ACTIVE', None), \
                    patch.object(service, 'web', SimpleNamespace()):
                self.assertFalse(service.can_start())
            hold.set()
            self.assertTrue(pool.drained.wait(3))
            with patch.object(service, '_RETIRED', SimpleNamespace(pool=pool)), \
                    patch.object(service, '_ACTIVE', None), \
                    patch.object(service, 'web', SimpleNamespace()):
                self.assertTrue(service.can_start())
        finally:
            loop.close()

    def test_apply_config_never_stops_a_live_foreign_owner(self):
        class Foreign:
            context = CONTEXT
            manager = Manager()
            stopped = False

            def request_stop(self):
                self.stopped = True

            def schedule_reconcile(self):
                self.stopped = True

        owner = Foreign()
        with patch.object(service, '_ACTIVE', owner), \
                patch.object(service, 'web', SimpleNamespace()):
            # 别的 manager 仍存活：不能停掉当前 owner 的实例。
            self.assertFalse(service.apply_config(CONTEXT, Manager()))
            self.assertFalse(owner.stopped)
            owner.manager.stopped = True
            self.assertFalse(service.apply_config(CONTEXT, Manager()))
            self.assertTrue(owner.stopped)

    # ---- BUG-18：代次变化窗口保留已接受通知与既有错误状态 -----------------

    async def _legacy_session(self):
        init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': protocol.DEFAULT_LEGACY, 'capabilities': {},
            'clientInfo': {'name': 'client', 'version': '1.0'}}}
        legacy_headers = Headers([('Content-Type', 'application/json'),
                                  ('Authorization', 'Bearer ' + KEY)])
        reply = await self.post(init, legacy_headers)
        self.assertEqual(reply.status, 200)
        return dict(reply.headers)['Mcp-Session-Id']

    async def test_generation_change_keeps_accepted_legacy_notification(self):
        session = await self._legacy_session()
        note = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
        reply = await self.post(note, Headers([
            ('Content-Type', 'application/json'),
            ('Authorization', 'Bearer ' + KEY),
            ('Mcp-Session-Id', session)]), rotate='dispatch')
        self.assertEqual(reply.status, 202)
        self.assertEqual(reply.body, b'')

    async def test_generation_change_keeps_legal_unknown_notification(self):
        session = await self._legacy_session()
        note = {'jsonrpc': '2.0', 'method': 'notifications/custom-thing'}
        reply = await self.post(note, Headers([
            ('Content-Type', 'application/json'),
            ('Authorization', 'Bearer ' + KEY),
            ('Mcp-Session-Id', session)]), rotate='dispatch')
        self.assertEqual(reply.status, 202)
        self.assertEqual(reply.body, b'')

    async def test_generation_change_keeps_modern_notification(self):
        meta = {protocol.META_VERSION: protocol.MODERN_VERSION,
                protocol.META_CAPABILITIES: {}}
        note = {'jsonrpc': '2.0', 'method': 'notifications/initialized',
                'params': {'_meta': meta}}
        modern_headers = Headers([
            ('Content-Type', 'application/json'),
            ('Authorization', 'Bearer ' + KEY),
            ('MCP-Protocol-Version', protocol.MODERN_VERSION),
            ('Mcp-Method', 'notifications/initialized')])
        reply = await self.post(note, modern_headers, rotate='dispatch')
        self.assertEqual(reply.status, 202)
        self.assertEqual(reply.body, b'')

    async def test_generation_change_replaces_tool_result_and_blocks_after_send(self):
        fired = threading.Event()

        def handler(ctx, args):
            return Outcome({'ok': True}, after_send=fired.set)

        self.service.tools = (ToolSpec('pingback', 'pingback', object_schema(), handler),)
        self.service.by_name = {tool.name: tool for tool in self.service.tools}
        reply = await self.post(modern_body('pingback', {}), headers(token=KEY, tool='pingback'),
                                rotate='dispatch')
        payload = json.loads(reply.body)['result']
        self.assertTrue(payload['isError'])
        self.assertEqual(payload['structuredContent'],
                         {'error': 'Outbound redaction failed safely', 'redacted': True})
        await asyncio.to_thread(fired.wait, 0.2)
        self.assertFalse(fired.is_set())

    async def test_generation_change_preserves_reject_status_and_code(self):
        cases = []
        # 未知 session：404
        cases.append((
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
            Headers([('Content-Type', 'application/json'),
                     ('Authorization', 'Bearer ' + KEY),
                     ('Mcp-Session-Id', 'unknown')]), 404, protocol.INVALID_REQUEST))
        # 显式 id:null：非法请求 id
        cases.append((
            {'jsonrpc': '2.0', 'id': None, 'method': 'tools/list'},
            Headers([('Content-Type', 'application/json'),
                     ('Authorization', 'Bearer ' + KEY)]), 400, protocol.INVALID_REQUEST))
        # 缺 method
        cases.append((
            {'jsonrpc': '2.0', 'id': 1},
            Headers([('Content-Type', 'application/json'),
                     ('Authorization', 'Bearer ' + KEY)]), 400, protocol.INVALID_REQUEST))
        # 非法 params
        cases.append((
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': 'bad'},
            Headers([('Content-Type', 'application/json'),
                     ('Authorization', 'Bearer ' + KEY)]), 400, protocol.INVALID_PARAMS))
        # 无 id initialize
        cases.append((
            {'jsonrpc': '2.0', 'method': 'initialize', 'params': {
                'protocolVersion': protocol.DEFAULT_LEGACY, 'capabilities': {},
                'clientInfo': {'name': 'client', 'version': '1.0'}}},
            Headers([('Content-Type', 'application/json'),
                     ('Authorization', 'Bearer ' + KEY)]), 400, protocol.INVALID_REQUEST))
        for body, request_headers, status, code in cases:
            with self.subTest(code=code):
                self.service.manager.values['api_key'] = KEY
                self.service.manager.values['generation'] = 1
                reply = await self.post(body, request_headers, rotate='error')
                self.assertEqual(reply.status, status)
                payload = json.loads(reply.body)
                self.assertEqual(payload['error']['code'], code)
                self.assertNotEqual(reply.body, b'')

    # ---- BUG-19：会话单锁查询 ---------------------------------------------

    async def test_dispatch_queries_sessions_once(self):
        real = self.service.sessions

        class Counting:
            def __init__(self, target):
                self._target = target
                self.version_calls = 0
                self.valid_calls = 0

            def __getattr__(self, name):
                return getattr(self._target, name)

            def version(self, session, owner=None):
                self.version_calls += 1
                return self._target.version(session, owner)

            def valid(self, session, owner=None):
                self.valid_calls += 1
                return self._target.valid(session, owner)

        counting = Counting(real)
        self.service.sessions = counting
        try:
            session = await self._legacy_session()
            listing = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}
            reply = await self.post(listing, Headers([
                ('Content-Type', 'application/json'),
                ('Authorization', 'Bearer ' + KEY),
                ('Mcp-Session-Id', session)]))
            self.assertEqual(reply.status, 200)
            self.assertEqual(counting.version_calls, 1)
            self.assertEqual(counting.valid_calls, 0)
        finally:
            self.service.sessions = real

    # ---- OPT-03：启动/停止窗口与 reconcile 收敛 ----------------------------

    def _loop_service(self, manager):
        svc = make_service(manager, ())
        svc.app = object()
        return svc

    async def test_startup_reconcile_races_converge(self):
        sites = []
        manager = Manager()
        svc = self._loop_service(manager)
        pool = svc.pool
        original = svc._reconcile
        peak = {'current': 0, 'max': 0}

        async def reconcile():
            peak['current'] += 1
            peak['max'] = max(peak['max'], peak['current'])
            try:
                await original()
            finally:
                peak['current'] -= 1

        svc._reconcile = reconcile
        thread = threading.Thread(target=service._run_loop, args=(svc,), daemon=True)
        try:
            with patch.object(service, 'web', stub_web(sites)):
                thread.start()
                # setup/start 期间改端口、连续发布、撤 key；最终收敛到最新快照。
                for port in (9001, 9002):
                    manager.values['listen_port'] = port
                    svc.schedule_reconcile()
                manager.rotate(NEW_KEY, 2)
                svc.schedule_reconcile()
                manager.values['api_key'] = ''
                svc.schedule_reconcile()
                svc.request_stop()
                thread.join(5)
                self.assertFalse(thread.is_alive())
        finally:
            svc.close()
        self.assertLessEqual(peak['max'], 1)
        self.assertIs(svc.pool, pool)
        # 已启动的监听最终都已停止；快照未就绪后不再出现新监听。
        for site in sites:
            if site.started:
                self.assertTrue(site.stopped)

    async def test_stop_before_loop_publish_never_listens(self):
        sites = []
        manager = Manager()
        svc = self._loop_service(manager)
        setup_gate = gate()
        thread = threading.Thread(target=service._run_loop, args=(svc,), daemon=True)
        try:
            with patch.object(service, 'web', stub_web(sites, setup_gate)):
                thread.start()
                self.assertTrue(setup_gate.entered.wait(2))
                # loop 尚未发布：停止意图由 close/_closed 记住，不能丢弃。
                svc.request_stop()
                setup_gate.released.set()
                thread.join(5)
                self.assertFalse(thread.is_alive())
        finally:
            svc.close()
        self.assertEqual(sites, [])
        self.assertIsNone(svc.loop)

    def test_managed_publish_refused_after_manager_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            data_root = os.path.join(directory, 'data')
            os.makedirs(data_root)
            manager = config.ConfigManager(data_root, 'full')
            manager.refresh()  # 首次轮询生成两份模板
            control = Path(config.control_dir(data_root))
            template = json.loads((control / config.CONFIG_NAME).read_text('utf-8'))
            template['api_key'] = KEY
            (control / config.CONFIG_NAME).write_text(json.dumps(template), encoding='utf-8')
            manager.refresh()
            manager.refresh()
            self.assertTrue(manager.snapshot().ready)
            entered = threading.Event()
            released = threading.Event()
            holder = SimpleNamespace(entered=entered, released=released)

            def gated_build(svc):
                entered.set()
                released.wait(2)
                svc.app = object()
                return object()

            context = Context(self.proc, directory, data_root)
            results = []

            def apply():
                with patch.object(service, 'web', stub_web([])):
                    with patch.object(service, '_build_app', gated_build):
                        results.append(service.apply_config(context, manager))
            thread = threading.Thread(target=apply, daemon=True)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                # 发布前 manager 停止：拒绝发布并关闭已建池，不留新监听。
                manager.stop()
                released.set()
                thread.join(5)
                self.assertFalse(thread.is_alive())
            finally:
                released.set()
                service.request_stop()
            self.assertEqual(results, [True])
            self.assertIsNone(service._ACTIVE)
            self.assertFalse(service.request_stop())

    def test_stop_blocks_late_config_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            data_root = os.path.join(directory, 'data')
            os.makedirs(data_root)
            manager = config.ConfigManager(data_root, 'full')
            manager.refresh()
            manager.refresh()
            template = json.loads(
                (Path(config.control_dir(data_root)) / config.CONFIG_NAME).read_text('utf-8'))
            template['api_key'] = KEY
            (Path(config.control_dir(data_root)) / config.CONFIG_NAME).write_text(
                json.dumps(template), encoding='utf-8')
            manager.refresh()
            manager.refresh()
            self.assertTrue(manager.snapshot().ready)
            generation = manager.snapshot().generation

            entered = threading.Event()
            released = threading.Event()
            original = config._read_file
            state = {'gated': False}

            def gated_read(dir_fd, name):
                result = original(dir_fd, name)
                if not state['gated']:
                    state['gated'] = True
                    entered.set()
                    released.wait(2)
                return result

            reader = threading.Thread(target=manager.refresh, daemon=True)
            try:
                with patch.object(config, '_read_file', gated_read):
                    reader.start()
                    self.assertTrue(entered.wait(2))
                    manager.stop()
                    released.set()
                    reader.join(5)
                    self.assertFalse(reader.is_alive())
                    # stop 后的迟到轮询不能恢复授权或发布新快照。
                    manager.refresh()
                    manager.refresh()
            finally:
                released.set()
            snapshot = manager.snapshot()
            self.assertFalse(snapshot.ready)
            self.assertFalse(snapshot.valid)
            self.assertGreater(snapshot.generation, generation)


if __name__ == '__main__':
    unittest.main()
