"""HTTP/MCP 服务测试；需要 aiohttp（集成镜像内运行）。"""

import asyncio
import hashlib
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from OlivOSCockpit import config, files, protocol, service  # noqa: E402
from OlivOSCockpit.contracts import (  # noqa: E402
    CALL_TIMEOUT,
    MAX_RESPONSE,
    MODE_FULL,
    MODE_LITE,
    Context,
    Outcome,
    ToolSpec,
    object_schema,
)

try:
    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer
    from multidict import CIMultiDict
except BaseException:  # pragma: no cover - 本机无 aiohttp 时跳过
    web = None

TOKEN = 'test-token'
VALID_KEY = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8
CONTEXT = Context(None, '/unused', '/unused/data')
INIT_PARAMS = {'protocolVersion': '2025-06-18', 'capabilities': {},
               'clientInfo': {'name': 'client', 'version': '1.0'}}


def wait_until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
    return False


def http_json(port, body, extra=None, token=TOKEN):
    headers = {'Authorization': 'Bearer ' + token,
               'Content-Type': 'application/json',
               'Accept': 'application/json, text/event-stream'}
    headers.update(extra or {})
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        connection.request('POST', '/mcp', body=json.dumps(body), headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def gate_tools(entered=None, release=None):
    entered = entered if entered is not None else threading.Event()
    release = release if release is not None else threading.Event()

    def handler(ctx, args):
        entered.set()
        release.wait(5)
        return Outcome({'done': True})

    def echo(ctx, args):
        return Outcome({'echo': args.get('value', 'ok')})

    return (
        ToolSpec('gate', 'gate', object_schema(), handler),
        ToolSpec('echo', 'echo', object_schema({'value': {'type': 'string'}}), echo),
    ), entered, release


def auth(headers=None):
    merged = {'Authorization': 'Bearer ' + TOKEN}
    merged.update(headers or {})
    return merged


def legacy(method, params=None, ident=1, session=None, version=None, notification=False):
    body = {'jsonrpc': '2.0', 'method': method}
    if not notification:
        body['id'] = ident
    if params is not None:
        body['params'] = params
    headers = auth({'Content-Type': 'application/json'})
    if session:
        headers['Mcp-Session-Id'] = session
    if version:
        headers['MCP-Protocol-Version'] = version
    return body, headers


def modern(method, params=None, ident=1, version=protocol.MODERN_VERSION, tool=None):
    merged = {'_meta': {
        protocol.META_VERSION: version,
        protocol.META_CAPABILITIES: {},
        protocol.META_CLIENT: {'name': 'client', 'version': '1.0'},
    }}
    merged.update(params or {})
    headers = auth({'Content-Type': 'application/json',
                    'MCP-Protocol-Version': version, 'Mcp-Method': method})
    if tool is not None:
        merged['name'] = tool
        headers['Mcp-Name'] = tool
    return {'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': merged}, headers


class Content:
    def __init__(self, data):
        self.data = data

    async def read(self, count):
        chunk, self.data = self.data[:count], self.data[count:]
        return chunk


class FakeRequest:
    method = 'POST'

    def __init__(self, body, extra=None, content_length=None):
        self.headers = CIMultiDict(auth({'Content-Type': 'application/json'}))
        for name, value in (extra or {}).items():
            self.headers.add(name, value)
        self.content = Content(body)
        self.content_length = len(body) if content_length is None else content_length


def make_service(tools, timeout=CALL_TIMEOUT):
    return service._Service(CONTEXT, TOKEN, tools, timeout)


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tools, self.entered, self.release = gate_tools()
        self.service = make_service(self.tools)
        self.app = web.Application(handler_args={'auto_decompress': False})
        self.app.router.add_route('*', '/mcp', self.service.handle)
        self.server = TestServer(self.app)
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self):
        self.release.set()
        await self.client.close()
        self.service.pool.close()

    async def post(self, body, headers=None, path='/mcp'):
        return await self.client.post(path, data=json.dumps(body), headers=headers or auth())

    async def _wait_full(self):
        """等到 8 个 HTTP 请求都已进入 worker；不用 sleep。"""
        for _ in range(500):
            if self.service.pool.slots._value == 0:
                return
            await asyncio.sleep(0.002)
        self.fail('pool never filled')

    async def test_auth_origin_and_method_guards(self):
        body, headers = modern('tools/list')
        for bad in (None, auth({'Authorization': ''}),
                    auth({'Authorization': 'Bearer wrong'}),
                    {'Authorization': TOKEN}):
            headers_bad = dict(headers)
            headers_bad.pop('Authorization')
            headers_bad.update(bad or {})
            response = await self.post(body, headers_bad)
            self.assertEqual(response.status, 401)
        response = await self.client.post('/mcp', data=json.dumps(body),
                                          headers={**headers, 'Origin': 'http://localhost.evil'})
        self.assertEqual(response.status, 403)
        response = await self.client.get('/mcp', headers=auth())
        self.assertEqual(response.status, 405)
        self.assertEqual(response.headers['Allow'], 'POST')

    async def test_body_and_json_limits(self):
        body, headers = modern('tools/list')
        response = await self.client.post('/mcp', data=json.dumps(body),
                                          headers={**headers, 'Content-Type': 'text/plain'})
        self.assertEqual(response.status, 415)
        response = await self.client.post('/mcp', data=json.dumps(body),
                                          headers={**headers,
                                                   'Content-Encoding': 'gzip'})
        self.assertEqual(response.status, 415)
        response = await self.client.post('/mcp', data=b'[]', headers=headers)
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(await response.text())['error']['code'],
                         protocol.INVALID_REQUEST)
        response = await self.client.post('/mcp', data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                                          headers=headers)
        self.assertEqual(response.status, 400)
        response = await self.client.post('/mcp', data=b'{"a":1,"a":2}', headers=headers)
        self.assertEqual(response.status, 400)
        huge = b'{"jsonrpc":"2.0","id":1,"method":"x","pad":"' + b'a' * (1024 * 1024) + b'"}'
        response = await self.client.post('/mcp', data=huge, headers=headers)
        self.assertEqual(response.status, 413)

    async def test_modern_call_needs_no_discover(self):
        body, headers = modern('tools/call', {'arguments': {'value': 'hi'}}, tool='echo')
        response = await self.post(body, headers)
        self.assertEqual(response.status, 200)
        payload = json.loads(await response.text())
        result = payload['result']
        self.assertEqual(result['resultType'], 'complete')
        self.assertEqual(result['structuredContent'], {'echo': 'hi'})
        self.assertFalse(result['isError'])
        self.assertEqual(result['_meta'][protocol.META_SERVER]['name'], 'OlivOS-Cockpit')
        self.assertEqual(json.loads(result['content'][0]['text']), {'echo': 'hi'})
        self.assertEqual(response.headers['MCP-Protocol-Version'], protocol.MODERN_VERSION)

    async def test_echo_redacts_json_body_without_changing_request(self):
        value = json.dumps({'message': 'body ' + TOKEN, 'user_id': 42, 'password': 'echo-secret'})
        body, headers = modern('tools/call', {'arguments': {'value': value}}, tool='echo')
        response = await self.post(body, headers)
        payload = json.loads(await response.text())['result']
        data = payload['structuredContent']
        self.assertEqual(json.loads(payload['content'][0]['text']), data)
        nested = json.loads(data['echo'])
        self.assertEqual(nested['user_id'], 42)
        self.assertEqual(nested['password'], '[REDACTED]')
        self.assertEqual(nested['message'], 'body [REDACTED]')
        self.assertTrue(payload['_meta']['redacted'])
        self.assertEqual(body['params']['arguments']['value'], value)

    async def test_error_headers_are_limited_to_required_protocol_headers(self):
        body, headers = modern('tools/list')
        rejected = protocol.Reject(400, protocol.INVALID_PARAMS, 'token=echo-secret', headers=(
            ('X-Debug', TOKEN), ('Set-Cookie', TOKEN), ('WWW-Authenticate', 'Bearer'),
            ('MCP-Protocol-Version', 'bogus'), ('Connection', 'close')))
        with patch.object(self.service, '_dispatch', AsyncMock(side_effect=rejected)):
            response = await self.post(body, headers)
            payload = json.loads(await response.text())
        self.assertNotIn('X-Debug', response.headers)
        self.assertNotIn('Set-Cookie', response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'], 'Bearer')
        self.assertEqual(response.headers['MCP-Protocol-Version'], protocol.MODERN_VERSION)
        self.assertEqual(response.headers['Connection'], 'close')
        self.assertNotIn('echo-secret', json.dumps(payload))
        self.assertEqual(payload['error']['code'], protocol.INVALID_PARAMS)

    async def test_modern_discover_and_list_are_static(self):
        body, headers = modern('server/discover')
        payload = json.loads(await (await self.post(body, headers)).text())
        result = payload['result']
        self.assertEqual(result['supportedVersions'], list(protocol.SUPPORTED))
        self.assertEqual((result['ttlMs'], result['cacheScope']), (0, 'private'))
        self.assertEqual(result['resultType'], 'complete')
        body, headers = modern('tools/list')
        first = json.loads(await (await self.post(body, headers)).text())['result']
        second = json.loads(await (await self.post(body, headers)).text())['result']
        self.assertEqual([tool['name'] for tool in first['tools']],
                         [tool['name'] for tool in second['tools']])
        self.assertEqual([tool['name'] for tool in first['tools']], ['gate', 'echo'])
        self.assertEqual((first['ttlMs'], first['cacheScope']), (0, 'private'))

    async def test_modern_header_and_version_errors(self):
        body, headers = modern('tools/call', {'arguments': {}}, tool='echo')
        headers.pop('Mcp-Name')
        payload = json.loads(await (await self.post(body, headers)).text())
        self.assertEqual(payload['error']['code'], protocol.HEADER_MISMATCH)
        body, headers = modern('tools/list', version='2026-01-01')
        response = await self.post(body, headers)
        self.assertEqual(response.status, 400)
        payload = json.loads(await response.text())
        self.assertEqual(payload['error']['code'], protocol.UNSUPPORTED_VERSION)
        self.assertEqual(payload['error']['data'], {
            'supported': [protocol.MODERN_VERSION], 'requested': '2026-01-01'})

    async def test_modern_version_error_supports_schema_and_redacts_requested(self):
        secret = TOKEN + '-version'
        body, headers = modern('tools/list', version=secret)
        response = await self.post(body, headers)
        self.assertEqual(response.status, 400)
        payload = json.loads(await response.text())
        self.assertEqual(payload['error']['code'], protocol.UNSUPPORTED_VERSION)
        self.assertEqual(payload['error']['data']['supported'], [protocol.MODERN_VERSION])
        self.assertNotIn(secret.encode(), await response.read())

    async def test_generation_change_keeps_notification_202_over_http(self):
        # 真实 HTTP：代次在请求开始与响应写出之间变化，已接受通知仍 202 无 body。
        for modern_era in (False, True):
            with self.subTest(modern_era=modern_era):
                if modern_era:
                    meta = {'_meta': {
                        protocol.META_VERSION: protocol.MODERN_VERSION,
                        protocol.META_CAPABILITIES: {}}}
                    body = {'jsonrpc': '2.0', 'method': 'notifications/initialized',
                            'params': meta}
                    headers = auth({'Content-Type': 'application/json',
                                    'MCP-Protocol-Version': protocol.MODERN_VERSION,
                                    'Mcp-Method': 'notifications/initialized'})
                else:
                    # 传统通知需要有效会话：先 initialize。
                    init, init_headers = legacy('initialize', INIT_PARAMS)
                    response = await self.post(init, init_headers)
                    session = response.headers['Mcp-Session-Id']
                    body = {'jsonrpc': '2.0', 'method': 'notifications/custom'}
                    headers = auth({'Content-Type': 'application/json',
                                    'Mcp-Session-Id': session})
                original_dispatch = self.service._dispatch
                original_policy = self.service._policy
                state = {'rotated': False}

                async def dispatch(req, policy_arg):
                    reply, task = await original_dispatch(req, policy_arg)
                    state['rotated'] = True
                    return reply, task

                def policy():
                    result = original_policy()
                    if state['rotated']:
                        # 无 manager 的服务代次为 None；统一按 0 起步递增。
                        result = replace(result, generation=(result.generation or 0) + 1)
                    return result

                with patch.object(self.service, '_dispatch', dispatch), \
                        patch.object(self.service, '_policy', policy):
                    response = await self.post(body, headers)
                self.assertEqual(response.status, 202)
                self.assertEqual(await response.read(), b'')

    async def test_legacy_lifecycle(self):
        body, headers = legacy('initialize', INIT_PARAMS)
        response = await self.post(body, headers)
        self.assertEqual(response.status, 200)
        session = response.headers['Mcp-Session-Id']
        result = json.loads(await response.text())['result']
        self.assertEqual(result['protocolVersion'], '2025-06-18')
        self.assertEqual(result['capabilities'], {'tools': {}})
        self.assertIn('serverInfo', result)

        note, note_headers = legacy('notifications/initialized', session=session,
                                    notification=True)
        response = await self.post(note, note_headers)
        self.assertEqual(response.status, 202)
        self.assertEqual(await response.read(), b'')

        body, headers = legacy('tools/list', session=session)
        payload = json.loads(await (await self.post(body, headers)).text())
        self.assertEqual([tool['name'] for tool in payload['result']['tools']],
                         ['gate', 'echo'])
        self.assertNotIn('resultType', payload['result'])

        body, headers = legacy('ping', session=session, version='2025-06-18')
        self.assertEqual(json.loads(await (await self.post(body, headers)).text())['result'], {})

    async def test_legacy_errors(self):
        body, headers = legacy('initialize', {'capabilities': {}})
        self.assertEqual((await self.post(body, headers)).status, 400)
        body, headers = legacy('tools/list', session='unknown')
        response = await self.post(body, headers)
        self.assertEqual(response.status, 404)
        body, headers = legacy('tools/list', session='unknown', version='1999-01-01')
        self.assertEqual((await self.post(body, headers)).status, 404)
        body, headers = legacy('tools/list')
        self.assertEqual((await self.post(body, headers)).status, 400)
        body, headers = modern('tools/list')
        response = await self.post(body, {**headers, 'Mcp-Method': 'tools/call'})
        self.assertEqual(json.loads(await response.text())['error']['code'],
                         protocol.HEADER_MISMATCH)

    async def test_unknown_tool_and_invalid_arguments_stay_200(self):
        body, headers = modern('tools/call', {'arguments': {}}, tool='nope')
        response = await self.post(body, headers)
        self.assertEqual(response.status, 400)
        body, headers = modern('tools/call', {'arguments': {'bogus': 1}}, tool='echo')
        payload = json.loads(await (await self.post(body, headers)).text())
        self.assertTrue(payload['result']['isError'])

    async def test_oversized_result_is_structured_truncation(self):
        def huge(ctx, args):
            return Outcome({'x': 'a' * (1024 * 1024)})

        tools = (ToolSpec('huge', 'huge', object_schema(), huge),)
        self.service.tools = tools
        self.service.by_name = {tool.name: tool for tool in tools}
        body, headers = modern('tools/call', {'arguments': {}}, tool='huge')
        response = await self.post(body, headers)
        payload = json.loads(await response.text())
        result = payload['result']
        self.assertTrue(result['isError'])
        self.assertTrue(result['structuredContent']['truncated'])
        self.assertEqual(json.loads(result['content'][0]['text']), result['structuredContent'])

    async def test_eight_slots_then_503(self):
        body, headers = modern('tools/call', {'arguments': {}}, tool='gate')
        pending = [asyncio.create_task(self.post(body, headers)) for _ in range(8)]
        await asyncio.to_thread(self.entered.wait, 2)
        response = await self.post(body, headers)
        self.assertEqual(response.status, 503)
        self.release.set()
        responses = await asyncio.gather(*pending)
        self.assertEqual({item.status for item in responses}, {200})
        self.assertEqual(self.entered.is_set(), True)

    async def test_timeout_releases_response_but_keeps_slot(self):
        self.service.timeout = 0.05
        fired = threading.Event()
        finished = threading.Event()

        def gated(ctx, args):
            self.entered.set()
            self.release.wait(5)
            finished.set()
            return Outcome({'late': True}, after_send=fired.set)

        tools = (ToolSpec('gate', 'gate', object_schema(), gated),)
        self.service.tools = tools
        self.service.by_name = {'gate': tools[0]}
        body, headers = modern('tools/call', {'arguments': {}}, tool='gate')
        pending = [asyncio.create_task(self.post(body, headers)) for _ in range(8)]
        await self._wait_full()
        response = await self.post(body, headers)
        self.assertEqual(response.status, 503)
        responses = await asyncio.gather(*pending)
        for item in responses:
            payload = json.loads(await item.text())
            self.assertTrue(payload['result']['isError'])
        self.release.set()
        await asyncio.to_thread(finished.wait, 2)
        await asyncio.sleep(0.05)
        self.assertFalse(fired.is_set())  # 超时后的迟到结果不执行 after_send

    async def test_slot_frees_after_handler_returns(self):
        self.service.timeout = 0.05
        body, headers = modern('tools/call', {'arguments': {}}, tool='gate')
        response = await self.post(body, headers)
        self.assertTrue(json.loads(await response.text())['result']['isError'])
        self.release.set()
        body, headers = modern('tools/call', {'arguments': {'value': 'x'}}, tool='echo')
        for _ in range(100):
            response = await self.post(body, headers)
            if response.status == 200:
                break
            await asyncio.sleep(0.01)
        self.assertFalse(json.loads(await response.text())['result']['isError'])


def modern_request(tool='echo'):
    body, _headers = modern('tools/call', {'arguments': {'value': 'x'}}, tool=tool)
    return FakeRequest(json.dumps(body).encode(), {
        'MCP-Protocol-Version': protocol.MODERN_VERSION,
        'Mcp-Method': 'tools/call', 'Mcp-Name': tool,
    })


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class HttpLimitTests(unittest.IsolatedAsyncioTestCase):
    def make(self, *tools, timeout=CALL_TIMEOUT):
        return make_service(tools, timeout=timeout)

    async def test_full_http_slots_answer_503_without_queueing(self):
        entered = threading.Event()

        def handler(ctx, args):
            entered.set()
            return Outcome({'ok': True})

        svc = self.make(ToolSpec('echo', 'echo', object_schema(), handler))
        replies = []

        async def write(_request, reply):
            replies.append(reply)
            return 'sent'

        try:
            for _ in range(8):
                self.assertTrue(svc.http_slots.acquire(blocking=False))
            with patch.object(svc, '_write', write):
                await svc.handle(modern_request())
            self.assertEqual(replies[0].status, 503)
            self.assertIn(('Connection', 'close'), replies[0].headers)
            # 名额满时立即返回，不排入任务队列，也不补开线程。
            self.assertFalse(entered.is_set())
            self.assertTrue(svc.pool.tasks.empty())
        finally:
            for _ in range(8):
                svc.http_slots.release()
            svc.pool.close()

    async def test_body_timeout_returns_408(self):
        class Slow:
            async def read(self, count):
                await asyncio.sleep(5)
                return b''

        svc = self.make(ToolSpec('echo', 'echo', object_schema(),
                                 lambda ctx, args: Outcome({})), timeout=0.01)
        request = modern_request()
        request.content = Slow()
        request.content_length = 100
        replies = []

        async def write(_request, reply):
            replies.append(reply)
            return 'sent'

        try:
            with patch.object(svc, '_write', write):
                await svc.handle(request)
            self.assertEqual(replies[0].status, 408)
            self.assertEqual(json.loads(replies[0].body)['error']['code'],
                             protocol.INVALID_REQUEST)
            self.assertIn(('Connection', 'close'), replies[0].headers)
        finally:
            svc.pool.close()

    async def test_http_cancel_only_stops_waiting_and_keeps_slot(self):
        entered = threading.Event()
        finished = threading.Event()
        release = threading.Event()

        def handler(ctx, args):
            entered.set()
            try:
                release.wait(5)
            finally:
                finished.set()
            return Outcome({'late': True})

        svc = self.make(ToolSpec('gate', 'gate', object_schema({'value': {'type': 'string'}}), handler))
        try:
            with patch.object(svc, '_write', AsyncMock(return_value='response')):
                task = asyncio.create_task(svc.handle(modern_request('gate')))
                await asyncio.to_thread(entered.wait, 2)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertEqual(svc.pool.slots._value, 7)  # 未结束的调用仍占名额
                release.set()
                await asyncio.to_thread(finished.wait, 2)
                for _ in range(200):
                    if svc.pool.slots._value == 8:
                        break
                    await asyncio.sleep(0.005)
                self.assertEqual(svc.pool.slots._value, 8)
        finally:
            release.set()
            svc.pool.close()

    async def test_worker_cancellation_propagates_and_worker_survives(self):
        def cancelled(ctx, args):
            raise asyncio.CancelledError()

        schema = object_schema({'value': {'type': 'string'}})
        tools = (ToolSpec('cancel', 'cancel', schema, cancelled),
                 ToolSpec('echo', 'echo', schema,
                          lambda ctx, args: Outcome({'ok': True})))
        svc = self.make(*tools)
        sent = AsyncMock(return_value='response')
        try:
            with patch.object(svc, '_write', sent):
                with self.assertRaises(asyncio.CancelledError):
                    await svc.handle(modern_request('cancel'))
            # worker 未退出，名额由 finally 归还。
            for _ in range(200):
                if svc.pool.slots._value == 8:
                    break
                await asyncio.sleep(0.005)
            self.assertEqual(svc.pool.slots._value, 8)
            with patch.object(svc, '_write', sent):
                self.assertEqual(await svc.handle(modern_request('echo')), 'response')
        finally:
            svc.pool.close()


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class SessionTests(unittest.TestCase):
    def test_ttl_and_eviction(self):
        sessions = service._Sessions()
        clock = [1000.0]
        with patch.object(service, 'monotonic', lambda: clock[0]):
            with patch.object(service, 'SESSION_TTL', 10):
                session = sessions.create('2025-06-18')
                self.assertTrue(sessions.valid(session))
                self.assertEqual(sessions.version(session), '2025-06-18')
                clock[0] += 11
                self.assertFalse(sessions.valid(session))
            with patch.object(service, 'MAX_SESSIONS', 2):
                first = sessions.create()
                second = sessions.create()
                third = sessions.create()
                self.assertFalse(sessions.valid(first))
                self.assertTrue(sessions.valid(second) and sessions.valid(third))

    def test_legacy_session_version_negotiated(self):
        sessions = service._Sessions()
        session = sessions.create('2025-03-26')
        self.assertEqual(sessions.version(session), '2025-03-26')


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class DeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_after_send_runs_only_after_write(self):
        fired = threading.Event()

        def handler(ctx, args):
            return Outcome({'ok': True}, after_send=fired.set)

        tool = ToolSpec('reload', 'reload', object_schema(), handler)
        svc = make_service((tool,))
        body, headers = modern('tools/call', {'arguments': {}}, tool='reload')
        request = FakeRequest(json.dumps(body).encode(),
                              {'MCP-Protocol-Version': protocol.MODERN_VERSION,
                               'Mcp-Method': 'tools/call',
                               'Mcp-Name': 'reload'})
        sent = AsyncMock(return_value='response')
        with patch.object(service._Service, '_write', sent):
            self.assertEqual(await svc.handle(request), 'response')
        await asyncio.to_thread(fired.wait, 2)
        self.assertTrue(fired.is_set())
        svc.pool.close()

    async def test_oversized_result_does_not_execute_after_send(self):
        fired = threading.Event()
        tool = ToolSpec(
            'reload', 'reload', object_schema(),
            lambda ctx, args: Outcome({'payload': 'x' * (1024 * 1024)}, after_send=fired.set),
        )
        svc = make_service((tool,))
        body, headers = modern('tools/call', {'arguments': {}}, tool='reload')
        request = FakeRequest(json.dumps(body).encode(), {
            'MCP-Protocol-Version': protocol.MODERN_VERSION,
            'Mcp-Method': 'tools/call', 'Mcp-Name': 'reload',
        })
        replies = []

        async def write(_request, reply):
            replies.append(reply)
            return 'response'

        try:
            with patch.object(svc, '_write', write):
                await svc.handle(request)
            for _ in range(100):
                if svc.pool.slots._value == 8:
                    break
                await asyncio.sleep(0.001)
            self.assertEqual(svc.pool.slots._value, 8)
            result = json.loads(replies[0].body)['result']
            self.assertTrue(result['isError'])
            self.assertTrue(result['structuredContent']['truncated'])
            self.assertFalse(fired.is_set())
        finally:
            svc.pool.close()

    async def test_socket_failure_aborts_after_send(self):
        fired = threading.Event()

        def handler(ctx, args):
            return Outcome({'ok': True}, after_send=fired.set)

        tool = ToolSpec('reload', 'reload', object_schema(), handler)
        svc = make_service((tool,))
        body, headers = modern('tools/call', {'arguments': {}}, tool='reload')
        request = FakeRequest(json.dumps(body).encode(),
                              {'MCP-Protocol-Version': protocol.MODERN_VERSION,
                               'Mcp-Method': 'tools/call',
                               'Mcp-Name': 'reload'})
        with patch.object(service._Service, '_write', AsyncMock(side_effect=ConnectionResetError)):
            self.assertIsNone(await svc.handle(request))
        self.assertFalse(fired.is_set())
        svc.pool.close()

    async def test_cancellation_propagates_and_frees_slot(self):
        entered = threading.Event()
        release = threading.Event()
        fired = threading.Event()

        def handler(ctx, args):
            entered.set()
            release.wait(5)
            return Outcome({'ok': True}, after_send=fired.set)

        tool = ToolSpec('reload', 'reload', object_schema(), handler)
        svc = make_service((tool,))
        body, headers = modern('tools/call', {'arguments': {}}, tool='reload')
        request = FakeRequest(json.dumps(body).encode(),
                              {'MCP-Protocol-Version': protocol.MODERN_VERSION,
                               'Mcp-Method': 'tools/call',
                               'Mcp-Name': 'reload'})
        with patch.object(service._Service, '_write', AsyncMock(return_value='response')):
            task = asyncio.create_task(svc.handle(request))
            await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            release.set()
            await asyncio.to_thread(entered.wait, 2)
        self.assertFalse(fired.is_set())
        svc.pool.close()


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class DataPaginationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cockpit-http-data-')
        self.root = Path(os.path.realpath(self.temp.name))
        self.data_root = self.root / 'plugin' / 'data'
        self.namespace = self.data_root / 'Demo'
        self.namespace.mkdir(parents=True)
        self.client = None
        self.service = None

    async def asyncTearDown(self):
        if self.client is not None:
            await self.client.close()
        if self.service is not None:
            self.service.pool.close()
        self.temp.cleanup()

    async def start(self, mode=MODE_FULL, modern_era=True):
        if self.client is not None:
            await self.client.close()
        if self.service is not None:
            self.service.pool.close()
        self.snapshot = config.Snapshot(api_key=TOKEN, valid=True, generation=1,
                                        lite_real_account_read=True)
        manager = SimpleNamespace(snapshot=lambda: self.snapshot)
        self.proc = SimpleNamespace(Proc_data={'bot_info_dict': {}})
        context = Context(self.proc, str(self.root), str(self.data_root),
                          config=manager, permission_mode=mode)
        self.service = service._Service(context, None, files.TOOLS, CALL_TIMEOUT, manager)
        app = web.Application(handler_args={'auto_decompress': False})
        app.router.add_route('*', '/mcp', self.service.handle)
        self.client = TestClient(TestServer(app))
        await self.client.start_server()
        self.modern_era = modern_era
        self.session = None
        if not modern_era:
            body, headers = legacy('initialize', INIT_PARAMS)
            response = await self.client.post('/mcp', data=json.dumps(body), headers=headers)
            self.assertEqual(response.status, 200)
            self.session = response.headers['Mcp-Session-Id']
            await response.read()
            body, headers = legacy('notifications/initialized', session=self.session, notification=True)
            response = await self.client.post('/mcp', data=json.dumps(body), headers=headers)
            self.assertEqual(response.status, 202)
            await response.read()

    async def read(self, path, cursor=None):
        args = {'namespace': 'Demo', 'mode': 'read', 'path': path}
        if cursor is not None:
            args['cursor'] = cursor
        if self.modern_era:
            body, headers = modern('tools/call', {'arguments': args}, tool='cockpit_data')
        else:
            body, headers = legacy('tools/call', {'name': 'cockpit_data', 'arguments': args},
                                   session=self.session)
        response = await self.client.post('/mcp', data=json.dumps(body), headers=headers)
        self.assertEqual(response.status, 200)
        wire = await response.read()
        self.assertLessEqual(len(wire), MAX_RESPONSE)
        payload = json.loads(wire)
        self.assertEqual(payload['id'], body['id'])
        result = payload['result']
        if self.modern_era:
            self.assertEqual(result['resultType'], 'complete')
        self.assertEqual(json.loads(result['content'][0]['text']), result['structuredContent'])
        return result, wire

    async def collect(self, path, forbidden=()):
        chunks = []
        seen = set()
        cursor = None
        for _ in range(256):
            result, wire = await self.read(path, cursor)
            self.assertFalse(result['isError'], result['structuredContent'])
            for secret in forbidden:
                self.assertNotIn(secret.encode(), wire)
            data = result['structuredContent']
            if cursor or data.get('next_cursor'):
                self.assertTrue(data.get('paged'))
                self.assertNotIn('sha256', data)
            chunks.append(data['content'])
            cursor = data.get('next_cursor')
            if not cursor:
                return ''.join(chunks), len(chunks)
            self.assertNotIn(cursor, seen, 'continuation cursor did not advance')
            seen.add(cursor)
        self.fail('file pagination did not finish within the bounded test loop')

    async def test_pending_context_beyond_source_window_never_leaks(self):
        await self.start()
        for index, (prefix, tail, secret) in enumerate((
            ('"access_token"', ':"field-window-secret"', 'field-window-secret'),
            ('Bearer', 'auth-window-secret', 'auth-window-secret'),
        )):
            path = self.namespace / ('pending-%d.txt' % index)
            source = 'record\n' * 100 + prefix + '\n' * (1024 * 1024) + tail + '\n'
            path.write_text(source, encoding='utf-8')
            cursor = None
            chunks = []
            for _ in range(16):
                result, wire = await self.read(path.name, cursor)
                self.assertNotIn(secret.encode(), wire)
                data = result['structuredContent']
                if result['isError']:
                    self.assertNotIn('next_cursor', data)
                    break
                chunks.append(data['content'])
                cursor = data.get('next_cursor')
                if not cursor:
                    self.assertIn('[REDACTED]', ''.join(chunks))
                    break
            else:
                self.fail('unsafe context did not stop or complete within the bounded loop')

    async def test_cleaner_failure_never_returns_raw_file_or_cursor(self):
        original = 'unlabelled-sensitive-value ' * 25000
        path = self.namespace / 'failure.txt'
        path.write_text(original, encoding='utf-8')
        await self.start()
        with patch.object(protocol.redaction.Cleaner, 'text',
                          side_effect=MemoryError('RAW-SHOULD-NOT-BE-SENT')):
            result, wire = await self.read(path.name)
        self.assertTrue(result['isError'])
        self.assertNotIn(b'unlabelled-sensitive-value', wire)
        self.assertNotIn(b'RAW-SHOULD-NOT-BE-SENT', wire)
        self.assertNotIn('next_cursor', result['structuredContent'])
        text, count = await self.collect(path.name)
        self.assertGreater(count, 1)
        self.assertEqual(text, original)

    async def test_small_read_keeps_complete_read_revision(self):
        original = b'{"enabled":true}'
        path = self.namespace / 'small.json'
        path.write_bytes(original)
        await self.start()
        result, _ = await self.read(path.name)
        self.assertFalse(result['isError'], result['structuredContent'])
        data = result['structuredContent']
        self.assertEqual(data['content'], original.decode())
        self.assertEqual(data['sha256'], hashlib.sha256(original).hexdigest())
        self.assertFalse(data.get('next_cursor'))
        self.assertFalse(data.get('paged', False))

    async def test_clean_json_view_continues_in_both_profiles_and_eras(self):
        source = {'body': '界' * 100000, 'access_token': 'field-only-secret'}
        path = self.namespace / 'large.json'
        original = json.dumps(source, ensure_ascii=False).encode()
        path.write_bytes(original)
        for mode in (MODE_FULL, MODE_LITE):
            for modern_era in (False, True):
                with self.subTest(mode=mode, modern=modern_era):
                    await self.start(mode, modern_era)
                    text, count = await self.collect(path.name, ('field-only-secret',))
                    self.assertGreater(count, 1)
                    self.assertEqual(json.loads(text), {'body': source['body'], 'access_token': '[REDACTED]'})
                    self.assertEqual(path.read_bytes(), original)

    async def test_cursor_survives_field_rules_but_not_credential_rotation(self):
        source = {'body': 'x' * 600000, 'next_cursor': 'file-value-must-be-redacted'}
        path = self.namespace / 'short.json'
        path.write_text(json.dumps(source), encoding='utf-8')
        await self.start()
        self.snapshot = replace(self.snapshot, redact_fields=('next_cursor', 'size', 'file_size'), generation=2)
        bot = SimpleNamespace(password='a')
        self.proc.Proc_data['bot_info_dict']['synthetic'] = bot
        first, _ = await self.read(path.name)
        self.assertFalse(first['isError'], first['structuredContent'])
        cursor = first['structuredContent']['next_cursor']
        self.assertEqual(first['structuredContent']['size'], '[REDACTED]')
        self.assertEqual(first['structuredContent']['file_size'], '[REDACTED]')
        second, _ = await self.read(path.name, cursor)
        self.assertFalse(second['isError'], second['structuredContent'])
        bot.password = 'b'
        rejected, _ = await self.read(path.name, cursor)
        self.assertTrue(rejected['isError'])
        text, count = await self.collect(path.name, ('file-value-must-be-redacted',))
        self.assertGreater(count, 1)
        self.assertEqual(json.loads(text), {'body': source['body'], 'next_cursor': '[REDACTED]'})

    async def test_file_larger_than_read_budget_is_complete_over_http(self):
        original = ('row ' + '界' * 10000 + '\n') * 36
        path = self.namespace / 'large.txt'
        path.write_text(original, encoding='utf-8', newline='')
        self.assertGreater(path.stat().st_size, 1024 * 1024)
        await self.start()
        text, count = await self.collect(path.name)
        self.assertGreater(count, 1)
        self.assertEqual(text, original)

    async def test_cursor_replay_tampering_revision_and_revocation(self):
        path = self.namespace / 'pages.txt'
        path.write_text('x' * 600000, encoding='utf-8')
        await self.start(MODE_LITE)
        first, _ = await self.read(path.name)
        self.assertFalse(first['isError'], first['structuredContent'])
        cursor = first['structuredContent']['next_cursor']
        replay, _ = await self.read(path.name, cursor)
        repeated, _ = await self.read(path.name, cursor)
        self.assertFalse(replay['isError'], replay['structuredContent'])
        self.assertEqual(replay['structuredContent']['content'], repeated['structuredContent']['content'])
        middle = len(cursor) // 2
        forged = cursor[:middle] + ('A' if cursor[middle] != 'A' else 'B') + cursor[middle + 1:]
        rejected, _ = await self.read(path.name, forged)
        self.assertTrue(rejected['isError'])
        other = self.namespace / 'other.txt'
        other.write_bytes(path.read_bytes())
        rejected, _ = await self.read(other.name, cursor)
        self.assertTrue(rejected['isError'])
        self.snapshot = replace(self.snapshot, lite_real_account_read=False, generation=2)
        rejected, _ = await self.read(path.name, cursor)
        self.assertTrue(rejected['isError'])
        self.snapshot = replace(self.snapshot, lite_real_account_read=True, generation=3)
        rejected, _ = await self.read(path.name, cursor)
        self.assertTrue(rejected['isError'])
        fresh, _ = await self.read(path.name)
        self.assertFalse(fresh['isError'], fresh['structuredContent'])
        cursor = fresh['structuredContent']['next_cursor']
        before = path.stat()
        with path.open('r+b') as stream:
            stream.write(b'y')
            stream.flush()
            os.fsync(stream.fileno())
        after = path.stat()
        self.assertEqual((before.st_ino, before.st_size), (after.st_ino, after.st_size))
        rejected, _ = await self.read(path.name, cursor)
        self.assertTrue(rejected['isError'])


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class ManagedPortFallbackTests(unittest.TestCase):
    """真实监听：配置端口被占用→有界回退→写回配置→两时代 HTTP 可用。"""

    def test_occupied_port_falls_back_persists_and_serves_both_eras(self):
        temp = tempfile.TemporaryDirectory(prefix='cockpit-managed-')
        self.addCleanup(temp.cleanup)
        root = os.path.realpath(temp.name)
        data_root = os.path.join(root, 'data')
        os.makedirs(data_root)

        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupied.bind(('127.0.0.1', 0))
        occupied.listen()
        self.addCleanup(occupied.close)
        configured = occupied.getsockname()[1]

        manager = config.ConfigManager(data_root, MODE_FULL)
        self.addCleanup(manager.stop)
        manager.refresh()
        manager.refresh()
        control = Path(config.control_dir(data_root))
        path = control / config.CONFIG_NAME
        source = json.loads(path.read_text('utf-8'))
        source.pop('denied_paths', None)  # 缺失的可选字段写回后仍缺失
        source.update(listen_port=configured, api_key=VALID_KEY)
        path.write_text(json.dumps(source), encoding='utf-8')
        manager.refresh()
        manager.refresh()
        self.assertTrue(manager.snapshot().ready)

        service.request_stop()
        self.assertTrue(wait_until(service.can_start, 5))

        class Proc:
            def __init__(self):
                self.messages = []

            def log(self, level, message):
                self.messages.append(message)

        proc = Proc()
        context = Context(proc, root, data_root)
        tool = ToolSpec('echo', 'echo', object_schema({'value': {'type': 'string'}}),
                        lambda ctx, args: Outcome({'echo': args.get('value', 'ok')}))
        manager.set_notify(lambda snapshot: service.apply_config(
            context, manager, snapshot, tools=(tool,)))
        errors = []

        def run_service():
            try:
                service.start_managed(context, manager, (tool,))
            except BaseException as exc:  # 线程顶层：交给断言报告
                errors.append(exc)

        manager_thread = threading.Thread(target=manager.run_forever, daemon=True)
        service_thread = threading.Thread(target=run_service, daemon=True)
        with patch.object(config, 'POLL_INTERVAL', 0.02):
            manager_thread.start()
            service_thread.start()
            try:
                def current_port():
                    try:
                        return json.loads(path.read_text('utf-8'))['listen_port']
                    except (OSError, ValueError, KeyError):
                        return None

                self.assertTrue(wait_until(
                    lambda: current_port() not in (None, configured), 10))
                actual = current_port()
                self.assertNotEqual(actual, configured)
                self.assertGreaterEqual(actual, service.FALLBACK_MIN_PORT)
                init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                        'params': dict(INIT_PARAMS)}
                self.assertTrue(wait_until(
                    lambda: http_json(actual, init, token=VALID_KEY)[0] == 200, 10))
                # 确认可服务后只记录一次实际端点；被占用的配置端口不得误报。
                self.assertEqual(
                    [message for message in proc.messages
                     if 'Service listening on' in message],
                    ['[OlivOSCockpit] Service listening on 127.0.0.1:%d.' % actual])

                status, headers, _raw = http_json(actual, init, token=VALID_KEY)
                self.assertEqual(status, 200)
                session = headers.get('Mcp-Session-Id')
                self.assertIsNotNone(session)

                legacy_list = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}
                status, _, raw = http_json(actual, legacy_list,
                                           {'Mcp-Session-Id': session},
                                           token=VALID_KEY)
                self.assertEqual(status, 200)
                self.assertEqual([item['name'] for item in
                                  json.loads(raw)['result']['tools']], ['echo'])

                modern_list = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list',
                               'params': {'_meta': {
                                   protocol.META_VERSION: protocol.MODERN_VERSION,
                                   protocol.META_CAPABILITIES: {}}}}
                status, _, raw = http_json(actual, modern_list, {
                    'MCP-Protocol-Version': protocol.MODERN_VERSION,
                    'Mcp-Method': 'tools/list'}, token=VALID_KEY)
                self.assertEqual(status, 200)
                self.assertEqual([item['name'] for item in
                                  json.loads(raw)['result']['tools']], ['echo'])

                written = json.loads(path.read_text('utf-8'))
                expected = dict(source)
                expected['listen_port'] = actual
                self.assertEqual(written, expected)
                self.assertNotIn('denied_paths', written)
                published = manager.snapshot()
                self.assertTrue(published.ready)
                self.assertEqual(published.listen_port, actual)
                # 被占用的端口仍由测试监听器持有，没有被探测/释放/复用。
                self.assertEqual(occupied.getsockname()[1], configured)
            finally:
                service.request_stop()
                manager.stop()
                service_thread.join(10)
                manager_thread.join(10)
                self.assertTrue(wait_until(service.can_start, 5))
        self.assertEqual(errors, [])
        self.assertFalse(service_thread.is_alive())
        self.assertFalse(manager_thread.is_alive())


@unittest.skipUnless(web is not None, 'aiohttp unavailable')
class LocalhostFamilyTests(unittest.IsolatedAsyncioTestCase):
    """localhost 正端口必须让 IPv4/IPv6 监听在同一个端口。"""

    @staticmethod
    def free_dual_family_port():
        for _ in range(200):
            v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                v4.bind(('127.0.0.1', 0))
                port = v4.getsockname()[1]
                if port < 1024:
                    continue
                v6.bind(('::1', port))
                return port
            except OSError:
                continue
            finally:
                v4.close()
                v6.close()
        return None

    async def test_localhost_binds_both_families_on_one_positive_port(self):
        families = {info[0] for info in socket.getaddrinfo(
            'localhost', 0, type=socket.SOCK_STREAM)}
        if socket.AF_INET not in families or socket.AF_INET6 not in families:
            self.skipTest('localhost has no dual-family loopback')
        port = self.free_dual_family_port()
        if port is None:
            self.skipTest('no dual-family loopback port available')

        manager = SimpleNamespace(
            snapshot=lambda: SimpleNamespace(
                valid=True, ready=True, api_key=TOKEN, listen_host='localhost',
                listen_port=port, fingerprint='fingerprint', redaction_enabled=True),
            allowed=lambda permission=None: True)
        tool = ToolSpec('echo', 'echo', object_schema(),
                        lambda ctx, args: Outcome({}))
        svc = service._Service(CONTEXT, None, (tool,), CALL_TIMEOUT, manager)
        service._build_app(svc)
        runner = web.AppRunner(svc.app, handle_signals=False)
        svc.runner = runner
        try:
            await runner.setup()
            await svc._reconcile()
            self.assertIsNotNone(svc.site)
            addresses = runner.addresses
            self.assertEqual({address[1] for address in addresses}, {port})
            bound = set()
            for address in addresses:
                bound.add(socket.AF_INET6 if ':' in address[0] else socket.AF_INET)
            self.assertIn(socket.AF_INET, bound)
            self.assertIn(socket.AF_INET6, bound)
            for host in ('127.0.0.1', '::1'):
                reader, writer = await asyncio.open_connection(host, port)
                writer.close()
                await writer.wait_closed()
                del reader
        finally:
            await svc._stop_site()
            await runner.cleanup()
            svc.close()


if __name__ == '__main__':
    unittest.main()
