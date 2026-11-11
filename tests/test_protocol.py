"""protocol 纯值层测试；不依赖 aiohttp。"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from OlivOSCockpit import files, protocol, redaction  # noqa: E402
from OlivOSCockpit.contracts import Outcome, ToolSpec, object_schema  # noqa: E402

MODERN = protocol.MODERN_VERSION
META = {
    protocol.META_VERSION: MODERN,
    protocol.META_CAPABILITIES: {},
    protocol.META_CLIENT: {'name': 'client', 'version': '1.0'},
}
MODERN_HEADERS = {'MCP-Protocol-Version': MODERN, 'Mcp-Method': 'tools/list'}
INIT_PARAMS = {'protocolVersion': '2025-06-18', 'capabilities': {},
               'clientInfo': {'name': 'client', 'version': '1.0'}}


def message(method='tools/list', params=None, ident=1, **extra):
    body = {'jsonrpc': '2.0', 'method': method}
    if ident is not None:
        body['id'] = ident
    if params is not None:
        body['params'] = params
    body.update(extra)
    return body


def modern(method='tools/list', params=None, ident=1, name=None):
    meta = dict(META)
    merged = dict(params or {})
    merged['_meta'] = meta
    body = message(method, merged, ident)
    headers = {'MCP-Protocol-Version': MODERN, 'Mcp-Method': method}
    if name is not None:
        body['params']['name'] = name
        headers['Mcp-Name'] = name
    return body, headers


class StrictJsonTests(unittest.TestCase):
    def test_accepts_single_object(self):
        self.assertEqual(protocol.loads(b'{"jsonrpc":"2.0"}'), {'jsonrpc': '2.0'})

    def test_rejects_everything_non_object_or_nonstandard(self):
        cases = [
            b'[]', b'[{}]', b'null', b'"x"',
            b'{"a":1,"a":2}',
            b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":1e999}',
            b'{"a":"\xff"}', b'', b'{',
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(protocol.Reject) as caught:
                protocol.loads(raw)
            self.assertEqual(caught.exception.status, 400)


    def test_deep_nesting_rejected_before_decode(self):
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(100000)
        try:
            with self.assertRaises(protocol.Reject) as caught:
                protocol.loads(('{"a":' * 40 + '1' + '}' * 40).encode())
            self.assertEqual(caught.exception.code, protocol.PARSE_ERROR)
        finally:
            sys.setrecursionlimit(old)


class ClassifyTests(unittest.TestCase):
    def test_modern_direct_call_needs_no_initialize(self):
        req = protocol.classify(*modern('tools/call', {'arguments': {}}, name='cockpit_status'))
        self.assertTrue(req.modern)
        self.assertIsNone(req.session)

    def test_modern_meta_presence_beats_unknown_session(self):
        body, headers = modern()
        headers['Mcp-Session-Id'] = 'unknown'
        self.assertTrue(protocol.classify(body, headers).modern)

    def test_modern_missing_required_meta_is_params_error(self):
        body, headers = modern()
        del body['params']['_meta'][protocol.META_CAPABILITIES]
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, headers)
        self.assertEqual(caught.exception.code, protocol.INVALID_PARAMS)

    def test_only_version_meta_key_selects_modern_era(self):
        meta = {protocol.META_CAPABILITIES: {}, 'io.modelcontextprotocol/custom': True}
        body = message('tools/list', {'_meta': meta})
        req = protocol.classify(body, {'Mcp-Session-Id': 'legacy-session'})
        self.assertFalse(req.modern)
        self.assertEqual(req.session, 'legacy-session')
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, MODERN_HEADERS)
        self.assertEqual(caught.exception.code, protocol.INVALID_REQUEST)

    def test_modern_headers_before_version_support(self):
        meta = dict(META, **{protocol.META_VERSION: '2027-01-01'})
        body = message('tools/list', {'_meta': meta})
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, {'MCP-Protocol-Version': '2027-01-01'})
        self.assertEqual(caught.exception.code, protocol.HEADER_MISMATCH)

        headers = {'MCP-Protocol-Version': '2027-01-01', 'Mcp-Method': 'tools/list'}
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, headers)
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(caught.exception.code, protocol.UNSUPPORTED_VERSION)
        self.assertEqual(caught.exception.data['supported'], [MODERN])
        self.assertEqual(caught.exception.data['requested'], '2027-01-01')

    def test_modern_method_and_tool_name_headers(self):
        body, headers = modern('tools/call', {'arguments': {}}, name='cockpit status')
        headers['Mcp-Name'] = 'cockpit%20status'
        protocol.classify(body, headers)  # 规范要求 URL decode 后比较。

        headers['Mcp-Name'] = 'cockpit_status'
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, headers)
        self.assertEqual(caught.exception.code, protocol.HEADER_MISMATCH)

    def test_modern_rejects_legacy_version_in_envelope(self):
        body, headers = modern()
        body['params']['_meta'][protocol.META_VERSION] = '2025-11-25'
        headers['MCP-Protocol-Version'] = '2025-11-25'
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, headers)
        self.assertEqual(caught.exception.code, protocol.UNSUPPORTED_VERSION)
        self.assertEqual(caught.exception.data['supported'], [MODERN])

    def test_initialize_negotiation_and_validation(self):
        req = protocol.classify(message('initialize', INIT_PARAMS), {})
        self.assertEqual((req.version, req.modern), ('2025-06-18', False))
        fallback = dict(INIT_PARAMS, protocolVersion='1999-01-01')
        self.assertEqual(protocol.classify(message('initialize', fallback), {}).version,
                         protocol.DEFAULT_LEGACY)
        for params in (None, {}, {'protocolVersion': '2025-11-25'},
                       dict(INIT_PARAMS, clientInfo={})):
            with self.subTest(params=params), self.assertRaises(protocol.Reject) as caught:
                protocol.classify(message('initialize', params), {})
            self.assertEqual(caught.exception.code, protocol.INVALID_PARAMS)

    def test_initialize_version_header_must_match(self):
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(message('initialize', INIT_PARAMS),
                              {'MCP-Protocol-Version': '2025-03-26'})
        self.assertEqual(caught.exception.status, 400)
        with self.assertRaises(protocol.Reject):
            protocol.classify(message('initialize', INIT_PARAMS),
                              {'MCP-Protocol-Version': '2027-01-01'})

    def test_initialize_requires_id(self):
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(message('initialize', INIT_PARAMS, ident=None), {})
        self.assertEqual(caught.exception.code, protocol.INVALID_REQUEST)

    def test_legacy_session_and_no_era(self):
        req = protocol.classify(message('tools/list'), {'Mcp-Session-Id': 's'})
        self.assertEqual(req.session, 's')
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(message('tools/list'), {})
        self.assertEqual(caught.exception.status, 400)

    def test_envelope_rules(self):
        for ident in (True, 1.5, [], {}):
            with self.subTest(ident=ident), self.assertRaises(protocol.Reject):
                protocol.classify({'jsonrpc': '2.0', 'id': ident, 'method': 'ping'}, {})
        with self.assertRaises(protocol.Reject):
            protocol.classify({'method': 'ping'}, {})
        with self.assertRaises(protocol.Reject):
            protocol.classify({'jsonrpc': '1.0', 'id': 1, 'method': 'ping'}, {})
        notification = protocol.classify(
            {'jsonrpc': '2.0', 'method': 'ping'}, {'Mcp-Session-Id': 's'})
        self.assertTrue(notification.notification)


class TransportValueTests(unittest.TestCase):
    def test_origin(self):
        for good in (None, 'http://127.0.0.1', 'https://127.0.0.1:8767',
                     'http://localhost:8767', 'http://[::1]:8767', 'HTTP://LOCALHOST'):
            protocol.check_origin(good)
        for bad in ('null', 'http://localhost.evil', 'http://evil/localhost',
                    'http://127.0.0.1.evil:1', 'ftp://127.0.0.1', 'http://127.0.0.1:0',
                    'http://127.0.0.1:99999', 'http://user@127.0.0.1'):
            with self.subTest(bad=bad), self.assertRaises(protocol.Reject) as caught:
                protocol.check_origin(bad)
            self.assertEqual(caught.exception.status, 403)

    def test_origin_trusted_hosts_are_opt_in_and_exact(self):
        for good in ('https://bot.example:8767', 'http://bot.example'):
            protocol.check_origin(good, hosts=('bot.example',))
            protocol.check_origin(good, host='bot.example')
        for bad in ('http://bot.example.evil', 'http://evil/bot.example',
                    'http://bot.example@evil', 'http://bot.example..',
                    'http://bot.example:', 'http://bot.example:0',
                    'http://127.0.0.1:8767', 'http://localhost'):
            with self.subTest(bad=bad), self.assertRaises(protocol.Reject) as caught:
                protocol.check_origin(bad, hosts=('bot.example',))
            self.assertEqual(caught.exception.status, 403)
        # 不传 host 时保持旧的 loopback 规则，绝不开放任意来源。
        with self.assertRaises(protocol.Reject):
            protocol.check_origin('https://bot.example')
        protocol.check_origin('http://[::1]:8767')
        with self.assertRaises(protocol.Reject):
            protocol.check_origin('http://[::1]:8767', hosts=('bot.example',))
        # 非法可信主机列表直接拒绝，而不是降级为放行。
        for hosts in (('',), ('bad host',), (None,), (3,)):
            with self.subTest(hosts=hosts), self.assertRaises(protocol.Reject):
                protocol.check_origin('http://127.0.0.1', hosts=hosts)
        # 空列表等于没有可信主机，任何 Origin 都拒绝。
        with self.assertRaises(protocol.Reject):
            protocol.check_origin('http://127.0.0.1', hosts=())
        protocol.check_origin(None, hosts=())

    def test_content_type(self):
        for good in ('application/json', 'application/json; charset=utf-8',
                     'Application/JSON;charset="UTF-8"'):
            protocol.check_content_type(good)
        for bad in (None, 'text/plain', 'application/not-json/foojson',
                    'application/jsonp', 'application/x-www-form-urlencoded'):
            with self.subTest(bad=bad), self.assertRaises(protocol.Reject):
                protocol.check_content_type(bad)

    def test_session_id(self):
        self.assertEqual(protocol.session_id('abc'), 'abc')
        for bad in ('', 'a b', 'x' * 300, '\x7f'):
            with self.subTest(bad=bad), self.assertRaises(protocol.Reject):
                protocol.session_id(bad)

    def test_encode_reply_enforces_limit_without_cutting_json(self):
        reply = protocol.encode_reply(protocol.result_body(1, {'ok': True}, True), True)
        decoded = json.loads(reply.body)
        self.assertEqual(decoded['result']['resultType'], 'complete')
        self.assertEqual(decoded['result']['ok'], True)
        huge = {'x': 'a' * (1024 * 1024)}
        with self.assertRaises(OverflowError):
            protocol.encode_reply(protocol.result_body(1, huge), False)

    def test_paged_cursor_is_generated_after_cleaning_and_fits_full_envelope(self):
        text = 'x' * (1024 * 1024)
        data = {'namespace': 'Demo', 'path': 'file.txt', 'size': len(text),
                'content': text, 'sha256': 'full-digest'}
        page = files.DataPage(None, files._path_tag('Demo', 'file.txt'),
                              (1, 2, len(text), 3, 4), len(text), 0, None,
                              True, True, None)
        body = protocol.result_body(1, protocol.tool_result(Outcome(data), ''), False)
        rules = redaction.policy({'redact_fields': ['next_cursor']})
        reply = protocol.encode_reply(body, False, known=('next_cursor',),
                                      policy=rules, page=page)
        self.assertLessEqual(len(reply.body), protocol.MAX_RESPONSE)
        result = json.loads(reply.body)['result']
        structured = result['structuredContent']
        self.assertTrue(structured['paged'])
        self.assertNotIn('sha256', structured)
        self.assertIsInstance(structured['next_cursor'], str)
        self.assertNotEqual(structured['next_cursor'], '[REDACTED]')
        self.assertEqual(json.loads(result['content'][0]['text']), structured)

    def test_error_response_with_huge_id_stays_bounded_valid_json(self):
        reply = protocol.reply_from(
            protocol.Reject(400, protocol.INVALID_REQUEST, 'Invalid request'),
            ident='界' * 200000,
        )
        self.assertLessEqual(len(reply.body), protocol.MAX_RESPONSE)
        payload = json.loads(reply.body)
        self.assertIsNone(payload['id'])
        self.assertEqual(payload['error']['code'], protocol.INVALID_REQUEST)

    def test_encode_reply_honours_redaction_policy(self):
        from OlivOSCockpit import redaction
        rules = redaction.policy({'allow_fields': ['token']})
        body = protocol.result_body(1, {'token': 'plain', 'password': 'secret'}, False)
        payload = json.loads(protocol.encode_reply(body, False, policy=rules).body)
        self.assertEqual(payload['result'],
                         {'token': 'plain', 'password': '[REDACTED]', '_meta': {'redacted': True}})
        off = redaction.policy({'redaction_enabled': False})
        payload = json.loads(protocol.encode_reply(body, False, policy=off).body)
        self.assertEqual(payload['result'], {'token': 'plain', 'password': 'secret'})
        # 超限仍以完整 JSON-RPC 信封安全失败，关闭时也不例外。
        with self.assertRaises(OverflowError):
            protocol.encode_reply(protocol.result_body(1, {'x': 'a' * (1024 * 1024)}, False),
                                  False, policy=off)

    def test_tool_result_shape(self):
        spec = ToolSpec('t', 'd', object_schema(), lambda ctx, args: None)
        result = protocol.tool_result(Outcome({'a': 1}), '{"a":1}')
        self.assertEqual(result['structuredContent'], {'a': 1})
        self.assertFalse(result['isError'])
        self.assertEqual(protocol.list_result([spec])['tools'][0]['name'], 't')
        truncated = protocol.truncated_result('t')
        self.assertTrue(truncated['isError'])
        self.assertTrue(truncated['structuredContent']['truncated'])
        json.loads(truncated['content'][0]['text'])


if __name__ == '__main__':
    unittest.main()
