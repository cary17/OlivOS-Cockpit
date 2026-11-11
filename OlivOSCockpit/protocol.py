"""MCP 双时代协议纯值层：严格 JSON、分类、校验与响应构造，不做 I/O。"""

import asyncio
from bisect import bisect_right
import json
import math
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from . import redaction
from .contracts import MAX_RESPONSE, SERVER_INFO, Outcome, check_json_budget

LEGACY_VERSIONS = ('2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05')
MODERN_VERSION = '2026-07-28'
SUPPORTED = LEGACY_VERSIONS + (MODERN_VERSION,)
DEFAULT_LEGACY = '2025-11-25'

META_VERSION = 'io.modelcontextprotocol/protocolVersion'
META_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities'
META_CLIENT = 'io.modelcontextprotocol/clientInfo'
META_SERVER = 'io.modelcontextprotocol/serverInfo'

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
HEADER_MISMATCH = -32020
UNSUPPORTED_VERSION = -32022

LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1'})
# 仅保留给旧调用方与测试；实际校验由 check_origin 解析后按主机白名单复核。
ORIGIN_RE = re.compile(
    r'^https?://(?:\[::1\]|127\.0\.0\.1|localhost)(?::[0-9]{1,5})?$', re.IGNORECASE)
_CONTENT_TYPE_RE = re.compile(
    r'^application/json\s*(?:;\s*charset\s*=\s*"?utf-8"?\s*)?$', re.IGNORECASE)


class Reject(Exception):
    """携带 HTTP 状态与 JSON-RPC 错误；消息只含固定安全文本。"""

    def __init__(self, status, code, message, data=None, headers=()):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.data = data
        self.headers = tuple(headers)


class _PageInvalid(Exception):
    """A paged file view no longer matches its signed continuation."""


@dataclass
class Request:
    method: str
    params: dict
    ident: object
    notification: bool
    modern: bool
    version: str | None = None
    session: str | None = None


@dataclass
class Reply:
    status: int
    body: bytes = b''
    headers: tuple = field(default=())
    modern: bool = False
    failed: bool = False


def dumps(value):
    # 编码时施加预算，避免先生成超大响应再测量。
    chunks = []
    size = 0
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    for chunk in encoder.iterencode(value):
        size += len(chunk)
        if size > MAX_RESPONSE:
            raise OverflowError('response too large')
        chunks.append(chunk)
    return ''.join(chunks)


def error_body(ident, code, message, data=None):
    error = {'code': code, 'message': message}
    if data is not None:
        error['data'] = data
    return {'jsonrpc': '2.0', 'id': ident, 'error': error}


def result_body(ident, result, modern=False):
    if modern:
        result = dict(result)
        result['resultType'] = 'complete'
    return {'jsonrpc': '2.0', 'id': ident, 'result': result}


def reply_from(rejected, modern=False, ident=None, extra=(), known=(), policy=None):
    """Reject 与成功响应共用脱敏边界；超限不回退原始错误数据。"""
    headers = tuple(rejected.headers) + tuple(extra)
    try:
        return encode_reply(error_body(ident, rejected.code, rejected.message, rejected.data),
                            modern, rejected.status, headers, known, policy)
    except asyncio.CancelledError:
        raise
    except BaseException:
        return safe_reply(ident, modern, rejected.status, headers, code=rejected.code)


def _trusted_hosts(hosts):
    if hosts is not None and type(hosts) not in (str, list, tuple, set, frozenset):
        # 兼容直接传入配置快照的调用方；没有 listen_host 时按不可信处理。
        hosts = getattr(hosts, 'listen_host', None)
        if hosts is None:
            raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    if hosts is None:
        return LOOPBACK_HOSTS
    if type(hosts) is str:
        hosts = (hosts,)
    result = set()
    for host in hosts:
        if type(host) is not str or not host or len(host) > 253:
            raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
        host = host.casefold()
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        if not host:
            raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
        result.add(host)
    return frozenset(result)


def _origin_authority(value, allowed):
    """解析 http(s) 源；hosts 为 None 时维持旧的 loopback 行为。"""
    if type(value) is not str or not value or len(value) > 512:
        raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    if any(char in value for char in '\r\n\t '):
        raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    scheme, sep, authority = value.partition('://')
    if not sep or scheme.casefold() not in ('http', 'https'):
        raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    if not authority or any(char in authority for char in '/?#@'):
        raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    if authority.startswith('['):
        host, sep, rest = authority[1:].partition(']')
        if not sep:
            raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
        port = rest[1:] if rest.startswith(':') else None
        if rest and port is None:
            raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    else:
        if authority.count(':') > 1 or authority.endswith(':'):
            raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
        host, _, port = authority.partition(':')
        port = port or None
    if port is not None and (not port.isdecimal() or not 1 <= int(port) <= 65535):
        raise Reject(403, INVALID_REQUEST, 'Invalid Origin')
    if host.casefold() not in allowed:
        raise Reject(403, INVALID_REQUEST, 'Invalid Origin')


def check_origin(value, hosts=None, host=None, allowed_hosts=None, trusted_hosts=None):
    """缺省放过；存在则匹配可信主机。hosts 省略时只允许 loopback。

    service 在配置了非回环监听地址时传入该主机（或主机列表）；
    不传时保持旧的 loopback 行为，绝不默认开放任意 Origin。
    """
    if value is None:
        return
    if hosts is None:
        hosts = host if host is not None else (
            allowed_hosts if allowed_hosts is not None else trusted_hosts)
    _origin_authority(value, _trusted_hosts(hosts))


def check_content_type(value):
    if value is None or not _CONTENT_TYPE_RE.match(value):
        raise Reject(415, INVALID_REQUEST, 'Content-Type must be application/json')


def check_accept(value):
    """规范要求客户端声明接受 JSON；只做宽松声明检查。"""
    if value is None:
        return
    lowered = value.lower()
    if 'application/json' not in lowered and '*/*' not in lowered:
        raise Reject(406, INVALID_REQUEST, 'Not Acceptable')


def _bad_constant(_name):
    raise ValueError('non-finite number')


def _finite_float(raw):
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError('non-finite number')
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def loads(raw):
    """严格 JSON：拒绝批量、重复键、NaN/Infinity、非法 UTF-8 与顶层非对象。"""
    if type(raw) is not bytes:
        raise Reject(400, INVALID_REQUEST, 'Request body must be JSON')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        raise Reject(400, PARSE_ERROR, 'Parse error') from None
    try:
        check_json_budget(text)
        value = json.loads(text, parse_constant=_bad_constant, parse_float=_finite_float,
                           object_pairs_hook=_unique_object)
    except (ValueError, OverflowError, RecursionError):
        raise Reject(400, PARSE_ERROR, 'Parse error') from None
    if type(value) is not dict:
        raise Reject(400, INVALID_REQUEST, 'Batch or non-object request rejected')
    return value


def classify(message, headers):
    """两阶段入口：先按判据分类，再做该时代的验证。返回 Request。"""
    if message.get('jsonrpc') != '2.0':
        raise Reject(400, INVALID_REQUEST, 'Invalid JSON-RPC version')
    ident = message.get('id')
    if 'id' in message and type(ident) not in (str, int):
        raise Reject(400, INVALID_REQUEST, 'Invalid request id')
    if type(message.get('method')) is not str:
        raise Reject(400, INVALID_REQUEST, 'Invalid request')
    method = message['method']
    params = message.get('params', {})
    if type(params) is not dict:
        raise Reject(400, INVALID_PARAMS, 'Invalid params')
    meta = params.get('_meta', {})
    if type(meta) is not dict:
        raise Reject(400, INVALID_PARAMS, 'Invalid params')
    notification = 'id' not in message

    if method == 'initialize':
        if notification:
            raise Reject(400, INVALID_REQUEST, 'initialize requires an id')
        return _initialize(params, headers, ident)

    if has_modern_meta(meta):
        return _modern(method, params, meta, headers, ident, notification)

    session = headers.get('Mcp-Session-Id')
    if session is None:
        raise Reject(400, INVALID_REQUEST, 'Missing protocol era')
    # 版本头在确认会话后再校验，未知会话优先 404。
    return Request(method, params, ident, notification, False,
                   headers.get('MCP-Protocol-Version'), session)


def _initialize(params, headers, ident):
    """传统握手参数必需校验；未知客户端版本按规范回落。"""
    version = params.get('protocolVersion')
    capabilities = params.get('capabilities')
    client = params.get('clientInfo')
    if (type(version) is not str or type(capabilities) is not dict
            or not _client_info(client)):
        raise Reject(400, INVALID_PARAMS, 'Invalid initialize params')
    negotiated = version if version in LEGACY_VERSIONS else DEFAULT_LEGACY
    header = headers.get('MCP-Protocol-Version')
    if header is not None:
        if header not in LEGACY_VERSIONS:
            raise Reject(400, UNSUPPORTED_VERSION, 'Unsupported protocol version',
                         {'supported': list(LEGACY_VERSIONS)})
        if header != negotiated:
            raise Reject(400, INVALID_REQUEST, 'Protocol version mismatch')
    return Request('initialize', params, ident, False, False, negotiated)


def has_modern_meta(meta):
    """时代只由保留的版本键判定；其他 _meta 键不改变传统会话语义。"""
    return META_VERSION in meta


def _modern(method, params, meta, headers, ident, notification):
    for name in (META_VERSION, META_CAPABILITIES):
        if name not in meta:
            raise Reject(400, INVALID_PARAMS, 'Missing required _meta')
    version = meta[META_VERSION]
    if type(version) is not str or type(meta[META_CAPABILITIES]) is not dict:
        raise Reject(400, INVALID_PARAMS, 'Invalid _meta')
    if META_CLIENT in meta and not _client_info(meta[META_CLIENT]):
        raise Reject(400, INVALID_PARAMS, 'Invalid clientInfo')

    if headers.get('MCP-Protocol-Version') != version:
        raise Reject(400, HEADER_MISMATCH, 'Protocol version header mismatch')
    if headers.get('Mcp-Method') != method:
        raise Reject(400, HEADER_MISMATCH, 'Method header mismatch')
    if method == 'tools/call':
        header_name = headers.get('Mcp-Name')
        name = params.get('name')
        if header_name is None or type(name) is not str or unquote(header_name) != name:
            raise Reject(400, HEADER_MISMATCH, 'Tool name header mismatch')

    if version != MODERN_VERSION:
        raise Reject(400, UNSUPPORTED_VERSION, 'Unsupported protocol version',
                     {'supported': [MODERN_VERSION], 'requested': version})
    return Request(method, params, ident, notification, True, version)


def _client_info(value):
    return (type(value) is dict and type(value.get('name')) is str
            and type(value.get('version')) is str)


def tool_arguments(params):
    args = params.get('arguments', {})
    if type(args) is not dict:
        raise Reject(400, INVALID_PARAMS, 'Invalid arguments')
    return args


def discover_result():
    return {
        'supportedVersions': list(SUPPORTED),
        'capabilities': {'tools': {}},
        'ttlMs': 0,
        'cacheScope': 'private',
        '_meta': {META_SERVER: dict(SERVER_INFO)},
    }


def list_result(tools):
    return {
        'tools': [tool.definition() for tool in tools],
        'ttlMs': 0,
        'cacheScope': 'private',
        '_meta': {META_SERVER: dict(SERVER_INFO)},
    }


def tool_result(outcome, text):
    """Outcome → tools/call result；tool 错误仍是 200 result。"""
    result = {
        'content': [{'type': 'text', 'text': text}],
        'structuredContent': outcome.data,
        'isError': bool(outcome.is_error),
    }
    if outcome.truncated:
        result['_meta'] = {'truncated': True}
    return result


def truncated_result(tool):
    """结果超限时的结构化替代，绝不编码被截断的 JSON 字节。"""
    message = {
        'truncated': True,
        'tool': tool,
        'error': 'Result exceeded response limit; request a narrower scope',
    }
    text = dumps(message)
    return {
        'content': [{'type': 'text', 'text': text}],
        'structuredContent': message,
        'isError': True,
    }


def _fixed_supported(error):
    """-32022 且 supported 精确等于服务端固定版本列表时返回该字段名。

    仅对 supported 这个字段执行 schema 级保留；requested 与其他字段是
    应用值，仍走普通清理。列表不精确匹配时不获豁免。
    """
    if error.get('code') != UNSUPPORTED_VERSION:
        return None
    data = error.get('data')
    if type(data) is not dict:
        return None
    supported = data.get('supported')
    if supported == [MODERN_VERSION] or supported == list(LEGACY_VERSIONS):
        return 'supported'
    return None


def _clean_body(body, known, policy=None):
    """应用值只在这里清理一次；service 的预清理结果再次进入时规则幂等。"""
    cleaner = redaction.Cleaner(known, policy)
    clean = {'jsonrpc': '2.0', 'id': body.get('id')}
    if 'error' in body:
        error = body['error']
        clean['error'] = {'code': error['code'], 'message': cleaner.value(error['message'])}
        if 'data' in error:
            fixed = _fixed_supported(error)
            if fixed is None:
                clean['error']['data'] = cleaner.value(error['data'])
            else:
                # supported 按 schema 保留（仍校验形状与预算）；其余字段携带
                # 键名进入普通清理，字段规则与已知凭据照常生效。
                cleaned = {}
                for key, value in error['data'].items():
                    cleaned.update(cleaner.value({key: value}, schema=(key == fixed)))
                clean['error']['data'] = cleaned
        if cleaner.changed:
            data = clean['error'].get('data')
            data = dict(data) if type(data) is dict else {'detail': data}
            data['_meta'] = dict(data.get('_meta') or {}, redacted=True)
            clean['error']['data'] = data
        return clean
    result = body['result']
    if 'structuredContent' in result:
        data = cleaner.value(result['structuredContent'])
        clean_result = {}
        for key, value in result.items():
            if key in ('content', 'structuredContent', 'resultType'):
                continue
            if key in ('isError', '_meta'):
                clean_result[key] = cleaner.value(value, schema=True)
            else:
                item = cleaner.value({key: value})
                if clean_result.keys() & item.keys():
                    raise redaction.RedactionError('redacted key collision')
                clean_result.update(item)
        clean_result['structuredContent'] = data
        clean_result['content'] = [{'type': 'text', 'text': dumps(data)}]
    else:
        clean_result = {}
        for key, value in result.items():
            if key == 'tools':
                if type(value) is not list or len(value) > redaction.MAX_NODES:
                    raise OverflowError('tool definition budget exceeded')
                clean_result[key] = [
                    {name: cleaner.value(item, schema=name in ('name', 'inputSchema', 'outputSchema', 'annotations'))
                     for name, item in tool.items()} for tool in value
                ]
            elif key in ('protocolVersion', 'supportedVersions', 'resultType', 'ttlMs', 'cacheScope',
                         'capabilities', 'serverInfo', '_meta'):
                clean_result[key] = cleaner.value(value, schema=True)
            else:
                item = cleaner.value({key: value})
                if clean_result.keys() & item.keys():
                    raise redaction.RedactionError('redacted key collision')
                clean_result.update(item)
    if 'resultType' in result:
        clean_result['resultType'] = result['resultType']
    if cleaner.changed:
        clean_result['_meta'] = dict(clean_result.get('_meta') or {}, redacted=True)
    clean['result'] = clean_result
    return clean


def safe_reply(ident, modern, status=200, headers=(), tool=False, truncated=False, code=-32603):
    """固定降级不再调用脱敏器，防止损坏的脱敏器再次逃逸。"""
    ident = ident if ident is None or type(ident) in (str, int) else None
    code = code if type(code) is int else -32603
    if tool:
        data = {'error': 'Outbound redaction failed safely', 'redacted': True}
        if truncated:
            data.update(truncated=True, error='Result exceeded response limit; request a narrower scope')
        result = tool_result(Outcome(data, is_error=True, truncated=truncated), dumps(data))
        result['_meta'] = dict(result.get('_meta') or {}, redacted=True)
        if modern:
            result['_meta'][META_SERVER] = dict(SERVER_INFO)
        body = result_body(ident, result, modern)
    else:
        body = error_body(ident, code, 'Outbound response unavailable safely',
                          {'_meta': {'redacted': True}})
    try:
        text = dumps(body)
    except (OverflowError, TypeError, ValueError, RecursionError):
        body['id'] = None
        text = dumps(body)
    if modern:
        headers = tuple(headers) + (('MCP-Protocol-Version', MODERN_VERSION),)
    return Reply(status, text.encode('ascii'), tuple(headers), modern, failed=True)


def _page_body(ident, data, modern, redacted=False, truncated=False):
    result = {
        'content': [{'type': 'text', 'text': dumps(data)}],
        'structuredContent': data,
        'isError': False,
    }
    meta = {}
    if truncated:
        meta['truncated'] = True
    if redacted:
        meta['redacted'] = True
    if modern:
        meta[META_SERVER] = dict(SERVER_INFO)
    if meta:
        result['_meta'] = meta
    return result_body(ident, result, modern)


def _page_error(body, modern, status, headers, known, policy, message):
    ident = body.get('id') if type(body) is dict else None
    data = {'error': message}
    result = tool_result(Outcome(data, is_error=True), dumps(data))
    if modern:
        result['_meta'] = {META_SERVER: dict(SERVER_INFO)}
    return encode_reply(result_body(ident, result, modern), modern, status, headers, known, policy)


def _encode_data_page(body, modern, status, headers, known, policy, page):
    result = body.get('result') if type(body) is dict else None
    if type(result) is not dict or type(result.get('structuredContent')) is not dict:
        raise _PageInvalid('Invalid paged result')
    source = result['structuredContent']
    raw_text = source.get('content')
    if type(raw_text) is not str:
        raise _PageInvalid('Invalid paged text')

    state = page.state
    context_tag = page.context_tag(known, policy)
    if state is not None and state.get('context_tag') != context_tag:
        raise _PageInvalid('Read cursor no longer matches redaction policy')

    cleaner = redaction.Cleaner(known, policy)
    jsonl = page.jsonl
    if jsonl is None:
        jsonl = cleaner.detect_jsonl(raw_text, eof=page.eof)
    if type(jsonl) is not bool or (state is not None and state.get('jsonl') is not jsonl):
        raise _PageInvalid('Invalid read cursor format')

    if page.fixed_end is not None:
        cut = len(raw_text)
        block_end = page.fixed_end
    else:
        try:
            cut = redaction.safe_record_cut(
                raw_text, known, policy, eof=page.eof, cleaner=cleaner, jsonl=jsonl)
        except OverflowError:
            raise _PageInvalid('Text has no safe bounded record boundary') from None
        block_end = page.source_start + len(raw_text[:cut].encode('utf-8'))
    if cut <= 0 and (page.source_start < page.file_size):
        raise _PageInvalid('Text has no safe bounded record boundary')

    clean_source = dict(source)
    clean_source['content'] = raw_text[:cut]
    clean_source['size'] = block_end - page.source_start
    clean_data = cleaner.value(clean_source, text_formats={'content': jsonl})
    clean_text = clean_data.get('content')
    if type(clean_text) is not str:
        raise _PageInvalid('Invalid cleaned text')
    if len(clean_text) > redaction.MAX_TEXT:
        raise _PageInvalid('Redacted record exceeds the safe page limit')

    if state is not None:
        if (state['block_end'] > state['block_start']
                and state.get('view_tag') != page.view_tag(clean_text)):
            raise _PageInvalid('Read cursor no longer matches cleaned content')
        view_offset = state['view_offset']
    else:
        view_offset = 0
    if view_offset > len(clean_text) or (
            state is not None and state['block_end'] > state['block_start']
            and view_offset == len(clean_text)):
        raise _PageInvalid('Invalid read cursor position')
    if jsonl and view_offset and clean_text[view_offset - 1] != '\n':
        raise _PageInvalid('Invalid read cursor position')

    ident = body.get('id')
    if page.complete_file and state is None:
        try:
            full_body = _page_body(ident, clean_data, modern, cleaner.changed)
            full_text = dumps(full_body)
        except OverflowError:
            full_text = None
        if full_text is not None:
            if modern:
                headers = tuple(headers) + (('MCP-Protocol-Version', MODERN_VERSION),)
            return Reply(status, full_text.encode('ascii'), tuple(headers), modern)

    start = view_offset
    remaining = len(clean_text) - start
    if remaining < 0:
        raise _PageInvalid('Invalid read cursor position')
    page_metadata = cleaner.value({
        'file_size': page.file_size,
        'paged': True,
    })

    def candidate(end):
        more_view = end < len(clean_text)
        more_source = not more_view and block_end < page.file_size
        token = None
        if more_view:
            token = page.issue_cursor(page.source_start, block_end, end,
                                      page.view_tag(clean_text), context_tag, jsonl=jsonl)
        elif more_source:
            token = page.issue_cursor(block_end, block_end, 0, '', context_tag, jsonl=jsonl)
        data = dict(clean_data)
        data.pop('sha256', None)
        data.update(page_metadata)
        data['content'] = clean_text[start:end]
        # This signed handle contains only offsets/revision tags, so emit it after
        # cleaning to keep secret matches and user field rules from corrupting it.
        if token is not None:
            data['next_cursor'] = token
        else:
            data.pop('next_cursor', None)
        reply_body = _page_body(
            ident, data, modern, cleaner.changed,
            truncated=token is not None,
        )
        return token, dumps(reply_body)

    if jsonl:
        cleaner._spend(len(clean_text))
        line_ends = []
        position = 0
        while True:
            newline = clean_text.find('\n', position)
            if newline < 0:
                break
            line_ends.append(newline + 1)
            position = newline + 1
        if clean_text and not clean_text.endswith('\n'):
            line_ends.append(len(clean_text))
        if len(line_ends) > redaction.MAX_NODES:
            raise _PageInvalid('JSONL record count exceeds the safe page limit')
        first = bisect_right(line_ends, start)
        low = 1 if remaining else 0
        high = len(line_ends) - first
        best = None
        # 末尾游标会缩短或省略，完整视图可能比带续读游标的短前缀更小。
        try:
            token, encoded = candidate(len(clean_text))
        except OverflowError:
            high -= 1
        else:
            best = (high, len(clean_text), token, encoded)
            low = high + 1
        while low <= high:
            middle = (low + high) // 2
            end = line_ends[first + middle - 1] if middle else start
            try:
                token, encoded = candidate(end)
            except OverflowError:
                high = middle - 1
            else:
                best = (middle, end, token, encoded)
                low = middle + 1
    else:
        low = 1 if remaining else 0
        high = remaining
        best = None
        while low <= high:
            middle = (low + high) // 2
            try:
                token, encoded = candidate(start + middle)
            except OverflowError:
                high = middle - 1
            else:
                best = (middle, start + middle, token, encoded)
                low = middle + 1

    if best is None or (remaining and best[0] == 0):
        return safe_reply(ident, modern, status, headers, tool=True, truncated=True)

    length, end, token, encoded = best
    while True:
        try:
            token, encoded = candidate(end)
        except OverflowError:
            if jsonl:
                length -= 1
                if length <= 0:
                    return safe_reply(ident, modern, status, headers, tool=True, truncated=True)
                end = line_ends[first + length - 1]
            else:
                length -= max(1, length // 16)
                if length <= 0:
                    return safe_reply(ident, modern, status, headers, tool=True, truncated=True)
                end = start + length
            continue
        break
    if modern:
        headers = tuple(headers) + (('MCP-Protocol-Version', MODERN_VERSION),)
    return Reply(status, encoded.encode('ascii'), tuple(headers), modern)


def encode_reply(body, modern, status=200, headers=(), known=(), policy=None, page=None):
    """净化副本后有界编码；paged data is cleaned before its view is sliced."""
    if page is not None:
        try:
            return _encode_data_page(body, modern, status, headers, known, policy, page)
        except asyncio.CancelledError:
            raise
        except _PageInvalid as exc:
            return _page_error(body, modern, status, headers, known, policy, str(exc))
        except OverflowError:
            return safe_reply(body.get('id') if type(body) is dict else None,
                              modern, status, headers, tool=True, truncated=True)
        except BaseException:
            return safe_reply(body.get('id') if type(body) is dict else None,
                              modern, status, headers, tool=True)
    try:
        text = dumps(_clean_body(body, known, policy))
    except asyncio.CancelledError:
        raise
    except OverflowError:
        raise
    except BaseException:
        result = body.get('result') if type(body) is dict else None
        return safe_reply(body.get('id') if type(body) is dict else None, modern, status, headers,
                          tool=type(result) is dict and 'structuredContent' in result,
                          code=body['error']['code'] if type(body) is dict and 'error' in body else -32603)
    if modern:
        headers = tuple(headers) + (('MCP-Protocol-Version', MODERN_VERSION),)
    return Reply(status, text.encode('ascii'), tuple(headers), modern)


def session_id(raw):
    """Mcp-Session-Id 头必须是可见 ASCII；重复头在 service 层拒绝。"""
    if raw is None or not raw or len(raw) > 256 or any(not 0x21 <= ord(ch) <= 0x7E for ch in raw):
        raise Reject(400, INVALID_REQUEST, 'Invalid session id')
    return raw


__all__ = [
    'DEFAULT_LEGACY', 'HEADER_MISMATCH', 'INVALID_PARAMS', 'INVALID_REQUEST',
    'LEGACY_VERSIONS', 'META_CAPABILITIES', 'META_CLIENT', 'META_SERVER', 'META_VERSION',
    'METHOD_NOT_FOUND', 'MODERN_VERSION', 'ORIGIN_RE', 'PARSE_ERROR', 'Reply', 'Reject',
    'Request', 'SUPPORTED', 'UNSUPPORTED_VERSION', 'check_accept', 'check_content_type',
    'LOOPBACK_HOSTS', 'check_origin', 'classify', 'discover_result', 'dumps', 'encode_reply',
    'error_body',
    'has_modern_meta', 'list_result', 'loads', 'reply_from', 'result_body', 'safe_reply', 'session_id',
    'tool_arguments', 'tool_result', 'truncated_result',
]
