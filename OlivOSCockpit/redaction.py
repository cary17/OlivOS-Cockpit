"""有界、仅副本的出站规则脱敏；不读取文件或调用宿主对象的方法。

字段规则按完整字段名 casefold 精确匹配，优先级为
用户 allow > 用户 redact > 内置凭据字段。全局关闭时不做任何替换，
但仍校验 JSON 形状、有限浮点、深度、节点与扫描预算。
"""

import heapq
import json
import math
import re
from bisect import bisect_right
from dataclasses import dataclass
from itertools import islice
from urllib.parse import unquote_plus

from .contracts import check_json_budget

MARKER = '[REDACTED]'
MAX_DEPTH = 16
MAX_NODES = 20000
MAX_SCAN = 4 * 1024 * 1024
MAX_WORK = 64 * 1024 * 1024
MAX_TEXT = 1024 * 1024
MAX_BOTS = 500
MAX_SECRETS = 256
MAX_SECRET = 4096
MAX_CREDENTIALS = 64 * 1024
MAX_FIELDS = 256
MAX_FIELD = 128

# 只保留已核实的 OlivOS 凭据字段；身份、路径、电话、邮箱、IP 等不再猜测。
BUILTIN_FIELDS = frozenset({
    'password', 'passwd', 'pwd', 'passphrase',
    'token', 'access_token', 'access-token', 'accesstoken',
    'refresh_token', 'refresh-token', 'refreshtoken',
    'session_token', 'session-token', 'sessiontoken',
    'authorization', 'auth', 'cookie', 'set-cookie', 'set_cookie', 'setcookie',
    'private_key', 'private-key', 'privatekey',
    'secret', 'client_secret', 'client-secret', 'clientsecret',
    'api_key', 'api-key', 'apikey',
    'access_key', 'access-key', 'accesskey',
    'secret_key', 'secret-key', 'secretkey',
    'signing_key', 'signing-key', 'signingkey',
    'encryption_key', 'encryption-key', 'encryptionkey',
    'session_key', 'session-key', 'sessionkey',
    'credential', 'credentials',
    # accountAPI extends.app_* / qsign-server[].key；SDK 登录态与临时票据。
    'app_key', 'app-key', 'appkey', 'app_secret', 'app-secret', 'appsecret',
    'key', 'bili_jct', 'ticket',
    '密码', '口令', '令牌', '私钥', '密钥', '凭据', '授权',
})
_HANDLES = frozenset({'hash', 'bot_hash', 'namespace', 'namespaces', 'bot_hashes'})


def _normal(name):
    return ''.join(char for char in name if char not in ' _-')


_BUILTIN_NORMAL = frozenset(_normal(name) for name in BUILTIN_FIELDS)

_ESCAPE = re.compile(
    r'\\(?:u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}'
    r'|u[0-9a-fA-F]{4}|["\\/bfnrt])')
_ASSIGN = re.compile(
    r'(?<![\w.-])(?P<quote>["\']?)(?P<key>'
    r'(?:(?:api|app|private|access|secret|signing|encryption|session)[ _-]?key'
    r'|(?:access|session|refresh)[ _-]?token|pass[ _-]?phrase|(?:client|app)[ _-]?secret'
    r'|set[ _-]?cookie|authorization|[\w.-]{1,128}))(?P=quote)\s*[:=]\s*', re.IGNORECASE)
_PRIVATE = re.compile(
    r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?:-----)?[\s\S]*?'
    r'(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)')
_PRIVATE_END = re.compile(r'-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----')
_SURROGATE = re.compile(r'[\ud800-\udfff]')
_USERINFO = re.compile(r'(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*://)[^\s/@]+@')
_QUERY = re.compile(r'([?&])([^=&#\s]{1,128})=([^&#\s]*)')
_AUTH = re.compile(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+')


class RedactionError(Exception):
    """固定安全错误，不携带原始数据。"""


@dataclass(frozen=True)
class Policy:
    enabled: bool = True
    redact_fields: frozenset = frozenset()
    allow_fields: frozenset = frozenset()


DEFAULT_POLICY = Policy()


def _read(source, name):
    if source is None:
        return None
    if type(source) is dict:
        return source.get(name)
    try:
        return getattr(source, name, None)
    except Exception:
        return None


def _has_settings(source):
    return any(_read(source, name) is not None
               for name in ('redaction_enabled', 'redact_fields', 'allow_fields'))


def _settings(config):
    """容忍未定的配置管理器：dict、snapshot()/snapshot、嵌套 redaction 或 Context。"""
    candidate = config
    for _ in range(4):
        if candidate is None:
            return None
        if _has_settings(candidate):
            return candidate
        if type(candidate) is not dict:
            snapshot = _read(candidate, 'snapshot')
            if callable(snapshot):
                try:
                    candidate = snapshot()
                except Exception:
                    return None
                continue
            if snapshot is not None:
                candidate = snapshot
                continue
        nested = _read(candidate, 'redaction')
        if nested is not None and nested is not candidate:
            candidate = nested
            continue
        inner = _read(candidate, 'config')
        if inner is None or inner is candidate:
            return candidate
        candidate = inner
    return candidate


def _fields(value):
    if type(value) not in (list, tuple, set, frozenset):
        return frozenset()
    result = set()
    for item in islice(value, MAX_FIELDS):
        if type(item) is not str:
            continue
        name = item.casefold()
        if 0 < len(name) <= MAX_FIELD:
            result.add(name)
    return frozenset(result)


def policy(config=None):
    """读取配置快照；缺失或形状不符时维持旧的默认开启行为。"""
    settings = _settings(config)
    if settings is None:
        return DEFAULT_POLICY
    enabled = _read(settings, 'redaction_enabled')
    enabled = enabled if type(enabled) is bool else True
    return Policy(enabled, _fields(_read(settings, 'redact_fields')),
                  _fields(_read(settings, 'allow_fields')))


def as_policy(value):
    return value if isinstance(value, Policy) else policy(value)


def _label(name, rules):
    """文本标签匹配：精确 casefold；内置再加分隔符不敏感变体。"""
    name = name.casefold()
    if name in rules.allow_fields:
        return False
    if name in rules.redact_fields or name in BUILTIN_FIELDS:
        return True
    return _normal(name) in _BUILTIN_NORMAL


def sensitive(key, rules=None):
    return _label(key, as_policy(rules))


def credentials(token, bots, policy=None):
    """逐次快照，只看原生 dict/vars 的 password、post_info.access_token 白名单。

    全局关闭时不做采集，也不因快照超限阻止响应。
    """
    if policy is not None and not as_policy(policy).enabled:
        return ()
    result = set()
    total = 0

    def add(value):
        nonlocal total
        if type(value) is not str or not value or value in result:
            return
        if len(value) > MAX_SECRET or len(result) >= MAX_SECRETS:
            raise OverflowError('credential budget exceeded')
        total += len(value)
        if total > MAX_CREDENTIALS:
            raise OverflowError('credential budget exceeded')
        result.add(value)

    def fields(value):
        if type(value) is dict:
            return value
        if value is None:
            return {}
        try:
            value = object.__getattribute__(value, '__dict__')
        except (AttributeError, TypeError):
            return {}
        return value if type(value) is dict else {}

    add(token)
    if bots is not None:
        if type(bots) is not dict or len(bots) > MAX_BOTS:
            raise OverflowError('credential budget exceeded')
        for bot in bots.values():
            data = fields(bot)
            add(data.get('password'))
            add(fields(data.get('post_info')).get('access_token'))
    return tuple(sorted(result, key=lambda item: (-len(item), item)))


def _decode(text):
    """原文 -> (解码文本, 片段表)；片段为 (原文起点, 原文长, 解码起点, 解码长)。"""
    pieces = []
    parts = []
    total = 0
    pos = 0
    for match in _ESCAPE.finditer(text):
        if len(pieces) + 2 > MAX_NODES:
            raise OverflowError('redaction escape budget exceeded')
        if match.start() > pos:
            chunk = text[pos:match.start()]
            pieces.append((pos, len(chunk), total, len(chunk)))
            parts.append(chunk)
            total += len(chunk)
        chunk = json.loads('"' + match.group(0) + '"')
        pieces.append((match.start(), match.end() - match.start(), total, len(chunk)))
        parts.append(chunk)
        total += len(chunk)
        pos = match.end()
    if pos < len(text):
        if len(pieces) >= MAX_NODES:
            raise OverflowError('redaction escape budget exceeded')
        chunk = text[pos:]
        pieces.append((pos, len(chunk), total, len(chunk)))
        parts.append(chunk)
    return ''.join(parts), pieces


def _raw_boundary(pieces, starts, index, end=False):
    slot = bisect_right(starts, index - 1 if end else index) - 1
    if slot < 0:
        raise RedactionError('invalid escape boundary')
    raw, raw_length, decoded, length = pieces[slot]
    if raw_length != length:
        return raw + raw_length if end else raw
    return raw + index - decoded


def _replace_known(text, known):
    """按原文位置合并有界匹配；不建立进程级凭据正则缓存。"""
    if not known or text == MARKER:
        return text
    decoded, pieces = _decode(text)
    starts = [part[2] for part in pieces]
    # 同时看原文，避免把凭据本身的字面反斜线误当成 JSON 转义而漏掉。
    views = (text,) if decoded == text else (text, decoded)
    pending = []

    def push(view, number, position):
        secret = known[number]
        if not secret:
            return
        found = views[view].find(secret, position)
        if found < 0:
            return
        finish = found + len(secret)
        start, end = found, finish
        if view:
            start = _raw_boundary(pieces, starts, found)
            end = _raw_boundary(pieces, starts, finish, end=True)
        heapq.heappush(pending, (start, -end, view, number, finish))

    for view in range(len(views)):
        for number in range(len(known)):
            push(view, number, 0)
    parts = []
    end = size = matches = 0
    while pending:
        start, negative_end, view, number, next_position = heapq.heappop(pending)
        matches += 1
        if matches > MAX_NODES:
            raise OverflowError('redaction match budget exceeded')
        finish = -negative_end
        if start >= end:
            size += start - end + len(MARKER)
            if size > MAX_TEXT:
                raise OverflowError('redaction text budget exceeded')
            parts.extend((text[end:start], MARKER))
            end = finish
        push(view, number, next_position)
    if not parts:
        return text
    if size + len(text) - end > MAX_TEXT:
        raise OverflowError('redaction text budget exceeded')
    parts.append(text[end:])
    return ''.join(parts)


def _pairs(items, duplicate):
    """出站文本探测采用 JSON 末值语义；重复键记入 duplicate，强制重编码。"""
    result = {}
    for key, value in items:
        if key in result:
            duplicate.append(True)
        result[key] = value
    return result


def _json_node_count(text, max_depth, max_nodes):
    depth = nodes = 0
    quoted = escaped = atom = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted, atom = True, False
            nodes += 1
        elif char in '[{':
            depth += 1
            nodes += 1
            atom = False
            if depth > max_depth:
                raise OverflowError('JSON depth budget exceeded')
        elif char in ']}':
            depth -= 1
            atom = False
            if depth < 0:
                raise ValueError('Invalid JSON nesting')
        elif char in ',: \t\r\n':
            atom = False
        elif not atom:
            atom = True
            nodes += 1
        if nodes > max_nodes:
            raise OverflowError('JSON node budget exceeded')
    return nodes


def _line_records(text):
    start = 0
    while start < len(text):
        newline = text.find('\n', start)
        if newline < 0:
            yield start, len(text), len(text)
            return
        end = newline - 1 if newline > start and text[newline - 1] == '\r' else newline
        yield start, end, newline + 1
        start = newline + 1


def _reject_json_constant(value):
    raise RedactionError('non-finite number')


class Cleaner:
    def __init__(self, known=(), policy=None):
        self.policy = as_policy(policy)
        self.changed = False
        self.nodes = 0
        self.json_nodes = 0
        self.scanned = 0
        self.work = 0
        if not self.policy.enabled:
            # 关闭时忽略快照，采集失败不得阻止返回。
            self.known = ()
            return
        # 同样限制纯模块调用方传入的已知值，不允许无界 iterable。
        if type(known) not in (tuple, list) or len(known) > MAX_SECRETS:
            raise RedactionError('invalid credential snapshot')
        if any(type(item) is not str or len(item) > MAX_SECRET for item in known):
            raise RedactionError('invalid credential snapshot')
        if sum(map(len, known)) > MAX_CREDENTIALS:
            raise OverflowError('credential budget exceeded')
        self.known = tuple(sorted({item for item in known if item}, key=lambda item: (-len(item), item)))

    def _spend(self, amount):
        self.work += amount
        if self.work > MAX_WORK:
            raise OverflowError('redaction scan budget exceeded')

    def _node(self, depth):
        self.nodes += 1
        if depth > MAX_DEPTH or self.nodes + self.json_nodes > MAX_NODES:
            raise OverflowError('redaction tree budget exceeded')

    def _check_text(self, text):
        if len(text) > MAX_TEXT:
            raise OverflowError('redaction text budget exceeded')
        self.scanned += len(text)
        if self.scanned > MAX_SCAN:
            raise OverflowError('redaction scan budget exceeded')

    def _plain(self, value, depth, text_formats=None, jsonl=False):
        """关闭、schema 或用户 allow：只做 JSON/资源安全校验，不替换任何值。"""
        self._node(depth)
        kind = type(value)
        if kind is str:
            self._check_text(value)
            if jsonl:
                self.text(value, depth, schema=True, jsonl=True)
            return value
        if value is None or kind in (bool, int):
            return value
        if kind is float:
            if math.isfinite(value):
                return value
            raise RedactionError('non-finite number')
        if kind is list:
            if len(value) > MAX_NODES - self.nodes - self.json_nodes:
                raise OverflowError('redaction node budget exceeded')
            return [self._plain(item, depth + 1) for item in value]
        if kind is dict:
            if len(value) > MAX_NODES - self.nodes - self.json_nodes:
                raise OverflowError('redaction node budget exceeded')
            result = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise RedactionError('non-JSON key')
                self._check_text(key)
                result[key] = self._plain(
                    item, depth + 1, jsonl=(type(text_formats) is dict
                                             and text_formats.get(key) is True))
            return result
        raise RedactionError('non-JSON value')

    def _field(self, key):
        """allow / redact / None；必须在任何文本替换之前决定。

        用户规则要求完整名称精确匹配；内置字段保留已核实的 `_ -` 变体。
        """
        name = key.casefold()
        if name in self.policy.allow_fields:
            return 'allow'
        if (name in self.policy.redact_fields or name in BUILTIN_FIELDS
                or _normal(name) in _BUILTIN_NORMAL):
            return 'redact'
        return None

    def value(self, value, depth=0, schema=False, text_formats=None, jsonl=None):
        if not self.policy.enabled or schema:
            return self._plain(value, depth, text_formats, jsonl is True)
        self._node(depth)
        kind = type(value)
        if kind is str:
            return self.text(value, depth, jsonl=jsonl)
        if value is None or kind in (bool, int):
            return value
        if kind is float:
            if math.isfinite(value):
                return value
            raise RedactionError('non-finite number')
        if kind is list:
            if len(value) > MAX_NODES - self.nodes - self.json_nodes:
                raise OverflowError('redaction node budget exceeded')
            return [self.value(item, depth + 1) for item in value]
        if kind is dict:
            if len(value) > MAX_NODES - self.nodes - self.json_nodes:
                raise OverflowError('redaction node budget exceeded')
            result = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise RedactionError('non-JSON key')
                self._check_text(key)
                clean_key = key
                action = self._field(key)
                child_format = (text_formats.get(key) if type(text_formats) is dict
                                else None)
                if action == 'allow':
                    # 用户显式允许优先：该字段的字符串值不再被任何规则或已知凭据替换，
                    # 但 JSON 形状与资源预算仍须校验。
                    result[clean_key] = self._plain(item, depth + 1, jsonl=child_format is True)
                elif action == 'redact':
                    if child_format is True and type(item) is str:
                        self.text(item, depth + 1, schema=True, jsonl=True)
                    self.changed |= type(item) is not str or item != MARKER
                    result[clean_key] = MARKER
                elif key in _HANDLES:
                    # 操作句柄不是身份探针；仅替换已知秘密。
                    if type(item) is str:
                        result[clean_key] = self.handle(item, depth + 1)
                    elif (type(item) is list and len(item) <= MAX_NODES - self.nodes - self.json_nodes
                          and all(type(part) is str for part in item)):
                        result[clean_key] = [self.handle(part, depth + 2) for part in item]
                    else:
                        result[clean_key] = self.value(item, depth + 1)
                else:
                    result[clean_key] = self.value(item, depth + 1, jsonl=child_format)
            return result
        raise RedactionError('non-JSON value')

    def handle(self, text, depth=0):
        self._check_text(text)
        if not self.policy.enabled:
            return text
        self._spend(len(text) * (len(self.known) + 1))
        clean = _replace_known(text, self.known)
        if clean != text:
            self.changed = True
        return clean

    def _end(self, text, start, line=False):
        if text.startswith(MARKER, start):
            return start + len(MARKER)
        if line:
            match = re.search(r'[\r\n]', text[start:])
            return len(text) if match is None else start + match.start()
        quote = None
        stack = []
        escaped = False
        structured = text[start:start + 1] in ('{', '[', '"', "'")
        for index in range(start, len(text)):
            char = text[index]
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == quote:
                    quote = None
                    if not stack:
                        return index + 1
            elif char in ('"', "'"):
                quote = char
            elif char in '{[':
                stack.append(char)
                if len(stack) > MAX_DEPTH:
                    raise OverflowError('redaction text depth exceeded')
            elif char in '}]':
                if not stack:
                    return index
                stack.pop()
                if not stack:
                    return index + 1
            elif not stack and (char.isspace() or char in ',;&'):
                return index
            if not structured and char in '&;':
                return index
        return len(text)

    def _assignments(self, text):
        parts = []
        end = 0
        for match in _ASSIGN.finditer(text):
            if match.start() < end or not _label(match['key'], self.policy):
                continue
            start = match.end()
            normal = _normal(match['key'].casefold())
            finish = self._end(text, start, normal in (
                'cookie', 'setcookie', 'authorization', 'auth', '授权', '凭据'))
            # 只计实际处理的 span；各命中区间不重叠，保持线性。
            self._spend(finish - start)
            parts.extend((text[end:start], MARKER))
            end = finish
        return ''.join(parts) + text[end:] if parts else text

    def detect_jsonl(self, text, checked=False, eof=True):
        if type(text) is not str:
            raise RedactionError('invalid text record')
        if not checked:
            self._check_text(text)
        self._spend(len(text) * 2)
        if '\n' not in text.strip(' \t\r\n'):
            return False
        start = 0
        while start < len(text) and text[start] in ' \t\r\n':
            start += 1
        if start < len(text) and text[start] in '{["':
            self._spend(len(text) * 2)
            try:
                check_json_budget(
                    text, max_depth=MAX_DEPTH, max_nodes=MAX_NODES - self.nodes - self.json_nodes)
                json.loads(text)
            except ValueError:
                pass
            else:
                return False
        self._spend(len(text))
        valid = nodes = 0
        partial_tail = not eof and bool(text) and not text.endswith('\n')
        for line_start, line_end, finish in _line_records(text):
            if partial_tail and finish == len(text):
                break
            while line_start < line_end and text[line_start] in ' \t\r':
                line_start += 1
            record_end = line_end
            while record_end > line_start and text[record_end - 1] in ' \t\r':
                record_end -= 1
            if line_start == record_end:
                continue
            if not (text[line_start] in '{["0123456789tfn'
                    or (text[line_start] == '-' and line_start + 1 < record_end
                        and text[line_start + 1].isdigit())):
                return False
            record = text[line_start:record_end]
            self._spend(len(record) * 2)
            structured = text[line_start] in '{['
            # 标量先验语法；容器必须先限额，解码资源错误不能被当作普通文本。
            if not structured:
                try:
                    json.loads(record, parse_constant=_reject_json_constant)
                except (RedactionError, json.JSONDecodeError):
                    return False
            try:
                nodes += _json_node_count(
                    record, MAX_DEPTH, MAX_NODES - self.nodes - self.json_nodes - nodes)
            except (RedactionError, ValueError):
                return False
            if structured:
                try:
                    json.loads(record, parse_constant=_reject_json_constant)
                except (RedactionError, json.JSONDecodeError):
                    return False
            valid += 1
        return valid > 1

    def _jsonl_text(self, text, depth, clean):
        parts = []
        for start, end, finish in _line_records(text):
            self._node(depth + 1)
            left = start
            while left < end and text[left] in ' \t\r':
                left += 1
            right = end
            while right > left and text[right - 1] in ' \t\r':
                right -= 1
            if left == right:
                parts.append(text[start:finish])
                continue
            record = text[left:right]
            self._spend(len(record) * 2)
            nodes = _json_node_count(
                record, MAX_DEPTH - depth, MAX_NODES - self.nodes - self.json_nodes)
            self.json_nodes += nodes
            duplicate = []
            try:
                parsed = json.loads(
                    record,
                    object_pairs_hook=lambda items: _pairs(items, duplicate),
                    parse_constant=_reject_json_constant,
                )
            except (ValueError, TypeError, RecursionError):
                raise RedactionError('invalid JSONL record') from None
            result = self.value(parsed, depth + 1) if clean else self._plain(parsed, depth + 1)
            if clean and (result != parsed or duplicate):
                self.changed = True
                encoded = json.dumps(result, ensure_ascii=False, allow_nan=False,
                                     separators=(',', ':'))
                self._spend(len(encoded))
                encoded = _SURROGATE.sub(
                    lambda match: '\\u%04x' % ord(match[0]), encoded)
                parts.extend((text[start:left], encoded, text[right:finish]))
            else:
                parts.append(text[start:finish])
        return ''.join(parts)

    def text(self, text, depth=0, schema=False, jsonl=None):
        self._check_text(text)
        if jsonl is True:
            self._spend(len(text) * (len(self.known) + 15))
            return self._jsonl_text(text, depth, self.policy.enabled and not schema)
        if schema or not self.policy.enabled or text == MARKER:
            return text
        self._spend(len(text) * (len(self.known) + 15))
        if jsonl is None and self.detect_jsonl(text, checked=True):
            return self._jsonl_text(text, depth, True)
        original = text
        if text.lstrip().startswith(('{', '[', '"')):
            duplicate = []
            try:
                check_json_budget(
                    text, max_depth=MAX_DEPTH - depth,
                    max_nodes=MAX_NODES - self.nodes - self.json_nodes)
                parsed = json.loads(text, object_pairs_hook=lambda items: _pairs(items, duplicate))
            except ValueError:
                pass
            else:
                clean = self.value(parsed, depth + 1)
                if clean != parsed or duplicate:
                    self.changed = True
                    return json.dumps(clean, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
                return text
            if re.search(r'\\u[0-9a-fA-F]{4}', text):
                # 字段名等含 Unicode 转义时纯文本回退可能漏洗；只遮盖这个字符串。
                self.changed = True
                return MARKER
        protected = []
        covered = 0
        for match in _ASSIGN.finditer(text):
            if match.start() < covered:
                continue
            action = self._field(match['key'])
            if action is None:
                continue
            normal = _normal(match['key'].casefold())
            finish = self._end(text, match.end(), normal in (
                'cookie', 'setcookie', 'authorization', 'auth', '授权', '凭据'))
            covered = finish
            if action == 'allow':
                protected.append((match.start(), finish))
        for match in _QUERY.finditer(text):
            if unquote_plus(match[2]).casefold() in self.policy.allow_fields:
                protected.append((match.start(), match.end()))
        parts = []
        end = 0
        for start, finish in sorted(protected):
            if start < end:
                continue
            parts.extend((self._scrub_text(text[end:start]), text[start:finish]))
            end = finish
        parts.append(self._scrub_text(text[end:]))
        text = ''.join(parts)
        if text != original:
            self.changed = True
            return text
        return original

    def _scrub_text(self, text):
        text = _PRIVATE.sub(MARKER, text)
        text = _QUERY.sub(lambda match: match[1] + match[2] + '=' + MARKER
                          if _label(unquote_plus(match[2]), self.policy) else match[0], text)
        text = self._assignments(text)
        text = _USERINFO.sub(lambda match: match[1] + MARKER + '@', text)
        text = _AUTH.sub(MARKER, text)
        return _replace_known(text, self.known)


def _raw_boundary_index(pieces, starts, raw_index):
    for raw, raw_length, decoded, decoded_length in pieces:
        if raw_index == raw:
            return decoded
        if raw_index == raw + raw_length:
            return decoded + decoded_length
        if raw < raw_index < raw + raw_length:
            if raw_length == decoded_length:
                return decoded + raw_index - raw
            return None
    return None


def _known_crossing_start(text, cut, known):
    if not known:
        return None
    width = max(map(len, known)) * 12
    left = max(0, cut - width)
    right = min(len(text), cut + width)
    decoded, pieces = _decode(text[left:right])
    starts = [part[2] for part in pieces]
    boundary = _raw_boundary_index(pieces, starts, cut - left)
    if boundary is None:
        raise OverflowError('secret boundary overlaps an encoded character')
    for secret in known:
        low = max(0, boundary - len(secret) + 1)
        search_end = min(len(decoded), boundary + len(secret))
        position = decoded.find(secret, low, search_end)
        while 0 <= position < boundary:
            raw_start = _raw_boundary(pieces, starts, position)
            raw_end = _raw_boundary(pieces, starts, position + len(secret), end=True)
            if raw_start < cut - left < raw_end:
                return left + raw_start
            position = decoded.find(secret, position + 1, search_end)
    return None


def _pending_context_start(text, cleaner):
    end = len(text.rstrip())
    start = max(0, end - MAX_FIELD - 4)
    # 用虚拟分隔符识别尚未完成的标签，探测串只含有界后缀。
    probe = text[start:end] + '='
    for match in _ASSIGN.finditer(probe):
        if match.end() == len(probe) and cleaner._field(match['key']) is not None:
            return start + match.start()
    match = re.search(r'(?i)\b(?:Bearer|Basic)\Z', text[start:end])
    return start + match.start() if match is not None else None


def safe_record_cut(text, known=(), policy=None, eof=False, cleaner=None, jsonl=False):
    """返回不拆分当前脱敏上下文的有界换行位置。"""
    if type(text) is not str:
        raise RedactionError('invalid text record')
    rules = as_policy(policy)
    if cleaner is None:
        cleaner = Cleaner(known, rules)
    elif not isinstance(cleaner, Cleaner):
        raise RedactionError('invalid text cleaner')
    else:
        rules = cleaner.policy
    cleaner._check_text(text)
    cleaner._spend(len(text) * 4)
    known = cleaner.known

    if jsonl:
        if eof:
            return len(text)
        cut = text.rfind('\n') + 1
        if cut <= 0:
            raise OverflowError('no complete JSONL record')
        return cut

    # Keep a value following a sensitive key across line whitespace in one record.
    assignment_count = 0
    for match in _ASSIGN.finditer(text):
        assignment_count += 1
        if assignment_count > MAX_NODES:
            raise OverflowError('redaction boundary node budget exceeded')
        if cleaner._field(match['key']) != 'redact':
            continue
        line_end = text.find('\n', match.end())
        if (line_end >= 0 and not text[match.end():line_end].strip()
                and text[line_end + 1:].strip()):
            raise OverflowError('ambiguous multiline sensitive assignment')

    if eof:
        return len(text)

    lookahead = max((len(item) for item in known), default=0) * 12
    limit = max(0, len(text) - lookahead)
    cut = text.rfind('\n', 0, limit + 1) + 1
    if cut <= 0:
        raise OverflowError('no complete safe text record')

    # A large multi-line JSON document has unbounded field context. Accept
    # complete JSON records on a line; reject visibly incomplete JSON records.
    def json_record(item):
        if not item or item[0] not in '{["':
            return False
        try:
            check_json_budget(item, max_depth=MAX_DEPTH, max_nodes=MAX_NODES)
            json.loads(item)
            return True
        except (ValueError, OverflowError, RecursionError):
            depth = 0
            quote = None
            escaped = False
            for char in item:
                if quote is not None:
                    if escaped:
                        escaped = False
                    elif char == '\\':
                        escaped = True
                    elif char == quote:
                        quote = None
                elif char in ('"', "'"):
                    quote = char
                elif char in '[{':
                    depth += 1
                elif char in ']}':
                    depth -= 1
            if depth > 0 or quote is not None:
                raise OverflowError('multiline JSON record cannot be paged') from None
            return False

    json_count = 0
    prefix = text[:cut]
    for match in re.finditer(r'(?m)^[ \t]*(?:\{|\[|")', prefix):
        json_count += 1
        if json_count > MAX_NODES:
            raise OverflowError('JSON record count budget exceeded')
        line_end = prefix.find('\n', match.end())
        if line_end < 0:
            line_end = len(prefix)
        item = prefix[match.start():line_end].strip()
        json_record(item)

    pending_start = _pending_context_start(text, cleaner)
    for _ in range(MAX_SECRETS):
        cleaner._spend(len(text) * (len(known) + 4))
        unsafe_start = pending_start if pending_start is not None and pending_start < cut else None
        extend_start = None
        extend_end = None

        def crossing(start, end):
            nonlocal unsafe_start, extend_start, extend_end
            if not start < cut < end:
                return
            if end <= limit:
                extend_start = start if extend_start is None else min(extend_start, start)
                extend_end = end if extend_end is None else max(extend_end, end)
            else:
                unsafe_start = start if unsafe_start is None else min(unsafe_start, start)

        known_start = _known_crossing_start(text, cut, known)
        if known_start is not None:
            unsafe_start = known_start if unsafe_start is None else min(unsafe_start, known_start)

        for match in _ASSIGN.finditer(text):
            if match.start() >= cut:
                break
            if cleaner._field(match['key']) is None:
                continue
            normal = _normal(match['key'].casefold())
            finish = cleaner._end(text, match.end(), normal in (
                'cookie', 'setcookie', 'authorization', 'auth', '授权', '凭据'))
            if finish > cut or finish == len(text):
                crossing(match.start(), max(finish, len(text) + 1))

        for count, match in enumerate(_AUTH.finditer(text), 1):
            if count > MAX_NODES:
                raise OverflowError('authorization boundary budget exceeded')
            crossing(match.start(), match.end() if match.end() < len(text) else len(text) + 1)

        private_count = 0
        for match in _PRIVATE.finditer(text):
            private_count += 1
            if private_count > MAX_NODES:
                raise OverflowError('private key boundary budget exceeded')
            finish = _PRIVATE_END.search(text, match.start(), match.end())
            if finish is not None:
                crossing(match.start(), match.start() + finish.end())
            elif match.start() < cut:
                crossing(match.start(), len(text) + 1)

        if unsafe_start is not None:
            previous = text.rfind('\n', 0, unsafe_start) + 1
            if previous <= 0 or previous >= cut:
                raise OverflowError('sensitive text record exceeds safe read limit')
            cut = previous
            continue
        if extend_end is not None:
            next_line = text.find('\n', extend_end, limit + 1)
            if next_line >= 0:
                cut = next_line + 1
                continue
            previous = text.rfind('\n', 0, extend_start) + 1
            if previous <= 0 or previous >= cut:
                raise OverflowError('sensitive text record exceeds safe read limit')
            cut = previous
            continue
        return cut

    raise OverflowError('redaction boundary budget exceeded')


__all__ = [
    'BUILTIN_FIELDS', 'Cleaner', 'DEFAULT_POLICY', 'MARKER', 'Policy',
    'RedactionError', 'as_policy', 'credentials', 'policy', 'safe_record_cut', 'sensitive',
]
