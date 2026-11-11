"""首版固定契约；不包含凭据或宿主的可序列化副本。"""

from dataclasses import dataclass, field
from typing import Any, Callable

VERSION = 'v0.2.0'
NAMESPACE = 'OlivOSCockpit'
SERVER_INFO = {'name': 'OlivOS-Cockpit', 'version': VERSION}
MAX_BODY = 1024 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_FILE = 1024 * 1024
MAX_LOG_SCAN = 8 * 1024 * 1024
MAX_LOG_LINES = 2000
MAX_ENTRIES = 500
MAX_MANIFEST = 64 * 1024
MAX_OPK = 8 * 1024 * 1024
MAX_ZIP_DIRECTORY = 256 * 1024
MAX_ZIP_ENTRIES = 1024
MAX_DEPTH = 8
MAX_CALLS = 8
CALL_TIMEOUT = 10.0
SESSION_TTL = 1800.0
MAX_SESSIONS = 256

MODE_FULL = 'full'
MODE_LITE = 'lite'
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20000


def check_json_budget(text, max_depth=MAX_JSON_DEPTH, max_nodes=MAX_JSON_NODES):
    """在递归 JSON 解码前限制结构；不依赖宿主的进程级 recursionlimit。"""
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


class ToolError(Exception):
    """只携带可向客户端披露的安全错误。"""


@dataclass(frozen=True)
class Context:
    proc: Any
    root: str
    data_root: str
    olivos: Any = None
    # 终端调试账号：仅内存状态，记录只读发现的选中 hash 与安全错误；
    # 账号由使用者在宿主账号配置中预置，本插件从不增删宿主账号。
    terminal: dict = field(default_factory=dict, compare=False, repr=False)
    # 配置管理器只提供线程安全快照；权限模式决定调用层可用能力。
    config: Any = field(default=None, compare=False, repr=False)
    permission_mode: str = MODE_FULL
    request_generation: int | None = field(default=None, compare=False, repr=False)


@dataclass
class Outcome:
    data: Any
    is_error: bool = False
    truncated: bool = False
    after_send: Callable[[], None] | None = None
    page: Any = field(default=None, repr=False)


@dataclass(frozen=True)
class ToolSpec:
    """capability/required_permission 是内部授权元数据，不进入 definition。"""

    name: str
    description: str
    schema: dict
    handler: Callable[[Context, dict], Outcome]
    read_only: bool = True
    capability: str | None = None
    required_permission: str | None = None

    def definition(self):
        # 只输出协议字段；授权元数据仍由调用层按快照判定，MCP readOnlyHint 不是授权。
        return {
            'name': self.name,
            'description': self.description,
            'inputSchema': self.schema,
            'annotations': {'readOnlyHint': self.read_only},
        }


def object_schema(properties=None, required=()):
    return {
        'type': 'object',
        'properties': properties or {},
        'required': list(required),
        'additionalProperties': False,
    }


def validate_arguments(spec, args):
    """只验证本项目实际使用的 schema 子集，不冒充通用 JSON Schema 实现。"""
    if type(args) is not dict:
        raise ToolError('arguments must be an object')
    schema = spec.schema
    properties = schema.get('properties', {})
    if set(args) - set(properties):
        raise ToolError('Unknown argument')
    if set(schema.get('required', ())) - set(args):
        raise ToolError('Missing required argument')
    types = {'string': str, 'integer': int, 'boolean': bool, 'object': dict, 'array': list}
    for name, value in args.items():
        rule = properties[name]
        expected = types.get(rule.get('type'))
        if expected is not None and type(value) is not expected:
            raise ToolError('Invalid argument type')
        if 'enum' in rule and value not in rule['enum']:
            raise ToolError('Invalid argument value')
        if type(value) is str:
            if len(value) < rule.get('minLength', 0) or len(value) > rule.get('maxLength', MAX_FILE):
                raise ToolError('Invalid argument length')
        if type(value) is int:
            if value < rule.get('minimum', value) or value > rule.get('maximum', value):
                raise ToolError('Argument out of range')
    return args


def failure(message='Operation failed safely'):
    return Outcome({'error': message}, is_error=True)
