"""Full 专属的实例级入站规则；不等待客户端、不做 I/O、不拦截插件出站。

install(ctx) 应先于共享 raw.install(ctx)，使观察器先记录原数据。规则只在
当前加载器内存中存在；权限、配置代次或账号身份变化后必须重新设置规则。
异常、超限和锁竞争均旁路，不改变原宿主调用的返回值或异常。
"""

import asyncio
import json
import math
import threading
from dataclasses import dataclass, field

from . import host, raw
from .config import ConfigManager, Snapshot
from .contracts import MODE_FULL, Outcome, ToolError, ToolSpec, object_schema, validate_arguments

MAX_RULES = 16
MAX_MESSAGE_BYTES = 64 * 1024
MAX_RULE_BYTES = 256 * 1024
MAX_SDK_BYTES = 256 * 1024
MAX_DEPTH = 8
MAX_NODES = 4000
PERMISSION = 'low_level_access'
_STAGES = ('sdk_in', 'processed_in')
_EVENTS = ('private_message', 'group_message')
_ACTIONS = ('drop', 'replace_text')
_MODES = ('old_string', 'olivos_string', 'olivos_para')
_MARKER = '_olivos_cockpit_intercept_controller'
_MISSING = object()

# 与 raw 共用同一份 V11 文本模型清单，coverage 不会与观察器分叉。
# 不含共享 onebot 名称的 V12/Red/Milky/OPQ 模型。
_ONEBOT_MODELS = raw.ONEBOT_V11_MODELS


def _coverage():
    return {
        'source_baseline': 'OlivOS 1.0.2-beta.3 c6a99fc2a3b4cc7dd1ea8e7b6fe762b7bee7c7d4',
        'hooks': {
            'sdk_in': 'current Proc.run_plugin(sdk_event), before API.Event conversion',
            'processed_in': 'current Proc.plugin_event_router, before each plugin callback',
        },
        'adapters': {
            'onebot_v11': {'sdk': 'onebot', 'platform': 'qq', 'models': list(_ONEBOT_MODELS)},
            'virtual_terminal': {'sdk': 'terminal_link', 'platform': 'terminal', 'models': ['default']},
        },
        'event_types': list(_EVENTS),
        'processed_message_modes': list(_MODES),
        'excluded': [
            'other SDK event classes and account models (including terminal postapi/ff14)',
            'OneBot guild/discuss, sent messages, notices, requests and API responses',
            'control-plane, menu, WebUI, outbound calls and frames discarded before run_plugin',
        ],
        'semantics': (
            'Rules bind an existing bot object and match bot_hash + stage + exact event_type. '
            'drop skips the current call and, at processed_in, blocks subsequent plugins. '
            'replace_text changes message bodies only; it is not a sandbox for triggered plugins. '
            'Rule registration is not evidence that any event has matched. Unsupported payloads, '
            'unsupported message modes, exceptions and lock contention pass through; contention is not counted. '
            'Configuration generation changes clear rules; already applied changes are not undone.'
        ),
        'limits': {
            'rules': MAX_RULES, 'message_utf8_bytes': MAX_MESSAGE_BYTES,
            'rules_json_bytes': MAX_RULE_BYTES, 'sdk_copy_bytes': MAX_SDK_BYTES,
            'sdk_copy_nodes': MAX_NODES, 'sdk_copy_depth': MAX_DEPTH,
        },
    }


def _failure(message):
    return Outcome({'error': message, 'coverage': _coverage()}, is_error=True)


def _fields(value):
    # 直接读实例 __dict__，不触发自定义 __getattribute__ 或 property。
    try:
        value = object.__getattribute__(value, '__dict__')
    except BaseException:
        raise ToolError('Unsupported host object layout') from None
    if type(value) is not dict:
        raise ToolError('Unsupported host object layout')
    return value


def _identifier(value):
    if type(value) is int and value.bit_length() <= 64:
        return str(value)
    if type(value) is str and 0 < len(value) <= 128 and '\x00' not in value:
        return value
    raise ToolError('Invalid account identity')


def _triple(value):
    if type(value) is not dict:
        raise ToolError('Invalid account platform')
    triple = tuple(value.get(key) for key in ('sdk', 'platform', 'model'))
    if any(type(item) is not str or len(item) > 128 for item in triple):
        raise ToolError('Invalid account platform')
    return triple


def _adapter(triple):
    if triple[:2] == ('onebot', 'qq') and triple[2] in _ONEBOT_MODELS:
        return 'onebot_v11'
    if triple == ('terminal_link', 'terminal', 'default'):
        return 'virtual_terminal'
    raise ToolError('Unsupported account adapter/model; see coverage')


def _published(ctx):
    """当前已发布的开关与代次；不检查请求代次或调用方权限模式。"""
    manager = ctx.config
    if type(manager) is not ConfigManager:
        return None
    current = _fields(manager).get('_snapshot')
    if (type(current) is Snapshot and current.valid is True and current.ready
            and current.full_real_account_write is True and current.full_low_level_access is True
            and type(current.generation) is int):
        return current
    return None


def _current(ctx):
    """工具调用可见的策略：还要求 Full 模式且请求代次仍是当前发布的代次。"""
    if ctx.permission_mode != MODE_FULL:
        return None
    current = _published(ctx)
    if current is None:
        return None
    expected = getattr(ctx, 'request_generation', None)
    if expected is not None and current.generation != expected:
        return None
    return current


def _copy_json(value, budget, depth=0):
    budget[0] += 1
    if depth > MAX_DEPTH or budget[0] > MAX_NODES:
        raise ToolError('SDK payload exceeds copy limits')
    if value is None or type(value) is bool:
        copied, size = value, 1
    elif type(value) is int and value.bit_length() <= 64:
        copied, size = value, 8
    elif type(value) is float and math.isfinite(value):
        copied, size = value, 8
    elif type(value) is str and len(value) <= MAX_SDK_BYTES:
        copied, size = value, len(value.encode('utf-8'))
    elif type(value) is list and len(value) <= MAX_NODES:
        return [_copy_json(item, budget, depth + 1) for item in value]
    elif type(value) is dict and len(value) <= MAX_NODES:
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ToolError('SDK payload is not native JSON')
            result[_copy_json(key, budget, depth + 1)] = _copy_json(item, budget, depth + 1)
        return result
    else:
        raise ToolError('SDK payload is not bounded native JSON')
    budget[1] += size
    if budget[1] > MAX_SDK_BYTES:
        raise ToolError('SDK payload exceeds copy limits')
    return copied


@dataclass(frozen=True)
class _Rule:
    id: str
    bot_hash: str
    stage: str
    event_type: str
    action: str
    message: str | None
    bot: object = field(repr=False)
    self_id: str
    platform: tuple
    adapter: str

    def public(self):
        result = {key: getattr(self, key) for key in ('id', 'bot_hash', 'stage', 'event_type', 'action')}
        if self.action == 'replace_text':
            result['message'] = self.message
        return result


class _Controller:
    def __init__(self, ctx, originals, previous):
        self.ctx = ctx
        self.proc = ctx.proc
        self.originals = originals
        self.previous = previous
        self.active = False
        self._lock = threading.Lock()
        self._rules = ()
        self._epoch = None
        self._counts = {'sdk_in_drop': 0, 'sdk_in_replace_text': 0,
                        'processed_in_drop': 0, 'processed_in_replace_text': 0, 'bypassed': 0}
        self._last_bypass = None
        olivos = ctx.olivos
        self.sdk_types = {
            'onebot_v11': getattr(getattr(olivos, 'onebotSDK', None), 'event', None),
            'virtual_terminal': getattr(getattr(olivos, 'virtualTerminalSDK', None), 'event', None),
        }
        api = getattr(olivos, 'API', None)
        # 与 raw 共用宿主账号指纹；缺失能力时注册与匹配安全失败。
        self.native_hash = getattr(api, 'getBotHash', None)
        self.event_type = getattr(api, 'Event', None)
        self.data_types = {name: getattr(self.event_type, name, None) for name in _EVENTS}
        self.packet_type = getattr(getattr(api, 'Control', None), 'packet', None)
        message_api = getattr(olivos, 'messageAPI', None)
        self.template_type = getattr(message_api, 'Message_templet', None)
        self.text_type = getattr(getattr(message_api, 'PARA', None), 'text', None)

        def run_plugin(sdk_event):
            try:
                replacement, dropped = self.apply('sdk_in', sdk_event)
            except BaseException:
                # 旁路：原宿主方法仍在下方恰好调用一次。
                replacement, dropped = sdk_event, False
            if not dropped:
                return originals['run_plugin'](replacement)
            return None

        def plugin_event_router(plugin_event, plugin_model, plugin_name):
            try:
                _, dropped = self.apply('processed_in', plugin_event)
            except BaseException:
                dropped = False
            if not dropped:
                return originals['plugin_event_router'](plugin_event, plugin_model, plugin_name)
            return None

        self.wrappers = {'run_plugin': run_plugin, 'plugin_event_router': plugin_event_router}

    def hooks_present(self):
        fields = _fields(self.proc)
        run = fields.get('run_plugin')
        observer = getattr(run, '_olivos_cockpit_raw_observer', None)
        sdk_hook = (run is self.wrappers['run_plugin'] or
                    (type(observer) is raw.Observer and observer.proc is self.proc
                     and observer.original is self.wrappers['run_plugin']))
        return sdk_hook and fields.get('plugin_event_router') is self.wrappers['plugin_event_router']

    def sync(self, current):
        epoch = (id(self.ctx.config), current.generation) if current is not None else None
        if epoch != self._epoch or current is None:
            self._rules = ()
            self._epoch = epoch

    def bound(self, rule):
        bots = host.bot_info_dict(self.proc)
        if bots is None or bots.get(rule.bot_hash) is not rule.bot:
            return False
        fields = _fields(rule.bot)
        return (type(fields.get('hash')) is str and fields['hash'] == rule.bot_hash
                and fields.get('enable', True) is True and _identifier(fields.get('id')) == rule.self_id
                and _triple(fields.get('platform')) == rule.platform)

    def digest(self, self_id, sdk, platform):
        """宿主 getBotHash；缺失、抛错或返回非 32 位字符串时安全失败。"""
        if not callable(self.native_hash):
            raise ToolError('Host account hash API unavailable')
        try:
            value = self.native_hash(
                bot_id=self_id, platform_sdk=sdk, platform_platform=platform,
                platform_model=None)
        except asyncio.CancelledError:
            raise
        except BaseException:
            raise ToolError('Host account hash API unavailable') from None
        if type(value) is not str or len(value) != raw.HASH_LENGTH:
            raise ToolError('Host account hash API returned an unsupported value')
        return value

    def compile(self, values):
        if type(values) is not list or len(values) > MAX_RULES:
            raise ToolError('rules must be an array of at most 16 rules')
        rules, ids, conditions, total = [], set(), set(), 0
        bots = host.bot_info_dict(self.proc)
        if bots is None:
            raise ToolError('Configured account list unavailable')
        for value in values:
            required = {'id', 'bot_hash', 'stage', 'event_type', 'action'}
            if (type(value) is not dict or len(value) > 6 or set(value) - required - {'message'}
                    or required - set(value)):
                raise ToolError('Rule fields must match the fixed rule schema')
            for key in required:
                item = value[key]
                limit = 64 if key == 'id' else 32
                if type(item) is not str or not 0 < len(item) <= limit or '\x00' in item:
                    raise ToolError('Invalid rule field')
            if value['stage'] not in _STAGES or value['event_type'] not in _EVENTS or value['action'] not in _ACTIONS:
                raise ToolError('Unsupported rule stage, event_type or action')
            message = value.get('message')
            if value['action'] == 'replace_text':
                if type(message) is not str or len(message) > MAX_MESSAGE_BYTES or '\x00' in message:
                    raise ToolError('replace_text requires bounded UTF-8 message text')
                if len(message.encode('utf-8')) > MAX_MESSAGE_BYTES:
                    raise ToolError('message exceeds 64 KiB UTF-8')
                if '[CQ:' in message or '[OP:' in message:
                    raise ToolError('CQ/OP segment syntax is not supported; replacement is plain text only')
                total += len(message.encode('utf-8'))
            elif 'message' in value:
                raise ToolError('drop must not contain message')
            condition = (value['bot_hash'], value['stage'], value['event_type'])
            if value['id'] in ids or condition in conditions:
                raise ToolError('Duplicate rule id or condition')
            ids.add(value['id'])
            conditions.add(condition)
            if total > MAX_RULE_BYTES:
                raise ToolError('Rules exceed the total size limit')
            bot = bots.get(value['bot_hash'])
            if bot is None:
                raise ToolError('Unknown bot_hash')
            fields = _fields(bot)
            triple = _triple(fields.get('platform'))
            self_id = _identifier(fields.get('id'))
            digest = self.digest(self_id, triple[0], triple[1])
            if (type(fields.get('hash')) is not str or fields['hash'] != value['bot_hash']
                    or digest != value['bot_hash']):
                raise ToolError('Configured account hash/identity conflict')
            adapter = _adapter(triple)
            if not isinstance(self.sdk_types[adapter], type):
                raise ToolError('Host SDK event class unavailable for this adapter')
            if adapter == 'virtual_terminal' and not isinstance(self.packet_type, type):
                raise ToolError('Host terminal packet class unavailable')
            if value['stage'] == 'processed_in':
                if not isinstance(self.event_type, type) or not isinstance(self.data_types[value['event_type']], type):
                    raise ToolError('Host core message event class unavailable')
                if value['action'] == 'replace_text' and not (
                        isinstance(self.template_type, type) and isinstance(self.text_type, type)):
                    raise ToolError('Host text message template unavailable')
            rule = _Rule(**{key: value[key] for key in required}, message=message,
                         bot=bot, self_id=self_id, platform=triple, adapter=adapter)
            if not self.bound(rule):
                raise ToolError('Configured account changed or is disabled')
            rules.append(rule)
        if len(json.dumps([rule.public() for rule in rules], ensure_ascii=False).encode('utf-8')) > MAX_RULE_BYTES:
            raise ToolError('Rules exceed the total JSON size limit')
        return tuple(rules)

    def sdk_view(self, event):
        fields = _fields(event)
        if fields.get('active') is not True:
            raise ToolError('Inactive SDK event')
        triple = _triple(fields.get('platform'))
        if type(event) is self.sdk_types['onebot_v11'] and triple == ('onebot', 'qq', 'default'):
            adapter = 'onebot_v11'
        elif (type(event) is self.sdk_types['virtual_terminal']
              and triple == ('terminal_link', 'terminal', 'default')):
            adapter = 'virtual_terminal'
        else:
            raise ToolError('Unsupported SDK class/platform; see coverage')
        base = fields.get('base_info')
        if type(base) is not dict:
            raise ToolError('Invalid SDK account identity')
        self_id = _identifier(base.get('self_id'))
        if adapter == 'onebot_v11':
            payload = fields.get('json')
            if (type(payload) is not dict or 'retcode' in payload or base.get('post_type') != 'message'
                    or payload.get('post_type') != 'message' or _identifier(payload.get('self_id')) != self_id):
                raise ToolError('Unsupported or conflicting OneBot inbound identity')
            if payload.get('message_type') == 'private':
                event_type = 'private_message'
            elif payload.get('message_type') == 'group' and payload.get('sub_type') == 'normal':
                event_type = 'group_message'
            else:
                raise ToolError('Unsupported OneBot inbound message type')
        else:
            packet = fields.get('payload')
            if type(packet) is not self.packet_type or fields.get('event_id') is not None:
                raise ToolError('Unsupported terminal input payload')
            packet_fields = _fields(packet)
            key = packet_fields.get('key')
            data = key.get('data') if type(key) is dict else None
            if (packet_fields.get('action') != 'send' or type(data) is not dict
                    or data.get('action') != 'input'):
                raise ToolError('Unsupported terminal input action')
            target = key.get('target')
            digest = self.digest(self_id, 'terminal_link', 'terminal')
            if target is not None and (type(target) is not dict or target.get('type') != 'terminal_link'
                                       or target.get('hash') != digest):
                raise ToolError('Terminal packet account routing conflict')
            user = data.get('user_conf')
            if user is not None and type(user) is not dict:
                raise ToolError('Unsupported terminal user configuration')
            flag = user.get('flag_group', True) if user is not None else True
            if type(flag) is not bool:
                raise ToolError('Unsupported terminal message type')
            event_type = 'group_message' if flag else 'private_message'
        return adapter, self_id, event_type

    def core_view(self, event):
        if type(event) is not self.event_type:
            raise ToolError('Unsupported core Event class')
        fields = _fields(event)
        sdk = fields.get('sdk_event')
        view = self.sdk_view(sdk)
        info, base = fields.get('plugin_info'), fields.get('base_info')
        if (fields.get('active') is not True or fields.get('blocked') is not False
                or fields.get('sdk_event_type') is not type(sdk) or type(info) is not dict
                or type(base) is not dict or _identifier(base.get('self_id')) != view[1]
                or _triple(fields.get('platform')) != _triple(_fields(sdk).get('platform'))
                or info.get('func_type') != view[2] or type(fields.get('data')) is not self.data_types[view[2]]):
            raise ToolError('Core Event identity or message type conflict')
        return view

    def rebuild(self, event, rule):
        fields = _fields(event)
        expected = {'raw', 'json', 'platform', 'active', 'base_info'} if rule.adapter == 'onebot_v11' else {
            'payload', 'event_id', 'platform', 'active', 'base_info'}
        if len(fields) != len(expected) or set(fields) != expected:
            raise ToolError('Unsupported SDK object layout')
        budget = [0, 0]
        if rule.adapter == 'onebot_v11':
            copied = _copy_json(fields, budget)
            if type(copied['raw']) is not str or json.loads(copied['raw']) != copied['json']:
                raise ToolError('OneBot raw/json payload conflict')
            copied['json']['message'] = rule.message
            if 'raw_message' in copied['json']:
                copied['json']['raw_message'] = rule.message
            copied['raw'] = json.dumps(copied['json'], ensure_ascii=False, allow_nan=False)
            if len(copied['raw'].encode('utf-8')) > MAX_SDK_BYTES:
                raise ToolError('Rebuilt SDK payload exceeds size limit')
        else:
            copied = _copy_json({key: value for key, value in fields.items() if key != 'payload'}, budget)
            packet_fields = _fields(fields['payload'])
            if len(packet_fields) != 2 or set(packet_fields) != {'action', 'key'}:
                raise ToolError('Unsupported terminal packet layout')
            packet_copy = _copy_json(packet_fields, budget)
            packet_copy['key']['data']['data'] = rule.message
            if len(json.dumps({'event': copied, 'packet': packet_copy}, ensure_ascii=False,
                              allow_nan=False).encode('utf-8')) > MAX_SDK_BYTES:
                raise ToolError('Rebuilt SDK payload exceeds size limit')
            packet = object.__new__(self.packet_type)
            _fields(packet).update(packet_copy)
            copied['payload'] = packet
        # 只重建精确 SDK 类的已知字段；不复制或字符串化任意宿主对象。
        replacement = object.__new__(type(event))
        _fields(replacement).update(copied)
        if self.sdk_view(replacement) != (rule.adapter, rule.self_id, rule.event_type):
            raise ToolError('Rebuilt SDK event identity conflict')
        return replacement

    def message_patch(self, event, message):
        mode = _fields(event)['plugin_info'].get('message_mode_tx')
        if mode not in _MODES:
            raise ToolError('Unsupported processed message mode; see coverage')
        template = self.template_type('olivos_para', [self.text_type(message)])
        original = self.template_type('olivos_para', [self.text_type(message)])
        if (_fields(template).get('active') is not True or _fields(original).get('active') is not True):
            raise ToolError('Host text message construction failed')
        rendered = template.get(mode)
        raw_rendered = original.get(mode)
        if mode != 'olivos_para' and (type(rendered) is not str or rendered != message
                                     or type(raw_rendered) is not str or raw_rendered != message):
            raise ToolError('Host plain-text message conversion failed')
        if mode == 'olivos_para' and (rendered is not template or raw_rendered is not original):
            raise ToolError('Host message template conversion failed')
        return {'message': rendered, 'raw_message': raw_rendered,
                'message_sdk': template, 'raw_message_sdk': original}

    def apply(self, stage, event):
        if not self.active or not self._lock.acquire(blocking=False):
            return event, False
        try:
            current = _current(self.ctx)
            self.sync(current)
            if current is None or not self._rules or not self.hooks_present():
                return event, False
            if not any(rule.stage == stage for rule in self._rules):
                return event, False
            view = self.sdk_view(event) if stage == 'sdk_in' else self.core_view(event)
            adapter, self_id, event_type = view
            digest = self.digest(
                self_id, 'onebot' if adapter == 'onebot_v11' else 'terminal_link',
                'qq' if adapter == 'onebot_v11' else 'terminal')
            rule = next((rule for rule in self._rules if rule.stage == stage and rule.bot_hash == digest
                         and rule.event_type == event_type and rule.adapter == adapter), None)
            if rule is None:
                return event, False
            if not self.bound(rule) or (stage == 'processed_in' and _fields(event).get('bot_info') is not rule.bot):
                raise ToolError('Configured account identity changed')
            replacement, patch = event, None
            data = _fields(event).get('data') if stage == 'processed_in' else None
            if rule.action == 'replace_text':
                if stage == 'sdk_in':
                    replacement = self.rebuild(event, rule)
                else:
                    patch = self.message_patch(event, rule.message)
            # 副作用前重新读取最新双开关和代次；不撤回已提交的更改。
            if (not self.active or _current(self.ctx) is not current or not self.bound(rule)
                    or not self.hooks_present()):
                self.sync(_current(self.ctx))
                return event, False
            if stage == 'processed_in':
                if self.core_view(event) != view or _fields(event)['data'] is not data:
                    raise ToolError('Core Event changed before rule commit')
                if rule.action == 'drop':
                    _fields(event)['blocked'] = True
                else:
                    _fields(data).update(patch)
            key = stage + '_' + rule.action
            self._counts[key] = min(self._counts[key] + 1, 2 ** 31 - 1)
            return replacement, rule.action == 'drop'
        except BaseException as exc:
            self._counts['bypassed'] = min(self._counts['bypassed'] + 1, 2 ** 31 - 1)
            self._last_bypass = str(exc) if type(exc) is ToolError else 'Interception failed safely'
            return event, False
        finally:
            self._lock.release()

    def report(self):
        return {'installed': self.active and self.hooks_present(),
                'generation': self._epoch[1] if self._epoch is not None else None,
                'rules': [rule.public() for rule in self._rules], 'count': len(self._rules),
                'counts': dict(self._counts), 'last_bypass': self._last_bypass,
                'storage': 'loader memory only', 'coverage': _coverage()}

    def uninstall(self):
        self.active = False
        self._rules = ()
        fields = _fields(self.proc)
        restored = True
        for name, wrapper in self.wrappers.items():
            if fields.get(name) is wrapper:
                if self.previous[name] is _MISSING:
                    del fields[name]
                else:
                    fields[name] = self.previous[name]
            else:
                restored = False
        if fields.get(_MARKER) is self:
            del fields[_MARKER]
        return restored


def _controller(ctx):
    controller = _fields(ctx.proc).get(_MARKER) if ctx.proc is not None else None
    return controller if type(controller) is _Controller and controller.proc is ctx.proc else None


def install(ctx):
    """仅包装当前 Proc 的两个方法；成功返回 controller，缺能力/非 Full 返回 None。"""
    try:
        if ctx.permission_mode != MODE_FULL or ctx.proc is None:
            return None
        fields = _fields(ctx.proc)
        existing = _controller(ctx)
        if existing is not None:
            if not existing.active or not existing.hooks_present() or not existing._lock.acquire(blocking=False):
                return None
            try:
                existing.ctx = ctx
                existing.sync(_current(ctx))
            finally:
                existing._lock.release()
            return existing
        if _MARKER in fields:
            return None
        originals = {name: getattr(ctx.proc, name, None) for name in ('run_plugin', 'plugin_event_router')}
        if not all(callable(method) for method in originals.values()):
            return None
        previous = {name: fields.get(name, _MISSING) for name in originals}
        controller = _Controller(ctx, originals, previous)
        fields.update(controller.wrappers)
        fields[_MARKER] = controller
        controller.active = True
        return controller
    except BaseException:
        return None


def uninstall(ctx):
    """停用规则，仅恢复仍为本模块包装的方法；外层 raw 应先卸载。"""
    try:
        controller = _controller(ctx)
        return controller.uninstall() if controller is not None else False
    except BaseException:
        return False


def _intercept_rules(ctx, args):
    controller = None
    acquired = False
    try:
        controller = _controller(ctx)
        published = _published(ctx)
        authorized = host.allowed(ctx, PERMISSION) and _current(ctx) is not None
        if not authorized:
            # 只在已发布代次变化时清理；过期或未授权请求不能清掉新代次规则。
            if controller is not None:
                controller.sync(published)
            return _failure('Full real-account write and low-level access must both be enabled and ready')
        current = _current(ctx)
        validate_arguments(TOOLS[0], args)
        if controller is None or not controller.active or not controller.hooks_present():
            return _failure('Instance interception hooks unavailable; install the Full controller before raw observer')
        acquired = controller._lock.acquire(blocking=False)
        if not acquired:
            return _failure('Interception rules busy; retry without blocking the host')
        # 持锁后复核：请求代次或已发布代次变化时都不改动规则。
        latest = _current(ctx)
        if (latest is None or latest is not current
                or _published(ctx) is not published):
            controller.sync(_published(ctx))
            return _failure('Interception permissions or configuration changed; retry')
        controller.sync(latest)
        operation = args['operation']
        if operation != 'set' and 'rules' in args:
            raise ToolError('rules is only accepted with operation=set')
        rules = controller.compile(args.get('rules')) if operation == 'set' else ()
        if _current(ctx) is not latest or not controller.active or not controller.hooks_present():
            controller.sync(_published(ctx))
            return _failure('Interception permissions or configuration changed; retry')
        if operation != 'list':
            if any(not controller.bound(rule) for rule in rules):
                return _failure('Configured account changed before rule registration')
            controller._rules = rules
        return Outcome(controller.report())
    except asyncio.CancelledError:
        raise
    except ToolError as exc:
        return _failure(str(exc))
    except BaseException:
        return _failure('Interception rule operation failed safely')
    finally:
        if acquired:
            controller._lock.release()


_RULE_SCHEMA = object_schema({
    'id': {'type': 'string', 'minLength': 1, 'maxLength': 64},
    'bot_hash': {'type': 'string', 'minLength': 32, 'maxLength': 32},
    'stage': {'type': 'string', 'enum': list(_STAGES)},
    'event_type': {'type': 'string', 'enum': list(_EVENTS)},
    'action': {'type': 'string', 'enum': list(_ACTIONS)},
    'message': {'type': 'string', 'maxLength': MAX_MESSAGE_BYTES},
}, ('id', 'bot_hash', 'stage', 'event_type', 'action'))

TOOLS = (ToolSpec(
    name='cockpit_intercept_rules',
    description=(
        'Full-only in-memory inbound rules: list, atomically set the complete rule table, or clear. '
        'Requires both Full real-account write and low-level switches and a ready configuration. '
        'Exact configured bot/stage/private-or-group event matching; drop or plain-text replacement only. '
        'No CQ/OP syntax, script, expression, arbitrary field/path, credentials, or outbound interception. '
        'Configuration generation changes clear rules; rule registration does not confirm a match. '
        'See returned coverage, limits and bypass counters; triggered plugins are not sandboxed.'
    ),
    schema=object_schema({
        'operation': {'type': 'string', 'enum': ['list', 'set', 'clear']},
        'rules': {'type': 'array', 'maxItems': MAX_RULES, 'items': _RULE_SCHEMA},
    }, ('operation',)),
    handler=_intercept_rules,
    read_only=False,
    required_permission=PERMISSION,
),)

__all__ = ['TOOLS', 'install', 'uninstall']
