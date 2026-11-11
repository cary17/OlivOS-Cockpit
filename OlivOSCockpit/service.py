"""HTTP/MCP 服务：按配置快照监听、双时代分派、固定 8 个工作线程执行工具。"""

import asyncio
import errno
import hashlib
import hmac
import inspect
import queue
import secrets
import threading
from dataclasses import dataclass, field, replace
from time import monotonic

try:
    from aiohttp import web
except BaseException:
    web = None

from . import host, protocol, redaction
from .contracts import (
    CALL_TIMEOUT,
    MAX_BODY,
    MAX_CALLS,
    MAX_SESSIONS,
    MODE_FULL,
    SESSION_TTL,
    Context,
    Outcome,
    ToolError,
    failure,
    validate_arguments,
)
from .registry import TOOLS

HOST = '127.0.0.1'
INTERNAL_ERROR = -32603
_MISSING = object()
# 配置端口被占用时只做有界的后续端口尝试；不使用 0 端口（IPv4/IPv6
# 会得到不同临时端口），也不探测后释放或复用端口。
PORT_FALLBACK_ATTEMPTS = 32
FALLBACK_MIN_PORT = 1024
PERSIST_TIMEOUT = 10.0


class _Sessions:
    """仅内存会话；先清过期，再淘汰最旧。owner 为 token 摘要，轮换即失效。"""

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def create(self, version=protocol.DEFAULT_LEGACY, owner=''):
        with self._lock:
            now = monotonic()
            for key in [key for key, value in self._items.items() if value[0] <= now]:
                del self._items[key]
            while len(self._items) >= MAX_SESSIONS:
                self._items.pop(next(iter(self._items)))
            session = secrets.token_urlsafe(32)
            self._items[session] = (now + SESSION_TTL, version, owner)
            return session

    def version(self, session, owner=None):
        """单锁内返回有效会话的协商版本；无效返回 None。

        过期、淘汰或 owner 不符都按未知会话处理并清理过期项；调用方一次
        查询即可同时判定有效性与版本，消除两次加锁之间的 TOCTOU。
        """
        with self._lock:
            value = self._items.get(session)
            if value is None:
                return None
            if value[0] <= monotonic():
                del self._items[session]
                return None
            # token 轮换后旧会话按未知会话处理，客户端重新 initialize。
            if owner is not None and value[2] != owner:
                return None
            return value[1]

    def valid(self, session, owner=None):
        return self.version(session, owner) is not None

    def clear(self):
        with self._lock:
            self._items.clear()


@dataclass
class _Task:
    spec: object
    args: dict = field(repr=False)
    loop: object
    future: object = field(default=None)
    release: threading.Event = field(default_factory=threading.Event)
    delivered: bool = False
    ok: bool = False
    generation: object = 0
    guard: object = None


def _token_id(token):
    """会话归属标识：只保存 token 摘要，不保存 token 本身。"""
    if type(token) is not str or not token:
        return ''
    return hashlib.sha256(token.encode('utf-8', 'surrogateescape')).hexdigest()


@dataclass(frozen=True)
class _Policy:
    """单个请求固定的认证、授权与脱敏策略来源。"""

    token: str = field(default='', repr=False)
    generation: object = 0
    snapshot: object = field(default=None, repr=False)
    session: str = ''


def _manager_stopped(manager):
    """探测管理器是否已停止；缺失属性视为未停止，探测失败按停止处理。"""
    if manager is None:
        return True
    try:
        state = manager.stopped
    except AttributeError:
        return False
    except BaseException:
        return True
    if callable(state):
        try:
            state = state()
        except BaseException:
            return True
    return state is True


def _value(obj, names, default):
    """按候选名探测属性，不假定配置模块的字段名。"""
    for name in names:
        try:
            value = getattr(obj, name, _MISSING)
        except BaseException:
            continue
        if value is not _MISSING:
            return value
    return default


def _address_in_use(exc):
    """仅 EADDRINUSE 允许尝试后续端口；权限/地址错误保持失败关闭。"""
    if not isinstance(exc, OSError):
        return False
    codes = {errno.EADDRINUSE, getattr(errno, 'WSAEADDRINUSE', errno.EADDRINUSE)}
    return exc.errno in codes or getattr(exc, 'winerror', None) in codes


def _port_candidates(port):
    """先配置端口，随后有界自增；超过 65535 回绕到 >=1024 的端口。"""
    yield port
    candidate = port
    for _ in range(PORT_FALLBACK_ATTEMPTS):
        candidate += 1
        if candidate > 65535 or candidate < FALLBACK_MIN_PORT:
            candidate = FALLBACK_MIN_PORT
        yield candidate


def _listener_ports(runner):
    """读取已启动站点的实际端口集合；接口缺失时返回 None（无法核验）。"""
    try:
        addresses = getattr(runner, 'addresses', None)
    except BaseException:
        return None
    if not addresses:
        return None
    ports = set()
    for address in addresses:
        try:
            value = address[1]
        except (TypeError, IndexError, KeyError):
            return None
        if type(value) is not int or not 1 <= value <= 65535:
            return None
        ports.add(value)
    return ports


def _manager_of(context):
    """兼容 Context.config / Context.manager 两种挂载名；都没有时返回 None。"""
    for name in ('config', 'manager'):
        try:
            value = getattr(context, name, None)
        except BaseException:
            continue
        if value is not None:
            return value
    return None


def _read_snapshot(manager):
    if manager is None:
        return None
    reader = getattr(manager, 'snapshot', None)
    if not callable(reader):
        reader = getattr(manager, 'current', None)
    if not callable(reader):
        return None
    try:
        return reader()
    except asyncio.CancelledError:
        raise
    except BaseException:
        return None


def _generation(snapshot):
    if snapshot is None:
        return None
    return _value(snapshot, ('generation',), 0)


def _ready(snapshot):
    """快照是否具备可用认证 key；无法确认时按未就绪处理。"""
    if snapshot is None:
        return False
    flag = getattr(snapshot, 'ready', _MISSING)
    if flag is not _MISSING:
        try:
            return bool(flag)
        except BaseException:
            return False
    token = _value(snapshot, ('api_key', 'token', 'key'), '')
    return type(token) is str and bool(token)


def _supports(func, names):
    try:
        parameters = inspect.signature(func).parameters
    except (TypeError, ValueError):
        return None
    for name in names:
        if name in parameters:
            return name
    return None


def _encode_policy_key():
    return _supports(protocol.encode_reply, ('policy', 'redaction_policy'))


def _reply_policy_key():
    return _supports(protocol.reply_from, ('policy', 'redaction_policy'))


def _safe_after_send(callback):
    try:
        callback()
    except asyncio.CancelledError:
        raise
    except BaseException:
        # 响应已发送，回调失败不得逃逸工作线程。
        pass


class _Pool:
    """worker 数等于并发上限；名额被占用直到任务真正结束。"""

    def __init__(self, context):
        self.context = context
        self.slots = threading.BoundedSemaphore(MAX_CALLS)
        self.tasks = queue.SimpleQueue()
        # 退出门：close 只发哨兵，阻塞中的 SDK 调用仍占 worker；
        # 全部 worker 真正退出后 drained 才置位，不能把清 _ACTIVE 当资源已回收。
        self._live = 0
        self._live_lock = threading.Lock()
        self._closing = False
        self.drained = threading.Event()
        try:
            for index in range(MAX_CALLS):
                with self._live_lock:
                    self._live += 1
                try:
                    threading.Thread(target=self._work, name=f'OlivOSCockpit-{index}', daemon=True).start()
                except BaseException:
                    self._retire()
                    raise
        except BaseException:
            self.close()
            raise

    def submit(self, task):
        with self._live_lock:
            if self._closing or not self.slots.acquire(blocking=False):
                return False
            self.tasks.put(task)
            return True

    def close(self):
        with self._live_lock:
            if self._closing:
                return
            self._closing = True
            for _ in range(MAX_CALLS):
                self.tasks.put(None)

    def _retire(self):
        with self._live_lock:
            self._live -= 1
            if self._live <= 0:
                self.drained.set()

    def _work(self):
        while True:
            task = self.tasks.get()
            if task is None:
                self._retire()
                return
            try:
                outcome = self._run(task)
                if outcome is not None:
                    try:
                        task.loop.call_soon_threadsafe(_resolve, task, outcome)
                    except BaseException:
                        pass
                if outcome is not None and outcome.after_send is not None:
                    # 名额保留到响应发送完成或明确放弃。
                    task.release.wait()
                    # 授权版本或 key 在发送后变化时，不再执行敏感提交。
                    if task.delivered and (task.guard is None or task.guard()):
                        _safe_after_send(outcome.after_send)
            except asyncio.CancelledError:
                _cancel(task)
            except BaseException:
                # 顶层兜底也覆盖提交前 guard；不能让某个 worker 永久退出。
                try:
                    task.loop.call_soon_threadsafe(_resolve, task, failure())
                except BaseException:
                    pass
            finally:
                self.slots.release()

    def _run(self, task):
        try:
            if task.guard is not None and not task.guard():
                return failure('Tool call no longer permitted')
            context = replace(self.context, request_generation=task.generation) \
                if isinstance(self.context, Context) else self.context
            outcome = task.spec.handler(context, task.args)
        except ToolError as exc:
            return Outcome({'error': str(exc)}, is_error=True)
        except asyncio.CancelledError:
            # 取消由私有事件循环发起：把取消状态回传 future，不作为工具错误吞掉。
            _cancel(task)
            return None
        except BaseException:
            return failure()
        return outcome if isinstance(outcome, Outcome) else failure()


def _raw_reply(body, modern, status=200, headers=()):
    """脱敏关闭且协议层无策略参数时按原值编码；仍遵守响应大小上限。"""
    if modern:
        headers = tuple(headers) + (('MCP-Protocol-Version', protocol.MODERN_VERSION),)
    try:
        text = protocol.dumps(body)
    except OverflowError:
        return protocol.safe_reply(body.get('id') if type(body) is dict else None,
                                   modern, status, headers, tool=True, truncated=True)
    return protocol.Reply(status, text.encode('ascii'), tuple(headers), modern)


def _resolve(task, outcome):
    if task.future is not None and not task.future.done():
        task.future.set_result(outcome)


def _cancel(task):
    """SDK 线程内取消：在私有事件循环里取消 future；worker 继续存活。

    不在工作线程读取 future 状态，已完成时 cancel() 自然返回 False。
    """
    if task.future is None:
        return
    try:
        task.loop.call_soon_threadsafe(task.future.cancel)
    except BaseException:
        pass


class _Service:
    def __init__(self, context, token, tools, timeout, manager=None):
        self.context = context
        self.token = token
        self.tools = tuple(tools)
        self.by_name = {tool.name: tool for tool in self.tools}
        self.timeout = timeout
        self.sessions = _Sessions()
        self.manager = manager
        self.pool = _Pool(context)
        self.http_slots = threading.BoundedSemaphore(MAX_CALLS)
        self.app = None
        self.loop = None
        self.runner = None
        self.site = None
        self.bound = None
        # 未托管/无临时候选时立即放行；回退候选在写回与发布确认前为 False。
        self._serving = True
        self._dirty = False
        self._job = None
        self._closed = False

    # ---- 配置快照 -------------------------------------------------------

    def _manager(self):
        manager = getattr(self, 'manager', None)
        return manager if manager is not None else _manager_of(getattr(self, 'context', None))

    def _policy(self):
        """请求级固定策略：认证、授权与脱敏取同一快照；快照不可用时失败关闭。"""
        manager = self._manager()
        snapshot = _read_snapshot(manager)
        token = getattr(self, 'token', '') or ''
        if manager is not None:
            # 有配置管理器时只信任其快照，不回退构造期的固定 token。
            token = _value(snapshot, ('api_key', 'token', 'key'), '') if snapshot is not None else ''
        if type(token) is not str:
            token = ''
        return _Policy(token, _generation(snapshot), snapshot, _token_id(token))

    def _authorize(self, spec, args, policy):
        """显式授权：优先配置管理器判定，否则用快照 allows(permission, mode)。"""
        manager = self._manager()
        permission = spec.required_permission or spec.capability
        for name, call_args in (('authorize', (spec, args)), ('allowed', (permission,))):
            check = getattr(manager, name, None)
            if not callable(check):
                continue
            try:
                return check(*call_args) is True
            except asyncio.CancelledError:
                raise
            except BaseException:
                return False
        snapshot = policy.snapshot if policy is not None else self._policy().snapshot
        if snapshot is None:
            # 托管服务拿不到快照时失败关闭；仅有固定 token 的旧路径保持放行。
            return manager is None
        allows = getattr(snapshot, 'allows', None)
        if not callable(allows):
            return False
        mode = _value(getattr(self, 'context', None), ('permission_mode',), MODE_FULL)
        try:
            return allows(permission, mode) is True
        except asyncio.CancelledError:
            raise
        except BaseException:
            return False

    def _authorized_now(self, spec, args, generation):
        """worker 与 after_send 复核；不得从工作线程抛出。"""
        try:
            policy = self._policy()
            if self._closed or policy.generation != generation:
                return False
            return self._authorize(spec, args, policy)
        except asyncio.CancelledError:
            raise
        except BaseException:
            return False

    # ---- 监听与重绑 -----------------------------------------------------

    def _log(self, message):
        proc = getattr(getattr(self, 'context', None), 'proc', None)
        if proc is None:
            return
        try:
            proc.log(3, '[OlivOSCockpit] ' + message)
        except BaseException:
            pass

    def close(self):
        if not self._closed:
            self._closed = True
            self.pool.close()

    def schedule_reconcile(self):
        """由配置监督线程调用；非阻塞、线程安全。"""
        self._dirty = True
        loop = getattr(self, 'loop', None)
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(self._kick)
        except BaseException:
            pass

    def request_stop(self):
        # 先用现有 close/_closed 记住停止并关闭提交门，再通知 loop；
        # loop 尚未发布也不能丢弃停止意图（_run_loop 在 setup 后检查 _closed）。
        self.close()
        loop = getattr(self, 'loop', None)
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(loop.stop)
        except BaseException:
            pass

    def _kick(self):
        job = self._job
        if job is not None and not job.done():
            # 变更在重绑过程中到达：本轮结束后再按最新快照执行一次。
            self._dirty = True
            return
        if not self._dirty or self._closed or self.loop is None:
            return
        self._dirty = False
        self._job = asyncio.ensure_future(self._reconcile())
        self._job.add_done_callback(self._finished)

    def _finished(self, _job):
        if self._dirty:
            self._kick()

    async def _close_site(self, site):
        """关闭一个站点（含启动失败的半注册站点）；不吞取消。"""
        if site is None:
            return
        try:
            await site.stop()
            server = getattr(self.runner, 'server', None)
            if server is not None:
                server.pre_shutdown()
                await server.shutdown(0)
        except asyncio.CancelledError:
            raise
        except BaseException:
            pass

    async def _stop_site(self):
        site = self.site
        self.site = None
        self.bound = None
        self._serving = True
        await self._close_site(site)

    async def _reconcile(self):
        try:
            manager = self._manager()
            snapshot = _read_snapshot(manager)
            if not _ready(snapshot):
                # valid 但无 key 或快照失效：停止监听并清空旧会话，不匿名放行。
                await self._stop_site()
                self.sessions.clear()
                return
            host_name = _value(snapshot, ('listen_host',), None)
            port = _value(snapshot, ('listen_port',), None)
            if (type(host_name) is not str or not host_name
                    or type(port) is not int or not 1 <= port <= 65535):
                # 地址/端口非法是配置错误，不触发端口回退。
                await self._stop_site()
                self._log('Service configuration rejected; not listening.')
                return
            if self.site is not None and self.bound == (host_name, port):
                return
            if self.runner is None:
                await self._stop_site()
                return
            # 先停止旧监听再绑定，避免端口复用冲突；失败即停止并明确记录。
            await self._stop_site()
            await self._start_site(manager, snapshot, host_name, port)
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._log('Service configuration could not be applied safely.')

    async def _start_site(self, manager, snapshot, host_name, configured):
        """配置端口优先；仅 EADDRINUSE 时有界尝试后续端口。"""
        for port in _port_candidates(configured):
            fallback = port != configured
            if fallback:
                # 临时候选在写回并发布确认前不得放行 HTTP/worker/after_send。
                self._serving = False
            site = web.TCPSite(self.runner, host_name, port)
            try:
                await site.start()
            except asyncio.CancelledError:
                try:
                    await self._close_site(site)
                except asyncio.CancelledError:
                    pass
                raise
            except BaseException as exc:
                await self._close_site(site)
                if not _address_in_use(exc):
                    self._serving = True
                    self._log('Service could not listen on the configured address.')
                    return
                continue
            ports = _listener_ports(self.runner)
            if ports is not None and ports != {port}:
                # IPv4/IPv6 必须同端口；异常结果按失败关闭处理。
                await self._close_site(site)
                self._serving = True
                self._log('Service listener did not bind a consistent port.')
                return
            self.site = site
            self.bound = None
            if not fallback:
                self.bound = (host_name, port)
                self._serving = True
                self._log('Service listening on %s:%d.' % (host_name, port))
                return
            try:
                accepted = await self._confirm_fallback(manager, snapshot, port)
            except asyncio.CancelledError:
                try:
                    await self._stop_site()
                except asyncio.CancelledError:
                    pass
                raise
            if accepted:
                self.bound = (host_name, port)
                self._serving = True
                self._log('Service listening on %s:%d.' % (host_name, port))
                return
            await self._stop_site()
            self._log('Service could not confirm an available listening port.')
            return
        self._serving = True
        self._log('Service could not find an available port near the configured one.')

    async def _confirm_fallback(self, manager, snapshot, port):
        """持有候选端口，等待配置管理器写回并在第二次观测后发布。"""
        request = getattr(manager, 'request_listen_port', None)
        if not callable(request):
            # 无写回接口的旧管理路径：无法确认来源，直接接受但保持原语义。
            return not _manager_stopped(manager)
        expected = _value(snapshot, ('fingerprint',), None)
        if type(expected) is not str or not expected:
            return False
        try:
            future = request(port, expected)
        except asyncio.CancelledError:
            raise
        except BaseException:
            return False
        if future is None:
            return False
        accepted = False
        try:
            accepted = await asyncio.wait_for(
                asyncio.wrap_future(future), PERSIST_TIMEOUT) is True
        except asyncio.TimeoutError:
            accepted = False
        except asyncio.CancelledError:
            try:
                future.cancel()
            except BaseException:
                pass
            raise
        finally:
            if not accepted:
                try:
                    future.cancel()
                except BaseException:
                    pass
        if not accepted:
            return False
        current = _read_snapshot(self._manager())
        return (not self._closed and not _manager_stopped(manager)
                and _ready(current)
                and _value(current, ('listen_port',), None) == port)

    # ---- 请求处理 -------------------------------------------------------

    async def handle(self, request):
        if not self._serving:
            # 回退候选尚未写回并发布：不认证、不占 worker、不执行 after_send。
            return await self._write(request, protocol.safe_reply(
                None, False, 503, headers=(('Connection', 'close'),)))
        # 请求体与响应构造也占名额，不能在工具池前无界累积 1 MiB 请求。
        if not self.http_slots.acquire(blocking=False):
            return await self._write(request, protocol.safe_reply(
                None, False, 503, headers=(('Connection', 'close'),)))
        try:
            return await self._handle(request)
        finally:
            self.http_slots.release()

    async def _handle(self, request):
        ident = None
        modern = False
        task = None
        consumed = False
        rejected = None
        extra = ()
        policy = self._policy()
        try:
            self._auth(request, policy)
            if request.method != 'POST':
                reply = protocol.Reply(405, b'', (('Allow', 'POST'),))
                consumed = True
            else:
                self._limits(request)
                try:
                    raw = await asyncio.wait_for(self._body(request), self.timeout)
                except asyncio.TimeoutError:
                    raise protocol.Reject(408, protocol.INVALID_REQUEST, 'Request body timed out') from None
                message = protocol.loads(raw)
                consumed = True
                ident = message.get('id')
                params = message.get('params')
                meta = params.get('_meta') if type(params) is dict else None
                modern = type(meta) is dict and protocol.has_modern_meta(meta)
                reply, task = await self._dispatch(protocol.classify(
                    message, self._headers(request)), policy)
        except protocol.Reject as exc:
            # 未读完请求体就拒绝时必须关闭连接，避免残留 payload 污染复用连接。
            rejected = exc
            extra = () if consumed else (('Connection', 'close'),)
            reply = self._error_reply(exc, modern,
                                      ident if type(ident) in (str, int) else None, extra,
                                      policy)
        except asyncio.CancelledError:
            if task is not None:
                task.delivered = False
                task.release.set()
            raise
        except BaseException:
            reply = protocol.safe_reply(None, modern, 500)
        response = None
        try:
            if policy.generation != self._policy().generation:
                if task is not None:
                    task.ok = False
                if rejected is not None:
                    # 错误响应保留既有 HTTP 状态、头与已知 Reject 错误码，不降级为 200。
                    reply = self._error_reply(rejected, modern,
                                              ident if type(ident) in (str, int) else None,
                                              extra, policy)
                elif (task is None and reply.status == 202 and not reply.body
                        and not reply.failed):
                    # 已成功接受的通知保留 202 空正文；不从已编码字节反推请求类型。
                    pass
                elif reply.status != 200 or reply.failed:
                    reply = protocol.safe_reply(ident, modern, reply.status,
                                                tuple(reply.headers), tool=task is not None)
                else:
                    reply = protocol.safe_reply(ident, modern, tool=task is not None)
            response = await self._write(request, reply)
            if task is not None:
                task.delivered = task.ok
        except asyncio.CancelledError:
            raise
        except BaseException:
            # 连接失败：响应未完成，after_send 不执行；名额仍由 finally 归还。
            response = None
        finally:
            if task is not None:
                task.release.set()
        return response

    def _auth(self, request, policy):
        origins = request.headers.getall('Origin', [])
        if len(origins) > 1:
            raise protocol.Reject(403, protocol.INVALID_REQUEST, 'Invalid Origin')
        configured_host = _value(policy.snapshot, ('listen_host',), HOST)
        protocol.check_origin(origins[0] if origins else None, hosts=configured_host)

        # 无有效 key 时拒绝一切请求；不回退匿名放行。
        values = request.headers.getall('Authorization', [])
        if not policy.token:
            raise protocol.Reject(401, protocol.INVALID_REQUEST, 'Unauthorized',
                                  headers=(('WWW-Authenticate', 'Bearer'),))
        expected = ('Bearer ' + policy.token).encode('utf-8', 'surrogateescape')
        if len(values) != 1 or not hmac.compare_digest(
                values[0].encode('utf-8', 'surrogateescape'), expected):
            raise protocol.Reject(401, protocol.INVALID_REQUEST, 'Unauthorized',
                                  headers=(('WWW-Authenticate', 'Bearer'),))

    def _limits(self, request):
        protocol.check_content_type(request.headers.get('Content-Type'))
        protocol.check_accept(request.headers.get('Accept'))
        encoding = request.headers.get('Content-Encoding')
        if encoding is not None and encoding.strip().lower() != 'identity':
            raise protocol.Reject(415, protocol.INVALID_REQUEST, 'Unsupported Content-Encoding')
        if request.content_length is not None and request.content_length > MAX_BODY:
            raise protocol.Reject(413, protocol.INVALID_REQUEST, 'Request body too large')

    async def _body(self, request):
        chunks = []
        total = 0
        while True:
            try:
                chunk = await request.content.read(65536)
            except web.HTTPRequestEntityTooLarge:
                # aiohttp 自己的上限先触发时，也按请求体过大处理。
                raise protocol.Reject(413, protocol.INVALID_REQUEST,
                                      'Request body too large') from None
            if not chunk:
                return b''.join(chunks)
            total += len(chunk)
            if total > MAX_BODY:
                raise protocol.Reject(413, protocol.INVALID_REQUEST, 'Request body too large')
            chunks.append(chunk)

    @staticmethod
    def _headers(request):
        def one(name):
            values = request.headers.getall(name, [])
            return values[0] if len(values) == 1 else None

        sessions = request.headers.getall('Mcp-Session-Id', [])
        if len(sessions) > 1:
            raise protocol.Reject(400, protocol.INVALID_REQUEST, 'Invalid session id')
        return {
            'MCP-Protocol-Version': one('MCP-Protocol-Version'),
            'Mcp-Method': one('Mcp-Method'),
            'Mcp-Name': one('Mcp-Name'),
            'Mcp-Session-Id': protocol.session_id(sessions[0]) if sessions else None,
        }

    def _redaction_enabled(self, policy):
        snapshot = policy.snapshot if policy is not None else None
        if snapshot is None:
            return True
        # 复用共享脱敏模块的策略解析，不在服务层另建一套判定。
        reader = getattr(redaction, 'policy', None)
        if callable(reader):
            try:
                return bool(getattr(reader(snapshot), 'enabled', True))
            except asyncio.CancelledError:
                raise
            except BaseException:
                return True
        return _value(snapshot, ('redaction_enabled',), True) is not False

    def _known(self, policy=None):
        policy = policy or self._policy()
        # 关闭脱敏时不需要已知凭据快照，也不因其不可用而阻断响应。
        if not self._redaction_enabled(policy):
            return ()
        known = host.safe(lambda: redaction.credentials(
            policy.token, host.bot_info_dict(self.context.proc)))
        if known is host.MISSING:
            raise redaction.RedactionError('credential snapshot unavailable')
        return known

    def _policy_arg(self, policy):
        """仅在协议层支持时传递配置策略快照；否则按旧签名兼容。"""
        return policy.snapshot if policy is not None else None

    def _encode(self, body, modern, status=200, headers=(), policy=None, known=None, page=None):
        policy = policy or self._policy()
        try:
            key = _encode_policy_key()
            if known is None:
                known = self._known(policy)
            page_key = _supports(protocol.encode_reply, ('page',)) if page is not None else None
            if page is not None and page_key is None:
                return protocol.safe_reply(
                    body.get('id') if type(body) is dict else None,
                    modern, status, headers, tool=True)
            options = {}
            if key is not None:
                options[key] = self._policy_arg(policy)
            if page_key is not None:
                options[page_key] = page
            if key is not None or page_key is not None:
                return protocol.encode_reply(body, modern, status, headers, known, **options)
            # 协议层尚无策略参数：脱敏关闭时原值构造信封，否则按旧签名脱敏。
            if not self._redaction_enabled(policy):
                return _raw_reply(body, modern, status, headers)
            return protocol.encode_reply(body, modern, status, headers, known)
        except asyncio.CancelledError:
            raise
        except OverflowError:
            raise
        except BaseException:
            return protocol.safe_reply(body.get('id'), modern, status, headers)

    def _error_reply(self, rejected, modern, ident=None, extra=(), policy=None):
        policy = policy or self._policy()
        try:
            key = _reply_policy_key()
            known = self._known(policy)
            if key is not None:
                return protocol.reply_from(
                    rejected, modern, ident, extra, known,
                    **{key: self._policy_arg(policy)})
            if not self._redaction_enabled(policy):
                body = protocol.error_body(ident, rejected.code, rejected.message, rejected.data)
                return _raw_reply(body, modern, rejected.status,
                                  tuple(rejected.headers) + tuple(extra))
            return protocol.reply_from(rejected, modern, ident, extra, known)
        except asyncio.CancelledError:
            raise
        except BaseException:
            return protocol.safe_reply(ident, modern, rejected.status,
                                       tuple(rejected.headers) + tuple(extra), code=rejected.code)

    async def _dispatch(self, req, policy):
        if req.session is not None:
            # 单锁查询：None 即未知会话（含过期/淘汰/owner 不符），直接 404。
            negotiated = self.sessions.version(req.session, policy.session)
            if negotiated is None:
                raise protocol.Reject(404, protocol.INVALID_REQUEST, 'Unknown session')
            # 传统会话：请求未带版本头时按协商值处理，带了就必须一致。
            if req.version is not None and req.version != negotiated:
                raise protocol.Reject(400, protocol.INVALID_REQUEST, 'Protocol version mismatch')
            req.version = negotiated

        if req.notification:
            # 通知不执行工具、不写入；未知通知同样静默接受。
            return protocol.Reply(202), None

        if req.method == 'initialize':
            session = self.sessions.create(req.version, policy.session)
            result = {
                'protocolVersion': req.version,
                'capabilities': {'tools': {}},
                'serverInfo': dict(protocol.SERVER_INFO),
            }
            return self._encode(
                protocol.result_body(req.ident, result), False,
                headers=(('Mcp-Session-Id', session),
                         ('MCP-Protocol-Version', req.version)), policy=policy), None

        if req.method == 'ping':
            if req.modern:
                raise protocol.Reject(404, protocol.METHOD_NOT_FOUND, 'Method not found')
            return self._encode(protocol.result_body(req.ident, {}), False, policy=policy), None

        if req.method == 'server/discover':
            if not req.modern:
                raise protocol.Reject(404, protocol.METHOD_NOT_FOUND, 'Method not found')
            return self._encode(
                protocol.result_body(req.ident, protocol.discover_result(), True), True,
                policy=policy), None

        if req.method == 'tools/list':
            if req.params.get('cursor') is not None:
                raise protocol.Reject(400, protocol.INVALID_PARAMS, 'Unknown cursor')
            result = protocol.list_result(self.tools) if req.modern else {
                'tools': [tool.definition() for tool in self.tools]}
            return self._encode(
                protocol.result_body(req.ident, result, req.modern), req.modern,
                policy=policy), None

        if req.method == 'tools/call':
            return await self._call(req, policy)

        raise protocol.Reject(404, protocol.METHOD_NOT_FOUND, 'Method not found')

    async def _call(self, req, policy):
        name = req.params.get('name')
        spec = self.by_name.get(name) if type(name) is str else None
        if spec is None:
            raise protocol.Reject(400, protocol.INVALID_PARAMS, 'Unknown tool')
        try:
            args = validate_arguments(spec, protocol.tool_arguments(req.params))
        except ToolError as exc:
            return self._result_reply(req, spec, Outcome({'error': str(exc)}, is_error=True),
                                      policy=policy), None

        # 验证后、提交前显式授权；readOnlyHint 不参与判定。
        if not self._authorize(spec, args, policy):
            return self._result_reply(
                req, spec, failure('Tool not permitted by configuration'),
                policy=policy), None

        task = _Task(spec, args, asyncio.get_running_loop(),
                     asyncio.get_running_loop().create_future(),
                     generation=policy.generation)
        # worker 执行前与 after_send 前复核同一授权版本。
        task.guard = lambda: self._authorized_now(spec, args, policy.generation)
        if not self.pool.submit(task):
            raise protocol.Reject(503, INTERNAL_ERROR, 'Too many concurrent tool calls')

        try:
            # 超时/取消只结束等待；任务继续占名额直到真正结束。
            outcome = await asyncio.wait_for(asyncio.shield(task.future), self.timeout)
            task.ok = not outcome.is_error
        except asyncio.TimeoutError:
            # 放弃响应：放行 worker，迟到的 reload 不执行。
            task.release.set()
            outcome = failure('Tool call timed out; it may still be running')
        except BaseException:
            task.release.set()
            raise
        try:
            return self._result_reply(req, spec, outcome, task, policy=policy), task
        except BaseException:
            task.ok = False
            task.release.set()
            raise

    def _result_reply(self, req, spec, outcome, task=None, policy=None):
        policy = policy or self._policy()
        try:
            known = self._known(policy)
            # 最终信封边界统一校验/清理，并从同一份数据生成 text 与 structuredContent。
            result = self._tool_result(outcome, '', req.modern)
            reply = self._encode(
                protocol.result_body(req.ident, result, req.modern), req.modern,
                policy=policy, known=known, page=outcome.page)
            if task is not None and reply.failed:
                task.ok = False
            return reply
        except asyncio.CancelledError:
            if task is not None:
                task.ok = False
            raise
        except OverflowError:
            if task is not None:
                task.ok = False
            return protocol.safe_reply(req.ident, req.modern, tool=True, truncated=True)
        except BaseException:
            if task is not None:
                task.ok = False
            return protocol.safe_reply(req.ident, req.modern, tool=True)

    @staticmethod
    def _tool_result(outcome, text, modern):
        result = protocol.tool_result(outcome, text)
        if modern:
            meta = dict(result.get('_meta') or {})
            meta[protocol.META_SERVER] = dict(protocol.SERVER_INFO)
            result['_meta'] = meta
        return result

    @staticmethod
    async def _write(request, reply):
        kwargs = {'status': reply.status}
        if reply.body:
            kwargs['body'] = reply.body
            kwargs['content_type'] = 'application/json'
        response = web.Response(**kwargs)
        fixed = {'allow': ('Allow', ('POST',)), 'www-authenticate': ('WWW-Authenticate', ('Bearer',)),
                 'connection': ('Connection', ('close',)),
                 'mcp-protocol-version': ('MCP-Protocol-Version', protocol.SUPPORTED)}
        for name, value in reply.headers:
            if type(name) is not str or type(value) is not str:
                continue
            lowered = name.lower()
            if lowered in fixed:
                canonical, allowed = fixed[lowered]
                if value in allowed:
                    response.headers[canonical] = value
            elif lowered == 'mcp-session-id':
                try:
                    response.headers['Mcp-Session-Id'] = protocol.session_id(value)
                except protocol.Reject:
                    pass
        await response.prepare(request)
        await response.write_eof()
        return response


def _build_app(service):
    if web is None:
        raise ToolError('HTTP dependency unavailable')
    # 禁用 HTTP 自动解压，压缩请求在读取 body 前就被拒绝。
    app = web.Application(client_max_size=MAX_BODY,
                          handler_args={'auto_decompress': False})
    app['cockpit'] = service
    app.router.add_route('*', '/mcp', service.handle)

    async def cleanup(_app):
        service.close()

    app.on_cleanup.append(cleanup)
    service.app = app
    return app


def create_app(context, token, tools=TOOLS, timeout=CALL_TIMEOUT, manager=None):
    if web is None:
        raise ToolError('HTTP dependency unavailable')
    if type(token) is not str or not token:
        raise ToolError('Token required')
    return _build_app(_Service(context, token, tools, timeout, manager))


def _run_loop(service):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    runner = None
    try:
        runner = web.AppRunner(service.app, handle_signals=False)
        service.runner = runner
        loop.run_until_complete(runner.setup())
        # setup 完成后才发布 loop；此前的停止意图已由 close/_closed 记住。
        service.loop = loop
        if service._closed:
            # 已请求停止：不监听、不进入 forever，由 finally 完成清理。
            return
        # 首轮与其余轮次统一走 _kick → _job → _finished/dirty，不直接 reconcile。
        service.schedule_reconcile()
        loop.run_forever()
    finally:
        service.loop = None
        job = service._job
        service._job = None
        if job is not None and not job.done():
            job.cancel()
            try:
                loop.run_until_complete(asyncio.gather(job, return_exceptions=True))
            except BaseException:
                pass
        try:
            loop.run_until_complete(service._stop_site())
            if runner is not None:
                loop.run_until_complete(runner.cleanup())
            else:
                service.close()
        except BaseException:
            pass
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except BaseException:
            pass
        asyncio.set_event_loop(None)
        loop.close()


_ACTIVE = None
# 最近退出的托管实例：其 worker 池可能仍有阻塞调用，池未退尽前不建新池。
_RETIRED = None
_STARTING = None
_ACTIVE_LOCK = threading.Lock()


def _retire(service):
    """按身份清除活跃实例并记住它，供 can_start 检查池是否退尽。"""
    global _ACTIVE, _RETIRED
    with _ACTIVE_LOCK:
        if _ACTIVE is service:
            _ACTIVE = None
            _RETIRED = service
    service.close()


def start(context, token, port, tools=TOOLS):
    """已弃用的旧固定入口：保留同名签名以便导入兼容，调用即安全失败。

    旧入口没有配置快照，服务级放行与 handler 内代次/授权复核相互矛盾；
    请改用配置驱动的 apply_config / start_managed 入口。
    """
    raise ToolError('Fixed service entry is deprecated; use the configuration-driven managed entry')


def _construct_managed(context, manager, tools):
    """先保留唯一启动位，再建池；失败的候选同样等待 worker 退尽。"""
    global _ACTIVE, _RETIRED, _STARTING
    token = (context, manager)
    with _ACTIVE_LOCK:
        if (_ACTIVE is not None or _STARTING is not None or not _pool_released()
                or _manager_stopped(manager) or not _ready(_read_snapshot(manager))):
            return None
        _STARTING = token
    candidate = None
    published = False
    try:
        candidate = _Service(context, None, tools, CALL_TIMEOUT, manager)
        _build_app(candidate)
        with _ACTIVE_LOCK:
            if (_ACTIVE is not None or _manager_stopped(manager)
                    or not _ready(_read_snapshot(manager))):
                return None
            _ACTIVE = candidate
            published = True
        return candidate
    finally:
        with _ACTIVE_LOCK:
            if candidate is not None and not published:
                _RETIRED = candidate
                candidate.close()
            if _STARTING is token:
                _STARTING = None


def start_managed(context, manager, tools=TOOLS):
    """按配置快照监听；配置监督器经 apply_config 请求重绑，不重复建池。"""
    if web is None:
        raise ToolError('HTTP dependency unavailable')
    if manager is None or not _ready(_read_snapshot(manager)):
        # 无有效 key 时不创建服务；由 main 决定何时重试。
        raise ToolError('Configuration not ready')
    instance = _construct_managed(context, manager, tools)
    if instance is None:
        raise ToolError('Service is already active or still shutting down')
    try:
        _run_loop(instance)
    finally:
        _retire(instance)


def apply_config(context, manager, snapshot=None, tools=TOOLS):
    """配置监督线程调用：按最新快照启动或重绑；不阻塞、不重建线程池。

    返回 False 表示 service 模块本身无可用路径（缺 aiohttp 等），由 main 决定记录。
    """
    global _ACTIVE
    if web is None:
        return False
    with _ACTIVE_LOCK:
        service = _ACTIVE
        starting = _STARTING
        released = _pool_released()
    if service is not None:
        if service.context is not context or service.manager is not manager:
            # 旧实例占着入口：只有它服务的 manager 已停止才请求退出，
            # 绝不因别处的旧回调停掉当前 owner 的实例。
            if _manager_stopped(service.manager):
                service.request_stop()
            return False
        service.schedule_reconcile()
        return True
    if not _ready(snapshot if snapshot is not None else _read_snapshot(manager)):
        # 尚未就绪：不创建服务，也不匿名监听。
        return True
    if starting is not None:
        return starting[0] is context and starting[1] is manager
    if not released:
        # 上一个池的阻塞调用未退尽：不建第二个池，交给监督器稍后重试。
        return False
    started = threading.Event()
    try:
        threading.Thread(
            target=_start_managed_thread, args=(context, manager, tools, started),
            name='OlivOSCockpit-service', daemon=True,
        ).start()
    except BaseException:
        return False
    # 只等初始化完成，不等待服务结束；超时也不阻塞监督线程。
    started.wait(5)
    # 发布门可能拒绝了并发启动或已有服务接管：对当前活跃服务再补一次调度，
    # 保证本次通知对应的最新快照不会丢在启动交错里。
    with _ACTIVE_LOCK:
        active = _ACTIVE
    if active is not None and active.context is context and active.manager is manager:
        active.schedule_reconcile()
    return True


def _start_managed_thread(context, manager, tools, started):
    try:
        instance = _construct_managed(context, manager, tools)
        if instance is None:
            return
    except BaseException:
        # 线程顶层兜底；不记录第三方原始异常。
        return
    finally:
        started.set()
    try:
        _run_loop(instance)
    except BaseException:
        pass
    finally:
        _retire(instance)


def request_stop():
    """非阻塞请求托管服务退出；主要供宿主卸载或监督器使用。"""
    with _ACTIVE_LOCK:
        service = _ACTIVE
    if service is None:
        return False
    service.request_stop()
    return True


def _pool_released():
    """调用者持有 _ACTIVE_LOCK；退尽后释放对旧实例的引用。"""
    global _RETIRED
    previous = _RETIRED
    if previous is None:
        return True
    try:
        released = bool(previous.pool.drained.is_set())
    except BaseException:
        return False
    if released:
        _RETIRED = None
    return released


def can_start():
    """具备 HTTP 依赖、无活跃或启动中实例、旧池退尽时才可建立新实例。"""
    if web is None:
        return False
    with _ACTIVE_LOCK:
        return _ACTIVE is None and _STARTING is None and _pool_released()


__all__ = [
    'HOST', 'apply_config', 'create_app', 'request_stop', 'start', 'start_managed',
]
