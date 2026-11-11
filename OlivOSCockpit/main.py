"""只建立宿主上下文和 daemon 线程，不接管宿主的进程级设置。"""

import os
import threading

from . import config, raw, registry, service, terminal
from .contracts import MODE_FULL, MODE_LITE, Context, ToolError

try:
    import OlivOS
except BaseException:
    OlivOS = None

_context = None
_manager = None
_thread = None
# 唯一待监督目标（context, manager）；监督线程只追平它，不自己持有归属。
_target = None
# 唯一有限待接替目标：旧实例让出后再尝试一次启动。
_pending = None
_lock = threading.Lock()


def _log(proc, message):
    try:
        proc.log(3, '[OlivOSCockpit] ' + message)
    except BaseException:
        pass


def _unique(items):
    """按对象身份去重，保持出现顺序；不依赖 __eq__。"""
    result = []
    for item in items:
        if item is not None and not any(item is seen for seen in result):
            result.append(item)
    return result


def _stopped(manager):
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


def _teardown(proc, managers, contexts):
    """逐步拆除旧资源：撤权并停止 → 停服务 → 卸载观察 → 卸载拦截。

    每步独立兜底，某一步失败不阻止其他步骤；清引用不代表线程已结束。
    """
    def attempt(action):
        try:
            action()
        except BaseException:
            _log(proc, 'Shutdown cleanup failed safely.')

    for manager in managers:
        attempt(manager.stop)
    attempt(service.request_stop)
    for context in contexts:
        attempt(lambda: raw.uninstall(context))
        detach = getattr(registry, 'detach', None)
        if callable(detach):
            attempt(lambda: detach(context))


def _mode():
    """Lite 产物可通过 registry.MODE 声明；缺失时按 Full 处理。"""
    return MODE_LITE if getattr(registry, 'MODE', MODE_FULL) == MODE_LITE else MODE_FULL


def _raw_policy(context):
    """采集时隔离 Lite 的真实账号原始包，只保留选中的虚拟终端。"""
    def accept(record):
        if context.permission_mode == MODE_FULL:
            return True
        manager = getattr(context, 'config', None)
        snapshot = manager.peek_snapshot() if type(manager) is config.ConfigManager else None
        allows = getattr(snapshot, 'allows', None)
        if callable(allows):
            try:
                if allows('real_account_read', MODE_LITE):
                    return True
            except BaseException:
                pass
        # 只认当前有效选择快照，并核对 default 终端三元组；不为 raw 读取做准备动作。
        selected = context.terminal.get('hash') if isinstance(context.terminal, dict) else None
        if type(selected) is not str or record.get('bot_hash') != selected:
            return False
        platform = record.get('platform')
        return (type(platform) is dict
                and platform.get('sdk') == terminal.SDK
                and platform.get('platform') == terminal.PLATFORM
                and platform.get('model') == terminal.MODEL)
    return accept


def _install_raw(context):
    attach = getattr(registry, 'attach', None)
    if callable(attach):
        try:
            attach(context)
        except BaseException:
            _log(context.proc, 'Instance interception hooks unavailable.')
    try:
        raw.install(context, policy=_raw_policy(context))
    except BaseException:
        _log(context.proc, 'Raw event observer unavailable; read-only tools remain available.')


def _current(context, manager):
    """回调归属门：只有当前目标可以发布、prepare 或撤销状态。"""
    target = _target
    return target is not None and target[0] is context and target[1] is manager


def _terminal_tick(context, manager):
    """监督循环的只读终端接缝：验证/重选，不发布配置、不清会话、不改代次。"""
    if _stopped(manager) or not _current(context, manager):
        return
    try:
        terminal.tick(context)
    except BaseException:
        _log(context.proc, 'Terminal tick failed safely.')


def _can_start():
    """service 是否已有可用路径且无未退出尽的旧实例；探测失败按不可启动处理。"""
    probe = getattr(service, 'can_start', None)
    if not callable(probe):
        return True
    try:
        return bool(probe())
    except BaseException:
        return False


def _retry_start(context, manager):
    """只消费当前待接替目标；被其他启动占位时保留，成功后停止重试。"""
    global _pending
    pending = _pending
    if pending is None or pending[0] is not context or pending[1] is not manager:
        return
    if not _current(context, manager) or _stopped(manager) or not _can_start():
        return
    with _lock:
        if _pending is not pending or not _current(context, manager) or _stopped(manager):
            return
        _pending = None
    try:
        snapshot = manager.peek_snapshot()
        result = service.apply_config(context, manager, snapshot, tools=registry.TOOLS)
        if result is False:
            if getattr(service, 'web', None) is not None and not _can_start():
                with _lock:
                    if _current(context, manager) and not _stopped(manager) and _pending is None:
                        _pending = pending
            else:
                _log(context.proc, 'Service start deferred; check host HTTP dependencies.')
    except BaseException:
        _log(context.proc, 'Service start could not be retried safely.')


def _tick(context, manager):
    """每秒监督接缝：只读终端 + 有限次数接替尝试，健康态不做 reconcile。"""
    _terminal_tick(context, manager)
    try:
        _retry_start(context, manager)
    except BaseException:
        _log(context.proc, 'Service handover retry failed safely.')


def _supervise(context, manager):
    """单监督线程：追平最新目标，宣称退出后才按身份清除 _thread。"""
    global _thread
    try:
        while True:
            _bind(context, manager)
            try:
                manager.run_forever()
            except BaseException:
                _log(context.proc, 'Configuration monitor failed safely.')
            # 在 init_after 写 _target 的同一把锁内判定退出：
            # 先读目标再抢锁会让"判活后线程退出"的交接丢失。
            with _lock:
                target = _target
                if target is None or (target[0] is context and target[1] is manager):
                    # 仅线程自身清引用；失败路径或 init 不得清一个活线程的引用。
                    if _thread is threading.current_thread():
                        _thread = None
                    return
            context, manager = target
    except BaseException:
        _log(context.proc, 'Configuration supervision could not continue safely.')


def _bind(context, manager):
    """把监督回调接到给定 manager；回调内部另有归属门。"""
    manager.set_log(lambda message: _log(context.proc, message))
    manager.set_notify(lambda snapshot: _on_config(context, manager, snapshot))
    set_tick = getattr(manager, 'set_tick', None)
    if callable(set_tick):
        set_tick(lambda: _tick(context, manager))



def _on_config(context, manager, snapshot):
    global _pending
    # 停止或已被接替的旧回调不再准备或发布；会话清理仍由服务私有 loop 负责。
    if _stopped(manager) or not _current(context, manager):
        return
    # 就绪发布额外验证只读选择，不创建或迁移账号。
    if snapshot.ready:
        try:
            terminal.prepare(context)
        except BaseException:
            context.terminal.update(checked=True, error='Debug terminal preparation failed')
    try:
        result = service.apply_config(context, manager, snapshot, tools=registry.TOOLS)
    except BaseException:
        _log(context.proc, 'Configuration change could not be applied safely.')
        return
    if result is False:
        # 无 HTTP 依赖不是暂态；只有旧实例占位才登记一次性接替。
        if getattr(service, 'web', None) is not None and not _can_start():
            with _lock:
                if _current(context, manager) and not _stopped(manager):
                    _pending = (context, manager)
        else:
            _log(context.proc, 'Service unavailable; check host HTTP dependencies.')


def _apply_context(proc, context, manager):
    """发布新 owner：清旧接替目标，旧回调随即被归属门丢弃。"""
    global _context, _manager, _target, _pending
    try:
        terminal.prepare(context)
    except BaseException:
        context.terminal.update(checked=True, error='Debug terminal preparation failed')
    _install_raw(context)
    if context.terminal.get('error'):
        _log(proc, 'Debug terminal unavailable; read-only tools remain available.')
    with _lock:
        _context = context
        _manager = manager
        _target = (context, manager)
        _pending = None


class Event:
    def init(plugin_event, Proc):
        global _context, _manager, _thread, _target, _pending
        # 在第一个可能失败的操作前先捕获旧引用；失败时仍能按对象身份清理旧资源。
        previous = _context
        previous_manager = _manager
        previous_thread = _thread
        manager = None
        try:
            root = os.getcwd()
            info = getattr(OlivOS, 'infoAPI', None)
            data = getattr(info, 'OlivOS_plugin_data_path', None)
            if type(data) is not str or not data or '\x00' in data:
                raise ToolError('Invalid host data path')
            data_root = os.path.normpath(data if os.path.isabs(data) else os.path.join(root, data))
            # 同 manager 且上下文来源全同才复用原 Context 对象（frozen，不改字段）；
            # 任一来源变化都新建 manager/Context，并撤销旧 owner 的接替目标。
            live = (previous is not None and previous.proc is Proc
                    and not _stopped(previous_manager))
            same = (live and previous.root == root and previous.data_root == data_root
                    and previous.olivos is OlivOS and previous.config is previous_manager)
            if same:
                context = previous
                manager = previous_manager
                # 初始化阶段只保存默认快照，不做阻塞 I/O。
                manager.prepare()
                try:
                    terminal.prepare(context)
                except BaseException:
                    context.terminal.update(checked=True,
                                            error='Debug terminal preparation failed')
                _install_raw(context)
                if context.terminal.get('error'):
                    _log(Proc, 'Debug terminal unavailable; read-only tools remain available.')
            else:
                # 旧 manager 必须停止，旧的监督循环才可能返回并接替新目标。
                if previous_manager is not None and not _stopped(previous_manager):
                    try:
                        previous_manager.stop()
                    except BaseException:
                        _log(Proc, 'Previous configuration monitor could not be stopped.')
                manager = config.ConfigManager(data_root, _mode())
                manager.prepare()
                _apply_context(Proc, Context(Proc, root, data_root, OlivOS,
                                             previous.terminal if live else {}, manager, _mode()),
                               manager)
        except BaseException:
            # 旧钩子、旧服务与监视线程不能因本次失败失去清理入口；
            # 新建候选尚未发布时也一并按对象身份清理。
            _teardown(Proc, _unique((previous_manager, manager)),
                      _unique((previous, _context)))
            with _lock:
                _context = None
                _manager = None
                _target = None
                _pending = None
                # 清引用不代表线程已结束：活监督器由自身按身份释放归属。
                if previous_thread is None or not previous_thread.is_alive():
                    _thread = None
            _log(Proc, 'Host context unavailable.')

    def init_after(plugin_event, Proc):
        global _thread, _manager, _target
        try:
            with _lock:
                if _context is None:
                    return
                manager = _manager if _manager is not None else _context.config
                if manager is None:
                    manager = config.ConfigManager(_context.data_root, _mode())
                    manager.prepare()
                    _manager = manager
                # 先登记目标再判线程：活线程下一轮追平，将死线程由这里接替。
                _target = (_context, manager)
                if _thread is not None and _thread.is_alive():
                    return
                _thread = threading.Thread(
                    target=_supervise, args=(_context, manager),
                    name='OlivOSCockpit-config', daemon=True,
                )
                _thread.start()
        except BaseException:
            _log(Proc, 'Could not start service thread.')

    def save(plugin_event, Proc):
        # 每步独立兜底；观察器先于内部拦截器还原，某步失败不妨碍后续清理。
        global _target, _pending
        with _lock:
            manager, context = _manager, _context
            _target = None
            _pending = None
        _teardown(Proc, _unique((manager,)), _unique((context,)))
