"""本地配置与脱敏规则：只读写控制目录内的两个文件，发布不可变快照。

本模块不监听端口、不导入 aiohttp；阻塞 I/O 只发生在监督线程内。
控制目录（含临时文件）由普通文件工具永久禁止访问，见 is_protected。
"""

import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
from dataclasses import dataclass, field, replace

from . import fs
from .contracts import MODE_FULL, MODE_LITE, check_json_budget

CONFIG_NAME = 'config.json'
REDACTION_NAME = 'redaction.json'
NAMESPACE_DIR = 'OlivOSCockpit'
CONTROL_DIR = 'control'

MAX_FILE = 64 * 1024
MAX_DENIED_PATHS = 256
MAX_RULES = 256
MAX_PATH_CHARS = 1024
MAX_RULE_CHARS = 128
MAX_HOST_CHARS = 255
MAX_KEY_CHARS = 96

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 8767
KEY_PREFIX = 'OlivOS-'
POLL_INTERVAL = 1.0

VERIFYING = 'Configuration changed; verifying'
NOT_LOADED = 'Configuration not loaded'
STOPPED = 'Configuration monitor stopped'

PERMISSION_REAL_ACCOUNT_READ = 'real_account_read'
PERMISSION_REAL_ACCOUNT_WRITE = 'real_account_write'
PERMISSION_LOW_LEVEL_ACCESS = 'low_level_access'
PERMISSION_PLUGIN_INSTALL = 'plugin_install'

_KEY_RE = re.compile(r'OlivOS-[A-Za-z0-9]{32,64}\Z')
_DIR_FLAGS = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
_DIR_FLAGS |= _NOFOLLOW
_FILE_FLAGS = (os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | _NOFOLLOW
               | getattr(os, 'O_NONBLOCK', 0))
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_CLOEXEC', 0) | _NOFOLLOW


class ConfigError(Exception):
    """固定安全错误；不携带文件内容或凭据。"""


def config_template():
    return {
        'listen_host': DEFAULT_HOST,
        'listen_port': DEFAULT_PORT,
        'api_key': '',
        'redaction_enabled': True,
        'lite_real_account_read': False,
        'full_real_account_write': False,
        'full_low_level_access': False,
        'denied_paths': [],
        'full_plugin_install': False,
    }


def redaction_template():
    return {'redact_fields': [], 'allow_fields': []}


@dataclass(frozen=True)
class Snapshot:
    """不可变策略快照；api_key 不进入 repr。"""

    listen_host: str = DEFAULT_HOST
    listen_port: int = DEFAULT_PORT
    api_key: str = field(default='', repr=False)
    redaction_enabled: bool = True
    lite_real_account_read: bool = False
    full_real_account_write: bool = False
    full_low_level_access: bool = False
    denied_paths: tuple = ()
    redact_fields: tuple = ()
    allow_fields: tuple = ()
    valid: bool = False
    error: str | None = None
    generation: int = 0
    fingerprint: str | None = None
    full_plugin_install: bool = False

    @property
    def ready(self):
        return self.valid and bool(self.api_key)

    def allows(self, permission, mode):
        """默认拒绝；Lite 忽略 Full 专属字段，只在调用层判定。"""
        if not self.valid or mode not in (MODE_FULL, MODE_LITE):
            return False
        if permission is None:
            return True
        if permission == PERMISSION_REAL_ACCOUNT_READ:
            return mode == MODE_FULL or self.lite_real_account_read
        if permission == PERMISSION_REAL_ACCOUNT_WRITE:
            return mode == MODE_FULL and self.full_real_account_write
        if permission == PERMISSION_LOW_LEVEL_ACCESS:
            return (mode == MODE_FULL and self.full_real_account_write
                    and self.full_low_level_access)
        if permission == PERMISSION_PLUGIN_INSTALL:
            # 安装插件是新写入能力：Full 且已就绪，并同时具备真实写开关。
            return (mode == MODE_FULL and self.ready and self.full_real_account_write
                    and self.full_plugin_install)
        return False


def control_dir(data_root):
    if (type(data_root) is not str or not os.path.isabs(data_root) or '\x00' in data_root
            or '..' in data_root.split(os.sep)):
        return None
    return os.path.join(os.path.normpath(data_root), NAMESPACE_DIR, CONTROL_DIR)


def is_protected(data_root, path):
    """控制目录及其临时文件对所有普通文件入口永久禁止；无法确认时拒绝。

    纯路径判断，按组件比较；实际打开仍需 fs 的目录 fd 与身份校验。
    """
    control = control_dir(data_root)
    if control is None:
        return True
    if type(path) is not str or not path or '\x00' in path or '..' in path.split(os.sep):
        return True
    target = path if os.path.isabs(path) else os.path.join(data_root, path)
    try:
        target = os.path.normcase(os.path.normpath(target))
        control = os.path.normcase(os.path.normpath(control))
        return os.path.commonpath((target, control)) == control
    except (ValueError, OSError):
        return True


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _bad_constant(_name):
    raise ValueError('non-finite number')


def _json(raw, label):
    if raw.startswith(b'\xef\xbb\xbf'):
        raw = raw[3:]
    try:
        text = raw.decode('utf-8', 'strict')
        check_json_budget(text)
        value = json.loads(text, object_pairs_hook=_unique, parse_constant=_bad_constant)
    except (UnicodeDecodeError, ValueError, OverflowError, RecursionError):
        raise ConfigError(label + ' is not valid JSON') from None
    if type(value) is not dict:
        raise ConfigError(label + ' must be a JSON object')
    return value


def _known(data, template, label):
    if set(data) - set(template):
        raise ConfigError('Unknown ' + label + ' field')


def _boolean(data, key, default):
    value = data.get(key, default)
    if type(value) is not bool:
        raise ConfigError('Invalid boolean configuration value')
    return value


def _strings(data, key, max_chars, max_count):
    value = data.get(key, [])
    if type(value) is not list or len(value) > max_count:
        raise ConfigError('Invalid list configuration value')
    result = []
    for item in value:
        if type(item) is not str or not item or len(item) > max_chars or '\x00' in item:
            raise ConfigError('Invalid list configuration value')
        if item not in result:
            result.append(item)
    return tuple(result)


def _host(value):
    if type(value) is not str or not value or len(value) > MAX_HOST_CHARS or '\x00' in value:
        raise ConfigError('Invalid listen_host')
    if value == 'localhost':
        return value
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ConfigError('Invalid listen_host') from None
    return value


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ConfigError('Invalid listen_port')
    return value


def _api_key(value):
    if type(value) is not str or len(value) > MAX_KEY_CHARS:
        raise ConfigError('Invalid api_key')
    if not value:
        return ''
    if not _KEY_RE.match(value):
        raise ConfigError('Invalid api_key format')
    suffix = value[len(KEY_PREFIX):]
    if not (any('A' <= char <= 'Z' for char in suffix)
            and any('a' <= char <= 'z' for char in suffix)
            and any('0' <= char <= '9' for char in suffix)):
        raise ConfigError('Invalid api_key format')
    return value


def _config_values(data):
    _known(data, config_template(), 'configuration')
    return {
        'listen_host': _host(data.get('listen_host', DEFAULT_HOST)),
        'listen_port': _port(data.get('listen_port', DEFAULT_PORT)),
        'api_key': _api_key(data.get('api_key', '')),
        'redaction_enabled': _boolean(data, 'redaction_enabled', True),
        'lite_real_account_read': _boolean(data, 'lite_real_account_read', False),
        'full_real_account_write': _boolean(data, 'full_real_account_write', False),
        'full_low_level_access': _boolean(data, 'full_low_level_access', False),
        'denied_paths': _strings(data, 'denied_paths', MAX_PATH_CHARS, MAX_DENIED_PATHS),
        # 旧配置没有该键时按关闭处理；类型仍须是布尔值。
        'full_plugin_install': _boolean(data, 'full_plugin_install', False),
    }


def _redaction_values(data):
    _known(data, redaction_template(), 'redaction')
    values = {
        'redact_fields': _strings(data, 'redact_fields', MAX_RULE_CHARS, MAX_RULES),
        'allow_fields': _strings(data, 'allow_fields', MAX_RULE_CHARS, MAX_RULES),
    }
    if any(len(item.casefold()) > MAX_RULE_CHARS for fields in values.values() for item in fields):
        raise ConfigError('Redaction field is too long')
    return values


def _encode(template):
    return (json.dumps(template, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def _read_bounded(fd, limit):
    chunks = []
    total = 0
    while total <= limit:
        try:
            chunk = fs.read(fd, min(65536, limit + 1 - total))
        except OSError:
            raise ConfigError('Configuration file is unavailable') from None
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > limit:
        raise ConfigError('Configuration file is too large')
    return b''.join(chunks)


def _read_file(dir_fd, name):
    try:
        fd = fs.open_file(name, _FILE_FLAGS, dir_fd=dir_fd, directory=False)
    except FileNotFoundError:
        raise ConfigError('Configuration file is missing') from None
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    try:
        info = fs.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError('Configuration file type is not supported')
        if info.st_size > MAX_FILE:
            raise ConfigError('Configuration file is too large')
        data = _read_bounded(fd, MAX_FILE)
        return data, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    finally:
        fs.close(fd)


def _remove_temp(dir_fd, temp, fd):
    try:
        staged = fs.stat_at(temp, dir_fd=dir_fd, follow_symlinks=False)
        owned = fs.fstat(fd)
        if (staged.st_dev, staged.st_ino) == (owned.st_dev, owned.st_ino):
            fs.unlink(temp, dir_fd=dir_fd)
    except OSError:
        pass


def _write_temp(dir_fd, name, data, original_info=None):
    temp = '.' + name + '.' + secrets.token_hex(8) + '.tmp'
    try:
        fd = fs.open_file(temp, _WRITE_FLAGS, 0o600, dir_fd=dir_fd, directory=False)
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    try:
        offset = 0
        while offset < len(data):
            written = fs.write(fd, data[offset:])
            if written <= 0:
                raise ConfigError('Configuration file is unavailable')
            offset += written
        if original_info is not None:
            fs.preserve_permissions(fd, original_info)
        fs.fsync(fd)
        return temp, fd
    except BaseException as exc:
        try:
            _remove_temp(dir_fd, temp, fd)
        finally:
            fs.close(fd)
        if isinstance(exc, OSError):
            raise ConfigError('Configuration file is unavailable') from None
        raise


def _create_new(dir_fd, name, data):
    """临时文件 + fsync；用 link 发布，绝不覆盖已存在文件。"""
    temp, fd = _write_temp(dir_fd, name, data)
    try:
        staged = fs.stat_at(temp, dir_fd=dir_fd, follow_symlinks=False)
        owner = fs.fstat(fd)
        if (staged.st_dev, staged.st_ino) != (owner.st_dev, owner.st_ino):
            raise ConfigError('Configuration staging file changed')
        try:
            fs.link(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except FileExistsError:
            return False
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    finally:
        try:
            _remove_temp(dir_fd, temp, fd)
        finally:
            fs.close(fd)
    try:
        fs.fsync(dir_fd)
    except OSError:
        pass
    return True


def _replace_file(dir_fd, name, data, expected_identity):
    """保留原权限并原子替换；提交后核验本进程暂存对象及完整内容，不提供 CAS。"""
    original = None
    try:
        original = fs.open_file(name, _FILE_FLAGS, dir_fd=dir_fd, directory=False)
        original_info = fs.fstat(original)
    except OSError:
        return None
    finally:
        if original is not None:
            fs.close(original)
    if (original_info.st_dev, original_info.st_ino, original_info.st_size,
            original_info.st_mtime_ns) != expected_identity:
        return None
    temp, fd = _write_temp(dir_fd, name, data, original_info)
    replaced = False
    try:
        try:
            info = fs.stat_at(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != expected_identity:
            return None
        staged = fs.stat_at(temp, dir_fd=dir_fd, follow_symlinks=False)
        owner = fs.fstat(fd)
        if (staged.st_dev, staged.st_ino) != (owner.st_dev, owner.st_ino):
            raise ConfigError('Configuration staging file changed')
        fs.replace(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        replaced = True
        try:
            fs.fsync(dir_fd)
        except OSError:
            pass
        raw, identity = _read_file(dir_fd, name)
        if raw != data or identity[:2] != (owner.st_dev, owner.st_ino):
            raise ConfigError('Configuration file could not be verified')
        return identity
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    finally:
        try:
            if not replaced:
                _remove_temp(dir_fd, temp, fd)
        finally:
            fs.close(fd)


def _child_dir(parent_fd, name, create):
    try:
        return fs.open_file(name, _DIR_FLAGS, dir_fd=parent_fd, directory=True)
    except FileNotFoundError:
        if not create:
            raise ConfigError('Configuration directory is missing') from None
    except OSError:
        raise ConfigError('Configuration directory is unavailable') from None
    try:
        fs.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError:
        raise ConfigError('Configuration directory is unavailable') from None
    try:
        return fs.open_file(name, _DIR_FLAGS, dir_fd=parent_fd, directory=True)
    except OSError:
        raise ConfigError('Configuration directory is unavailable') from None


def _fingerprint(parts):
    digest = hashlib.sha256()
    for name, data, identity in parts:
        digest.update(name.encode('ascii'))
        digest.update(repr(identity).encode('ascii'))
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)
    return digest.hexdigest()


class ConfigManager:
    """线程安全快照与变更回调；run_forever 由 main 的唯一 daemon 线程调用。"""

    def __init__(self, data_root, mode=MODE_FULL):
        self.data_root = data_root
        self.mode = mode
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._pending = None
        self._seeded = False
        self._generation = 0
        self._notify_cb = None
        self._log_cb = None
        self._tick_cb = None
        self._snapshot = Snapshot(valid=False, error=NOT_LOADED)
        self._published_key = (False, NOT_LOADED, None)
        # 至多一个服务启动端口写回请求；由监督线程执行 I/O 并确认发布。
        self._write_request = None

    def prepare(self):
        """初始化阶段只记录默认快照，不做 I/O。"""
        return self._snapshot

    def snapshot(self):
        with self._lock:
            return self._snapshot

    def peek_snapshot(self):
        """宿主事件回调只读已发布的不可变对象，不等待监视器锁。"""
        return self._snapshot

    @property
    def stopped(self):
        return self._stop.is_set()

    def set_notify(self, callback):
        self._notify_cb = callback if callable(callback) else None

    def set_tick(self, callback):
        """监督循环每秒的只读接缝；回调不得发布配置或做阻塞 I/O。"""
        self._tick_cb = callback if callable(callback) else None

    def set_log(self, callback):
        self._log_cb = callback if callable(callback) else None

    def allowed(self, permission=None):
        return self.snapshot().allows(permission, self.mode)

    def request_listen_port(self, port, expected_fingerprint):
        """请求把实际监听端口写回配置；返回一次性 Future，或 None。

        只接受当前有效且指纹一致的快照；同一时刻至多一个请求。写回与
        两次观测确认都由监督线程完成，调用线程不做文件 I/O。
        """
        if (type(port) is not int or not 1 <= port <= 65535
                or type(expected_fingerprint) is not str or not expected_fingerprint):
            return None
        future = concurrent.futures.Future()
        with self._lock:
            if self._stop.is_set() or self._write_request is not None:
                return None
            current = self._snapshot
            if (not current.valid or not current.ready
                    or current.fingerprint != expected_fingerprint):
                return None
            self._write_request = {
                'port': port,
                'expected': expected_fingerprint,
                'future': future,
                'state': 'pending',
                'fingerprint': None,
            }
        return future

    def stop(self):
        """非阻塞撤权并停止：清 pending、快照失效且无 key、递增 generation。

        在自身锁内完成失效更新，停止后的迟到 commit/ready 不再发布；
        stop 自己的失效更新不受停止 guard 拦截。待写回请求在锁外结束。
        """
        with self._lock:
            self._stop.set()
            self._pending = None
            self._generation += 1
            self._snapshot = Snapshot(valid=False, error=STOPPED,
                                      generation=self._generation)
            self._published_key = (False, STOPPED, None)
            request = self._write_request
            self._write_request = None
        if request is not None:
            self._resolve(request, False)

    def refresh(self):
        """在调用线程执行一次有界轮询；监督线程也使用它。"""
        try:
            self._poll_once()
        except ConfigError as exc:
            self._fail(str(exc))
        except fs.ToolError:
            self._fail('Configuration directory is unavailable')
        except OSError:
            self._fail('Configuration files are unavailable')

    def run_forever(self):
        """在调用方的 daemon 线程内轮询；重复调用不会产生第二个监视器。"""
        while not self._stop.is_set():
            try:
                self.refresh()
            except BaseException:
                # 后台线程顶层兜底，不记录原始异常。
                self._log('Configuration monitor failed safely.')
            try:
                self._process_write_request()
            except BaseException:
                # 写回失败只结束等待方；不记录原始异常。
                self._log('Configuration update failed safely.')
            tick = self._tick_cb
            if tick is not None and not self._stop.is_set():
                try:
                    tick()
                except BaseException:
                    # 只读接缝的顶层兜底；不记录原始异常。
                    self._log('Terminal tick failed safely.')
            if self._stop.wait(POLL_INTERVAL):
                return

    def _log(self, message):
        callback = self._log_cb
        if callback is None:
            return
        try:
            callback(message)
        except BaseException:
            pass

    def _notify(self, snapshot):
        if snapshot is None:
            return
        if not snapshot.valid:
            self._log('Configuration unavailable: ' + (snapshot.error or 'unknown'))
        callback = self._notify_cb
        if callback is None:
            return
        try:
            callback(snapshot)
        except BaseException:
            pass

    def _commit_locked(self, snapshot):
        if self._stop.is_set():
            # 已停止：迟到轮询不得重新发布或恢复授权；stop 自身更新在加锁内直接写入。
            return None
        key = (snapshot.valid, snapshot.error, snapshot.fingerprint)
        if key == self._published_key:
            return None
        self._generation += 1
        snapshot = replace(snapshot, generation=self._generation)
        self._snapshot = snapshot
        self._published_key = key
        return snapshot

    def _fail(self, message):
        with self._lock:
            self._pending = None
            published = self._commit_locked(Snapshot(valid=False, error=message))
        self._notify(published)

    def _observe(self, fingerprint, values):
        with self._lock:
            current = self._snapshot
            if current.valid and current.fingerprint == fingerprint:
                self._pending = None
                return
            if self._pending == fingerprint:
                self._pending = None
                published = self._commit_locked(
                    Snapshot(valid=True, error=None, fingerprint=fingerprint, **values))
            else:
                self._pending = fingerprint
                if (current.valid is False and current.error == VERIFYING
                        and current.fingerprint == fingerprint):
                    return
                # 内容或文件身份变化时先撤权，稳定确认后再发布。
                published = self._commit_locked(
                    Snapshot(valid=False, error=VERIFYING, fingerprint=fingerprint))
        self._notify(published)

    def _resolve(self, request, result):
        """锁外完成 Future；等待方可能已取消或超时。"""
        future = request.get('future') if type(request) is dict else None
        if future is None:
            return
        try:
            if not future.done():
                future.set_result(result is True)
        except BaseException:
            pass

    def _finish_write(self, request, result):
        with self._lock:
            if self._write_request is request:
                self._write_request = None
        self._resolve(request, result)

    def _process_write_request(self):
        """监督线程的写回接缝：先 refresh 观测，再处理至多一个请求。"""
        with self._lock:
            request = self._write_request
            if request is None:
                return
            future = request['future']
            if future.done():
                self._write_request = None
                return
            state = request['state']
        if self._stop.is_set():
            self._finish_write(request, False)
            return
        try:
            if state == 'pending':
                self._write_port(request)
            else:
                self._confirm_write(request)
        except BaseException:
            self._finish_write(request, False)

    def _write_port(self, request):
        port = request['port']
        expected = request['expected']
        try:
            dir_fd = self._control_fd(create=False)
        except ConfigError:
            self._finish_write(request, False)
            return
        try:
            try:
                config_raw, config_id = _read_file(dir_fd, CONFIG_NAME)
                redaction_raw, redaction_id = _read_file(dir_fd, REDACTION_NAME)
            except ConfigError:
                self._finish_write(request, False)
                return
            current = _fingerprint((
                (CONFIG_NAME, config_raw, config_id),
                (REDACTION_NAME, redaction_raw, redaction_id),
            ))
            if current != expected:
                # 人工编辑、删除或替换：不基于过期来源覆盖。
                self._finish_write(request, False)
                return
            try:
                data = _json(config_raw, 'Configuration')
                values = _config_values(data)
            except ConfigError:
                self._finish_write(request, False)
                return
            if values['listen_port'] == port:
                self._finish_write(request, False)
                return
            # 只改 listen_port；其他键、值和缺失的可选字段保持原样。
            data['listen_port'] = port
            try:
                encoded = _encode(data)
            except (TypeError, ValueError, UnicodeError):
                self._finish_write(request, False)
                return
            if len(encoded) > MAX_FILE:
                self._finish_write(request, False)
                return
            try:
                _replace_file(dir_fd, CONFIG_NAME, encoded, config_id)
            except ConfigError:
                self._finish_write(request, False)
                return
            try:
                published_raw, published_id = _read_file(dir_fd, CONFIG_NAME)
                redaction_raw, redaction_id = _read_file(dir_fd, REDACTION_NAME)
            except ConfigError:
                self._finish_write(request, False)
                return
            if published_raw != encoded:
                self._finish_write(request, False)
                return
            fingerprint = _fingerprint((
                (CONFIG_NAME, published_raw, published_id),
                (REDACTION_NAME, redaction_raw, redaction_id),
            ))
            with self._lock:
                if self._write_request is not request or request['future'].done():
                    return
                request['state'] = 'written'
                request['fingerprint'] = fingerprint
        finally:
            try:
                fs.close(dir_fd)
            except OSError:
                pass

    def _confirm_write(self, request):
        with self._lock:
            snapshot = self._snapshot
            stopped = self._stop.is_set()
        if stopped or snapshot is None:
            self._finish_write(request, False)
            return
        if (snapshot.valid and snapshot.fingerprint == request['fingerprint']
                and snapshot.listen_port == request['port']):
            # 第二次一致观测已发布：端口进入策略，调用方可接受连接。
            self._finish_write(request, True)
            return
        if (not snapshot.valid and snapshot.error == VERIFYING
                and snapshot.fingerprint == request['fingerprint']):
            # 第一次观测已撤权；等待第二次一致观测。
            return
        self._finish_write(request, False)

    def _control_fd(self, create):
        try:
            root_fd = fs.open_root(self.data_root)
        except fs.ToolError:
            raise ConfigError('Configuration directory is unavailable') from None
        try:
            ns_fd = _child_dir(root_fd, NAMESPACE_DIR, create)
        finally:
            fs.close(root_fd)
        try:
            return _child_dir(ns_fd, CONTROL_DIR, create)
        finally:
            fs.close(ns_fd)

    def _seed(self, dir_fd):
        if self._seeded:
            # 首次加载后文件被删除或替换：不重建，按缺失安全失败。
            for name in (CONFIG_NAME, REDACTION_NAME):
                try:
                    fs.close(fs.open_file(name, _FILE_FLAGS, dir_fd=dir_fd, directory=False))
                except FileNotFoundError:
                    raise ConfigError('Configuration file is missing') from None
                except OSError:
                    raise ConfigError('Configuration file is unavailable') from None
            return
        present = {}
        for name in (CONFIG_NAME, REDACTION_NAME):
            try:
                fs.close(fs.open_file(name, _FILE_FLAGS, dir_fd=dir_fd, directory=False))
                present[name] = True
            except FileNotFoundError:
                present[name] = False
            except OSError:
                raise ConfigError('Configuration file is unavailable') from None
        # 先标记，创建失败后不重试，避免用户删除后又被自动补回。
        self._seeded = True
        for name, template in ((CONFIG_NAME, config_template()),
                               (REDACTION_NAME, redaction_template())):
            if not present[name] and not _create_new(dir_fd, name, _encode(template)):
                raise ConfigError('Configuration file is missing')

    def _poll_once(self):
        dir_fd = self._control_fd(create=not self._seeded)
        try:
            self._seed(dir_fd)
            config_raw, config_id = _read_file(dir_fd, CONFIG_NAME)
            redaction_raw, redaction_id = _read_file(dir_fd, REDACTION_NAME)
        finally:
            fs.close(dir_fd)
        try:
            values = _config_values(_json(config_raw, 'Configuration'))
            values.update(_redaction_values(_json(redaction_raw, 'Redaction rules')))
        except ConfigError as exc:
            self._fail(str(exc))
            return
        fingerprint = _fingerprint((
            (CONFIG_NAME, config_raw, config_id),
            (REDACTION_NAME, redaction_raw, redaction_id),
        ))
        self._observe(fingerprint, values)


__all__ = [
    'CONFIG_NAME', 'CONTROL_DIR', 'ConfigError', 'ConfigManager', 'DEFAULT_HOST',
    'DEFAULT_PORT', 'NAMESPACE_DIR', 'PERMISSION_LOW_LEVEL_ACCESS',
    'PERMISSION_PLUGIN_INSTALL', 'PERMISSION_REAL_ACCOUNT_READ',
    'PERMISSION_REAL_ACCOUNT_WRITE', 'REDACTION_NAME', 'Snapshot', 'config_template',
    'control_dir', 'is_protected', 'redaction_template',
]
