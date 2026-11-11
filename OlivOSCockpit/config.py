"""本地配置与脱敏规则：只读写控制目录内的两个文件，发布不可变快照。

本模块不监听端口、不导入 aiohttp；阻塞 I/O 只发生在监督线程内。
控制目录（含临时文件）由普通文件工具永久禁止访问，见 is_protected。
"""

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
            chunk = os.read(fd, min(65536, limit + 1 - total))
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
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        raise ConfigError('Configuration file is missing') from None
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError('Configuration file type is not supported')
        if info.st_size > MAX_FILE:
            raise ConfigError('Configuration file is too large')
        data = _read_bounded(fd, MAX_FILE)
        return data, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    finally:
        os.close(fd)


def _write_temp(dir_fd, name, data):
    temp = '.' + name + '.' + secrets.token_hex(8) + '.tmp'
    try:
        fd = os.open(temp, _WRITE_FLAGS, 0o600, dir_fd=dir_fd)
    except OSError:
        raise ConfigError('Configuration file is unavailable') from None
    try:
        offset = 0
        while offset < len(data):
            try:
                offset += os.write(fd, data[offset:])
            except OSError:
                raise ConfigError('Configuration file is unavailable') from None
        try:
            os.fsync(fd)
        except OSError:
            raise ConfigError('Configuration file is unavailable') from None
    finally:
        os.close(fd)
    return temp


def _create_new(dir_fd, name, data):
    """临时文件 + fsync；用 link 发布，绝不覆盖已存在文件。"""
    temp = _write_temp(dir_fd, name, data)
    try:
        try:
            os.link(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except FileExistsError:
            return False
        except OSError:
            raise ConfigError('Configuration file is unavailable') from None
    finally:
        try:
            os.unlink(temp, dir_fd=dir_fd)
        except OSError:
            pass
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    return True


def _child_dir(parent_fd, name, create):
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        if not create:
            raise ConfigError('Configuration directory is missing') from None
    except OSError:
        raise ConfigError('Configuration directory is unavailable') from None
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError:
        raise ConfigError('Configuration directory is unavailable') from None
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
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

    def stop(self):
        """非阻塞撤权并停止：清 pending、快照失效且无 key、递增 generation。

        在自身锁内完成失效更新，停止后的迟到 commit/ready 不再发布；
        stop 自己的失效更新不受停止 guard 拦截。
        """
        with self._lock:
            self._stop.set()
            self._pending = None
            self._generation += 1
            self._snapshot = Snapshot(valid=False, error=STOPPED,
                                      generation=self._generation)
            self._published_key = (False, STOPPED, None)

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

    def _control_fd(self, create):
        try:
            root_fd = fs.open_root(self.data_root)
        except fs.ToolError:
            raise ConfigError('Configuration directory is unavailable') from None
        try:
            ns_fd = _child_dir(root_fd, NAMESPACE_DIR, create)
        finally:
            os.close(root_fd)
        try:
            return _child_dir(ns_fd, CONTROL_DIR, create)
        finally:
            os.close(ns_fd)

    def _seed(self, dir_fd):
        if self._seeded:
            # 首次加载后文件被删除或替换：不重建，按缺失安全失败。
            for name in (CONFIG_NAME, REDACTION_NAME):
                try:
                    os.close(os.open(name, _FILE_FLAGS, dir_fd=dir_fd))
                except FileNotFoundError:
                    raise ConfigError('Configuration file is missing') from None
                except OSError:
                    raise ConfigError('Configuration file is unavailable') from None
            return
        present = {}
        for name in (CONFIG_NAME, REDACTION_NAME):
            try:
                os.close(os.open(name, _FILE_FLAGS, dir_fd=dir_fd))
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
            os.close(dir_fd)
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
    'CONFIG_NAME', 'CONTROL_DIR', 'ConfigError', 'ConfigManager', 'DEFAULT_BOT_ID',
    'DEFAULT_HOST', 'DEFAULT_PORT', 'NAMESPACE_DIR', 'PERMISSION_LOW_LEVEL_ACCESS',
    'PERMISSION_REAL_ACCOUNT_READ', 'PERMISSION_REAL_ACCOUNT_WRITE', 'REDACTION_NAME',
    'Snapshot', 'config_template', 'control_dir', 'is_protected', 'redaction_template',
]
