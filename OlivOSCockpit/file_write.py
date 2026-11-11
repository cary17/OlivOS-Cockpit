"""Full 专属：仅替换其他插件数据目录内已存在的 UTF-8 配置文件。"""

import hashlib
import json
import os
import posixpath
import re
import secrets
import threading

from . import config, fs, host
from .contracts import (MAX_FILE, MODE_FULL, Outcome, ToolError, ToolSpec, check_json_budget,
                        object_schema, validate_arguments)

_SUFFIXES = frozenset(('.json', '.ini', '.toml', '.yaml', '.yml', '.conf', '.cfg'))
_SHA256 = re.compile(r'[0-9a-fA-F]{64}\Z')
_WRITE_LOCK = threading.Lock()
_TEMP_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
               | getattr(os, 'O_CLOEXEC', 0))


def _snapshot(ctx, generation=None):
    current = host.snapshot(ctx)
    if (current is None or current is host.MISSING
            or getattr(ctx, 'permission_mode', None) != MODE_FULL
            or getattr(current, 'valid', False) is not True
            or getattr(current, 'full_real_account_write', False) is not True
            or type(getattr(current, 'generation', None)) is not int):
        raise ToolError('Writing plugin configuration is not permitted')
    if generation is not None and current.generation != generation:
        raise ToolError('Configuration changed; retry with the current policy')
    return current.generation


def _identity(info):
    return ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
             info.st_nlink) + fs.permission_identity(info))


def _original(parent, name):
    fd, kind = fs.open_rel(parent, name)
    try:
        info = fs.fstat(fd)
        if kind != 'file' or not fs.non_executable(info):
            raise ToolError('Only non-executable configuration files can be updated')
        if info.st_size > MAX_FILE:
            raise ToolError('Configuration file is too large')
        raw, _, truncated = fs.read_fd(fd, MAX_FILE)
        if truncated:
            raise ToolError('Configuration file is too large')
        raw.decode('utf-8', 'strict')
        if _identity(info) != _identity(fs.fstat(fd)):
            raise ToolError('Configuration file changed; read it again')
        return info, hashlib.sha256(raw).hexdigest()
    finally:
        fs.close(fd)


_UNVERIFIED = ('Replacement may have completed but the final state could not be verified; '
               'read the file again and do not retry automatically')


def _verify_committed(parent, name, temp_fd, content):
    """提交后核验（OPT-02）：重开最终路径，确认 inode 身份与完整内容。

    最终文件 dev/ino 必须与仍持有的暂存 fd 一致，完整内容 SHA 与本次提交
    一致；不与被替换的旧 inode 比较，也不比较 rename 前后的完整 stat 元组。
    成功只说明核验观察点的路径解析、inode 身份与读到的内容符合本次提交，
    不提供跨进程 CAS，也不承诺之后不被改写；失败不回滚、不清理外部对象。
    """
    try:
        current, revision = _original(parent, name)
    except (ToolError, OSError, UnicodeError):
        return False
    try:
        owner = fs.fstat(temp_fd)
    except OSError:
        return False
    if (current.st_dev, current.st_ino) != (owner.st_dev, owner.st_ino):
        return False
    return revision == hashlib.sha256(content).hexdigest()


def _replace(ctx, parent, name, content, expected, generation, before_replace=None):
    original, revision = _original(parent, name)
    if revision != expected:
        raise ToolError('Configuration revision mismatch; read the complete file again')
    _snapshot(ctx, generation)
    fs.authorize_path(ctx, os.path.join(parent.path, name), write=True)
    temp = '.cockpit-' + secrets.token_hex(16) + '.tmp'
    temp_fd = None
    replaced = False
    try:
        temp_fd = fs.open_file(temp, _TEMP_FLAGS, 0o600, dir_fd=parent, directory=False)
        fs.authorize_path(ctx, os.path.join(parent.path, temp), write=True)
        offset = 0
        while offset < len(content):
            written = fs.write(temp_fd, content[offset:])
            if written <= 0:
                raise ToolError('Configuration update failed safely')
            offset += written
        fs.preserve_permissions(temp_fd, original)
        fs.fsync(temp_fd)
        current, revision = _original(parent, name)
        if _identity(original) != _identity(current) or revision != expected:
            raise ToolError('Configuration file changed; read it again')
        staged, staged_revision = _original(parent, temp)
        if (_identity(staged) != _identity(fs.fstat(temp_fd))
                or staged_revision != hashlib.sha256(content).hexdigest()):
            raise ToolError('Configuration staging file changed')
        if before_replace is not None:
            before_replace()
        fs.authorize_path(ctx, os.path.join(parent.path, name), write=True)
        _snapshot(ctx, generation)
        # shortcut: 最后复核与 replace 不是跨进程 CAS；需外部协作锁时再升级协议。
        fs.replace(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        # 提交后的失败不回滚，也不进入提交前清理分支。
        replaced = True
        try:
            fs.fsync(parent)
            durability = 'synced'
        except OSError:
            durability = 'unknown'
        if not _verify_committed(parent, name, temp_fd, content):
            raise ToolError(_UNVERIFIED)
        return Outcome({'persisted': True, 'durability': durability,
                        'sha256': hashlib.sha256(content).hexdigest(), 'reloaded': False,
                        'note': 'File persisted; this does not mean the plugin has been reloaded'})
    finally:
        if temp_fd is not None:
            try:
                if not replaced:
                    staged = fs.stat_at(temp, dir_fd=parent, follow_symlinks=False)
                    owned = fs.fstat(temp_fd)
                    if (staged.st_dev, staged.st_ino) == (owned.st_dev, owned.st_ino):
                        fs.unlink(temp, dir_fd=parent)
            except OSError:
                pass
            finally:
                fs.close(temp_fd)


def cockpit_plugin_file_update(ctx, args):
    validate_arguments(TOOLS[0], args)
    generation = _snapshot(ctx)
    namespace, relative = args['namespace'], args['path']
    if (not namespace or namespace in ('.', '..') or '/' in namespace or '\\' in namespace
            or '\x00' in namespace or ':' in namespace
            or namespace.casefold() == config.NAMESPACE_DIR.casefold()):
        raise ToolError('Invalid or protected namespace')
    fs._component(namespace)
    if not relative:
        raise ToolError('Invalid configuration path')
    fs._relative_names(relative)
    relative = posixpath.normpath(relative)
    if posixpath.splitext(relative)[1].lower() not in _SUFFIXES:
        raise ToolError('Unsupported configuration file suffix')
    if not _SHA256.fullmatch(args['expected_sha256']):
        raise ToolError('expected_sha256 must be a SHA-256 hex digest')
    try:
        content = args['content'].encode('utf-8', 'strict')
        if len(content) > MAX_FILE:
            raise ToolError('Configuration content is too large')
        if relative.lower().endswith('.json'):
            # 解码前先限制嵌套与节点数，不依赖宿主的 recursionlimit。
            check_json_budget(args['content'])
            json.loads(args['content'], object_pairs_hook=config._unique,
                       parse_constant=config._bad_constant, parse_float=str, parse_int=str)
    except (UnicodeError, ValueError, OverflowError, RecursionError):
        raise ToolError('Configuration content is not valid UTF-8 or strict JSON') from None
    fs.require()
    if not fs.updates_supported():
        raise ToolError('Secure file updates are not supported on this platform')
    with _WRITE_LOCK:
        _snapshot(ctx, generation)
        root = fs.open_root(ctx.data_root, context=ctx)
        try:
            parent_rel = posixpath.join(namespace, posixpath.dirname(relative))
            parent, kind = fs.open_rel(root, parent_rel)
        finally:
            fs.close(root)
        try:
            if kind != 'dir':
                raise ToolError('Configuration parent is not a directory')
            fs.authorize_path(ctx, os.path.join(parent.path, posixpath.basename(relative)), write=True)
            outcome = _replace(ctx, parent, posixpath.basename(relative), content,
                               args['expected_sha256'].lower(), generation)
            outcome.data.update(namespace=namespace, path=relative)
            return outcome
        except (OSError, UnicodeError):
            raise ToolError('Configuration update failed safely') from None
        finally:
            fs.close(parent)


TOOLS = (
    ToolSpec(
        'cockpit_plugin_file_update',
        'Replace an existing non-executable UTF-8 plugin configuration file under its data namespace. '
        'Requires the SHA-256 from a complete cockpit_data read and Full write permission. '
        'Atomic replacement is not cross-process compare-and-swap and does not reload the plugin.',
        object_schema({
            'namespace': {'type': 'string', 'minLength': 1, 'maxLength': 128},
            'path': {'type': 'string', 'minLength': 1, 'maxLength': 1024},
            'expected_sha256': {'type': 'string', 'minLength': 64, 'maxLength': 64},
            'content': {'type': 'string', 'maxLength': MAX_FILE},
        }, ('namespace', 'path', 'expected_sha256', 'content')),
        cockpit_plugin_file_update,
        read_only=False,
        required_permission=config.PERMISSION_REAL_ACCOUNT_WRITE,
    ),
)
