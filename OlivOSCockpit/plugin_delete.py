"""Full 专属：按已核对的整包摘要删除 OPK，可选清理同 namespace 数据。"""

import hashlib
import hmac
import os
import stat
import time

from . import fs, host, plugin_install
from .config import PERMISSION_PLUGIN_DELETE as PERMISSION
from .contracts import (MAX_OPK, Outcome, ToolError, ToolSpec, object_schema,
                        validate_arguments)

MAX_DATA_ENTRIES = 512
MAX_DATA_DEPTH = 10
# 尽早停止后续变更；无法中断正在阻塞的宿主文件操作。
_REMOVE_BUDGET_SECONDS = 8.0
_DATA_INCOMPLETE = 'Plugin data could not be fully validated for removal'


def _authorize(ctx, generation):
    if (plugin_install._snapshot(ctx).generation != generation
            or not host.allowed(ctx, PERMISSION)):
        raise ToolError('Deleting plugin packages is not permitted or configuration changed')


def _within_budget(deadline):
    if time.monotonic() >= deadline:
        raise ToolError('Plugin removal time budget exceeded')


def _same_directory(current, expected):
    return (stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino))


def _exists(parent, name):
    fs.authorize_rel(parent, name, write=True)
    try:
        fs.stat_at(name, dir_fd=parent)
    except FileNotFoundError:
        return False
    return True


def _package(root, filename, namespace, expected_sha256):
    entries, truncated, _ = fs.scan_dir(root, plugin_install.MAX_SCAN_ENTRIES)
    matches = [entry for entry in entries if entry['name'].casefold() == filename.casefold()]
    if (truncated or len(matches) != 1 or matches[0]['name'] != filename
            or matches[0]['type'] != 'file'):
        raise ToolError('Exact package filename is unavailable or ambiguous')
    fs.authorize_rel(root, filename, write=True)
    fd, kind = fs.open_rel(root, filename)
    try:
        info = fs.fstat(fd)
        if kind != 'file' or info.st_nlink != 1:
            raise ToolError('Package is not a regular single-link file')
        fs.require_same_mount(root, fd)
        if info.st_size > MAX_OPK:
            raise ToolError('Package too large')
        package, _, truncated = fs.read_fd(fd, MAX_OPK)
        if truncated or len(package) != info.st_size or fs._revision(info) != fs._revision(fs.fstat(fd)):
            raise ToolError('Package changed during verification')
        if not hmac.compare_digest(hashlib.sha256(package).hexdigest(), expected_sha256):
            raise ToolError('Package digest mismatch; inspect it again before deleting')
        _, actual = plugin_install._manifest(fs.package_manifest(package))
        if actual != namespace:
            raise ToolError('Package manifest namespace does not match the confirmed namespace')
        return info
    finally:
        fs.close(fd)


def _inspect_data(parent, name, remaining, depth, deadline):
    """有界预检后才允许删除；不跟随链接，也不越过挂载边界。"""
    _within_budget(deadline)
    if depth > MAX_DATA_DEPTH:
        raise ToolError(_DATA_INCOMPLETE)
    fs.authorize_rel(parent, name, write=True)
    fd, kind = fs.open_rel(parent, name)
    try:
        fs.require_same_mount(parent, fd)
        info = fs.fstat(fd)
        if kind == 'file' and depth > 0:
            return info, None
        if kind != 'dir':
            raise ToolError(_DATA_INCOMPLETE)
        entries, truncated, blocked = fs.scan_dir(fd, remaining[0])
        if truncated or blocked or any(entry['type'] not in ('file', 'dir') for entry in entries):
            raise ToolError(_DATA_INCOMPLETE)
        remaining[0] -= len(entries)
        return info, tuple((entry['name'], _inspect_data(fd, entry['name'], remaining, depth + 1, deadline))
                           for entry in entries)
    finally:
        fs.close(fd)


def _remove_data(parent, name, node, check):
    info, children = node
    check()
    if children is not None:
        fs.authorize_rel(parent, name, write=True)
        fd, kind = fs.open_rel(parent, name)
        try:
            if kind != 'dir' or fs._revision(fs.fstat(fd)) != fs._revision(info):
                raise ToolError('Plugin data directory changed during removal')
            fs.require_same_mount(parent, fd)
            for child, planned in children:
                _remove_data(fd, child, planned, check)
        finally:
            fs.close(fd)
        check()
    fs.remove_checked(parent, name, info, directory=children is not None)


def _loaded(ctx, namespace):
    snapshot = host.plugin_names(ctx.proc)
    if snapshot is None:
        return None
    names, truncated = snapshot
    if namespace in names:
        return True
    return None if truncated else False


def _sync(parent):
    try:
        fs.fsync(parent)
    except OSError:
        return False
    return True


def _delete(ctx, filename, namespace, expected_sha256, delete_data, generation, deadline):
    def check():
        _within_budget(deadline)
        _authorize(ctx, generation)

    check()
    root = fs.open_package_root(ctx)
    data_root = None
    try:
        expected = _package(root, filename, namespace, expected_sha256)
        node = None
        result = {'filename': filename, 'namespace': namespace,
                  'package_removed': None, 'data': 'not_attempted' if delete_data else 'kept',
                  'currently_loaded': _loaded(ctx, namespace), 'requires_loader_restart': None,
                  'durability': 'unknown'}
        if delete_data:
            # 与安装共用包/源码清单扫描，但只豁免这一个顶层文件。
            plugin_install._scan_existing(root, filename, namespace)
            data_root = fs.open_root(ctx.data_root, context=ctx)
            # 数据根和包根由宿主独立提供；不得把包根或其中的源码当作插件数据。
            data_path = fs._denial_key(os.path.join(data_root.path, namespace))
            package_path = fs._denial_key(root.path)
            if (fs._within(data_path, package_path) or fs._within(package_path, data_path)
                    or _same_directory(fs.fstat(data_root), fs.fstat(root))):
                raise ToolError('Plugin data path overlaps the package root')
            if _exists(data_root, namespace):
                node = _inspect_data(data_root, namespace, [MAX_DATA_ENTRIES], 0, deadline)
        check()
        try:
            fs.remove_checked(root, filename, expected)
            if _exists(root, filename):
                raise ToolError('Package path is not empty after removal')
        except (OSError, ToolError):
            result['error'] = ('Package removal was not confirmed; inspect the package before taking more action')
            return Outcome(result, is_error=True)
        synced = _sync(root)
        result['package_removed'] = True
        result['requires_loader_restart'] = True
        if delete_data:
            try:
                check()
                if node is not None:
                    _remove_data(data_root, namespace, node, check)
                    synced = _sync(data_root) and synced
                if _exists(data_root, namespace):
                    raise ToolError('Plugin data was changed or recreated')
                result['data'] = 'absent' if node is None else 'removed'
            except (OSError, ToolError):
                result['data'] = 'partial_or_unknown'
                result['error'] = ('Package removed; data cleanup was not confirmed. '
                                   'Inspect the data directory and do not retry automatically')
                return Outcome(result, is_error=True)
        result['durability'] = 'synced' if synced else 'unknown'
        result['note'] = ('Disk removal does not unload a running plugin. Restart the loader separately; '
                          'a running plugin can recreate its data.')
        return Outcome(result)
    finally:
        if data_root is not None:
            fs.close(data_root)
        fs.close(root)


def cockpit_plugin_delete(ctx, args):
    validate_arguments(TOOLS[0], args)
    generation = plugin_install._snapshot(ctx).generation
    _authorize(ctx, generation)
    if not fs.updates_supported():
        raise ToolError('Secure package removal is not supported on this platform')
    filename = plugin_install._filename(args['filename'])
    namespace = plugin_install._namespace(args['namespace'])
    expected_sha256 = args['expected_sha256']
    if plugin_install._SHA256.fullmatch(expected_sha256) is None:
        raise ToolError('expected_sha256 must be a SHA-256 hex digest')
    if not plugin_install._LOCK.acquire(blocking=False):
        raise ToolError('Another plugin package operation is in progress')
    try:
        return _delete(ctx, filename, namespace, expected_sha256.lower(), args.get('delete_data', False),
                       generation, time.monotonic() + _REMOVE_BUDGET_SECONDS)
    except (OSError, UnicodeError, ValueError):
        raise ToolError('Plugin removal preflight failed safely') from None
    finally:
        plugin_install._LOCK.release()


TOOLS = (
    ToolSpec(
        'cockpit_plugin_delete',
        'Delete one installed top-level OPK after inspecting it with cockpit_meta and confirming '
        'its filename, manifest namespace and complete SHA-256. Keeps the namespace data unless '
        'delete_data is explicitly true. Does not restart the loader or unload running code. '
        'Requires Full real write plus the separate plugin deletion switch. Inspect partial or '
        'unknown results before taking any further action; do not retry automatically.',
        object_schema({
            'filename': {'type': 'string', 'minLength': 1, 'maxLength': 255},
            'namespace': {'type': 'string', 'minLength': 1, 'maxLength': 64},
            'expected_sha256': {'type': 'string', 'minLength': 64, 'maxLength': 64},
            'delete_data': {'type': 'boolean'},
        }, ('filename', 'namespace', 'expected_sha256')),
        cockpit_plugin_delete,
        read_only=False,
        required_permission=PERMISSION,
    ),
)
