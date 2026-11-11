"""Full 专属账号落盘：仅编辑已有账号的开关与有限凭据，不修改运行时账号或路由。"""

import hashlib
import json
import os
import re

from . import account_tools, file_write, fs, host
from .contracts import MAX_ENTRIES, MAX_FILE, Outcome, ToolError, ToolSpec, object_schema, validate_arguments

MAX_CREDENTIAL = 4096
_CREDENTIAL = re.compile(r'[A-Za-z0-9_.:@+=/\-]*\Z')
_FIELDS = ('id', 'enable', 'password', 'sdk_type', 'platform_type', 'model_type', 'server', 'extends', 'debug')
_SERVER_FIELDS = ('auto', 'type', 'host', 'port', 'access_token')
_LIMITED = 'Unsupported changes; only enable, debug, password and server.access_token can be updated'


def _policy(ctx, generation=None):
    if not account_tools._permitted(ctx, host.REAL_ACCOUNT_WRITE):
        raise ToolError('Writing real configured accounts is not permitted')
    return file_write._snapshot(ctx, generation)


def _changes(raw):
    changes = account_tools._copy(raw)
    if not changes or set(changes) - {'enable', 'debug', 'password', 'server'}:
        raise ToolError(_LIMITED)
    for key in ('enable', 'debug'):
        if key in changes and type(changes[key]) is not bool:
            raise ToolError('Account enable and debug changes must be booleans')
    credentials = []
    if 'password' in changes:
        credentials.append(changes['password'])
    if 'server' in changes:
        server = changes['server']
        if type(server) is not dict or set(server) != {'access_token'}:
            raise ToolError(_LIMITED)
        credentials.append(server['access_token'])
    for value in credentials:
        if type(value) is not str or len(value) > MAX_CREDENTIAL:
            raise ToolError('Credential updates must be strings of at most 4096 ASCII characters')
        if '[redacted]' in value.casefold():
            raise ToolError('Redacted placeholders cannot be written as credentials')
        # 外部 booter 存在未转义的模板/命令参数；不承诺支持任意密码字符。
        if not _CREDENTIAL.fullmatch(value):
            raise ToolError('Unsupported credential characters; only ASCII letters, digits and _.:@+=/- are supported')
    return changes


def _validate(ctx, account):
    projected = {key: account[key] for key in _FIELDS if key in account}
    if type(projected.get('server')) is dict:
        projected['server'] = {key: projected['server'][key] for key in _SERVER_FIELDS if key in projected['server']}
    projected = account_tools._copy(projected)
    errors = host.safe(lambda: ctx.olivos.accountAPI._validate_account_config(projected))
    if type(errors) is not list:
        raise ToolError('Native pure account validator unavailable or failed safely')
    if errors:
        raise ToolError('Updated account failed native validation; configuration was not written')


def cockpit_accounts_update(ctx, args):
    generation = _policy(ctx)
    validate_arguments(TOOLS[0], args)
    if not file_write._SHA256.fullmatch(args['expected_sha256']):
        raise ToolError('expected_sha256 must be a SHA-256 hex digest')
    expected = args['expected_sha256'].lower()
    changes = _changes(args['changes'])
    fs.require()
    if (os.rename not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd
            or not all(callable(getattr(os, name, None)) for name in ('replace', 'fchmod', 'fchown', 'fsync'))):
        raise ToolError('Secure account updates are not supported on this platform')
    with file_write._WRITE_LOCK:
        _policy(ctx, generation)
        path, boot_revision = account_tools._resolve(ctx)
        if (not path.lower().endswith('.json')
                or path.casefold() in tuple(os.path.normpath(os.path.join(ctx.root, 'conf', name)).casefold()
                                           for name in account_tools._BOOT_FILES)):
            raise ToolError('Only the declared non-executable account JSON file can be updated')
        parent = fs.open_root(os.path.dirname(path), context=ctx)
        try:
            name = os.path.basename(path)
            fs.authorize_path(ctx, path, write=True)
            document, revision, original = account_tools._read(parent, name)
            if revision != expected:
                raise ToolError('Account configuration revision mismatch; read it again')
            index = args['index']
            if index >= len(document['account']):
                raise ToolError('Account index is not present in the configured file')
            account = document['account'][index]
            for key, value in changes.items():
                if key == 'server':
                    if type(account.get('server')) is not dict:
                        raise ToolError('Configured account server fields are invalid')
                    account['server']['access_token'] = value['access_token']
                else:
                    account[key] = value
            _validate(ctx, account)
            encoded = (json.dumps(document, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode('utf-8')
            if len(encoded) > MAX_FILE:
                raise ToolError('Updated account configuration exceeds the file limit')
            if account_tools._resolve(ctx) != (path, boot_revision):
                raise ToolError('Disk boot configuration changed; read the account configuration again')
            current, current_revision = file_write._original(parent, name)
            if file_write._identity(current) != file_write._identity(original) or current_revision != expected:
                raise ToolError('Account configuration changed; read it again')
            _policy(ctx, generation)

            def before_replace():
                if account_tools._resolve(ctx) != (path, boot_revision):
                    raise ToolError('Disk boot configuration changed before account commit')
                _policy(ctx, generation)

            persisted = file_write._replace(ctx, parent, name, encoded, expected, generation,
                                            before_replace=before_replace)
            return Outcome({
                'source': 'configured_file',
                'path_source': 'disk_boot_configuration',
                'runtime_active_config': 'unknown',
                'index': index,
                'persisted': persisted.data['persisted'],
                'durability': persisted.data['durability'],
                'sha256': hashlib.sha256(encoded).hexdigest(),
                'runtime_updated': False,
                'requires_host_restart': True,
                'note': 'Only the disk-declared account file was persisted. Restart the whole OlivOS host to apply; '
                        'a plugin-loader restart or an in-memory loader update does not update every adapter.',
            })
        except (OSError, UnicodeError, ValueError, RecursionError):
            raise ToolError('Account configuration update failed safely') from None
        finally:
            os.close(parent)


TOOLS = (
    ToolSpec(
        'cockpit_accounts_update',
        'Persist limited changes to one existing account in the JSON file declared by standard disk '
        'boot configuration. '
        'Only enable/debug booleans, password and server.access_token are supported; IDs, SDK/model, endpoints, '
        'paths and other routing fields are not editable. Credentials are limited to 4096 ASCII letters/digits or '
        '_.:@+=/-; redacted placeholders are rejected. Full real-account write permission is off by default. '
        'Requires a complete-file SHA-256 from cockpit_accounts_config. Preserves unknown and unmodified fields. '
        'The native validator only checks the known projection and rejects unknown top-level/server fields, so '
        'preserving unknown data does not guarantee the whole archive is accepted by the host. '
        'Atomic replacement is not cross-process compare-and-swap. Does not update runtime accounts; requires '
        'a whole-host restart, not just reloading plugins.',
        object_schema({
            'index': {'type': 'integer', 'minimum': 0, 'maximum': MAX_ENTRIES - 1},
            'expected_sha256': {'type': 'string', 'minLength': 64, 'maxLength': 64},
            'changes': object_schema({
                'enable': {'type': 'boolean'},
                'debug': {'type': 'boolean'},
                'password': {'type': 'string', 'maxLength': MAX_CREDENTIAL},
                'server': object_schema({
                    'access_token': {'type': 'string', 'maxLength': MAX_CREDENTIAL},
                }, ('access_token',)),
            }),
        }, ('index', 'expected_sha256', 'changes')),
        cockpit_accounts_update,
        read_only=False,
        required_permission=host.REAL_ACCOUNT_WRITE,
    ),
)
