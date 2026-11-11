"""文件工具与安全原语测试；仅标准库，不加载宿主、不访问真实 OlivOS 目录。"""

import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import types
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from OlivOSCockpit import contracts, files, fs, protocol, redaction
Context = contracts.Context
ToolError = contracts.ToolError
MAX_ENTRIES = contracts.MAX_ENTRIES


def base_dir():
    """realpath 后作根，确保测试根自身不含链接（严格模式下仍可用）。"""
    return os.path.realpath(tempfile.mkdtemp(prefix='cockpit-test-'))


def host_stub(plugin_path='./plugin/app/'):
    return types.SimpleNamespace(pluginAPI=types.SimpleNamespace(plugin_path=plugin_path))


def make_ctx(root):
    return Context(proc=None, root=root, data_root=os.path.join(root, 'plugin/data'),
                   olivos=host_stub())


class Snapshot:
    """最小配置快照替身；只实现本模块用到的字段。"""

    def __init__(self, **values):
        self.__dict__.update(values)
        self.__dict__.setdefault('denied_paths', ())

    def allows(self, permission, mode):
        if permission is None:
            return True
        if permission == 'real_account_read':
            return mode == contracts.MODE_FULL or getattr(self, 'lite_real_account_read', False)
        return False


class Manager:
    def __init__(self, snapshot):
        self.value = snapshot

    def snapshot(self):
        return self.value


def make_scoped_ctx(root, mode=contracts.MODE_FULL, **values):
    return Context(proc=None, root=root, data_root=os.path.join(root, 'plugin/data'),
                   olivos=host_stub(), config=Manager(Snapshot(**values)), permission_mode=mode)


def touch(path, data=b'', mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fp:
        fp.write(data)
    if mode is not None:
        os.chmod(path, mode)


def read_bytes(path):
    with open(path, 'rb') as fp:
        return fp.read()


def read_page(ctx, args, known=(), modern=False, policy=None):
    outcome = files.cockpit_data(ctx, args)
    body = protocol.result_body(1, protocol.tool_result(outcome, ''), modern)
    reply = protocol.encode_reply(body, modern, known=known, policy=policy, page=outcome.page)
    return outcome, reply, json.loads(reply.body)['result']


def manifest_bytes(namespace='Demo', name='Demo'):
    return json.dumps({'name': name, 'namespace': namespace, 'version': '1.0.0',
                       'svn': 1, 'info': 'x', 'author': 'a',
                       'compatible_svn': [1], 'priority': 10,
                       'secret': 'do-not-leak'}).encode()


def make_opk(path, namespace='Demo', extra_entries=None, compression=zipfile.ZIP_DEFLATED,
             duplicate=False):
    with zipfile.ZipFile(path, 'w', compression) as archive:
        archive.writestr('app.json', manifest_bytes(namespace))
        if duplicate:
            archive.writestr('app.json', manifest_bytes(namespace))
        for name, data in (extra_entries or {}).items():
            archive.writestr(name, data)


class _ZipFileConstructed(BaseException):
    pass


def _no_zipfile(*args, **kwargs):
    raise _ZipFileConstructed('zipfile.ZipFile was constructed before validation')


def zip64_locator_sample(count=16):
    """[CD count 条][ZIP64 记录][locator][EOCD 只声明 1 条]；stdlib 会经 locator 解出全部。"""
    name = b'app.json'
    entry = struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', 45, 45, 0, 0, 0, 0,
                        0, 0, 0, len(name), 0, 0, 0, 0, 0, 0) + name
    cd = entry * count
    z64 = b'PK\x06\x06' + struct.pack('<QHHIIQQQQ', 44, 45, 45, 0, 0,
                                      count, count, len(cd), 0)
    loc = b'PK\x06\x07' + struct.pack('<IQI', 0, len(cd), 1)
    size = len(cd) + len(z64) + len(loc) + 22
    eocd = b'PK\x05\x06' + struct.pack('<HHHHIIH', 0, 0, 1, 1, 20, size - 42, 0)
    return cd + z64 + loc + eocd


def lying_eocd_sample(count=16):
    """真实中央目录 count 条，EOCD 只声明 1 条；stdlib 按 cd_size 解出全部。"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('app.json', manifest_bytes())
        for index in range(count - 1):
            archive.writestr('f%02d' % index, b'x')
    data = bytearray(buffer.getvalue())
    eocd = data.rfind(b'PK\x05\x06')
    data[eocd + 8:eocd + 10] = (1).to_bytes(2, 'little')
    data[eocd + 10:eocd + 12] = (1).to_bytes(2, 'little')
    return bytes(data)


def comment_pseudo_eocd_sample(path, count=16):
    """真 EOCD 声明 1 条；注释里的伪 EOCD 指向复制的 16 条目录，stdlib 由此解出 16 条。"""
    template = io.BytesIO()
    with zipfile.ZipFile(template, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('app.json', manifest_bytes())
        for index in range(count - 1):
            archive.writestr('f%02d' % index, b'x')
    copy = template.getvalue()
    copied_cd = copy[copy.find(b'PK\x01\x02'):copy.rfind(b'PK\x05\x06')]

    base = io.BytesIO()
    with zipfile.ZipFile(base, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('app.json', manifest_bytes())
    raw = bytearray(base.getvalue())
    real = raw.rfind(b'PK\x05\x06')
    prefix = b'F' * 10
    cd_start = real + 22 + len(prefix)
    fake = b'PK\x05\x06' + struct.pack('<HHHHIIH', 0, 0, 1, 1,
                                       len(copied_cd), cd_start, 0)
    comment = prefix + copied_cd + fake + b'TRAIL'
    raw[real + 8:real + 10] = (1).to_bytes(2, 'little')
    raw[real + 10:real + 12] = (1).to_bytes(2, 'little')
    raw[real + 20:real + 22] = len(comment).to_bytes(2, 'little')
    with open(path, 'wb') as fp:
        fp.write(bytes(raw) + comment)


def fd_count():
    try:
        return len(os.listdir('/proc/self/fd'))
    except OSError:
        return None


class SafeError(unittest.TestCase):
    def assertSafe(self, fn, *args):
        with self.assertRaises(ToolError) as ctx:
            fn(*args)
        message = str(ctx.exception)
        self.assertNotIn(tempfile.gettempdir(), message)
        self.assertNotIn('/root', message)
        return message


class SymlinkTests(SafeError):
    def setUp(self):
        self.base = base_dir()
        self.real = os.path.join(self.base, 'real')
        os.makedirs(os.path.join(self.real, 'logfile'))
        self.link = os.path.join(self.base, 'link')
        os.symlink(self.real, self.link)

    def test_symlink_root_rejected(self):
        self.assertSafe(fs.open_root, self.link)
        self.assertSafe(fs.open_root, self.link + '/logfile')

    def test_symlink_ancestor_rejected(self):
        nested = os.path.join(self.link, 'sub')
        os.makedirs(nested)
        self.assertSafe(fs.open_root, nested)

    def test_symlink_leaf_rejected(self):
        touch(os.path.join(self.base, 'outside.txt'), b'secret')
        root = base_dir()
        os.makedirs(os.path.join(root, 'data'))
        os.symlink(os.path.join(self.base, 'outside.txt'), os.path.join(root, 'data', 'x'))
        fd = fs.open_root(root)
        try:
            self.assertSafe(fs.read_at, fd, 'data/x')
        finally:
            os.close(fd)

    def test_symlink_in_data_is_listed_not_followed(self):
        root = base_dir()
        os.makedirs(os.path.join(root, 'plugin/data/Demo'))
        touch(os.path.join(root, 'outside.txt'), b'x')
        os.symlink(os.path.join(root, 'outside.txt'), os.path.join(root, 'plugin/data/Demo/x'))
        outcome = files.cockpit_data(make_ctx(root), {'namespace': 'Demo'})
        self.assertEqual(outcome.data['entries'][0]['type'], 'link')
        self.assertSafe(files.cockpit_data, make_ctx(root),
                        {'namespace': 'Demo', 'mode': 'read', 'path': 'x'})


class PathTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        os.makedirs(os.path.join(self.root, 'plugin/data/Demo/sub dir/中文'))
        touch(os.path.join(self.root, 'plugin/data/Demo/sub dir/中文/a b.txt'), b'hello')

    def test_namespace_rejected(self):
        for value in ('', '.', '..', 'a/b', 'a\\b', '/abs'):
            self.assertSafe(files.cockpit_data, make_ctx(self.root), {'namespace': value})

    def test_path_rejected(self):
        for value in ('../x', 'a/../../x', '/etc/passwd', '..\\x'):
            self.assertSafe(files.cockpit_data, make_ctx(self.root),
                            {'namespace': 'Demo', 'path': value})

    def test_nested_unicode_and_space(self):
        outcome = files.cockpit_data(make_ctx(self.root), {'namespace': 'Demo', 'path': 'sub dir/中文'})
        self.assertEqual(outcome.data['entries'][0]['name'], 'a b.txt')
        outcome = files.cockpit_data(make_ctx(self.root),
                                  {'namespace': 'Demo', 'mode': 'read',
                                   'path': 'sub dir/中文/a b.txt'})
        self.assertEqual(outcome.data['content'], 'hello')
        self.assertFalse(outcome.truncated)

    def test_path_with_dot_components(self):
        outcome = files.cockpit_data(make_ctx(self.root),
                                  {'namespace': 'Demo', 'path': './sub dir/中文/./'})
        self.assertEqual(outcome.data['entries'][0]['name'], 'a b.txt')


class PermissionTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        touch(os.path.join(self.root, 'plugin/data/Demo/a.txt'), b'ok')
        os.makedirs(os.path.join(self.root, 'plugin/data/OlivOSCockpit/control'))
        touch(os.path.join(self.root, 'plugin/data/OlivOSCockpit/control/config.json'), b'{}')

    def read(self, ctx):
        return files.cockpit_data(ctx, {'namespace': 'Demo', 'mode': 'read', 'path': 'a.txt'})

    def test_lite_default_denies_real_read(self):
        out = self.read(make_scoped_ctx(self.root, contracts.MODE_LITE))
        self.assertTrue(out.is_error)
        self.assertNotIn('ok', repr(out.data))

    def test_lite_opt_in_and_full_default_allow(self):
        self.assertEqual(self.read(make_scoped_ctx(self.root)).data['content'], 'ok')
        self.assertEqual(self.read(make_scoped_ctx(
            self.root, contracts.MODE_LITE, lite_real_account_read=True)).data['content'], 'ok')

    def test_control_directory_is_permanently_forbidden(self):
        for mode in (contracts.MODE_FULL, contracts.MODE_LITE):
            ctx = make_scoped_ctx(self.root, mode, lite_real_account_read=True)
            for namespace in ('OlivOSCockpit', 'olivoscockpit'):
                self.assertSafe(files.cockpit_data, ctx, {'namespace': namespace})
                self.assertSafe(files.cockpit_data, ctx, {
                    'namespace': namespace, 'mode': 'read', 'path': 'control/config.json'})

    def test_denied_paths_cover_file_and_directory_entries(self):
        touch(os.path.join(self.root, 'plugin/data/Demo/hidden/secret.txt'), b's')
        ctx = make_scoped_ctx(self.root, denied_paths=('Demo/hidden',))
        self.assertSafe(files.cockpit_data, ctx,
                        {'namespace': 'Demo', 'mode': 'read', 'path': 'hidden/secret.txt'})
        names = [entry['name'] for entry in files.cockpit_data(
            ctx, {'namespace': 'Demo'}).data['entries']]
        self.assertNotIn('hidden', names)

    def test_denied_paths_cover_absolute_log_path(self):
        logdir = os.path.join(self.root, 'logfile')
        touch(os.path.join(logdir, 'a.log'), b'x\n')
        touch(os.path.join(logdir, 'b.log'), b'y\n')
        ctx = make_scoped_ctx(self.root, denied_paths=(os.path.join(logdir, 'a.log'),))
        self.assertSafe(files.cockpit_log, ctx, {'filename': 'a.log'})
        self.assertEqual(files.cockpit_log(ctx, {}).data['filename'], 'b.log')


class SpecialFileTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        self.ns = os.path.join(self.root, 'plugin/data/Demo')
        self.logdir = os.path.join(self.root, 'logfile')
        os.makedirs(self.ns)
        os.makedirs(self.logdir)

    def test_fifo_rejected(self):
        os.mkfifo(os.path.join(self.ns, 'pipe'))
        self.assertSafe(files.cockpit_data, make_ctx(self.root),
                        {'namespace': 'Demo', 'mode': 'read', 'path': 'pipe'})
        self.assertSafe(files.cockpit_log, make_ctx(self.root), {'filename': 'pipe'})

    def test_fifo_in_logdir_explicit_filename(self):
        os.mkfifo(os.path.join(self.logdir, 'x.log'))
        self.assertSafe(files.cockpit_log, make_ctx(self.root), {'filename': 'x.log'})

    def test_no_log_file(self):
        self.assertSafe(files.cockpit_log, make_ctx(self.root), {})


class DataTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        self.ns = os.path.join(self.root, 'plugin/data/Demo')
        os.makedirs(self.ns)

    def test_utf8_file_is_returned_without_splitting_codepoints(self):
        payload = ('中文结尾' * 1000 + '\n').encode('utf-8')
        touch(os.path.join(self.ns, 'cn'), payload)
        _, reply, result = read_page(
            make_ctx(self.root), {'namespace': 'Demo', 'mode': 'read', 'path': 'cn'})
        self.assertFalse(result['isError'])
        self.assertEqual(result['structuredContent']['content'], payload.decode('utf-8'))
        self.assertEqual(json.loads(result['content'][0]['text']), result['structuredContent'])
        self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)

    def test_long_plain_text_is_not_charged_as_jsonl(self):
        original = 'unlabelled-sensitive-value ' * 25000
        path = os.path.join(self.ns, 'failure.txt')
        payload = original.encode('utf-8')
        touch(path, payload)
        ctx = make_ctx(self.root)
        cursor = None
        parts = []
        pages = 0
        while True:
            args = {'namespace': 'Demo', 'mode': 'read', 'path': 'failure.txt'}
            if cursor is not None:
                args['cursor'] = cursor
            _, reply, result = read_page(ctx, args)
            data = result['structuredContent']
            self.assertFalse(result['isError'])
            self.assertTrue(data['paged'])
            self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)
            parts.append(data['content'])
            cursor = data.get('next_cursor')
            pages += 1
            if cursor is None:
                break
            self.assertLess(pages, 10)
        self.assertGreater(pages, 1)
        self.assertEqual(''.join(parts), original)
        self.assertEqual(read_bytes(path), payload)

    def test_jsonl_preserves_line_framing_and_paginates_only_complete_rows(self):
        lines = ['{"id":0,"token":"private-value","pad":"' + '界' * 7000 + '"}']
        lines.extend('{"id":%d,"token":"private-value","pad":"%s"}'
                     % (index, '界' * 7000) for index in range(1, 60))
        payload = ('\r\n'.join(lines[:-1]) + '\r\n' + lines[-1]).encode('utf-8')
        path = os.path.join(self.ns, 'records.jsonl')
        touch(path, payload)
        ctx = make_ctx(self.root)
        cursor = None
        parts = []
        parsed = []
        pages = 0
        while True:
            args = {'namespace': 'Demo', 'mode': 'read', 'path': 'records.jsonl'}
            if cursor is not None:
                args['cursor'] = cursor
            _, reply, result = read_page(ctx, args, known=('private-value',), modern=bool(pages % 2))
            data = result['structuredContent']
            self.assertTrue(data['paged'])
            self.assertNotIn('sha256', data)
            self.assertEqual(json.loads(result['content'][0]['text']), data)
            self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)
            part = data['content']
            for line in part.split('\n'):
                if line:
                    parsed.append(json.loads(line))
            parts.append(part)
            cursor = data.get('next_cursor')
            pages += 1
            if cursor is None:
                break
            self.assertLess(pages, 100)
        joined = ''.join(parts)
        self.assertGreater(pages, 1)
        self.assertEqual(joined.count('\r\n'), len(lines) - 1)
        self.assertFalse(joined.endswith('\n'))
        self.assertTrue(all(record['token'] == '[REDACTED]' for record in parsed))
        self.assertEqual([record['id'] for record in parsed], list(range(60)))
        self.assertEqual(read_bytes(path), payload)

    def test_jsonl_full_view_fits_before_cursor_prefixes(self):
        path = os.path.join(self.ns, 'edge.jsonl')
        args = {'namespace': 'Demo', 'mode': 'read', 'path': 'edge.jsonl'}
        for modern in (False, True):
            with self.subTest(modern=modern):
                padding = 500000
                for _ in range(3):
                    content = '{"pad":"' + 'x' * padding + '"}\n{}\n'
                    data = {'namespace': 'Demo', 'path': 'edge.jsonl', 'size': len(content),
                            'content': content, 'file_size': len(content), 'paged': True}
                    expected = json.dumps(protocol._page_body(1, data, modern, False),
                                          ensure_ascii=True, allow_nan=False, separators=(',', ':'))
                    padding += (contracts.MAX_RESPONSE - len(expected)) // 2
                content = '{"pad":"' + 'x' * padding + '"}\n{}\n'
                touch(path, content.encode('utf-8'))
                _, reply, result = read_page(make_ctx(self.root), args, modern=modern)
                self.assertFalse(result['isError'])
                data = result['structuredContent']
                self.assertTrue(data['paged'])
                self.assertNotIn('next_cursor', data)
                self.assertNotIn('sha256', data)
                self.assertEqual(data['content'], content)
                self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)

    def test_jsonl_surrogate_escape_pages_without_losing_unicode(self):
        first = '{"token":"private-value","s":"' + chr(92) + 'ud800"}'
        lines = [first] + ['{"pad":"' + 'x' * 1050 + '"}' for _ in range(700)]
        payload = '\n'.join(lines).encode('utf-8')
        self.assertLess(len(payload), contracts.MAX_FILE)
        path = os.path.join(self.ns, 'surrogate.jsonl')
        touch(path, payload)
        ctx = make_ctx(self.root)
        cursor = None
        parts = []
        parsed = []
        pages = 0
        while True:
            args = {'namespace': 'Demo', 'mode': 'read', 'path': 'surrogate.jsonl'}
            if cursor is not None:
                args['cursor'] = cursor
            _, reply, result = read_page(ctx, args)
            data = result['structuredContent']
            self.assertFalse(result['isError'])
            self.assertTrue(data['paged'])
            self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)
            part = data['content']
            for line in part.split('\n'):
                if line:
                    parsed.append(json.loads(line))
            parts.append(part)
            cursor = data.get('next_cursor')
            pages += 1
            if cursor is None:
                break
            self.assertLess(pages, 100)
        self.assertGreater(pages, 1)
        self.assertEqual(parsed[0]['token'], '[REDACTED]')
        self.assertEqual(ord(parsed[0]['s']), 0xD800)
        self.assertIn('\\ud800', ''.join(parts))
        self.assertEqual(read_bytes(path), payload)

    def test_jsonl_cursor_v2_line_boundary_and_legacy_rejection(self):
        path = os.path.join(self.ns, 'cursor.txt')
        payload = ''.join('{"id":%d,"pad":"%s"}\n' % (index, '界' * 1000)
                          for index in range(400)).encode('utf-8')
        touch(path, payload)
        ctx = make_ctx(self.root)
        _, _, first = read_page(ctx, {
            'namespace': 'Demo', 'mode': 'read', 'path': 'cursor.txt'})
        cursor = first['structuredContent'].get('next_cursor')
        self.assertIsNotNone(cursor)
        state = files._consume_cursor(cursor)
        self.assertEqual(state['v'], 2)
        self.assertTrue(state['jsonl'])
        invalid = dict(state, view_offset=state['view_offset'] + 1)
        _, _, rejected = read_page(ctx, {
            'namespace': 'Demo', 'mode': 'read', 'path': 'cursor.txt',
            'cursor': files._encode_cursor(invalid)})
        self.assertTrue(rejected['isError'])
        self.assertIn('cursor position', rejected['structuredContent']['error'])
        legacy = files._encode_cursor(dict(state, v=1))
        with self.assertRaises(ToolError):
            files.cockpit_data(ctx, {
                'namespace': 'Demo', 'mode': 'read', 'path': 'cursor.txt',
                'cursor': legacy})

    def test_jsonl_invalid_and_oversized_rows_fail_without_partial_output(self):
        secret = 'private-value'
        touch(os.path.join(self.ns, 'invalid.jsonl'),
              ('{"token":' + json.dumps(secret) + '}\nnot-json').encode('utf-8'))
        _, reply, result = read_page(make_ctx(self.root), {
            'namespace': 'Demo', 'mode': 'read', 'path': 'invalid.jsonl'})
        self.assertTrue(result['isError'])
        self.assertNotIn(secret, reply.body.decode('ascii'))
        payload = ('{"pad":"' + '界' * 100000 + '"}').encode('utf-8')
        touch(os.path.join(self.ns, 'large-row.jsonl'), payload)
        _, reply, result = read_page(make_ctx(self.root), {
            'namespace': 'Demo', 'mode': 'read', 'path': 'large-row.jsonl'})
        self.assertTrue(result['isError'])
        self.assertNotIn('content', result['structuredContent'])
        self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)

    def test_jsonl_blank_rows_consume_the_node_budget(self):
        touch(os.path.join(self.ns, 'blank.jsonl'), b'\n' * 1000)
        with patch.object(redaction, 'MAX_NODES', 32):
            _, reply, result = read_page(make_ctx(self.root), {
                'namespace': 'Demo', 'mode': 'read', 'path': 'blank.jsonl'})
        self.assertTrue(result['isError'])
        self.assertTrue(result['structuredContent']['truncated'])
        self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)

    def test_invalid_utf8_still_rejected_at_limit(self):
        touch(os.path.join(self.ns, 'bad'), b'a' * (contracts.MAX_FILE - 2) + b'\xff\xff')
        self.assertSafe(files.cockpit_data, make_ctx(self.root),
                        {'namespace': 'Demo', 'mode': 'read', 'path': 'bad'})

    def test_binary_rejected(self):
        touch(os.path.join(self.ns, 'bin'), b'\xff\xfe\x00')
        self.assertSafe(files.cockpit_data, make_ctx(self.root),
                        {'namespace': 'Demo', 'mode': 'read', 'path': 'bin'})

    def test_oversized_unframed_record_is_rejected_safely(self):
        touch(os.path.join(self.ns, 'big'), b'a' * (contracts.MAX_FILE + 10))
        _, reply, result = read_page(
            make_ctx(self.root), {'namespace': 'Demo', 'mode': 'read', 'path': 'big'})
        self.assertTrue(result['isError'])
        self.assertIn('safe bounded record', result['structuredContent']['error'])
        self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)

    def test_large_line_records_are_reassembled_through_sequential_pages(self):
        payload = ''.join('%02d:' % index + '界' * 15000 + '\n'
                          for index in range(35)).encode('utf-8')
        touch(os.path.join(self.ns, 'lines.txt'), payload)
        ctx = make_ctx(self.root)
        cursor = None
        parts = []
        pages = 0
        while True:
            args = {'namespace': 'Demo', 'mode': 'read', 'path': 'lines.txt'}
            if cursor is not None:
                args['cursor'] = cursor
            _, reply, result = read_page(ctx, args)
            data = result['structuredContent']
            self.assertTrue(data['paged'])
            self.assertNotIn('sha256', data)
            self.assertEqual(json.loads(result['content'][0]['text']), data)
            self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)
            parts.append(data['content'])
            cursor = data.get('next_cursor')
            pages += 1
            if cursor is None:
                break
            self.assertLess(pages, 100)
        self.assertGreater(pages, 1)
        self.assertEqual(''.join(parts), payload.decode('utf-8'))

    def test_complete_json_context_is_redacted_before_view_pagination(self):
        secret = 'credential-not-for-output'
        payload = ('{"token":' + json.dumps(secret) + ',"pad":"'
                   + '界' * 100000 + '"}').encode('utf-8')
        touch(os.path.join(self.ns, 'large.json'), payload)
        ctx = make_ctx(self.root)
        cursor = None
        parts = []
        pages = 0
        rules = redaction.policy({'redact_fields': ['next_cursor']})
        while True:
            args = {'namespace': 'Demo', 'mode': 'read', 'path': 'large.json'}
            if cursor is not None:
                args['cursor'] = cursor
            _, reply, result = read_page(
                ctx, args, known=(secret, 'A'), modern=bool(pages % 2), policy=rules)
            data = result['structuredContent']
            self.assertTrue(data['paged'])
            self.assertNotIn('sha256', data)
            self.assertNotIn(secret, reply.body.decode('ascii'))
            self.assertEqual(json.loads(result['content'][0]['text']), data)
            self.assertLessEqual(len(reply.body), contracts.MAX_RESPONSE)
            parts.append(data['content'])
            cursor = data.get('next_cursor')
            if cursor is not None:
                self.assertNotEqual(cursor, '[REDACTED]')
                self.assertLessEqual(len(cursor), 1024)
            pages += 1
            if cursor is None:
                break
            self.assertLess(pages, 100)
        cleaned = json.loads(''.join(parts))
        self.assertEqual(cleaned['token'], '[REDACTED]')
        self.assertGreater(pages, 1)

    def test_cursor_rejects_changed_credential_cleaning_context(self):
        secret = 'known-secret-from-host'
        touch(os.path.join(self.ns, 'context.json'),
              ('{"token":' + json.dumps(secret) + ',"pad":"'
               + '界' * 100000 + '"}').encode('utf-8'))
        ctx = make_ctx(self.root)
        _, _, first = read_page(
            ctx, {'namespace': 'Demo', 'mode': 'read', 'path': 'context.json'},
            known=(secret,))
        cursor = first['structuredContent'].get('next_cursor')
        self.assertIsNotNone(cursor)
        _, _, resumed = read_page(
            ctx, {'namespace': 'Demo', 'mode': 'read', 'path': 'context.json',
                  'cursor': cursor}, known=('different-secret',))
        self.assertTrue(resumed['isError'])
        self.assertIn('redaction policy', resumed['structuredContent']['error'])
        self.assertNotIn(secret, json.dumps(resumed))

    def test_cursor_replay_tamper_path_revision_and_generation_fail_closed(self):
        path = os.path.join(self.ns, 'cursor.json')
        payload = ('{"pad":"' + '界' * 100000 + '"}').encode('utf-8')
        touch(path, payload)
        ctx = make_ctx(self.root)

        def first_cursor(context=ctx, filename='cursor.json'):
            _, _, result = read_page(context, {
                'namespace': 'Demo', 'mode': 'read', 'path': filename})
            return result['structuredContent'].get('next_cursor')

        tampered = first_cursor()
        self.assertIsNotNone(tampered)
        changed = tampered[:-1] + ('A' if tampered[-1] != 'A' else 'B')
        with self.assertRaises(ToolError):
            files.cockpit_data(ctx, {'namespace': 'Demo', 'mode': 'read',
                                     'path': 'cursor.json', 'cursor': changed})

        replay = first_cursor()
        args = {'namespace': 'Demo', 'mode': 'read', 'path': 'cursor.json', 'cursor': replay}
        _, _, replayed = read_page(ctx, args)
        _, _, repeated = read_page(ctx, args)
        self.assertEqual(replayed['structuredContent']['content'],
                         repeated['structuredContent']['content'])

        cross_file = first_cursor()
        touch(os.path.join(self.ns, 'other.json'), payload)
        with self.assertRaises(ToolError):
            files.cockpit_data(ctx, {'namespace': 'Demo', 'mode': 'read',
                                     'path': 'other.json', 'cursor': cross_file})

        revised = first_cursor()
        info_before = os.stat(path)
        with open(path, 'r+b') as stream:
            stream.seek(10)
            stream.write(b'X')
            stream.flush()
        info_after = os.stat(path)
        self.assertEqual((info_before.st_dev, info_before.st_ino, info_before.st_size),
                         (info_after.st_dev, info_after.st_ino, info_after.st_size))
        with self.assertRaises(ToolError):
            files.cockpit_data(ctx, {'namespace': 'Demo', 'mode': 'read',
                                     'path': 'cursor.json', 'cursor': revised})

        touch(os.path.join(self.ns, 'generation.json'), payload)
        generation_one = Context(
            None, self.root, os.path.join(self.root, 'plugin/data'), olivos=host_stub(),
            config=Manager(Snapshot(generation=1)), request_generation=1)
        generation_two = Context(
            None, self.root, os.path.join(self.root, 'plugin/data'), olivos=host_stub(),
            config=Manager(Snapshot(generation=2)), request_generation=2)
        generation_cursor = first_cursor(generation_one, 'generation.json')
        with self.assertRaises(ToolError):
            files.cockpit_data(generation_two, {
                'namespace': 'Demo', 'mode': 'read', 'path': 'generation.json',
                'cursor': generation_cursor})

    def test_large_directory_bounded(self):
        for index in range(MAX_ENTRIES + 40):
            touch(os.path.join(self.ns, 'f%04d' % index))
        outcome = files.cockpit_data(make_ctx(self.root), {'namespace': 'Demo'})
        self.assertTrue(outcome.truncated)
        self.assertEqual(len(outcome.data['entries']), MAX_ENTRIES)

    def test_missing_namespace(self):
        self.assertSafe(files.cockpit_data, make_ctx(self.root), {'namespace': 'Nope'})
        self.assertSafe(files.cockpit_data, make_ctx(self.root),
                        {'namespace': 'Demo', 'mode': 'read', 'path': 'missing'})


class LogTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        self.logdir = os.path.join(self.root, 'logfile')
        os.makedirs(self.logdir)

    def test_picks_newest_log(self):
        touch(os.path.join(self.logdir, 'old.log'), b'old\n')
        touch(os.path.join(self.logdir, 'new.log'), b'new\n')
        touch(os.path.join(self.logdir, 'notes.txt'), b'ignore\n')
        os.utime(os.path.join(self.logdir, 'old.log'), (1000, 1000))
        os.utime(os.path.join(self.logdir, 'new.log'), (2000, 2000))
        outcome = files.cockpit_log(make_ctx(self.root), {})
        self.assertEqual(outcome.data['filename'], 'new.log')
        self.assertEqual(outcome.data['lines'], 'new\n')

    def test_filters_are_text_not_regex(self):
        lines = ['INFO [One] started\n', 'WARN [Two] slow\n', 'info [One] again\n']
        touch(os.path.join(self.logdir, 'a.log'), ''.join(lines).encode())
        outcome = files.cockpit_log(make_ctx(self.root), {'level': 'info', 'namespace': '[One]'})
        self.assertEqual(outcome.data['lines'], 'INFO [One] started\ninfo [One] again\n')
        outcome = files.cockpit_log(make_ctx(self.root), {'namespace': '.*'})
        self.assertEqual(outcome.data['lines'], '')
        self.assertTrue(outcome.truncated)

    def test_tail_truncation_keeps_newest(self):
        old = b'old-start\n' + b'x' * 200 + b'\n'
        tail = b'last-line\n'
        touch(os.path.join(self.logdir, 'big.log'), old + tail)
        outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'big.log'})
        self.assertFalse(outcome.truncated)  # 远小于 8 MiB 上限
        self.assertTrue(outcome.data['lines'].endswith('last-line\n'))
        original = files.MAX_LOG_SCAN  # 模块按值导入的常量
        try:
            files.MAX_LOG_SCAN = 12
            outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'big.log'})
        finally:
            files.MAX_LOG_SCAN = original
        self.assertTrue(outcome.truncated)
        self.assertIn('last-line', outcome.data['lines'])

    def test_newline_flood_bounded(self):
        # 1 MiB 纯换行约 100 万行；有界尾部切片不应构造全量行对象。
        touch(os.path.join(self.logdir, 'flood.log'), b'\n' * (1024 * 1024))
        outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'flood.log'})
        self.assertTrue(outcome.truncated)
        self.assertLessEqual(len(outcome.data['lines'].split('\n')), contracts.MAX_LOG_LINES + 1)

    def test_line_limit(self):
        data = b''.join(b'line-%d\n' % index for index in range(contracts.MAX_LOG_LINES + 20))
        touch(os.path.join(self.logdir, 'many.log'), data)
        outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'many.log'})
        self.assertTrue(outcome.truncated)
        lines = outcome.data['lines'].splitlines()
        self.assertEqual(len(lines), contracts.MAX_LOG_LINES)
        self.assertEqual(lines[-1], 'line-%d' % (contracts.MAX_LOG_LINES + 19))

    def test_requested_line_count_returns_only_latest_lines(self):
        touch(os.path.join(self.logdir, 'short.log'), b'one\ntwo\nthree\n')
        outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'short.log', 'lines': 2})
        self.assertEqual(outcome.data['lines'], 'two\nthree\n')
        self.assertTrue(outcome.truncated)
        spec = next(tool for tool in files.TOOLS if tool.name == 'cockpit_log')
        for invalid in (0, contracts.MAX_LOG_LINES + 1, True, '2'):
            with self.assertRaises(ToolError):
                contracts.validate_arguments(spec, {'lines': invalid})

    def test_tail_starting_mid_codepoint(self):
        prefix = '前缀'.encode()  # 6 字节，3 字节码点
        touch(os.path.join(self.logdir, 'cn.log'), b'x' * 5 + prefix + '\n完整行\n'.encode())
        original = files.MAX_LOG_SCAN
        try:
            files.MAX_LOG_SCAN = 16  # 落在“前”的 3 字节中间
            outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'cn.log'})
        finally:
            files.MAX_LOG_SCAN = original
        self.assertTrue(outcome.truncated)
        self.assertEqual(outcome.data['lines'], '完整行\n')
        self.assertEqual(outcome.data['bytes_scanned'], 16)
        self.assertFalse(outcome.data['lines'].startswith('\ufffd'))

    def test_tail_partial_first_line_kept_whole(self):
        touch(os.path.join(self.logdir, 'lines.log'), b'line-one\nline-two\nline-three\n')
        original = files.MAX_LOG_SCAN
        try:
            files.MAX_LOG_SCAN = 15  # 落在 'line-two' 中间
            outcome = files.cockpit_log(make_ctx(self.root), {'filename': 'lines.log'})
        finally:
            files.MAX_LOG_SCAN = original
        self.assertTrue(outcome.truncated)
        self.assertEqual(outcome.data['lines'], 'line-three\n')

    def test_binary_log_rejected(self):
        touch(os.path.join(self.logdir, 'bin.log'), b'\xff\xfe\xfd')
        self.assertSafe(files.cockpit_log, make_ctx(self.root), {'filename': 'bin.log'})

    def test_filename_basename_only(self):
        self.assertSafe(files.cockpit_log, make_ctx(self.root), {'filename': '../x.log'})
        self.assertSafe(files.cockpit_log, make_ctx(self.root), {'filename': '/etc/passwd'})


class PluginTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        self.app = os.path.join(self.root, 'plugin/app')
        os.makedirs(self.app)

    def test_plugins_mixed_sources(self):
        make_opk(os.path.join(self.app, 'Alpha.opk'), namespace='Alpha')
        make_opk(os.path.join(self.app, 'Beta.opk'), namespace='Beta',
                 compression=zipfile.ZIP_STORED)
        touch(os.path.join(self.app, 'Gamma/app.json'), manifest_bytes('Gamma'))
        touch(os.path.join(self.app, 'notes.txt'), b'not a package')
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        by_name = {item['filename']: item for item in outcome.data['plugins']}
        self.assertEqual(by_name['Alpha.opk']['manifest']['namespace'], 'Alpha')
        self.assertEqual(by_name['Beta.opk']['manifest']['namespace'], 'Beta')
        self.assertEqual(by_name['Gamma']['manifest']['namespace'], 'Gamma')
        self.assertNotIn('notes.txt', by_name)
        self.assertNotIn('secret', by_name['Alpha.opk']['manifest'])
        self.assertFalse(outcome.truncated)

    def test_manifest_non_finite_float_dropped(self):
        payload = (b'{"namespace": "Demo", "version": NaN, "svn": Infinity,'
                   b' "priority": 1.5, "name": "Demo"}')
        touch(os.path.join(self.app, 'NaN/app.json'), payload)
        outcome = files.cockpit_meta(make_ctx(self.root), {'namespace': 'Demo'})
        self.assertEqual(outcome.data['manifest']['priority'], 1.5)
        self.assertNotIn('version', outcome.data['manifest'])
        self.assertNotIn('svn', outcome.data['manifest'])
        json.dumps(outcome.data, allow_nan=False)

    def test_deep_manifest_rejected_before_decode(self):
        old = sys.getrecursionlimit()
        sys.setrecursionlimit(100000)
        try:
            payload = b'{"namespace": "Demo", "name": ' + b'[' * 40 + b']' * 40 + b'}'
            touch(os.path.join(self.app, 'Deep/app.json'), payload)
            self.assertSafe(files.cockpit_meta, make_ctx(self.root), {'filename': 'Deep'})
            outcome = files.cockpit_plugins(make_ctx(self.root), {})
            record = {item['filename']: item for item in outcome.data['plugins']}['Deep']
            self.assertIn('error', record)
        finally:
            sys.setrecursionlimit(old)

    def test_oversized_source_manifest_rejected(self):
        payload = b'{"namespace": "Demo", "pad": "' + b'x' * contracts.MAX_MANIFEST + b'"}'
        touch(os.path.join(self.app, 'Big/app.json'), payload)
        self.assertSafe(files.cockpit_meta, make_ctx(self.root),
                        {'filename': 'Big'})
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        record = {item['filename']: item for item in outcome.data['plugins']}['Big']
        self.assertIn('error', record)

    def test_bad_packages_reported_not_fatal(self):
        make_opk(os.path.join(self.app, 'Good.opk'), namespace='Good')
        touch(os.path.join(self.app, 'Broken.opk'), b'not a zip')
        make_opk(os.path.join(self.app, 'Dup.opk'), duplicate=True)
        oversized = os.path.join(self.app, 'Huge.opk')
        with open(oversized, 'wb') as fp:
            fp.truncate(contracts.MAX_OPK + 1)
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        records = {item['filename']: item for item in outcome.data['plugins']}
        self.assertEqual(records['Good.opk']['manifest']['namespace'], 'Good')
        self.assertIn('error', records['Broken.opk'])
        self.assertIn('error', records['Dup.opk'])
        self.assertIn('error', records['Huge.opk'])
        self.assertNotIn(tempfile.gettempdir(), json.dumps(outcome.data))

    def test_large_directory_bounded(self):
        for index in range(MAX_ENTRIES + 5):
            make_opk(os.path.join(self.app, 'P%03d.opk' % index), namespace='P%03d' % index)
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        self.assertTrue(outcome.truncated)
        self.assertEqual(len(outcome.data['plugins']), MAX_ENTRIES)

    def test_meta_by_namespace_with_lite_filename(self):
        make_opk(os.path.join(self.app, 'OlivOSCockpitLite.opk'), namespace='OlivOSCockpit')
        outcome = files.cockpit_meta(make_ctx(self.root), {'namespace': 'OlivOSCockpit'})
        self.assertEqual(outcome.data['filename'], 'OlivOSCockpitLite.opk')
        self.assertEqual(outcome.data['manifest']['namespace'], 'OlivOSCockpit')

    def test_meta_by_namespace_source_dir(self):
        touch(os.path.join(self.app, 'Src/app.json'), manifest_bytes('Src'))
        outcome = files.cockpit_meta(make_ctx(self.root), {'namespace': 'Src'})
        self.assertEqual(outcome.data['manifest']['namespace'], 'Src')

    def test_meta_requires_exactly_one_selector(self):
        self.assertSafe(files.cockpit_meta, make_ctx(self.root), {})
        self.assertSafe(files.cockpit_meta, make_ctx(self.root),
                        {'namespace': 'A', 'filename': 'A.opk'})
        self.assertSafe(files.cockpit_meta, make_ctx(self.root), {'filename': '../A.opk'})

    def test_meta_ambiguous_and_missing(self):
        make_opk(os.path.join(self.app, 'A.opk'), namespace='Same')
        make_opk(os.path.join(self.app, 'B.opk'), namespace='Same')
        self.assertSafe(files.cockpit_meta, make_ctx(self.root), {'namespace': 'Same'})
        self.assertSafe(files.cockpit_meta, make_ctx(self.root), {'namespace': 'Missing'})
        self.assertSafe(files.cockpit_meta, make_ctx(self.root), {'filename': 'Missing.opk'})

    def test_non_directory_package_path_closes_fd(self):
        touch(os.path.join(self.root, 'plugin/data/Demo'), b'x')
        touch(os.path.join(self.root, 'logfile'), b'x')
        fd_dir = '/proc/self/fd'
        before = len(os.listdir(fd_dir)) if os.path.isdir(fd_dir) else None
        for _ in range(20):
            self.assertSafe(files.cockpit_data, make_ctx(self.root), {'namespace': 'Demo'})
            self.assertSafe(files.cockpit_log, make_ctx(self.root), {})
        if before is not None:
            self.assertEqual(len(os.listdir(fd_dir)), before)

    def test_meta_by_filename(self):
        make_opk(os.path.join(self.app, 'A.opk'), namespace='A')
        outcome = files.cockpit_meta(make_ctx(self.root), {'filename': 'A.opk'})
        self.assertEqual(outcome.data['manifest']['name'], 'Demo')
        touch(os.path.join(self.app, 'Src/app.json'), manifest_bytes('Src'))
        outcome = files.cockpit_meta(make_ctx(self.root), {'filename': 'Src'})
        self.assertEqual(outcome.data['manifest']['namespace'], 'Src')

    def test_meta_reports_digest_and_size_from_the_same_read(self):
        package = os.path.join(self.app, 'A.opk')
        make_opk(package, namespace='A')
        outcome = files.cockpit_meta(make_ctx(self.root), {'filename': 'A.opk'})
        raw = read_bytes(package)
        self.assertEqual(outcome.data['size'], len(raw))
        self.assertEqual(outcome.data['sha256'], hashlib.sha256(raw).hexdigest())


class OpkTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        self.app = os.path.join(self.root, 'plugin/app')
        os.makedirs(self.app)

    def check_rejects(self, builder, name='Test.opk'):
        path = os.path.join(self.app, name)
        builder(path)
        fd = fs.open_root(self.app)
        try:
            self.assertSafe(fs.package_manifest, fs.read_package(fd, name))
        finally:
            os.close(fd)

    def test_manifest_too_large_by_header(self):
        def build(path):
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('app.json', b'{' + b' ' * contracts.MAX_MANIFEST + b'}')
        self.check_rejects(build)

    def test_stored_central_directory_claims_small(self):
        # 中央目录声称 5 字节，实际存储内容更大且是合法 JSON。
        path = os.path.join(self.app, 'Liar.opk')
        payload = json.dumps({'namespace': 'Liar', 'pad': 'p' * 1000}).encode()
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as archive:
            archive.writestr('app.json', payload)
        raw = bytearray(read_bytes(path))
        marker = b'app.json'
        start = raw.find(marker) - 30  # 中央目录条目内 name 前有 30 字节固定头与额外信息
        cd = raw.find(b'PK\x01\x02')
        size_offset = cd + 24  # 中央目录：压缩大小(20) 之后是未压缩大小(24)
        filename_len = int.from_bytes(raw[cd + 28:cd + 30], 'little')
        extra_len = int.from_bytes(raw[cd + 30:cd + 32], 'little')
        assert raw[cd + 46:cd + 46 + filename_len] == b'app.json'
        assert start < cd
        raw[size_offset:size_offset + 4] = (5).to_bytes(4, 'little')
        raw[cd + 20:cd + 24] = (5).to_bytes(4, 'little')
        del filename_len, extra_len
        with open(path, 'wb') as fp:
            fp.write(raw)
        fd = fs.open_root(self.app)
        try:
            try:
                result = fs.package_manifest(fs.read_package(fd, 'Liar.opk'))
            except ToolError:
                return  # 声明小于实际时读取被声明值截断，解析失败即安全
            self.assertLessEqual(len(result), 5)
        finally:
            os.close(fd)

    def test_encrypted_rejected(self):
        def build(path):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app.json', manifest_bytes())
            raw = bytearray(read_bytes(path))
            cd = raw.find(b'PK\x01\x02')
            flags = int.from_bytes(raw[cd + 8:cd + 10], 'little') | 1
            raw[cd + 8:cd + 10] = flags.to_bytes(2, 'little')
            local = raw.find(b'PK\x03\x04')
            flags = int.from_bytes(raw[local + 6:local + 8], 'little') | 1
            raw[local + 6:local + 8] = flags.to_bytes(2, 'little')
            with open(path, 'wb') as fp:
                fp.write(raw)
        self.check_rejects(build)

    def test_bad_compression_rejected(self):
        def build(path):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app.json', manifest_bytes())
            raw = bytearray(read_bytes(path))
            cd = raw.find(b'PK\x01\x02')
            raw[cd + 10:cd + 12] = (12).to_bytes(2, 'little')  # bzip2
            with open(path, 'wb') as fp:
                fp.write(raw)
        self.check_rejects(build)

    def test_zip64_locator_rejected(self):
        def build(path):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app.json', manifest_bytes())
            with open(path, 'ab') as fp:
                fp.write(b'PK\x06\x07' + b'\x00' * 16)
                fp.write(b'PK\x06\x06' + b'\x00' * 40)
                fp.write(b'PK\x05\x06' + b'\x00' * 18)
        self.check_rejects(build)

    def test_multidisk_rejected(self):
        def build(path):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app.json', manifest_bytes())
            raw = bytearray(read_bytes(path))
            eocd = raw.rfind(b'PK\x05\x06')
            raw[eocd + 4:eocd + 6] = (1).to_bytes(2, 'little')
            with open(path, 'wb') as fp:
                fp.write(raw)
        self.check_rejects(build)

    def test_directory_entry_named_app_json(self):
        def build(path):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app.json/', b'')
                archive.writestr('other', b'x')
        path = os.path.join(self.app, 'Dir.opk')
        build(path)
        self.check_rejects(build, 'Dir.opk')

    def test_traversal_entry_rejected(self):
        def build(path):
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('app.json', manifest_bytes())
                archive.writestr('../evil', b'x')
        self.check_rejects(build)

    def test_malformed_data_crc(self):
        def build(path):
            with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as archive:
                archive.writestr('app.json', manifest_bytes())
            raw = bytearray(read_bytes(path))
            cd = raw.find(b'PK\x01\x02')
            name_len = int.from_bytes(raw[cd + 28:cd + 30], 'little')
            extra_len = int.from_bytes(raw[cd + 30:cd + 32], 'little')
            comment_len = int.from_bytes(raw[cd + 32:cd + 34], 'little')
            local_offset = int.from_bytes(raw[cd + 42:cd + 46], 'little')
            data_start = local_offset + 30 + name_len + extra_len
            raw[data_start:data_start + 2] = b'{"'
            raw[cd + 16:cd + 20] = (0xDEADBEEF).to_bytes(4, 'little')
            del comment_len
            with open(path, 'wb') as fp:
                fp.write(raw)
        self.check_rejects(build)


class ZipPrecheckTests(SafeError):
    """预检必须在 zipfile 构造之前拒绝；限额降到 8 让 16 条样本可复现。"""

    def setUp(self):
        self.limit = patch.object(fs, 'MAX_ZIP_ENTRIES', 8)
        self.limit.start()
        self.addCleanup(self.limit.stop)

    def assert_rejected_before_zipfile(self, data):
        with patch.object(fs.zipfile, 'ZipFile', side_effect=_no_zipfile):
            self.assertSafe(fs.package_manifest, data)

    def test_zip64_locator_bypass_rejected_before_zipfile(self):
        self.assert_rejected_before_zipfile(zip64_locator_sample())

    def test_declared_entry_count_lie_rejected_before_zipfile(self):
        self.assert_rejected_before_zipfile(lying_eocd_sample())

    def test_comment_pseudo_eocd_rejected_before_zipfile(self):
        root = base_dir()
        path = os.path.join(root, 'Comment.opk')
        comment_pseudo_eocd_sample(path)
        self.assert_rejected_before_zipfile(read_bytes(path))

    def test_zip64_local_header_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            with archive.open('app.json', 'w', force_zip64=True) as manifest:
                manifest.write(manifest_bytes())
        self.assertSafe(fs.package_manifest, buffer.getvalue())

    def test_normal_comments_and_prepended_stub_match_stdlib(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('app.json', manifest_bytes())
            archive.comment = b'ordinary package comment'
        for prefix in (b'', b'prepended archive stub'):
            self.assertEqual(fs.package_manifest(prefix + buffer.getvalue()), manifest_bytes())

    def test_normal_package_still_parses_below_limit(self):
        root = base_dir()
        path = os.path.join(root, 'Good.opk')
        make_opk(path)
        self.assertEqual(fs.package_manifest(read_bytes(path)), manifest_bytes())


class DescriptorTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        os.makedirs(os.path.join(self.root, 'data'))
        touch(os.path.join(self.root, 'data', 'x'), b'ok')

    def test_open_root_closes_fd_when_check_raises_base_exception(self):
        before = fd_count()
        with patch.object(fs, '_check_fd', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                fs.open_root(self.root)
        if before is not None:
            self.assertEqual(fd_count(), before)

    def test_open_rel_closes_fd_when_result_check_raises_base_exception(self):
        parent = fs.open_root(self.root)
        self.addCleanup(os.close, parent)
        before = fd_count()
        real_check = fs._check_fd
        calls = []

        def second_check(fd):
            calls.append(fd)
            if len(calls) == 2:
                raise KeyboardInterrupt
            return real_check(fd)

        with patch.object(fs, '_check_fd', side_effect=second_check):
            with self.assertRaises(KeyboardInterrupt):
                fs.open_rel(parent, 'data/x')
        if before is not None:
            self.assertEqual(fd_count(), before)

    def test_oserror_still_becomes_tool_error_and_closes(self):
        before = fd_count()
        with patch.object(fs, '_check_fd', side_effect=OSError):
            self.assertSafe(fs.open_root, self.root)
        if before is not None:
            self.assertEqual(fd_count(), before)


class PluginBudgetTests(SafeError):
    def setUp(self):
        self.root = base_dir()
        self.app = os.path.join(self.root, 'plugin/app')
        os.makedirs(self.app)

    def test_budget_stops_after_bounded_records(self):
        pad = 'x' * 60000
        for index in range(12):
            touch(os.path.join(self.app, 'P%02d/app.json' % index),
                  json.dumps({'namespace': 'P%02d' % index, 'info': pad}).encode())
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        self.assertTrue(outcome.truncated)
        self.assertLess(len(outcome.data['plugins']), 12)
        self.assertGreater(len(outcome.data['plugins']), 0)
        used = sum(len(json.dumps(item, ensure_ascii=True,
                                  separators=(',', ':')).encode('ascii'))
                   for item in outcome.data['plugins'])
        self.assertLessEqual(used, contracts.MAX_RESPONSE // 4)
        for item in outcome.data['plugins']:
            self.assertEqual(item['manifest']['info'], pad)

    def test_short_string_lists_are_counted_without_truncating_single_metadata(self):
        value = ['x' * 100] * 64
        for index in range(12):
            manifest = {key: value for key in ('name', 'version', 'svn', 'info', 'author', 'priority')}
            manifest['namespace'] = 'P%02d' % index
            touch(os.path.join(self.app, 'P%02d/app.json' % index), json.dumps(manifest).encode())
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        self.assertTrue(outcome.truncated)
        self.assertGreater(len(outcome.data['plugins']), 0)
        self.assertLess(len(outcome.data['plugins']), 12)
        self.assertEqual(outcome.data['plugins'][0]['manifest']['info'], value)
        self.assertEqual(files.cockpit_meta(make_ctx(self.root), {'filename': 'P00'}).data['manifest']['info'], value)

    def test_error_records_and_escaped_filenames_share_the_budget(self):
        for index in range(3):
            path = os.path.join(self.app, '坏' * 16 + str(index) + '.opk')
            with open(path, 'wb') as stream:
                if index == 0:
                    stream.truncate(contracts.MAX_OPK + 1)
                else:
                    stream.write(b'invalid package')
        with patch.object(files, 'MAX_RESPONSE', 1024, create=True):
            outcome = files.cockpit_plugins(make_ctx(self.root), {})
        self.assertTrue(outcome.truncated)
        self.assertGreater(len(outcome.data['plugins']), 0)
        self.assertLess(len(outcome.data['plugins']), 3)
        self.assertTrue(all('error' in item for item in outcome.data['plugins']))

    def test_budget_keeps_small_records_complete(self):
        make_opk(os.path.join(self.app, 'A.opk'), namespace='A')
        outcome = files.cockpit_plugins(make_ctx(self.root), {})
        self.assertFalse(outcome.truncated)
        self.assertEqual(outcome.data['plugins'][0]['manifest']['namespace'], 'A')

    def test_meta_namespace_scan_stops_at_second_match(self):
        make_opk(os.path.join(self.app, 'A.opk'), namespace='Same')
        make_opk(os.path.join(self.app, 'B.opk'), namespace='Same')
        make_opk(os.path.join(self.app, 'C.opk'), namespace='Same')
        with patch.object(fs, 'package_manifest', wraps=fs.package_manifest) as spy:
            self.assertSafe(files.cockpit_meta, make_ctx(self.root), {'namespace': 'Same'})
        self.assertEqual(spy.call_count, 2)


class PrimitiveTests(unittest.TestCase):
    def test_unsupported_platform_fails_safely(self):
        original = fs.supported
        fs.supported = lambda: False
        try:
            for call, args in ((fs.open_root, ('/tmp',)), (fs.open_rel, (0, 'x')),
                               (fs.list_dir, (0,))):
                with self.assertRaises(ToolError):
                    call(*args)
        finally:
            fs.supported = original

    def test_leaf_swapped_to_symlink_is_rejected(self):
        root = base_dir()
        os.makedirs(os.path.join(root, 'data'))
        touch(os.path.join(root, 'data', 'x'), b'ok')
        outside = os.path.join(root, 'outside')
        touch(outside, b'secret')
        real_open = os.open
        swapped = []

        def racing_open(path, flags, *args, **kwargs):
            # 叶文件在校验后被替换为链接；O_NOFOLLOW 应让打开本身失败。
            if path == 'x' and not swapped:
                swapped.append(True)
                os.unlink(os.path.join(root, 'data', 'x'))
                os.symlink(outside, os.path.join(root, 'data', 'x'))
            return real_open(path, flags, *args, **kwargs)

        fd = fs.open_root(root)
        os.open = racing_open
        # supported() 按对象身份检查 os.open；把替身登记进集合，退出时还原。
        os.supports_dir_fd.add(racing_open)
        try:
            with self.assertRaises(ToolError):
                fs.read_at(fd, 'data/x')
        finally:
            os.supports_dir_fd.discard(racing_open)
            os.open = real_open
            os.close(fd)
        self.assertTrue(swapped)

    def test_open_root_rejects_relative_and_dotdot(self):
        for value in ('tmp', './tmp', '/tmp/../etc'):
            with self.assertRaises(ToolError):
                fs.open_root(value)

    def test_tools_table(self):
        self.assertEqual([tool.name for tool in files.TOOLS],
                         ['cockpit_plugins', 'cockpit_log', 'cockpit_data', 'cockpit_meta'])
        self.assertTrue(all(tool.read_only for tool in files.TOOLS))
        for tool in files.TOOLS:
            self.assertTrue(callable(tool.handler))
            contracts.validate_arguments(tool, {} if tool.name == 'cockpit_plugins' else
                                         {'namespace': 'X'} if tool.name in ('cockpit_data',) else {})

    def test_validate_rejects_unknown_and_bad_types(self):
        spec = files.TOOLS[2]
        for args in ({'namespace': 'X', 'extra': 1}, {'namespace': 5},
                     {'namespace': 'X', 'mode': 'delete'}):
            with self.assertRaises(ToolError):
                contracts.validate_arguments(spec, args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
