import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RELEASE = 'v0.1.0'
_spec = importlib.util.spec_from_file_location('build_opk', ROOT / 'scripts' / 'build_opk.py')
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)

class BuildTests(unittest.TestCase):
    def test_artifacts_are_deterministic_and_lite_contains_no_full_implementation(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = builder.build(directory, ROOT)
            self.assertEqual([path.name for path in paths],
                             [f'OlivOSCockpit-{RELEASE}.opk', f'OlivOSCockpitLite-{RELEASE}.opk'])
            first = [path.read_bytes() for path in paths]
            self.assertEqual(first, [path.read_bytes() for path in builder.build(directory, ROOT)])
            for path in paths:
                lite = 'Lite' in path.name
                with zipfile.ZipFile(path) as archive:
                    names = set(archive.namelist())
                    expected = {module.name for module in (ROOT / 'OlivOSCockpit').glob('*.py')}
                    expected.discard('catalog_tools.py')
                    if lite:
                        expected -= {'full_only.py', 'adapter_tools.py', 'file_write.py',
                                     'account_write.py', 'intercept.py'}
                    self.assertTrue(expected <= names, expected - names)
                    self.assertIn('app.json', names)
                    self.assertIn('__init__.py', names)
                    self.assertIn('redaction.py', names)
                    self.assertTrue(all('/' not in name for name in names))
                    raw = archive.read('app.json')
                    self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
                    manifest = json.loads(raw)
                    self.assertEqual(manifest['namespace'], 'OlivOSCockpit')
                    self.assertEqual(manifest['version'], RELEASE)
                    self.assertEqual(manifest['compatible_svn'], 190)
                    self.assertNotIn('svn', manifest)
                    self.assertEqual('full_only.py' in names, not lite)
                    self.assertEqual('adapter_tools.py' in names, not lite)
                    for module in ('file_write.py', 'account_write.py', 'intercept.py'):
                        self.assertEqual(module in names, not lite)
                    self.assertNotIn('catalog_tools.py', names)
                    for module in ('config.py', 'raw.py', 'read_tools.py', 'account_tools.py'):
                        self.assertIn(module, names)
                    for name in names:
                        if not name.endswith('.py'):
                            continue
                        text = archive.read(name).decode('utf-8')
                        self.assertNotIn('deck_', text)
                    if lite:
                        self.assertIn('terminal.py', names)
                        for name in names:
                            if name.endswith('.py'):
                                text = archive.read(name).decode('utf-8')
                                self.assertNotIn('full_only', text)
                    else:
                        self.assertIn('full_only.py', names)
                        self.assertIn('adapter_tools.py', names)

    def test_skill_archive_is_deterministic_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = builder.build_skill(directory, ROOT)
            self.assertEqual(path, Path(directory) / f'olivos-cockpit-skill-{RELEASE}.zip')
            first = path.read_bytes()
            self.assertEqual(first, builder.build_skill(directory, ROOT).read_bytes())
            source = ROOT / 'skills' / 'olivos-cockpit'
            expected = {'olivos-cockpit/SKILL.md'} | {
                'olivos-cockpit/references/' + item.name
                for item in (source / 'references').glob('*.md')}
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(set(archive.namelist()), expected)
                self.assertIn('olivos-cockpit/references/operations.md', expected)
                self.assertIn('olivos-cockpit/references/tool-guide.md', expected)
                for name in expected:
                    raw = archive.read(name)
                    self.assertFalse(raw.startswith(b'\xef\xbb\xbf'), name)
                    raw.decode('utf-8')
                skill = archive.read('olivos-cockpit/SKILL.md').decode('utf-8')
                self.assertIn(f'metadata:\n  version: {RELEASE}', skill)
                self.assertIn(f'OlivOSCockpit-{RELEASE}.opk', skill)
                self.assertIn(f'OlivOSCockpitLite-{RELEASE}.opk', skill)
                self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0)
                                    for info in archive.infolist()))

    def test_release_version_matches_all_sources_and_rejects_mismatch(self):
        self.assertEqual(builder.release_version(ROOT), RELEASE)
        sources = {
            'OlivOSCockpit/app.json': ROOT / 'OlivOSCockpit' / 'app.json',
            'OlivOSCockpit/contracts.py': ROOT / 'OlivOSCockpit' / 'contracts.py',
            'skills/olivos-cockpit/SKILL.md': ROOT / 'skills' / 'olivos-cockpit' / 'SKILL.md',
        }
        cases = (
            ('OlivOSCockpit/app.json', '"version": "v0.1.0"', '"version": "v0.1.1"'),
            ('OlivOSCockpit/app.json', '"version": "v0.1.0"', '"version": "0.1.0"'),
            ('OlivOSCockpit/contracts.py', "VERSION = 'v0.1.0'", "VERSION = 'v0.1.1'"),
            ('skills/olivos-cockpit/SKILL.md', 'version: v0.1.0', 'version: v0.1.1'),
        )
        for relative, old, new in cases:
            with self.subTest(relative=relative, replacement=new), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for path in sources.values():
                    target = root / path.relative_to(ROOT)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
                target = root / relative
                text = target.read_text('utf-8')
                self.assertIn(old, text)
                target.write_text(text.replace(old, new), encoding='utf-8')
                with self.assertRaises(ValueError):
                    builder.release_version(root)

    def test_cli_builds_exactly_three_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, '-B', str(ROOT / 'scripts' / 'build_opk.py'),
                 '--output', directory],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            names = [Path(line).name for line in result.stdout.splitlines() if line.strip()]
            self.assertEqual(names, [f'OlivOSCockpit-{RELEASE}.opk',
                                     f'OlivOSCockpitLite-{RELEASE}.opk',
                                     f'olivos-cockpit-skill-{RELEASE}.zip'])
            self.assertEqual(sorted(item.name for item in Path(directory).iterdir()), sorted(names))

    def test_clean_opk_import_and_first_call_after_unpacked_directory_removed(self):
        script = '''
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import zipfile

archive_path, mode = sys.argv[1], sys.argv[2]
FULL_ONLY = {'cockpit_send', 'cockpit_reload', 'cockpit_proc_get'}
with tempfile.TemporaryDirectory() as directory:
    base = Path(directory)
    package = base / 'OlivOSCockpit'
    package.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(package)
    os.chdir(base)
    # 注入宿主 stub：OlivOS 模块本身只提供插件回调所需的属性。
    olivos = types.ModuleType('OlivOS')
    olivos.infoAPI = types.SimpleNamespace(OlivOS_plugin_data_path='./plugin/data')
    sys.modules['OlivOS'] = olivos
    sys.path.insert(0, str(base))
    module = importlib.import_module('OlivOSCockpit')
    import OlivOSCockpit.config as config
    import OlivOSCockpit.raw_tools as raw_tools
    import OlivOSCockpit.read_tools as read_tools
    import OlivOSCockpit.account_tools as account_tools
    from OlivOSCockpit.contracts import Context, MODE_FULL, MODE_LITE
    from OlivOSCockpit.registry import TOOLS
    names = {tool.name for tool in TOOLS}
    assert names and all(name.startswith('cockpit_') for name in names)
    assert len(names) == len(TOOLS)
    lite = mode == 'lite'
    assert ('OlivOSCockpit.full_only' in sys.modules) == (not lite)
    assert ('OlivOSCockpit.adapter_tools' in sys.modules) == (not lite)
    for full_module in ('file_write', 'account_write', 'intercept'):
        assert ('OlivOSCockpit.' + full_module in sys.modules) == (not lite)
    assert 'OlivOSCockpit.catalog_tools' not in sys.modules
    assert {tool.name for tool in read_tools.TOOLS + account_tools.TOOLS} <= names
    if lite:
        assert getattr(module.registry, 'MODE', MODE_FULL) == MODE_LITE
        assert names & FULL_ONLY == set()
        assert {tool.name for tool in TOOLS if not tool.read_only} == {'cockpit_terminal_input'}
        assert 'cockpit_accounts_update' not in names
        assert 'cockpit_plugin_file_update' not in names
        assert 'cockpit_intercept_rules' not in names
        assert {tool.name for tool in raw_tools.TOOLS} <= names
    else:
        assert getattr(module.registry, 'MODE', MODE_FULL) == MODE_FULL
        assert FULL_ONLY <= names
        assert 'cockpit_milky_send_group' in names
    # 运行数据根：模板由 ConfigManager 首次刷新创建，无 key 不监听。
    data_root = str(base / 'plugin' / 'data')
    Path(data_root).mkdir(parents=True, exist_ok=True)
    proc = types.SimpleNamespace(
        Proc_data={'bot_info_dict': {}},
        log=lambda *args: None,
        get_plugin_list=lambda: ['OlivOSCockpit'],
    )
    module.main.Event.init(None, proc)
    assert module.main._context is not None
    control = Path(config.control_dir(data_root))
    manager = module.main._manager
    assert manager is not None
    manager.refresh()
    manager.refresh()
    assert (control / config.CONFIG_NAME).exists()
    assert (control / config.REDACTION_NAME).exists()
    template = json.loads((control / config.CONFIG_NAME).read_text('utf-8'))
    assert template['api_key'] == ''
    assert not manager.snapshot().ready
    shutil.rmtree(package)
    from OlivOSCockpit import protocol, redaction, service
    assert redaction.Cleaner().value({'password': 'secret'}) == {'password': '[REDACTED]'}
    reply = protocol.encode_reply(protocol.result_body(7, {'token': 'secret-value'}), False)
    assert json.loads(reply.body)['result']['token'] == '[REDACTED]'
    ctx = Context(proc, str(base), data_root, olivos, config=manager, permission_mode=mode)
    result = next(tool for tool in TOOLS if tool.name == 'cockpit_bots').handler(ctx, {})
    assert result.is_error == lite
    terminal_tool = next(tool for tool in TOOLS if tool.name == 'cockpit_terminal_input')
    assert not terminal_tool.read_only
    assert terminal_tool.handler(ctx, {'message': 'x'}).is_error  # 无宿主队列时安全失败
    values = dict(template, api_key='OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8,
                  lite_real_account_read=True)
    (control / config.CONFIG_NAME).write_text(json.dumps(values), encoding='utf-8')
    manager.refresh()
    manager.refresh()
    assert manager.snapshot().ready
    demo = Path(data_root) / 'Demo'
    demo.mkdir()
    original = 'x' * 600000
    (demo / 'large.txt').write_text(original, encoding='utf-8')
    data_tool = next(tool for tool in TOOLS if tool.name == 'cockpit_data')
    args = {'namespace': 'Demo', 'mode': 'read', 'path': 'large.txt'}
    request = protocol.Request('tools/call', {'name': data_tool.name, 'arguments': args}, 8, False, False)
    svc = service._Service(ctx, None, TOOLS, 10, manager)
    chunks = []
    try:
        for _ in range(128):
            outcome = data_tool.handler(ctx, args)
            reply = svc._result_reply(request, data_tool, outcome)
            assert len(reply.body) <= 1024 * 1024
            result = json.loads(reply.body)['result']
            assert not result['isError'], result
            data = result['structuredContent']
            assert json.loads(result['content'][0]['text']) == data
            chunks.append(data['content'])
            cursor = data.get('next_cursor')
            if not cursor:
                break
            args['cursor'] = cursor
        else:
            raise AssertionError('packaged file continuation did not finish')
    finally:
        svc.close()
    assert len(chunks) > 1
    assert ''.join(chunks) == original
    assert not package.exists()
    # 模块间导出一致：registry 与各工具集合无重复名，也没有循环导入残留。
    for imported in ('OlivOSCockpit.registry', 'OlivOSCockpit.raw', 'OlivOSCockpit.config',
                     'OlivOSCockpit.service', 'OlivOSCockpit.protocol'):
        assert imported in sys.modules
'''
        with tempfile.TemporaryDirectory() as directory:
            for path in builder.build(directory, ROOT):
                result = subprocess.run(
                    [sys.executable, '-I', '-B', '-c', script, str(path),
                     'lite' if 'Lite' in path.name else 'full'],
                    capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
