"""可选的真实加载器冒烟；仅在明确启用的隔离测试环境中执行。"""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('loader_build_opk', ROOT / 'scripts' / 'build_opk.py')
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)

TOKEN = 'OlivOS-' + 'A' * 16 + 'b' * 8 + '1' * 8
FULL_ONLY = ('cockpit_send', 'cockpit_reload', 'cockpit_proc_get')


@unittest.skipUnless(os.environ.get('OLIVOS_COCKPIT_TEST_REAL_LOADER') == '1',
                     'requires an isolated real OlivOS runtime; opt in explicitly')
class LoaderTests(unittest.TestCase):
    def test_full_and_lite_real_loader_after_temporary_package_cleanup(self):
        script = '''
import base64
import hashlib
import io
import json
import os
import queue
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
from types import SimpleNamespace
import urllib.error
import urllib.request
import zipfile

opk, mode, token = sys.argv[1], sys.argv[2], sys.argv[3]
FULL_ONLY = {'cockpit_send', 'cockpit_reload', 'cockpit_proc_get'}
with tempfile.TemporaryDirectory() as directory:
    # 只有测试子进程切换 cwd；插件代码不能 chdir。
    os.chdir(directory)
    import OlivOS
    Path('plugin/app').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(opk, Path('plugin/app') / Path(opk).name)
    inbox = queue.Queue(maxsize=4)
    loader = OlivOS.pluginAPI.shallow(enable_gui=False, bot_info_dict={}, rx_queue=inbox)
    OlivOS.pluginAPI.gProc = loader
    loader.database = SimpleNamespace(_init_namespace=lambda namespace: None)
    # 新契约：调试终端账号由使用者预置；测试用宿主原生 API 模拟启动期创建的账号。
    provisioned = OlivOS.API.bot_info_T(id=20261104, platform_sdk='terminal_link',
                                        platform_platform='terminal', platform_model='default')
    loader.Proc_data['bot_info_dict'][provisioned.hash] = provisioned
    loader.load_plugin_list()
    assert set(loader.get_plugin_list()) == {'OlivOSCockpit'}, loader.get_plugin_list()
    assert not Path('plugin/tmp/OlivOSCockpit').exists()
    from OlivOSCockpit.registry import TOOLS
    expected = len(TOOLS)
    names = {tool.name for tool in TOOLS}
    assert ('OlivOSCockpit.full_only' in sys.modules) == (mode == 'full')
    assert ('OlivOSCockpit.adapter_tools' in sys.modules) == (mode == 'full')
    assert ('OlivOSCockpit.plugin_install' in sys.modules) == (mode == 'full')
    if mode == 'lite':
        assert names & FULL_ONLY == set()
        assert {tool.name for tool in TOOLS if not tool.read_only} == {'cockpit_terminal_input'}
    else:
        assert FULL_ONLY <= names
        assert all(tool.name == 'cockpit_terminal_input' or tool.required_permission in (
            'real_account_write', 'low_level_access', 'plugin_install')
            for tool in TOOLS if not tool.read_only)
    # 保持一个已占用端口，验证真实加载器回退后客户端使用回写的端口。
    blocker = socket.socket()
    blocker.bind(('127.0.0.1', 0))
    blocker.listen()
    original_port = blocker.getsockname()[1]
    # 配置来自运行数据根，而不是环境变量。
    control = Path('plugin/data/OlivOSCockpit/control')
    control.mkdir(parents=True, exist_ok=True)
    (control / 'config.json').write_text(json.dumps({
        'listen_host': '127.0.0.1', 'listen_port': original_port, 'api_key': token,
        'redaction_enabled': True, 'lite_real_account_read': False,
        'full_real_account_write': False, 'full_low_level_access': False,
        'denied_paths': [],
    }), encoding='utf-8')
    (control / 'redaction.json').write_text(
        json.dumps({'redact_fields': [], 'allow_fields': []}), encoding='utf-8')
    loader.run_plugin_func(None, 'init')
    loader.run_plugin_func(None, 'init_after')
    common = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
    }
    def post(body, headers):
        settings = json.loads((control / 'config.json').read_text(encoding='utf-8'))
        req = urllib.request.Request('http://127.0.0.1:' + str(settings['listen_port']) + '/mcp',
            data=json.dumps(body).encode(), headers=headers, method='POST')
        try:
            response = urllib.request.urlopen(req, timeout=2)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            return response.status, response.headers, json.loads(data) if data else None
    def read_when_ready(body, headers):
        # 仅用于只读请求；配置发布窗口的 503/重绑断线不触发写入重放。
        for attempt in range(200):
            try:
                result = post(body, headers)
            except OSError:
                if attempt == 199:
                    raise
            else:
                if result[0] == 200:
                    return result
                assert result[0] == 503, result
            threading.Event().wait(0.03)
        raise AssertionError('read-only request remained unavailable')
    modern = dict(common, **{'MCP-Protocol-Version':'2026-07-28', 'Mcp-Method':'tools/list'})
    body = {'jsonrpc':'2.0','id':1,'method':'tools/list','params':{'_meta':{
        'io.modelcontextprotocol/protocolVersion':'2026-07-28',
        'io.modelcontextprotocol/clientCapabilities':{},
    }}}
    status, headers, result = read_when_ready(body, modern)
    assert status == 200 and len(result['result']['tools']) == expected
    assert {tool['name'] for tool in result['result']['tools']} == names
    assert result['result']['resultType'] == 'complete'
    assert json.loads((control / 'config.json').read_text(encoding='utf-8'))['listen_port'] != original_port
    blocker.close()
    initialize = {'jsonrpc':'2.0','id':2,'method':'initialize','params':{
        'protocolVersion':'2025-11-25','capabilities':{},
        'clientInfo':{'name':'isolated-smoke','version':'1'},
    }}
    status, headers, result = post(initialize, common)
    assert status == 200
    legacy = dict(common, **{'Mcp-Session-Id':headers['Mcp-Session-Id'],
                            'MCP-Protocol-Version':'2025-11-25'})
    status, _, result = post({'jsonrpc':'2.0','method':'notifications/initialized'}, legacy)
    assert status == 202 and result is None
    for modern_call in (False, True):
        params = {'name':'cockpit_plugin_loaded_list','arguments':{}}
        query_headers = legacy
        if modern_call:
            params['_meta'] = body['params']['_meta']
            query_headers = dict(common, **{'MCP-Protocol-Version':'2026-07-28',
                'Mcp-Method':'tools/call','Mcp-Name':'cockpit_plugin_loaded_list'})
        status, _, result = post({'jsonrpc':'2.0','id':10,'method':'tools/call',
            'params':params}, query_headers)
        assert status == 200 and not result['result']['isError'], result
        loaded = result['result']['structuredContent']
        assert loaded['namespaces'] == ['OlivOSCockpit'] and loaded['count'] == 1, loaded
        assert not loaded['truncated'] and len(loaded['plugins']) == 1, loaded
        detail = loaded['plugins'][0]
        assert detail['namespace'] == 'OlivOSCockpit', detail
        assert detail['version'] == 'v0.2.0', detail
        assert 'model' not in detail
        native = loader.plugin_models_dict['OlivOSCockpit']
        for key in ('priority', 'priority_default', 'priority_user', 'priority_effective'):
            if key in native:
                assert detail[key] == native[key], (key, detail)
        assert json.loads(result['result']['content'][0]['text']) == loaded
    status, _, result = post({'jsonrpc':'2.0','id':3,'method':'tools/call',
        'params':{'name':'cockpit_bots','arguments':{}}}, legacy)
    if mode == 'lite':
        assert status == 200 and result['result'].get('isError', False), result
    else:
        assert status == 200 and not result['result'].get('isError', False)
        debug = result['result']['structuredContent']['debug_terminal']
        assert debug['selected'], debug
        assert 'memory_created' not in debug, debug
        assert debug['account']['hash'] == provisioned.hash, debug
        # 用户预置的账号就是配置账号：计数包含它。
        assert result['result']['structuredContent']['count'] == 1, result
    from OlivOSCockpit import files, main
    # 插件自身 svn 与宿主 compatible_svn 是两个独立字段。
    manifest = files.cockpit_meta(main._context, {'filename': Path(opk).name})
    assert not manifest.is_error, manifest.data
    assert manifest.data['manifest']['version'] == 'v0.2.0', manifest.data
    assert manifest.data['manifest']['compatible_svn'] == 190, manifest.data
    assert manifest.data['manifest']['svn'] == 1, manifest.data
    state = main._context.terminal
    assert state['hash'] == provisioned.hash and state['bot'] is provisioned, state
    main.Event.init(None, loader)
    assert main._context.terminal is state
    # 零突变：重复 init 不增删账号，选中的仍是用户预置对象。
    assert len(loader.Proc_data['bot_info_dict']) == 1
    assert loader.Proc_data['bot_info_dict'][provisioned.hash] is provisioned
    observed = []
    def observe(plugin_event, Proc):
        assert Proc is loader
        assert plugin_event.bot_info is state['bot']
        data = plugin_event.data
        group_id = getattr(data, 'group_id', None)
        if group_id is not None:
            assert data.sender['role'] == 'member'
        observed.append((plugin_event.plugin_info['func_type'], data.user_id,
                         group_id, data.message))
    main.Event.private_message = staticmethod(observe)
    main.Event.group_message = staticmethod(observe)
    status, _, result = post({'jsonrpc':'2.0','id':4,'method':'tools/call',
        'params':{'name':'cockpit_terminal_input','arguments':{
            'message':'cockpit smoke','user_id':'42'}}}, legacy)
    assert status == 200 and not result['result']['isError'], result
    terminal_result = result['result']['structuredContent']
    assert terminal_result['queued'] is True and terminal_result['chat'] == 'private'
    loader.run_plugin(inbox.get(timeout=1).sdk_event)
    terminal_headers = dict(common, **{'MCP-Protocol-Version':'2026-07-28',
        'Mcp-Method':'tools/call','Mcp-Name':'cockpit_terminal_input'})
    status, _, result = post({'jsonrpc':'2.0','id':5,'method':'tools/call',
        'params':{'name':'cockpit_terminal_input','arguments':{
            'message':'cockpit group smoke','user_id':'42','group_id':'9000'},
            '_meta':body['params']['_meta']}}, terminal_headers)
    assert status == 200 and not result['result']['isError'], result
    assert result['result']['structuredContent']['chat'] == 'group'
    clean = result['result']['structuredContent']
    assert clean['account']['hash'] == state['hash'], clean
    assert json.loads(result['result']['content'][0]['text']) == clean
    assert 'OlivOSCockpit.redaction' in sys.modules
    group_event = inbox.get(timeout=1).sdk_event
    loader.run_plugin(group_event)
    assert observed == [('private_message','42',None,'cockpit smoke'),
                        ('group_message','42','9000','cockpit group smoke')], observed
    status, _, result = post({'jsonrpc':'2.0','id':9,'method':'tools/call',
        'params':{'name':'cockpit_raw_events','arguments':{'limit':2}}}, legacy)
    assert status == 200 and not result['result']['isError'], result
    snapshot = result['result']['structuredContent']
    assert snapshot['active'] and snapshot['count'] == 2, snapshot
    assert all(record['bot_hash'] == state['hash'] for record in snapshot['records']), snapshot
    assert all(record['adapter'] == 'virtualTerminal' for record in snapshot['records']), snapshot
    status, _, result = post({'jsonrpc':'2.0','id':6,'method':'tools/call',
        'params':{'name':'cockpit_terminal_input','arguments':{
            'message':'must not queue','bot_hash':state['hash']}}}, legacy)
    assert status == 200 and result['result']['isError'], result
    assert inbox.empty()
    if mode == 'lite':
        for name in ('cockpit_send', 'cockpit_reload', 'cockpit_proc_get'):
            status, _, result = post({'jsonrpc':'2.0','id':7,'method':'tools/call',
                'params':{'name':name,'arguments':{}}}, legacy)
            assert status == 400 and result['error']['code'] == -32602, result
    loader.Proc_info.rx_queue = None
    status, _, result = post({'jsonrpc':'2.0','id':8,'method':'tools/call',
        'params':{'name':'cockpit_terminal_input','arguments':{'message':'no queue'}}}, legacy)
    assert status == 200 and result['result']['isError'], result
    assert not Path('plugin/tmp/OlivOSCockpit').exists()
    demo = Path('plugin/data/Demo')
    demo.mkdir()
    source = ('row ' + '界' * 10000 + chr(10)) * 36
    data_path = demo / 'large.txt'
    data_path.write_text(source, encoding='utf-8')
    assert data_path.stat().st_size > 1024 * 1024
    if mode == 'lite':
        settings_path = control / 'config.json'
        settings = json.loads(settings_path.read_text(encoding='utf-8'))
        settings['lite_real_account_read'] = True
        settings_path.write_text(json.dumps(settings), encoding='utf-8')
        main._manager.refresh()
        main._manager.refresh()
    data_headers = dict(common, **{'MCP-Protocol-Version':'2026-07-28',
        'Mcp-Method':'tools/call','Mcp-Name':'cockpit_data'})
    cursor = None
    chunks = []
    for index in range(128):
        arguments = {'namespace':'Demo','mode':'read','path':'large.txt'}
        if cursor is not None:
            arguments['cursor'] = cursor
        request = {'jsonrpc':'2.0','id':20 + index,'method':'tools/call','params':{
            'name':'cockpit_data','arguments':arguments,'_meta':body['params']['_meta']}}
        status, _, result = read_when_ready(request, data_headers)
        assert status == 200 and not result['result']['isError'], result
        clean = result['result']['structuredContent']
        assert clean['paged'] and 'sha256' not in clean, clean
        assert json.loads(result['result']['content'][0]['text']) == clean
        chunks.append(clean['content'])
        cursor = clean.get('next_cursor')
        if not cursor:
            break
    else:
        raise AssertionError('real loader file continuation did not finish')
    assert len(chunks) > 1 and ''.join(chunks) == source
    assert data_path.read_text(encoding='utf-8') == source
    message = '保留' * 256 + 'safe-' * 320
    records = [{'index':index, 'token':'jsonl-private-' + str(index), 'message':message}
               for index in range(400)]
    ending = chr(13) + chr(10)
    jsonl_source = ending.join(json.dumps(record, ensure_ascii=False) for record in records)
    jsonl_path = demo / 'records.jsonl'
    jsonl_path.write_text(jsonl_source, encoding='utf-8')
    assert jsonl_path.stat().st_size > 1024 * 1024
    expected_records = [dict(record, token='[REDACTED]') for record in records]
    status, headers, result = post(initialize, common)
    assert status == 200, result
    legacy = dict(common, **{'Mcp-Session-Id':headers['Mcp-Session-Id'],
                            'MCP-Protocol-Version':'2025-11-25'})
    status, _, result = post({'jsonrpc':'2.0','method':'notifications/initialized'}, legacy)
    assert status == 202 and result is None
    for modern_call in (False, True):
        cursor = None
        chunks = []
        parsed = []
        for index in range(128):
            arguments = {'namespace':'Demo','mode':'read','path':'records.jsonl'}
            if cursor is not None:
                arguments['cursor'] = cursor
            params = {'name':'cockpit_data','arguments':arguments}
            query_headers = legacy
            if modern_call:
                params['_meta'] = body['params']['_meta']
                query_headers = data_headers
            status, _, result = post({'jsonrpc':'2.0','id':300 + index,
                'method':'tools/call','params':params}, query_headers)
            assert status == 200 and not result['result']['isError'], result
            clean = result['result']['structuredContent']
            assert clean['paged'] and 'sha256' not in clean, clean
            assert json.loads(result['result']['content'][0]['text']) == clean
            assert clean['content'] and 'jsonl-private-' not in clean['content']
            parsed.extend(json.loads(line) for line in clean['content'].split(chr(10)) if line.strip())
            chunks.append(clean['content'])
            cursor = clean.get('next_cursor')
            if not cursor:
                break
            assert clean['content'].endswith(chr(10))
        else:
            raise AssertionError('real loader JSONL continuation did not finish')
        assert len(chunks) > 1 and parsed == expected_records
        assert ''.join(chunks).count(ending) == len(records) - 1
    assert jsonl_path.read_bytes().decode('utf-8') == jsonl_source
    if mode == 'full':
        def install_call(arguments, modern_call):
            params = {'name':'cockpit_plugin_install','arguments':arguments}
            query_headers = legacy
            if modern_call:
                params['_meta'] = body['params']['_meta']
                query_headers = dict(common, **{'MCP-Protocol-Version':'2026-07-28',
                    'Mcp-Method':'tools/call','Mcp-Name':'cockpit_plugin_install'})
            status, _, result = post({'jsonrpc':'2.0','id':700,'method':'tools/call',
                'params':params}, query_headers)
            assert status == 200, result
            return result['result']
        denied = install_call({'operation':'begin','filename':'installer-smoke.opk',
            'namespace':'InstallerSmoke','size':1}, True)
        assert denied['isError'], denied
        settings_path = control / 'config.json'
        settings = json.loads(settings_path.read_text(encoding='utf-8'))
        settings.update(full_real_account_write=True, full_low_level_access=True, full_plugin_install=True)
        settings_path.write_text(json.dumps(settings), encoding='utf-8')
        main._manager.refresh()
        main._manager.refresh()
        status, _, result = read_when_ready(body, modern)
        assert status == 200, result
        status, headers, result = post(initialize, common)
        assert status == 200, result
        legacy = dict(common, **{'Mcp-Session-Id':headers['Mcp-Session-Id'],
                                'MCP-Protocol-Version':'2025-11-25'})
        status, _, result = post({'jsonrpc':'2.0','method':'notifications/initialized'}, legacy)
        assert status == 202 and result is None
        for revision, modern_call in enumerate((False, True)):
            package_manifest = dict(manifest.data['manifest'], namespace='InstallerSmoke',
                                    name='Installer smoke', version='v0.0.' + str(revision))
            package_manifest.pop('svn', None)  # 上传第三方包不强制本插件自己的清单约定。
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr('app.json', json.dumps(package_manifest).encode('utf-8'))
                bundle.writestr('__init__.py', '')
                bundle.writestr('main.py', '# revision ' + str(revision))
            package_bytes = archive.getvalue()
            digest = hashlib.sha256(package_bytes).hexdigest()
            result = install_call({'operation':'begin','filename':'installer-smoke.opk',
                'namespace':'InstallerSmoke','size':len(package_bytes)}, modern_call)
            assert not result['isError'], result
            upload_id = result['structuredContent']['upload_id']
            for offset in range(0, len(package_bytes), 256):
                chunk = package_bytes[offset:offset + 256]
                result = install_call({'operation':'write','upload_id':upload_id,
                    'offset':offset,'chunk':base64.b64encode(chunk).decode('ascii')}, modern_call)
                assert not result['isError'], result
                assert result['structuredContent']['offset'] == offset + len(chunk), result
            # 新建和同 namespace 覆盖都只传新包摘要，不要求旧包摘要或修订。
            result = install_call({'operation':'commit','upload_id':upload_id,
                'sha256':digest}, modern_call)
            assert not result['isError'], result
            installed = result['structuredContent']
            assert installed['persisted'] and not installed['loaded'], installed
            assert installed['sha256'] == digest and installed['replaced'] == bool(revision), installed
            assert Path('plugin/app/installer-smoke.opk').read_bytes() == package_bytes
            metadata = files.cockpit_meta(main._context, {'filename':'installer-smoke.opk'})
            assert not metadata.is_error and metadata.data['sha256'] == digest, metadata.data
            assert set(loader.get_plugin_list()) == {'OlivOSCockpit'}
        rules_tool = next(tool for tool in TOOLS if tool.name == 'cockpit_intercept_rules')
        outcome = rules_tool.handler(main._context, {'operation':'set','rules':[{
            'id':'terminal-smoke','bot_hash':state['hash'],'stage':'sdk_in',
            'event_type':'group_message','action':'drop',
        }]})
        assert not outcome.is_error, outcome.data
        loader.run_plugin(group_event)
        assert len(observed) == 2, observed
        report = rules_tool.handler(main._context, {'operation':'list'})
        assert not report.is_error and report.data['counts']['sdk_in_drop'] == 1, report.data
    print('real loader, both MCP eras, raw events, terminal callbacks, and file continuation passed:', expected)
'''
        with tempfile.TemporaryDirectory() as directory:
            for path in builder.build(directory, ROOT):
                result = subprocess.run(
                    [sys.executable, '-I', '-B', '-c', script, str(path),
                     'lite' if 'Lite' in path.name else 'full', TOKEN],
                    capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(result.returncode, 0, result.stdout + '\n' + result.stderr)


if __name__ == '__main__':
    unittest.main()
