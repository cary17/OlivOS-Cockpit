"""出站脱敏纯模块与交付边界测试，不依赖 aiohttp 或真实 OlivOS。"""

import asyncio
import copy
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from OlivOSCockpit import files, full_only, protocol, redaction, service  # noqa: E402
from OlivOSCockpit.contracts import Context, Outcome, ToolSpec, object_schema  # noqa: E402

MARKER = redaction.MARKER
TOKEN = 'unlabelled-cockpit-value'
OFF = {'redaction_enabled': False}


def stub_service(proc=None, olivos=None):
    svc = object.__new__(service._Service)
    svc.context = Context(proc, '/unused', '/unused/data', olivos)
    svc.token = TOKEN
    return svc


def request(modern=True):
    return protocol.Request('tools/call', {}, 'rpc-account-42', False, modern)


def result(svc, data, modern=True, task=None, policy=None):
    tool = ToolSpec('test', 'test', object_schema(), lambda ctx, args: None)
    return svc._result_reply(request(modern), tool, data, task, policy=policy)


class CleanerTests(unittest.TestCase):
    def test_builtin_credential_fields_only(self):
        source = {'password': {'nested': 'secret'}, 'api-Key': 'key', 'accessToken': 'access',
                  'PRIVATE_key': ['private'], 'Authorization': 'auth', 'set_cookie': 'cookie',
                  'account': {'hash': 'safe-hash', 'id': 42},
                  'items': [{'id': 42, 'user_id': 0, 'groupId': 9000, 'target-id': '123',
                             'root': '/host/private', 'bot_hash': 'h-safe', 'namespace': 'Example',
                             'path': 'normal/child.txt'}]}
        before = copy.deepcopy(source)
        cleaner = redaction.Cleaner()
        clean = cleaner.value(source)
        self.assertTrue(cleaner.changed)
        self.assertEqual(source, before)
        for key in ('password', 'api-Key', 'accessToken', 'PRIVATE_key', 'Authorization', 'set_cookie'):
            self.assertEqual(clean[key], MARKER)
        # 身份、目录、路径不再被字段规则误遮；操作句柄保持可用。
        self.assertEqual(clean['account'], {'hash': 'safe-hash', 'id': 42})
        self.assertEqual(clean['items'][0], before['items'][0])

    def test_field_names_match_complete_casefold_equality(self):
        source = {'token': 't', 'TOKEN': 't', 'mytoken': 'm', 'my_token': 'm', 'access_token': 'a',
                  'accesstoken': 'a', 'user_id': 'u', 'userid': 'u', 'userId': 'u',
                  'password_hash': 'h', 'passwordhint': 'h'}
        clean = redaction.Cleaner().value(source)
        self.assertEqual(clean['token'], MARKER)
        self.assertEqual(clean['TOKEN'], MARKER)
        self.assertEqual(clean['access_token'], MARKER)
        self.assertEqual(clean['accesstoken'], MARKER)
        # 不是完整名称（前缀/拼接）就不命中。
        for key in ('mytoken', 'my_token', 'user_id', 'userid', 'userId', 'password_hash', 'passwordhint'):
            self.assertEqual(clean[key], source[key], key)

    def test_builtin_keeps_separator_variants_after_verification(self):
        source = {'access-token': 'a', 'session key': 's', 'client_secret': 'c',
                  'set-cookie': 'k', 'private key': 'p'}
        self.assertEqual(redaction.Cleaner().value(source), {key: MARKER for key in source})

    def test_verified_adapter_and_account_credential_fields(self):
        source = {'app_key': 'application-key', 'AppSecret': 'application-secret',
                  'key': 'qsign-key', 'bili_jct': 'csrf-value', 'ticket': 'temporary-ticket'}
        self.assertEqual(redaction.Cleaner().value(source), {key: MARKER for key in source})
        self.assertEqual(redaction.Cleaner(policy={'allow_fields': ['app_key']}).value(source)['app_key'],
                         'application-key')

    def test_session_ids_and_identity_aliases_are_not_secrets(self):
        source = {'session_id': 'opaque-session', 'sid': 'opaque-sid', 'tel': 13800138000,
                  'real_name': 'Private Person', '姓名': '私有姓名', '昵称': '私有昵称',
                  'home_address': 'Private street', 'email': 'a@b.example', 'ip': '10.0.0.1'}
        self.assertEqual(redaction.Cleaner().value(source), source)

    def test_numeric_handles_survive_but_known_values_in_handles_do_not(self):
        source = {'bot_hash': '12345678901234567890', 'namespace': '127.0.0.1',
                  'namespaces': ['Example'], 'account': {'hash': '12345678901234567890'}}
        self.assertEqual(redaction.Cleaner().value(source), source)
        source['bot_hash'] = TOKEN
        self.assertEqual(redaction.Cleaner((TOKEN,)).value(source)['bot_hash'], MARKER)

    def test_unlabelled_known_values_and_json_escapes(self):
        secret = '凭据-"line\\end'
        for text in (secret, json.dumps(secret), 'prefix ' + json.dumps(secret)[1:-1] + ' suffix',
                     r'prefix unlabelled\u002dcockpit\u002dvalue suffix'):
            cleaner = redaction.Cleaner((TOKEN, secret))
            clean = cleaner.value(text)
            self.assertNotIn(secret, clean)
            self.assertNotIn(TOKEN, clean)
            self.assertIn(MARKER, clean)
            self.assertTrue(cleaner.changed)

    def test_known_replacement_keeps_other_backslashes(self):
        text = r'body C:\new ' + TOKEN + r' tail'
        self.assertEqual(redaction.Cleaner((TOKEN,)).value(text), r'body C:\new ' + MARKER + r' tail')

    def test_known_escape_boundaries_and_literal_backslashes(self):
        cases = (
            ('a', 'prefix ' + chr(92) + 'u0061 suffix', 'prefix ' + MARKER + ' suffix'),
            ('a\n', r'prefix a\n suffix', 'prefix ' + MARKER + ' suffix'),
            (r'part\new', r'prefix part\new suffix', 'prefix ' + MARKER + ' suffix'),
            ('😀', 'prefix ' + chr(92) + 'ud83d' + chr(92) + 'ude00 suffix',
             'prefix ' + MARKER + ' suffix'),
        )
        for secret, text, expected in cases:
            with self.subTest(secret=secret):
                self.assertEqual(redaction.Cleaner((secret,)).value(text), expected)

    def test_known_matches_are_bounded_and_leftmost_longest(self):
        self.assertEqual(redaction.Cleaner(('ab', 'abc')).value('prefix abc suffix'),
                         'prefix ' + MARKER + ' suffix')
        self.assertEqual(redaction.Cleaner(('z',)).value('z' * 2000), MARKER * 2000)
        with patch.object(redaction, 'MAX_NODES', 32), self.assertRaises(OverflowError):
            redaction.Cleaner(('z',)).value('z' * 100)
        with patch.object(redaction, 'MAX_NODES', 32), self.assertRaises(OverflowError):
            redaction.Cleaner(('not-present',)).value((chr(92) + 'u0061') * 100)

    def test_native_log_account_formats_are_not_identity_scanned(self):
        text = 'User(42) Group(-9000) qq|10001 terminal|987654321 用户ID=73'
        self.assertEqual(redaction.Cleaner().value(text), text)

    def test_common_text_rules_and_preserved_body(self):
        samples = (
            'password="two words" useful text',
            "API_Key='quoted-value' useful text",
            'API key = "quoted-value" useful text',
            'private key = "quoted-value" useful text',
            'accessToken={"nested":["deep-value"]} useful text',
            'Authorization: Bearer abcDEF123\nuseful text',
            'Basic YWJjOnBhc3M= useful text',
            'Cookie: a=one; b=two\nuseful text',
            'https://alice:pass@example.org/x?access_token=urlvalue&ok=yes useful text',
            'https://example.org/?api%5Fkey=comma,secret&ok=yes useful text',
            '-----BEGIN RSA PRIVATE KEY-----\nbase64-secret\n-----END RSA PRIVATE KEY----- useful text',
        )
        for text in samples:
            with self.subTest(text=text):
                clean = redaction.Cleaner().value(text)
                self.assertIn(MARKER, clean)
                self.assertIn('useful text', clean)
                for forbidden in ('two words', 'quoted-value', 'deep-value', 'abcDEF123',
                                  'YWJjOnBhc3M', 'a=one', 'b=two', 'alice:pass', 'urlvalue',
                                  'comma,secret', 'base64-secret'):
                    self.assertNotIn(forbidden, clean)

    def test_generic_personal_format_rules_are_gone(self):
        for text in ('mail alice@example.org phone +1 (415) 555-2671 IP 192.168.1.12',
                     'IPv6 2001:db8::123 user_id=42 群号9000',
                     r'root /data/host/private C:\Users\alice\file',
                     'idcard 11010119900101123X username=alice',
                     'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature',
                     'sk-proj-abcdefghijklmnop123456',
                     'github_pat_abcdefghijklmnop123456'):
            self.assertEqual(redaction.Cleaner().value(text), text)

    def test_spaced_secret_labels(self):
        for label in ('secret key', 'access key', 'signing key', 'encryption key',
                      'session token', 'pass phrase', 'client secret'):
            with self.subTest(label=label):
                clean = redaction.Cleaner().value(f'{label}="private-value" useful text')
                self.assertNotIn('private-value', clean)
                self.assertIn('useful text', clean)

    def test_nested_json_and_truncated_private_key(self):
        text = json.dumps({'safe': 'body', 'user_id': 123, 'payload': json.dumps({'secret': 'inner'})})
        clean = json.loads(redaction.Cleaner().value(text))
        self.assertEqual(clean['user_id'], 123)
        self.assertEqual(json.loads(clean['payload'])['secret'], MARKER)
        self.assertEqual(clean['safe'], 'body')
        for text in ('start\n-----BEGIN PRIVATE KEY-----\nprivate-fragment',
                     r'start\n-----BEGIN EC PRIVATE KEY-----\nprivate-fragment'):
            clean = redaction.Cleaner().value(text)
            self.assertIn('start', clean)
            self.assertNotIn('private-fragment', clean)

    def test_redacted_json_stays_valid_and_idempotent(self):
        text = json.dumps({'apiKey': 'private-value', 'id': 42, 'safe': 'useful text'})
        once = redaction.Cleaner().value(text)
        twice = redaction.Cleaner().value(once)
        self.assertEqual(json.loads(twice), {'apiKey': MARKER, 'id': 42, 'safe': 'useful text'})
        self.assertEqual(once, twice)
        formatted = json.dumps(json.loads(once), indent=2)
        self.assertEqual(redaction.Cleaner().value(formatted), formatted)

    def test_jsonl_reencodes_only_changed_records_and_preserves_framing(self):
        raw = (' { "safe" : "quoted" }\r\n\n'
               '{"nested":{"token":"known-secret"},"\\u0074oken":"field-secret",'
               '"note":"known-secret","custom_secret":"user-secret"}\n'
               '{"unicode":"before after"}\n'
               '{"duplicate":"first","duplicate":"second"}')
        rules = redaction.policy({'redact_fields': ['custom_secret']})
        clean = redaction.Cleaner(('known-secret',), rules).text(raw, jsonl=True)
        self.assertTrue(clean.startswith(' { "safe" : "quoted" }\r\n\n'))
        records = clean.split('\n')
        self.assertEqual(records[0], ' { "safe" : "quoted" }\r')
        self.assertEqual(records[1], '')
        self.assertEqual(json.loads(records[2]), {
            'nested': {'token': MARKER}, 'token': MARKER, 'note': MARKER,
            'custom_secret': MARKER,
        })
        self.assertEqual(records[3], '{"unicode":"before after"}')
        self.assertEqual(json.loads(records[4]), {'duplicate': 'second'})
        self.assertFalse(clean.endswith('\n'))

    def test_jsonl_auto_detection_single_document_and_shared_budgets(self):
        records = '{"token":"secret"}\n{"safe":"quoted"}'
        clean = redaction.Cleaner().text(records)
        self.assertEqual(json.loads(clean.split('\n')[0]), {'token': MARKER})
        self.assertEqual(json.loads(clean.split('\n')[1]), {'safe': 'quoted'})
        with self.assertRaises(redaction.RedactionError):
            redaction.Cleaner().text('{"safe":1}\n{"token":', jsonl=True)
        for example in ('Example configuration:\n{"a":1}\n{"b":2}\n',
                        '{"a":1}\n{"b":2}\nordinary tail'):
            with self.subTest(example=example):
                self.assertEqual(redaction.Cleaner().text(example), example)
        self.assertTrue(redaction.Cleaner().detect_jsonl(
            '{"a":1}\n{"b":2}\n{"partial":', eof=False))
        document = '{\n  "token": "secret"\n}'
        self.assertEqual(json.loads(redaction.Cleaner().text(document)), {'token': MARKER})
        with patch.object(redaction, 'MAX_NODES', 8), self.assertRaises(OverflowError):
            redaction.Cleaner().text('{"x":1}\n{"x":1}', jsonl=True)
        with patch.object(redaction, 'MAX_WORK', len(records) * 16), self.assertRaises(OverflowError):
            redaction.Cleaner().text(records, jsonl=True)

    def test_jsonl_parse_and_clean_nodes_share_one_budget(self):
        text = '[' + ','.join(['0'] * 15000) + ']'
        with self.assertRaises(OverflowError):
            redaction.Cleaner().text(text, jsonl=True)
        with patch.object(redaction, 'MAX_NODES', 16), self.assertRaises(OverflowError):
            redaction.Cleaner().text('[0,0,0]\n[0,0,0]', jsonl=True)

    def test_auto_jsonl_budget_overflow_never_falls_back_to_plain_text(self):
        record = r'{"token":"probe-secret"}' + '\n'
        with patch.object(redaction, 'MAX_NODES', 10), self.assertRaises(OverflowError):
            redaction.Cleaner().text('0\n' + record * 10)
        integer = '9' * 5000
        for text in (integer + '\n' + record, '0\n{"id":' + integer + '}\n' + record):
            with self.assertRaises((ValueError, OverflowError)):
                redaction.Cleaner().text(text)
        for text in ('0,1,' * 100 + '\nordinary tail', 'falsehood ' * 100, integer + '\n'):
            with self.subTest(text=text), patch.object(redaction, 'MAX_NODES', 10):
                self.assertEqual(redaction.Cleaner().text(text), text)

    def test_jsonl_honors_outer_policy_and_fails_closed(self):
        raw = '{"token":"known-secret"}\n{"safe":1}'
        allow = redaction.policy({'allow_fields': ['content']})
        self.assertEqual(redaction.Cleaner(('known-secret',), allow).value(
            {'content': raw}, text_formats={'content': True})['content'], raw)
        off = redaction.policy(OFF)
        self.assertEqual(redaction.Cleaner(('known-secret',), off).value(
            {'content': raw}, text_formats={'content': True})['content'], raw)
        content_redact = redaction.policy({'redact_fields': ['content']})
        self.assertEqual(redaction.Cleaner((), content_redact).value(
            {'content': raw}, text_formats={'content': True})['content'], MARKER)
        redact = redaction.policy({'redact_fields': ['token']})
        self.assertEqual(json.loads(redaction.Cleaner((), redact).text(raw, jsonl=True).split('\n')[0]),
                         {'token': MARKER})
        with self.assertRaises(redaction.RedactionError):
            redaction.Cleaner().text('{"value":NaN}', jsonl=True)
        with self.assertRaises((redaction.RedactionError, ValueError)):
            redaction.Cleaner(('known-secret',), allow).value(
                {'content': '{"token":"known-secret"}\nnot-json'},
                text_formats={'content': True})

    def test_chinese_credentials(self):
        source = {'密码': 'private-password', '令牌': 'private-token',
                  '私钥': 'private-key', '访问令牌': 'private-prefixed',
                  '用户ID': 42, '手机号': 13800138000,
                  '邮箱': 'private-address', 'sender_id': 42}
        clean = redaction.Cleaner().value(source)
        for key in ('密码', '令牌', '私钥'):
            self.assertEqual(clean[key], MARKER)
        # 完整名称之外的组合词（访问令牌）不按前缀猜测。
        for key in ('访问令牌', '用户ID', '手机号', '邮箱', 'sender_id'):
            self.assertEqual(clean[key], source[key])
        for text in ('令牌=private-token useful text',
                     '授权: Bearer private-auth\nuseful text'):
            clean = redaction.Cleaner().value(text)
            self.assertIn('useful text', clean)
            for secret in ('private-token', 'private-auth'):
                self.assertNotIn(secret, clean)

    def test_field_rules_preserve_keys_and_allow_priority(self):
        source = {'prefix-abc-value': 'ok', 'abc-value': 1, MARKER: 2}
        self.assertEqual(redaction.Cleaner(('abc-value',)).value(source), source)
        rules = redaction.policy({'allow_fields': ['token']})
        self.assertEqual(redaction.Cleaner(('token',), rules).value({'token': 'token'}),
                         {'token': 'token'})

    def test_tree_text_scan_and_credential_budgets(self):
        deep = 0
        for _ in range(redaction.MAX_DEPTH + 1):
            deep = [deep]
        for data in (deep, [None] * (redaction.MAX_NODES + 1), 'x' * (redaction.MAX_TEXT + 1)):
            with self.assertRaises(OverflowError):
                redaction.Cleaner().value(data)
        for name in ('MAX_SCAN', 'MAX_WORK'):
            with patch.object(redaction, name, 1), self.assertRaises(OverflowError):
                redaction.Cleaner().value('ordinary text')
        with self.assertRaises(OverflowError):
            redaction.credentials(TOKEN, {str(i): {} for i in range(redaction.MAX_BOTS + 1)})
        with self.assertRaises(OverflowError):
            redaction.credentials('x' * (redaction.MAX_SECRET + 1), None)
        with patch.object(redaction, 'MAX_SECRETS', 1), self.assertRaises(OverflowError):
            redaction.credentials(TOKEN, {'a': {'password': 'other'}})

    def test_snapshot_native_objects_and_dicts_without_repr_or_password_property(self):
        class Bot:
            def __init__(self):
                self.__dict__.update(password='native-password', post_info=SimpleNamespace(access_token='native-access'))

            @property
            def password(self):
                raise AssertionError('property must not run')

            def __str__(self):
                raise AssertionError('str must not run')

            __repr__ = __str__

        bots = {'a': Bot(), 'b': {'password': 'dict-password', 'post_info': {'access_token': 'dict-access'}}}
        snapshot = redaction.credentials(TOKEN, bots)
        self.assertEqual(set(snapshot), {TOKEN, 'native-password', 'native-access', 'dict-password', 'dict-access'})
        proc = SimpleNamespace(Proc_data={'bot_info_dict': bots})
        svc = stub_service(proc)
        reply = result(svc, Outcome({'log': ' '.join(snapshot)}))
        clean = json.loads(reply.body)['result']['structuredContent']['log']
        for secret in snapshot:
            self.assertNotIn(secret, clean)
        bots['a'].__dict__['password'] = 'updated-value'
        self.assertIn('updated-value', svc._known())
        self.assertNotIn('native-password', svc._known())


class MalformedJsonTests(unittest.TestCase):
    """BUG-02：畸形/重复键 JSON 只降级该字符串，不丢整个工具响应。"""

    def test_duplicate_keys_use_last_value_and_are_normalized(self):
        original = '{"safe":"keep","a":1,"a":2}'
        cleaner = redaction.Cleaner()
        clean = cleaner.value({'line': original, 'id': 7, 'note': 'kept'})
        self.assertEqual(json.loads(clean['line']), {'safe': 'keep', 'a': 2})
        self.assertEqual(clean['line'].count('"a"'), 1)
        self.assertEqual((clean['id'], clean['note']), (7, 'kept'))
        self.assertTrue(cleaner.changed)

    def test_duplicate_sensitive_nested_and_escaped_keys(self):
        backslash = chr(92)
        cases = (
            ('{"token":"first-leak","token":"second-leak"}', 'second-leak', 'first-leak'),
            ('{"outer":{"password":"nested-leak","password":"nested-leak-2"}}',
             'nested-leak-2', 'nested-leak'),
            ('{"' + backslash + 'u0074oken":"escaped-leak-one","'
             + backslash + 'u0074oken":"escaped-leak-two"}',
             'escaped-leak-two', 'escaped-leak-one'),
        )
        for text, last, first in cases:
            with self.subTest(text=text):
                cleaner = redaction.Cleaner()
                clean = cleaner.value(text)
                self.assertIn(MARKER, clean)
                self.assertNotIn(last, clean)
                self.assertNotIn(first, clean)
                self.assertTrue(cleaner.changed)

    def test_malformed_brackets_fall_back_to_text_scrubbing(self):
        cleaner = redaction.Cleaner()
        clean = cleaner.value({'line': '{"password":"leak-value"}}', 'id': 7, 'safe': 'kept'})
        self.assertNotIn('leak-value', clean['line'])
        self.assertIn(MARKER, clean['line'])
        self.assertEqual((clean['id'], clean['safe']), (7, 'kept'))
        self.assertTrue(cleaner.changed)

    def test_malformed_unicode_escape_masks_only_that_string(self):
        backslash = chr(92)
        poison = '{"' + backslash + 'u0074oken":"escape-leak","safe":1}}'
        cleaner = redaction.Cleaner()
        clean = cleaner.value({'line': poison, 'id': 7, 'safe': 'kept'})
        self.assertEqual(clean['line'], MARKER)
        self.assertEqual((clean['id'], clean['safe']), (7, 'kept'))
        self.assertTrue(cleaner.changed)

    def test_duplicate_key_user_allow_is_preserved(self):
        rules = redaction.policy({'allow_fields': ['token']})
        clean = redaction.Cleaner((TOKEN,), rules).value(
            '{"token":"first-plain","token":"second-plain"}')
        self.assertEqual(json.loads(clean), {'token': 'second-plain'})
        self.assertNotIn(MARKER, clean)

    def test_json_branch_budgets_and_non_finite_still_fail_closed(self):
        with self.assertRaises(OverflowError):
            redaction.Cleaner().value('[' * (redaction.MAX_DEPTH + 1) + ']' * (redaction.MAX_DEPTH + 1))
        with self.assertRaises(redaction.RedactionError):
            redaction.Cleaner().value('{"x": NaN}')
        for name in ('MAX_SCAN', 'MAX_WORK'):
            with patch.object(redaction, name, 1), self.assertRaises(OverflowError):
                redaction.Cleaner().value('{"x": 1}')

    def test_repeated_assignments_and_quoted_values_stay_linear(self):
        # 512 字、64 个命中：旧计费按剩余长度累加会超额，按实际 span 计费则线性。
        with patch.object(redaction, 'MAX_WORK', 12000):
            cleaner = redaction.Cleaner()
            text = 'token=x ' * 64
            clean = cleaner.value(text)
            self.assertEqual(clean.count(MARKER), 64)
            self.assertNotIn('token=x', clean)
            self.assertLessEqual(cleaner.work, 12000)
        clean = redaction.Cleaner().value('password="quoted value" ' * 8)
        self.assertEqual(clean.count(MARKER), 8)
        self.assertNotIn('quoted value', clean)


class RecordBoundaryTests(unittest.TestCase):
    def test_pending_labels_and_auth_prefixes_do_not_lose_context(self):
        cases = (
            ('before\n"access_token"\n' + '\n' * 200, ':"field-only-secret"\n',
             'field-only-secret', None),
            ('before\nBearer\n' + '\n' * 200, 'auth-only-secret\n', 'auth-only-secret', None),
            ('before\nBasic\n' + '\n' * 200, 'basic-only-secret\n', 'basic-only-secret', None),
            ('before\nBearer\n' + 'z' * 200, '\n', 'z' * 200, None),
            ('before\n"custom_field"\n' + '\n' * 200, ':"custom-only-secret"\n',
             'custom-only-secret', {'redact_fields': ['custom_field']}),
        )
        known = ('keep-out',)
        for window, tail, secret, rules in cases:
            with self.subTest(prefix=window[:32]):
                whole = redaction.Cleaner(known, rules).text(window + tail)
                self.assertNotIn(secret, whole)
                cut = redaction.safe_record_cut(window, known, rules, eof=False)
                combined = (redaction.Cleaner(known, rules).text(window[:cut])
                            + redaction.Cleaner(known, rules).text(window[cut:] + tail))
                self.assertNotIn(secret, combined)

    def test_pending_allow_fields_keep_their_known_value(self):
        secret = 'allowed-credential'
        rules = redaction.policy({'allow_fields': ['token']})
        for prefix in ('token\n', 'token=\n'):
            window = 'before\n' + prefix + '\n' * 1000
            tail = (':' if '=' not in prefix else '') + secret + '\n'
            self.assertIn(secret, redaction.Cleaner((secret,), rules).text(window + tail))
            cut = redaction.safe_record_cut(window, (secret,), rules, eof=False)
            combined = (redaction.Cleaner((secret,), rules).text(window[:cut])
                        + redaction.Cleaner((secret,), rules).text(window[cut:] + tail))
            self.assertIn(secret, combined)

    def test_record_boundary_scans_obey_the_work_budget(self):
        with patch.object(redaction, 'MAX_WORK', 1), self.assertRaises(OverflowError):
            redaction.safe_record_cut('before\n' + 'tail' * 50, eof=False)

    def test_safe_record_cut_keeps_known_credentials_and_pem_blocks_whole(self):
        secret = 'known\ncredential'
        secret_text = 'start\n' + secret + '\n' + 't' * 180
        secret_cut = redaction.safe_record_cut(secret_text, (secret,), eof=False)
        secret_start = secret_text.index(secret)
        self.assertFalse(secret_start < secret_cut < secret_start + len(secret))

        pem = ('-----BEGIN PRIVATE KEY-----\n' + 'x\n' * 60
               + '-----END PRIVATE KEY-----')
        pem_text = 'start\n' + pem + '\n' + 't' * 60
        pem_cut = redaction.safe_record_cut(pem_text, ('known-secret',), eof=False)
        pem_start = pem_text.index('-----BEGIN')
        pem_end = pem_text.index('-----END') + len('-----END PRIVATE KEY-----')
        self.assertFalse(pem_start < pem_cut < pem_end)

    def test_safe_record_cut_keeps_sensitive_assignment_context_together(self):
        text = 'before\naccess_token=\nunknown-value\n' + 't' * 69
        cut = redaction.safe_record_cut(text, ('1234567',), eof=False)
        start = text.index('access_token')
        finish = text.index('\n', text.index('unknown-value')) + 1
        self.assertTrue(cut <= start or cut >= finish)

    def test_safe_record_cut_rejects_multiline_json(self):
        pretty = '{\n  "access_token":\n  "unknown-value"\n}\n' + 'tail\n' * 20
        with self.assertRaises(OverflowError):
            redaction.safe_record_cut(pretty, eof=False)

    def test_safe_record_cut_keeps_escaped_known_secret_whole(self):
        secret = 'a\nbc'
        text = 'prefix\n\\u0061\nbc\n' + 'x' * 46
        cut = redaction.safe_record_cut(text, (secret,), eof=False)
        start = text.index('\\u0061')
        end = text.index('bc', start) + 2
        self.assertFalse(start < cut < end)

    def test_safe_record_cut_is_utf8_line_aligned(self):
        text = ('界' * 100 + '\n' + '再' * 100 + '\n')
        cut = redaction.safe_record_cut(text, eof=False)
        self.assertEqual(text[cut - 1], '\n')
        text[:cut].encode('utf-8').decode('utf-8')


class PolicyTests(unittest.TestCase):
    def test_defaults_on_and_adapter_tolerates_unknown_shapes(self):
        for config in (None, {}, {'unrelated': 1}, SimpleNamespace(unrelated=1),
                       {'redaction': {'redact_fields': ['foo']}}):
            rules = redaction.policy(config)
            self.assertTrue(rules.enabled)
        self.assertIn('foo', redaction.policy({'redaction': {'redact_fields': ['foo']}}).redact_fields)
        self.assertIn('bar', redaction.policy({'redaction': {'allow_fields': ['bar']}}).allow_fields)

        class Manager:
            def snapshot(self):
                return SimpleNamespace(redaction_enabled=False, allow_fields=('token',),
                                       redact_fields=[])

        self.assertFalse(redaction.policy(Manager()).enabled)
        self.assertIn('token', redaction.policy(Manager()).allow_fields)
        self.assertFalse(redaction.policy(SimpleNamespace(config=Manager())).enabled)
        self.assertTrue(redaction.policy({'redaction_enabled': 'yes'}).enabled)

    def test_non_list_field_rules_are_ignored(self):
        rules = redaction.policy({'redact_fields': 'token', 'allow_fields': [3, 'x']})
        self.assertEqual(rules.redact_fields, frozenset())
        self.assertEqual(rules.allow_fields, frozenset({'x'}))

    def test_user_allow_beats_user_redact_and_builtin(self):
        rules = redaction.policy({'allow_fields': ['Token'], 'redact_fields': ['token', 'Custom']})
        clean = redaction.Cleaner((TOKEN,), rules).value(
            {'token': TOKEN, 'Token': 'Bearer plain', 'Custom': 'CUSTOM',
             'other': TOKEN, 'password': 'pw'})
        # allow（token）优先于同类用户 redact 与内置 password。
        self.assertEqual(clean['token'], TOKEN)
        self.assertEqual(clean['Token'], 'Bearer plain')
        self.assertEqual(clean['Custom'], MARKER)
        self.assertEqual(clean['other'], MARKER)
        self.assertEqual(clean['password'], MARKER)

    def test_allow_matches_exact_name_only(self):
        rules = redaction.policy({'allow_fields': ['token']})
        clean = redaction.Cleaner((), rules).value({'token': 't', 'mytoken': 'm', 'access_token': 'a'})
        self.assertEqual(clean['token'], 't')
        self.assertEqual(clean['mytoken'], 'm')
        self.assertEqual(clean['access_token'], MARKER)

    def test_token_access_token_mytoken_under_allow_token(self):
        rules = redaction.policy({'allow_fields': ['Token']})
        source = {'token': TOKEN, 'access_token': TOKEN, 'mytoken': TOKEN, 'TOKEN': TOKEN}
        clean = redaction.Cleaner((TOKEN,), rules).value(source)
        # 字段名精确大小写折叠匹配 token，才允许反脱敏；access_token 仍是内置凭据。
        self.assertEqual(clean['token'], TOKEN)
        self.assertEqual(clean['TOKEN'], TOKEN)
        self.assertEqual(clean['access_token'], MARKER)
        self.assertEqual(clean['mytoken'], MARKER)
        # 文本标签同样：allow token 不再命中，但 access_token/mytoken 标签仍命中。
        # mytoken 不是内置字段，文本标签不会被前缀猜测命中。
        text = redaction.Cleaner((), rules).value('token=plain access_token=secret mytoken=other')
        self.assertIn('token=plain', text)
        self.assertIn('access_token=' + MARKER, text)
        self.assertIn('mytoken=other', text)

    def test_allowed_text_label_preserves_known_and_bearer_values(self):
        rules = redaction.policy({'allow_fields': ['token']})
        text = 'token="Bearer ' + TOKEN + '" password=hidden other=' + TOKEN
        clean = redaction.Cleaner((TOKEN,), rules).value(text)
        self.assertIn('token="Bearer ' + TOKEN + '"', clean)
        self.assertIn('password=' + MARKER, clean)
        self.assertIn('other=' + MARKER, clean)

    def test_allowed_encoded_query_preserves_known_value(self):
        rules = redaction.policy({'allow_fields': ['access_token']})
        text = 'https://example.org/?access%5Ftoken=' + TOKEN + '&password=hidden'
        clean = redaction.Cleaner((TOKEN,), rules).value(text)
        self.assertIn('access%5Ftoken=' + TOKEN, clean)
        self.assertIn('password=' + MARKER, clean)

    def test_allow_access_token_leaves_only_that_field(self):
        rules = redaction.policy({'allow_fields': ['access_token']})
        clean = redaction.Cleaner((TOKEN,), rules).value(
            {'access_token': 'plain-access', 'token': TOKEN})
        self.assertEqual(clean, {'access_token': 'plain-access', 'token': MARKER})

    def test_allow_subtree_keeps_values_but_still_validates(self):
        rules = redaction.policy({'allow_fields': ['payload']})
        clean = redaction.Cleaner((TOKEN,), rules).value(
            {'payload': {'password': 'p', 'text': TOKEN, 'item': [TOKEN]}, 'other': {'password': 'p'}})
        self.assertEqual(clean['payload'], {'password': 'p', 'text': TOKEN, 'item': [TOKEN]})
        self.assertEqual(clean['other'], {'password': MARKER})
        for bad in ({'payload': [None] * (redaction.MAX_NODES + 1)},
                    {'payload': 'x' * (redaction.MAX_TEXT + 1)}):
            with self.assertRaises(OverflowError):
                redaction.Cleaner((), rules).value(bad)
        with self.assertRaises(redaction.RedactionError):
            redaction.Cleaner((), rules).value({'payload': {'bad': float('inf')}})

    def test_nested_json_allow_is_consistent_with_structured_output(self):
        rules = redaction.policy({'allow_fields': ['token']})
        raw = {'token': 'plain-token', 'password': 'p', 'note': TOKEN}
        clean = redaction.Cleaner((TOKEN,), rules).value(raw)
        text = redaction.Cleaner((TOKEN,), rules).value(json.dumps(raw))
        self.assertEqual(json.loads(text), clean)
        self.assertEqual(clean, {'token': 'plain-token', 'password': MARKER, 'note': MARKER})

    def test_disabled_policy_keeps_values_but_still_rejects_bad_input(self):
        rules = redaction.policy(OFF)
        source = {'token': 'raw', 'password': 'raw', 'user_id': 1, 'note': 'Bearer ' + TOKEN}
        self.assertEqual(redaction.Cleaner((TOKEN,), rules).value(source), source)
        self.assertEqual(redaction.credentials(TOKEN, {}, rules), ())
        self.assertEqual(redaction.Cleaner((TOKEN,), rules).value('令牌=raw'), '令牌=raw')
        for data in ({'x': float('nan')}, {1: 'x'}, {1, 2}, {'x': 'y' * (redaction.MAX_TEXT + 1)}):
            with self.assertRaises((redaction.RedactionError, OverflowError)):
                redaction.Cleaner((), rules).value(data)
        with patch.object(redaction, 'MAX_SCAN', 1), self.assertRaises(OverflowError):
            redaction.Cleaner((), rules).value('ordinary text')

    def test_disabled_policy_ignores_known_snapshot_and_password_values(self):
        rules = redaction.policy(OFF)
        clean = redaction.Cleaner(('bad',), rules).value(
            {'password': 'raw-password', 'log': 'Bearer raw-token bad'})
        self.assertEqual(clean, {'password': 'raw-password', 'log': 'Bearer raw-token bad'})

    def test_allow_does_not_weaken_known_secret_scan_elsewhere(self):
        rules = redaction.policy({'allow_fields': ['token']})
        clean = redaction.Cleaner((TOKEN,), rules).value(
            {'token': TOKEN, 'log': 'unrelated ' + TOKEN, 'message': 'password=hidden'})
        self.assertEqual(clean['token'], TOKEN)
        self.assertEqual(clean['log'], 'unrelated ' + MARKER)
        self.assertEqual(clean['message'], 'password=' + MARKER)


class ReplyTests(unittest.TestCase):
    def test_both_eras_share_clean_text_and_data_without_mutating_outcome(self):
        source = {'message': 'body ' + TOKEN, 'id': 123, 'bot_hash': 'safe-hash', 'namespace': 'Example'}
        before = copy.deepcopy(source)
        callback = lambda: None
        outcome = Outcome(source, after_send=callback)
        for modern in (False, True):
            reply = result(stub_service(), outcome, modern)
            payload = json.loads(reply.body)
            clean = payload['result']
            self.assertEqual(payload['id'], 'rpc-account-42')
            self.assertEqual(json.loads(clean['content'][0]['text']), clean['structuredContent'])
            self.assertEqual(clean['structuredContent']['id'], 123)
            self.assertEqual(clean['structuredContent']['bot_hash'], 'safe-hash')
            self.assertTrue(clean['_meta']['redacted'])
            self.assertFalse(clean['isError'])
            self.assertNotIn(TOKEN.encode(), reply.body)
        self.assertEqual(source, before)
        self.assertIs(outcome.after_send, callback)

    def test_service_paged_result_uses_one_cleaned_view_in_both_eras(self):
        text = 'x' * 1024 * 1024
        data = {'namespace': 'Demo', 'path': 'large.txt', 'size': len(text),
                'content': text, 'sha256': 'full-only-if-unpaged'}
        page = files.DataPage(
            None, files._path_tag('Demo', 'large.txt'),
            (1, 2, len(text), 3, 4), len(text), 0, None, True, True, None)
        outcome = Outcome(data, page=page)
        for modern in (False, True):
            reply = result(stub_service(), outcome, modern)
            payload = json.loads(reply.body)
            clean = payload['result']
            structured = clean['structuredContent']
            self.assertFalse(clean['isError'])
            self.assertTrue(structured['paged'])
            self.assertNotIn('sha256', structured)
            self.assertIsInstance(structured['next_cursor'], str)
            self.assertEqual(json.loads(clean['content'][0]['text']), structured)
            self.assertNotIn(TOKEN.encode(), reply.body)
            self.assertLessEqual(len(reply.body), protocol.MAX_RESPONSE)

    def test_protocol_direct_success_errors_discover_schema_and_ids(self):
        for modern in (False, True):
            reply = protocol.encode_reply(protocol.result_body('rpc-42', {'id': 123, 'token': 'raw'}, modern), modern)
            payload = json.loads(reply.body)['result']
            self.assertEqual(payload['id'], 123)
            self.assertEqual(payload['token'], MARKER)
            reply = protocol.reply_from(protocol.Reject(400, -32602, 'password=hidden', {'user_id': 42}),
                                        modern, 'rpc-42')
            payload = json.loads(reply.body)
            self.assertEqual((payload['id'], payload['error']['code']), ('rpc-42', -32602))
            self.assertNotIn(b'hidden', reply.body)
            self.assertEqual(payload['error']['data']['user_id'], 42)
            self.assertTrue(payload['error']['data']['_meta']['redacted'])
        spec = ToolSpec('tool', 'description', object_schema({'user_id': {'type': 'string'},
                                                            'token': {'type': 'string'}}), lambda ctx, args: None)
        reply = protocol.encode_reply(protocol.result_body(99, protocol.list_result((spec,)), True), True)
        payload = json.loads(reply.body)
        self.assertEqual(payload['result']['tools'][0], spec.definition())
        self.assertEqual(payload['result']['resultType'], 'complete')
        reply = protocol.encode_reply(protocol.result_body(99, protocol.discover_result(), True), True,
                                      known=(protocol.MODERN_VERSION,))
        self.assertEqual(json.loads(reply.body)['result']['supportedVersions'], list(protocol.SUPPORTED))
        self.assertEqual(dict(reply.headers)['MCP-Protocol-Version'], protocol.MODERN_VERSION)

    def test_public_protocol_metadata_is_not_rewritten_as_a_known_secret(self):
        known = ('tool', 'tools', 'isError', '_meta', 'readOnlyHint', 'OlivOS',
                 'protocol', 'capabilities', 'serverInfo', 'v0.2.0', protocol.MODERN_VERSION)
        spec = ToolSpec('tool', 'description', object_schema({'user_id': {'type': 'string'}}),
                        lambda ctx, args: None)
        data = {'safe': 'value'}
        tool = protocol.tool_result(Outcome(data), protocol.dumps(data))
        tool['_meta'] = {protocol.META_SERVER: dict(protocol.SERVER_INFO)}
        results = (protocol.list_result((spec,)), protocol.discover_result(), tool,
                   {'protocolVersion': protocol.DEFAULT_LEGACY, 'capabilities': {'tools': {}},
                    'serverInfo': dict(protocol.SERVER_INFO)})
        for modern in (False, True):
            for value in results:
                body = protocol.result_body(42, value, modern)
                reply = protocol.encode_reply(body, modern, known=known)
                self.assertEqual(json.loads(reply.body), body)
            rejected = protocol.Reject(400, protocol.UNSUPPORTED_VERSION, 'Unsupported version',
                                       {'supported': [protocol.MODERN_VERSION]})
            reply = protocol.reply_from(rejected, modern, 42, known=known)
            self.assertEqual(json.loads(reply.body)['error']['data']['supported'],
                             [protocol.MODERN_VERSION])

    def _reject_from_classify(self, requested):
        """从 classify 实际抛出的现代版本错误编码，不手工构造现实不会生成的 dict。"""
        meta = {protocol.META_VERSION: requested,
                protocol.META_CAPABILITIES: {},
                protocol.META_CLIENT: {'name': 'client', 'version': '1.0'}}
        body = {'jsonrpc': '2.0', 'id': 42, 'method': 'tools/list',
                'params': {'_meta': meta}}
        headers = {'MCP-Protocol-Version': requested, 'Mcp-Method': 'tools/list'}
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(body, headers)
        return caught.exception

    def test_modern_version_error_preserves_fixed_supported_and_cleans_requested(self):
        rejected = self._reject_from_classify(TOKEN)
        self.assertEqual(rejected.data['requested'], TOKEN)
        reply = protocol.reply_from(rejected, True, 42, known=(TOKEN,))
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['supported'], [protocol.MODERN_VERSION])
        self.assertEqual(data['requested'], MARKER)
        self.assertTrue(data['_meta']['redacted'])

    def test_modern_version_error_user_field_rules_still_apply(self):
        rejected = self._reject_from_classify('2027-01-01')
        rules = redaction.policy({'redact_fields': ['requested']})
        reply = protocol.reply_from(rejected, True, 42, known=(), policy=rules)
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['supported'], [protocol.MODERN_VERSION])
        self.assertEqual(data['requested'], MARKER)
        # supported 字段走 schema 保留，不受用户字段规则影响。
        rules = redaction.policy({'redact_fields': ['supported']})
        reply = protocol.reply_from(rejected, True, 42, known=(), policy=rules)
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['supported'], [protocol.MODERN_VERSION])
        self.assertNotIn('_meta', data)

    def test_legacy_version_error_preserves_fixed_supported_list(self):
        with self.assertRaises(protocol.Reject) as caught:
            protocol.classify(
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2027-01-01', 'capabilities': {},
                    'clientInfo': {'name': 'client', 'version': '1.0'}}},
                {'MCP-Protocol-Version': '2027-01-01'})
        rejected = caught.exception
        self.assertEqual(rejected.data['supported'], list(protocol.LEGACY_VERSIONS))
        reply = protocol.reply_from(rejected, False, 1, known=('2027-01-01',))
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['supported'], list(protocol.LEGACY_VERSIONS))
        self.assertNotIn(b'2027-01-01', reply.body)

    def test_non_whitelisted_error_data_gets_no_exemption(self):
        # 普通错误：data 整体走普通清理
        plain = protocol.Reject(400, protocol.INVALID_PARAMS, 'Invalid params',
                                {'echo': TOKEN, 'password': 'p'})
        reply = protocol.reply_from(plain, False, 1, known=(TOKEN,))
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['echo'], MARKER)
        self.assertEqual(data['password'], MARKER)
        # -32022 但 supported 非固定列表：不豁免，值按普通文本清理
        odd = protocol.Reject(400, protocol.UNSUPPORTED_VERSION, 'Unsupported version',
                              {'supported': [TOKEN], 'note': TOKEN})
        reply = protocol.reply_from(odd, False, 1, known=(TOKEN,))
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['supported'], [MARKER])
        self.assertEqual(data['note'], MARKER)
        # 固定 supported 之外的额外 secret 字段仍被清理
        extra = protocol.Reject(400, protocol.UNSUPPORTED_VERSION, 'Unsupported version',
                                {'supported': [protocol.MODERN_VERSION], 'requested': 'x',
                                 'password': 'p', 'note': TOKEN})
        reply = protocol.reply_from(extra, False, 1, known=(TOKEN,))
        data = json.loads(reply.body)['error']['data']
        self.assertEqual(data['supported'], [protocol.MODERN_VERSION])
        self.assertEqual(data['password'], MARKER)
        self.assertEqual(data['note'], MARKER)

    def test_poison_json_text_does_not_downgrade_whole_response(self):
        for raw in ({'line': '{"password":"leak-value"}}', 'id': 123, 'safe': 'kept'},
                    {'line': '{"token":"first-leak","token":"second-leak"}', 'id': 123,
                     'safe': 'kept'}):
            for modern in (False, True):
                body = protocol.result_body(7, protocol.tool_result(Outcome(raw), protocol.dumps(raw)), modern)
                reply = protocol.encode_reply(body, modern)
                self.assertFalse(reply.failed)
                payload = json.loads(reply.body)['result']
                self.assertNotIn(b'leak', reply.body)
                self.assertEqual(payload['structuredContent']['id'], 123)
                self.assertEqual(payload['structuredContent']['safe'], 'kept')
                self.assertEqual(json.loads(payload['content'][0]['text']),
                                 payload['structuredContent'])

    def test_protocol_regenerates_duplicate_text_from_clean_data(self):
        raw = {'id': 123, 'message': TOKEN}
        body = protocol.result_body(7, protocol.tool_result(Outcome(raw), 'intentionally unsafe ' + TOKEN), True)
        before = copy.deepcopy(body)
        reply = protocol.encode_reply(body, True, known=(TOKEN,))
        payload = json.loads(reply.body)['result']
        self.assertEqual(json.loads(payload['content'][0]['text']), payload['structuredContent'])
        self.assertNotIn(TOKEN.encode(), reply.body)
        self.assertTrue(payload['_meta']['redacted'])
        self.assertEqual(body, before)

    def test_second_protocol_pass_keeps_allow_fields_untouched(self):
        rules = redaction.policy({'allow_fields': ['token']})
        raw = {'token': TOKEN, 'note': TOKEN}
        body = protocol.result_body(7, protocol.tool_result(Outcome(raw), protocol.dumps(raw)), True)
        for _ in range(2):
            reply = protocol.encode_reply(body, True, known=(TOKEN,), policy=rules)
            result = json.loads(reply.body)['result']
            body = protocol.result_body(7, {**result, 'resultType': 'complete'}, True)
        self.assertEqual(result['structuredContent']['token'], TOKEN)
        self.assertEqual(result['structuredContent']['note'], MARKER)
        self.assertEqual(json.loads(result['content'][0]['text']), result['structuredContent'])

    def test_disabled_policy_keeps_values_and_marks_nothing(self):
        rules = redaction.policy(OFF)
        raw = {'token': TOKEN, 'password': 'p'}
        body = protocol.result_body(7, protocol.tool_result(Outcome(raw), protocol.dumps(raw)), True)
        reply = protocol.encode_reply(body, True, known=(TOKEN,), policy=rules)
        result = json.loads(reply.body)['result']
        self.assertEqual(result['structuredContent'], raw)
        self.assertEqual(json.loads(result['content'][0]['text']), raw)
        self.assertNotIn('redacted', result.get('_meta', {}))
        error = protocol.reply_from(protocol.Reject(400, -32602, 'password=hidden'), True, 7, policy=rules)
        self.assertEqual(json.loads(error.body)['error']['message'], 'password=hidden')

    def test_disabled_policy_still_bounds_output(self):
        rules = redaction.policy(OFF)
        with self.assertRaises(OverflowError):
            protocol.encode_reply(protocol.result_body(1, {'x': 'a' * (1024 * 1024)}, False), False,
                                  policy=rules)
        reply = protocol.encode_reply(protocol.result_body(1, {'x': float('inf')}, False), False,
                                      policy=rules)
        self.assertTrue(reply.failed)
        self.assertNotIn(b'Infinity', reply.body)

    def test_redactor_baseexception_fallback_is_bounded_and_never_reenters(self):
        for error in (SystemExit, KeyboardInterrupt):
            with patch.object(redaction, 'Cleaner', side_effect=error) as broken:
                reply = result(stub_service(), Outcome({'raw': TOKEN}), task=SimpleNamespace(ok=True))
                self.assertEqual(broken.call_count, 1)
                self.assertTrue(reply.failed)
                self.assertNotIn(TOKEN.encode(), reply.body)
                self.assertTrue(json.loads(reply.body)['result']['isError'])
            with patch.object(redaction, 'Cleaner', side_effect=error) as broken:
                reply = protocol.reply_from(protocol.Reject(400, -32602, TOKEN), True, 42, known=(TOKEN,))
                self.assertEqual(broken.call_count, 1)
                self.assertEqual(json.loads(reply.body)['error']['code'], -32602)
                self.assertTrue(reply.failed)
        reply = protocol.safe_reply('界' * 200000, True, tool=True)
        self.assertLessEqual(len(reply.body), protocol.MAX_RESPONSE)
        self.assertIsNone(json.loads(reply.body)['id'])

    def test_encoding_budget_and_second_boundary_failure_abort_task(self):
        task = SimpleNamespace(ok=True)
        reply = result(stub_service(), Outcome({'value': 'x' * redaction.MAX_TEXT}), task=task)
        self.assertFalse(task.ok)
        self.assertTrue(json.loads(reply.body)['result']['structuredContent']['truncated'])
        self.assertLessEqual(len(reply.body), protocol.MAX_RESPONSE)
        task.ok = True
        with patch.object(protocol, '_clean_body', side_effect=SystemExit):
            reply = result(stub_service(), Outcome({'value': 'ok'}), task=task)
        self.assertFalse(task.ok)
        self.assertTrue(reply.failed)
        with patch.object(redaction.Cleaner, 'value', side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                result(stub_service(), Outcome({'value': 'ok'}), task=task)
            with self.assertRaises(asyncio.CancelledError):
                protocol.reply_from(protocol.Reject(400, -32602, 'safe'))

    def test_sdk_receives_original_message_and_target(self):
        observed = []

        class Bot:
            def __init__(self):
                self.hash = 'safe-hash'
                self.id = '10001'
                self.enable = True
                self.password = 'bot-password'
                self.platform = {'sdk': 'qq', 'platform': 'qq', 'model': 'm'}

        class Snapshot:
            generation = 0

            def allows(self, permission, mode):
                return permission in ('real_account_write', 'real_account_read', None)

        class Manager:
            def snapshot(self):
                return Snapshot()

        class Template:
            def __init__(self, mode, data):
                self.active = True
                self.mode_rx = mode
                self.data = data

        class SDK:
            messageAPI = SimpleNamespace(
                PARA=SimpleNamespace(text=lambda text: SimpleNamespace(type='text', data={'text': text})),
                Message_templet=Template)
            contentAPI = SimpleNamespace(fake_sdk_event=lambda **kwargs: kwargs['bot_info'])
            API = SimpleNamespace(Event=lambda fake, log: SimpleNamespace(
                active=True, bot_info=fake, platform={'sdk': 'qq', 'platform': 'qq', 'model': 'm'},
                plugin_info={'message_mode_rx': 'olivos_para'},
                send=lambda send_type, target, message, host_id=None:
                    observed.append((send_type, target, message))))

        bot = Bot()
        proc = SimpleNamespace(Proc_data={'bot_info_dict': {'safe-hash': bot}}, log=lambda *args: None)
        svc = stub_service(proc, SDK())
        svc.context = Context(proc, '/unused', '/unused/data', SDK(),
                              config=Manager(), permission_mode='full')
        args = {'bot_hash': 'safe-hash', 'send_type': 'private', 'target_id': '42',
                'message': 'password=actual-message ' + TOKEN}
        before = dict(args)
        outcome = full_only._send(svc.context, args)
        reply = result(svc, outcome)
        self.assertFalse(outcome.is_error, outcome.data)
        self.assertEqual([(send_type, target) for send_type, target, _ in observed],
                         [('private', '42')])
        template = observed[0][2]
        self.assertEqual(template.mode_rx, 'olivos_para')
        self.assertEqual([(para.type, para.data) for para in template.data],
                         [('text', {'text': before['message']})])
        self.assertEqual(args, before)
        self.assertEqual(outcome.data['target_id'], '42')
        self.assertEqual(json.loads(reply.body)['result']['structuredContent']['target_id'], '42')


class DeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_controlled_necessary_headers_are_written(self):
        class Response:
            def __init__(self, **kwargs):
                self.headers = {}
                self.kwargs = kwargs

            async def prepare(self, request):
                pass

            async def write_eof(self):
                pass

        headers = (('X-Debug', TOKEN), ('Set-Cookie', TOKEN), ('Allow', 'POST'),
                   ('WWW-Authenticate', 'Bearer'), ('MCP-Protocol-Version', protocol.MODERN_VERSION),
                   ('Mcp-Session-Id', 'required-session'), ('Connection', 'close'),
                   ('Allow', TOKEN), ('Mcp-Session-Id', 'bad session'))
        with patch.object(service, 'web', SimpleNamespace(Response=Response)):
            response = await service._Service._write(None, protocol.Reply(202, headers=headers))
        self.assertEqual(response.headers, {'Allow': 'POST', 'WWW-Authenticate': 'Bearer',
                                           'MCP-Protocol-Version': protocol.MODERN_VERSION,
                                           'Mcp-Session-Id': 'required-session', 'Connection': 'close'})
        self.assertEqual(response.kwargs, {'status': 202})

    async def test_redaction_failure_does_not_deliver_after_send(self):
        fired = threading.Event()
        tool = ToolSpec('reload', 'reload', object_schema(),
                        lambda ctx, args: Outcome({'ok': True}, after_send=fired.set))
        svc = service._Service(stub_service().context, TOKEN, (tool,), 1)
        headers = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json',
                   'MCP-Protocol-Version': protocol.MODERN_VERSION, 'Mcp-Method': 'tools/call', 'Mcp-Name': 'reload'}

        class Headers(dict):
            def getall(self, name, default):
                return [self[name]] if name in self else default

        raw = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': 'reload', 'arguments': {}, '_meta': {protocol.META_VERSION: protocol.MODERN_VERSION,
                                                       protocol.META_CAPABILITIES: {}}}}).encode()

        class Content:
            async def read(self, count):
                nonlocal raw
                chunk, raw = raw[:count], raw[count:]
                return chunk

        req = SimpleNamespace(method='POST', headers=Headers(headers), content=Content(), content_length=len(raw))
        replies = []

        async def write(_request, reply):
            replies.append(reply)
            return 'sent'

        try:
            with patch.object(svc, '_write', write), patch.object(redaction.Cleaner, 'value', side_effect=SystemExit):
                self.assertEqual(await svc.handle(req), 'sent')
            for _ in range(100):
                if svc.pool.slots._value == 8:
                    break
                await asyncio.sleep(0.001)
            self.assertEqual(svc.pool.slots._value, 8)
            self.assertFalse(fired.is_set())
            self.assertTrue(json.loads(replies[0].body)['result']['isError'])
        finally:
            svc.pool.close()


if __name__ == '__main__':
    unittest.main()
