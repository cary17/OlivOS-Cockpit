"""人工发布的版本、变更范围和撤版边界；所有 GitHub 写操作均使用替身。"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
_spec = importlib.util.spec_from_file_location('release_workflow', ROOT / 'scripts' / 'release.py')
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)

VERSION = 'v0.1.0'
COMMIT = 'a' * 40
REPO = 'example/cockpit'


def row(tag, published='2026-11-01T00:00:00Z', *, draft=False, ident=1):
    return {'id': ident, 'tag_name': tag, 'draft': draft, 'published_at': published,
            'target_commitish': COMMIT}


class ReleaseTests(unittest.TestCase):
    def test_previous_release_uses_publication_time_and_includes_prereleases(self):
        rows = [row('v0.1.0', ident=1),
                row('v0.2.0-beta.1', '2026-11-02T00:00:00Z', ident=2),
                row('v0.3.0', '2026-11-03T00:00:00Z', draft=True, ident=3),
                row(VERSION, '2026-11-04T00:00:00Z', ident=4)]
        self.assertEqual(release.previous_release(rows, VERSION)['tag_name'], 'v0.2.0-beta.1')
        self.assertIsNone(release.previous_release([row(VERSION)], VERSION))

    def test_notes_only_include_explicit_plugin_and_skill_features(self):
        body = release.render_notes([
            'feat(plugin): 支持数据续读', 'fix(plugin): 修复游标校验',
            'perf(plugin): 减少日志扫描', 'feat(skill): 增加排障路由',
            'fix(skill): 修正权限提示', 'perf(skill): 精简工具指引',
            'feat(plugin)!: 调整终端输入契约', 'feat(api): 错误 scope',
            'fix(ui): 错误 scope', 'feat: 无 scope 功能', 'fix: 无 scope 修复',
            'docs(plugin): 更新插件说明', 'docs(skill): 更新 skill 说明',
            'chore(plugin): 插件维护', 'chore(skill): skill 维护',
            'ci(plugin): 更新 Actions', 'build(plugin): 调整构建',
            'test(plugin): 补充回归', 'release(plugin): v0.2.0',
            'license(plugin): 调整许可', 'refactor(plugin): 拆分 helper',
            'style(plugin): 格式调整', '版本整理', '修正账号选择',
            'feat(plugin): 支持数据续读',
        ])
        self.assertIn('**新增**\n\n- 支持数据续读\n- 增加排障路由\n- 调整终端输入契约', body)
        self.assertIn('**优化**\n\n- 减少日志扫描\n- 精简工具指引', body)
        self.assertIn('**修复**\n\n- 修复游标校验\n- 修正权限提示', body)
        self.assertEqual(body.count('支持数据续读'), 1)
        for excluded in ('错误 scope', '无 scope', '更新插件说明', '更新 skill 说明',
                         '插件维护', 'skill 维护', 'Actions', '调整构建', '补充回归',
                         'v0.2.0', '调整许可', '拆分 helper', '格式调整',
                         '版本整理', '修正账号选择'):
            self.assertNotIn(excluded, body)
        self.assertEqual(release.render_notes([]), '')

    def test_first_release_describes_features_without_commit_dump(self):
        with patch.object(release, 'releases', return_value=[]), patch.object(release, 'git') as git:
            self.assertEqual(release.notes(REPO, VERSION, COMMIT), release.FIRST_RELEASE)
            git.assert_not_called()

    def test_deleted_release_tag_does_not_hide_its_changes_from_next_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(
                    ['git', '-C', str(root), *args], text=True, encoding='utf-8').strip()
            git('init', '--quiet')
            git('config', 'user.name', 'Release Test')
            git('config', 'user.email', 'release@example.invalid')
            git('commit', '--quiet', '--allow-empty', '-m', 'feat(plugin): 首次功能')
            git('tag', 'v0.0.1')
            git('commit', '--quiet', '--allow-empty', '-m', 'feat(plugin): 撤回版本里的新功能')
            git('tag', 'v0.0.2')  # Release 已撤回，tag 仍保留。
            git('commit', '--quiet', '--allow-empty', '-m', 'fix(plugin): 后续修复')
            with patch.object(release, 'ROOT', root), patch.object(
                    release, 'releases', return_value=[row('v0.0.1')]):
                body = release.notes(REPO, VERSION, git('rev-parse', 'HEAD'))
            self.assertIn('撤回版本里的新功能', body)
            self.assertIn('后续修复', body)
            self.assertNotIn('首次功能', body)

    def test_prepare_rejects_version_mismatch_before_network_or_state_write(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                release, 'release_version', return_value=VERSION), patch.object(release, 'api') as api:
            state = Path(directory) / 'state.json'
            with self.assertRaisesRegex(ValueError, 'version'):
                release.prepare(REPO, 'v9.0.0', state)
            api.assert_not_called()
            self.assertFalse(state.exists())

    def test_rerun_does_not_recreate_a_withdrawn_draft(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
                release, 'release_version', return_value=VERSION), patch.object(
                release, 'git', return_value=COMMIT), patch.object(
                release, 'check_tag'), patch.object(release, 'releases', return_value=[]), patch.object(
                release, 'api') as api, patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT': '2'}):
            with self.assertRaisesRegex(ValueError, 'withdrawn'):
                release.prepare(REPO, VERSION, Path(directory) / 'state.json')
            api.assert_not_called()

    def test_first_manual_run_reserves_a_draft_for_the_exact_commit(self):
        draft = row(VERSION, None, draft=True, ident=42)
        with tempfile.TemporaryDirectory() as directory, patch.object(
                release, 'release_version', return_value=VERSION), patch.object(
                release, 'git', return_value=COMMIT), patch.object(release, 'check_tag'), patch.object(
                release, 'releases', return_value=[]), patch.object(
                release, 'api', return_value=draft) as api, patch.dict(
                os.environ, {'GITHUB_RUN_ATTEMPT': '1'}):
            path = Path(directory) / 'state.json'
            release.prepare(REPO, VERSION, path)
            self.assertTrue(api.call_args.kwargs['body']['draft'])
            self.assertEqual(api.call_args.kwargs['body']['target_commitish'], COMMIT)
            self.assertEqual(json.loads(path.read_text())['release_id'], 42)

    def test_tag_check_accepts_lightweight_and_annotated_tags_and_rejects_moved_tag(self):
        with patch.object(release, 'api', return_value={'object': {'type': 'commit', 'sha': COMMIT}}):
            release.check_tag(REPO, VERSION, COMMIT)
            with self.assertRaises(ValueError):
                release.check_tag(REPO, VERSION, 'b' * 40)
        with patch.object(release, 'api', side_effect=[
                {'object': {'type': 'tag', 'sha': 'b' * 40}},
                {'object': {'type': 'commit', 'sha': COMMIT}}]):
            release.check_tag(REPO, VERSION, COMMIT)

    def test_publish_never_recreates_deleted_draft(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state.json'
            state.write_text(json.dumps({'repo': REPO, 'version': VERSION,
                                         'commit': COMMIT, 'release_id': 42}))
            with patch.object(release, 'release_version', return_value=VERSION), patch.object(
                    release, 'git', return_value=COMMIT), patch.object(
                    release, 'api', side_effect=RuntimeError('HTTP 404')) as api, patch.object(
                    release.subprocess, 'run') as upload:
                with self.assertRaisesRegex(RuntimeError, '404'):
                    release.publish(REPO, state, root)
                api.assert_called_once_with(f'repos/{REPO}/releases/42')
                upload.assert_not_called()

    def test_publish_uses_reserved_id_and_rechecks_notes_after_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, assets = root / 'state.json', root / 'assets'
            assets.mkdir()
            for name in ('OlivOSCockpit.opk', 'OlivOSCockpitLite.opk',
                         'olivos-cockpit-skill.zip'):
                (assets / name).write_bytes(b'tested archive')
            state.write_text(json.dumps({'repo': REPO, 'version': VERSION,
                                         'commit': COMMIT, 'release_id': 42}))
            draft = row(VERSION, None, draft=True, ident=42)
            with patch.object(release, 'release_version', return_value=VERSION), patch.object(
                    release, 'git', return_value=COMMIT), patch.object(release, 'check_tag'), patch.object(
                    release, 'api', side_effect=[draft, draft, {'html_url': 'release-url'}]) as api, patch.object(
                    release.subprocess, 'run') as upload, patch.object(
                    release, 'notes', return_value='Updated after withdrawal\n') as notes:
                release.publish(REPO, state, assets)
                self.assertEqual(api.call_args.args, (f'repos/{REPO}/releases/42', '--method', 'PATCH'))
                self.assertFalse(api.call_args.kwargs['body']['draft'])
                self.assertEqual(api.call_args.kwargs['body']['body'], 'Updated after withdrawal\n')
                upload.assert_called_once()
                notes.assert_called_once_with(REPO, VERSION, COMMIT)
                self.assertTrue(all(call.args[0].endswith('/42') for call in api.call_args_list))
                # 构建后仍可能撤回；即使附件上传完，也不得重新建版或继续发布。
                with patch.object(release, 'api', side_effect=[draft, RuntimeError('HTTP 404')]) as gone:
                    with self.assertRaisesRegex(RuntimeError, '404'):
                        release.publish(REPO, state, assets)
                    self.assertEqual(len(gone.call_args_list), 2)
                    self.assertTrue(all(not call.kwargs for call in gone.call_args_list))
                self.assertEqual(upload.call_count, 2)
                (assets / 'extra.zip').write_bytes(b'not a release asset')
                with patch.object(release, 'api', return_value=draft), self.assertRaisesRegex(
                        ValueError, 'exactly'):
                    release.publish(REPO, state, assets)
                self.assertEqual(upload.call_count, 2)

    def test_missing_ok_only_tolerates_not_found(self):
        failed = subprocess.CompletedProcess([], 1, '', 'gh: Not Found (HTTP 404)')
        with patch.object(release.subprocess, 'run', return_value=failed):
            self.assertIsNone(release.api('test', missing_ok=True))
            with self.assertRaises(RuntimeError):
                release.api('test')
        failed.stderr = 'gh: Forbidden (HTTP 403)'
        with patch.object(release.subprocess, 'run', return_value=failed), self.assertRaises(RuntimeError):
            release.api('test', missing_ok=True)


if __name__ == '__main__':
    unittest.main()
