"""人工发布辅助：草稿占位、简短变更说明及撤版检查；仅由工作流调用。"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from build_opk import release_version

ROOT = Path(__file__).resolve().parents[1]
FIRST_RELEASE = """**新增**

- 提供 Full / Lite 两种 OPK，通过 MCP 查询宿主、账号、插件、日志与插件数据。
- 支持预置虚拟终端账号的消息输入和入站事件观察。
- Full 支持受控消息发送、加载器重载、配置与账号存档更新及入站规则。
- 提供同版本 AI 使用 skill，覆盖排障、数据读取、权限与受控操作。
"""


def api(endpoint, *options, body=None, missing_ok=False):
    command = ['gh', 'api', endpoint, *options]
    if body is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(body) if body is not None else None,
                            capture_output=True, text=True, check=False)
    if result.returncode:
        if missing_ok and '(HTTP 404)' in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip() or 'GitHub API request failed')
    return json.loads(result.stdout)


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()


def releases(repo):
    pages = api(f'repos/{repo}/releases', '--paginate', '--slurp')
    return [release for page in pages for release in page]


def previous_release(rows, version):
    public = [row for row in rows if not row['draft'] and row.get('published_at')
              and row['tag_name'] != version]
    return max(public, key=lambda row: (row['published_at'], row['id']), default=None)


def render_notes(subjects):
    groups = {'新增': [], '优化': [], '修复': []}
    for subject in subjects:
        match = re.fullmatch(r'(\w+)(?:\([^\n)]+\))?!?:\s*(.+)', subject)
        if match:
            kind, title = match.groups()
            if kind in {'docs', 'test', 'tests', 'ci', 'build', 'chore', 'style'}:
                continue
            group = {'feat': '新增', '新增': '新增', '增加': '新增', '添加': '新增', '支持': '新增',
                     'fix': '修复', '修复': '修复', '修正': '修复', '解决': '修复'}.get(kind, '优化')
        else:
            title = subject
            group = ('新增' if title.startswith(('新增', '增加', '添加', '支持')) else
                     '修复' if title.startswith(('修复', '修正', '解决')) else '优化')
        if title and title not in groups[group]:
            groups[group].append(title)
    blocks = [f'**{group}**\n\n' + '\n'.join(f'- {title}' for title in titles)
              for group, titles in groups.items() if titles]
    return '\n\n'.join(blocks) + '\n' if blocks else '本次无新增功能、优化或修复记录。\n'


def notes(repo, version, commit):
    previous = previous_release(releases(repo), version)
    if previous is None:
        return FIRST_RELEASE
    base = git('rev-parse', '--verify', '--end-of-options',
               f'refs/tags/{previous["tag_name"]}^{{commit}}')
    subprocess.run(['git', '-C', str(ROOT), 'merge-base', '--is-ancestor', base, commit], check=True)
    subjects = git('log', '--no-merges', '--reverse', '--format=%s', f'{base}..{commit}').splitlines()
    return render_notes(subjects)


def check_tag(repo, version, commit):
    reference = api(f'repos/{repo}/git/ref/tags/{version}', missing_ok=True)
    if reference is None:
        return  # 草稿可先引用尚未创建的 tag，发布时按固定 commit 创建。
    target = reference['object']
    for _ in range(16):
        if target['type'] == 'commit' and target['sha'] == commit:
            return
        if target['type'] != 'tag':
            break
        target = api(f'repos/{repo}/git/tags/{target["sha"]}')['object']
    raise ValueError('Release tag points to a different commit or cannot be resolved')


def check_draft(release, version, commit):
    if (release['tag_name'] != version or not release['draft']
            or release['target_commitish'] != commit):
        raise ValueError('Release was published or changed; refusing to overwrite it')


def prepare(repo, version, state_path):
    if version != release_version(ROOT):
        raise ValueError('Requested version does not match plugin and skill')
    commit = git('rev-parse', '--verify', 'HEAD^{commit}')
    check_tag(repo, version, commit)
    current = next((row for row in releases(repo) if row['tag_name'] == version), None)
    body = notes(repo, version, commit)
    if current is None:
        # shortcut: 重跑缺草稿统一按撤回处理；需要区分预留前失败时再持久化运行状态。
        if int(os.environ.get('GITHUB_RUN_ATTEMPT', '1')) > 1:
            raise ValueError('Release draft is missing or withdrawn; start a new manual run')
        current = api(f'repos/{repo}/releases', '--method', 'POST', body={
            'tag_name': version, 'target_commitish': commit, 'name': version,
            'body': body, 'draft': True, 'prerelease': '-' in version,
        })
    check_draft(current, version, commit)
    state_path.write_text(json.dumps({'repo': repo, 'version': version, 'commit': commit,
                                      'release_id': current['id']}) + '\n', encoding='utf-8')
    print(f'Reserved draft {version} (release ID {current["id"]})')


def publish(repo, state_path, assets):
    state = json.loads(state_path.read_text(encoding='utf-8'))
    version, commit = release_version(ROOT), git('rev-parse', '--verify', 'HEAD^{commit}')
    if (state['repo'], state['version'], state['commit']) != (repo, version, commit):
        raise ValueError('Release state does not match this checkout')
    endpoint = f'repos/{repo}/releases/{int(state["release_id"])}'
    check_draft(api(endpoint), version, commit)
    check_tag(repo, version, commit)
    expected = {f'OlivOSCockpit-{version}.opk', f'OlivOSCockpitLite-{version}.opk',
                f'olivos-cockpit-skill-{version}.zip'}
    files = list(assets.iterdir())
    if ({path.name for path in files} != expected
            or any(path.is_symlink() or not path.is_file() for path in files)):
        raise ValueError('Expected exactly the Full OPK, Lite OPK and matching skill ZIP')
    # upload 不创建 Release；最终发布始终使用预留的 ID，删除后只会失败。
    subprocess.run(['gh', 'release', 'upload', version, '--repo', repo, '--clobber',
                    *[str(path) for path in sorted(files)]], check=True)
    check_draft(api(endpoint), version, commit)
    check_tag(repo, version, commit)
    # 上一版也可能在构建期间被撤回，发布前按仍公开的 Release 重新生成说明。
    body = notes(repo, version, commit)
    published = api(endpoint, '--method', 'PATCH', body={'body': body, 'draft': False})
    print(published['html_url'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    preparing = commands.add_parser('prepare')
    preparing.add_argument('--version', required=True)
    preparing.add_argument('--state', type=Path, required=True)
    publishing = commands.add_parser('publish')
    publishing.add_argument('--state', type=Path, required=True)
    publishing.add_argument('--assets', type=Path, required=True)
    args = parser.parse_args()
    repo = os.environ['GITHUB_REPOSITORY']
    if args.command == 'prepare':
        prepare(repo, args.version, args.state)
    else:
        publish(repo, args.state, args.assets)


if __name__ == '__main__':
    main()
