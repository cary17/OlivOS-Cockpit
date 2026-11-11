"""仅用标准库构建互斥的 Full / Lite OPK 与使用 skill 包，不上传或安装。"""

import argparse
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

VERSION_RE = re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$')
COMMON = (
    '__init__.py', 'main.py', 'contracts.py', 'config.py', 'protocol.py', 'service.py',
    'fs.py', 'files.py', 'host.py', 'terminal.py', 'redaction.py', 'raw.py',
    'raw_tools.py', 'read_tools.py', 'account_tools.py',
)


def _root(root):
    return Path(root) if root is not None else Path(__file__).resolve().parent.parent


def _text(path):
    raw = Path(path).read_bytes()
    if raw.startswith(b'\xef\xbb\xbf'):
        raise ValueError(f'{path} must not contain a BOM')
    return raw.decode('utf-8')


def _skill_version(root):
    lines = _text(root / 'skills' / 'olivos-cockpit' / 'SKILL.md').splitlines()
    if not lines or lines[0].strip() != '---':
        raise ValueError('SKILL.md must start with front matter')
    try:
        end = next(index for index, line in enumerate(lines[1:], 1) if line.strip() == '---')
    except StopIteration:
        raise ValueError('SKILL.md front matter is not terminated') from None
    version = None
    in_metadata = False
    for line in lines[1:end]:
        if line.rstrip() == 'metadata:':
            in_metadata = True
        elif in_metadata and line[:1] in (' ', '\t'):
            key, separator, value = line.strip().partition(':')
            if separator and key == 'version':
                version = value.strip()
        elif in_metadata:
            in_metadata = False
    if not version:
        raise ValueError('SKILL.md metadata.version is missing')
    return version


def _contracts_version(root):
    match = re.search(r"^VERSION\s*=\s*['\"]([^'\"]+)['\"]\s*$",
                      _text(root / 'OlivOSCockpit' / 'contracts.py'), re.MULTILINE)
    if match is None:
        raise ValueError('contracts.VERSION is missing')
    return match.group(1)


def release_version(root=None):
    root = _root(root)
    manifest = json.loads(_text(root / 'OlivOSCockpit' / 'app.json'))
    versions = {
        'OlivOSCockpit/app.json': manifest.get('version') if type(manifest) is dict else None,
        'OlivOSCockpit/contracts.py': _contracts_version(root),
        'skills/olivos-cockpit/SKILL.md': _skill_version(root),
    }
    for source, version in versions.items():
        if type(version) is not str or VERSION_RE.fullmatch(version) is None:
            raise ValueError(f'{source} has an invalid release version')
    if len(set(versions.values())) != 1:
        raise ValueError('Release versions do not match')
    return next(iter(versions.values()))


def _write_archive(destination, files):
    destination = Path(destination)
    fd, temporary = tempfile.mkstemp(prefix='.' + destination.name, suffix='.tmp', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for filename, content in sorted(files.items()):
                    item = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
                    item.compress_type = zipfile.ZIP_DEFLATED
                    item.external_attr = 0o100644 << 16
                    archive.writestr(item, content)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build(output, root=None):
    root = _root(root)
    version = release_version(root)
    source = root / 'OlivOSCockpit'
    output = Path(output)
    manifest = json.loads(_text(source / 'app.json'))
    if manifest['namespace'] != 'OlivOSCockpit':
        raise ValueError('Unexpected namespace')
    common = {name: (source / name).read_bytes() for name in COMMON}
    output.mkdir(parents=True, exist_ok=True)
    paths = []
    for lite in (False, True):
        name = 'OlivOSCockpitLite' if lite else 'OlivOSCockpit'
        app = dict(manifest)
        if lite:
            app['name'] = 'OlivOS Cockpit Lite'
            app['info'] = ('OlivOS MCP 调试插件 Lite：真实数据只读，另有内存虚拟终端输入；'
                           '不包含 Full-only 工具实现。')
        files = dict(common)
        files['LICENSE'] = (root / 'LICENSE').read_bytes()
        files['app.json'] = (json.dumps(app, ensure_ascii=False, indent=4) + '\n').encode('utf-8')
        files['registry.py'] = (
            (root / 'profiles' / 'lite_registry.py') if lite else (source / 'registry.py')
        ).read_bytes()
        if not lite:
            files['full_only.py'] = (source / 'full_only.py').read_bytes()
            files['adapter_tools.py'] = (source / 'adapter_tools.py').read_bytes()
            for module in ('intercept.py', 'file_write.py', 'account_write.py'):
                files[module] = (source / module).read_bytes()
        destination = output / f'{name}-{version}.opk'
        _write_archive(destination, files)
        paths.append(destination)
    return paths


def build_skill(output, root=None):
    root = _root(root)
    version = release_version(root)
    source = root / 'skills' / 'olivos-cockpit'
    references = sorted((source / 'references').glob('*.md'))
    if not references:
        raise ValueError('Skill references are missing')
    files = {
        'olivos-cockpit/SKILL.md': (source / 'SKILL.md').read_bytes(),
        'olivos-cockpit/LICENSE': (root / 'LICENSE').read_bytes(),
    }
    for path in references:
        files['olivos-cockpit/references/' + path.name] = path.read_bytes()
    for name, content in files.items():
        if content.startswith(b'\xef\xbb\xbf'):
            raise ValueError(f'{name} must not contain a BOM')
        content.decode('utf-8')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f'olivos-cockpit-skill-{version}.zip'
    _write_archive(destination, files)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent.parent / 'dist')
    options = parser.parse_args()
    paths = build(options.output)
    paths.append(build_skill(options.output))
    for path in paths:
        print(path)


if __name__ == '__main__':
    main()
