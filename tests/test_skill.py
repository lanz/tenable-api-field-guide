"""Structural checks: the skill loads on every platform, its examples are valid Python, the
pyTenable methods it recommends exist, and nothing internal has slipped in."""

import importlib
import inspect
import re
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'SKILL.md'
REFERENCES = sorted((ROOT / 'references').glob('*.md'))
DOCS = [SKILL, *REFERENCES, ROOT / 'README.md']


def read(path: Path) -> str:
    return path.read_text(encoding='utf-8').replace('\r\n', '\n')


def frontmatter() -> dict:
    match = re.match(r'^---\n(.*?)\n---\n', read(SKILL), re.S)
    assert match, 'SKILL.md must start with YAML frontmatter'
    return yaml.safe_load(match.group(1))


def test_frontmatter_meets_agent_skills_rules():
    meta = frontmatter()
    # Copilot, Cursor and Codex require a lowercase-hyphen name equal to the folder name,
    # at most 64 characters, and a description of at most 1024 characters.
    assert re.fullmatch(r'[a-z0-9-]{1,64}', meta['name'])
    assert meta['name'] == 'tenable-api-field-guide'
    assert 0 < len(meta['description']) <= 1024
    # Optional Agent Skills fields: `license`, and `metadata` as a map of strings.
    assert meta.get('license') == 'MIT'
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in meta.get('metadata', {}).items())


def test_every_referenced_file_exists():
    for ref in re.findall(r'`(references/[\w.-]+\.md)`', read(SKILL)):
        assert (ROOT / ref).is_file(), ref
    for path in REFERENCES:
        for ref in re.findall(r'`([\w-]+\.md)`', read(path)):
            assert (ROOT / 'references' / ref).is_file(), f'{path.name} links {ref}'


PYTHON_BLOCKS = [
    pytest.param(block, id=f'{path.name}#{i}')
    for path in [SKILL, *REFERENCES]
    for i, block in enumerate(re.findall(r'```python\n(.*?)```', read(path), re.S))
]


@pytest.mark.parametrize('code', PYTHON_BLOCKS)
def test_python_examples_compile(code):
    compile(textwrap.dedent(code), '<example>', 'exec')


INTERNAL = re.compile(
    r'(accessKey=[0-9a-f]{20,}|secretKey=[0-9a-f]{20,}'
    r'|\.eng\.tenable|tenablesecurity\.com|artifactory|netskope|atlassian\.net|slack\.com'
    r'|\bqa-(staging|milestone|develop)\b|\b(RDC|RA|AAP|AIP|TVM|VRB)-\d+\b)',
    re.I,
)


@pytest.mark.parametrize('path', DOCS, ids=[p.name for p in DOCS])
def test_no_secrets_or_internal_references(path):
    hit = INTERNAL.search(read(path))
    assert not hit, hit.group(0) if hit else ''


# pyTenable calls the skill tells people to make: (module, class, attribute chain).
PYTENABLE_CALLS = [
    ('tenable.io', 'TenableIO', 'exports.vulns'),
    ('tenable.io', 'TenableIO', 'exports.assets'),
    ('tenable.io', 'TenableIO', 'exports.assets_v2'),
    ('tenable.io', 'TenableIO', 'exports.compliance'),
    ('tenable.io', 'TenableIO', 'exports.was'),
    ('tenable.io', 'TenableIO', 'exports.status'),
    ('tenable.io', 'TenableIO', 'exports.cancel'),
    ('tenable.io', 'TenableIO', 'scans.list'),
    ('tenable.io', 'TenableIO', 'scans.results'),
    ('tenable.io', 'TenableIO', 'scans.details'),
    ('tenable.sc', 'TenableSC', 'analysis.vulns'),
    ('tenable.sc', 'TenableSC', 'hosts.search'),
    ('tenable.tenableone', 'TenableOne', 'attack_path.vectors.top_attack_paths_search'),
    ('tenable.nessus', 'Nessus', 'server.properties'),
    ('tenable.nessus', 'Nessus', 'scans.list'),
    ('tenable.nessus', 'Nessus', 'scans.export_scan'),
    ('tenable.nessus', 'Nessus', 'plugins.list'),
    ('tenable.nessus', 'Nessus', 'plugins.families'),
    ('tenable.nessus', 'Nessus', 'plugins.family_details'),
    ('tenable.nessus', 'Nessus', 'plugins.plugin_details'),
    ('tenable.nessus', 'Nessus', 'agents.list'),
    ('tenable.nessus', 'Nessus', 'agent_groups.list'),
]


def _endpoint_class(prop: property) -> type:
    """The endpoint class a pyTenable property returns, found from the names its getter uses."""
    module = importlib.import_module(prop.fget.__module__)
    for name in prop.fget.__code__.co_names:
        candidate = getattr(module, name, None)
        if isinstance(candidate, type):
            return candidate
    raise AssertionError(f'could not resolve the class behind {prop.fget.__qualname__}')


@pytest.mark.parametrize('module, cls, chain', PYTENABLE_CALLS, ids=[c[2] for c in PYTENABLE_CALLS])
def test_documented_pytenable_methods_exist(module, cls, chain):
    obj = getattr(pytest.importorskip(module), cls)
    for name in chain.split('.'):
        attr = inspect.getattr_static(obj, name)
        obj = _endpoint_class(attr) if isinstance(attr, property) else attr
    assert callable(obj), chain
