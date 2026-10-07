"""Coordinator-only seed for the native Git-file treatment (REQ-007).

No task dispatch, tracker API, filesystem writes, or builder memory service.
The caller owns preparation, initial commit, and reviewed input identities.
"""
import hashlib
import json
import re
import unicodedata


TRACKER_PATH = '.factory/project/task-state.md'


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate package manifest key')
        result[key] = value
    return result


def _single_line(value, label):
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or len(value) > 512
            or any(unicodedata.category(character).startswith('C')
                   or character in '\u2028\u2029' for character in value)):
        raise ValueError(f'Ordinary bounded single-line {label} required')
    return value


def render_git_seed(package_bytes, expected_sha256):
    """Return todo Markdown from the exact reviewed package manifest bytes.

    This hash check is input binding, not human approval or protocol freeze.
    Additional disclosed package metadata is retained in /spec, not duplicated
    into the mutable tracker. Never execute manifest content.
    """
    if (not isinstance(package_bytes, bytes) or len(package_bytes) > 1024 * 1024
            or not isinstance(expected_sha256, str)
            or not re.fullmatch('[0-9a-f]{64}', expected_sha256)
            or hashlib.sha256(package_bytes).hexdigest() != expected_sha256):
        raise ValueError('Exact bounded reviewed package bytes required')
    manifest = json.loads(package_bytes, object_pairs_hook=_unique_pairs)
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1):
        raise ValueError('Package manifest schema 1 required')
    version = _single_line(manifest.get('specification_version'), 'specification version')
    packages = manifest.get('packages')
    if not isinstance(packages, list) or not 1 <= len(packages) <= 1000:
        raise ValueError('Nonempty bounded frozen package list required')
    sections = ['# Task state', 'Schema: 1', f'Specification: {version}']
    identifiers = set()
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError('Package object required')
        identifier = package.get('id')
        if (not isinstance(identifier, str) or not re.fullmatch('WP-[0-9]{3,6}', identifier)
                or identifier in identifiers):
            raise ValueError('Unique frozen work-package ID required')
        title = _single_line(package.get('title'), 'package title')
        identifiers.add(identifier)
        sections.extend(['', f'## {identifier} — {title}', 'Status: todo', 'Progress:', 'Next:'])
    return ('\n'.join(sections) + '\n').encode('utf-8')
