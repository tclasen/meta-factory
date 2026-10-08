"""Original Unix mode metadata, separate from private captured storage modes.

These operator records describe mode bits only, not ACLs, owners, timestamps or
extended attributes. Never infer original modes from private artifact storage.
"""
import hashlib
import json
import os
from pathlib import Path
import stat


def manifest_digest(inventory):
    return hashlib.sha256(json.dumps(dict(files=inventory['files'], bytes=inventory['bytes']),
                                     sort_keys=True).encode()).hexdigest()


def unix_mode(value):
    mode = stat.S_IMODE(value.st_mode)
    if mode > 0o777:
        raise ValueError('Special Unix mode bits require a separate capture profile')
    return mode


def mode_record(inventory, files, directories):
    return dict(version=1, capture_manifest_sha256=manifest_digest(inventory),
                files=dict(files), directories=dict(directories))


def validate_modes(source, inventory):
    """Validate complete operator metadata against the private captured tree."""
    record = inventory.get('unix_modes')
    if (not isinstance(record, dict)
            or set(record) != {'version', 'capture_manifest_sha256', 'files', 'directories'}
            or type(record['version']) is not int or record['version'] != 1
            or record['capture_manifest_sha256'] != manifest_digest(inventory)):
        raise ValueError('Original Unix mode metadata is missing or unbound')
    files, directories = record['files'], record['directories']
    expected_files = {name for name, entry in inventory['files'].items()
                      if entry.get('kind', 'file') == 'file'}
    root = Path(source)
    expected_directories = {'.'} | {str(p.relative_to(root)) for p in root.rglob('*')
                                  if not p.is_symlink() and p.is_dir()}
    if (not isinstance(files, dict) or set(files) != expected_files
            or not isinstance(directories, dict) or set(directories) != expected_directories
            or len(files) > 100000 or len(directories) > 100000):
        raise ValueError('Incomplete Unix mode scope')
    for mapping in (files, directories):
        for name, mode in mapping.items():
            path = Path(name)
            if (not isinstance(name, str) or not name or path.is_absolute()
                    or '..' in path.parts or str(path) != name
                    or type(mode) is not int or not 0 <= mode <= 0o777):
                raise ValueError('Unsupported Unix mode record')
    if any(bool(mode & 0o111) != inventory['files'][name]['executable']
           for name, mode in files.items()):
        raise ValueError('Original executable status differs from capture')
    return record


def restore_deployment_modes(project, inventory, *, captured_source):
    """Apply modes only to a new owned staging copy under a private parent.

    Caller verifies bytes/links and ownership of the exclusively created copy
    before invoking this function. It must never receive the retained artifact
    path. No source command, Git hook or application code runs here.
    """
    project = Path(project).resolve(strict=True)
    captured_source = Path(captured_source).resolve(strict=True)
    if (project == captured_source or project in captured_source.parents
            or captured_source in project.parents):
        raise ValueError('Deployment and retained capture must be disjoint')
    parent = project.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ValueError('Private owned deployment parent required')
    record = validate_modes(project, inventory)
    # No-follow file descriptors prevent applying permissions to symlink targets.
    for name, mode in record['files'].items():
        descriptor = os.open(project/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise ValueError('Owned regular deployment file required')
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    # Descendants first, root last, so restrictive original parent modes do not
    # obstruct construction. Captured storage remains private and untouched.
    for name, mode in sorted(record['directories'].items(),
                             key=lambda item: len(Path(item[0]).parts), reverse=True):
        descriptor = os.open(project/name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError('Owned deployment directory required')
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
