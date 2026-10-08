"""Check independently selected captured files in an owned writable app mount."""
import copy
import hashlib
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .verdicts import Inconclusive


def open_directory(path):
    """Hold every parent while opening its child; refuse all symlink ancestors."""
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


class SourceBinding:
    """Read-only selected-file proof, not an exhaustive source or image attestation.

    Expected file records must come from independent captured inventory, never
    live application output. Review which files are immutable and which generated
    fixture/artifact paths may change. Unselected paths are outside this check.
    The outer owner must interrupt hanging filesystem I/O and callbacks.
    """
    def __init__(self, project, expected, *, lifetime_check, lifetime_scope=None, max_bytes=64*1024**2,
                 max_files=4096):
        if (not callable(lifetime_check) or (lifetime_scope is not None and not callable(lifetime_scope))
                or type(max_bytes) is not int or max_bytes <= 0
                or type(max_files) is not int or max_files <= 0
                or not isinstance(expected, dict) or not expected or len(expected) > max_files):
            raise ValueError('Bounded independent source selection required')
        total = 0
        for name, record in expected.items():
            if (not isinstance(name, str) or not name or '\\' in name
                    or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                    or str(PurePosixPath(name)) != name or name == '.'
                    or any(ord(character) < 32 for character in name)):
                raise ValueError('Canonical relative source path required')
            if (not isinstance(record, dict) or not set(record) <= {'kind', 'sha256', 'size', 'executable'}
                    or not {'sha256', 'size', 'executable'} <= set(record)
                    or record.get('kind', 'file') != 'file'
                    or not isinstance(record['sha256'], str)
                    or not re.fullmatch('[0-9a-f]{64}', record['sha256'])
                    or type(record['size']) is not int or record['size'] < 0
                    or type(record['executable']) is not bool):
                raise ValueError('Captured ordinary file record required')
            total += record['size']
            if total > max_bytes:
                raise ValueError('Selected source exceeds byte bound')
        self.project = Path(os.path.abspath(project))
        self.expected = copy.deepcopy(expected)
        self.lifetime_check = lifetime_check
        self.lifetime_scope = lifetime_scope
        self.owner = os.getpid()
        self.live(0)
        descriptor = open_directory(self.project)
        try:
            metadata = os.fstat(descriptor)
            self.root_identity = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)
        self.check()

    def live(self, reserve):
        if os.getpid() != self.owner or self.lifetime_check(reserve) is not True:
            raise Inconclusive('Selected source lifetime unavailable')

    def check(self, reserve=0):
        """Return exact True only for stable selected bytes on the original root."""
        if type(reserve) not in (int, float) or not math.isfinite(reserve) or reserve < 0:
            raise ValueError('Finite nonnegative source reserve required')
        if self.lifetime_scope is None:
            return self._read(reserve, self.live)
        self.live(reserve)
        with self.lifetime_scope(reserve) as check:
            if not callable(check):
                raise ValueError('Scoped lifetime check required')

            def live(amount):
                if os.getpid() != self.owner or check(amount) is not True:
                    raise Inconclusive('Selected source scoped lifetime unavailable')

            result = self._read(reserve, live)
        self.live(reserve)
        return result

    def _read(self, reserve, live):
        live(reserve)
        root = None
        try:
            root = open_directory(self.project)
            metadata = os.fstat(root)
            if (metadata.st_dev, metadata.st_ino) != self.root_identity:
                raise Inconclusive('Selected source mount identity changed')
            for name, expected in self.expected.items():
                live(reserve)
                parent = os.dup(root)
                descriptor = None
                try:
                    parts = PurePosixPath(name).parts
                    for component in parts[:-1]:
                        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=parent)
                        os.close(parent)
                        parent = child
                    descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=parent)
                    before = os.fstat(descriptor)
                    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                            or before.st_size != expected['size']
                            or bool(before.st_mode & 0o111) != expected['executable']):
                        raise Inconclusive('Selected source metadata changed')
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        live(reserve)
                        chunk = os.read(descriptor, min(65536, expected['size']-size+1))
                        live(reserve)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > expected['size']:
                            raise Inconclusive('Selected source grew during inspection')
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                    current_parent = os.dup(root)
                    try:
                        for component in parts[:-1]:
                            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                            dir_fd=current_parent)
                            os.close(current_parent)
                            current_parent = child
                        current = os.stat(parts[-1], dir_fd=current_parent, follow_symlinks=False)
                    finally:
                        os.close(current_parent)
                    if (file_identity(before) != file_identity(after)
                            or file_identity(after) != file_identity(current)
                            or size != expected['size'] or digest.hexdigest() != expected['sha256']):
                        raise Inconclusive('Selected source content or identity changed')
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    os.close(parent)
            # Reopen the named root so renaming it during a held-FD read cannot pass.
            current_root = open_directory(self.project)
            try:
                metadata = os.fstat(current_root)
                if (metadata.st_dev, metadata.st_ino) != self.root_identity:
                    raise Inconclusive('Selected source mount identity changed')
            finally:
                os.close(current_root)
            live(reserve)
            return True
        except OSError:
            raise Inconclusive('Selected source path unavailable') from None
        finally:
            if root is not None:
                os.close(root)
