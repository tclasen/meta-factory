"""Linux node-local private CRI follower; not complete namespace history proof."""
import copy
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys
import threading
import time

from .evidence import positive
from .log_retention import _file_identity
from .log_transport import source_binding


MODIFY, ATTRIB, CLOSE_WRITE = 2, 4, 8
MOVED_FROM, MOVED_TO, CREATE, DELETE = 64, 128, 256, 512
DELETE_SELF, MOVE_SELF, UNMOUNT, OVERFLOW, IGNORED = 1024, 2048, 8192, 16384, 32768
MASK = MODIFY | ATTRIB | CLOSE_WRITE | MOVED_FROM | MOVED_TO | CREATE | DELETE | DELETE_SELF | MOVE_SELF | UNMOUNT
MAX_POLLS = 4096
MAX_EVENTS = 4096
MAX_ROTATIONS = 128
_HEADER = struct.Struct('iIII')


class LinuxCRIFollower:
    """Read one bound container's existing active file on a trusted Linux node.

    Caller independently binds directory/active name to the immutable container,
    node identity, API/namespace identity and original guard/deadlines. The CRI
    writer must be trusted and append-only, with ordinary rename/reopen rotation;
    the old writer's CLOSE_WRITE must be observed after its rename. Other writers
    and unseen rotations are not accepted. Run this inside an owned bounded child
    so the outer watchdog can terminate blocked filesystem/check operations.

    Inotify is armed before opening the active file. A held descriptor preserves
    access across rename/unlink. Before reading growth, rehash the entire captured
    prefix to refuse truncation/overwrite. Ordered rename cookies and old-writer
    close events permit rotation, never mtime sorting. Multiple overlapping
    rotations/queue overflow/late old-file writes or identity/lifetime failures
    permanently invalidate collection. Private retention keeps prior positives.

    This does not recursively discover Pods/containers, recover older rotations,
    prove namespace coverage, bind time/watch fences or survive owner death.
    Every receipt has history_complete=False. close() stops collection and
    abandons retention; known captured positives remain inspectable.
    """
    _source_binding = staticmethod(source_binding)

    def __init__(self, retention, source, directory, active_name, *, node_uid, check, deadline):
        if not sys.platform.startswith('linux'):
            raise ValueError('Private CRI follower requires Linux')
        if not isinstance(active_name, str) or not re.fullmatch(r'(?:0|[1-9][0-9]{0,6})\.log', active_name):
            raise ValueError('Bound private CRI active filename required')
        positive(deadline, 'CRI follower deadline')
        if not callable(check): raise ValueError('Private CRI lifetime check required')
        _file_identity(dict(node_uid=node_uid, device=0, inode=1))
        self._retention, self._source = retention, self._source_binding(source)
        self._directory, self._name = directory if type(directory) is int else Path(directory), active_name
        self._node, self._check, self._deadline = node_uid, check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._dir_fd = self._notify_fd = None
        self._current = self._pending = None
        self._retired = set()
        self._polls = self._rotations = self._bytes = 0
        self._failed = self._closed = self._unlinked = False
        self._cleanup_ok = True
        try:
            self._verify()
            if type(self._directory) is int:
                # A dup would share scandir's position with the discoverer.
                # Open '.' through the held directory for an independent offset.
                self._dir_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=self._directory)
                if not stat.S_ISDIR(os.fstat(self._dir_fd).st_mode):
                    raise ValueError('Private CRI directory required')
            else:
                self._dir_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.inotify_init1.argtypes = [ctypes.c_int]; libc.inotify_init1.restype = ctypes.c_int
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            libc.inotify_add_watch.restype = ctypes.c_int
            self._notify_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            if self._notify_fd < 0:
                self._notify_fd = None
                raise ValueError('Private CRI notification unavailable')
            self._watch = libc.inotify_add_watch(self._notify_fd, ('/proc/self/fd/'+str(self._dir_fd)).encode(), MASK)
            if self._watch < 0: raise ValueError('Private CRI notification unavailable')
            with os.scandir(self._dir_fd) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > 512 or entry.name.startswith(self._name+'.'):
                        raise ValueError('Private CRI older generations unavailable')
            self._current = self._open(self._name)
            self._retention.open(self._source, self._current['identity'])
            self._verify()
        except BaseException as error:
            self._cleanup()
            self._retention.abandon()
            if not isinstance(error, Exception): raise
            raise ValueError('Private CRI follower unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private CRI follower owner unavailable')

    def _verify(self):
        if (time.monotonic()+5 >= self._deadline
                or self._check(copy.deepcopy(self._source), 5) is not True):
            raise ValueError('Private CRI identity or lifetime unavailable')

    def _open(self, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self._dir_fd)
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode): raise ValueError('Private CRI regular file required')
            identity = dict(node_uid=self._node, device=observed.st_dev, inode=observed.st_ino)
            _file_identity(identity)
            return dict(fd=descriptor, identity=identity, offset=0, digest=hashlib.sha256())
        except BaseException:
            os.close(descriptor)
            raise

    def _events(self):
        result = []
        while True:
            try: raw = os.read(self._notify_fd, 65536)
            except BlockingIOError: return result
            if not raw: raise ValueError('Private CRI notification unavailable')
            offset = 0
            while offset < len(raw):
                if len(raw)-offset < _HEADER.size: raise ValueError('Private CRI event framing unavailable')
                watch, mask, cookie, size = _HEADER.unpack_from(raw, offset)
                offset += _HEADER.size
                if size > 4096 or size > len(raw)-offset: raise ValueError('Private CRI event framing unavailable')
                name = raw[offset:offset+size].split(b'\x00', 1)[0].decode('ascii')
                offset += size
                if mask & (OVERFLOW | IGNORED | UNMOUNT | DELETE_SELF | MOVE_SELF) or watch != self._watch:
                    raise ValueError('Private CRI notification continuity unavailable')
                if '/' in name or not name: raise ValueError('Private CRI event scope unavailable')
                result.append((mask, cookie, name))
                if len(result) > MAX_EVENTS: raise ValueError('Private CRI event bound')

    def _handle(self, events):
        for mask, cookie, name in events:
            if name == self._name:
                if mask & MOVED_FROM:
                    if not cookie or self._pending is not None or self._unlinked:
                        raise ValueError('Private CRI overlapping rotation')
                    self._pending = dict(cookie=cookie, name=None, closed=False, new=None)
                if mask & (CREATE | MOVED_TO):
                    if mask & MOVED_TO or self._pending is None or self._pending['name'] is None or self._pending['new'] is not None:
                        raise ValueError('Private CRI generation unavailable')
                    self._pending['new'] = self._open(self._name)
                if mask & DELETE:
                    if self._pending is not None: raise ValueError('Private CRI deletion ambiguity')
                    self._unlinked = True
            elif name.startswith(self._name+'.'):
                if self._pending is not None and cookie == self._pending['cookie'] and mask & MOVED_TO:
                    if self._pending['name'] is not None: raise ValueError('Private CRI rotation cookie unavailable')
                    self._pending['name'] = name
                elif self._pending is not None and name == self._pending['name']:
                    if mask & MODIFY: self._pending['closed'] = False
                    if mask & CLOSE_WRITE: self._pending['closed'] = True
                elif name in self._retired:
                    if mask & (MODIFY | CLOSE_WRITE | CREATE | MOVED_TO):
                        raise ValueError('Private CRI retired generation changed')
                elif not any(name == retired+'.gz' for retired in self._retired):
                    raise ValueError('Private CRI unobserved generation')

    def _same_active(self, state):
        observed = os.stat(self._name, dir_fd=self._dir_fd, follow_symlinks=False)
        return stat.S_ISREG(observed.st_mode) and (observed.st_dev, observed.st_ino) == (state['identity']['device'], state['identity']['inode'])

    def _read_current(self):
        state = self._current
        observed = os.fstat(state['fd'])
        if observed.st_size < state['offset']: raise ValueError('Private CRI truncation')
        digest, offset = hashlib.sha256(), 0
        while offset < state['offset']:
            self._verify()
            data = os.pread(state['fd'], min(65536, state['offset']-offset), offset)
            if not data: raise ValueError('Private CRI captured prefix unavailable')
            digest.update(data); offset += len(data)
        if digest.digest() != state['digest'].digest(): raise ValueError('Private CRI captured prefix changed')
        while state['offset'] < observed.st_size:
            self._verify()
            data = os.pread(state['fd'], min(65536, observed.st_size-state['offset']), state['offset'])
            if not data: raise ValueError('Private CRI read truncated')
            self._retention.append(self._source, state['identity'], state['offset'], data)
            state['digest'].update(data); state['offset'] += len(data); self._bytes += len(data)

    def poll(self):
        self._owned()
        with self._lock:
            try:
                if self._closed or self._failed or self._polls >= MAX_POLLS:
                    raise ValueError('Private CRI collection unavailable')
                self._verify(); self._polls += 1
                self._handle(self._events())
                if self._pending is None and not self._unlinked and not self._same_active(self._current):
                    raise ValueError('Private CRI active identity changed')
                self._read_current()
                if self._pending is not None and self._pending['closed'] and self._pending['new'] is not None:
                    # Drain events generated before opening the new descriptor;
                    # never feed a later inode as an earlier unseen generation.
                    self._handle(self._events())
                    if not self._pending['closed'] or not self._same_active(self._pending['new']):
                        raise ValueError('Private CRI rotation identity unavailable')
                    self._read_current()
                    final_size = os.fstat(self._current['fd']).st_size
                    if final_size != self._current['offset'] or self._rotations >= MAX_ROTATIONS:
                        raise ValueError('Private CRI rotation boundary unavailable')
                    self._retention.rotate(self._source, self._current['identity'], self._pending['new']['identity'], final_size=final_size)
                    os.close(self._current['fd'])
                    self._retired.add(self._pending['name'])
                    self._current = self._pending['new']; self._pending = None
                    self._rotations += 1
                    self._read_current()
                self._verify()
                return dict(outcome='private_cri_polled', polls=self._polls,
                            rotations=self._rotations, bytes_collected=self._bytes,
                            history_complete=False)
            except BaseException as error:
                self._failed = True
                self._retention.abandon()
                self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI collection unavailable') from None

    def _cleanup(self):
        descriptors = [self._dir_fd, self._notify_fd]
        if self._current is not None: descriptors.append(self._current['fd'])
        if self._pending is not None and self._pending['new'] is not None: descriptors.append(self._pending['new']['fd'])
        self._dir_fd = self._notify_fd = self._current = self._pending = None
        closed = True
        for descriptor in set(value for value in descriptors if value is not None):
            try: os.close(descriptor)
            except OSError: closed = False
        self._closed = True
        self._cleanup_ok &= closed
        return self._cleanup_ok

    def close(self):
        self._owned()
        with self._lock:
            self._retention.abandon()
            return dict(outcome='private_cri_follower_closed', descriptors_closed=self._cleanup(),
                        polls=self._polls, rotations=self._rotations,
                        bytes_collected=self._bytes, history_complete=False)


class LinuxCRIDescriptorFollower(LinuxCRIFollower):
    """Follow one borrowed, independently attributed read-only regular file FD.

    A trusted node notification receiver supplies the FD and verifies its peer,
    mount, namespace, node, event/path and generation identity before calling.
    The caller retains ownership; this follower duplicates it with CLOEXEC and
    uses pread, leaving the caller's offset untouched. Already unlinked files
    are allowed. Existing prefix verification, private byte limits and guarded
    lifetime checks apply. There is no path lookup, directory watch, rotation
    discovery, writer-close proof or completeness claim. New generations need
    separate trusted event accounting. Run in an owned bounded child to contain
    blocked filesystem operations. Closing invalidates retention as usual.
    """
    def __init__(self, retention, source, descriptor, *, node_uid, check, deadline):
        if not sys.platform.startswith('linux'):
            raise ValueError('Private CRI descriptor requires Linux')
        import fcntl
        positive(deadline, 'CRI descriptor deadline')
        if type(descriptor) is not int or descriptor < 0 or not callable(check):
            raise ValueError('Private CRI descriptor inputs required')
        _file_identity(dict(node_uid=node_uid, device=0, inode=1))
        self._retention, self._source = retention, self._source_binding(source)
        self._node, self._check, self._deadline = node_uid, check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._dir_fd = self._notify_fd = self._current = self._pending = None
        self._polls = self._rotations = self._bytes = 0
        self._failed = self._closed = False
        self._cleanup_ok = True
        owned = None
        try:
            self._verify()
            owned = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 0)
            flags = fcntl.fcntl(owned, fcntl.F_GETFL)
            observed = os.fstat(owned)
            if (not stat.S_ISREG(observed.st_mode) or flags & os.O_ACCMODE != os.O_RDONLY
                    or flags & getattr(os, 'O_PATH', 0)):
                raise ValueError('Private read-only regular CRI descriptor required')
            identity = dict(node_uid=node_uid, device=observed.st_dev, inode=observed.st_ino)
            _file_identity(identity)
            self._current = dict(fd=owned, identity=identity, offset=0, digest=hashlib.sha256())
            owned = None
            self._retention.open(self._source, identity)
            self._verify()
        except BaseException as error:
            if owned is not None: os.close(owned)
            self._cleanup(); self._retention.abandon()
            if not isinstance(error, Exception): raise
            raise ValueError('Private CRI descriptor unavailable') from None

    def poll(self):
        self._owned()
        with self._lock:
            try:
                if self._closed or self._failed or self._polls >= MAX_POLLS:
                    raise ValueError('Private CRI descriptor unavailable')
                self._verify(); self._polls += 1
                self._read_current()
                self._verify()
                return dict(outcome='private_cri_descriptor_polled', polls=self._polls,
                            bytes_collected=self._bytes, history_complete=False)
            except BaseException as error:
                self._failed = True
                self._retention.abandon(); self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI descriptor collection unavailable') from None
