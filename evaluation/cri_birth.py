"""Bounded recursive Linux CRI discovery; missed births remain incomplete."""
import ctypes
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
import uuid

from .cri_follower import (MASK, CREATE, DELETE, MOVED_FROM, MOVED_TO, DELETE_SELF,
                           MOVE_SELF, UNMOUNT, OVERFLOW, IGNORED, _HEADER)
from .cri_staging import PrivateCRIStaging, provisional_entry, _key
from .evidence import positive
from .log_retention import _file_identity


MAX_DIRECTORIES = 512
MAX_ENTRIES = 512
MAX_EVENTS = 4096
_FILE = re.compile(r'(0|[1-9][0-9]{0,6})\.log')
_ROTATION = re.compile(r'(0|[1-9][0-9]{0,6})\.log\..+')


class LinuxCRIBirthWatch:
    """Arm directories before scans and stage node files independently of CID.

    Trusted root is the original node's /var/log/pods, privately operator-mounted
    and never builder-selected. check(reserve) verifies original Namespace UID,
    node/runtime/owner and both clocks. Only exact namespace Pod directories,
    canonical UUID Pod UIDs, declared-name grammar and numeric restart files are
    considered. Other namespaces are not traversed. New matching directories are
    opened O_NOFOLLOW and watched before scanning their entries. Staging borrows
    held directory FDs, so ancestor replacement cannot redirect file opens.

    This is polling-based inotify, not a guarantee of catching arbitrarily short
    lived files: descendants can appear and vanish before their new parent watch
    is armed without any observable file event. Created/moved paths gone before
    opening, directory
    deletion/move, queue overflow, unreadable paths, unexpected names or bounds
    permanently invalidate discovery. No relist/reset. Captured bound positives
    survive; unbound bytes are discarded on failure. Watchers and followers close
    together. Existing files are counted separately as startup observations, not
    bootstrap coverage or a proven empty deployment fence.

    Caller supplies independent API/runtime/file binding to staging.bind. This
    never assigns a CID, scans unbound bytes or proves a namespace history. Run
    inside an owned bounded child for blocking filesystem/callback termination.
    At most 512 directories/entries per scan,4096 events/polls plus staging caps.
    Every receipt says history_complete=False; absence cannot authorize a pass.
    """
    def __init__(self, staging, root, *, node_uid, check, deadline):
        positive(deadline, 'Private CRI discovery deadline')
        if (not sys.platform.startswith('linux') or type(staging) is not PrivateCRIStaging
                or not callable(check) or deadline > staging._deadline):
            raise ValueError('Private Linux CRI discovery inputs required')
        staging._owned(); _file_identity(dict(node_uid=node_uid, device=0, inode=1))
        self._staging, self._root, self._node, self._check, self._deadline = staging, Path(root), node_uid, check, deadline
        self._namespace = staging._retention._binding['name']
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._notify_fd, self._directories, self._used_dirs, self._files = None, {}, set(), set()
        self._polls, self._events_seen, self._startup_files = 0, 0, 0
        self._initial, self._valid, self._closed, self._gap, self._cleanup_ok = True, True, False, False, True
        try:
            self._verify()
            self._libc = ctypes.CDLL(None, use_errno=True)
            self._libc.inotify_init1.argtypes = [ctypes.c_int]; self._libc.inotify_init1.restype = ctypes.c_int
            self._libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            self._libc.inotify_add_watch.restype = ctypes.c_int
            self._notify_fd = self._libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            if self._notify_fd < 0:
                self._notify_fd = None
                raise ValueError('Private CRI discovery notification unavailable')
            root_fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._register(root_fd, 0, {})
            self._initial = False
            self._verify()
        except BaseException as error:
            self._gap = True; self._cleanup()
            if not isinstance(error, Exception): raise
            raise ValueError('Private CRI discovery unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private CRI discovery owner unavailable')

    def _verify(self):
        if (not self._valid or self._closed or not self._staging.summary()['valid']
                or time.monotonic()+5 >= self._deadline or self._check(5) is not True):
            raise ValueError('Private CRI discovery lifetime unavailable')

    def _register(self, descriptor, level, entry):
        registered = False
        try:
            self._verify()
            observed = os.fstat(descriptor); identity = (observed.st_dev, observed.st_ino)
            if (not stat.S_ISDIR(observed.st_mode) or identity in self._used_dirs
                    or len(self._directories) >= MAX_DIRECTORIES):
                raise ValueError('Private CRI directory identity unavailable')
            watch = self._libc.inotify_add_watch(self._notify_fd,
                         ('/proc/self/fd/'+str(descriptor)).encode(), MASK)
            if watch < 0 or watch in self._directories:
                raise ValueError('Private CRI directory watch unavailable')
            state = dict(fd=descriptor, level=level, entry=entry, children={})
            self._directories[watch] = state; self._used_dirs.add(identity); registered = True
            self._scan(state)
            return state
        finally:
            if not registered: os.close(descriptor)

    def _pod(self, name):
        if not name.startswith(self._namespace+'_'): return None
        parts = name.split('_')
        if len(parts) != 3 or parts[0] != self._namespace or str(uuid.UUID(parts[2])) != parts[2]:
            raise ValueError('Private CRI Pod directory unavailable')
        return provisional_entry(dict(namespace=self._namespace,pod_name=parts[1],pod_uid=parts[2],
                                      container_name='validation',restart_index=0))

    def _discover(self, state, name):
        self._verify()
        if not name or '/' in name or '\x00' in name:
            raise ValueError('Private CRI entry scope unavailable')
        level, entry = state['level'], state['entry']
        if level == 0:
            child_entry = self._pod(name)
            if child_entry is None: return
        elif level == 1:
            child_entry = provisional_entry(dict(entry,container_name=name))
        else:
            match = _FILE.fullmatch(name)
            if match is None:
                rotation = _ROTATION.fullmatch(name)
                if rotation and _key(dict(entry,restart_index=int(rotation[1]))) in self._files:
                    return
                raise ValueError('Private CRI file generation unavailable')
            child_entry = provisional_entry(dict(entry,restart_index=int(match[1])))
            key = _key(child_entry)
            if key not in self._files:
                self._staging.stage(child_entry,state['fd'],node_uid=self._node,
                                    check=lambda value,reserve:self._file_check(value,reserve))
                self._files.add(key)
                if self._initial: self._startup_files += 1
            return
        if name in state['children']:
            observed = os.stat(name,dir_fd=state['fd'],follow_symlinks=False)
            prior = os.fstat(state['children'][name]['fd'])
            if not stat.S_ISDIR(observed.st_mode) or (observed.st_dev,observed.st_ino) != (prior.st_dev,prior.st_ino):
                raise ValueError('Private CRI directory replacement unavailable')
            return
        descriptor = os.open(name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=state['fd'])
        state['children'][name] = self._register(descriptor,level+1,child_entry)

    def _file_check(self, entry, reserve):
        self._verify()
        return entry['namespace'] == self._namespace and time.monotonic()+reserve < self._deadline

    def _scan(self, state):
        with os.scandir(state['fd']) as entries:
            for count, entry in enumerate(entries,1):
                if count > MAX_ENTRIES: raise ValueError('Private CRI directory entry bound')
                self._discover(state,entry.name)

    def _events(self):
        events = []
        while True:
            try: raw = os.read(self._notify_fd,65536)
            except BlockingIOError: return events
            if not raw: raise ValueError('Private CRI discovery notification unavailable')
            offset = 0
            while offset < len(raw):
                if len(raw)-offset < _HEADER.size: raise ValueError('Private CRI discovery event framing unavailable')
                watch, mask, cookie, size = _HEADER.unpack_from(raw,offset); offset += _HEADER.size
                if size > 4096 or size > len(raw)-offset:
                    raise ValueError('Private CRI discovery event framing unavailable')
                name = raw[offset:offset+size].split(b'\x00',1)[0].decode('ascii'); offset += size
                if mask & (OVERFLOW | IGNORED | UNMOUNT | DELETE_SELF | MOVE_SELF) or watch not in self._directories:
                    raise ValueError('Private CRI discovery continuity unavailable')
                if not name or '/' in name: raise ValueError('Private CRI discovery event scope unavailable')
                events.append((self._directories[watch],mask,name))
                if len(events) > MAX_EVENTS: raise ValueError('Private CRI discovery event bound')

    def poll(self):
        self._owned()
        with self._lock:
            try:
                self._verify()
                if self._polls >= 4096: raise ValueError('Private CRI discovery poll bound')
                self._polls += 1; count = 0
                while True:
                    events = self._events()
                    if not events: break
                    count += len(events)
                    if count > MAX_EVENTS: raise ValueError('Private CRI discovery event bound')
                    self._events_seen += len(events)
                    for state, mask, name in events:
                        self._verify()
                        if state['level'] == 0 and not name.startswith(self._namespace+'_'): continue
                        if mask & (CREATE | MOVED_TO): self._discover(state,name)
                        if mask & (DELETE | MOVED_FROM):
                            # File unlink/rotation remains the held follower's job.
                            # Directory removal cannot establish writer closure.
                            if state['level'] < 2:
                                raise ValueError('Private CRI discovered directory disappeared')
                            if _FILE.fullmatch(name):
                                entry = dict(state['entry'],restart_index=int(_FILE.fullmatch(name)[1]))
                                if _key(entry) not in self._files:
                                    raise ValueError('Private CRI file birth missed')
                self._staging.poll(); self._verify()
                return self.summary()
            except BaseException as error:
                self._gap = True; self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI discovery unavailable') from None

    def _cleanup(self):
        self._valid, self._closed = False, True
        descriptors = [state['fd'] for state in self._directories.values()]
        if self._notify_fd is not None: descriptors.append(self._notify_fd)
        self._notify_fd = None
        for descriptor in descriptors:
            try: os.close(descriptor)
            except OSError: self._cleanup_ok = False
        self._directories.clear()
        try: self._cleanup_ok &= self._staging.close()['descriptors_closed']
        except Exception: self._cleanup_ok = False

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_birth_discovery',files_seen=len(self._files),
                        directories_seen=len(self._used_dirs),startup_files=self._startup_files,
                        observed_events=self._events_seen,polls=self._polls,discovery_gap=self._gap,
                        valid=self._valid and not self._closed and self._staging.summary()['valid'],
                        descriptors_closed=self._closed and self._cleanup_ok,
                        birth_coverage_verified=False,history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._cleanup()
            return self.summary()
