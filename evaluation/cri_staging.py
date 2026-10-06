"""Private pre-CID CRI staging; attribution requires an independent late binding."""
import copy
from collections import deque
import os
import threading
import time

from .cri_follower import LinuxCRIFollower
from .evidence import positive
from .log_retention import PrivateCRIRetention, MAX_SOURCES, MAX_FILES, MAX_OPERATIONS, _file_identity
from .log_transport import source_binding


def provisional_entry(value):
    fields = {'namespace', 'pod_name', 'pod_uid', 'container_name', 'restart_index'}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value['restart_index']) is not int or not 0 <= value['restart_index'] <= 9999999):
        raise ValueError('Private provisional CRI entry required')
    # Reuse name/UID grammar without assigning any provisional container ID.
    source_binding({key: value[key] for key in fields - {'restart_index'}} |
                   dict(container_id='validation', previous=False))
    return copy.deepcopy(value)


def _key(entry):
    return tuple(entry[field] for field in
                 ('namespace', 'pod_name', 'pod_uid', 'container_name', 'restart_index'))


class _ProvisionalFollower(LinuxCRIFollower):
    _source_binding = staticmethod(provisional_entry)


class _Slot:
    """Private follower sink; never exposes bytes or provisional canary results."""
    def __init__(self, manager, entry, node_uid):
        self.manager, self.entry, self.node_uid = manager, entry, node_uid
        self.files, self.source, self.check = [], None, None

    def _verify(self, entry):
        self.manager._verify()
        if entry != self.entry:
            raise ValueError('Private provisional CRI scope unavailable')
        if self.source is not None:
            self.manager._binding_check(self, self.source, self.check)

    def open(self, entry, identity):
        self._verify(entry)
        if self.files:
            raise ValueError('Private provisional CRI duplicate file')
        self._new_file(identity)

    def _new_file(self, identity):
        manager = self.manager
        manager._operation()
        file_key = _file_identity(identity)
        if (file_key[0] != self.node_uid or file_key in manager._used_files
                or file_key in manager._retention._used_files
                or len(manager._used_files) >= MAX_FILES):
            raise ValueError('Private provisional CRI file identity unavailable')
        manager._used_files.add(file_key)
        self.files.append(dict(identity=copy.deepcopy(identity), data=deque(), size=0))

    def append(self, entry, identity, offset, data):
        self._verify(entry); self.manager._operation()
        active = self.files[-1]
        if (identity != active['identity'] or type(offset) is not int or offset != active['size']
                or not isinstance(data, bytes) or not 1 <= len(data) <= 65536
                or self.manager._staged_bytes + self.manager._retention._bytes + len(data)
                > self.manager._retention._max_bytes):
            raise ValueError('Private provisional CRI offset or byte bound')
        if self.source is None:
            active['data'].append(data); self.manager._staged_bytes += len(data)
        else:
            self.manager._retention.append(self.source, identity, offset, data)
        active['size'] += len(data)

    def rotate(self, entry, old, new, *, final_size):
        self._verify(entry)
        active = self.files[-1]
        if (old != active['identity'] or type(final_size) is not int or final_size != active['size']
                or _file_identity(old)[:2] != _file_identity(new)[:2]
                or self.source is None and active['data'] and active['data'][-1][-1] != 10):
            raise ValueError('Private provisional CRI rotation unavailable')
        self._new_file(new)
        if self.source is not None:
            self.manager._retention.rotate(self.source, old, new, final_size=final_size)

    def abandon(self):
        self.manager._valid = False
        self.manager._retention.abandon()


class PrivateCRIStaging:
    """Follow existing provisional files before observing their immutable CID.

    Trusted node birth discovery supplies independently scoped filesystem entries
    and paths, never builder-selected paths. stage() takes namespace/Pod name/UID,
    container name and numeric restart index; it deliberately requires no CID.
    check(reserve) binds the original namespace, node, owner and both clocks.
    Per-file check(entry, reserve) verifies the scoped node/filesystem lifetime.
    poll follows held Linux descriptors across append/rotation/unlink.

    pending() is private binding input: entries, node UID and collected file IDs,
    never raw bytes. bind(entry, source, check=...) requires the exact immutable
    API identity at that restart index and independent node/runtime/file proof
    through check(proof, reserve). It replays captured generations into retention
    and keeps collecting directly under that binding. Unbound bytes cannot be
    scanned or used as application evidence. Failure closes all followers and
    invalidates retention, retaining prior bound positives.

    Use a dedicated retention exclusively with this manager. Aggregate staged
    plus retained bytes share its cap; 128 entries/512 files/65536 sink operations
    and 4096 polls bound state. Run inside an owned bounded child to terminate
    blocked callbacks/filesystem operations. No raw bytes leave original-process
    memory. close releases staged references, not secure-erasure evidence.

    This does not discover births recursively or recover older rotations, prove
    pre-deployment bootstrap coverage, establish API/time/writer fences, or survive
    owner death. Every receipt says history_complete=False; absence cannot pass.
    """
    def __init__(self, retention, *, check, deadline):
        positive(deadline, 'Private CRI staging deadline')
        if type(retention) is not PrivateCRIRetention or not callable(check):
            raise ValueError('Private CRI staging inputs required')
        retention._owned()
        if retention._sources or not retention._valid or retention._closed:
            raise ValueError('Dedicated private CRI retention required')
        self._retention, self._check, self._deadline = retention, check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._slots, self._followers, self._used_files, self._used_sources = {}, {}, set(), set()
        self._staged_bytes, self._operations, self._polls = 0, 0, 0
        self._valid, self._closed, self._cleanup_ok = True, False, True

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private CRI staging owner unavailable')

    def _verify(self):
        if (not self._valid or self._closed or not self._retention._valid or self._retention._closed
                or time.monotonic()+5 >= self._deadline or self._check(5) is not True):
            raise ValueError('Private CRI staging lifetime unavailable')

    def _operation(self):
        if self._operations >= MAX_OPERATIONS:
            raise ValueError('Private CRI staging operation bound')
        self._operations += 1

    def _proof(self, slot, source):
        return dict(entry=copy.deepcopy(slot.entry), source=copy.deepcopy(source), node_uid=slot.node_uid,
                    files=[copy.deepcopy(value['identity']) for value in slot.files])

    def _binding_check(self, slot, source, check):
        self._verify()
        if check(self._proof(slot, source), 5) is not True:
            raise ValueError('Private provisional CRI binding unavailable')
        self._verify()

    def _cleanup(self):
        self._valid, self._closed = False, True
        for follower in self._followers.values():
            try: self._cleanup_ok &= follower.close()['descriptors_closed']
            except Exception: self._cleanup_ok = False
        self._retention.abandon()
        for slot in self._slots.values():
            for value in slot.files: value['data'].clear()
        self._staged_bytes = 0

    def stage(self, entry, directory, *, node_uid, check):
        self._owned()
        with self._lock:
            try:
                self._verify(); entry = provisional_entry(entry)
                key = _key(entry)
                if (entry['namespace'] != self._retention._binding['name'] or key in self._slots
                        or len(self._slots) >= MAX_SOURCES or not callable(check)):
                    raise ValueError('Private provisional CRI entry unavailable')
                _file_identity(dict(node_uid=node_uid, device=0, inode=1))
                slot = _Slot(self, entry, node_uid); self._slots[key] = slot
                self._followers[key] = _ProvisionalFollower(slot, entry, directory,
                    str(entry['restart_index'])+'.log', node_uid=node_uid,
                    check=check, deadline=self._deadline)
                self._followers[key].poll()
                self._verify()
                return self.summary()
            except BaseException as error:
                self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI staging unavailable') from None

    def pending(self):
        """Copied private binding inputs, never public evidence or raw bytes."""
        self._owned()
        with self._lock:
            if not self._valid or self._closed:
                raise ValueError('Private CRI staging unavailable')
            return [dict(entry=copy.deepcopy(slot.entry), node_uid=slot.node_uid,
                         files=[copy.deepcopy(value['identity']) for value in slot.files])
                    for slot in self._slots.values() if slot.source is None]

    def bind(self, entry, source, *, check):
        self._owned()
        with self._lock:
            try:
                self._verify(); entry, source = provisional_entry(entry), source_binding(source)
                slot = self._slots.get(_key(entry))
                key = tuple(source[field] for field in
                            ('namespace', 'pod_name', 'pod_uid', 'container_name', 'container_id'))
                if (slot is None or slot.source is not None or key in self._used_sources
                        or not callable(check)
                        or any(entry[field] != source[field] for field in entry if field != 'restart_index')):
                    raise ValueError('Private provisional CRI source unavailable')
                self._binding_check(slot, source, check)
                for index, value in enumerate(slot.files):
                    self._binding_check(slot, source, check)
                    if index == 0:
                        self._retention.open(source, value['identity'])
                    else:
                        previous = slot.files[index-1]
                        self._retention.rotate(source, previous['identity'], value['identity'], final_size=previous['size'])
                    offset = 0
                    while value['data']:
                        self._binding_check(slot, source, check)
                        data = value['data'][0]
                        self._retention.append(source, value['identity'], offset, data)
                        value['data'].popleft()
                        self._staged_bytes -= len(data); offset += len(data)
                self._binding_check(slot, source, check)
                slot.source, slot.check = source, check
                self._used_sources.add(key)
                for value in slot.files: value['data'].clear()
                return self.summary()
            except BaseException as error:
                self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI staging binding unavailable') from None

    def poll(self):
        self._owned()
        with self._lock:
            try:
                self._verify()
                if self._polls >= 4096: raise ValueError('Private CRI staging poll bound')
                self._polls += 1
                for key, follower in self._followers.items():
                    slot = self._slots[key]
                    if slot.source is not None: self._binding_check(slot, slot.source, slot.check)
                    follower.poll()
                    if slot.source is not None: self._binding_check(slot, slot.source, slot.check)
                self._verify()
                return self.summary()
            except BaseException as error:
                self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private CRI staging unavailable') from None

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_staging', entries=len(self._slots),
                        bound_sources=len(self._used_sources), unbound_sources=len(self._slots)-len(self._used_sources),
                        files=len(self._used_files), staged_bytes=self._staged_bytes, polls=self._polls,
                        valid=self._valid and not self._closed and self._retention._valid and not self._retention._closed,
                        descriptors_closed=self._closed and self._cleanup_ok, history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._cleanup()
            return self.summary()
