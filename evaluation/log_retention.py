"""Bounded parent-memory CRI retention; never a full-history/pass attestation."""
import copy
import os
import threading

from .cri_log import decode_cri_prefix
from .log_transport import source_binding
from .secret_scan import DEFAULT_BYTES, scan_secret_chunks


MAX_SOURCES = 128
MAX_FILES = 512
MAX_OPERATIONS = 65536


def _file_identity(value):
    if (not isinstance(value, dict) or set(value) != {'node_uid', 'device', 'inode'}
            or not isinstance(value['node_uid'], str) or not value['node_uid']
            or '\x00' in value['node_uid'] or len(value['node_uid'].encode()) > 512
            or type(value['device']) is not int or not 0 <= value['device'] <= 2**64-1
            or type(value['inode']) is not int or not 1 <= value['inode'] <= 2**64-1):
        raise ValueError('Private node file identity required')
    return (value['node_uid'], value['device'], value['inode'])


class PrivateCRIRetention:
    """Keep collected bytes private across file growth/rotation/source deletion.

    Trusted collector supplies independently verified source and node/file IDs,
    exact contiguous offsets, final old-file sizes and new rotation identities.
    Reused identities, skips, overlaps, late writes, bounds and abandonment
    permanently invalidate further collection. Existing bytes remain inspectable
    so a known positive is not erased by a subsequent collection failure.

    This does not verify collector identity, observe files, discover missing
    rotations, bind watch/time fences or prove source/history coverage. Inspection
    always says history_complete=False: only a positive can be application-failure
    evidence. Absence cannot authorize a pass. A separate trusted collector and
    coverage protocol are required. No raw bytes are returned or written to disk.
    """
    def __init__(self, binding, *, max_bytes=DEFAULT_BYTES):
        if not isinstance(binding, dict) or set(binding) != {'name', 'uid'}:
            raise ValueError('Private retention namespace binding required')
        source_binding(dict(namespace=binding['name'], pod_name='validation', pod_uid=binding['uid'],
                            container_name='validation', container_id='validation', previous=False))
        if type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 * 1024:
            raise ValueError('Private retention byte bound required')
        self._binding, self._max_bytes = copy.deepcopy(binding), max_bytes
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._sources, self._used_files = {}, set()
        self._bytes, self._operations = 0, 0
        self._valid, self._closed = True, False

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private log retention owner unavailable')

    def _refuse(self):
        self._valid = False
        raise ValueError('Private log retention unavailable') from None

    def _operation(self):
        if self._closed or not self._valid or self._operations >= MAX_OPERATIONS:
            self._refuse()
        self._operations += 1

    def _key(self, source):
        value = source_binding(source)
        if value['namespace'] != self._binding['name']:
            raise ValueError('Private retention namespace unavailable')
        # Current/previous is a read selector, not the immutable container's ID.
        return tuple(value[field] for field in
                     ('namespace', 'pod_name', 'pod_uid', 'container_name', 'container_id'))

    def _new_file(self, state, identity):
        if identity in self._used_files or len(self._used_files) >= MAX_FILES:
            self._refuse()
        state['files'].append(dict(identity=identity, data=bytearray()))
        self._used_files.add(identity)

    def _active(self, source, file_identity):
        key, identity = self._key(source), _file_identity(file_identity)
        state = self._sources.get(key)
        if state is None or state['sealed'] or state['files'][-1]['identity'] != identity:
            self._refuse()
        return state

    def open(self, source, file_identity):
        self._owned()
        with self._lock:
            try:
                self._operation()
                key, identity = self._key(source), _file_identity(file_identity)
                if key in self._sources or len(self._sources) >= MAX_SOURCES:
                    self._refuse()
                state = dict(files=[], sealed=False)
                self._new_file(state, identity)
                self._sources[key] = state
            except Exception: self._refuse()

    def append(self, source, file_identity, offset, data):
        self._owned()
        with self._lock:
            try:
                self._operation()
                state = self._active(source, file_identity)
                retained = state['files'][-1]['data']
                if (type(offset) is not int or offset != len(retained) or not isinstance(data, bytes)
                        or self._bytes + len(data) > self._max_bytes):
                    self._refuse()
                retained.extend(data)
                self._bytes += len(data)
            except Exception: self._refuse()

    def _end_file(self, source, file_identity, final_size):
        state = self._active(source, file_identity)
        data = state['files'][-1]['data']
        if type(final_size) is not int or final_size != len(data) or (data and data[-1] != 10):
            self._refuse()
        return state

    def rotate(self, source, old_file, new_file, *, final_size):
        self._owned()
        with self._lock:
            try:
                self._operation()
                state = self._end_file(source, old_file, final_size)
                identity = _file_identity(new_file)
                if identity[:2] != state['files'][-1]['identity'][:2]: self._refuse()
                self._new_file(state, identity)
            except Exception: self._refuse()

    def seal(self, source, file_identity, *, final_size):
        self._owned()
        with self._lock:
            try:
                self._operation()
                self._end_file(source, file_identity, final_size)['sealed'] = True
            except Exception: self._refuse()

    def inspect(self, values=None, *, binary_values=None):
        self._owned()
        # Validate requested controls before inspecting any private retained data.
        scan_secret_chunks([], values, binary_values=binary_values)
        with self._lock:
            if self._closed: raise ValueError('Private log retention unavailable')
            present, decoded_sources = False, 0
            for state in self._sources.values():
                files = [bytes(value['data']) for value in state['files']]
                prefix = decode_cri_prefix(files, max_bytes=self._max_bytes)
                candidates = [prefix]
                if prefix['complete']:
                    decoded_sources += 1
                else:
                    # A bad generation need not hide valid prefixes in later
                    # independently supplied files of the same bound container.
                    for raw in files:
                        candidates.append(decode_cri_prefix([raw], max_bytes=self._max_bytes))
                for candidate in candidates:
                    for stream in ('stdout', 'stderr'):
                        scan = scan_secret_chunks([candidate[stream]], values,
                                                  binary_values=binary_values, max_bytes=self._max_bytes)
                        present |= scan['canary_present']
            return dict(canary_present=present, history_complete=False,
                        retention_valid=self._valid, sources=len(self._sources),
                        decoded_sources=decoded_sources, files=len(self._used_files),
                        retained_bytes=self._bytes)

    def abandon(self):
        self._owned()
        with self._lock: self._valid = False

    def close(self):
        """Release references to private bytes; no secure-memory-erasure claim."""
        self._owned()
        with self._lock:
            self._valid, self._closed = False, True
            self._sources.clear()
            self._used_files.clear()
