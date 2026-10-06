"""Parent-owned opaque Pod watch cursor, committed only at verified window close."""
import copy
import hashlib
import json
import os
import threading
import uuid

from .log_transport import source_binding
from .pod_watch import MAX_EVENT_BYTES, MAX_EVENTS, _version, watch_event


MAX_WINDOWS = 4096


class PodWatchCursor:
    """Private cursor state; never use window counts as full-history evidence.

    Construct from an independently verified complete PodList anchor. For every
    window, begin(), feed every delivered event to accept(), then finish() with
    that exact trusted transport receipt. No resource-version ordering arithmetic
    or silent relisting. Errors/gaps/abandonment permanently invalidate this cursor.
    Resumption alone does not recover deleted/rotated log bytes or prove coverage.
    """
    def __init__(self, binding, resource_version):
        if not isinstance(binding, dict) or set(binding) != {'name', 'uid'}:
            raise ValueError('Private namespace cursor binding required')
        source_binding(dict(namespace=binding['name'], pod_name='validation', pod_uid=binding['uid'],
                            container_name='validation', container_id='validation', previous=False))
        self.binding = copy.deepcopy(binding)
        self._version = _version(resource_version)
        if self._version == '0': raise ValueError('Anchored private watch cursor required')
        self._owner = os.getpid()
        self._lock = threading.RLock()
        self._valid, self._active = True, False
        self._windows = 0
        self._pending = None

    def _owned(self):
        # Check before taking a lock that may have been inherited by a fork.
        if os.getpid() != self._owner:
            raise ValueError('Private Pod watch cursor owner unavailable')

    def _refuse(self):
        self._valid, self._active, self._pending = False, False, None
        raise ValueError('Private Pod watch cursor unavailable') from None

    @property
    def resource_version(self):
        self._owned()
        with self._lock:
            if not self._valid or self._active:
                raise ValueError('Private Pod watch cursor unavailable')
            return self._version

    def begin(self):
        self._owned()
        with self._lock:
            if not self._valid or self._active or self._windows >= MAX_WINDOWS:
                self._refuse()
            self._active = True
            self._pending = dict(window_id='pod-watch-'+uuid.uuid4().hex, anchor=self._version,
                                 version=self._version, events=0)
            return dict(window_id=self._pending['window_id'], resource_version=self._version)

    def accept(self, event):
        self._owned()
        with self._lock:
            if not self._valid or not self._active or self._pending['events'] >= MAX_EVENTS:
                self._refuse()
            try:
                raw = json.dumps(event, allow_nan=False, ensure_ascii=False).encode()
                if len(raw) > MAX_EVENT_BYTES: raise ValueError('Private cursor event bound')
                value = watch_event(raw, self.binding['name'])
                version = value['object']['metadata']['resourceVersion']
                if version == '0': raise ValueError('Unanchored private watch cursor')
                self._pending['version'] = version
                self._pending['events'] += 1
            except Exception:
                self._refuse()

    def finish(self, receipt):
        self._owned()
        with self._lock:
            if not self._valid or not self._active: self._refuse()
            pending = self._pending
            binding_hash = hashlib.sha256(json.dumps(self.binding, sort_keys=True).encode()).hexdigest()
            anchor_hash = hashlib.sha256(pending['anchor'].encode()).hexdigest()
            if (not isinstance(receipt, dict) or receipt.get('outcome') != 'watch_window_closed'
                    or receipt.get('window_id') != pending['window_id']
                    or receipt.get('binding_sha256') != binding_hash
                    or receipt.get('anchor_sha256') != anchor_hash
                    or type(receipt.get('events')) is not int or receipt['events'] != pending['events']
                    or any(receipt.get(flag) is not True for flag in
                           ('source_verified_before', 'source_verified_after', 'client_group_absent'))):
                self._refuse()
            self._version = pending['version']
            self._windows += 1
            self._active, self._pending = False, None
            return dict(outcome='cursor_committed', windows=self._windows, events=receipt['events'])

    def abandon(self):
        self._owned()
        with self._lock:
            self._valid, self._active, self._pending = False, False, None
