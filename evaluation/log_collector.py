"""Coordinate private observed identities and Linux files; never coverage proof."""
import copy
import os
import threading
import time

from .cri_follower import LinuxCRIFollower
from .evidence import positive
from .log_retention import PrivateCRIRetention
from .pod_history import PodIdentityHistory


class NamespaceLogCollector:
    """Attach each observed identity once and retain bytes across Pod deletion.

    Trusted resolve(entry, reserve) returns None while binding is unavailable, or
    exactly directory/node_uid/check. It independently verifies node/file/source
    identity, including historical sources; paths must never come from builders.
    check(reserve) verifies the original namespace, owner and clocks. Both calls
    run inside an owned bounded child: Python deadlines cannot interrupt blocking
    filesystem or callback operations. Unresolved identities remain explicit and
    are retried. A follower failure stops all sources, preserving prior positives.
    close abandons shared retention but does not erase it. No source is retired
    on API deletion alone, which is not proof that its writer has closed.

    This does not capture pre-CID files, discover unobserved generations, establish
    bootstrap/time/writer fences or prove namespace coverage. Every receipt says
    history_complete=False. Absence never authorizes an acceptance pass.
    """
    def __init__(self, history, retention, resolve, *, check, deadline):
        positive(deadline, 'Namespace collection deadline')
        if (type(history) is not PodIdentityHistory or type(retention) is not PrivateCRIRetention
                or not callable(resolve) or not callable(check)):
            raise ValueError('Private namespace collection inputs required')
        history._owned(); retention._owned()
        if history._binding != retention._binding:
            raise ValueError('Private namespace collection binding required')
        self._history, self._retention = history, retention
        self._resolve, self._check, self._deadline = resolve, check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._followers, self._unresolved = {}, 0
        self._polls, self._closed, self._failed, self._cleanup_ok = 0, False, False, True

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private namespace collection owner unavailable')

    def _verify(self):
        if (time.monotonic()+5 >= self._deadline or self._check(5) is not True
                or not self._history.summary()['valid']
                or not self._retention._valid or self._retention._closed):
            raise ValueError('Private namespace collection lifetime unavailable')

    def _cleanup(self):
        for follower in self._followers.values():
            try:
                self._cleanup_ok &= follower.close()['descriptors_closed']
            except Exception:
                self._cleanup_ok = False
        self._retention.abandon()
        self._closed = True

    def poll(self):
        self._owned()
        with self._lock:
            try:
                if self._closed or self._failed or self._polls >= 4096:
                    raise ValueError('Private namespace collection unavailable')
                self._verify(); self._polls += 1
                self._unresolved = 0
                for entry in self._history.sources():
                    source = entry['source']
                    key = tuple(source[field] for field in
                                ('namespace', 'pod_name', 'pod_uid', 'container_name', 'container_id'))
                    if key in self._followers:
                        continue
                    self._verify()
                    bound = self._resolve(copy.deepcopy(entry), 5)
                    self._verify()
                    if bound is None:
                        self._unresolved += 1
                        continue
                    if not isinstance(bound, dict) or set(bound) != {'directory', 'node_uid', 'check'}:
                        raise ValueError('Private source resolution unavailable')
                    self._followers[key] = LinuxCRIFollower(self._retention, source,
                        bound['directory'], str(entry['restart_index'])+'.log',
                        node_uid=bound['node_uid'], check=bound['check'], deadline=self._deadline)
                for follower in self._followers.values():
                    self._verify(); follower.poll()
                self._verify()
                return self.summary()
            except BaseException as error:
                self._failed = True
                self._cleanup()
                if not isinstance(error, Exception): raise
                raise ValueError('Private namespace collection unavailable') from None

    def summary(self):
        self._owned()
        with self._lock:
            history = self._history.summary()
            return dict(outcome='private_namespace_collection', polls=self._polls,
                        attached_sources=len(self._followers), unresolved_sources=self._unresolved,
                        pending_containers=history['pending_containers'],
                        identity_gap=history['identity_gap'],
                        valid=not self._failed and not self._closed and history['valid']
                        and self._retention._valid and not self._retention._closed,
                        descriptors_closed=self._closed and self._cleanup_ok,
                        history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._cleanup()
            return self.summary()
