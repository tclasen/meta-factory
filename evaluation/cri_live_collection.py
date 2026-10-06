"""Guarded private runtime metadata, held initial files and preserved positives."""
import copy
from contextlib import contextmanager
import os
import stat
import threading
import time

from .cri_archive import PrivateCRIRuntimeArchive
from .cri_follower import LinuxCRIDescriptorFollower
from .cri_runtime_buffer import PrivateCRIRuntimeEventBuffer
from .cri_runtime_stream import PrivateCRIEventDecoder
from .cri_staging import provisional_entry, _key
from .evidence import positive
from .log_retention import PrivateCRIRetention


class PrivateCRILiveCollection:
    """Join live private events to independently authenticated initial log FDs.

    The original runtime/Node/Namespace/owner/clocks are checked before AND after
    each public admission/bind/poll transaction. Private child guards require that
    active transaction, original API validity and deadline; no scope cache can be
    used outside it. Child metadata validation is pure; held-file callbacks repeat
    independent file observation during archive admission and every poll.
    check(reserve) and per-file check(proof,reserve) are trusted bounded operator
    code. The caller authenticates the transport/native sender and retains the
    borrowed FD. Run potentially blocking guards/IO in a bounded owned child.

    Any source/schema/guard/file/lookup refusal closes all owned follower FDs,
    releases buffer/archive metadata and invalidates retention. Previously captured
    canary bytes remain inspectable until release(), which drops references without
    claiming secure erasure. Expected window finish is framing only, not source
    continuity. Transport interruption must call close().

    This supports initial held generations, not rotation/birth/bootstrap/all-node
    coverage, writer/API/time fences, persisted positives or owner-death recovery.
    Duplicate initial bindings refuse; no generation inherits attribution. None
    means pending/unseen API/runtime metadata, never clean/complete collection.
    Public receipts contain counts only; all source/file metadata remain private.
    """
    def __init__(self, history, *, node_uid, node_name, check, deadline):
        positive(deadline, 'Private live collection deadline')
        if not callable(check): raise ValueError('Private live collection guard required')
        self._history, self._node, self._name = history, node_uid, node_name
        self._check, self._deadline = check, deadline
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._valid, self._active, self._released = True, False, False
        self._buffer = self._archive = self._decoder = self._retention = None
        self._followers = {}; self._descriptors_closed = True
        try:
            with self._transaction():
                self._buffer = PrivateCRIRuntimeEventBuffer(history,node_uid=node_uid,
                    node_name=node_name,check=self._scope,deadline=deadline)
                self._archive = PrivateCRIRuntimeArchive(history,node_uid=node_uid,
                    node_name=node_name,check=self._scope,deadline=deadline)
                self._retention = PrivateCRIRetention(history._binding)
                self._decoder = PrivateCRIEventDecoder(self._buffer.accept,
                    check=self._scope,invalidate=self._invalidate)
        except BaseException as error:
            self._stop()
            if not isinstance(error, Exception): raise
            raise ValueError('Private live collection unavailable') from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private live collection owner unavailable')

    def _scope(self, reserve):
        return (os.getpid()==self._owner and self._valid and self._active
                and time.monotonic()+reserve<self._deadline
                and self._history.summary()['valid'])

    def _original(self):
        if (not self._valid or time.monotonic()+5>=self._deadline
                or self._check(5) is not True or not self._history.summary()['valid']):
            raise ValueError('Private live collection scope unavailable')
        if (any(child is not None and not child.summary()['valid']
                for child in (self._buffer,self._archive,self._decoder))
                or self._retention is not None and (not self._retention._valid or self._retention._closed)):
            raise ValueError('Private live collection dependency unavailable')

    @contextmanager
    def _transaction(self):
        self._owned()
        with self._lock:
            if self._active: raise ValueError('Private live collection reentry unavailable')
            self._original(); self._active = True
            try:
                yield
                self._original()
            finally:
                self._active = False

    def _invalidate(self):
        self._valid = False
        for follower in self._followers.values():
            result = follower.close()
            self._descriptors_closed &= result['descriptors_closed']
        self._followers.clear()
        if self._buffer is not None: self._buffer.close()
        if self._archive is not None: self._archive.close()
        if self._retention is not None: self._retention.abandon()

    def _stop(self):
        if self._decoder is not None: self._decoder.close()
        # Even a failed decoder callback cannot leave other dependents valid.
        self._invalidate()

    def _failure(self, error):
        self._stop()
        if not isinstance(error, Exception): raise error
        result = ValueError('Private live collection unavailable')
        reason = getattr(error, 'reason', None)
        result.reason = reason if reason in ('framing','lifetime','input_bound','shape_or_bound','input_or_callback') else 'input_or_lifetime'
        raise result from None

    def feed(self, chunk):
        self._owned()
        try:
            with self._transaction(): self._decoder.feed(chunk)
            return self.summary()
        except BaseException as error: self._failure(error)

    def finish(self):
        self._owned()
        try:
            with self._transaction(): self._decoder.finish()
            return self.summary()
        except BaseException as error: self._failure(error)

    def bind(self, entry, node, descriptor, *, check):
        """Bind one borrowed readonly initial FD, or return None while pending."""
        self._owned()
        try:
            with self._transaction():
                import fcntl
                entry = provisional_entry(entry)
                if type(descriptor) is not int or descriptor<0 or not callable(check):
                    raise ValueError('Private live file inputs required')
                observed = os.fstat(descriptor); flags = fcntl.fcntl(descriptor,fcntl.F_GETFL)
                if not stat.S_ISREG(observed.st_mode) or flags&os.O_ACCMODE != os.O_RDONLY or flags&getattr(os,'O_PATH',0):
                    raise ValueError('Private live readonly file required')
                key = _key(entry)
                if key in self._followers: raise ValueError('Private live duplicate initial file')
                creation = self._buffer.event_for(entry)
                if creation is None: return None
                identity = dict(node_uid=self._node,device=observed.st_dev,inode=observed.st_ino)
                projection = self._archive.capture_event(entry,node,creation,identity,check=check)
                if projection is None: return None
                def source_check(source, reserve):
                    if not self._scope(reserve): return False
                    value = self._archive.resolve(entry,identity,check=check)
                    return value is not None and value['source']==source
                follower = LinuxCRIDescriptorFollower(self._retention,projection['source'],descriptor,
                    node_uid=self._node,check=source_check,deadline=self._deadline)
                self._followers[key] = follower
            return self.summary()
        except BaseException as error: self._failure(error)

    def poll(self):
        self._owned()
        try:
            with self._transaction():
                for follower in self._followers.values(): follower.poll()
            return self.summary()
        except BaseException as error: self._failure(error)

    def inspect(self, values=None, *, binary_values=None):
        """Inspect private captured prefixes even after refusal; no healthy claim."""
        self._owned()
        with self._lock:
            if self._released or self._retention is None:
                raise ValueError('Private live evidence unavailable')
            return self._retention.inspect(values,binary_values=binary_values)

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_live_collection',valid=self._valid,
                bound_initial_files=len(self._followers),descriptors_closed=self._descriptors_closed and not self._followers,
                metadata_released=not self._valid,bytes_released=self._released,
                window_finished=self._decoder.summary()['window_finished'] if self._decoder else False,
                history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._stop()
            return self.summary()

    def release(self):
        """Drop private evidence only after its caller has recorded findings."""
        self._owned()
        with self._lock:
            self._stop()
            if self._retention is not None: self._retention.close()
            self._released = True
            return self.summary()
