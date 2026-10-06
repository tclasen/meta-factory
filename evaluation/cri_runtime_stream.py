"""Incremental private CRI JSON admission; incomplete streams invalidate dependents."""
import codecs
import json
import math
import os
import threading

from .pod_watch import _unique


MAX_CHUNK_BYTES = 65536
MAX_EVENT_BYTES = 2 * 1024 * 1024
MAX_STREAM_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 4096


def _finite_float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError('Private nonfinite value')
    return parsed


class _Refusal(ValueError):
    def __init__(self, reason):
        self.reason = reason


class PrivateCRIEventDecoder:
    """Decode concatenated/pretty CRI objects while an owned stream is live.

    consume receives PRIVATE objects synchronously; retain only minimal metadata.
    check(reserve) verifies original runtime/Node/Namespace/owner and clocks.
    invalidate releases all dependent metadata/collection on ANY refusal. It must
    be trusted bounded cleanup code; failed invalidation is reported explicitly.
    Unexpected transport failure must call close(), not finish(). finish verifies
    framing for an intentionally closed observation window; it is no continuity,
    bootstrap/birth/tombstone/writer/API/time fence or healthy-grading receipt.
    No IO/transport authentication is performed here. Run blocking callbacks in
    a bounded owned child. Raw JSON never enters public receipts or diagnostics.
    """
    def __init__(self, consume, *, check, invalidate):
        if not all(callable(v) for v in (consume, check, invalidate)):
            raise ValueError('Private CRI decoder callbacks required')
        self._consume, self._check, self._invalidate = consume, check, invalidate
        self._owner, self._lock = os.getpid(), threading.RLock()
        self._valid, self._finished, self._invalidated = True, False, False
        self._text, self._bytes, self._events = '', 0, 0
        self._utf8 = codecs.getincrementaldecoder('utf-8')('strict')
        self._json = json.JSONDecoder(object_pairs_hook=_unique,
            parse_float=_finite_float,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Private nonfinite value')))
        try: self._verify()
        except BaseException as error:
            self._discard()
            if not isinstance(error, Exception): raise
            failure = ValueError('Private CRI stream unavailable')
            failure.reason = error.reason if type(error) is _Refusal else 'input_or_callback'
            raise failure from None

    def _owned(self):
        if os.getpid() != self._owner:
            raise ValueError('Private CRI decoder owner unavailable')

    def _verify(self):
        if not self._valid or self._finished or self._check(5) is not True:
            raise _Refusal('lifetime')

    def _discard(self):
        was_valid = self._valid
        self._valid = False
        self._text = ''; self._utf8.reset()
        if was_valid:
            try:
                self._invalidate()
                self._invalidated = True
            except Exception:
                self._invalidated = False

    def _decode(self, final=False):
        while True:
            self._text = self._text.lstrip(' \t\r\n')
            if not self._text: return
            try:
                event, end = self._json.raw_decode(self._text)
            except json.JSONDecodeError:
                if final or len(self._text.encode()) > MAX_EVENT_BYTES:
                    raise _Refusal('framing') from None
                return
            if (not isinstance(event, dict) or len(self._text[:end].encode()) > MAX_EVENT_BYTES
                    or self._events >= MAX_EVENTS):
                raise _Refusal('shape_or_bound')
            self._verify()
            self._consume(event)
            self._verify()
            self._events += 1
            self._text = self._text[end:]

    def feed(self, chunk):
        self._owned()
        with self._lock:
            try:
                self._verify()
                if (type(chunk) is not bytes or not chunk or len(chunk) > MAX_CHUNK_BYTES
                        or self._bytes + len(chunk) > MAX_STREAM_BYTES):
                    raise _Refusal('input_bound')
                self._bytes += len(chunk)
                self._text += self._utf8.decode(chunk)
                self._decode()
                self._verify()
                return self.summary()
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                failure = ValueError('Private CRI stream unavailable')
                failure.reason = error.reason if type(error) is _Refusal else 'input_or_callback'
                raise failure from None

    def finish(self):
        """Close a declared observation window; absence never passes collection."""
        self._owned()
        with self._lock:
            try:
                self._verify()
                self._text += self._utf8.decode(b'', final=True)
                self._decode(final=True)
                self._verify()
                self._finished = True
                return self.summary()
            except BaseException as error:
                self._discard()
                if not isinstance(error, Exception): raise
                failure = ValueError('Private CRI stream unavailable')
                failure.reason = error.reason if type(error) is _Refusal else 'input_or_callback'
                raise failure from None

    def summary(self):
        self._owned()
        with self._lock:
            return dict(outcome='private_cri_event_decoder', valid=self._valid,
                window_finished=self._finished, input_bytes=self._bytes, events=self._events,
                dependents_invalidated=self._invalidated, history_complete=False)

    def close(self):
        self._owned()
        with self._lock:
            self._discard()
            return self.summary()
